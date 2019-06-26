#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "node.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "stream_base-inl.h"
#include "node_quic_session-inl.h"
#include "node_quic_stream.h"
#include "node_quic_socket.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <algorithm>
#include <limits>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

namespace quic {

uv_buf_t QuicStreamListener::OnStreamAlloc(size_t size) {
  // TODO(@jasnell): For now, allocate space to copy the data into.
  // Check later to see if we can get away with not copying like
  // we do with http2
  Environment* env = static_cast<QuicStream*>(stream_)->env();
  return env->AllocateManaged(size).release();
}

void QuicStreamListener::OnStreamRead(ssize_t nread, const uv_buf_t& buf) {
  QuicStream* stream = static_cast<QuicStream*>(stream_);
  Environment* env = stream->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  if (nread < 0) {
    PassReadErrorToPreviousListener(nread);
    return;
  }

  AllocatedBuffer buffer(stream->env(), buf);
  stream->CallJSOnreadMethod(nread, buffer.ToArrayBuffer());
}

// TODO(@jasnell): QUIC streams have an absolute maximum amount
// of data that can be transmitted over the lifetime of the stream.
// We need to be performing two checks in here:
//
// 1. On transmit, we should ensure that a QuicStream instance
//    never attempts to send more than the maximum data limit.
//    This can be done by implementing a countdown that causes
//    the stream to emit an error if the threshold is exceeded.
//
// 2. On receive, we need to ensure that ngtcp2 catches the limit.
//    When a stream reaches it's maximum, the stream will need to
//    be destroyed. We should differentiate streams that end because
//    there is no more data vs. streams that end because it has
//    reached the transmit limit.
//

// TODO(@jasnell): Currently, streams max exist for the entire
// lifespan of the QuicSession, which can be indefinite so long as
// there is activity. It would make sense to implement an optional
// maximum lifespan for individual stream instances, or to implement
// a timeout that is independent of the session. This timeout would
// best be implemented at the JavaScript side, but can be implemented
// in the C++ code also. We should differentiate streams that end
// because it reached the maximum time vs. streams that end because
// it has no more data.

QuicStream::QuicStream(
    QuicSession* session,
    Local<Object> wrap,
    uint64_t stream_id) :
    AsyncWrap(session->env(), wrap, AsyncWrap::PROVIDER_QUICSTREAM),
    StreamBase(session->env()),
    session_(session),
    stream_id_(stream_id),
    flags_(QUICSTREAM_FLAG_INITIAL),
    max_offset_(0),
    available_outbound_length_(0),
    inbound_consumed_data_while_paused_(0),
    data_rx_rate_(1, std::numeric_limits<int64_t>::max()),
    data_rx_size_(1, NGTCP2_MAX_PKT_SIZE),
    data_rx_ack_(1, std::numeric_limits<int64_t>::max()),
    data_rx_acksize_(1, NGTCP2_MAX_PKT_SIZE),
    stats_buffer_(
      session->env()->isolate(),
      sizeof(stream_stats_) / sizeof(uint64_t),
      reinterpret_cast<uint64_t*>(&stream_stats_)) {
  CHECK_NOT_NULL(session);
  SetInitialFlags();
  session->AddStream(this);
  StreamBase::AttachToObject(GetObject());
  PushStreamListener(&stream_listener_);
  stream_stats_.created_at = uv_hrtime();

  USE(wrap->DefineOwnProperty(
      env()->context(),
      env()->stats_string(),
      stats_buffer_.GetJSArray(),
      PropertyAttribute::ReadOnly));
}

QuicStream::~QuicStream() {
  // Check that Destroy() has been called
  CHECK_NULL(session_);
  CHECK_EQ(0, streambuf_.Length());
  uint64_t now = uv_hrtime();
  Debug(this,
        "QuicStream %llu destroyed.\n"
        "  Duration: %llu\n"
        "  Bytes Received: %llu\n"
        "  Bytes Sent: %llu",
        GetID(),
        now - stream_stats_.created_at,
        stream_stats_.bytes_received,
        stream_stats_.bytes_sent);
}

inline void QuicStream::SetInitialFlags() {
  if (GetDirection() == QUIC_STREAM_UNIDIRECTIONAL) {
    if (session_->IsServer()) {
      switch (GetOrigin()) {
        case QUIC_STREAM_SERVER:
          SetReadClose();
          break;
        case QUIC_STREAM_CLIENT:
          SetWriteClose();
          break;
        default:
          UNREACHABLE();
      }
    } else {
      switch (GetOrigin()) {
        case QUIC_STREAM_SERVER:
          SetWriteClose();
          break;
        case QUIC_STREAM_CLIENT:
          SetReadClose();
          break;
        default:
          UNREACHABLE();
      }
    }
  }
}

// QuicStream::Close() is called by the QuicSession when ngtcp2 detects that
// a stream has been closed. This, in turn, calls out to the JavaScript to
// start the process of tearing down and destroying the QuicStream instance.
void QuicStream::Close(uint16_t app_error_code) {
  SetReadClose();
  SetWriteClose();
  HandleScope scope(env()->isolate());
  Context::Scope context_context(env()->context());
  Local<Value> argv[] = {
    Number::New(env()->isolate(), app_error_code)
  };
  MakeCallback(env()->quic_on_stream_close_function(), arraysize(argv), argv);
}

// Receiving a STREAM_RESET means that the peer will no longer be sending
// new frames for the given stream, although retransmissions of prior
// frames may still be received. Once the reset is received, the readable
// side of the stream is closed without waiting for a STREAM frame with
// the fin. If a fin has already been received, the reset is ignored.
// From the JavaScript API point of view, a reset is largely indistinguishable
// from a normal end-of-stream with the exception that the receivedReset
// property will be set with the final size and application error code
// specified.
void QuicStream::Reset(uint64_t final_size, uint16_t app_error_code) {
  // Ignore the reset completely if fin has already been received.
  if (IsFin())
    return;
  Debug(this,
        "Resetting stream %llu with app error code %d, and final size %llu",
        GetID(),
        app_error_code,
        final_size);
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  streambuf_.Cancel();
  Local<Value> argv[] = {
    Number::New(env()->isolate(), app_error_code),
    Number::New(env()->isolate(), static_cast<double>(final_size)),
  };
  MakeCallback(env()->quic_on_stream_reset_function(), arraysize(argv), argv);
}

void QuicStream::Destroy() {
  Debug(this, "Destroying QuicStream %llu on %s",
        stream_id_,
        session_->IsServer() ? "server" : "client");
  SetReadClose();
  SetWriteClose();
  streambuf_.Cancel();
  session_->RemoveStream(stream_id_);
  session_ = nullptr;
  // Explicitly delete the QuicStream. We won't be
  // needing it any longer.
  delete this;
}

// Do shutdown is called when the JS stream writable side is closed.
// We want to mark the writable side closed and send pending data.
int QuicStream::DoShutdown(ShutdownWrap* req_wrap) {
  Debug(this, "Shutdown QuicStream %llu writable side on Quic%sSession",
        GetID(), session_->IsServer() ? "Server" : "Client");
  if (IsDestroyed())
    return UV_EPIPE;
  // Do nothing if the stream was already shutdown. Specifically,
  // we should not attempt to send anything on the QuicSession
  if (!IsWritable())
    return 1;
  stream_stats_.closing_at = uv_hrtime();
  SetWriteClose();
  session_->SendStreamData(this);
  return 1;
}

int QuicStream::DoWrite(
    WriteWrap* req_wrap,
    uv_buf_t* bufs,
    size_t nbufs,
    uv_stream_t* send_handle) {
  CHECK_NULL(send_handle);

  // A write should not have happened if we've been destroyed or
  // the QuicStream is no longer writable.
  if (IsDestroyed() || !IsWritable()) {
    req_wrap->Done(UV_EOF);
    return 0;
  }
  // There's a difficult balance required here:
  //
  // Unlike typical UDP, which is fire-and-forget, QUIC packets
  // have to be acknowledged. If a packet is not acknowledged
  // soon enough, it is retransmitted. The exact arrangement
  // of packets being retransmitted varies over the course of
  // the connection on many factors. Fortunately, ngtcp2 takes
  // care of most of the details here, we just need to retain
  // the data until we're certain it's no longer needed.
  //
  // That said, on the JS Streams API side, we can only write
  // one batch of buffers at a time. That is, DoWrite won't be
  // called again until the previous DoWrite is completed by
  // calling WriteWrap::Done(). The challenge, however, is that
  // calling Done() essentially signals that we're done with
  // the buffers being written, allowing those to be freed.
  //
  // In other words, if we just store the given buffers and
  // wait to call Done() when we receive an acknowledgement,
  // we severely limit our throughput and kill performance
  // because the JavaScript side won't be able to send additional
  // buffers until we receive the acknowledgement from the peer.
  // However, if we call Done() here to allow the next chunk to
  // be written, we have to copy the data because the buffers
  // may end up being freed once the callback is invoked. The
  // memcpy obviously incurs a cost but it'll at least be less
  // than waiting for the acknowledgement, allowing data to be
  // written faster but at the cost of a data copy.
  //
  // Because of the need to copy, performing many small writes
  // will incur a performance penalty over a smaller number of
  // larger writes, but only up to a point. Frequently copying
  // large chunks of data will end up slowing things down also.
  //
  // Because we are copying to allow the JS side to write
  // faster independently of the underlying send, we will have
  // to be careful not to allow the internal buffer to grow
  // too large, or we'll run into several other problems.

  uint64_t len = streambuf_.Copy(bufs, nbufs);
  IncrementStat(len, &stream_stats_, &stream_stats::bytes_sent);
  req_wrap->Done(0);
  stream_stats_.stream_sent_at = uv_hrtime();
  session_->SendStreamData(this);

  // IncrementAvailableOutboundLength(len);
  return 0;
}

void QuicStream::AckedDataOffset(uint64_t offset,  size_t datalen) {
  if (IsDestroyed())
    return;
  streambuf_.Consume(datalen);

  uint64_t now = uv_hrtime();
  if (stream_stats_.stream_acked_at > 0)
    data_rx_ack_.Record(now - stream_stats_.stream_acked_at);
  stream_stats_.stream_acked_at = now;
  data_rx_acksize_.Record(datalen);

  // TODO(@jasnell): One possible DOS attack vector is a peer that sends
  // very small acks at a rate that is just fast enough not to run afoul
  // of the idle timeout. This can force a QuicStream to hold on to
  // buffered data for long periods of time, eating up resources. The
  // data_rx_ack_ and data_rx_acksize_ histograms can be used to detect
  // this behavior. There are, however, legitimate reasons why a peer
  // would send small acks at a slow rate, so there are no blanket rules
  // that we can apply to this. We need to determine a reasonable default
  // that can be overriden by user code. When the activity falls below
  // that threshold, we will emit an event that the user code can respond
  // to.
}

size_t QuicStream::DrainInto(
    std::vector<ngtcp2_vec>* vec) {
  return streambuf_.DrainInto(vec);
}

void QuicStream::Commit(size_t count) {
  streambuf_.SeekHead(count);
}

inline void QuicStream::IncrementAvailableOutboundLength(size_t amount) {
  available_outbound_length_ += amount;
}

inline void QuicStream::DecrementAvailableOutboundLength(size_t amount) {
  available_outbound_length_ -= amount;
}

int QuicStream::ReadStart() {
  CHECK(!this->IsDestroyed());
  CHECK(IsReadable());
  SetReadStart();
  SetReadResume();
  session_->ExtendStreamOffset(this, inbound_consumed_data_while_paused_);
  return 0;
}

int QuicStream::ReadStop() {
  CHECK(!this->IsDestroyed());
  CHECK(IsReadable());
  SetReadPause();
  return 0;
}

// Passes chunks of data on to the JavaScript side as soon as they are
// received but only if we're still readable. The caller of this must have a
// HandleScope.
//
// Note that this is pushing data to the JS side regardless of whether
// anything is listening. For flow-control, we only send window updates
// to the sending peer if the stream is in flowing mode, so the sender
// should not be sending too much data.
// TODO(@jasnell): We may need to be more defensive here with regards to
// flow control to keep the buffer from growing too much. ngtcp2 may give
// us some protection but we need to verify.
void QuicStream::ReceiveData(
    int fin,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  Debug(this, "Receiving %d bytes of data. Final? %s. Readable? %s",
        datalen, fin ? "yes" : "no", IsReadable() ? "yes" : "no");

  if (!IsReadable())
    return;

  // ngtcp2 guarantees that datalen will only be 0 if fin is set.
  // Let's just make sure.
  CHECK(datalen > 0 || fin == 1);

  // ngtcp2 guarantees that offset is always greater than the previously
  // received offset. Let's just make sure.
  CHECK_GE(offset, max_offset_);
  max_offset_ = offset;

  if (datalen > 0) {
    IncrementStats(datalen);
    // TODO(@jasnell): IncrementStats will update the data_rx_rate_ and
    // data_rx_size_ histograms. These will provide data necessary to
    // detect and prevent Slow Send DOS attacks specifically by allowing
    // us to see if a connection is sending very small chunks of data
    // at very slow speeds. It is important to emphasize, however, that
    // slow send rates may be perfectly legitimate so we cannot simply take
    // blanket action when slow rates are detected. Nor can we reliably
    // define what a slow rate even is! Will will need to determine some
    // reasonable default and allow user code to change the default as well
    // as determine what action to take. The current strategy will be to
    // trigger an event on the stream when data transfer rates are likely
    // to be considered too slow.
    while (datalen > 0) {
      uv_buf_t buf = EmitAlloc(datalen);
      size_t avail = std::min(static_cast<size_t>(buf.len), datalen);

      // TODO(@jasnell): For now, we're allocating and copying. Once
      // we determine if we can safely switch to a non-allocated mode
      // like we do with http2 streams, we can make this branch more
      // efficient by using the LIKELY optimization
      // if (LIKELY(buf.base == nullptr))
      if (buf.base == nullptr)
        buf.base = reinterpret_cast<char*>(const_cast<uint8_t*>(data));
      else
        memcpy(buf.base, data, avail);
      data += avail;
      datalen -= avail;
      bool read_paused = IsReadPaused();
      EmitRead(avail, buf);
      // Reading can be paused while we are processing. If that's
      // the case, we still want to acknowledge the current bytes
      // so that pausing does not throw off our flow control.
      if (read_paused)
        inbound_consumed_data_while_paused_ += avail;
      else
        session_->ExtendStreamOffset(this, avail);
    }
  }

  // When fin != 0, we've received that last chunk of data for this
  // stream, indicating that the stream is no longer readable.
  if (fin) {
    SetFin();
    SetReadClose();
    EmitRead(UV_EOF);
  }
}

inline void QuicStream::IncrementStats(uint64_t datalen) {
  IncrementStat(datalen, &stream_stats_, &stream_stats::bytes_received);

  uint64_t now = uv_hrtime();
  if (stream_stats_.stream_received_at > 0)
    data_rx_rate_.Record(stream_stats_.stream_received_at - now);
  stream_stats_.stream_received_at = now;
  data_rx_size_.Record(datalen);
}

QuicStream* QuicStream::New(
    QuicSession* session,
    uint64_t stream_id) {
  Local<Object> obj;
  if (!session->env()
              ->quicserverstream_constructor_template()
              ->NewInstance(session->env()->context()).ToLocal(&obj)) {
    return nullptr;
  }
  return new QuicStream(session, obj, stream_id);
}

// JavaScript API
namespace {
void QuicStreamGetID(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(static_cast<double>(stream->GetID()));
}

void OpenUnidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  int err = session->OpenUnidirectionalStream(&stream_id);
  if (err != 0) {
    args.GetReturnValue().Set(err);
    return;
  }

  QuicStream* stream = QuicStream::New(session, stream_id);
  args.GetReturnValue().Set(stream->object());
}

void OpenBidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  int err = session->OpenBidirectionalStream(&stream_id);
  if (err != 0) {
    args.GetReturnValue().Set(err);
    return;
  }

  QuicStream* stream = QuicStream::New(session, stream_id);
  args.GetReturnValue().Set(stream->object());
}

void QuicStreamDestroy(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->Destroy();
}

void QuicStreamShutdown(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());

  uint32_t code = NGTCP2_APP_NOERROR;
  uint32_t family = QUIC_ERROR_APPLICATION;
  USE(args[0]->Uint32Value(env->context()).To(&code));
  USE(args[1]->Uint32Value(env->context()).To(&family));

  stream->Session()->ShutdownStream(
      stream->GetID(),
      family == QUIC_ERROR_APPLICATION ? code : 0);
 }
}  // namespace

void QuicStream::Initialize(
    Environment* env,
    Local<Object> target,
    Local<Context> context) {
  Isolate* isolate = env->isolate();
  Local<String> class_name = FIXED_ONE_BYTE_STRING(isolate, "QuicStream");
  Local<FunctionTemplate> stream = FunctionTemplate::New(env->isolate());
  stream->SetClassName(class_name);
  stream->Inherit(AsyncWrap::GetConstructorTemplate(env));
  StreamBase::AddMethods(env, stream);
  Local<ObjectTemplate> streamt = stream->InstanceTemplate();
  streamt->SetInternalFieldCount(StreamBase::kStreamBaseFieldCount);
  streamt->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(stream, "destroy", QuicStreamDestroy);
  env->SetProtoMethod(stream, "shutdownStream", QuicStreamShutdown);
  env->SetProtoMethod(stream, "id", QuicStreamGetID);
  env->set_quicserverstream_constructor_template(streamt);
  target->Set(env->context(),
              class_name,
              stream->GetFunction(env->context()).ToLocalChecked()).FromJust();

  env->SetMethod(target, "openBidirectionalStream", OpenBidirectionalStream);
  env->SetMethod(target, "openUnidirectionalStream", OpenUnidirectionalStream);
}

}  // namespace quic
}  // namespace node
