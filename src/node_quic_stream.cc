#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "node.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "stream_base-inl.h"
#include "node_quic_session.h"
#include "node_quic_stream.h"
#include "node_quic_socket.h"
#include "node_quic_util.h"
#include "v8.h"

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
  size_t offset = 0;  // TODO(@jasnell): Proper offset
  stream->CallJSOnreadMethod(nread, buffer.ToArrayBuffer(), offset);
}

QuicStream::QuicStream(
    QuicSession* session,
    Local<Object> wrap,
    uint64_t stream_id) :
    AsyncWrap(session->env(), wrap, AsyncWrap::PROVIDER_QUICSTREAM),
    StreamBase(session->env()),
    session_(session),
    flags_(0),
    stream_id_(stream_id),
    available_outbound_length_(0),
    streambuf_idx_(0),
    tx_stream_offset_(0),
    should_send_fin_(false) {
  CHECK_NOT_NULL(session);
  StreamBase::AttachToObject(GetObject());
  PushStreamListener(&stream_listener_);
  session->AddStream(this);
}

QuicStream::~QuicStream() {
  // Check that Destroy() has been called
  CHECK_NULL(session_);
}

void QuicStream::Close(
    uint16_t app_error_code) {
  Debug(this, "Stream %llu closed with code %d", GetID(), app_error_code);
  HandleScope scope(env()->isolate());
  flags_ |= QUIC_STREAM_FLAG_CLOSED;
  Local<Value> arg = Number::New(env()->isolate(), app_error_code);
  MakeCallback(env()->quic_on_stream_close_function(), 1, &arg);
}

void QuicStream::Destroy() {
  QuicBuffer::Cancel(&streambuf_);
  session_->RemoveStream(stream_id_);
  session_ = nullptr;
}

int QuicStream::DoShutdown(ShutdownWrap* req_wrap) {
  if (IsDestroyed())
    return UV_EPIPE;

  Debug(this, "Writable side shutdown");
  flags_ |= QUIC_STREAM_FLAG_SHUT;

  return 1;
}

int QuicStream::DoWrite(
    WriteWrap* req_wrap,
    uv_buf_t* bufs,
    size_t nbufs,
    uv_stream_t* send_handle) {

  CHECK_NULL(send_handle);
  if (IsDestroyed()) {  // or !IsWritable
    req_wrap->Done(UV_EOF);
    return 0;
  }
  // Buffers written must be held on to until acked. The callback
  // passed in here will be callled when the ack is received.
  // TODO(@jasnell): For now, the data will be held onto for
  // pretty much eternity, and the implementation will retry an
  // unlimited number of times. We need to constrain that to
  // fail reasonably after a given number of attempts.
  // Specifically, we need to ensure that all of the data is
  // cleaned up when the stream is destroyed, even if it hasn't
  // been acknowledged.
  for (size_t i = 0; i < nbufs; ++i) {
    streambuf_.emplace_back(
        reinterpret_cast<uint8_t*>(bufs[i].base),
        bufs[i].len,
        [&](int status, void* user_data, size_t len) {
          // TODO(@jasnell): Do we need any async magic happening here.
          WriteWrap* wrap = static_cast<WriteWrap*>(user_data);
          CHECK_NOT_NULL(wrap);
          DecrementAvailableOutboundLength(len);
          wrap->Done(status);
        },
        // Persist references to the WriteWrap so it is not GC'd
        // while we are waiting for the ack to arrive.
        req_wrap,
        req_wrap->object());
    IncrementAvailableOutboundLength(bufs[i].len);
  }
  return 0;
}

uint64_t QuicStream::GetID() const {
  return stream_id_;
}

QuicSession* QuicStream::Session() {
  return session_;
}

int QuicStream::AckedDataOffset(
    uint64_t offset,
    size_t datalen) {
  QuicBuffer::AckData(
      &streambuf_,
      &streambuf_idx_,
      &tx_stream_offset_,
      offset + datalen);
  if (streambuf_.empty() && flags_ & QUIC_STREAM_FLAG_SHUT) {
    if (session_->ShutdownStreamWrite(stream_id_) != 0) {
      return -1;
    }
  }
  return 0;
}

int QuicStream::Send0RTTData() {
  int err;
  for (auto it = std::begin(streambuf_) + streambuf_idx_;
       it != std::end(streambuf_); ++it) {
    auto& v = *it;
    bool fin = should_send_fin_ &&
               it + 1 == std::end(streambuf_);
    err = session_->Send0RTTStreamData(this, fin, &v);
    if (err != 0)
      return err;
    if (v.size() > 0)
      break;
    ++streambuf_idx_;
  }

  return 0;
}

int QuicStream::SendPendingData(bool retransmit) {
  int err;
  if (streambuf_idx_ == streambuf_.size()) {
    if (should_send_fin_) {
      QuicBuffer buf(static_cast<uint8_t*>(nullptr), 0);
      if (session_->SendStreamData(this, 1, &buf) != 0)
        return -1;
    }
    return 0;
  }

  for (auto it = std::begin(streambuf_) + streambuf_idx_;
       it != std::end(streambuf_); ++it) {
    auto& v = *it;
    bool fin = should_send_fin_ &&
               streambuf_idx_ == streambuf_.size() - 1;
    err = session_->SendStreamData(this, fin, &v);
    if (err != 0)
      return err;
    if (v.size() > 0)
      break;
    ++streambuf_idx_;
  }
  return 0;
}

inline void QuicStream::IncrementAvailableOutboundLength(size_t amount) {
  available_outbound_length_ += amount;
}

inline void QuicStream::DecrementAvailableOutboundLength(size_t amount) {
  available_outbound_length_ -= amount;
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

void QuicStream::ResetShouldSendFin() {
  should_send_fin_ = false;
}

int QuicStream::ReadStart() {
  CHECK(!this->IsDestroyed());
  Debug(this, "Reading started.");
  flags_ |= QUIC_STREAM_FLAG_READ_START;
  flags_ &= ~QUIC_STREAM_FLAG_READ_PAUSED;

  // Flush data to JS here?

  return 0;
}

int QuicStream::ReadStop() {
  CHECK(!this->IsDestroyed());
  if (!IsReading())
    return 0;
  Debug(this, "Reading stopped");
  flags_ |= QUIC_STREAM_FLAG_READ_PAUSED;
  return 0;
}

int QuicStream::ReceiveData(
    int fin,
    const uint8_t* data,
    size_t datalen) {
  Debug(this, "Receiving %d bytes of data", datalen);
  HandleScope scope(env()->isolate());
  do {
    uv_buf_t buf = EmitAlloc(datalen);
    ssize_t avail = datalen;
    if (static_cast<ssize_t>(buf.len) < avail)
      avail = buf.len;

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
    Debug(this, "Emitting %d bytes of data", avail);
    EmitRead(avail, buf);
  } while (datalen != 0);

  if (fin) {
    Debug(this, "Emitting EOF");
    EmitRead(UV_EOF);
    Session()->ShutdownStreamRead(stream_id_);
  }

  return 0;
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
  streamt->SetInternalFieldCount(StreamBase::kStreamBaseField + 1);
  streamt->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(stream,
                      "destroy",
                      QuicStreamDestroy);
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
