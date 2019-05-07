#ifndef SRC_NODE_QUIC_STREAM_H_
#define SRC_NODE_QUIC_STREAM_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "async_wrap.h"
#include "env.h"
#include "node_quic_util.h"
#include "stream_base-inl.h"
#include "v8.h"

#include <deque>

namespace node {
namespace quic {

class QuicSession;
class QuicServerSession;

enum quic_stream_flags {
  QUIC_STREAM_FLAG_NONE = 0x0,
  // Writable side has ended
  QUIC_STREAM_FLAG_SHUT = 0x1,
  // Reading has started
  QUIC_STREAM_FLAG_READ_START = 0x2,
  // Reading is paused
  QUIC_STREAM_FLAG_READ_PAUSED = 0x4,
  // Stream is closed
  QUIC_STREAM_FLAG_CLOSED = 0x8,
  // Stream has received all the data it can
  QUIC_STREAM_FLAG_EOS = 0x20
};

class QuicStreamListener : public StreamListener {
 public:
  uv_buf_t OnStreamAlloc(size_t suggested_size) override;
  void OnStreamRead(ssize_t nread, const uv_buf_t& buf) override;
};

class QuicStream : public AsyncWrap,
                   public StreamBase {
 public:
  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target,
      v8::Local<v8::Context> context);

  static QuicStream* New(
      QuicSession* session,
      uint64_t stream_id);

  QuicStream(
      QuicSession* session,
      v8::Local<v8::Object> target,
      uint64_t stream_id);

  ~QuicStream() override;

  uint64_t GetID() const;
  QuicSession* Session();

  virtual int AckedDataOffset(
      uint64_t offset,
      size_t datalen);

  virtual void Close(
      uint16_t app_error_code);

  virtual void Destroy();

  int DoWrite(
      WriteWrap* req_wrap,
      uv_buf_t* bufs,
      size_t nbufs,
      uv_stream_t* send_handle) override;

  inline void IncrementAvailableOutboundLength(
      size_t amount);
  inline void DecrementAvailableOutboundLength(
      size_t amount);

  bool IsAlive() override {
    return !IsDestroyed() && !IsShutdown() && !IsClosing();
  }
  bool IsClosing() override {
    return flags_ & QUIC_STREAM_FLAG_SHUT ||
           flags_ & QUIC_STREAM_FLAG_EOS;
  }
  bool IsDestroyed() { return session_ == nullptr; }
  bool IsEnded() { return flags_ & QUIC_STREAM_FLAG_EOS; }
  bool IsPaused() { return flags_ & QUIC_STREAM_FLAG_READ_PAUSED; }
  bool IsReading() { return flags_ & QUIC_STREAM_FLAG_READ_START; }
  bool IsShutdown() { return flags_ & QUIC_STREAM_FLAG_SHUT; }

  virtual int ReceiveData(
      int fin,
      const uint8_t* data,
      size_t datalen);

  // Required for StreamBase
  int ReadStart() override;

  // Required for StreamBase
  int ReadStop() override;

  // Required for StreamBase
  int DoShutdown(
      ShutdownWrap* req_wrap) override;

  int Send0RTTData();
  int SendPendingData(
      bool retransmit = false);

  AsyncWrap* GetAsyncWrap() override { return this; }

  void MemoryInfo(MemoryTracker* tracker) const override {
    // TODO(@jasnell): Verify that we're tracking the right things here.
    tracker->TrackFieldWithSize(
      "buffer",
      available_outbound_length_,
      "QuicBuffer");
  }

  SET_MEMORY_INFO_NAME(QuicStream)
  SET_SELF_SIZE(QuicStream)

 private:
  QuicStreamListener stream_listener_;
  QuicSession* session_;
  uint32_t flags_;
  uint64_t stream_id_;

  QuicBuffer streambuf_;
  bool should_send_fin_;
  size_t available_outbound_length_;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_STREAM_H_
