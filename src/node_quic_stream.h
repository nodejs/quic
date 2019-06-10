#ifndef SRC_NODE_QUIC_STREAM_H_
#define SRC_NODE_QUIC_STREAM_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "memory_tracker-inl.h"
#include "async_wrap.h"
#include "env.h"
#include "histogram-inl.h"
#include "node_quic_util.h"
#include "stream_base-inl.h"
#include "v8.h"

#include <deque>

namespace node {
namespace quic {

class QuicSession;
class QuicServerSession;

class QuicStreamListener : public StreamListener {
 public:
  uv_buf_t OnStreamAlloc(size_t suggested_size) override;
  void OnStreamRead(ssize_t nread, const uv_buf_t& buf) override;
};

// QuicStream's are simple data flows that, fortunately, do not
// require much. They may be:
//
// * Bidirectional or Unidirectional
// * Server or Client Initiated
//
// The flow direction and origin of the stream are important in
// determining the write and read state (Open or Closed). Specifically:
//
// A Unidirectional stream originating with the Server is:
//
// * Server Writable (Open) but not Client Writable (Closed)
// * Client Readable (Open) but not Server Readable (Closed)
//
// Likewise, a Unidirectional stream originating with the
// Client is:
//
// * Client Writable (Open) but not Server Writable (Closed)
// * Server Readable (Open) but not Client Readable (Closed)
//
// Bidirectional Stream States
// +------------+--------------+--------------------+---------------------+
// |            | Initiated By | Initial Read State | Initial Write State |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Server     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Client     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Server     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Client     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
//
// Unidirectional Stream States
// +------------+--------------+--------------------+---------------------+
// |            | Initiated By | Initial Read State | Initial Write State |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Server     |       Closed       |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Client     |        Open        |        Closed       |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Server     |        Open        |        Closed       |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Client     |       Closed       |         Open        |
// +------------+--------------+--------------------+---------------------+
//
// The Closed states is terminal. A stream may be destroyed
// naturally when both the read and write states are Closed.
// Although, any stream may be abruptly terminated at any time.
//
// A stream that is Open Writable may have data pending or not.
//
// A QuicSession should only attempt to send stream data when (a) there
// is data pending to send of (b) there is no remaining data to send and
// the writable side is ready to transition to Closed.
class QuicStream : public AsyncWrap,
                   public StreamBase {
 public:
  enum QuicStreamDirection {
    QUIC_STREAM_BIRECTIONAL,
    QUIC_STREAM_UNIDIRECTIONAL
  };

  enum QuicStreamOrigin {
    QUIC_STREAM_SERVER,
    QUIC_STREAM_CLIENT
  };

  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target,
      v8::Local<v8::Context> context);

  static QuicStream* New(QuicSession* session, uint64_t stream_id);

  ~QuicStream() override;

  inline QuicStreamDirection GetDirection() const {
    return stream_id_ & 0b10 ?
        QUIC_STREAM_UNIDIRECTIONAL :
        QUIC_STREAM_BIRECTIONAL;
  }

  inline QuicStreamOrigin GetOrigin() const {
    return stream_id_ & 0b01 ?
        QUIC_STREAM_SERVER :
        QUIC_STREAM_CLIENT;
  }

  uint64_t GetID() const { return stream_id_; }

  inline bool IsDestroyed() {
    return session_ == nullptr;
  }

  inline bool IsWritable() {
    return (flags_ & QUICSTREAM_FLAG_WRITE) == 0;
  }

  inline bool IsReadable() {
    return (flags_ & QUICSTREAM_FLAG_READ) == 0;
  }

  inline bool IsReadStarted() {
    return flags_ & QUICSTREAM_FLAG_READ_STARTED;
  }

  inline bool IsReadPaused() {
    return flags_ & QUICSTREAM_FLAG_READ_PAUSED;
  }

  bool IsAlive() override {
    return !IsDestroyed() && !IsClosing();
  }

  bool IsClosing() override {
    return !IsWritable() && !IsReadable();
  }

  QuicSession* Session() { return session_; }

  virtual void AckedDataOffset(uint64_t offset, size_t datalen);

  virtual void Close(uint16_t app_error_code = 0);

  virtual void Reset(uint64_t final_size, uint16_t app_error_code = 0);

  virtual void Destroy();

  int DoWrite(
      WriteWrap* req_wrap,
      uv_buf_t* bufs,
      size_t nbufs,
      uv_stream_t* send_handle) override;

  inline void IncrementAvailableOutboundLength(size_t amount);
  inline void DecrementAvailableOutboundLength(size_t amount);

  virtual void ReceiveData(int fin, const uint8_t* data, size_t datalen);

  // Required for StreamBase
  int ReadStart() override;

  // Required for StreamBase
  int ReadStop() override;

  // Required for StreamBase
  int DoShutdown(ShutdownWrap* req_wrap) override;

  size_t DrainInto(
    std::vector<ngtcp2_vec>* vec,
    QuicBuffer::drain_from from);

  void Commit(size_t count);

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
  QuicStream(
      QuicSession* session,
      v8::Local<v8::Object> target,
      uint64_t stream_id);

  inline void SetInitialFlags();

  enum Flags {
    QUICSTREAM_FLAG_INITIAL = 0,
    QUICSTREAM_FLAG_READ = 1,
    QUICSTREAM_FLAG_WRITE = 2,
    QUICSTREAM_FLAG_READ_STARTED = 3,
    QUICSTREAM_FLAG_READ_PAUSED = 8
  };

  inline void SetWriteClose() {
    flags_ |= QUICSTREAM_FLAG_WRITE;
  }

  inline void SetReadClose() {
    flags_ |= QUICSTREAM_FLAG_READ;
  }

  inline void SetReadStart() {
    flags_ |= QUICSTREAM_FLAG_READ_STARTED;
  }

  inline void SetReadPause() {
    flags_ |= QUICSTREAM_FLAG_READ_PAUSED;
  }

  inline void SetReadResume() {
    flags_ &= QUICSTREAM_FLAG_READ_PAUSED;
  }

  inline void IncrementStats(uint64_t datalen);

  QuicStreamListener stream_listener_;
  QuicSession* session_;
  uint64_t stream_id_;
  uint32_t flags_;

  QuicBuffer streambuf_;
  size_t available_outbound_length_;
  size_t inbound_consumed_data_while_paused_;

  struct stream_stats {
    // The timestamp at which the stream was created
    uint64_t created_at;
    // The timestamp at which the stream most recently sent data
    uint64_t stream_sent_at;
    // The timestamp at which the stream most recently received data
    uint64_t stream_received_at;
    // The timestamp at which the stream most recently received an
    // acknowledgement for data
    uint64_t stream_acked_at;
    // The timestamp at which a graceful close started
    uint64_t closing_at;
    // The total number of bytes received
    uint64_t bytes_received;
    // The total number of bytes sent
    uint64_t bytes_sent;
  };
  stream_stats stream_stats_{0, 0, 0, 0, 0, 0, 0};

  // data_rx_rate_ measures the elapsed time between data packets
  // for this stream. When used in combination with the data_rx_size,
  // this can be used to track the overall data throughput over time
  // for the stream. Specifically, this can be used to detect
  // potentially bad acting peers that are sending many small chunks
  // of data too slowly in an attempt to DOS the peer.
  Histogram data_rx_rate_;

  // data_rx_size_ measures the size of data packets for this stream
  // over time. When used in combination with the data_rx_rate_,
  // this can be used to track the overall data throughout over time
  // for the stream. Specifically, this can be used to detect
  // potentially bad acting peers that are sending many small chunks
  // of data too slowly in an attempt to DOS the peer.
  Histogram data_rx_size_;

  // data_rx_ack_ measures the elapsed time between data acks
  // for this stream. This data can be used to detect peers that are
  // generally taking too long to acknowledge sent stream data.
  Histogram data_rx_ack_;

  // data_rx_acksize_ measures the size of data acks for this stream.
  // This data can be used to detect potentially malicious peers that
  // are acknoledging data at too slow of a rate.
  Histogram data_rx_acksize_;

  AliasedBigUint64Array stats_buffer_;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_STREAM_H_
