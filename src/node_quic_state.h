#ifndef SRC_NODE_QUIC_STATE_H_
#define SRC_NODE_QUIC_STATE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_buffer.h"

namespace node {

enum QuicSocketConfigIndex {
  IDX_QUIC_SOCKET_MAX_STREAM_DATA_BIDI_LOCAL,
  IDX_QUIC_SOCKET_MAX_STREAM_DATA_BIDI_REMOTE,
  IDX_QUIC_SOCKET_MAX_STREAM_DATA_UNI,
  IDX_QUIC_SOCKET_MAX_DATA,
  IDX_QUIC_SOCKET_MAX_STREAMS_BIDI,
  IDX_QUIC_SOCKET_MAX_STREAMS_UNI,
  IDX_QUIC_SOCKET_IDLE_TIMEOUT,
  IDX_QUIC_SOCKET_MAX_PACKET_SIZE,
  IDX_QUIC_SOCKET_ACK_DELAY_EXPONENT,
  IDX_QUIC_SOCKET_DISABLE_MIGRATION,
  IDX_QUIC_SOCKET_MAX_ACK_DELAY,
  IDX_QUIC_SOCKET_CONFIG_COUNT
};

class QuicState {
 public:
  explicit QuicState(v8::Isolate* isolate) :
    root_buffer(
      isolate,
      sizeof(quic_state_internal)),
    quicsocketconfig_buffer(
      isolate,
      offsetof(quic_state_internal, quicsocketconfig_buffer),
      IDX_QUIC_SOCKET_CONFIG_COUNT + 1,
      root_buffer) {
  }

  AliasedBuffer<uint8_t, v8::Uint8Array> root_buffer;
  AliasedBuffer<double, v8::Float64Array> quicsocketconfig_buffer;

 private:
  struct quic_state_internal {
    // doubles first so that they are always sizeof(double)-aligned
    double quicsocketconfig_buffer[IDX_QUIC_SOCKET_CONFIG_COUNT + 1];
  };
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_STATE_H_
