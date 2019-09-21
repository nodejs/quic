#ifndef SRC_NODE_QUIC_SESSION_INL_H_
#define SRC_NODE_QUIC_SESSION_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_quic_session.h"

#include <algorithm>

namespace node {

namespace quic {

void QuicSession::CheckAllocatedSize(size_t previous_size) const {
  CHECK_GE(current_ngtcp2_memory_, previous_size);
}

void QuicSession::IncreaseAllocatedSize(size_t size) {
  current_ngtcp2_memory_ += size;
}

void QuicSession::DecreaseAllocatedSize(size_t size) {
  current_ngtcp2_memory_ -= size;
}

void QuicSession::SetTLSAlert(int err) {
  SetLastError(InitQuicError(QUIC_ERROR_CRYPTO, err));
}

void QuicSession::SetLastError(QuicError error) {
  last_error_ = error;
}

void QuicSession::SetLastError(QuicErrorFamily family, uint64_t code) {
  SetLastError({ family, code });
}

void QuicSession::SetLastError(QuicErrorFamily family, int code) {
  SetLastError(family, ngtcp2_err_infer_quic_transport_error_code(code));
}

bool QuicSession::IsInClosingPeriod() {
  return ngtcp2_conn_is_in_closing_period(Connection());
}

bool QuicSession::IsInDrainingPeriod() {
  return ngtcp2_conn_is_in_draining_period(Connection());
}

// Locate the QuicStream with the given id or return nullptr
QuicStream* QuicSession::FindStream(int64_t id) {
  auto it = streams_.find(id);
  if (it == std::end(streams_))
    return nullptr;
  return it->second.get();
}

bool QuicSession::HasStream(int64_t id) {
  return streams_.find(id) != std::end(streams_);
}

QuicError QuicSession::GetLastError() const { return last_error_; }

bool QuicSession::IsGracefullyClosing() const {
  return IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING);
}

bool QuicSession::IsDestroyed() const {
  return IsFlagSet(QUICSESSION_FLAG_DESTROYED);
}

void QuicSession::StartGracefulClose() {
  SetFlag(QUICSESSION_FLAG_GRACEFUL_CLOSING);
  session_stats_.closing_at = uv_hrtime();
}

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_SESSION_INL_H_
