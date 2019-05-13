#ifndef SRC_NODE_QUIC_MONITOR_H_
#define SRC_NODE_QUIC_MONITOR_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "uv.h"
#include <memory>
#include <deque>

namespace node {

class Environment;

namespace quic {

// Forward declaration
class QuicSession;

// One QuicMonitor is created per node::Environment and is invoked on every
// turn of the event loop to check for stale QUIC sessions or retransmissions.
// This is used to avoid creating a timer for every QUIC session
class QuicMonitor {
 public:
  explicit QuicMonitor(Environment* env);
  ~QuicMonitor();

  void MaybeStart();
  void MaybeStop();

  void Schedule(std::shared_ptr<QuicSession> session);

 private:
  static void OnCheck(uv_check_t* handle);
  static void OnCleanup(Environment* env, uv_handle_t* handle, void* arg);
  void Check();
  void Cleanup();

  const Environment* env_;
  uv_check_t handle_;
  std::deque<std::weak_ptr<QuicSession>> scheduled_;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_MONITOR_H_
