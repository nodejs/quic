#include "base_object-inl.h"
#include "env.h"
#include "env-inl.h"
#include "node_quic_monitor.h"
#include "node_quic_session.h"

namespace node {
namespace quic {

QuicMonitor::QuicMonitor(Environment* env) : env_(env) {
  uv_check_init(env_->event_loop(), &handle_);
  env->RegisterHandleCleanup(
      reinterpret_cast<uv_handle_t*>(&handle_), OnCleanup, nullptr);
}

QuicMonitor::~QuicMonitor() {
  CHECK_EQ(scheduled_.size(), 0);
}

void QuicMonitor::Cleanup() {
  scheduled_.clear();
  uv_check_stop(&handle_);
}

void QuicMonitor::OnCleanup(Environment* env, uv_handle_t* handle, void* arg) {
  QuicMonitor* monitor =
      ContainerOf(
          &QuicMonitor::handle_,
          reinterpret_cast<uv_check_t*>(handle));
  monitor->Cleanup();
}

void QuicMonitor::MaybeStart() {
  // The Monitor will start if there are items scheduled in the deque and
  // the monitor is not already active
  if (uv_is_active(reinterpret_cast<uv_handle_t*>(&handle_)) ||
      scheduled_.empty()) {
    return;
  }
  uv_check_start(&handle_, OnCheck);
}

void QuicMonitor::MaybeStop() {
  // The Monitor will stop if it is active and there are no items remaining
  // in the queue
  if (uv_is_active(reinterpret_cast<uv_handle_t*>(&handle_)) &&
      scheduled_.empty()) {
    uv_check_stop(&handle_);
  }
}

void QuicMonitor::Schedule(std::shared_ptr<QuicSession> session) {
  scheduled_.push_back(session);
  MaybeStart();
}

void QuicMonitor::Check() {
  std::deque<std::weak_ptr<QuicSession>> batch;
  scheduled_.swap(batch);
  CHECK(scheduled_.empty());
  while (!batch.empty()) {
    auto item = batch.front();
    if (auto session = item.lock()) {
      // If it did not timeout, we're still waiting,
      // check again next iteration. If MaybeTimeout
      // returns true, then the timeout was handled
      // and we do not have to reschedule.
      if (!session->MaybeTimeout())
        scheduled_.push_back(item);
    }
    // If lock failed, the QuicSession has already
    // been destroyed and we don't have to worry
    // about it any more.
    batch.pop_front();
  }
  MaybeStop();
}

void QuicMonitor::OnCheck(uv_check_t* handle) {
  QuicMonitor* monitor = ContainerOf(&QuicMonitor::handle_, handle);
  monitor->Check();
}

}  // namespace quic
}  // namespace node
