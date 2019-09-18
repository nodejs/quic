#include "node_quic_util.h"
#include "env-inl.h"
#include "util-inl.h"
#include "uv.h"

namespace node {
namespace quic {

void Timer::Free(Timer* timer) {
  timer->env_->CloseHandle(
      reinterpret_cast<uv_handle_t*>(&timer->timer_),
      [&](uv_handle_t* timer) {
        Timer* t = ContainerOf(
            &Timer::timer_,
            reinterpret_cast<uv_timer_t*>(timer));
        delete t;
      });
}

void Timer::OnTimeout(uv_timer_t* timer) {
  Timer* t = ContainerOf(&Timer::timer_, timer);
  t->OnTimeout();
}

void Timer::CleanupHook(void* data) {
  Free(static_cast<Timer*>(data));
}

}  // namespace quic
}  // namespace node
