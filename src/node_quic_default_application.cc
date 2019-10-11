#include "node_quic_default_application.h"
#include "node_quic_session-inl.h"

namespace node {
namespace quic {

DefaultApplication::DefaultApplication(
    QuicSession* session) :
    QuicApplication(session) {}

bool DefaultApplication::Initialize() {
  if (!NeedsInit())
    return false;
  SetInitDone();
  return true;
}

}  // namespace quic
}  // namespace node
