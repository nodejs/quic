#ifndef SRC_NODE_QUIC_DEFAULT_APPLICATION_H_
#define SRC_NODE_QUIC_DEFAULT_APPLICATION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_quic_session.h"
#include "node_quic_util.h"
#include "v8.h"

namespace node {

namespace quic {

class DefaultApplication : public QuicApplication {
 public:
  explicit DefaultApplication(QuicSession* session);

  bool Initialize() override;
};

}  // namespace quic

}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_DEFAULT_APPLICATION_H_
