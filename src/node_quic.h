#ifndef SRC_NODE_QUIC_H_
#define SRC_NODE_QUIC_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "ngtcp2/ngtcp2.h"
#include "node_internals.h"
#include "v8.h"

namespace node {
namespace quic {

class Quic {
 public:
  Quic();
  ~Quic();
  static void ProtocolVersion(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ALPNVersion(const v8::FunctionCallbackInfo<v8::Value>& args);

 private:
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_H_
