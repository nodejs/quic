#include "node_internals.h"
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
  t->fn_();
}

ngtcp2_crypto_level from_ossl_level(OSSL_ENCRYPTION_LEVEL ossl_level) {
  switch (ossl_level) {
  case ssl_encryption_initial:
    return NGTCP2_CRYPTO_LEVEL_INITIAL;
  case ssl_encryption_early_data:
    return NGTCP2_CRYPTO_LEVEL_EARLY;
  case ssl_encryption_handshake:
    return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
  case ssl_encryption_application:
    return NGTCP2_CRYPTO_LEVEL_APP;
  default:
    UNREACHABLE();
  }
}

const char* crypto_level_name(ngtcp2_crypto_level level) {
  switch (level) {
    case NGTCP2_CRYPTO_LEVEL_INITIAL:
      return "initial";
    case NGTCP2_CRYPTO_LEVEL_EARLY:
      return "early";
    case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
      return "handshake";
    case NGTCP2_CRYPTO_LEVEL_APP:
      return "app";
    default:
      UNREACHABLE();
  }
}

QuicError::QuicError(
    int32_t family_,
    uint64_t code_) :
    family(family_),
    code(code_) {}

QuicError::QuicError(
    int32_t family_,
    int code_) :
    family(family_) {
  switch (family) {
    case QUIC_ERROR_CRYPTO:
      code_ |= NGTCP2_CRYPTO_ERROR;
      // Fall-through...
    case QUIC_ERROR_SESSION:
      code = ngtcp2_err_infer_quic_transport_error_code(code_);
      break;
    case QUIC_ERROR_APPLICATION:
      code = code_;
    default:
      UNREACHABLE();
  }
}

QuicError::QuicError(
  Environment* env,
  v8::Local<v8::Value> codeArg,
  v8::Local<v8::Value> familyArg,
  int32_t family_) :
  code(NGTCP2_NO_ERROR),
  family(family_) {
  if (codeArg->IsBigInt()) {
    code = codeArg.As<v8::BigInt>()->Int64Value();
  } else if (codeArg->IsNumber()) {
    double num = 0;
    CHECK(codeArg->NumberValue(env->context()).To(&num));
    code = static_cast<uint64_t>(num);
  }
  if (familyArg->IsNumber()) {
    CHECK(familyArg->Int32Value(env->context()).To(&family));
  }
}

const char* QuicError::GetFamilyName() {
  switch (family) {
    case QUIC_ERROR_SESSION:
      return "Session";
    case QUIC_ERROR_APPLICATION:
      return "Application";
    case QUIC_ERROR_CRYPTO:
      return "Crypto";
    default:
      UNREACHABLE();
  }
}

}  // namespace quic
}  // namespace node
