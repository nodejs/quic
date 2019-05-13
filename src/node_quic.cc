#include "debug_utils.h"
#include "node.h"
#include "env-inl.h"
#include "node_crypto.h"  // SecureContext
#include "node_process.h"
#include "node_quic_session.h"
#include "node_quic_socket.h"
#include "node_quic_stream.h"
#include "node_quic_state.h"
#include "node_quic_util.h"

#include <climits>
#include <algorithm>

namespace node {

using crypto::SecureContext;
using v8::Context;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Value;

namespace quic {

namespace {
// Register the JavaScript callbacks the internal binding will use to report
// status and updates. This is called only once when the quic module is loaded.
void QuicSetCallbacks(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();

#define SETFUNCTION(name, callback)                                           \
  do {                                                                        \
    Local<Value> fn;                                                          \
    CHECK(obj->Get(env->context(),                                            \
                   FIXED_ONE_BYTE_STRING(env->isolate(), name)).ToLocal(&fn));\
    CHECK(fn->IsFunction());                                                  \
    env->set_quic_on_##callback##_function(fn.As<Function>());                \
  } while (0)

  SETFUNCTION("onSocketReady", socket_ready);
  SETFUNCTION("onSocketClose", socket_close);
  SETFUNCTION("onSocketError", socket_error);
  SETFUNCTION("onSessionReady", session_ready);
  SETFUNCTION("onSessionClose", session_close);
  SETFUNCTION("onSessionError", session_error);
  SETFUNCTION("onSessionExtend", session_extend);
  SETFUNCTION("onSessionHandshake", session_handshake);
  SETFUNCTION("onSessionTicket", session_ticket);
  SETFUNCTION("onStreamReady", stream_ready);
  SETFUNCTION("onStreamClose", stream_close);
  SETFUNCTION("onStreamError", stream_error);

#undef SETFUNCTION
}

void QuicProtocolVersion(const FunctionCallbackInfo<Value>& args) {
  args.GetReturnValue().Set(NGTCP2_PROTO_VER);
}

void QuicALPNVersion(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(OneByteString(env->isolate(), NGTCP2_ALPN_H3));
}

int ALPN_Select_Proto_CB(SSL* ssl,
                         const unsigned char** out,
                         unsigned char* outlen,
                         const unsigned char* in,
                         unsigned int inlen,
                         void* arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  const uint8_t* alpn;
  size_t alpnlen;
  uint32_t version = session->GetNegotiatedVersion();

  switch (version) {
  case NGTCP2_PROTO_VER:
    alpn = reinterpret_cast<const uint8_t*>(NGTCP2_ALPN_H3);
    alpnlen = strsize(NGTCP2_ALPN_H3);
    break;
  default:
    // Unexpected QUIC protocol version
    return SSL_TLSEXT_ERR_NOACK;
  }

  for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
    if (std::equal(alpn, alpn + alpnlen, p)) {
      *out = p + 1;
      *outlen = *p;
      return SSL_TLSEXT_ERR_OK;
    }
  }

  *out = alpn + 1;
  *outlen = alpn[0];

  return SSL_TLSEXT_ERR_OK;
}

int Client_Transport_Params_Add_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char** out,
    size_t* outlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* add_arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));

  ngtcp2_transport_params params;
  session->GetLocalTransportParams(&params);

  constexpr size_t bufsize = 64;
  auto buf = std::make_unique<uint8_t[]>(bufsize);

  auto nwrite = ngtcp2_encode_transport_params(
      buf.get(), bufsize,
      NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
      &params);
  if (nwrite < 0) {
    // Error encoding transport params
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  *out = buf.release();
  *outlen = static_cast<size_t>(nwrite);

  return 1;
}

int Server_Transport_Params_Add_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char** out,
    size_t* outlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* add_arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));

  ngtcp2_transport_params params;
  session->GetLocalTransportParams(&params);

  constexpr size_t bufsize = 512;

  auto buf = std::make_unique<uint8_t[]>(bufsize);

  ssize_t nwrite = ngtcp2_encode_transport_params(
      buf.get(), bufsize,
      NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);
  if (nwrite < 0) {
    // Error encoding transport params
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  *out = buf.release();
  *outlen = static_cast<size_t>(nwrite);

  return 1;
}

void Transport_Params_Free_CB(SSL* ssl,
                              unsigned int ext_type,
                              unsigned int context,
                              const unsigned char* out,
                              void* add_arg) {
  delete[] const_cast<unsigned char*>(out);
}

int Client_Transport_Params_Parse_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char* in,
    size_t inlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* parse_arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));

  ngtcp2_transport_params params;

  if (ngtcp2_decode_transport_params(
          &params,
          NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
          in, inlen) != 0) {
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  if (session->SetRemoteTransportParams(&params) != 0) {
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  return 1;
}

int Server_Transport_Params_Parse_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char* in,
    size_t inlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* parse_arg) {
  if (context != SSL_EXT_CLIENT_HELLO) {
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));

  ngtcp2_transport_params params;

  if (ngtcp2_decode_transport_params(
          &params,
          NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
          in, inlen) != 0) {
    // Error decoding transport params
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  if (session->SetRemoteTransportParams(&params) != 0) {
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  return 1;
}

void InitKeylog(Environment* env, SecureContext* sc) {
  static const char LF = '\n';
  if (env->options()->has_quic_keylog) {
    if (env->options()->quic_keylog_file.empty()) {
      DiagnosticFilename filename(env, "quic", "keylog");
      env->options()->quic_keylog_file = *filename;
    }

    // Emitting keylog entries is inherently insecure. Warn the user.
    ProcessEmitWarning(
      env,
      "Emitting QUIC TLS secrets to file: %s",
      env->options()->quic_keylog_file.c_str());

    SSL_CTX_set_keylog_callback(**sc, [](const SSL* ssl, const char* line) {
      QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
      Environment* env = session->env();
      uv_fs_t req;
      int fd =
          uv_fs_open(
              env->event_loop(),
              &req,
              env->options()->quic_keylog_file.c_str(),
              O_CREAT | O_APPEND, 0644, nullptr);
      uv_fs_req_cleanup(&req);
      // TODO(@jasnell): Error handling
      CHECK_GE(fd, 0);

      uv_buf_t buf = uv_buf_init(const_cast<char*>(line), strlen(line));
      CHECK_GE(
        uv_fs_write(env->event_loop(), &req, fd, &buf, 1, -1, nullptr), 0);
      buf = uv_buf_init(const_cast<char*>(&LF), 1);
      CHECK_GE(
        uv_fs_write(env->event_loop(), &req, fd, &buf, 1, -1, nullptr), 0);

      CHECK_EQ(uv_fs_close(env->event_loop(), &req, fd, nullptr), 0);
      uv_fs_req_cleanup(&req);
    });
  }
}

// Sets QUIC specific configuration options for the SecureContext.
// It's entirely likely that there's a better way to do this, but
// for now this works.
void QuicInitSecureContext(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsObject());  // Secure Context
  CHECK(args[1]->IsString());  // groups
  SecureContext* sc;
  ASSIGN_OR_RETURN_UNWRAP(&sc, args[0].As<Object>(),
                          args.GetReturnValue().Set(UV_EBADF));

  constexpr auto ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_CIPHER_SERVER_PREFERENCE |
                            SSL_OP_NO_ANTI_REPLAY;
  SSL_CTX_set_options(**sc, ssl_opts);
  SSL_CTX_clear_options(**sc, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
  SSL_CTX_set_mode(**sc, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_QUIC_HACK);
  SSL_CTX_set_default_verify_paths(**sc);
  SSL_CTX_set_max_early_data(**sc, std::numeric_limits<uint32_t>::max());
  SSL_CTX_set_alpn_select_cb(**sc, ALPN_Select_Proto_CB, nullptr);
  CHECK_EQ(
      SSL_CTX_add_custom_ext(
          **sc,
          NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
          SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
          Server_Transport_Params_Add_CB,
          Transport_Params_Free_CB, nullptr,
          Server_Transport_Params_Parse_CB,
          nullptr), 1);

  const node::Utf8Value groups(env->isolate(), args[1]);
  if (!SSL_CTX_set1_groups_list(**sc, *groups)) {
    unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
    if (!err)
      return env->ThrowError("Failed to set groups");
    return crypto::ThrowCryptoError(env, err);
  }

  InitKeylog(env, sc);
}

void QuicInitSecureContextClient(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsObject());  // Secure Context
  CHECK(args[1]->IsString());  // groups
  SecureContext* sc;
  ASSIGN_OR_RETURN_UNWRAP(&sc, args[0].As<Object>(),
                          args.GetReturnValue().Set(UV_EBADF));

  SSL_CTX_set_mode(**sc, SSL_MODE_QUIC_HACK);
  SSL_CTX_clear_options(**sc, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
  SSL_CTX_set_default_verify_paths(**sc);

  CHECK_EQ(SSL_CTX_add_custom_ext(
      **sc,
      NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
      SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
      Client_Transport_Params_Add_CB,
      Transport_Params_Free_CB,
      nullptr,
      Client_Transport_Params_Parse_CB,
      nullptr), 1);


  const node::Utf8Value groups(env->isolate(), args[1]);
  if (!SSL_CTX_set1_groups_list(**sc, *groups)) {
    unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
    if (!err)
      return env->ThrowError("Failed to set groups");
    return crypto::ThrowCryptoError(env, err);
  }

  SSL_CTX_set_session_cache_mode(
    **sc, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(**sc, [](SSL* ssl, SSL_SESSION* session) {
    QuicClientSession* s =
        static_cast<QuicClientSession*>(
            SSL_get_app_data(ssl));
    return s->SetSession(session);
  });

  InitKeylog(env, sc);
}
}  // namespace


void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  std::unique_ptr<QuicState> state(new QuicState(isolate));
#define SET_STATE_TYPEDARRAY(name, field)             \
  target->Set(context,                                \
              FIXED_ONE_BYTE_STRING(isolate, (name)), \
              (field)).FromJust()
  SET_STATE_TYPEDARRAY(
    "sessionConfig", state->quicsessionconfig_buffer.GetJSArray());
#undef SET_STATE_TYPEDARRAY

  env->set_quic_state(std::move(state));

  QuicSocket::Initialize(env, target, context);
  QuicServerSession::Initialize(env, target, context);
  QuicClientSession::Initialize(env, target, context);
  QuicStream::Initialize(env, target, context);

  env->SetMethod(target,
                 "setCallbacks",
                 QuicSetCallbacks);
  env->SetMethod(target,
                 "protocolVersion",
                 QuicProtocolVersion);
  env->SetMethod(target,
                 "alpnVersion",
                 QuicALPNVersion);
  env->SetMethod(target,
                 "initSecureContext",
                 QuicInitSecureContext);
  env->SetMethod(target,
                 "initSecureContextClient",
                 QuicInitSecureContextClient);

  Local<Object> constants = Object::New(env->isolate());
  NODE_DEFINE_CONSTANT(constants, AF_INET);
  NODE_DEFINE_CONSTANT(constants, AF_INET6);
  NODE_DEFINE_CONSTANT(constants, SSL_OP_ALL);
  NODE_DEFINE_CONSTANT(constants, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
  NODE_DEFINE_CONSTANT(constants, SSL_OP_SINGLE_ECDH_USE);
  NODE_DEFINE_CONSTANT(constants, SSL_OP_CIPHER_SERVER_PREFERENCE);
  NODE_DEFINE_CONSTANT(constants, SSL_OP_NO_ANTI_REPLAY);
  NODE_DEFINE_CONSTANT(constants, UV_UDP_REUSEADDR);
  NODE_DEFINE_CONSTANT(constants, UV_UDP_IPV6ONLY);
  NODE_DEFINE_CONSTANT(constants, UV_EBADF);
  NODE_DEFINE_CONSTANT(constants, DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL);
  NODE_DEFINE_CONSTANT(constants, TLS1_3_VERSION);

  NODE_DEFINE_CONSTANT(constants, NGTCP2_DEFAULT_MAX_ACK_DELAY);

  NODE_DEFINE_CONSTANT(constants, ERR_INVALID_REMOTE_TRANSPORT_PARAMS);
  NODE_DEFINE_CONSTANT(constants, ERR_INVALID_TLS_SESSION_TICKET);

#define V(idx, name, def)                                                      \
  NODE_DEFINE_CONSTANT(constants, IDX_QUIC_SESSION_## idx ##_DEFAULT);
  QUICSESSION_CONFIG(V)
#undef V

  target->Set(context,
              env->constants_string(),
              constants).FromJust();
}

}  // namespace quic
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)
