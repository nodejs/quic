#include "aliased_buffer.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "ngtcp2/ngtcp2.h"
#include "node.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "node_quic_session.h"
#include "node_quic_socket.h"
#include "node_quic_stream.h"
#include "node_quic_state.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"
#include "node_crypto_clienthello-inl.h" // ClientHelloParser

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <array>
#include <functional>
#include <type_traits>
#include <utility>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace node {

using crypto::EntropySource;
using crypto::SecureContext;

using v8::Context;
using v8::Float64Array;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

namespace quic {

namespace {
int BIO_Write(
    BIO* b,
    const char* buf,
    int len) {
  return -1;
}

int BIO_Read(
    BIO* b,
    char* buf,
    int len) {
  BIO_clear_retry_flags(b);
  QuicSession* session = static_cast<QuicSession*>(BIO_get_data(b));
  len = session->ReadPeerHandshake(reinterpret_cast<uint8_t*>(buf), len);
  if (len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }
  return len;
}

int BIO_Puts(
    BIO*b,
    const char* str) {
  return BIO_Write(b, str, strlen(str));
}

int BIO_Gets(
    BIO* b,
    char* buf,
    int len) {
  return -1;
}

long BIO_Ctrl(
    BIO* b,
    int cmd,
    long num,
    void *ptr) {
  return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

int BIO_Create(
    BIO* b) {
  BIO_set_init(b, 1);
  return 1;
}

int BIO_Destroy(
    BIO* b) {
  return b == nullptr ? 0 : 1;
}

BIO_METHOD* CreateBIOMethod() {
  static BIO_METHOD* method = nullptr;

  if (method == nullptr) {
    method = BIO_meth_new(BIO_TYPE_FD, "bio");
    BIO_meth_set_write(method, BIO_Write);
    BIO_meth_set_read(method, BIO_Read);
    BIO_meth_set_puts(method, BIO_Puts);
    BIO_meth_set_gets(method, BIO_Gets);
    BIO_meth_set_ctrl(method, BIO_Ctrl);
    BIO_meth_set_create(method, BIO_Create);
    BIO_meth_set_destroy(method, BIO_Destroy);
  }
  return method;
}

void MessageCB(
    int write_p,
    int version,
    int content_type,
    const void* buf,
    size_t len,
    SSL* ssl,
    void* arg) {
  if (!write_p)
    return;

  QuicSession* session = static_cast<QuicSession*>(arg);
  const uint8_t* msg = reinterpret_cast<const uint8_t*>(buf);

  switch (content_type) {
    case SSL3_RT_HANDSHAKE:
      break;
    case SSL3_RT_ALERT:
      CHECK_EQ(len, 2);
      if (msg[0] != 2 /* FATAL */)
        return;
      session->SetTLSAlert(msg[1]);
      return;
    default:
      return;
  }

  session->WriteHandshake(reinterpret_cast<const uint8_t*>(buf), len);
}

int KeyCB(
    SSL* ssl,
    int name,
    const unsigned char* secret,
    size_t secretlen,
    void* arg) {
  QuicSession* session = static_cast<QuicSession*>(arg);

  if (session->OnKey(name, secret, secretlen) != 0)
    return 0;

  return 1;
}

// NOTE(@jasnell): The majority of this is adapted directly from the
// example code in https://github.com/ngtcp2/ngtcp2. It can likely
// use a refactor to be more Node-ish

// inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
// template can take functions returning other than void.
template <typename F, typename... T> struct Defer {
  Defer(F &&f, T &&... t)
      : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
  Defer(Defer &&o) noexcept : f(std::move(o.f)) {}
  ~Defer() { f(); }

  using ResultType = typename std::result_of<typename std::decay<F>::type(
      typename std::decay<T>::type...)>::type;
  std::function<ResultType()> f;
};

template <typename F, typename... T> Defer<F, T...> defer(F &&f, T &&... t) {
  return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
}

inline void prf_sha256(CryptoContext& ctx) { ctx.prf = EVP_sha256(); }

inline void aead_aes_128_gcm(CryptoContext& ctx) {
  ctx.aead = EVP_aes_128_gcm();
  ctx.hp = EVP_aes_128_ctr();
}

inline size_t aead_key_length(const CryptoContext &ctx) {
  return EVP_CIPHER_key_length(ctx.aead);
}

inline size_t aead_nonce_length(const CryptoContext &ctx) {
  return EVP_CIPHER_iv_length(ctx.aead);
}

inline size_t aead_tag_length(const CryptoContext &ctx) {
  if (ctx.aead == EVP_aes_128_gcm() || ctx.aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if (ctx.aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  UNREACHABLE();
}

inline ssize_t Encrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const CryptoContext& ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  size_t taglen = aead_tag_length(ctx);

  if (destlen < plaintextlen + taglen)
    return -1;

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr)
    return -1;

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_EncryptInit_ex(actx, ctx.aead, nullptr, nullptr, nullptr) != 1)
    return -1;

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN,
                          noncelen, nullptr) != 1) {
    return -1;
  }

  if (EVP_EncryptInit_ex(actx, nullptr, nullptr, key, nonce) != 1)
    return -1;

  size_t outlen = 0;
  int len;

  if (EVP_EncryptUpdate(actx, nullptr, &len, ad, adlen) != 1)
    return -1;

  if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1)
    return -1;

  outlen = len;

  if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1)
    return -1;

  outlen += len;

  CHECK_LE(outlen + taglen, destlen);

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG,
                          taglen, dest + outlen) != 1) {
    return -1;
  }

  outlen += taglen;

  return outlen;
}

inline ssize_t Decrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const CryptoContext& ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  size_t taglen = aead_tag_length(ctx);

  if (taglen > ciphertextlen || destlen + taglen < ciphertextlen)
    return -1;

  ciphertextlen -= taglen;
  auto tag = ciphertext + ciphertextlen;

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr)
    return -1;

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_DecryptInit_ex(actx, ctx.aead, nullptr, nullptr, nullptr) != 1)
    return -1;

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN,
                          noncelen, nullptr) != 1) {
    return -1;
  }

  if (EVP_DecryptInit_ex(actx, nullptr, nullptr, key, nonce) != 1)
    return -1;

  size_t outlen;
  int len;

  if (EVP_DecryptUpdate(actx, nullptr, &len, ad, adlen) != 1)
    return -1;

  if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1)
    return -1;

  outlen = len;

  if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen,
                          const_cast<uint8_t *>(tag)) != 1) {
    return -1;
  }

  if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1)
    return -1;

  outlen += len;

  return outlen;
}

inline ssize_t HP_Mask(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext& ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  static constexpr uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

  auto actx = EVP_CIPHER_CTX_new();
  if (actx == nullptr)
    return -1;

  auto actx_d = defer(EVP_CIPHER_CTX_free, actx);

  if (EVP_EncryptInit_ex(actx, ctx.hp, nullptr, key, sample) != 1)
    return -1;

  size_t outlen = 0;
  int len;
  if (EVP_EncryptUpdate(actx, dest, &len,
                        PLAINTEXT, strsize(PLAINTEXT)) != 1) {
    return -1;
  }
  CHECK_EQ(len, 5);

  outlen = len;

  if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1)
    return -1;

  CHECK_EQ(len, 0);

  return outlen;
}

inline int HKDF_Expand(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* info,
    size_t infolen,
    const CryptoContext& ctx) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr)
    return -1;

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1)
    return -1;

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
    return -1;

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx.prf) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1)
    return -1;

  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1)
    return -1;

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1)
    return -1;

  return 0;
}

inline int HKDF_Extract(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* salt,
    size_t saltlen,
    const CryptoContext& ctx) {
  auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (pctx == nullptr)
    return -1;

  auto pctx_d = defer(EVP_PKEY_CTX_free, pctx);

  if (EVP_PKEY_derive_init(pctx) != 1)
    return -1;

  if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1)
    return -1;

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx.prf) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1)
    return -1;

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1)
    return -1;

  if (EVP_PKEY_derive(pctx, dest, &destlen) != 1)
    return -1;

  return 0;
}

inline int HKDF_Expand_Label(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* label,
    size_t labellen,
    const CryptoContext& ctx) {
  std::array<uint8_t, 256> info;
  static constexpr const uint8_t LABEL[] = "tls13 ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = strsize(LABEL) + labellen;
  p = std::copy_n(LABEL, strsize(LABEL), p);
  p = std::copy_n(label, labellen, p);
  *p++ = 0;

  return HKDF_Expand(dest, destlen,
                     secret, secretlen,
                     info.data(),
                     p - std::begin(info),
                     ctx);
}

inline int DeriveInitialSecret(
    CryptoInitialParams& params,
    const ngtcp2_cid* secret,
    const uint8_t* salt,
    size_t saltlen) {
  CryptoContext ctx;
  prf_sha256(ctx);
  return HKDF_Extract(params.initial_secret.data(),
                      params.initial_secret.size(),
                      secret->data,
                      secret->datalen,
                      salt,
                      saltlen,
                      ctx);
}

inline int DeriveServerInitialSecret(
    CryptoInitialParams& params) {
  static constexpr uint8_t LABEL[] = "server in";
  CryptoContext ctx;
  prf_sha256(ctx);
  return HKDF_Expand_Label(params.secret.data(),
                           params.secret.size(),
                           params.initial_secret.data(),
                           params.initial_secret.size(),
                           LABEL,
                           strsize(LABEL), ctx);
}

inline int DeriveClientInitialSecret(
    CryptoInitialParams& params) {
  static constexpr uint8_t LABEL[] = "client in";
  CryptoContext ctx;
  prf_sha256(ctx);
  return HKDF_Expand_Label(params.secret.data(),
                           params.secret.size(),
                           params.initial_secret.data(),
                           params.initial_secret.size(),
                           LABEL,
                           strsize(LABEL), ctx);
}

inline ssize_t DerivePacketProtectionKey(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext &ctx) {
  static constexpr uint8_t LABEL[] = "quic key";

  size_t keylen = aead_key_length(ctx);
  if (keylen > destlen)
    return -1;

  if (HKDF_Expand_Label(dest, keylen,
                        secret, secretlen,
                        LABEL, strsize(LABEL),
                        ctx) != 0) {
    return -1;
  }

  return keylen;
}

inline ssize_t DerivePacketProtectionIV(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext& ctx) {
  static constexpr uint8_t LABEL[] = "quic iv";

  size_t ivlen = std::max(static_cast<size_t>(8), aead_nonce_length(ctx));
  if (ivlen > destlen)
    return -1;

  if (HKDF_Expand_Label(dest, ivlen,
                        secret, secretlen,
                        LABEL, strsize(LABEL),
                        ctx) != 0) {
    return -1;
  }

  return ivlen;
}

inline ssize_t DeriveHeaderProtectionKey(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext &ctx) {
  static constexpr uint8_t LABEL[] = "quic hp";

  size_t keylen = aead_key_length(ctx);
  if (keylen > destlen)
    return -1;

  if(HKDF_Expand_Label(dest, keylen,
                       secret, secretlen,
                       LABEL, strsize(LABEL),
                       ctx) != 0) {
    return -1;
  }

  return keylen;
}

inline int DeriveTokenKey(
    CryptoToken& params,
    const uint8_t* rand_data,
    size_t rand_datalen,
    CryptoContext& context,
    std::array<uint8_t, TOKEN_SECRETLEN>& token_secret) {
  std::array<uint8_t, 32> secret;

  if (HKDF_Extract(
          secret.data(),
          secret.size(),
          token_secret.data(),
          token_secret.size(),
          rand_data,
          rand_datalen,
          context) != 0) {
    return -1;
  }

  ssize_t slen =
      DerivePacketProtectionKey(
          params.key.data(),
          params.keylen,
          secret.data(),
          secret.size(),
          context);
  if (slen < 0)
    return -1;
  params.keylen = slen;

  slen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.ivlen,
          secret.data(),
          secret.size(),
          context);
  if (slen < 0)
    return -1;
  params.ivlen = slen;

  return 0;
}

inline ssize_t UpdateTrafficSecret(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext &ctx) {

  static constexpr uint8_t LABEL[] = "traffic upd";

  if (destlen < secretlen)
    return -1;

  if (HKDF_Expand_Label(dest, secretlen,
                        secret, secretlen,
                        LABEL,
                        strsize(LABEL),
                        ctx) != 0) {
    return -1;
  }

  return secretlen;
}

inline int Negotiated_PRF(CryptoContext& ctx, SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case 0x03001301u: // TLS_AES_128_GCM_SHA256
    case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
      ctx.prf = EVP_sha256();
      return 0;
    case 0x03001302u: // TLS_AES_256_GCM_SHA384
      ctx.prf = EVP_sha384();
      return 0;
    default:
      return -1;
  }
}

inline int Negotiated_AEAD(CryptoContext& ctx, SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case 0x03001301u: // TLS_AES_128_GCM_SHA256
      ctx.aead = EVP_aes_128_gcm();
      ctx.hp = EVP_aes_128_ctr();
      return 0;
    case 0x03001302u: // TLS_AES_256_GCM_SHA384
      ctx.aead = EVP_aes_256_gcm();
      ctx.hp = EVP_aes_256_ctr();
      return 0;
    case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
      ctx.aead = EVP_chacha20_poly1305();
      ctx.hp = EVP_chacha20();
      return 0;
    default:
      return -1;
  }
}

inline size_t AEAD_Max_Overhead(const CryptoContext& ctx) {
  return aead_tag_length(ctx);
}

inline int MessageDigest(
    uint8_t* res,
    const EVP_MD* meth,
    const uint8_t* data,
    size_t len) {
  int err;

  auto ctx = EVP_MD_CTX_new();
  if (ctx == nullptr)
    return -1;

  auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

  err = EVP_DigestInit_ex(ctx, meth, nullptr);
  if (err != 1)
    return -1;

  err = EVP_DigestUpdate(ctx, data, len);
  if (err != 1)
    return -1;

  unsigned int mdlen = EVP_MD_size(meth);

  err = EVP_DigestFinal_ex(ctx, res, &mdlen);
  if (err != 1)
    return -1;

  return 0;
}

inline int GenerateRandData(
    uint8_t *buf,
    size_t len) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;
  EntropySource(rand.data(), rand.size());

  if (MessageDigest(md.data(), EVP_sha256(),
                    rand.data(), rand.size()) != 0) {
    return -1;
  }
  CHECK_LE(len, md.size());
  std::copy_n(std::begin(md), len, buf);
  return 0;
}

inline void ClearTLSError() {
  ERR_clear_error();
}

inline const char* TLSErrorString(int code) {
  return ERR_error_string(code, nullptr);
}

int SetupKeys(
  const uint8_t* secret,
  size_t secretlen,
  CryptoParams& params,
  CryptoContext& context) {
  params.keylen =
      DerivePacketProtectionKey(
          params.key.data(),
          params.key.size(),
          secret,
          secretlen,
          context);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          secret, secretlen,
          context);
  if (params.ivlen < 0)
    return -1;

  params.hplen =
      DeriveHeaderProtectionKey(
          params.hp.data(),
          params.hp.size(),
          secret, secretlen,
          context);
  if (params.hplen < 0)
    return -1;

  return 0;
}

int SetupClientSecret(
  CryptoInitialParams& params,
  CryptoContext& context) {
  if (DeriveClientInitialSecret(params) != 0)
    return -1;

  params.keylen =
      DerivePacketProtectionKey(
          params.key.data(),
          params.key.size(),
          params.secret.data(),
          params.secret.size(),
          context);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          params.secret.data(),
          params.secret.size(),
          context);
  if (params.ivlen < 0)
    return -1;

  params.hplen =
      DeriveHeaderProtectionKey(
          params.hp.data(),
          params.hp.size(),
          params.secret.data(),
          params.secret.size(),
          context);
  if (params.hplen < 0)
    return -1;

  return 0;
}

int SetupServerSecret(
    CryptoInitialParams& params,
    CryptoContext& context) {

  if (DeriveServerInitialSecret(params) != 0)
    return -1;

  params.keylen =
      DerivePacketProtectionKey(
          params.key.data(),
          params.key.size(),
          params.secret.data(),
          params.secret.size(),
          context);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          params.secret.data(),
          params.secret.size(),
          context);
  if (params.ivlen < 0)
    return -1;

  params.hplen =
      DeriveHeaderProtectionKey(
          params.hp.data(),
          params.hp.size(),
          params.secret.data(),
          params.secret.size(),
          context);
  if (params.hplen < 0)
    return -1;

  return 0;
}

template <install_fn fn>
int InstallKeys(
    ngtcp2_conn* connection,
    CryptoParams& params) {
  return fn(connection,
     params.key.data(),
     params.keylen,
     params.iv.data(),
     params.ivlen,
     params.hp.data(),
     params.hplen);
}

template <install_fn fn>
int InstallKeys(
    ngtcp2_conn* connection,
    CryptoInitialParams& params) {
  return fn(connection,
     params.key.data(),
     params.keylen,
     params.iv.data(),
     params.ivlen,
     params.hp.data(),
     params.hplen);
}

}  // namespace


// Reset the QuicSessionConfig to initial defaults.
// TODO(@jasnell): Currently only called once so candidate for inlining.
void QuicSessionConfig::ResetToDefaults() {
#define V(idx, name, def) name##_ = def;
  QUICSESSION_CONFIG(V)
#undef V
}

// Sets the QuicSessionConfig using an AliasedBuffer for efficiency.
void QuicSessionConfig::Set(Environment* env) {
  ResetToDefaults();
  AliasedBuffer<double, Float64Array>& buffer =
      env->quic_state()->quicsessionconfig_buffer;
  uint64_t flags = buffer[IDX_QUIC_SESSION_CONFIG_COUNT];

#define V(idx, name, def)                                                      \
  if (flags & (1 << IDX_QUIC_SESSION_##idx))                                   \
    name##_ = static_cast<uint64_t>(buffer[IDX_QUIC_SESSION_##idx]);
  QUICSESSION_CONFIG(V)
#undef V
}

// Copies the QuicSessionConfig into a ngtcp2_settings object
void QuicSessionConfig::ToSettings(ngtcp2_settings* settings,
                                   bool stateless_reset_token) {
#define V(idx, name, def) settings->name = name##_;
  QUICSESSION_CONFIG(V)
#undef V

  settings->log_printf = QuicSession::DebugLog;
  settings->initial_ts = uv_hrtime();
  settings->ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  settings->max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;

  if (stateless_reset_token) {
    settings->stateless_reset_token_present = 1;
    EntropySource(settings->stateless_reset_token,
                  arraysize(settings->stateless_reset_token));
  }
}


// Static ngtcp2 callbacks...

int QuicSession::OnClientInitial(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->TLSHandshake() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnReceiveClientInitial(
    ngtcp2_conn* conn,
    const ngtcp2_cid* dcid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->ReceiveClientInitial(dcid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnReceiveCryptoData(
    ngtcp2_conn* conn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  return session->ReceiveCryptoData(offset, data, datalen);
}

int QuicSession::OnReceiveRetry(
    ngtcp2_conn *conn,
    const ngtcp2_pkt_hd *hd,
    const ngtcp2_pkt_retry *retry,
    void *user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->ReceiveRetry() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnExtendMaxStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->ExtendMaxStreamsBidi(max_streams) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnExtendMaxStreamsUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->ExtendMaxStreamsUni(max_streams) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnHandshakeCompleted(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  session->HandshakeCompleted();
  return 0;
}

ssize_t QuicSession::OnDoHSEncrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  ssize_t nwrite =
      session->DoHSEncrypt(
          dest, destlen,
          plaintext, plaintextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return nwrite;
}

ssize_t QuicSession::OnDoHSDecrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  ssize_t nwrite =
      session->DoHSDecrypt(
          dest, destlen,
          ciphertext, ciphertextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }
  return nwrite;
}

ssize_t QuicSession::OnDoEncrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  ssize_t nwrite =
      session->DoEncrypt(
          dest, destlen,
          plaintext, plaintextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return nwrite;
}

ssize_t QuicSession::OnDoDecrypt(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  ssize_t nwrite =
      session->DoDecrypt(
          dest, destlen,
          ciphertext, ciphertextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }
  return nwrite;
}

ssize_t QuicSession::OnDoInHPMask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  ssize_t nwrite =
      session->DoInHPMask(
          dest, destlen,
          key, keylen,
          sample, samplelen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return nwrite;
}

ssize_t QuicSession::OnDoHPMask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  ssize_t nwrite =
      session->DoHPMask(
          dest, destlen,
          key, keylen,
          sample, samplelen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return nwrite;
}

int QuicSession::OnReceiveStreamData(
    ngtcp2_conn* conn,
    int64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->ReceiveStreamData(stream_id, fin, offset, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnStreamOpen(
    ngtcp2_conn* conn,
    int64_t stream_id,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->StreamOpen(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnAckedCryptoOffset(
    ngtcp2_conn* conn,
    uint64_t offset,
    size_t datalen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  session->AckedCryptoOffset(offset, datalen);
  return 0;
}

int QuicSession::OnAckedStreamDataOffset(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t offset,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->AckedStreamDataOffset(stream_id, offset, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int QuicSession::OnStreamClose(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  session->StreamClose(stream_id, app_error_code);
  return 0;
}

int QuicSession::OnRand(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    ngtcp2_rand_ctx ctx,
    void* user_data) {
  EntropySource(dest, destlen);
  return 0;
}

int QuicSession::OnGetNewConnectionID(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  session->GetNewConnectionID(cid, token, cidlen);
  return 0;
}

int QuicSession::OnUpdateKey(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (session->UpdateKey() != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

int QuicSession::OnRemoveConnectionID(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  session->RemoveConnectionID(cid);
  return 0;
}

int QuicSession::OnPathValidation(
    ngtcp2_conn* conn,
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res,
    void* user_data) {
  // TODO(@jasnell): Implement this?
  return 0;
}

void QuicSession::SetupTokenContext(CryptoContext& context) {
  aead_aes_128_gcm(context);
  prf_sha256(context);
}

int QuicSession::GenerateToken(
    uint8_t* token,
    size_t& tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    CryptoContext& token_crypto_ctx,
    std::array<uint8_t, TOKEN_SECRETLEN>& token_secret) {
  std::array<uint8_t, 4096> plaintext;

  const size_t addrlen = SocketAddress::GetAddressLen(addr);

  uint64_t now = uv_hrtime();

  auto p = std::begin(plaintext);
  p = std::copy_n(reinterpret_cast<const uint8_t *>(addr), addrlen, p);
  p = std::copy_n(reinterpret_cast<uint8_t *>(&now), sizeof(now), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  CryptoToken params;

  if (GenerateRandData(rand_data.data(), rand_data.size()) != 0)
    return -1;

  if (DeriveTokenKey(
          params,
          rand_data.data(),
          rand_data.size(),
          token_crypto_ctx,
          token_secret) != 0) {
    return -1;
  }

  ssize_t n =
      Encrypt(
          token, tokenlen,
          plaintext.data(), std::distance(std::begin(plaintext), p),
          token_crypto_ctx,
          params.key.data(),
          params.keylen,
          params.iv.data(),
          params.ivlen,
          reinterpret_cast<const uint8_t *>(addr), addrlen);

  if (n < 0)
    return -1;
  memcpy(token + n, rand_data.data(), rand_data.size());
  tokenlen = n + rand_data.size();
  return 0;
}

int QuicSession::VerifyToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    CryptoContext& token_crypto_ctx,
    std::array<uint8_t, TOKEN_SECRETLEN>& token_secret) {

  uv_getnameinfo_t info;
  char* host = nullptr;
  const size_t addrlen = SocketAddress::GetAddressLen(addr);
  if (uv_getnameinfo(
          env->event_loop(),
          &info, nullptr,
          addr, NI_NUMERICSERV) == 0) {
    host = info.host;
    DCHECK_EQ(SocketAddress::GetPort(addr), std::stoi(info.service));
  } else {
    SocketAddress::GetAddress(addr, &host);
  }

  if (hd->tokenlen < TOKEN_RAND_DATALEN) {
    // token is too short
    return  -1;
  }

  uint8_t* rand_data = hd->token + hd->tokenlen - TOKEN_RAND_DATALEN;
  uint8_t* ciphertext = hd->token;
  size_t ciphertextlen = hd->tokenlen - TOKEN_RAND_DATALEN;

  CryptoToken params;

  if (DeriveTokenKey(
        params,
        rand_data,
        TOKEN_RAND_DATALEN,
        token_crypto_ctx,
        token_secret) != 0) {
    return -1;
  }

  std::array<uint8_t, 4096> plaintext;

  ssize_t n =
      Decrypt(
          plaintext.data(), plaintext.size(),
          ciphertext, ciphertextlen,
          token_crypto_ctx,
          params.key.data(),
          params.keylen,
          params.iv.data(),
          params.ivlen,
          reinterpret_cast<const uint8_t*>(addr), addrlen);
  if (n < 0) {
    // Could not decrypt token
    return -1;
  }

  if (static_cast<size_t>(n) < addrlen + sizeof(uint64_t)) {
    // Bad token construction
    return -1;
  }

  ssize_t cil = static_cast<size_t>(n) - addrlen - sizeof(uint64_t);
  if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
    // Bad token construction
    return -1;
  }

  if (memcmp(plaintext.data(), addr, addrlen) != 0) {
    // Client address does not match
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data() + addrlen, sizeof(uint64_t));

  uint64_t now = uv_hrtime();

  // 10-second window... TODO(@jasnell): make configurable?
  if (t + 10ULL + NGTCP2_SECONDS < now) {
    // Token has expired
    return -1;
  }

  return 0;
}

QuicSession::QuicSession(
    QuicSocket* socket,
    Local<Object> wrap,
    SecureContext* ctx,
    AsyncWrap::ProviderType type) :
    AsyncWrap(socket->env(), wrap, type),
    initial_(true),
    connection_(nullptr),
    tls_alert_(0),
    max_pktlen_(0),
    idle_timer_(nullptr),
    retransmit_timer_(nullptr),
    socket_(socket),
    nkey_update_(0),
    hs_crypto_ctx_{},
    crypto_ctx_{},
    sendbuf_{NGTCP2_MAX_PKTLEN_IPV4},
    handshake_idx_(0),
    ncread_(0),
    tx_crypto_offset_(0) {
  ssl_.reset(SSL_new(ctx->ctx_.get()));
  CHECK(ssl_);
  // TODO(@jasnell): memory accounting
  //env_->isolate()->AdjustAmountOfExternalAllocatedMemory(kExternalSize);
}

QuicSession::~QuicSession() {
  // Ensure that Destroy has been called first
  CHECK_NULL(socket_);
  CHECK_NULL(connection_);
  CHECK_NULL(idle_timer_);
  CHECK_NULL(retransmit_timer_);
  CHECK(streams_.empty());
  CHECK(!ssl_);
}

void QuicSession::AckedCryptoOffset(
    uint64_t offset,
    size_t datalen) {
  Debug(this,
        "Received acknowledgement for crypto data. Offset %llu, Length %d",
        offset, datalen);
  QuicBuffer::AckData(
      handshake_,
      handshake_idx_,
      tx_crypto_offset_,
      offset + datalen);
}

inline bool QuicSession::IsDestroyed() {
  return connection_ == nullptr;
}

int QuicSession::AckedStreamDataOffset(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this,
        "Received acknowledgement for stream %llu data. Offset %llu, Length %d",
        stream_id, offset, datalen);
  QuicStream* stream = static_cast<QuicStream*>(FindStream(stream_id));
  if (stream != nullptr)
    stream->AckedDataOffset(offset, datalen);
  return 0;
}

void QuicSession::AddStream(
    QuicStream* stream) {
  CHECK(!IsDestroyed());
  Debug(this, "Adding stream %llu to session.", stream->GetID());
  streams_.emplace(stream->GetID(), stream);
}

void QuicSession::DebugLog(
    void* user_data,
    const char* fmt, ...) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  char message[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);
  Debug(session, message);
}

void QuicSession::Destroy() {
  if (IsDestroyed())
    return;

  Remove();

  // Streams should have already been closed and destroyed by this point...
  // Let's verify that they have been.
  CHECK(streams_.empty());
  Debug(this, "Destroying the QuicSession.");
  StopIdleTimer();
  StopRetransmitTimer();

  if (sendbuf_.WantsAck())
    sendbuf_.Done(UV_ECANCELED, sendbuf_.size());
  QuicBuffer::Cancel(handshake_);

  ngtcp2_conn_del(connection_);

  ssl_.reset();
  socket_ = nullptr;
  connection_ = nullptr;

  // TODO(@jasnell): Memory accounting
  delete this;
}

ssize_t QuicSession::DoDecrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  CHECK(!IsDestroyed());
  Debug(this, "Decrypting packet data.");
  return Decrypt(
    dest, destlen,
    ciphertext, ciphertextlen,
    crypto_ctx_,
    key, keylen,
    nonce, noncelen,
    ad, adlen);
}

ssize_t QuicSession::DoEncrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  CHECK(!IsDestroyed());
  Debug(this, "Encrypting packet data.");
  return Encrypt(
    dest, destlen,
    plaintext, plaintextlen,
    crypto_ctx_,
    key, keylen,
    nonce, noncelen,
    ad, adlen);
}

ssize_t QuicSession::DoHPMask(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  CHECK(!IsDestroyed());
  Debug(this, "hp_mask");
  return HP_Mask(
    dest, destlen,
    crypto_ctx_,
    key, keylen,
    sample, samplelen);
}

ssize_t QuicSession::DoHSDecrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  CHECK(!IsDestroyed());
  Debug(this, "Decrypting handshake data.");
  return Decrypt(
    dest, destlen,
    ciphertext, ciphertextlen,
    hs_crypto_ctx_,
    key, keylen,
    nonce, noncelen,
    ad, adlen);
}

ssize_t QuicSession::DoHSEncrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  CHECK(!IsDestroyed());
  Debug(this, "Encrypting handshake data.");
  return Encrypt(
    dest, destlen,
    plaintext, plaintextlen,
    hs_crypto_ctx_,
    key, keylen,
    nonce, noncelen,
    ad, adlen);
}

ssize_t QuicSession::DoInHPMask(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  CHECK(!IsDestroyed());
  Debug(this, "in hp_mask");
  return HP_Mask(
    dest, destlen,
    hs_crypto_ctx_,
    key, keylen,
    sample, samplelen);
}

QuicStream* QuicSession::FindStream(
    uint64_t id) {
  auto it = streams_.find(id);
  if (it == std::end(streams_))
    return nullptr;
  return (*it).second;
}

void QuicSession::GetLocalTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  ngtcp2_conn_get_local_transport_params(
    connection_,
    params);
}

uint32_t QuicSession::GetNegotiatedVersion() {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_get_negotiated_version(connection_);
};

int QuicSession::GetNewConnectionID(
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen) {
  CHECK(!IsDestroyed());
  cid->datalen = cidlen;
  EntropySource(cid->data, cidlen);
  EntropySource(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  AssociateCID(cid);
  return 0;
}

SocketAddress* QuicSession::GetRemoteAddress() {
  return &remote_address_;
}

inline void QuicSession::InitTLS(SSL* ssl) {
  Debug(this, "Initializing TLS.");
  BIO* bio = BIO_new(CreateBIOMethod());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, this);
  SSL_set_msg_callback(ssl, MessageCB);
  SSL_set_msg_callback_arg(ssl, this);
  SSL_set_key_callback(ssl, KeyCB, this);

  InitTLS_Post(ssl);
}

bool QuicSession::IsHandshakeCompleted() {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_get_handshake_completed(connection_);
}

bool QuicSession::IsInClosingPeriod() {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_is_in_closing_period(connection_);
}

void QuicSession::OnIdleTimeout(
    uv_timer_t* timer) {
  QuicSession* session = static_cast<QuicSession*>(timer->data);
  CHECK_NOT_NULL(session);
  session->OnIdleTimeout();
}

int QuicServerSession::OnKey(
    int name,
    const uint8_t* secret,
    size_t secretlen) {
  CHECK(!IsDestroyed());
  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      rx_secret_.assign(secret, secret + secretlen);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      tx_secret_.assign(secret, secret + secretlen);
      break;
    default:
      return 0;
  }

  if (Negotiated_PRF(crypto_ctx_, ssl()) != 0 ||
      Negotiated_AEAD(crypto_ctx_, ssl()) != 0) {
    return -1;
  }

  CryptoParams params;

  if (SetupKeys(secret, secretlen, params, crypto_ctx_) != 0)
    return -1;

  ngtcp2_conn_set_aead_overhead(
      connection_,
      AEAD_Max_Overhead(crypto_ctx_));

  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_early_keys>(connection_, params);
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_rx_keys>(connection_, params);
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_rx_keys>(connection_, params);
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_tx_keys>(connection_, params);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_tx_keys>(connection_, params);
    break;
  }

  return 0;
}

void QuicSession::OnRetransmitTimeout(
    uv_timer_t* timer) {
  QuicSession* session = static_cast<QuicSession*>(timer->data);
  CHECK_NOT_NULL(session);
  session->OnRetransmitTimeout();
}

size_t QuicSession::ReadHandshake(
    const uint8_t** pdest) {
  CHECK(!IsDestroyed());
  Debug(this, "Reading handshake data.");
  if (handshake_idx_ == handshake_.size())
    return 0;
  auto &v = handshake_[handshake_idx_++];
  *pdest = v.rpos();
  return v.size();
}

size_t QuicSession::ReadPeerHandshake(
    uint8_t* buf,
    size_t buflen) {
  CHECK(!IsDestroyed());
  Debug(this, "Reading peer handshake data.");
  auto n = std::min(buflen, peer_handshake_.size() - ncread_);
  std::copy_n(std::begin(peer_handshake_) + ncread_, n, buf);
  ncread_ += n;
  return n;
}

int QuicSession::ReceiveClientInitial(
    const ngtcp2_cid* dcid) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving client initial parameters.");

  CryptoInitialParams params;

  if (DeriveInitialSecret(
      params,
      dcid,
      reinterpret_cast<const uint8_t *>(NGTCP2_INITIAL_SALT),
      strsize(NGTCP2_INITIAL_SALT))) {
    return -1;
  }

  prf_sha256(hs_crypto_ctx_);
  aead_aes_128_gcm(hs_crypto_ctx_);

  if (SetupServerSecret(params, hs_crypto_ctx_) != 0)
    return -1;

  InstallKeys<ngtcp2_conn_install_initial_tx_keys>(connection_, params);

  if (SetupClientSecret(params, hs_crypto_ctx_) != 0)
    return -1;

  InstallKeys<ngtcp2_conn_install_initial_rx_keys>(connection_, params);

  return 0;
}

void QuicSession::HandshakeCompleted() {
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  MakeCallback(env()->quic_on_session_handshake_function(), 0, nullptr);
}

int QuicSession::ReceiveCryptoData(
    uint64_t offset,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving crypto data.");
  WritePeerHandshake(data, datalen);
  if (!IsHandshakeCompleted()) {
    int err = TLSHandshake();
    if (err != 0)
      return err;
    return 0;
  }
  return TLSRead();
}

int QuicSession::ReceiveStreamData(
    int64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  // Locate the QuicStream to receive this data. If
  // one does not exist, create it and notify the JS side...
  // then pass on the received data
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  QuicStream* stream = static_cast<QuicStream*>(FindStream(stream_id));
  if (stream == nullptr)
    stream = CreateStream(stream_id);

   ngtcp2_conn_extend_max_stream_offset(
      connection_,
      stream_id,
      datalen);
   ngtcp2_conn_extend_max_offset(
      connection_,
      datalen);

   if (stream->ReceiveData(fin, data, datalen) != 0)
     return -1;

  StartIdleTimer(-1);

  return 0;
}

void QuicSession::RemoveConnectionID(
    const ngtcp2_cid* cid) {
  CHECK(!IsDestroyed());
  DisassociateCID(cid);
}

void QuicSession::RemoveStream(
    int64_t stream_id) {
  CHECK(!IsDestroyed());
  Debug(this, "Removing stream %llu", stream_id);
  streams_.erase(stream_id);
}

int QuicSession::Send0RTTStreamData(
    QuicStream* stream,
    int fin,
    QuicBuffer& data) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen;

  for (;;) {
    ngtcp2_vec datav{const_cast<uint8_t*>(data.rpos()), data.size()};
    auto n = ngtcp2_conn_client_write_handshake(
        connection_,
        sendbuf_.wpos(),
        max_pktlen_,
        &ndatalen,
        stream->GetID(),
        fin,
        &datav, 1,
        uv_hrtime());
    if (n < 0) {
      switch (n) {
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          return 0;
      }
      Debug(this, "Failure writing early stream data. Error %d", n);
      Close();  // Close with the error code
      return -1;
    }

    if (n == 0)
      return 0;

    if (ndatalen > 0)
      data.seek(ndatalen);

    sendbuf_.push(n);

    int err = SendPacket();
    if (err != 0)
      return err;

    if (data.size() == 0) {
      data.Done(0, data.size());
      break;
    }
  }

  return 0;
}

int QuicSession::SendStreamData(
    QuicStream* stream,
    int fin,
    QuicBuffer& data) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen;
  QuicPathStorage path;

  for (;;) {
    auto n = ngtcp2_conn_write_stream(connection_,
                                      &path.path,
                                      sendbuf_.wpos(),
                                      max_pktlen_,
                                      &ndatalen,
                                      stream->GetID(),
                                      fin,
                                      data.rpos(),
                                      data.size(),
                                      uv_hrtime());
    if (n < 0) {
      switch (n) {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
          return 0;
      }
      Debug(this, "Error writing stream data. Error %d", n);
      return HandleError(n);
    }

    if (n == 0)
      return 0;

    if (ndatalen >= 0) {
      if (fin && static_cast<size_t>(ndatalen) == data.size()) {
        stream->ResetShouldSendFin();
      }

      data.seek(ndatalen);
    }

    sendbuf_.push(n);
    remote_address_.Update(&path.path.remote);

    int err = SendPacket();
    if (err != 0)
      return err;

    if (ndatalen >= 0 && data.size() == 0)
      break;
  }
  return 0;
}

int QuicSession::SendPacket() {
  CHECK(!IsDestroyed());
  if (sendbuf_.size() > 0) {
    Debug(this, "Sending pending %d bytes of session data", sendbuf_.size());
    return Socket()->SendPacket(&remote_address_, &sendbuf_);
  }
  return 0;
}

int QuicSession::SetRemoteTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_set_remote_transport_params(connection_, params);
}

void QuicSession::ScheduleRetransmit() {
  CHECK(!IsDestroyed());
  ngtcp2_tstamp expiry =
      std::min(ngtcp2_conn_loss_detection_expiry(connection_),
      ngtcp2_conn_ack_delay_expiry(connection_));
  uint64_t now = uv_hrtime();
  uint64_t interval =
      expiry < now ? 1e-9
          : static_cast<uint64_t>(expiry - now) / NGTCP2_SECONDS;
  Debug(this, "Scheduling retransmission timer for interval %llu", interval);
  if (retransmit_timer_ == nullptr) {
    retransmit_timer_ = new uv_timer_t();
    uv_timer_init(env()->event_loop(), retransmit_timer_);
    retransmit_timer_->data = this;
  }
  uv_timer_start(retransmit_timer_,
                 OnRetransmitTimeout,
                 interval,
                 interval);
  uv_unref(reinterpret_cast<uv_handle_t*>(retransmit_timer_));
}

void QuicSession::SetHandshakeCompleted() {
  CHECK(!IsDestroyed());
  ngtcp2_conn_handshake_completed(connection_);
}

void QuicSession::SetTLSAlert(
    int err) {
  tls_alert_ = err;
}

QuicStream* QuicSession::CreateStream(int64_t stream_id) {
  Debug(this, "Stream %llu is new. Creating.", stream_id);
  QuicStream* stream = QuicStream::New(this, stream_id);
  // TODO(@jasnell): Should we really abort here? It depends on whether
  // a malicious sender can trigger this somehow. This should be safe
  // but we should verify.
  CHECK_NOT_NULL(stream);
  Local<Value> argv[] = {
    stream->object(),
    Number::New(env()->isolate(), static_cast<double>(stream_id))
  };
  MakeCallback(env()->quic_on_stream_ready_function(), arraysize(argv), argv);
  return stream;
}

int QuicSession::StreamOpen(
    int64_t stream_id) {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  QuicStream* stream =
      static_cast<QuicStream*>(FindStream(stream_id));
  if (stream != nullptr)
    return NGTCP2_STREAM_STATE_ERROR;
  CreateStream(stream_id);
  StartIdleTimer(-1);
  return 0;
}

int QuicSession::ShutdownStreamRead(int64_t stream_id, uint16_t code) {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_shutdown_stream_read(
      connection_,
      stream_id,
      code);
}

int QuicSession::ShutdownStreamWrite(int64_t stream_id, uint16_t code) {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_shutdown_stream_write(
      connection_,
      stream_id,
      code);
}

int QuicSession::OpenUnidirectionalStream(int64_t* stream_id) {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_open_uni_stream(connection_, stream_id, nullptr);
}

int QuicSession::OpenBidirectionalStream(int64_t* stream_id) {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_open_bidi_stream(connection_, stream_id, nullptr);
}

QuicSocket* QuicSession::Socket() {
  return socket_;
}

void QuicSession::StartIdleTimer(
    uint64_t idle_timeout) {
  CHECK(!IsDestroyed());
  if (idle_timer_ == nullptr) {
    idle_timer_ = new uv_timer_t();
    uv_timer_init(env()->event_loop(), idle_timer_);
    idle_timer_->data = this;
  }

  if (!uv_is_active(reinterpret_cast<uv_handle_t*>(idle_timer_))) {
    Debug(this, "Scheduling idle timer on interval %llu", idle_timeout);
    uv_timer_start(idle_timer_,
                   OnIdleTimeout,
                   idle_timeout,
                   idle_timeout);
    uv_unref(reinterpret_cast<uv_handle_t*>(idle_timer_));
  } else {
    uv_timer_again(idle_timer_);
  }
}

void QuicSession::StopIdleTimer() {
  CHECK(!IsDestroyed());
  if (idle_timer_ == nullptr)
    return;
  Debug(this, "Halting idle timer.");
  uv_timer_stop(idle_timer_);
  auto cb = [](uv_timer_t* handle) { delete handle; };
  env()->CloseHandle(idle_timer_, cb);
  idle_timer_ = nullptr;
}

void QuicSession::StopRetransmitTimer() {
  CHECK(!IsDestroyed());
  if (retransmit_timer_ == nullptr)
    return;
  Debug(this, "Halting retransmission timer.");
  uv_timer_stop(retransmit_timer_);
  auto cb = [](uv_timer_t* handle) { delete handle; };
  env()->CloseHandle(retransmit_timer_, cb);
  retransmit_timer_ = nullptr;
}

void QuicSession::StreamClose(
    int64_t stream_id,
    uint16_t app_error_code) {
  CHECK(!IsDestroyed());
  Debug(this, "Closing stream %llu with code %d",
        stream_id, app_error_code);
  QuicStream* stream = FindStream(stream_id);
  if (stream != nullptr)
    stream->Close(app_error_code);
}

int QuicSession::TLSHandshake() {
  CHECK(!IsDestroyed());
  Debug(this, "Performing TLS handshake. Initial? %s", initial_ ? "yes" : "no");
  ClearTLSError();
  int err;

  if (initial_) {
    err = TLSHandshake_Initial();
    if (err != 0) {
      return 0;
    }
  }

  err = SSL_do_handshake(ssl());
  if (err <= 0) {
    err = SSL_get_error(ssl(), err);
    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        return 0;
      case SSL_ERROR_SSL:
        Debug(this, "TLS handshake error: %s", TLSErrorString(err));
        return NGTCP2_ERR_CRYPTO;
      default:
        Debug(this, "TLS handshake error: %d", err);
        return NGTCP2_ERR_CRYPTO;
    }
  }
  err = TLSHandshake_Complete();
  if (err != 0) {
    return err;
  }

  Debug(this, "TLS Handshake is complete.");

  SetHandshakeCompleted();
  return 0;
}

int QuicServerSession::TLSRead() {
  CHECK(!IsDestroyed());
  ClearTLSError();

  std::array<uint8_t, 4096> buf;
  size_t nread;
  Debug(this, "Reading TLS data");
  for (;;) {
    int err = SSL_read_ex(ssl(), buf.data(), buf.size(), &nread);
    if (err == 1) {
      return NGTCP2_ERR_PROTO;
    }
    int code = SSL_get_error(ssl(), 0);
    switch (code) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        return 0;
      case SSL_ERROR_SSL:
      case SSL_ERROR_ZERO_RETURN:
        // TLS read error
        // std::cerr << "TLS read error: "
        //           << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return NGTCP2_ERR_CRYPTO;
      default:
        //std::cerr << "TLS read error: " << err << std::endl;
        return NGTCP2_ERR_CRYPTO;
    }
  }
}

int QuicSession::UpdateKey() {
  CHECK(!IsDestroyed());
  Debug(this, "Updating keys.");
  int err;

  std::array<uint8_t, 64> secret;
  ssize_t secretlen;
  CryptoParams params;

  ++nkey_update_;

  secretlen =
      UpdateTrafficSecret(
          secret.data(),
          secret.size(),
          tx_secret_.data(),
          tx_secret_.size(),
          crypto_ctx_);
  if (secretlen < 0)
    return -1;

  tx_secret_.assign(
      std::begin(secret),
      std::end(secret));

  params.keylen =
      DerivePacketProtectionKey(
          params.key.data(),
          params.key.size(),
          secret.data(),
          secretlen,
          crypto_ctx_);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          secret.data(),
          secretlen,
          crypto_ctx_);
  if (params.ivlen < 0)
    return -1;

  err = ngtcp2_conn_update_tx_key(
      connection_,
      params.key.data(),
      params.keylen,
      params.iv.data(),
      params.ivlen);
  if (err != 0)
    return -1;

  secretlen =
      UpdateTrafficSecret(
          secret.data(),
          secret.size(),
          rx_secret_.data(),
          rx_secret_.size(),
          crypto_ctx_);
  if (secretlen < 0)
    return -1;

  rx_secret_.assign(
      std::begin(secret),
      std::end(secret));

  params.keylen =
      DerivePacketProtectionKey(
          params.key.data(),
          params.key.size(),
          secret.data(),
          secretlen,
          crypto_ctx_);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          secret.data(),
          secretlen,
          crypto_ctx_);
  if (params.ivlen < 0)
    return -1;

  err = ngtcp2_conn_update_rx_key(
      connection_,
      params.key.data(),
      params.keylen,
      params.iv.data(),
      params.ivlen);
  if (err != 0)
    return -1;

  return 0;
}

void QuicSession::WritePeerHandshake(
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Writing %d bytes of peer handshake data.", datalen);
  std::copy_n(data, datalen, std::back_inserter(peer_handshake_));
}

void QuicSession::WriteHandshake(
    std::deque<QuicBuffer>& dest,
    size_t &idx,
    const uint8_t* data,
    size_t datalen) {
  Debug(this, "Writing %d bytes of handshake data.", datalen);
  dest.emplace_back(data, datalen);
  ++idx;
  auto& buf = dest.back();
  CHECK_EQ(
      ngtcp2_conn_submit_crypto_data(
          connection_,
          buf.rpos(), buf.size()), 0);
}

void QuicSession::WriteHandshake(
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  WriteHandshake(
      handshake_, handshake_idx_,
      data, datalen);
}

void QuicSession::Close() {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  MakeCallback(env()->quic_on_session_close_function(), 0, nullptr);
}

// QUIC Server Session

QuicServerSession::QuicServerSession(
    QuicSocket* socket,
    Local<Object> wrap,
    const ngtcp2_cid* rcid) :
    QuicSession(socket,
                wrap,
                socket->GetServerSecureContext(),
                AsyncWrap::PROVIDER_QUICSERVERSESSION),
    rcid_(*rcid),
    draining_(false) {
}

void QuicServerSession::AssociateCID(
    ngtcp2_cid* cid) {
  QuicCID id(cid);
  Socket()->AssociateCID(id, this);
}

void QuicServerSession::DisassociateCID(
    const ngtcp2_cid* cid) {
  QuicCID id(cid);
  Socket()->DisassociateCID(id);
}

int QuicServerSession::DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Performing server TLS handshake.");
  int err;

  err = ngtcp2_conn_read_handshake(
      connection_,
      path,
      data, datalen,
      uv_hrtime());
  if (err != 0) {
    Debug(this, "Failure reading handshake data: %s\n", ngtcp2_strerror(err));
    return -1;
  }

  if (sendbuf_.size() > 0) {
    err = SendPacket();
    if (err != 0)
      return err;
  }

  ssize_t nwrite =
      ngtcp2_conn_write_handshake(
          connection_,
          sendbuf_.wpos(),
          max_pktlen_,
          uv_hrtime());
  if (nwrite < 0) {
    Debug(this, "Error writing connection handshake");
    return -1;
  }

  if (nwrite == 0)
    return 0;

  sendbuf_.push(nwrite);

  Debug(this, "Sending handshake packet");
  return SendPacket();
}

int QuicServerSession::HandleError(
    int error) {
  if (StartClosingPeriod(error) != 0)
    return -1;
  return SendConnectionClose(error);
}

void QuicServerSession::InitTLS_Post(SSL* ssl) {
  SSL_set_accept_state(ssl);
}

int QuicServerSession::Init(
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version) {

  CHECK_NULL(connection_);

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS(ssl());

  ngtcp2_settings settings{};
  Socket()->SetServerSessionSettings(this, &settings);

  EntropySource(scid_.data, NGTCP2_SV_SCIDLEN);
  scid_.datalen = NGTCP2_SV_SCIDLEN;

  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  int err =
      ngtcp2_conn_server_new(
          &connection_,
          dcid,
          &scid_,
          *path,
          version,
          &callbacks_,
          &settings,
          static_cast<QuicSession*>(this));
  if (err != 0) {
    Debug(this, "There was an error creating the session. Error %d", err);
    return err;
  }

  if (ocid)
    ngtcp2_conn_set_retry_ocid(connection_, ocid);

  StartIdleTimer(settings.idle_timeout);

  return 0;
}

bool QuicServerSession::IsDraining() {
  return draining_;
}

QuicServerSession* QuicServerSession::New(
    QuicSocket* socket,
    const ngtcp2_cid* rcid) {
  Local<Object> obj;
  if (!socket->env()
             ->quicserversession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return nullptr;
  }
  return new QuicServerSession(socket, obj, rcid);
}

void QuicServerSession::NewSessionDoneCb() {
  // TODO(@jasnell): What to do with this
  Debug(this, "New Session Done");
}

void QuicServerSession::OnIdleTimeout() {
  if (connection_ == nullptr)
    return;

  if (IsInClosingPeriod() || IsDraining()) {
    Remove();
    Close();
    return;
  }

  StartDrainingPeriod();
}

void QuicServerSession::OnRetransmitTimeout() {
  Debug(this, "Retransmit timer fired...");
  uint64_t now = uv_hrtime();

  if (ngtcp2_conn_loss_detection_expiry(connection_) <= now) {
    Debug(this, "Connection loss detection...");
    SendPendingData(true);
    return;
  }

  if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Connection ack delay...");
    SendPendingData();
  }
}

int QuicServerSession::Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  CHECK(!IsDestroyed());
  Debug(this, "Received packet. nread = %d bytes", nread);
  int err;

  if (IsInClosingPeriod()) {
    Debug(this, "In closing period");
    // TODO(@jasnell) Implement this using exponential backoff
    return SendConnectionClose(0);
  }

  if (IsDraining()) {
    Debug(this, "Draining...");
    return 0;
  }

  if (IsHandshakeCompleted()) {
    Debug(this, "TLS Handshake is completed");

    QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

    err = ngtcp2_conn_read_pkt(
        connection_,
        *path,
        data, nread,
        uv_hrtime());
    if (err != 0) {
      Debug(this, "Error reading packet. Error %d\n", err);
      if (err == NGTCP2_ERR_DRAINING) {
        StartDrainingPeriod();
        return -1; // Closing
      }
      return HandleError(err);
    }
    Debug(this, "Successfully read packet");
  } else {
    Debug(this, "TLS Handshake continuing");
    err = DoHandshake(nullptr, data, nread);
    if (err != 0)
      return HandleError(err);
  }
  StartIdleTimer(-1);
  return 0;
}

void QuicServerSession::Remove() {
  CHECK(!IsDestroyed());
  Debug(this, "Remove this QuicServerSession from the QuicSocket.");
  QuicCID rcid(rcid_);
  Socket()->DisassociateCID(rcid);

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());

  for (auto &cid : cids) {
    QuicCID id(&cid);
    Socket()->DisassociateCID(id);
  }

  QuicCID scid(scid_);
  Socket()->RemoveSession(scid);
}

int QuicServerSession::SendConnectionClose(int error) {
  CHECK(!IsDestroyed());
  Debug(this, "Sending connection close");
  CHECK(conn_closebuf_ && conn_closebuf_->size());

  // TODO(@jasnell): Do this without copying
  if (sendbuf_.size() == 0) {
    std::copy_n(conn_closebuf_->rpos(),
                conn_closebuf_->size(),
                sendbuf_.wpos());
    sendbuf_.push(conn_closebuf_->size());
  }

  return SendPacket();
}

int QuicServerSession::SendPendingData(bool retransmit) {
  CHECK(!IsDestroyed());
  Debug(this, "Sending pending data for server session");
  int err;

  if (IsInClosingPeriod()) {
    Debug(this, "Server session is in closing period");
    return 0;
  }

  err = SendPacket();
  if (err != 0) {
    Debug(this, "Error sending data. Error %d", err);
    return err;
  }

  CHECK_GE(sendbuf_.left(), max_pktlen_);

  if (retransmit) {
    err = ngtcp2_conn_on_loss_detection_timer(connection_, uv_hrtime());
    if (err != 0) {
      Debug(this, "Error resetting loss detection timer. Error %d", err);
      return -1;
    }
  }

  if (!IsHandshakeCompleted()) {
    Debug(this, "Handshake is not completed");
    err = DoHandshake(nullptr, nullptr, 0);
    ScheduleRetransmit();
    return err;
  }

  for (auto stream : streams_) {
    err = stream.second->SendPendingData(retransmit);
    if (err != 0)
      return err;
  }

  QuicPathStorage path;

  for ( ;; ) {
    Debug(this, "Writing packet data");
    ssize_t n =
        ngtcp2_conn_write_pkt(
            connection_,
            &path.path,
            sendbuf_.wpos(),
            max_pktlen_,
            uv_hrtime());
    if (n < 0) {
      Debug(this, "There was an error writing the packet. Error %d", n);
      return HandleError(n);
    }
    if (n == 0) {
      Debug(this, "Nothing to write");
      break;
    }
    sendbuf_.push(n);

    remote_address_.Update(&path.path.remote);

    err = SendPacket();
    if (err != 0) {
      Debug(this, "Error sending packet. Error %d", err);
      return err;
    }
  }
  Debug(this, "Done sending pending server session data");

  ScheduleRetransmit();
  return 0;
}

int QuicServerSession::StartClosingPeriod(int error) {
  CHECK(!IsDestroyed());
  if (IsInClosingPeriod())
    return 0;

  Debug(this, "Closing period has started");

  StopRetransmitTimer();
  StartIdleTimer(-1);

  sendbuf_.reset();
  CHECK_GE(sendbuf_.left(), max_pktlen_);

  conn_closebuf_ = std::make_unique<QuicBuffer>(NGTCP2_MAX_PKTLEN_IPV4);

  uint16_t err_code;
  if (tls_alert_) {
    err_code = NGTCP2_CRYPTO_ERROR | tls_alert_;
  } else {
    err_code = ngtcp2_err_infer_quic_transport_error_code(error);
  }

  ssize_t n =
      ngtcp2_conn_write_connection_close(
          connection_,
          nullptr,
          conn_closebuf_->wpos(),
          max_pktlen_,
          err_code,
          uv_hrtime());
  if (n < 0)
    return -1;

  conn_closebuf_->push(n);
  return 0;
}

void QuicServerSession::StartDrainingPeriod() {
  CHECK(!IsDestroyed());
  if (draining_)
    return;
  StopRetransmitTimer();
  draining_ = true;
  StartIdleTimer(-1);
}

int QuicServerSession::TLSHandshake_Initial() {
  std::array<uint8_t, 8> buf;
  size_t nread;
  int err = SSL_read_early_data(ssl(), buf.data(), buf.size(), &nread);
  initial_ = false;
  switch (err) {
    case SSL_READ_EARLY_DATA_ERROR: {
      Debug(this, "TLS Read Early Data Error. Error %d", err);
      int code = SSL_get_error(ssl(), err);
      switch (code) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          return 0;
        case SSL_ERROR_SSL:
          Debug(this, "TLS handshake error: %s", TLSErrorString(code));
          return NGTCP2_ERR_CRYPTO;
        default:
          Debug(this, "TLS handshake error: %d", code);
          return NGTCP2_ERR_CRYPTO;
      }
      break;
    }
    case SSL_READ_EARLY_DATA_SUCCESS:
      Debug(this, "TLS Read Early Data Success");
      if (nread > 0)
        return NGTCP2_ERR_PROTO;
      break;
    case SSL_READ_EARLY_DATA_FINISH:
      Debug(this, "TLS Read Early Data Finish");
  }
  return 0;
}

int QuicServerSession::TLSHandshake_Complete() {
  return 0;
}

const ngtcp2_cid* QuicServerSession::rcid() const {
  return &rcid_;
}

const ngtcp2_cid* QuicServerSession::scid() const {
  return &scid_;
}

// QUIC Client Session

QuicClientSession* QuicClientSession::New(
    QuicSocket* socket,
    const struct sockaddr* addr,
    uint32_t version,
    SecureContext* context,
    const char* hostname,
    uint32_t port) {
  Local<Object> obj;
  if (!socket->env()
             ->quicclientsession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return nullptr;
  }
  return new QuicClientSession(socket,
                               obj,
                               addr,
                               version,
                               context,
                               hostname,
                               port);
}

QuicClientSession::QuicClientSession(
    QuicSocket* socket,
    v8::Local<v8::Object> wrap,
    const struct sockaddr* addr,
    uint32_t version,
    SecureContext* context,
    const char* hostname,
    uint32_t port) :
    QuicSession(socket, wrap, context, AsyncWrap::PROVIDER_QUICCLIENTSESSION),
    resumption_(false),
    hostname_(hostname) {
    // port_(port) {
  Init(addr, version);
}

int QuicClientSession::Init(
    const struct sockaddr* addr,
    uint32_t version) {

  CHECK_NULL(connection_);

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS(ssl());

  ngtcp2_cid dcid;

  // TODO(@jasnell): Make scid len configurable
  scid_.datalen = NGTCP2_SV_SCIDLEN;
  EntropySource(scid_.data, scid_.datalen);

  // TODO(@jasnell): Make dcid and dcid len configurable
  dcid.datalen = NGTCP2_SV_SCIDLEN;
  EntropySource(dcid.data, dcid.datalen);

  ngtcp2_settings settings{};
  QuicSessionConfig client_session_config;
  client_session_config.Set(env());
  client_session_config.ToSettings(&settings);

  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  int err =
      ngtcp2_conn_client_new(
          &connection_,
          &dcid,
          &scid_,
          *path,
          version,
          &callbacks_,
          &settings,
          static_cast<QuicSession*>(this));
  if (err != 0) {
    Debug(this, "There was an error creating the session. Error %d", err);
    return err;
  }

  err = SetupInitialCryptoContext();
  if (err != 0)
    return err;

  QuicCID cid(scid_);
  socket_->AddSession(cid, this);
  StartIdleTimer(settings.idle_timeout);

  // Zero Round Trip
  for (auto stream : streams_) {
    err = stream.second->Send0RTTData();
    if (err != 0)
      return err;
  }

  return DoHandshakeWriteOnce();
}

void QuicClientSession::InitTLS_Post(SSL* ssl) {
  SSL_set_connect_state(ssl);

  const uint8_t* alpn = reinterpret_cast<const uint8_t*>(NGTCP2_ALPN_D19);
  size_t alpnlen = strsize(NGTCP2_ALPN_D19);
  SSL_set_alpn_protos(ssl, alpn, alpnlen);

  if (SocketAddress::numeric_host(hostname_)) {
    // TODO(@jasnell): Proper SNI hostname
    SSL_set_tlsext_host_name(ssl, "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl, hostname_);
  }
  // TODO(@jasnell): Add support for session file
}

int QuicClientSession::OnKey(
    int name,
    const uint8_t* secret,
    size_t secretlen) {
  CHECK(!IsDestroyed());
  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      tx_secret_.assign(secret, secret + secretlen);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      rx_secret_.assign(secret, secret + secretlen);
      break;
    default:
      return 0;
  }

  if (Negotiated_PRF(crypto_ctx_, ssl()) != 0 ||
      Negotiated_AEAD(crypto_ctx_, ssl()) != 0) {
    return -1;
  }

  CryptoParams params;

  if (SetupKeys(secret, secretlen, params, crypto_ctx_) != 0)
    return -1;

  ngtcp2_conn_set_aead_overhead(
      connection_,
      AEAD_Max_Overhead(crypto_ctx_));

  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_early_keys>(connection_, params);
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_tx_keys>(connection_, params);
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_tx_keys>(connection_, params);
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_rx_keys>(connection_, params);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_rx_keys>(connection_, params);
    break;
  }

  return 0;
}

int QuicClientSession::DoHandshakeWriteOnce() {
  Debug(this, "Do Handshake Write");

  ssize_t nwrite =
      ngtcp2_conn_write_handshake(
          connection_,
          sendbuf_.wpos(),
          max_pktlen_,
          uv_hrtime());
  if (nwrite < 0) {
    Debug(this, "Error %d writing connection handshake", nwrite);
    return -1;
  }

  if (nwrite == 0)
    return 0;

  sendbuf_.push(nwrite);

  Debug(this, "Sending handshake packet");

  int err = SendPacket();
  if (err != 0)
    return err;
  return nwrite;
}

int QuicClientSession::TLSRead() {
  CHECK(!IsDestroyed());
  ClearTLSError();

  std::array<uint8_t, 4096> buf;
  size_t nread;
  Debug(this, "Reading TLS data");
  for (;;) {
    int err = SSL_read_ex(ssl(), buf.data(), buf.size(), &nread);
    if (err == 1) {
      continue;
    }
    int code = SSL_get_error(ssl(), 0);
    switch (code) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        return 0;
      case SSL_ERROR_SSL:
      case SSL_ERROR_ZERO_RETURN:
        // TLS read error
        // std::cerr << "TLS read error: "
        //           << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return NGTCP2_ERR_CRYPTO;
      default:
        //std::cerr << "TLS read error: " << err << std::endl;
        return NGTCP2_ERR_CRYPTO;
    }
  }
}

int QuicClientSession::DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {

  CHECK(!IsDestroyed());

  int err;
  err = SendPacket();
  if (err != 0)
    return err;

  Debug(this, "Reading %d bytes of handshake data from peer", datalen);
  err = ngtcp2_conn_read_handshake(
      connection_,
      path,
      data, datalen,
      uv_hrtime());
  if (err != 0) {
    Debug(this, "Failure reading handshake data: %s\n", ngtcp2_strerror(err));
    Close();
    return -1;
  }

  // Zero Round Trip
  for (auto stream : streams_) {
    err = stream.second->Send0RTTData();
    if (err != 0)
      return err;
  }

  ssize_t nwrite;
  for (;;) {
    nwrite = DoHandshakeWriteOnce();
    if (nwrite <= 0)
      break;
  }
  return nwrite;
}

int QuicClientSession::HandleError(int code) {
  if (!connection_ || IsInClosingPeriod())
    return 0;

  sendbuf_.reset();
  CHECK(sendbuf_.left() >= max_pktlen_);

  if (code == NGTCP2_ERR_RECV_VERSION_NEGOTIATION)
    return 0;

  //TODO(danbev) Use error code
  /*
  uint16_t err_code =
      tls_alert_ ?
          NGTCP2_CRYPTO_ERROR | tls_alert_ :
          ngtcp2_err_infer_quic_transport_error_code(code);
  */

  return SendConnectionClose(code);
}

int QuicClientSession::SendConnectionClose(int error) {
  CHECK(!IsDestroyed());
  ssize_t n =
      ngtcp2_conn_write_connection_close(
        connection_,
        nullptr,
        sendbuf_.wpos(),
        max_pktlen_,
        error,
        uv_hrtime());
  if (n < 0) {
    Debug(this, "Error writing connection close: %d", n);
    return -1;
  }
  sendbuf_.push(n);

  return SendPacket();
}

void QuicClientSession::NewSessionDoneCb() {}

void QuicClientSession::OnIdleTimeout() {
  if (connection_ == nullptr)
    return;
  Debug(this, "Idle timeout");
  Close();
}

void QuicClientSession::OnRetransmitTimeout() {
  Debug(this, "Retransmit timer fired...");
  uint64_t now = uv_hrtime();

  if (ngtcp2_conn_loss_detection_expiry(connection_) <= now) {
    Debug(this, "Connection loss detection...");
    int err = SendPendingData(true);
    if (err != 0)
      HandleError(err);
    return;
  }

  if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Connection ack delay...");
    int err = SendPendingData();
    if (err != 0)
      HandleError(err);
  }
}

int QuicClientSession::Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  CHECK(!IsDestroyed());
  Debug(this, "Received packet. nread = %d bytes", nread);
  int err;

  if (IsHandshakeCompleted()) {
    Debug(this, "TLS Handshake is completed");

    QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

    err = ngtcp2_conn_read_pkt(
        connection_,
        *path,
        data, nread,
        uv_hrtime());
    if (err != 0) {
      // TODO(@jasnell): Close with the error code?
      Close();
      return err;
    }
    Debug(this, "Successfully read packet");
  } else {
    Debug(this, "TLS Handshake continuing");
    return DoHandshake(nullptr, data, nread);
  }
  StartIdleTimer(-1);
  return 0;
}

int QuicClientSession::ReceiveRetry() {
  CHECK(!IsDestroyed());
  Debug(this, "Received retry");
  return SetupInitialCryptoContext();
}

int QuicClientSession::ExtendMaxStreams(
    bool bidi,
    uint64_t max_streams) {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  Local<Value> argv[] = {
    bidi ? v8::True(env()->isolate()) : v8::False(env()->isolate()),
    Number::New(env()->isolate(), static_cast<double>(max_streams))
  };
  MakeCallback(env()->quic_on_session_extend_function(), arraysize(argv), argv);
  return 0;
}

int QuicClientSession::ExtendMaxStreamsUni(
    uint64_t max_streams) {
  CHECK(!IsDestroyed());
  return ExtendMaxStreams(false, max_streams);
}

int QuicClientSession::ExtendMaxStreamsBidi(
    uint64_t max_streams) {
  CHECK(!IsDestroyed());
  return ExtendMaxStreams(true, max_streams);
}

void QuicClientSession::Remove() {
  CHECK(!IsDestroyed());
  Debug(this, "Remove this QuicClientSession from the QuicSocket.");
  QuicCID scid(scid_);
  Socket()->RemoveSession(scid);
}

int QuicClientSession::SendPendingData(bool retransmit) {
  CHECK(!IsDestroyed());
  Debug(this, "Sending pending data for client session");
  int err;

  err = SendPacket();
  if (sendbuf_.size() > 0) {
    Debug(this, "Sending pending %d bytes of session data", sendbuf_.size());
    err = SendPacket();
    if (err != 0) {
      Debug(this, "Error sending data. Error %d", err);
      return err;
    }
  }

  CHECK_GE(sendbuf_.left(), max_pktlen_);

  if (retransmit) {
    err = ngtcp2_conn_on_loss_detection_timer(connection_, uv_hrtime());
    if (err != 0) {
      Debug(this, "Error resetting loss detection timer. Error %d", err);
      // TODO(@jasnell): Close with error code
      Close();
      return -1;
    }
  }

  if (!IsHandshakeCompleted()) {
    Debug(this, "Handshake is not completed");
    err = DoHandshake(nullptr, nullptr, 0);
    //ScheduleRetransmit();
    return err;
  }

  for ( ;; ) {
    Debug(this, "Writing packet data");
    ssize_t n =
        ngtcp2_conn_write_pkt(
            connection_,
            nullptr,
            sendbuf_.wpos(),
            max_pktlen_,
            uv_hrtime());
    if (n < 0) {
      Debug(this, "There was an error writing the packet. Error %d", n);
      return HandleError(n);
    }
    if (n == 0) {
      Debug(this, "Nothing to write");
      break;
    }
    sendbuf_.push(n);

    err = SendPacket();
    if (err != 0) {
      Debug(this, "Error sending packet. Error %d", err);
      return err;
    }
  }

  if (!retransmit) {
    for (auto stream : streams_) {
      err = stream.second->SendPendingData(retransmit);
      if (err != 0)
        return err;
    }
  }

  Debug(this, "Done sending pending client session data");

  //ScheduleRetransmit();
  return 0;
}

int QuicClientSession::TLSHandshake_Complete() {
  if (resumption_ &&
      SSL_get_early_data_status(ssl()) != SSL_EARLY_DATA_ACCEPTED) {
    Debug(this, "Early data was rejected.");
    int err = ngtcp2_conn_early_data_rejected(connection_);
    if (err != 0) {
      Debug(this,
            "Failure notifying ngtcp2 about early data rejection. Error %d",
            err);
    }
    return err;
  }
  return TLSRead();
}

int QuicClientSession::TLSHandshake_Initial() {
  if (resumption_ && SSL_SESSION_get_max_early_data(SSL_get_session(ssl()))) {
    size_t nwrite;
    int err = SSL_write_early_data(ssl(), "", 0, &nwrite);
    if (err == 0) {
      err = SSL_get_error(ssl(), err);
      switch (err) {
        case SSL_ERROR_SSL:
          Debug(this, "TLS Handshake Error: %s",
                ERR_error_string(ERR_get_error(), nullptr));
          break;
        default:
          Debug(this, "TLS Handshake Error: %d", err);
      }
      return -1;
    }
  }
  initial_ = false;
  return 0;
}

int QuicClientSession::SetupInitialCryptoContext() {
  CHECK(!IsDestroyed());
  int err;

  CryptoInitialParams params;

  const ngtcp2_cid* dcid = ngtcp2_conn_get_dcid(connection_);

  prf_sha256(hs_crypto_ctx_);
  aead_aes_128_gcm(hs_crypto_ctx_);

  err =
      DeriveInitialSecret(
          params,
          dcid,
          reinterpret_cast<const uint8_t*>(NGTCP2_INITIAL_SALT),
          strsize(NGTCP2_INITIAL_SALT));
  if (err != 0) {
    Debug(this, "Failure deriving initial secret");
    return -1;
  }

  if (SetupClientSecret(params, hs_crypto_ctx_) != 0)
    return -1;

  InstallKeys<ngtcp2_conn_install_initial_tx_keys>(connection_, params);

  if (SetupServerSecret(params, hs_crypto_ctx_) != 0)
    return -1;

  InstallKeys<ngtcp2_conn_install_initial_rx_keys>(connection_, params);

  return 0;
}


// JavaScript API
namespace {
void QuicSessionDestroy(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Destroy();
}

void NewQuicClientSession(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsObject());
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args[0].As<Object>());

  node::Utf8Value address(args.GetIsolate(), args[2]);
  int32_t family;
  uint32_t port, flags;
  if (!args[1]->Int32Value(env->context()).To(&family) ||
      !args[3]->Uint32Value(env->context()).To(&port) ||
      !args[4]->Uint32Value(env->context()).To(&flags))
    return;

  CHECK(args[5]->IsObject());  // Secure Context
  SecureContext* sc;
  ASSIGN_OR_RETURN_UNWRAP(&sc, args[5].As<Object>());

  sockaddr_storage addr;
  int err = SocketAddress::ToSockAddr(family, *address, port, &addr);
  if (err != 0)
    return args.GetReturnValue().Set(err);

  socket->ReceiveStart();

  // TODO(@jasnell): Make version configurable??
  QuicClientSession* session =
      QuicClientSession::New(
          socket,
          const_cast<const sockaddr*>(reinterpret_cast<sockaddr*>(&addr)),
          NGTCP2_PROTO_VER_D19, sc,
          *address,
          port);
  CHECK_NOT_NULL(session);

  //socket->SendPendingData();

  args.GetReturnValue().Set(session->object());
}
}

void QuicServerSession::Initialize(
    Environment* env,
    Local<Object> target,
    Local<Context> context) {
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "QuicServerSession");
  Local<FunctionTemplate> session = FunctionTemplate::New(env->isolate());
  session->SetClassName(class_name);
  session->Inherit(AsyncWrap::GetConstructorTemplate(env));
  Local<ObjectTemplate> sessiont = session->InstanceTemplate();
  sessiont->SetInternalFieldCount(1);
  sessiont->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(session,
                      "destroy",
                      QuicSessionDestroy);
  env->set_quicserversession_constructor_template(sessiont);
}

void QuicClientSession::Initialize(
    Environment* env,
    Local<Object> target,
    Local<Context> context) {
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "QuicClientSession");
  Local<FunctionTemplate> session = FunctionTemplate::New(env->isolate());
  session->SetClassName(class_name);
  session->Inherit(AsyncWrap::GetConstructorTemplate(env));
  Local<ObjectTemplate> sessiont = session->InstanceTemplate();
  sessiont->SetInternalFieldCount(1);
  sessiont->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(session,
                      "destroy",
                      QuicSessionDestroy);
  env->set_quicclientsession_constructor_template(sessiont);

  env->SetMethod(target, "createClientSession", NewQuicClientSession);
}

}  // namespace quic
}  // namespace node
