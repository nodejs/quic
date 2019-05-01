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
#include "node_crypto_clienthello-inl.h"  // ClientHelloParser

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <array>
#include <functional>
#include <type_traits>
#include <utility>


namespace node {

using crypto::EntropySource;
using crypto::SecureContext;

using v8::ArrayBufferView;
using v8::Context;
using v8::Float64Array;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Local;
using v8::MaybeLocal;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

namespace quic {

namespace {

// All of the functions within this anonymous namespace provide support for
// the TLS 1.3 handshake and cryptographic protection of QUIC frames. These
// are supporting functions that are used frequently throughout the life of
// a QuicSession. Most of the functionality here is defined by either TLS 1.3
// or the TLS 1.3 for QUIC specification.

// MessageCB provides a hook into the TLS handshake dataflow. Currently, it
// is used to capture TLS alert codes (errors) and to collect the TLS handshake
// data that is to be sent
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
      session->WriteHandshake(reinterpret_cast<const uint8_t*>(buf), len);
      break;
    case SSL3_RT_ALERT:
      CHECK_EQ(len, 2);
      if (msg[0] == 2)
        session->SetTLSAlert(msg[1]);
      break;
    default:
      // Fall-through
      break;
  }
}

// KeyCB provides a hook into the keying process of the TLS handshake,
// triggering registration of the keys associated with the TLS session.
int KeyCB(
    SSL* ssl,
    int name,
    const unsigned char* secret,
    size_t secretlen,
    void* arg) {
  QuicSession* session = static_cast<QuicSession*>(arg);

  return session->OnKey(name, secret, secretlen) != 0 ? 0 : 1;
}

#define RETURN_IF_FAIL(test, success, ret) if (test != success) return ret;
#define RETURN_IF_FAIL_OPENSSL(test) RETURN_IF_FAIL(test, 1, -1)

// All QUIC data is encrypted and will pass through here at some point.
// The ngtcp2 callbacks trigger this function, and it should only ever
// be called from within an ngtcp2 callback.
inline ssize_t Encrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const CryptoContext* ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen) {
  size_t taglen = aead_tag_length(ctx);

  if (destlen < plaintextlen + taglen)
    return -1;

  DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> actx;
  actx.reset(EVP_CIPHER_CTX_new());
  CHECK(actx);

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptInit_ex(
          actx.get(),
          ctx->aead,
          nullptr,
          nullptr,
          nullptr))

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_SET_IVLEN,
          noncelen,
          nullptr))

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptInit_ex(
          actx.get(),
          nullptr,
          nullptr,
          key,
          nonce))

  size_t outlen = 0;
  int len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptUpdate(
          actx.get(),
          nullptr,
          &len,
          ad,
          adlen))

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptUpdate(
          actx.get(),
          dest,
          &len,
          plaintext,
          plaintextlen))

  outlen = len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptFinal_ex(
          actx.get(),
          dest + outlen,
          &len))

  outlen += len;

  CHECK_LE(outlen + taglen, destlen);

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_GET_TAG,
          taglen,
          dest + outlen))

  outlen += taglen;

  return outlen;
}

// All QUIC data is encrypted and will pass through here at some point.
// The ngtcp2 callbacks trigger this function, and it should only ever
// be called from within an ngtcp2 callback.
inline ssize_t Decrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const CryptoContext* ctx,
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

  DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> actx;
  actx.reset(EVP_CIPHER_CTX_new());
  CHECK(actx);

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptInit_ex(
          actx.get(),
          ctx->aead,
          nullptr,
          nullptr,
          nullptr))

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_SET_IVLEN,
          noncelen,
          nullptr))

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptInit_ex(
          actx.get(),
          nullptr,
          nullptr,
          key,
          nonce))

  size_t outlen;
  int len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptUpdate(
          actx.get(),
          nullptr,
          &len,
          ad,
          adlen))

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptUpdate(
          actx.get(),
          dest,
          &len,
          ciphertext,
          ciphertextlen))

  outlen = len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_SET_TAG,
          taglen,
          const_cast<uint8_t *>(tag)))

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptFinal_ex(
          actx.get(),
          dest + outlen,
          &len))

  outlen += len;

  return outlen;
}

// QUIC headers are protected using TLS as well as the data. As part
// of the frame encoding/decoding process, a header protection mask
// must be calculated and applied. The ngtcp2 callbacks trigger this
// function, and it should only ever be called from within an ngtcp2
// callback.
inline ssize_t HP_Mask(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext& ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  static constexpr uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

  DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> actx;
  actx.reset(EVP_CIPHER_CTX_new());
  CHECK(actx);

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptInit_ex(
          actx.get(),
          ctx.hp,
          nullptr,
          key,
          sample))

  size_t outlen = 0;
  int len;
  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptUpdate(
          actx.get(),
          dest,
          &len,
          PLAINTEXT,
          strsize(PLAINTEXT)))
  CHECK_EQ(len, 5);

  outlen = len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptFinal_ex(
          actx.get(),
          dest + outlen,
          &len))

  CHECK_EQ(len, 0);

  return outlen;
}

// The HKDF_Expand function is used exclusively by the HKDF_Expand_Label
// function to establish the packet protection keys. HKDF-Expand-Label
// is a component of TLS 1.3. This function is only called by the
// HKDF_Expand_label function.
inline int HKDF_Expand(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* info,
    size_t infolen,
    const CryptoContext* ctx) {
  DeleteFnPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> pctx;
  pctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
  CHECK(pctx);

  RETURN_IF_FAIL_OPENSSL(EVP_PKEY_derive_init(pctx.get()))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_hkdf_mode(
          pctx.get(),
          EVP_PKEY_HKDEF_MODE_EXPAND_ONLY))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set_hkdf_md(
          pctx.get(),
          ctx->prf))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_salt(
          pctx.get(), "", 0))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_key(
          pctx.get(),
          secret,
          secretlen))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_add1_hkdf_info(
          pctx.get(),
          info,
          infolen))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_derive(
          pctx.get(),
          dest,
          &destlen))

  return 0;
}

// The HKDF_Extract function is used to extract initial keying material
// used to derive the packet protection keys. HKDF-Extract is a component
// of TLS 1.3.
inline int HKDF_Extract(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* salt,
    size_t saltlen,
    const CryptoContext* ctx) {
  DeleteFnPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> pctx;
  pctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
  CHECK(pctx);

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_derive_init(
          pctx.get()))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_hkdf_mode(
          pctx.get(),
          EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set_hkdf_md(
          pctx.get(),
          ctx->prf))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_salt(
          pctx.get(),
          salt,
          saltlen))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_key(
          pctx.get(),
          secret,
          secretlen))

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_derive(
          pctx.get(),
          dest,
          &destlen))

  return 0;
}

// The HKDF_Expand_Label function is used as part of the process to
// derive packet protection keys for QUIC packets.
inline int HKDF_Expand_Label(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* label,
    size_t labellen,
    const CryptoContext* ctx) {
  std::array<uint8_t, 256> info;
  static constexpr const uint8_t LABEL[] = "tls13 ";

  auto p = std::begin(info);
  *p++ = destlen / 256;
  *p++ = destlen % 256;
  *p++ = strsize(LABEL) + labellen;
  p = std::copy_n(LABEL, strsize(LABEL), p);
  p = std::copy_n(label, labellen, p);
  *p++ = 0;

  return HKDF_Expand(
      dest, destlen,
      secret, secretlen,
      info.data(),
      p - std::begin(info),
      ctx);
}

inline int DeriveInitialSecret(
    CryptoInitialParams* params,
    const ngtcp2_cid* secret,
    const uint8_t* salt,
    size_t saltlen) {
  CryptoContext ctx;
  prf_sha256(&ctx);
  return HKDF_Extract(
      params->initial_secret.data(),
      params->initial_secret.size(),
      secret->data, secret->datalen,
      salt, saltlen,
      &ctx);
}

inline int DeriveServerInitialSecret(
    CryptoInitialParams* params) {
  static constexpr uint8_t LABEL[] = "server in";
  CryptoContext ctx;
  prf_sha256(&ctx);
  return HKDF_Expand_Label(
      params->secret.data(),
      params->secret.size(),
      params->initial_secret.data(),
      params->initial_secret.size(),
      LABEL, strsize(LABEL), &ctx);
}

inline int DeriveClientInitialSecret(
    CryptoInitialParams* params) {
  static constexpr uint8_t LABEL[] = "client in";
  CryptoContext ctx;
  prf_sha256(&ctx);
  return HKDF_Expand_Label(
      params->secret.data(),
      params->secret.size(),
      params->initial_secret.data(),
      params->initial_secret.size(),
      LABEL, strsize(LABEL), &ctx);
}

inline ssize_t DerivePacketProtectionKey(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext* ctx) {
  static constexpr uint8_t LABEL[] = "quic key";

  size_t keylen = aead_key_length(ctx);
  if (keylen > destlen)
    return -1;

  RETURN_IF_FAIL(
      HKDF_Expand_Label(
          dest,
          keylen,
          secret,
          secretlen,
          LABEL,
          strsize(LABEL),
          ctx), 0, -1)

  return keylen;
}

inline ssize_t DerivePacketProtectionIV(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext* ctx) {
  static constexpr uint8_t LABEL[] = "quic iv";

  size_t ivlen = std::max(static_cast<size_t>(8), aead_nonce_length(ctx));
  if (ivlen > destlen)
    return -1;

  RETURN_IF_FAIL(
      HKDF_Expand_Label(
          dest,
          ivlen,
          secret,
          secretlen,
          LABEL,
          strsize(LABEL),
          ctx), 0, -1)

  return ivlen;
}

inline ssize_t DeriveHeaderProtectionKey(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext* ctx) {
  static constexpr uint8_t LABEL[] = "quic hp";

  size_t keylen = aead_key_length(ctx);
  if (keylen > destlen)
    return -1;

  RETURN_IF_FAIL(
      HKDF_Expand_Label(
          dest,
          keylen,
          secret,
          secretlen,
          LABEL,
          strsize(LABEL),
          ctx), 0, -1)

  return keylen;
}

inline int DeriveTokenKey(
    CryptoToken* params,
    const uint8_t* rand_data,
    size_t rand_datalen,
    CryptoContext* context,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {
  std::array<uint8_t, 32> secret;

  RETURN_IF_FAIL(
      HKDF_Extract(
          secret.data(),
          secret.size(),
          token_secret->data(),
          token_secret->size(),
          rand_data,
          rand_datalen,
          context), 0, -1)

  ssize_t slen =
      DerivePacketProtectionKey(
          params->key.data(),
          params->keylen,
          secret.data(),
          secret.size(),
          context);
  if (slen < 0)
    return -1;
  params->keylen = slen;

  slen =
      DerivePacketProtectionIV(
          params->iv.data(),
          params->ivlen,
          secret.data(),
          secret.size(),
          context);
  if (slen < 0)
    return -1;
  params->ivlen = slen;

  return 0;
}

inline ssize_t UpdateTrafficSecret(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* secret,
    size_t secretlen,
    const CryptoContext* ctx) {

  static constexpr uint8_t LABEL[] = "traffic upd";

  if (destlen < secretlen)
    return -1;

  RETURN_IF_FAIL(
      HKDF_Expand_Label(
          dest,
          secretlen,
          secret,
          secretlen,
          LABEL,
          strsize(LABEL),
          ctx), 0, -1)

  return secretlen;
}

inline int MessageDigest(
    uint8_t* res,
    const EVP_MD* meth,
    const uint8_t* data,
    size_t len) {
  DeleteFnPtr<EVP_MD_CTX, EVP_MD_CTX_free> ctx;
  ctx.reset(EVP_MD_CTX_new());
  CHECK(ctx);

  RETURN_IF_FAIL_OPENSSL(EVP_DigestInit_ex(ctx.get(), meth, nullptr))
  RETURN_IF_FAIL_OPENSSL(EVP_DigestUpdate(ctx.get(), data, len))
  unsigned int mdlen = EVP_MD_size(meth);
  RETURN_IF_FAIL_OPENSSL(EVP_DigestFinal_ex(ctx.get(), res, &mdlen))
  return 0;
}

inline int GenerateRandData(
    uint8_t* buf,
    size_t len) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;
  EntropySource(rand.data(), rand.size());

  RETURN_IF_FAIL(
      MessageDigest(
          md.data(),
          EVP_sha256(),
          rand.data(),
          rand.size()), 0, -1);
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

inline int SetupKeys(
  const uint8_t* secret,
  size_t secretlen,
  CryptoParams* params,
  const CryptoContext* context) {
  params->keylen =
      DerivePacketProtectionKey(
          params->key.data(),
          params->key.size(),
          secret,
          secretlen,
          context);
  if (params->keylen < 0)
    return -1;

  params->ivlen =
      DerivePacketProtectionIV(
          params->iv.data(),
          params->iv.size(),
          secret, secretlen,
          context);
  if (params->ivlen < 0)
    return -1;

  params->hplen =
      DeriveHeaderProtectionKey(
          params->hp.data(),
          params->hp.size(),
          secret, secretlen,
          context);
  if (params->hplen < 0)
    return -1;

  return 0;
}

inline int SetupClientSecret(
  CryptoInitialParams* params,
  const CryptoContext* context) {
  RETURN_IF_FAIL(DeriveClientInitialSecret(params), 0, -1);

  params->keylen =
      DerivePacketProtectionKey(
          params->key.data(),
          params->key.size(),
          params->secret.data(),
          params->secret.size(),
          context);
  if (params->keylen < 0)
    return -1;

  params->ivlen =
      DerivePacketProtectionIV(
          params->iv.data(),
          params->iv.size(),
          params->secret.data(),
          params->secret.size(),
          context);
  if (params->ivlen < 0)
    return -1;

  params->hplen =
      DeriveHeaderProtectionKey(
          params->hp.data(),
          params->hp.size(),
          params->secret.data(),
          params->secret.size(),
          context);
  if (params->hplen < 0)
    return -1;

  return 0;
}

inline int SetupServerSecret(
    CryptoInitialParams* params,
    const CryptoContext* context) {

  RETURN_IF_FAIL(DeriveServerInitialSecret(params), 0, -1);

  params->keylen =
      DerivePacketProtectionKey(
          params->key.data(),
          params->key.size(),
          params->secret.data(),
          params->secret.size(),
          context);
  if (params->keylen < 0)
    return -1;

  params->ivlen =
      DerivePacketProtectionIV(
          params->iv.data(),
          params->iv.size(),
          params->secret.data(),
          params->secret.size(),
          context);
  if (params->ivlen < 0)
    return -1;

  params->hplen =
      DeriveHeaderProtectionKey(
          params->hp.data(),
          params->hp.size(),
          params->secret.data(),
          params->secret.size(),
          context);
  if (params->hplen < 0)
    return -1;

  return 0;
}

template <install_fn fn>
inline int InstallKeys(
    ngtcp2_conn* connection,
    const CryptoParams& params) {
  return fn(connection,
     params.key.data(),
     params.keylen,
     params.iv.data(),
     params.ivlen,
     params.hp.data(),
     params.hplen);
}

template <install_fn fn>
inline int InstallKeys(
    ngtcp2_conn* connection,
    const CryptoInitialParams& params) {
  return fn(connection,
     params.key.data(),
     params.keylen,
     params.iv.data(),
     params.ivlen,
     params.hp.data(),
     params.hplen);
}

}  // namespace


// The QuicSessionConfig is a utility class that uses an AliasedBuffer via the
// Environment to collect configuration settings for a QuicSession.

// Reset the QuicSessionConfig to initial defaults. The default values are set
// in the QUICSESSION_CONFIG macro definition in node_quic_session.h
void QuicSessionConfig::ResetToDefaults() {
#define V(idx, name, def) name##_ = def;
  QUICSESSION_CONFIG(V)
#undef V
}

// Sets the QuicSessionConfig using an AliasedBuffer for efficiency.
void QuicSessionConfig::Set(Environment* env) {
  ResetToDefaults();
  AliasedFloat64Array& buffer =
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
  ngtcp2_settings_default(settings);
#define V(idx, name, def) settings->name = name##_;
  QUICSESSION_CONFIG(V)
#undef V

  settings->log_printf = QuicSession::DebugLog;
  settings->initial_ts = uv_hrtime();
  settings->disable_migration = 0;

  if (stateless_reset_token) {
    settings->stateless_reset_token_present = 1;
    EntropySource(settings->stateless_reset_token,
                  arraysize(settings->stateless_reset_token));
  }
}

// Static ngtcp2 callbacks are registered when ngtcp2 when a new ngtcp2_conn is
// created. These are static functions that, for the most part, simply defer to
// a QuicSession instance that is passed through as user_data.

int QuicSession::OnClientInitial(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->TLSHandshake(), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnReceiveClientInitial(
    ngtcp2_conn* conn,
    const ngtcp2_cid* dcid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ReceiveClientInitial(dcid), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
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
  return session->ReceiveCryptoData(offset, data, datalen);
}

int QuicSession::OnReceiveRetry(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_hd* hd,
    const ngtcp2_pkt_retry* retry,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ReceiveRetry(), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnExtendMaxStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ExtendMaxStreamsBidi(max_streams), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnExtendMaxStreamsUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ExtendMaxStreamsUni(max_streams), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnHandshakeCompleted(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
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
  ssize_t nwrite =
      session->DoHSEncrypt(
          dest, destlen,
          plaintext, plaintextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
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
  ssize_t nwrite =
      session->DoHSDecrypt(
          dest, destlen,
          ciphertext, ciphertextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0)
    return NGTCP2_ERR_TLS_DECRYPT;
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
  ssize_t nwrite =
      session->DoEncrypt(
          dest, destlen,
          plaintext, plaintextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
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
  ssize_t nwrite =
      session->DoDecrypt(
          dest, destlen,
          ciphertext, ciphertextlen,
          key, keylen,
          nonce, noncelen,
          ad, adlen);
  if (nwrite < 0)
    return NGTCP2_ERR_TLS_DECRYPT;
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
  ssize_t nwrite =
      session->DoInHPMask(
          dest, destlen,
          key, keylen,
          sample, samplelen);
  if (nwrite < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
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
  ssize_t nwrite =
      session->DoHPMask(
          dest, destlen,
          key, keylen,
          sample, samplelen);
  if (nwrite < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
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
  RETURN_IF_FAIL(
      session->ReceiveStreamData(stream_id, fin, offset, data, datalen), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnStreamOpen(
    ngtcp2_conn* conn,
    int64_t stream_id,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->StreamOpen(stream_id), 0,
      NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnAckedCryptoOffset(
    ngtcp2_conn* conn,
    uint64_t offset,
    size_t datalen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
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
  RETURN_IF_FAIL(
      session->AckedStreamDataOffset(stream_id, offset, datalen), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

int QuicSession::OnStreamClose(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->StreamClose(stream_id, app_error_code);
  return 0;
}

int QuicSession::OnStreamReset(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t final_size,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->StreamReset(stream_id, final_size, app_error_code);
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
  session->GetNewConnectionID(cid, token, cidlen);
  return 0;
}

int QuicSession::OnUpdateKey(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(session->UpdateKey(), 0, NGTCP2_ERR_CALLBACK_FAILURE)
  return 0;
}

int QuicSession::OnRemoveConnectionID(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->RemoveConnectionID(cid);
  return 0;
}

int QuicSession::OnPathValidation(ngtcp2_conn* conn,
                                  const ngtcp2_path* path,
                                  ngtcp2_path_validation_result res,
                                  void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  CHECK_NOT_NULL(session);
  if (res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
    session->SetLocalAddress(&path->local);
  } else {
    // TODO(danbev): How should a failed path validation be handled? A
    // connection migration might fail, which could be indicated by path
    // validation failure, and it may no longer be possible to use the local
    // address (for // example if migrating from wifi to 3g/4g).
  }
  return 0;
}

void QuicSession::SetupTokenContext(CryptoContext* context) {
  aead_aes_128_gcm(context);
  prf_sha256(context);
}

int QuicSession::GenerateToken(
    uint8_t* token,
    size_t* tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    CryptoContext* token_crypto_ctx,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {
  std::array<uint8_t, 4096> plaintext;

  const size_t addrlen = SocketAddress::GetAddressLen(addr);

  uint64_t now = uv_hrtime();

  auto p = std::begin(plaintext);
  p = std::copy_n(reinterpret_cast<const uint8_t *>(addr), addrlen, p);
  p = std::copy_n(reinterpret_cast<uint8_t *>(&now), sizeof(now), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  CryptoToken params;

  RETURN_IF_FAIL(GenerateRandData(rand_data.data(), rand_data.size()), 0, -1)

  RETURN_IF_FAIL(
      DeriveTokenKey(
          &params,
          rand_data.data(),
          rand_data.size(),
          token_crypto_ctx,
          token_secret), 0, -1)

  ssize_t n =
      Encrypt(
          token, *tokenlen,
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
  *tokenlen = n + rand_data.size();
  return 0;
}

int QuicSession::VerifyToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    CryptoContext* token_crypto_ctx,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {

  uv_getnameinfo_t info;
  char* host = nullptr;
  const size_t addrlen = SocketAddress::GetAddressLen(addr);
  if (uv_getnameinfo(
          env->event_loop(),
          &info, nullptr,
          addr, NI_NUMERICSERV) == 0) {
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

  RETURN_IF_FAIL(
      DeriveTokenKey(
          &params,
          rand_data,
          TOKEN_RAND_DATALEN,
          token_crypto_ctx,
          token_secret), 0, -1)

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

// QuicSession is an abstract base class that defines the code used by both
// server and client sessions.
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
    tx_crypto_offset_(0),
    state_(env()->isolate(), IDX_QUIC_SESSION_STATE_COUNT) {
  ssl_.reset(SSL_new(ctx->ctx_.get()));
  CHECK(ssl_);

  wrap->DefineOwnProperty(
    env()->context(),
    env()->state_string(),
    state_.GetJSArray(),
    v8::PropertyAttribute::ReadOnly);

  // TODO(@jasnell): memory accounting
  // env_->isolate()->AdjustAmountOfExternalAllocatedMemory(kExternalSize);
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

void QuicSession::AssociateCID(
    ngtcp2_cid* cid) {
  QuicCID id(cid);
  Socket()->AssociateCID(&id, this);
}

// Because of the fire-and-forget nature of UDP, the QuicSession must retain
// the data sent as packets until the recipient has acknowledged that data.
// This applies to TLS Handshake data as well as stream data. Once acknowledged,
// the buffered data can be released. This function is called only by the
// OnAckedCryptoOffset ngtcp2 callback function.
void QuicSession::AckedCryptoOffset(
    uint64_t offset,
    size_t datalen) {
  Debug(this,
        "Received acknowledgement for crypto data. Offset %llu, Length %d",
        offset, datalen);
  QuicBuffer::AckData(
      &handshake_,
      &handshake_idx_,
      &tx_crypto_offset_,
      offset + datalen);
}

// Because of the fire-and-forget nature of UDP, the QuicSession must retain
// the data sent as packets until the recipient has acknowledged that data.
// This applies to TLS Handshake data as well as stream data. Once acknowledged,
// the buffered data can be released. This function is called only by the
// OnAckedStreamDataOffset ngtcp2 callback function.
int QuicSession::AckedStreamDataOffset(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this,
        "Received acknowledgement for stream %llu data. Offset %llu, Length %d",
        stream_id, offset, datalen);
  QuicStream* stream = FindStream(stream_id);
  if (stream != nullptr)
    stream->AckedDataOffset(offset, datalen);
  return 0;
}

// Add the given QuicStream to this QuicSession's collection of streams. All
// streams added must be removed before the QuicSession instance is freed.
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

// Destroy the QuicSession and free it.
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
  QuicBuffer::Cancel(&handshake_);

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
  return Decrypt(
    dest, destlen,
    ciphertext, ciphertextlen,
    &crypto_ctx_,
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
  return Encrypt(
    dest, destlen,
    plaintext, plaintextlen,
    &crypto_ctx_,
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
  return Decrypt(
    dest, destlen,
    ciphertext, ciphertextlen,
    &hs_crypto_ctx_,
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
  return Encrypt(
    dest, destlen,
    plaintext, plaintextlen,
    &hs_crypto_ctx_,
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
  return HP_Mask(
    dest, destlen,
    hs_crypto_ctx_,
    key, keylen,
    sample, samplelen);
}

// Locate the QuicStream with the given id or return nullptr
QuicStream* QuicSession::FindStream(
    int64_t id) {
  auto it = streams_.find(id);
  if (it == std::end(streams_))
    return nullptr;
  return (*it).second;
}

bool QuicSession::IsDestroyed() {
  return connection_ == nullptr;
}

// Copies the local transport params into the given struct
// for serialization.
void QuicSession::GetLocalTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  ngtcp2_conn_get_local_transport_params(
    connection_,
    params);
}

// Gets the QUIC version negotiated for this QuicSession
uint32_t QuicSession::GetNegotiatedVersion() {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_get_negotiated_version(connection_);
}

// Generates and associates a new connection ID for this QuicSession
int QuicSession::GetNewConnectionID(
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen) {
  CHECK(!IsDestroyed());
  cid->datalen = cidlen;
  EntropySource(cid->data, cidlen);
  EntropySource(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  AssociateCID(cid);

  state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] =
    state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] + 1;

  return 0;
}

// Returns the associated peers address. Note that this
// value can change over the lifetime of the QuicSession.
// The fact that the session is not tied intrinsically to
// a single address is one of the benefits of QUIC.
SocketAddress* QuicSession::GetRemoteAddress() {
  return &remote_address_;
}

// Initialize the TLS context for this QuicSession. This
// is called exactly once during the construction and
// initialization of the QuicSession
void QuicSession::InitTLS() {
  Debug(this, "Initializing TLS.");
  BIO* bio = BIO_new(CreateBIOMethod());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl(), bio, bio);
  SSL_set_app_data(ssl(), this);
  SSL_set_msg_callback(ssl(), MessageCB);
  SSL_set_msg_callback_arg(ssl(), this);
  SSL_set_key_callback(ssl(), KeyCB, this);

  // Servers and Clients do slightly different things at
  // this point. Both QuicClientSession and QuicServerSession
  // override the InitTLS_Post function to carry on with
  // the TLS initialization.
  InitTLS_Post();
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

void QuicSession::OnRetransmitTimeout(
    uv_timer_t* timer) {
  QuicSession* session = static_cast<QuicSession*>(timer->data);
  CHECK_NOT_NULL(session);
  session->OnRetransmitTimeout();
}

// Used exclusively during the TLS handshake period to
// read local handshake data.
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

// Used exclusively during the TLS handshake period to
// read peer handshake data.
// TODO(@jasnell): Currently, this copies the handshake
// data. We should investigate
size_t QuicSession::ReadPeerHandshake(
    uint8_t* buf,
    size_t buflen) {
  CHECK(!IsDestroyed());
  Debug(this, "Reading peer handshake data.");
  size_t n = std::min(buflen, peer_handshake_.size() - ncread_);
  std::copy_n(std::begin(peer_handshake_) + ncread_, n, buf);
  ncread_ += n;
  return n;
}

// The ReceiveClientInitial function is called by ngtcp2 when
// a new connection has been initiated. The very first step to
// establishing a communication channel is to setup the keys
// that will be used to secure the communication.
int QuicSession::ReceiveClientInitial(
    const ngtcp2_cid* dcid) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving client initial parameters.");

  CryptoInitialParams params;

  RETURN_IF_FAIL(
      DeriveInitialSecret(
          &params,
          dcid,
          reinterpret_cast<const uint8_t *>(NGTCP2_INITIAL_SALT),
          strsize(NGTCP2_INITIAL_SALT)), 0, -1)

  SetupTokenContext(&hs_crypto_ctx_);

  RETURN_IF_FAIL(SetupServerSecret(&params, &hs_crypto_ctx_), 0, -1)
  InstallKeys<ngtcp2_conn_install_initial_tx_keys>(connection_, params);

  RETURN_IF_FAIL(SetupClientSecret(&params, &hs_crypto_ctx_), 0, -1)
  InstallKeys<ngtcp2_conn_install_initial_rx_keys>(connection_, params);

  return 0;
}

// The HandshakeCompleted function is called by ngtcp2 once it
// determines that the TLS Handshake is done. The only thing we
// need to do at this point is let the javascript side know.
void QuicSession::HandshakeCompleted() {
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);

  Local<Value> servername;
  Local<Value> alpn;
  Local<Value> cipher;
  Local<Value> version;

  // Get the SNI hostname requested by the client for the session
  const char* host_name =
      SSL_get_servername(
          ssl_.get(),
          TLSEXT_NAMETYPE_host_name);
  if (host_name != nullptr) {
    servername = String::NewFromUtf8(
        env()->isolate(),
        host_name,
        v8::NewStringType::kNormal).ToLocalChecked();
  }

  // Get the ALPN protocol identifier that was negotiated for the session
  const unsigned char* alpn_buf = nullptr;
  unsigned int alpnlen;

  SSL_get0_alpn_selected(ssl_.get(), &alpn_buf, &alpnlen);
  if (alpnlen == sizeof(NGTCP2_ALPN_D19) - 2 &&
      memcmp(alpn_buf, NGTCP2_ALPN_D19 + 1, sizeof(NGTCP2_ALPN_D19) - 2) == 0) {
    alpn = env()->quic_alpn_string();
  } else {
    alpn = OneByteString(env()->isolate(), alpn_buf, alpnlen);
  }

  // Get the cipher and version
  const SSL_CIPHER* c = SSL_get_current_cipher(ssl_.get());
  if (c != nullptr) {
    const char* cipher_name = SSL_CIPHER_get_name(c);
    const char* cipher_version = SSL_CIPHER_get_version(c);
    cipher = OneByteString(env()->isolate(), cipher_name);
    version = OneByteString(env()->isolate(), cipher_version);
  }

  Local<Value> argv[] = {
    servername,
    alpn,
    cipher,
    version
  };

  MakeCallback(env()->quic_on_session_handshake_function(),
               arraysize(argv),
               argv);
}

// Serialize and send a chunk of TLS Handshake data to the peer.
// This is called multiple times until the internal buffer is cleared.
int QuicSession::DoHandshakeWriteOnce() {
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

  int err = SendPacket();
  if (err != 0)
    return err;
  return nwrite;
}

// Reads a chunk of handshake data into the ngtcp2_conn for processing.
int QuicSession::DoHandshakeReadOnce(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {
  if (datalen > 0) {
    int err = ngtcp2_conn_read_handshake(
        connection_,
        path,
        data,
        datalen,
        uv_hrtime());
    if (err != 0)
      return err;
  }
  return 0;
}

// Called by ngtcp2 when a chunk of peer TLS handshake data is received.
// For every chunk, we move the TLS handshake further along until it
// is complete.
int QuicSession::ReceiveCryptoData(
    uint64_t offset,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving %d bytes of crypto data.", datalen);
  WritePeerHandshake(data, datalen);
  if (!IsHandshakeCompleted()) {
    int err = TLSHandshake();
    if (err != 0)
      return err;
    return 0;
  }
  // It's possible that not all of the data was consumed. Anything
  // that's remaining needs to be read but it not used.
  return TLSRead();
}

const ngtcp2_cid* QuicSession::scid() const {
  return &scid_;
}

// Called by ngtcp2 when a chunk of stream data has been received. If
// the stream does not yet exist, it is created, then the data is
// forwarded on.
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
  QuicStream* stream = FindStream(stream_id);
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

// Removes the given connection id from the QuicSession.
void QuicSession::RemoveConnectionID(
    const ngtcp2_cid* cid) {
  CHECK(!IsDestroyed());
  state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] =
    state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] - 1;
  CHECK_GE(state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT], 0);
  DisassociateCID(cid);
}

// Removes the given stream from the QuicSession. All streams must
// be removed before the QuicSession is destroyed.
void QuicSession::RemoveStream(
    int64_t stream_id) {
  CHECK(!IsDestroyed());
  Debug(this, "Removing stream %llu", stream_id);
  streams_.erase(stream_id);
}

// Sends 0RTT stream data.
int QuicSession::Send0RTTStreamData(
    QuicStream* stream,
    int fin,
    QuicBuffer* data) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen;

  // Called repeatedly until there is no more data to send.
  for (;;) {
    ngtcp2_vec datav{const_cast<uint8_t*>(data->rpos()), data->size()};
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
      data->seek(ndatalen);

    sendbuf_.push(n);

    int err = SendPacket();
    if (err != 0)
      return err;

    if (data->size() == 0) {
      data->Done(0, data->size());
      break;
    }
  }

  return 0;
}

// Sends buffered stream data.
int QuicSession::SendStreamData(
    QuicStream* stream,
    int should_send_fin,
    QuicBuffer* data) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen = 0;
  QuicPathStorage path;

  CHECK_NOT_NULL(connection_);
  int fin = 0;

  // Called repeatedly until there is no more data
  for (;;) {
    ngtcp2_vec vec = data->ToVec();
    if (should_send_fin && vec.len == 0)
      fin = 1;
    auto n = ngtcp2_conn_writev_stream(connection_,
                                       &path.path,
                                       sendbuf_.wpos(),
                                       max_pktlen_,
                                       &ndatalen,
                                       stream->GetID(),
                                       fin,
                                       &vec, 1,
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
      if (fin && static_cast<size_t>(ndatalen) == data->size()) {
        stream->ResetShouldSendFin();
      }

      data->seek(ndatalen);
    }

    sendbuf_.push(n);
    remote_address_.Update(&path.path.remote);

    int err = SendPacket();
    if (err != 0)
      return err;

    if (ndatalen >= 0 && data->size() == 0)
      break;
  }
  return 0;
}

// Transmits the current contents of the internal sendbuf to the peer
int QuicSession::SendPacket() {
  CHECK(!IsDestroyed());
  if (sendbuf_.size() > 0) {
    Debug(this, "Sending pending %d bytes of session data", sendbuf_.size());
    return Socket()->SendPacket(&remote_address_, &sendbuf_);
  }
  return 0;
}

// Set the transport parameters received from the remote peer
int QuicSession::SetRemoteTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  StoreRemoteTransportParams(params);
  return ngtcp2_conn_set_remote_transport_params(connection_, params);
}

// Schedule the retransmission timer
// TODO(@jasnell): this is currently not working correctly and needs to
// be refactored.
void QuicSession::ScheduleRetransmit() {
  CHECK(!IsDestroyed());
  uint64_t expiry = static_cast<uint64_t>(ngtcp2_conn_get_expiry(connection_));
  uint64_t now = uv_hrtime();
  uint64_t interval = expiry < now ? 0 : expiry - now;
  Debug(this,
        "Scheduling retransmission timer for interval %llu seconds"
        " (Expiry %llu, Now %llu)", interval / NGTCP2_SECONDS, expiry, now);
  if (retransmit_timer_ == nullptr) {
    retransmit_timer_ = new uv_timer_t();
    uv_timer_init(env()->event_loop(), retransmit_timer_);
    retransmit_timer_->data = this;
  }
  uv_timer_start(retransmit_timer_,
                 OnRetransmitTimeout,
                 interval,
                 0);
  uv_unref(reinterpret_cast<uv_handle_t*>(retransmit_timer_));
}

// Notifies the ngtcp2_conn that the TLS handshake is completed.
void QuicSession::SetHandshakeCompleted() {
  CHECK(!IsDestroyed());
  ngtcp2_conn_handshake_completed(connection_);
}

void QuicSession::SetLocalAddress(const ngtcp2_addr* addr) {
  ngtcp2_conn_set_local_addr(connection_, addr);
}

void QuicSession::SetTLSAlert(
    int err) {
  tls_alert_ = err;
}

// Creates a new stream object and passes it off to the javascript side.
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

// Called by ngtcp2 when a stream has been opened. If the stream has already
// been created, return an error.
int QuicSession::StreamOpen(
    int64_t stream_id) {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  QuicStream* stream = FindStream(stream_id);
  if (stream != nullptr)
    return NGTCP2_STREAM_STATE_ERROR;
  CreateStream(stream_id);
  StartIdleTimer(-1);
  return 0;
}

// Called by ngtcp2 when a strema has been reset.
void QuicSession::StreamReset(
    int64_t stream_id,
    uint64_t final_size,
    uint16_t app_error_code) {
  // TODO(@jasnell): Reset the stream
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

// Starts the idle timer. This timer monitors for activity on the session
// and shuts the session down if there is no activity by the timeout. If
// the timer has already been started, it is restarted.
// TODO(@jasnell): Using multiple timers for every QuicSession is going
// to be expensive. We need to refactor the approach here so that we are
// not overly reliant on multiple timer instances.
void QuicSession::StartIdleTimer(
    uint64_t idle_timeout) {
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

// Stops the idle timer and frees the timer handle.
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

// Stops the retranmission timer and frees the timer handle.
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

// Called by ngtcp2 when a stream has been closed. If the stream does
// not exist, the close is ignored.
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

// Incrementally performs the TLS handshake. This function is called
// multiple times while handshake data is being passed back and forth
// between the peers.
int QuicSession::TLSHandshake() {
  CHECK(!IsDestroyed());
  Debug(this, "TLS handshake %s", initial_ ? "starting" : "continuing");
  ClearTLSError();
  int err;

  if (initial_) {
    err = TLSHandshake_Initial();
    if (err != 0) {
      return err;
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

  Debug(this, "TLS Handshake completed.");

  SetHandshakeCompleted();
  return 0;
}

// It's possible for TLS handshake to contain extra data that is not
// consumed by ngtcp2. That's ok and the data is just extraneous. We just
// read it and throw it away, unless there's an error.
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
        // std::cerr << "TLS read error: " << err << std::endl;
        return NGTCP2_ERR_CRYPTO;
    }
  }
}

// Called by ngtcp2 when the QuicSession keys need to be updated. This may
// happen multiple times through the lifetime of the QuicSession.
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
          &crypto_ctx_);
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
          &crypto_ctx_);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          secret.data(),
          secretlen,
          &crypto_ctx_);
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
          &crypto_ctx_);
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
          &crypto_ctx_);
  if (params.keylen < 0)
    return -1;

  params.ivlen =
      DerivePacketProtectionIV(
          params.iv.data(),
          params.iv.size(),
          secret.data(),
          secretlen,
          &crypto_ctx_);
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

// Writes peer handshake data to the internal buffer
void QuicSession::WritePeerHandshake(
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Writing %d bytes of peer handshake data.", datalen);
  std::copy_n(data, datalen, std::back_inserter(peer_handshake_));
}

// Writes local handshake data from the buffer to ngtcp2_conn
void QuicSession::WriteHandshake(
    std::deque<QuicBuffer>* dest,
    size_t* idx,
    const uint8_t* data,
    size_t datalen) {
  Debug(this, "Writing %d bytes of handshake data.", datalen);
  dest->emplace_back(data, datalen);
  ++idx;
  auto& buf = dest->back();
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
      &handshake_, &handshake_idx_,
      data, datalen);
}

// Called when the QuicSession is closed and we need to let the javascript
// side know
void QuicSession::Close() {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  MakeCallback(env()->quic_on_session_close_function(), 0, nullptr);
}

// The QuicServerSession specializes the QuicSession with server specific
// behaviors. The key differentiator between client and server lies with
// the TLS Handshake and certain aspects of stream state management.
// Fortunately, ngtcp2 takes care of most of the differences for us,
// so most of the overrides here deal with TLS handshake differences.
QuicServerSession::QuicServerSession(
    QuicSocket* socket,
    Local<Object> wrap,
    const ngtcp2_cid* rcid) :
    QuicSession(socket,
                wrap,
                socket->GetServerSecureContext(),
                AsyncWrap::PROVIDER_QUICSERVERSESSION),
    pscid_{},
    rcid_(*rcid),
    draining_(false) {
}

void QuicServerSession::DisassociateCID(
    const ngtcp2_cid* cid) {
  QuicCID id(cid);
  Socket()->DisassociateCID(&id);
}

int QuicServerSession::DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  RETURN_IF_FAIL(DoHandshakeReadOnce(path, data, datalen), 0, -1);

  int err = SendPacket();
  if (err != 0)
    return err;

  for (;;) {
    ssize_t nwrite = DoHandshakeWriteOnce();
    if (nwrite <= 0)
      return nwrite;
  }
}

int QuicServerSession::HandleError(
    int error) {
  RETURN_IF_FAIL(StartClosingPeriod(error), 0, -1)
  return SendConnectionClose(error);
}

void QuicServerSession::Cleanup() {
  QuicBuffer* buf = conn_closebuf_.get();
  if (buf != nullptr && buf->WantsAck())
    buf->Done(UV_ECANCELED, buf->size());
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

  if (Negotiated_PRF(&crypto_ctx_, ssl()) != 0 ||
      Negotiated_AEAD(&crypto_ctx_, ssl()) != 0) {
     return -1;
   }

  CryptoParams params;

  RETURN_IF_FAIL(SetupKeys(secret, secretlen, &params, &crypto_ctx_), 0, -1)

  ngtcp2_conn_set_aead_overhead(
      connection_,
      aead_tag_length(&crypto_ctx_));

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

void QuicServerSession::InitTLS_Post() {
  SSL_set_accept_state(ssl());
}

int QuicServerSession::Init(
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version) {

  CHECK_NULL(connection_);

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS();

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

  uint64_t expiry =
    static_cast<uint64_t>(ngtcp2_conn_loss_detection_expiry(connection_));

  if (expiry <= now) {
    if (ngtcp2_conn_on_loss_detection_timer(connection_, uv_hrtime()) != 0) {
      Close();
      return;
    }
    //SendPendingData(true);
    return;
  }

  if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Connection ack delay...");
    //SendPendingData();
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

  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  if (IsHandshakeCompleted()) {
    err = ngtcp2_conn_read_pkt(
        connection_,
        *path,
        data, nread,
        uv_hrtime());
    if (err != 0) {
      Debug(this, "Error reading packet. Error %d\n", err);
      if (err == NGTCP2_ERR_DRAINING) {
        StartDrainingPeriod();
        return -1;  // Closing
      }
      return HandleError(err);
    }
    Debug(this, "Successfully read packet");
    return 0;

  }

  Debug(this, "TLS Handshake %s", initial_ ? "starting" : "continuing");
  err = DoHandshake(*path, data, nread);
  if (err != 0)
    return HandleError(err);

  return 0;
}

void QuicServerSession::Remove() {
  CHECK(!IsDestroyed());
  Debug(this, "Remove this QuicServerSession from the QuicSocket.");
  QuicCID rcid(rcid_);
  Socket()->DisassociateCID(&rcid);

  QuicCID pscid(pscid_);
  Socket()->DisassociateCID(&pscid);

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());

  for (auto &cid : cids) {
    QuicCID id(&cid);
    Socket()->DisassociateCID(&id);
  }

  QuicCID scid(scid_);
  Socket()->RemoveSession(&scid);
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
    if (n == 0)
      break;

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

const ngtcp2_cid* QuicServerSession::pscid() const {
  return &pscid_;
}

const ngtcp2_cid* QuicServerSession::rcid() const {
  return &rcid_;
}


// The QuicClientSession class provides a specialization of QuicSession that
// implements client-specific behaviors. Most of the client-specific stuff is
// limited to TLS and early data
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

  InitTLS();

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
  socket_->AddSession(&cid, this);
  StartIdleTimer(settings.idle_timeout);

  // Zero Round Trip
  for (auto stream : streams_) {
    err = stream.second->Send0RTTData();
    if (err != 0)
      return err;
  }

  return DoHandshakeWriteOnce();
}

int QuicClientSession::SetSocket(
    QuicSocket* socket,
    bool nat_rebinding) {
  if (socket == nullptr || socket == socket_)
    return 0;

  // Step 1: Remove this Session from the current Socket
  Remove();

  // Step 2: Add this Session to the given Socket
  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());

  QuicCID scid(&scid_);
  socket->AddSession(&scid, this);
  for (auto &cid : cids) {
    QuicCID id(&cid);
    socket->AssociateCID(&id, this);
  }

  // Step 3: Update the internal references
  socket_ = socket;
  socket->ReceiveStart();

  // Step 4: Update ngtcp2
  SocketAddress* local_address = socket->GetLocalAddress();
  if (nat_rebinding) {
    ngtcp2_addr addr = local_address->ToAddr();
    ngtcp2_conn_set_local_addr(connection_, &addr);
  } else {
    QuicPath path(local_address, &remote_address_);
    RETURN_IF_FAIL(
       ngtcp2_conn_initiate_migration(connection_, *path, uv_hrtime()),
       0, -1)
  }

  return SendPendingData();
}

void QuicClientSession::StoreRemoteTransportParams(
    ngtcp2_transport_params* params) {
  transportParams_.AllocateSufficientStorage(sizeof(ngtcp2_transport_params));
  memcpy(*transportParams_, params, sizeof(ngtcp2_transport_params));
}

int QuicClientSession::SetSession(SSL_SESSION* session) {
  int size = i2d_SSL_SESSION(session, nullptr);
  if (size > SecureContext::kMaxSessionSize)
    return 0;

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  unsigned int session_id_length;
  const unsigned char* session_id_data =
      SSL_SESSION_get_id(session, &session_id_length);

  Local<Value> argv[] = {
    Buffer::Copy(
        env(),
        reinterpret_cast<const char*>(session_id_data),
        session_id_length).ToLocalChecked(),
    v8::Undefined(env()->isolate()),
    v8::Undefined(env()->isolate())
  };

  AllocatedBuffer sessionTicket = env()->AllocateManaged(size);
  unsigned char* session_data =
    reinterpret_cast<unsigned char*>(sessionTicket.data());
  memset(session_data, 0, size);
  i2d_SSL_SESSION(session, &session_data);
  if (!sessionTicket.empty())
    argv[1] = sessionTicket.ToBuffer().ToLocalChecked();

  if (transportParams_.length() > 0) {
    argv[2] = Buffer::New(
        env(),
        *transportParams_,
        transportParams_.length(),
        [](char* data, void* hint) {}, nullptr).ToLocalChecked();
  }
  MakeCallback(env()->quic_on_session_ticket_function(), arraysize(argv), argv);

  return 1;
}

void QuicClientSession::InitTLS_Post() {
  SSL_set_connect_state(ssl());

  const uint8_t* alpn = reinterpret_cast<const uint8_t*>(NGTCP2_ALPN_D19);
  size_t alpnlen = strsize(NGTCP2_ALPN_D19);
  SSL_set_alpn_protos(ssl(), alpn, alpnlen);

  // If the hostname is an IP address and we have no additional
  // information, use localhost.
  if (SocketAddress::numeric_host(hostname_)) {
    SSL_set_tlsext_host_name(ssl(), "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl(), hostname_);
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

  if (Negotiated_PRF(&crypto_ctx_, ssl()) != 0 ||
      Negotiated_AEAD(&crypto_ctx_, ssl()) != 0) {
    return -1;
  }

  CryptoParams params;

  RETURN_IF_FAIL(SetupKeys(secret, secretlen, &params, &crypto_ctx_), 0, -1)

  ngtcp2_conn_set_aead_overhead(
      connection_,
      aead_tag_length(&crypto_ctx_));

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
        // std::cerr << "TLS read error: " << err << std::endl;
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

  err = DoHandshakeReadOnce(path, data, datalen);
  if (err != 0) {
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

  // TODO(danbev) Use error code
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
    // int err = SendPendingData(true);
    // if (err != 0)
    //   HandleError(err);
    return;
  }

  if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Connection ack delay...");
    // int err = SendPendingData();
    // if (err != 0)
    //   HandleError(err);
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

  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  if (IsHandshakeCompleted()) {
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
    return DoHandshake(*path, data, nread);
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
  Socket()->RemoveSession(&scid);

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());

  for (auto &cid : cids) {
    QuicCID id(&cid);
    Socket()->DisassociateCID(&id);
  }
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
    // ScheduleRetransmit();
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

  // ScheduleRetransmit();
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

  CryptoInitialParams params;
  const ngtcp2_cid* dcid = ngtcp2_conn_get_dcid(connection_);

  SetupTokenContext(&hs_crypto_ctx_);

  RETURN_IF_FAIL(
      DeriveInitialSecret(
          &params,
          dcid,
          reinterpret_cast<const uint8_t*>(NGTCP2_INITIAL_SALT),
          strsize(NGTCP2_INITIAL_SALT)), 0, -1)

  RETURN_IF_FAIL(SetupClientSecret(&params, &hs_crypto_ctx_), 0, -1)
  InstallKeys<ngtcp2_conn_install_initial_tx_keys>(connection_, params);

  RETURN_IF_FAIL(SetupServerSecret(&params, &hs_crypto_ctx_), 0, -1)
  InstallKeys<ngtcp2_conn_install_initial_rx_keys>(connection_, params);

  return 0;
}

int QuicClientSession::SetEarlyTransportParams(Local<Value> buffer) {
  ArrayBufferViewContents<uint8_t> sbuf(buffer.As<ArrayBufferView>());
  ngtcp2_transport_params params;
  if (sbuf.length() != sizeof(ngtcp2_transport_params))
    return ERR_INVALID_REMOTE_TRANSPORT_PARAMS;
  memcpy(&params, sbuf.data(), sizeof(ngtcp2_transport_params));
  ngtcp2_conn_set_early_remote_transport_params(connection_, &params);
  return 0;
}

int QuicClientSession::SetSession(Local<Value> buffer) {
  ArrayBufferViewContents<unsigned char> sbuf(buffer.As<ArrayBufferView>());
  const unsigned char* p = sbuf.data();
  crypto::SSLSessionPointer s(d2i_SSL_SESSION(nullptr, &p, sbuf.length()));
  if (s == nullptr)
    return ERR_INVALID_TLS_SESSION_TICKET;
  if (SSL_set_session(ssl_.get(), s.get()) != 1)
    return ERR_INVALID_TLS_SESSION_TICKET;
  return 0;
}

// JavaScript API
namespace {
void QuicSessionSetSocket(const FunctionCallbackInfo<Value>& args) {
  QuicClientSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(args[0]->IsObject());
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args[0].As<Object>());
  args.GetReturnValue().Set(session->SetSocket(socket));
}

void QuicSessionDestroy(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Destroy();
}

// TODO(@jasnell): Consolidate shared code with node_crypto
void QuicSessionGetEphemeralKeyInfo(const FunctionCallbackInfo<Value>& args) {
  QuicClientSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  Local<Context> context = env->context();

  CHECK(session->ssl());

  Local<Object> info = Object::New(env->isolate());

  EVP_PKEY* raw_key;
  if (SSL_get_server_tmp_key(session->ssl(), &raw_key)) {
    crypto::EVPKeyPointer key(raw_key);
    int kid = EVP_PKEY_id(key.get());
    switch (kid) {
      case EVP_PKEY_DH:
        info->Set(context, env->type_string(),
                  FIXED_ONE_BYTE_STRING(env->isolate(), "DH")).FromJust();
        info->Set(context, env->size_string(),
                  Integer::New(env->isolate(), EVP_PKEY_bits(key.get())))
            .FromJust();
        break;
      case EVP_PKEY_EC:
      case EVP_PKEY_X25519:
      case EVP_PKEY_X448:
        {
          const char* curve_name;
          if (kid == EVP_PKEY_EC) {
            EC_KEY* ec = EVP_PKEY_get1_EC_KEY(key.get());
            int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            curve_name = OBJ_nid2sn(nid);
            EC_KEY_free(ec);
          } else {
            curve_name = OBJ_nid2sn(kid);
          }
          info->Set(context, env->type_string(),
                    FIXED_ONE_BYTE_STRING(env->isolate(), "ECDH")).FromJust();
          info->Set(context, env->name_string(),
                    OneByteString(args.GetIsolate(),
                                  curve_name)).FromJust();
          info->Set(context, env->size_string(),
                    Integer::New(env->isolate(),
                                 EVP_PKEY_bits(key.get()))).FromJust();
        }
        break;
      default:
        break;
    }
  }

  return args.GetReturnValue().Set(info);
}

// TODO(@jasnell): Consolidate with shared code in node_crypto
void QuicSessionGetPeerCertificate(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();

  crypto::ClearErrorOnReturn clear_error_on_return;

  Local<Object> result;
  // Used to build the issuer certificate chain.
  Local<Object> issuer_chain;

  // NOTE: This is because of the odd OpenSSL behavior. On client `cert_chain`
  // contains the `peer_certificate`, but on server it doesn't.
  crypto::X509Pointer cert(
      session->IsServer() ? SSL_get_peer_certificate(session->ssl()) : nullptr);
  STACK_OF(X509)* ssl_certs = SSL_get_peer_cert_chain(session->ssl());
  if (!cert && (ssl_certs == nullptr || sk_X509_num(ssl_certs) == 0))
    goto done;

  // Short result requested.
  if (args.Length() < 1 || !args[0]->IsTrue()) {
    result = crypto::X509ToObject(env, cert ? cert.get() : sk_X509_value(ssl_certs, 0));
    goto done;
  }

  if (auto peer_certs = crypto::CloneSSLCerts(std::move(cert), ssl_certs)) {
    // First and main certificate.
    crypto::X509Pointer cert(sk_X509_value(peer_certs.get(), 0));
    CHECK(cert);
    result = crypto::X509ToObject(env, cert.release());

    issuer_chain =
        crypto::AddIssuerChainToObject(
            &cert, result,
            std::move(peer_certs), env);
    issuer_chain = crypto::GetLastIssuedCert(&cert,
                                             session->ssl(),
                                             issuer_chain, env);
    // Last certificate should be self-signed.
    if (X509_check_issued(cert.get(), cert.get()) == X509_V_OK)
      issuer_chain->Set(env->context(),
                        env->issuercert_string(),
                        issuer_chain).FromJust();
  }

 done:
  args.GetReturnValue().Set(result);
}

// TODO(@jasnell): Reconcile with shared code in node_crypto
void QuicSessionGetCertificate(
    const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();

  crypto::ClearErrorOnReturn clear_error_on_return;

  Local<Object> result;

  X509* cert = SSL_get_certificate(session->ssl());

  if (cert != nullptr)
    result = crypto::X509ToObject(env, cert);

  args.GetReturnValue().Set(result);
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

  node::Utf8Value servername(args.GetIsolate(), args[6]);

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
          *servername,
          port);
  CHECK_NOT_NULL(session);

  // Remote Transport Params
  if (args[7]->IsArrayBufferView()) {
    err = session->SetEarlyTransportParams(args[7]);
    if (err != 0)
      return args.GetReturnValue().Set(err);
  }

  // Session Ticket
  if (args[8]->IsArrayBufferView()) {
    err = session->SetSession(args[8]);
    if (err != 0)
      return args.GetReturnValue().Set(err);
  }

  // socket->SendPendingData();

  args.GetReturnValue().Set(session->object());
}

void AddMethods(Environment* env, Local<FunctionTemplate> session) {
  env->SetProtoMethod(session,
                      "destroy",
                      QuicSessionDestroy);
  env->SetProtoMethod(session,
                      "getCertificate",
                      QuicSessionGetCertificate);
  env->SetProtoMethod(session,
                      "getPeerCertificate",
                      QuicSessionGetPeerCertificate);
}
}  // namespace

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
  AddMethods(env, session);
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
  AddMethods(env, session);
  env->SetProtoMethod(session,
                      "getEphemeralKeyInfo",
                      QuicSessionGetEphemeralKeyInfo);
  env->SetProtoMethod(session,
                      "setSocket",
                      QuicSessionSetSocket);
  env->set_quicclientsession_constructor_template(sessiont);

  env->SetMethod(target, "createClientSession", NewQuicClientSession);
}

}  // namespace quic
}  // namespace node
