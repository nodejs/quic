#ifndef SRC_NODE_QUIC_CRYPTO_H_
#define SRC_NODE_QUIC_CRYPTO_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_crypto.h"
#include "node_quic_session.h"
#include "node_quic_util.h"

#include <ngtcp2/ngtcp2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace node {

using crypto::EntropySource;

namespace quic {

inline int BIO_Write(BIO* b, const char* buf, int len) {
  return -1;
}

inline int BIO_Read(BIO* b, char* buf, int len) {
  BIO_clear_retry_flags(b);
  QuicSession* session = static_cast<QuicSession*>(BIO_get_data(b));
  len = session->ReadPeerHandshake(reinterpret_cast<uint8_t*>(buf), len);
  if (len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }
  return len;
}

inline int BIO_Puts(BIO* b, const char* str) {
  return BIO_Write(b, str, strlen(str));
}

inline int BIO_Gets(BIO* b, char* buf, int len) {
  return -1;
}

inline long BIO_Ctrl(  // NOLINT(runtime/int)
    BIO* b,
    int cmd,
    long num,  // NOLINT(runtime/int)
    void* ptr) {
  return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

inline int BIO_Create(BIO* b) {
  BIO_set_init(b, 1);
  return 1;
}

inline int BIO_Destroy(BIO* b) {
  return b == nullptr ? 0 : 1;
}

inline BIO_METHOD* CreateBIOMethod() {
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

inline void prf_sha256(CryptoContext* ctx) { ctx->prf = EVP_sha256(); }

inline void aead_aes_128_gcm(CryptoContext* ctx) {
  ctx->aead = EVP_aes_128_gcm();
  ctx->hp = EVP_aes_128_ctr();
}

inline size_t aead_key_length(const CryptoContext* ctx) {
  return EVP_CIPHER_key_length(ctx->aead);
}

inline size_t aead_nonce_length(const CryptoContext* ctx) {
  return EVP_CIPHER_iv_length(ctx->aead);
}

inline size_t aead_tag_length(const CryptoContext* ctx) {
  if (ctx->aead == EVP_aes_128_gcm() || ctx->aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if (ctx->aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  UNREACHABLE();
}

inline int Negotiated_PRF(CryptoContext* ctx, SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case 0x03001301u:  // TLS_AES_128_GCM_SHA256
    case 0x03001303u:  // TLS_CHACHA20_POLY1305_SHA256
      ctx->prf = EVP_sha256();
      return 0;
    case 0x03001302u:  // TLS_AES_256_GCM_SHA384
      ctx->prf = EVP_sha384();
      return 0;
    default:
      return -1;
  }
}

inline int Negotiated_AEAD(CryptoContext* ctx, SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case 0x03001301u:  // TLS_AES_128_GCM_SHA256
      ctx->aead = EVP_aes_128_gcm();
      ctx->hp = EVP_aes_128_ctr();
      return 0;
    case 0x03001302u:  // TLS_AES_256_GCM_SHA384
      ctx->aead = EVP_aes_256_gcm();
      ctx->hp = EVP_aes_256_ctr();
      return 0;
    case 0x03001303u:  // TLS_CHACHA20_POLY1305_SHA256
      ctx->aead = EVP_chacha20_poly1305();
      ctx->hp = EVP_chacha20();
      return 0;
    default:
      return -1;
  }
}

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
          nullptr));

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_SET_IVLEN,
          noncelen,
          nullptr));

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptInit_ex(
          actx.get(),
          nullptr,
          nullptr,
          key,
          nonce));

  size_t outlen = 0;
  int len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptUpdate(
          actx.get(),
          nullptr,
          &len,
          ad,
          adlen));

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptUpdate(
          actx.get(),
          dest,
          &len,
          plaintext,
          plaintextlen));

  outlen = len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptFinal_ex(
          actx.get(),
          dest + outlen,
          &len));

  outlen += len;

  CHECK_LE(outlen + taglen, destlen);

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_GET_TAG,
          taglen,
          dest + outlen));

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
          nullptr));

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_SET_IVLEN,
          noncelen,
          nullptr));

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptInit_ex(
          actx.get(),
          nullptr,
          nullptr,
          key,
          nonce));

  size_t outlen;
  int len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptUpdate(
          actx.get(),
          nullptr,
          &len,
          ad,
          adlen));

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptUpdate(
          actx.get(),
          dest,
          &len,
          ciphertext,
          ciphertextlen));

  outlen = len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_CIPHER_CTX_ctrl(
          actx.get(),
          EVP_CTRL_AEAD_SET_TAG,
          taglen,
          const_cast<uint8_t *>(tag)));

  RETURN_IF_FAIL_OPENSSL(
      EVP_DecryptFinal_ex(
          actx.get(),
          dest + outlen,
          &len));

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
          sample));

  size_t outlen = 0;
  int len;
  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptUpdate(
          actx.get(),
          dest,
          &len,
          PLAINTEXT,
          strsize(PLAINTEXT)));
  CHECK_EQ(len, 5);

  outlen = len;

  RETURN_IF_FAIL_OPENSSL(
      EVP_EncryptFinal_ex(
          actx.get(),
          dest + outlen,
          &len));

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

  RETURN_IF_FAIL_OPENSSL(EVP_PKEY_derive_init(pctx.get()));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_hkdf_mode(
          pctx.get(),
          EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set_hkdf_md(
          pctx.get(),
          ctx->prf));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_salt(
          pctx.get(), "", 0));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_key(
          pctx.get(),
          secret,
          secretlen));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_add1_hkdf_info(
          pctx.get(),
          info,
          infolen));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_derive(
          pctx.get(),
          dest,
          &destlen));

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
          pctx.get()));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_hkdf_mode(
          pctx.get(),
          EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set_hkdf_md(
          pctx.get(),
          ctx->prf));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_salt(
          pctx.get(),
          salt,
          saltlen));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_CTX_set1_hkdf_key(
          pctx.get(),
          secret,
          secretlen));

  RETURN_IF_FAIL_OPENSSL(
      EVP_PKEY_derive(
          pctx.get(),
          dest,
          &destlen));

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
          ctx), 0, -1);

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
          ctx), 0, -1);

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
          ctx), 0, -1);

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
          context), 0, -1);

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
          ctx), 0, -1);

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

  RETURN_IF_FAIL_OPENSSL(EVP_DigestInit_ex(ctx.get(), meth, nullptr));
  RETURN_IF_FAIL_OPENSSL(EVP_DigestUpdate(ctx.get(), data, len));
  unsigned int mdlen = EVP_MD_size(meth);
  RETURN_IF_FAIL_OPENSSL(EVP_DigestFinal_ex(ctx.get(), res, &mdlen));
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

// MessageCB provides a hook into the TLS handshake dataflow. Currently, it
// is used to capture TLS alert codes (errors) and to collect the TLS handshake
// data that is to be sent.
inline void MessageCB(
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

  switch (content_type) {
    case SSL3_RT_HANDSHAKE: {
      session->WriteHandshake(reinterpret_cast<const uint8_t*>(buf), len);
      break;
    }
    case SSL3_RT_ALERT: {
      const uint8_t* msg = reinterpret_cast<const uint8_t*>(buf);
      CHECK_EQ(len, 2);
      if (msg[0] == 2)
        session->SetTLSAlert(msg[1]);
      break;
    }
    default:
      // Fall-through
      break;
  }
}

inline std::string ToHex(const uint8_t* s, size_t len) {
  static constexpr char LOWER_XDIGITS[] = "0123456789abcdef";
  std::string res;
  res.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    auto c = s[i];
    res[i * 2] = LOWER_XDIGITS[c >> 4];
    res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
  }
  return res;
}

inline void LogSecret(
    SSL* ssl,
    int name,
    const unsigned char* secret,
    size_t secretlen) {
  if (auto keylog_cb = SSL_CTX_get_keylog_callback(SSL_get_SSL_CTX(ssl))) {
    unsigned char crandom[32];
    if (SSL_get_client_random(ssl, crandom, 32) != 32)
      return;
    std::string line;
    switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      line = "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      line = "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      line = "QUIC_CLIENT_TRAFFIC_SECRET_0";
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      line = "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      line = "QUIC_SERVER_TRAFFIC_SECRET_0";
      break;
    default:
      return;
    }
    line += " " + ToHex(crandom, 32);
    line += " " + ToHex(secret, secretlen);
    keylog_cb(ssl, line.c_str());
  }
}

inline int CertCB(SSL* ssl, void* arg) {
  QuicSession* session = static_cast<QuicSession*>(arg);
  return session->OnCert();
}

// KeyCB provides a hook into the keying process of the TLS handshake,
// triggering registration of the keys associated with the TLS session.
inline int KeyCB(
    SSL* ssl,
    int name,
    const unsigned char* secret,
    size_t secretlen,
    void* arg) {
  QuicSession* session = static_cast<QuicSession*>(arg);

  // Output the secret to the keylog
  LogSecret(ssl, name, secret, secretlen);

  return session->OnKey(name, secret, secretlen) != 0 ? 0 : 1;
}

inline int ClearTLS(SSL* ssl, bool continue_on_error = false) {
  std::array<uint8_t, 4096> buf;
  size_t nread;
  for (;;) {
    int err = SSL_read_ex(ssl, buf.data(), buf.size(), &nread);
    if (err == 1) {
      if (continue_on_error)
        continue;
      return NGTCP2_ERR_PROTO;
    }
    int code = SSL_get_error(ssl, 0);
    switch (code) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
      case SSL_ERROR_WANT_CLIENT_HELLO_CB:
      case SSL_ERROR_WANT_X509_LOOKUP:
        return 0;
      case SSL_ERROR_SSL:
      case SSL_ERROR_ZERO_RETURN:
        return NGTCP2_ERR_CRYPTO;
      default:
        return NGTCP2_ERR_CRYPTO;
    }
  }
  return 0;
}

inline int DoTLSHandshake(SSL* ssl) {
  int err = SSL_do_handshake(ssl);
  if (err <= 0) {
    err = SSL_get_error(ssl, err);
    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        // For the next two, the handshake has been suspended but
        // the data was otherwise successfully read, so return 0
        // here but the handshake won't continue until we trigger
        // things on our side.
      case SSL_ERROR_WANT_CLIENT_HELLO_CB:
      case SSL_ERROR_WANT_X509_LOOKUP:
        return 0;
      case SSL_ERROR_SSL:
        return NGTCP2_ERR_CRYPTO;
      default:
        return NGTCP2_ERR_CRYPTO;
    }
  }
  return err;
}

inline int DoTLSReadEarlyData(SSL* ssl) {
  std::array<uint8_t, 8> buf;
  size_t nread;
  int err = SSL_read_early_data(ssl, buf.data(), buf.size(), &nread);
  switch (err) {
    case SSL_READ_EARLY_DATA_ERROR: {
      int code = SSL_get_error(ssl, err);
      switch (code) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        // For the next two, the handshake has been suspended but
        // the data was otherwise successfully read, so return 0
        // here but the handshake won't continue until we trigger
        // things on our side.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        case SSL_ERROR_WANT_X509_LOOKUP:
          return 0;
        case SSL_ERROR_SSL:
          return NGTCP2_ERR_CRYPTO;
        default:
          return NGTCP2_ERR_CRYPTO;
      }
      break;
    }
    case SSL_READ_EARLY_DATA_SUCCESS:
      if (nread > 0)
        return NGTCP2_ERR_PROTO;
      break;
    case SSL_READ_EARLY_DATA_FINISH:
      break;
  }
  return 0;
}

inline crypto::OpenSSLBuffer GetClientHelloRandom(SSL* ssl) {
  const unsigned char* buf;
  SSL_client_hello_get0_random(ssl, &buf);
  return crypto::OpenSSLBuffer(
      const_cast<char*>(reinterpret_cast<const char*>(buf)));
}

inline crypto::OpenSSLBuffer GetClientHelloSessionID(SSL* ssl) {
  const unsigned char* buf;
  SSL_client_hello_get0_session_id(ssl, &buf);
  return crypto::OpenSSLBuffer(
      const_cast<char*>(reinterpret_cast<const char*>(buf)));
}

inline v8::Local<v8::Array> GetClientHelloCiphers(
    Environment* env,
    SSL* ssl) {
  v8::Local<v8::Array> ciphers_array;
  const unsigned char* buf;
  size_t len = SSL_client_hello_get0_ciphers(ssl, &buf);
  if (len == 0)
    return ciphers_array;

  ciphers_array = v8::Array::New(env->isolate(), len / 2);
  size_t pos = 0;
  for (size_t n = 0; n < len; n += 2) {
    auto cipher = SSL_CIPHER_find(ssl, buf);
    buf += 2;
    const char* cipher_name = SSL_CIPHER_get_name(cipher);
    const char* cipher_version = SSL_CIPHER_get_version(cipher);
    v8::Local<v8::Object> obj = v8::Object::New(env->isolate());
    USE(obj->Set(
        env->context(),
        env->name_string(),
        OneByteString(env->isolate(), cipher_name)));
    USE(obj->Set(
        env->context(),
        env->version_string(),
        OneByteString(env->isolate(), cipher_version)));
    USE(ciphers_array->Set(env->context(), pos++, obj));
  }

  return ciphers_array;
}

inline crypto::OpenSSLBuffer GetClientHelloCompressionMethods(SSL* ssl) {
  const unsigned char* buf;
  SSL_client_hello_get0_compression_methods(ssl, &buf);
  return crypto::OpenSSLBuffer(
      const_cast<char*>(reinterpret_cast<const char*>(buf)));
}

inline const char* GetClientHelloServerName(SSL* ssl) {
    const unsigned char* buf;
    size_t len;
    size_t rem;

    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &buf, &rem) ||
        rem <= 2)
        return nullptr;

    len = (*(buf++) << 8);
    len += *(buf++);
    if (len + 2 != rem)
      return nullptr;
    rem = len;

    if (rem == 0 || *buf++ != TLSEXT_NAMETYPE_host_name)
      return nullptr;
    rem--;
    if (rem <= 2)
      return nullptr;
    len = (*(buf++) << 8);
    len += *(buf++);
    if (len + 2 > rem)
      return nullptr;
    rem = len;
    return reinterpret_cast<const char*>(buf);
}

inline const char* GetClientHelloALPN(SSL* ssl) {
    const unsigned char* buf;
    size_t len;
    size_t rem;

    if (!SSL_client_hello_get0_ext(
            ssl,
            TLSEXT_TYPE_application_layer_protocol_negotiation,
            &buf, &rem) || rem < 2) {
      return nullptr;
    }

    len = (buf[0] << 8) | buf[1];
    if (len + 2 != rem)
      return nullptr;
    buf += 3;
    return reinterpret_cast<const char*>(buf);
}

inline int UseSNIContext(SSL* ssl, crypto::SecureContext* context) {
  SSL_CTX* ctx = context->ctx_.get();
  X509* x509 = SSL_CTX_get0_certificate(ctx);
  EVP_PKEY* pkey = SSL_CTX_get0_privatekey(ctx);
  STACK_OF(X509)* chain;

  int err = SSL_CTX_get0_chain_certs(ctx, &chain);
  if (err)
    err = SSL_use_certificate(ssl, x509);
  if (err)
    err = SSL_use_PrivateKey(ssl, pkey);
  if (err && chain != nullptr)
    err = SSL_set1_chain(ssl, chain);
  return err;
}

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_CRYPTO_H_
