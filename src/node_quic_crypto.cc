#include "node_quic_crypto.h"
#include "env-inl.h"
#include "node_crypto.h"
#include "node_quic_session-inl.h"
#include "node_quic_util.h"
#include "node_url.h"
#include "string_bytes.h"
#include "v8.h"

#include <ngtcp2/ngtcp2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iterator>
#include <numeric>
#include <unordered_map>
#include <string>
#include <sstream>

namespace node {

using v8::Array;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace quic {

namespace {
int BIO_Write(BIO* b, const char* buf, int len) {
  return -1;
}

int BIO_Read(BIO* b, char* buf, int len) {
  BIO_clear_retry_flags(b);
  QuicSession* session = static_cast<QuicSession*>(BIO_get_data(b));
  len = session->ReadPeerHandshake(reinterpret_cast<uint8_t*>(buf), len);
  if (len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }
  return len;
}

int BIO_Puts(BIO* b, const char* str) {
  return BIO_Write(b, str, strlen(str));
}

int BIO_Gets(BIO* b, char* buf, int len) {
  return -1;
}

long BIO_Ctrl(  // NOLINT(runtime/int)
    BIO* b,
    int cmd,
    long num,  // NOLINT(runtime/int)
    void* ptr) {
  return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

int BIO_Create(BIO* b) {
  BIO_set_init(b, 1);
  return 1;
}

int BIO_Destroy(BIO* b) {
  return b == nullptr ? 0 : 1;
}
}  // namespace

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

// TODO(@jasnell): Replace with ngtcp2_crypto_aead_keylen once
// we move to ngtcp2_crypto.h
size_t aead_key_length(const CryptoContext* ctx) {
  return static_cast<size_t>(EVP_CIPHER_key_length(ctx->aead));
}

// TODO(@jasnell): Replace with ngtcp2_crypto_aead_noncelen once
// we move to ngtcp2_crypto.h
size_t aead_nonce_length(const CryptoContext* ctx) {
  return static_cast<size_t>(EVP_CIPHER_iv_length(ctx->aead));
}

// TODO(@jasnell): Replace with ngtcp2_crypto_packet_protection_ivlen
// once we move to ngtcp2_crypto.h
size_t packet_protection_ivlen(const CryptoContext* ctx) {
  size_t noncelen = aead_nonce_length(ctx);
  return std::max(static_cast<size_t>(8), noncelen);
}

// TODO(@jasnell): Replace with ngtcp2_crypto_aead_taglen once
// we move to ngtcp2_crypto.h
size_t aead_tag_length(const CryptoContext* ctx) {
  if (ctx->aead == EVP_aes_128_gcm() ||
      ctx->aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if (ctx->aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  if (ctx->aead == EVP_aes_128_ccm()) {
    return EVP_CCM_TLS_TAG_LEN;
  }
  return 0;
}

// TODO(@jasnell): Replace with ngtcp2_crypto_ctx_initial once
// we move to ngtcp2_crypto.h
void SetupInitialCryptoContext(CryptoContext* context) {
  context->aead = EVP_aes_128_gcm();
  context->hp = EVP_aes_128_ctr();
  context->md = EVP_sha256();
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto.h
const EVP_CIPHER* crypto_ssl_get_aead(SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case TLS1_3_CK_AES_128_GCM_SHA256:
      return EVP_aes_128_gcm();
    case TLS1_3_CK_AES_256_GCM_SHA384:
      return EVP_aes_256_gcm();
    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
      return EVP_chacha20_poly1305();
    case TLS1_3_CK_AES_128_CCM_SHA256:
      return EVP_aes_128_ccm();
    default:
      return nullptr;
  }
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto.h
const EVP_CIPHER* crypto_ssl_get_hp(SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case TLS1_3_CK_AES_128_GCM_SHA256:
    case TLS1_3_CK_AES_128_CCM_SHA256:
      return EVP_aes_128_ctr();
    case TLS1_3_CK_AES_256_GCM_SHA384:
      return EVP_aes_256_ctr();
    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
      return EVP_chacha20();
    default:
      return nullptr;
  }
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto.h
const EVP_MD* crypto_ssl_get_md(SSL* ssl) {
  switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case TLS1_3_CK_AES_128_GCM_SHA256:
    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
    case TLS1_3_CK_AES_128_CCM_SHA256:
      return EVP_sha256();
    case TLS1_3_CK_AES_256_GCM_SHA384:
      return EVP_sha384();
    default:
      return nullptr;
  }
}

// TODO(@jasnell): Replace with ngtcp2_crypto_ctx_tls once
// we move to ngtcp2_crypto
void SetupCryptoContext(CryptoContext* ctx, SSL* ssl) {
  ctx->aead = crypto_ssl_get_aead(ssl);
  ctx->md = crypto_ssl_get_md(ssl);
  ctx->hp = crypto_ssl_get_hp(ssl);
}

// TODO(@jasnell): Replace with ngtcp2_crypto_hkdf_extract once
// we move to ngtcp2_crypto
bool HKDF_Extract(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext* ctx,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* salt,
    size_t saltlen) {
  PKeyCtxPointer pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
  return
      pctx &&
      EVP_PKEY_derive_init(pctx.get()) == 1 &&
      EVP_PKEY_CTX_hkdf_mode(
          pctx.get(),
          EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) == 1 &&
      EVP_PKEY_CTX_set_hkdf_md(pctx.get(), ctx->md) == 1 &&
      EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt, saltlen) == 1 &&
      EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), secret, secretlen) == 1 &&
      EVP_PKEY_derive(pctx.get(), dest, &destlen) == 1;
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
bool HKDF_Expand(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext* ctx,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* info,
    size_t infolen) {
  PKeyCtxPointer pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));

  return
      pctx &&
      EVP_PKEY_derive_init(pctx.get()) == 1 &&
      EVP_PKEY_CTX_hkdf_mode(
          pctx.get(),
          EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) == 1 &&
      EVP_PKEY_CTX_set_hkdf_md(pctx.get(), ctx->md) == 1 &&
      EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), "", 0) == 1 &&
      EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), secret, secretlen) == 1 &&
      EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info, infolen) == 1 &&
      EVP_PKEY_derive(pctx.get(), dest, &destlen) == 1;
}

// TODO(@jasnell): Replace with ngtcp2_crypto_hkdf_expand_label
// once we move to ngtcp2_crypto
bool HKDF_Expand_Label(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext* ctx,
    const uint8_t* secret,
    size_t secretlen,
    const uint8_t* label,
    size_t labellen) {
  static const uint8_t LABEL[] = "tls13 ";
  uint8_t info[256];
  uint8_t* p = info;

  *p++ = static_cast<uint8_t>(destlen / 256);
  *p++ = static_cast<uint8_t>(destlen % 256);
  *p++ = static_cast<uint8_t>(sizeof(LABEL) - 1 + labellen);
  memcpy(p, LABEL, sizeof(LABEL) - 1);
  p += sizeof(LABEL) - 1;
  memcpy(p, label, labellen);
  p += labellen;
  *p++ = 0;

  return HKDF_Expand(
      dest,
      destlen,
      ctx,
      secret,
      secretlen,
      info,
      static_cast<size_t>(p - info));
}

// TODO(@jasnell): Replace with ngtcp2_crypto_encrypt once
// we move to ngtcp2_crypto
ssize_t Encrypt(
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

  CipherCtxPointer actx(EVP_CIPHER_CTX_new());
  CHECK(actx);

  size_t outlen = 0;
  int len;

  if (EVP_EncryptInit_ex(actx.get(), ctx->aead, nullptr, nullptr, nullptr) != 1)
    return NGTCP2_ERR_CRYPTO;

  if (EVP_CIPHER_CTX_ctrl(actx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                          noncelen, nullptr) != 1) {
    return NGTCP2_ERR_CRYPTO;
  }

  if (EVP_EncryptInit_ex(actx.get(), nullptr, nullptr, key, nonce) != 1)
    return NGTCP2_ERR_CRYPTO;

  if (EVP_EncryptUpdate(actx.get(), nullptr, &len, ad, adlen) != 1)
    return NGTCP2_ERR_CRYPTO;

  if (EVP_EncryptUpdate(actx.get(), dest, &len, plaintext, plaintextlen) != 1)
    return NGTCP2_ERR_CRYPTO;

  outlen = len;

  if (EVP_EncryptFinal_ex(actx.get(), dest + outlen, &len) != 1)
    return NGTCP2_ERR_CRYPTO;

  outlen += len;

  CHECK_LE(outlen + taglen, destlen);

  if (EVP_CIPHER_CTX_ctrl(actx.get(), EVP_CTRL_AEAD_GET_TAG, taglen,
                          dest + outlen) != 1) {
    return NGTCP2_ERR_CRYPTO;
  }

  outlen += taglen;

  return outlen;
}

// TODO(@jasnell): Replace with ngtcp2_crypto_decrypt once
// we move to ngtcp2_crypto
ssize_t Decrypt(
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

  CipherCtxPointer actx(EVP_CIPHER_CTX_new());
  CHECK(actx);

  size_t outlen;
  int len;

  if (EVP_DecryptInit_ex(actx.get(), ctx->aead, nullptr, nullptr, nullptr) != 1)
    return NGTCP2_ERR_TLS_DECRYPT;

  if (EVP_CIPHER_CTX_ctrl(actx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                          noncelen, nullptr) != 1) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  if (EVP_DecryptInit_ex(actx.get(), nullptr, nullptr, key, nonce) != 1)
    return NGTCP2_ERR_TLS_DECRYPT;

  if (EVP_DecryptUpdate(actx.get(), nullptr, &len, ad, adlen) != 1)
    return NGTCP2_ERR_TLS_DECRYPT;

  if (EVP_DecryptUpdate(actx.get(), dest, &len, ciphertext, ciphertextlen) != 1)
    return NGTCP2_ERR_TLS_DECRYPT;

  outlen = len;

  if (EVP_CIPHER_CTX_ctrl(actx.get(), EVP_CTRL_AEAD_SET_TAG,
                          taglen, const_cast<uint8_t *>(tag)) != 1) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  if (EVP_DecryptFinal_ex(actx.get(), dest + outlen, &len) != 1)
    return NGTCP2_ERR_TLS_DECRYPT;

  outlen += len;

  return outlen;
}

// TODO(@jasnell): Replace with ngtcp2_crypto_hp_mask once
// we move to ngtcp2_crypto
ssize_t HP_Mask(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext* ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  static constexpr uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

  DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> actx;
  actx.reset(EVP_CIPHER_CTX_new());
  CHECK(actx);

  size_t outlen = 0;
  int len;

  if (EVP_EncryptInit_ex(actx.get(), ctx->hp, nullptr, key, sample) != 1)
    return NGTCP2_ERR_CRYPTO;

  if (EVP_EncryptUpdate(actx.get(), dest, &len, PLAINTEXT,
                        strsize(PLAINTEXT)) != 1) {
    return NGTCP2_ERR_CRYPTO;
  }

  CHECK_EQ(len, 5);

  outlen = len;

  if (EVP_EncryptFinal_ex(actx.get(), dest + outlen, &len) != 1)
    return NGTCP2_ERR_CRYPTO;

  CHECK_EQ(len, 0);

  return outlen;
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
bool DeriveInitialSecrets(
    uint8_t* rx_secret,
    uint8_t* tx_secret,
    uint8_t* initial_secret,
    const ngtcp2_cid* dcid,
    ngtcp2_crypto_side side) {

  static const uint8_t CLABEL[] = "client in";
  static const uint8_t SLABEL[] = "server in";
  uint8_t initial_secret_buf[NGTCP2_CRYPTO_INITIAL_SECRETLEN];
  uint8_t* client_secret;
  uint8_t* server_secret;
  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);

  if (!initial_secret)
    initial_secret = initial_secret_buf;


  if (!HKDF_Extract(
          initial_secret,
          NGTCP2_CRYPTO_INITIAL_SECRETLEN,
          &ctx,
          dcid->data,
          dcid->datalen,
          reinterpret_cast<const uint8_t *>(NGTCP2_INITIAL_SALT),
          sizeof(NGTCP2_INITIAL_SALT) - 1)) {
    return false;
  }

  switch (side) {
    case NGTCP2_CRYPTO_SIDE_SERVER:
      client_secret = rx_secret;
      server_secret = tx_secret;
      break;
    case NGTCP2_CRYPTO_SIDE_CLIENT:
      client_secret = tx_secret;
      server_secret = rx_secret;
      break;
    default:
      UNREACHABLE();
  }

  return
      HKDF_Expand_Label(
          client_secret,
          NGTCP2_CRYPTO_INITIAL_SECRETLEN,
          &ctx,
          initial_secret,
          NGTCP2_CRYPTO_INITIAL_SECRETLEN,
          CLABEL,
          sizeof(CLABEL) - 1) &&
      HKDF_Expand_Label(
          server_secret,
          NGTCP2_CRYPTO_INITIAL_SECRETLEN,
          &ctx,
          initial_secret,
          NGTCP2_CRYPTO_INITIAL_SECRETLEN,
          SLABEL,
          sizeof(SLABEL) - 1);
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
bool DerivePacketProtectionKey(
    uint8_t* key,
    uint8_t* iv,
    uint8_t* hp_key,
    const CryptoContext* ctx,
    const uint8_t* secret,
    size_t secretlen) {
  static const uint8_t KEY_LABEL[] = "quic key";
  static const uint8_t IV_LABEL[] = "quic iv";
  static const uint8_t HP_KEY_LABEL[] = "quic hp";
  size_t keylen = aead_key_length(ctx);
  size_t ivlen = packet_protection_ivlen(ctx);

  return
      HKDF_Expand_Label(
          key,
          keylen,
          ctx,
          secret,
          secretlen,
          KEY_LABEL,
          sizeof(KEY_LABEL) - 1) &&
      HKDF_Expand_Label(
          iv,
          ivlen,
          ctx,
          secret,
          secretlen,
          IV_LABEL,
          sizeof(IV_LABEL) - 1) &&
      (hp_key == nullptr ||
       HKDF_Expand_Label(
          hp_key,
          keylen,
          ctx,
          secret,
          secretlen,
          HP_KEY_LABEL,
          sizeof(HP_KEY_LABEL) - 1));
}

// TODO(@jasnell): Replace with ngtcp2_crypto_derive_and_install_initial_key
// once we move to ngtcp2_crypto
bool DeriveAndInstallInitialKey(
  ngtcp2_conn* conn,
  const ngtcp2_cid* dcid,
  ngtcp2_crypto_side side) {
  InitialSecret rx_secret;
  InitialSecret tx_secret;
  InitialKey rx_key;
  InitialKey tx_key;
  InitialIV rx_iv;
  InitialIV tx_iv;
  InitialKey rx_hp;
  InitialKey tx_hp;

  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);

  return
      DeriveInitialSecrets(
          rx_secret.data(),
          tx_secret.data(),
          nullptr,
          dcid,
          side) &&
      DerivePacketProtectionKey(
          rx_key.data(),
          rx_iv.data(),
          rx_hp.data(),
          &ctx,
          rx_secret.data(),
          NGTCP2_CRYPTO_INITIAL_SECRETLEN) &&
      DerivePacketProtectionKey(
          tx_key.data(),
          tx_iv.data(),
          tx_hp.data(),
          &ctx,
          tx_secret.data(),
          NGTCP2_CRYPTO_INITIAL_SECRETLEN) &&
      ngtcp2_conn_install_initial_tx_keys(
          conn,
          tx_key.data(),
          NGTCP2_CRYPTO_INITIAL_KEYLEN,
          tx_iv.data(),
          NGTCP2_CRYPTO_INITIAL_IVLEN,
          tx_hp.data(),
          NGTCP2_CRYPTO_INITIAL_KEYLEN) == 0 &&
      ngtcp2_conn_install_initial_rx_keys(
          conn,
          rx_key.data(),
          NGTCP2_CRYPTO_INITIAL_KEYLEN,
          rx_iv.data(),
          NGTCP2_CRYPTO_INITIAL_IVLEN,
          rx_hp.data(),
          NGTCP2_CRYPTO_INITIAL_KEYLEN) == 0;
}

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
bool UpdateTrafficSecret(
    SessionSecret* dest,
    std::vector<uint8_t>* secret,
    const CryptoContext* ctx) {

  static constexpr uint8_t LABEL[] = "traffic upd";

  CHECK_GE(dest->size(), secret->size());

  return HKDF_Expand_Label(
    dest->data(),
    secret->size(),
    ctx,
    secret->data(),
    secret->size(),
    LABEL,
    strsize(LABEL));
}

// TODO(@jasnell): Replace with ngtcp2_crypto_update_and_install_key
// once we move to ngtcp2_crypto
bool UpdateAndInstallKey(
    ngtcp2_conn* conn,
    std::vector<uint8_t>* current_rx_secret,
    std::vector<uint8_t>* current_tx_secret,
    size_t secretlen,
    const CryptoContext* ctx) {
  SessionSecret rx_secret;
  SessionSecret tx_secret;
  SessionKey rx_key;
  SessionIV rx_iv;
  SessionKey tx_key;
  SessionIV tx_iv;

  size_t keylen = aead_key_length(ctx);
  size_t ivlen = packet_protection_ivlen(ctx);

  if (!UpdateTrafficSecret(&rx_secret, current_rx_secret, ctx) ||
      !DerivePacketProtectionKey(
          rx_key.data(),
          rx_iv.data(),
          nullptr,
          ctx,
          rx_secret.data(),
          secretlen) ||
      !UpdateTrafficSecret(&tx_secret, current_tx_secret, ctx) ||
      !DerivePacketProtectionKey(
          tx_key.data(),
          tx_iv.data(),
          nullptr,
          ctx,
          tx_secret.data(),
          secretlen)) {
    return false;
  }

  current_rx_secret->assign(std::begin(rx_secret), std::end(rx_secret));
  current_tx_secret->assign(std::begin(tx_secret), std::end(tx_secret));

  return
      ngtcp2_conn_update_rx_key(
        conn,
        rx_key.data(),
        keylen,
        rx_iv.data(),
        ivlen) == 0 &&
      ngtcp2_conn_update_tx_key(
        conn,
        tx_key.data(),
        keylen,
        tx_iv.data(),
        ivlen) == 0;
}

bool DeriveTokenKey(
    uint8_t* token_key,
    uint8_t* token_iv,
    const uint8_t* rand_data,
    size_t rand_datalen,
    const CryptoContext* context,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {
  TokenSecret secret;

  return
      HKDF_Extract(
          secret.data(),
          secret.size(),
          context,
          token_secret->data(),
          token_secret->size(),
          rand_data,
          rand_datalen) &&
      DerivePacketProtectionKey(
          token_key,
          token_iv,
          nullptr,
          context,
          secret.data(),
          secret.size());
}

bool MessageDigest(
    std::array<uint8_t, 32>* dest,
    const std::array<uint8_t, 16>& rand) {
  const EVP_MD* meth = EVP_sha256();
  DeleteFnPtr<EVP_MD_CTX, EVP_MD_CTX_free> ctx;
  ctx.reset(EVP_MD_CTX_new());
  CHECK(ctx);

  if (EVP_DigestInit_ex(ctx.get(), meth, nullptr) != 1)
    return false;

  if (EVP_DigestUpdate(ctx.get(), rand.data(), rand.size()) != 1)
    return false;

  unsigned int mdlen = EVP_MD_size(meth);

  return EVP_DigestFinal_ex(ctx.get(), dest->data(), &mdlen) == 1;
}

bool GenerateRandData(uint8_t* buf, size_t len) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;
  EntropySource(rand.data(), rand.size());

  if (!MessageDigest(&md, rand))
    return false;

  CHECK_LE(len, md.size());
  std::copy_n(std::begin(md), len, buf);
  return true;
}

void ClearTLSError() {
  ERR_clear_error();
}

const char* TLSErrorString(int code) {
  return ERR_error_string(code, nullptr);
}

void InstallEarlyKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp) {
  CHECK_EQ(
     ngtcp2_conn_install_early_keys(
        connection,
        key.data(),
        keylen,
        iv.data(),
        ivlen,
        hp.data(),
        keylen), 0);
}

void InstallHandshakeRXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp) {
  CHECK_EQ(
     ngtcp2_conn_install_handshake_rx_keys(
        connection,
        key.data(),
        keylen,
        iv.data(),
        ivlen,
        hp.data(),
        keylen), 0);
}

void InstallHandshakeTXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp) {
  CHECK_EQ(
     ngtcp2_conn_install_handshake_tx_keys(
        connection,
        key.data(),
        keylen,
        iv.data(),
        ivlen,
        hp.data(),
        keylen), 0);
}

void InstallRXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp) {
  CHECK_EQ(
     ngtcp2_conn_install_rx_keys(
        connection,
        key.data(),
        keylen,
        iv.data(),
        ivlen,
        hp.data(),
        keylen), 0);
}

void InstallTXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp) {
  CHECK_EQ(
     ngtcp2_conn_install_tx_keys(
        connection,
        key.data(),
        keylen,
        iv.data(),
        ivlen,
        hp.data(),
        keylen), 0);
}

// MessageCB provides a hook into the TLS handshake dataflow. Currently, it
// is used to capture TLS alert codes (errors) and to collect the TLS handshake
// data that is to be sent.
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
  }
}

void LogSecret(
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

    line += " " + StringBytes::hex_encode(
        reinterpret_cast<const char*>(crandom), 32);
    line += " " + StringBytes::hex_encode(
        reinterpret_cast<const char*>(secret), secretlen);
    keylog_cb(ssl, line.c_str());
  }
}

int CertCB(SSL* ssl, void* arg) {
  QuicSession* session = static_cast<QuicSession*>(arg);
  return session->OnCert();
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

  // Output the secret to the keylog
  LogSecret(ssl, name, secret, secretlen);

  return session->OnKey(name, secret, secretlen) ? 1 : 0;
}

int ClearTLS(SSL* ssl, bool continue_on_error) {
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

int DoTLSHandshake(SSL* ssl) {
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

int DoTLSReadEarlyData(SSL* ssl) {
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

Local<Array> GetClientHelloCiphers(
    Environment* env,
    SSL* ssl) {
  const unsigned char* buf;
  size_t len = SSL_client_hello_get0_ciphers(ssl, &buf);
  std::vector<Local<Value>> ciphers_array;
  for (size_t n = 0; n < len; n += 2) {
    const SSL_CIPHER* cipher = SSL_CIPHER_find(ssl, buf);
    buf += 2;
    const char* cipher_name = SSL_CIPHER_get_name(cipher);
    const char* cipher_version = SSL_CIPHER_get_version(cipher);
    Local<Object> obj = Object::New(env->isolate());
    USE(obj->Set(
        env->context(),
        env->name_string(),
        OneByteString(env->isolate(), cipher_name)));
    USE(obj->Set(
        env->context(),
        env->version_string(),
        OneByteString(env->isolate(), cipher_version)));
    ciphers_array.push_back(obj);
  }
  return Array::New(env->isolate(), ciphers_array.data(), ciphers_array.size());
}

const char* GetClientHelloServerName(SSL* ssl) {
    const unsigned char* buf;
    size_t len;
    size_t rem;

    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &buf, &rem) ||
        rem <= 2)
        return nullptr;

    len = *(buf++) << 8;
    len += *(buf++);
    if (len + 2 != rem)
      return nullptr;
    rem = len;

    if (rem == 0 || *buf++ != TLSEXT_NAMETYPE_host_name)
      return nullptr;
    rem--;
    if (rem <= 2)
      return nullptr;
    len = *(buf++) << 8;
    len += *(buf++);
    if (len + 2 > rem)
      return nullptr;
    rem = len;
    return reinterpret_cast<const char*>(buf);
}

const char* GetClientHelloALPN(SSL* ssl) {
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

int UseSNIContext(SSL* ssl, crypto::SecureContext* context) {
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

int Client_Hello_CB(
    SSL* ssl,
    int* tls_alert,
    void* arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  int ret = session->OnClientHello();
  switch (ret) {
    case 0:
      return 1;
    case -1:
      return -1;
    default:
      *tls_alert = ret;
      return 0;
  }
}

int ALPN_Select_Proto_CB(
    SSL* ssl,
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
      alpn = reinterpret_cast<const uint8_t*>(session->GetALPN().c_str());
      alpnlen = session->GetALPN().length();
      break;
    default:
      // Unexpected QUIC protocol version
      return SSL_TLSEXT_ERR_NOACK;
  }

  for (auto p = in, end = in + inlen; p + alpnlen < end; p += *p + 1) {
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

int TLS_Status_Callback(SSL* ssl, void* arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  return session->OnTLSStatus();
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

void Transport_Params_Free_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char* out,
    void* add_arg) {
  delete[] reinterpret_cast<const uint8_t*>(out);
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

bool GenerateRetryToken(
    uint8_t* token,
    size_t* tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {
  std::array<uint8_t, 4096> plaintext;

  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);

  const size_t addrlen = SocketAddress::GetAddressLen(addr);
  size_t keylen = aead_key_length(&ctx);
  size_t ivlen = packet_protection_ivlen(&ctx);

  uint64_t now = uv_hrtime();

  auto p = std::begin(plaintext);
  p = std::copy_n(reinterpret_cast<const uint8_t*>(addr), addrlen, p);
  p = std::copy_n(reinterpret_cast<uint8_t*>(&now), sizeof(now), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  TokenKey token_key;
  TokenIV token_iv;

  if (!GenerateRandData(rand_data.data(), TOKEN_RAND_DATALEN))
    return false;

  if (!DeriveTokenKey(
          token_key.data(),
          token_iv.data(),
          rand_data.data(),
          TOKEN_RAND_DATALEN,
          &ctx,
          token_secret)) {
    return false;
  }

  ssize_t n =
      Encrypt(
          token, *tokenlen,
          plaintext.data(), std::distance(std::begin(plaintext), p),
          &ctx,
          token_key.data(),
          keylen,
          token_iv.data(),
          ivlen,
          reinterpret_cast<const uint8_t *>(addr), addrlen);

  if (n < 0)
    return false;

  memcpy(token + n, rand_data.data(), rand_data.size());
  *tokenlen = n + rand_data.size();
  return true;
}

bool InvalidRetryToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret,
    uint64_t verification_expiration) {

  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);

  size_t keylen = aead_key_length(&ctx);
  size_t ivlen = packet_protection_ivlen(&ctx);
  const size_t addrlen = SocketAddress::GetAddressLen(addr);

  if (hd->tokenlen < TOKEN_RAND_DATALEN)
    return  true;

  uint8_t* rand_data = hd->token + hd->tokenlen - TOKEN_RAND_DATALEN;
  uint8_t* ciphertext = hd->token;
  size_t ciphertextlen = hd->tokenlen - TOKEN_RAND_DATALEN;

  TokenKey token_key;
  TokenIV token_iv;

  if (!DeriveTokenKey(
          token_key.data(),
          token_iv.data(),
          rand_data,
          TOKEN_RAND_DATALEN,
          &ctx,
          token_secret)) {
    return true;
  }

  std::array<uint8_t, 4096> plaintext;

  ssize_t n =
      Decrypt(
          plaintext.data(), plaintext.size(),
          ciphertext, ciphertextlen,
          &ctx,
          token_key.data(),
          keylen,
          token_iv.data(),
          ivlen,
          reinterpret_cast<const uint8_t*>(addr), addrlen);

  // Will also cover case where n is negative
  if (static_cast<size_t>(n) < addrlen + sizeof(uint64_t))
    return true;

  ssize_t cil = static_cast<size_t>(n) - addrlen - sizeof(uint64_t);
  if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN))
    return true;

  if (memcmp(plaintext.data(), addr, addrlen) != 0)
    return true;


  uint64_t t;
  memcpy(&t, plaintext.data() + addrlen, sizeof(uint64_t));

  uint64_t now = uv_hrtime();

  // 10-second window by default, but configurable for each
  // QuicSocket instance with a MIN_RETRYTOKEN_EXPIRATION second
  // minimum and a MAX_RETRYTOKEN_EXPIRATION second maximum.
  if (t + verification_expiration * NGTCP2_SECONDS < now)
    return true;

  ngtcp2_cid_init(ocid, plaintext.data() + addrlen + sizeof(uint64_t), cil);

  return false;
}

int VerifyPeerCertificate(SSL* ssl) {
  int err = X509_V_ERR_UNSPECIFIED;
  if (X509* peer_cert = SSL_get_peer_certificate(ssl)) {
    X509_free(peer_cert);
    err = SSL_get_verify_result(ssl);
  }
  return err;
}

std::string GetCertificateCN(X509* cert) {
  X509_NAME* subject = X509_get_subject_name(cert);
  if (subject != nullptr) {
    int nid = OBJ_txt2nid("CN");
    int idx = X509_NAME_get_index_by_NID(subject, nid, -1);
    if (idx != -1) {
      X509_NAME_ENTRY* cn = X509_NAME_get_entry(subject, idx);
      if (cn != nullptr) {
        ASN1_STRING* cn_str = X509_NAME_ENTRY_get_data(cn);
        if (cn_str != nullptr) {
          return std::string(reinterpret_cast<const char*>(
              ASN1_STRING_get0_data(cn_str)));
        }
      }
    }
  }
  return std::string();
}

std::unordered_multimap<std::string, std::string> GetCertificateAltNames(
    X509* cert) {
  std::unordered_multimap<std::string, std::string> map;
  crypto::BIOPointer bio(BIO_new(BIO_s_mem()));
  BUF_MEM* mem;
  int idx = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
  if (idx < 0)  // There is no subject alt name
    return map;

  X509_EXTENSION* ext = X509_get_ext(cert, idx);
  CHECK_NOT_NULL(ext);
  const X509V3_EXT_METHOD* method = X509V3_EXT_get(ext);
  CHECK_EQ(method, X509V3_EXT_get_nid(NID_subject_alt_name));

  GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
  if (names == nullptr)  // There are no names
    return map;

  for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
    USE(BIO_reset(bio.get()));
    GENERAL_NAME* gen = sk_GENERAL_NAME_value(names, i);
    if (gen->type == GEN_DNS) {
      ASN1_IA5STRING* name = gen->d.dNSName;
      BIO_write(bio.get(), name->data, name->length);
      BIO_get_mem_ptr(bio.get(), &mem);
      map.emplace("dns", std::string(mem->data, mem->length));
    } else {
      STACK_OF(CONF_VALUE)* nval = i2v_GENERAL_NAME(
          const_cast<X509V3_EXT_METHOD*>(method), gen, nullptr);
      if (nval == nullptr)
        continue;
      X509V3_EXT_val_prn(bio.get(), nval, 0, 0);
      sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
      BIO_get_mem_ptr(bio.get(), &mem);
      std::string value(mem->data, mem->length);
      if (value.compare(0, 11, "IP Address:") == 0) {
        map.emplace("ip", value.substr(11));
      } else if (value.compare(0, 4, "URI:") == 0) {
        url::URL url(value.substr(4));
        if (url.flags() & url::URL_FLAGS_CANNOT_BE_BASE ||
            url.flags() & url::URL_FLAGS_FAILED) {
          continue;  // Skip this one
        }
        map.emplace("uri", url.host());
      }
    }
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  bio.reset();
  return map;
}

bool SplitHostname(
    const char* hostname,
    std::vector<std::string>* parts,
    const char delim) {
  static std::string check_str =
      "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30"
      "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40"
      "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50"
      "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60"
      "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70"
      "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F";

  std::stringstream str(hostname);
  std::string part;
  while (getline(str, part, delim)) {
    // if (part.length() == 0 ||
    //     part.find_first_not_of(check_str) != std::string::npos) {
    //   return false;
    // }
    for (size_t n = 0; n < part.length(); n++) {
      if (part[n] >= 'A' && part[n] <= 'Z')
        part[n] = (part[n] | 0x20);  // Lower case the letter
      if (check_str.find(part[n]) == std::string::npos)
        return false;
    }
    parts->push_back(part);
  }
  return true;
}


bool CheckCertNames(
    const std::vector<std::string>& host_parts,
    const std::string& name,
    bool use_wildcard) {

  if (name.length() == 0)
    return false;

  std::vector<std::string> name_parts;
  if (!SplitHostname(name.c_str(), &name_parts))
    return false;

  if (name_parts.size() != host_parts.size())
    return false;

  for (size_t n = host_parts.size() - 1; n > 0; --n) {
    if (host_parts[n] != name_parts[n])
      return false;
  }

  if (name_parts[0].find("*") == std::string::npos ||
      name_parts[0].find("xn--") != std::string::npos) {
    return host_parts[0] == name_parts[0];
  }

  if (!use_wildcard)
    return false;

  std::vector<std::string> sub_parts;
  SplitHostname(name_parts[0].c_str(), &sub_parts, '*');

  if (sub_parts.size() > 2)
    return false;

  if (name_parts.size() <= 2)
    return false;

  std::string prefix;
  std::string suffix;
  if (sub_parts.size() == 2) {
    prefix = sub_parts[0];
    suffix = sub_parts[1];
  } else {
    prefix = "";
    suffix = sub_parts[0];
  }

  if (prefix.length() + suffix.length() > host_parts[0].length())
    return false;

  if (host_parts[0].compare(0, prefix.length(), prefix))
    return false;

  if (host_parts[0].compare(
          host_parts[0].length() - suffix.length(),
          suffix.length(), suffix)) {
    return false;
  }

  return true;
}

int VerifyHostnameIdentity(
    const char* hostname,
    const std::string& cert_cn,
    const std::unordered_multimap<std::string, std::string>& altnames) {

  int err = X509_V_ERR_HOSTNAME_MISMATCH;

  // 1. If the hostname is an IP address (v4 or v6), the certificate is valid
  //    if and only if there is an 'IP Address:' alt name specifying the same
  //    IP address. The IP address must be canonicalized to ensure a proper
  //    check. It's possible that the X509_check_ip_asc covers this. If so,
  //    we can remove this check.

  if (SocketAddress::numeric_host(hostname)) {
    auto ips = altnames.equal_range("ip");
    for (auto ip = ips.first; ip != ips.second; ++ip) {
      if (ip->second.compare(hostname) == 0) {
        // Success!
        return 0;
      }
    }
    // No match, and since the hostname is an IP address, skip any
    // further checks
    return err;
  }

  auto dns_names = altnames.equal_range("dns");
  auto uri_names = altnames.equal_range("uri");

  size_t dns_count = std::distance(dns_names.first, dns_names.second);
  size_t uri_count = std::distance(uri_names.first, uri_names.second);

  std::vector<std::string> host_parts;
  SplitHostname(hostname, &host_parts);

  // 2. If there no 'DNS:' or 'URI:' Alt names, if the certificate has a
  //    Subject, then we need to extract the CN field from the Subject. and
  //    check that the hostname matches the CN, taking into consideration
  //    the possibility of a wildcard in the CN. If there is a match, congrats,
  //    we have a valid certificate. Return and be happy.

  if (dns_count == 0 && uri_count == 0) {
    if (cert_cn.length() > 0 && CheckCertNames(host_parts, cert_cn))
        return 0;
    // No match, and since there are no dns or uri entries, return
    return err;
  }

  // 3. If, however, there are 'DNS:' and 'URI:' Alt names, things become more
  //    complicated. Essentially, we need to iterate through each 'DNS:' and
  //    'URI:' Alt name to find one that matches. The 'DNS:' Alt names are
  //    relatively simple but may include wildcards. The 'URI:' Alt names
  //    require the name to be parsed as a URL, then extract the hostname from
  //    the URL, which is then checked against the hostname. If you find a
  //    match, yay! Return and be happy. (Note, it's possible that the 'DNS:'
  //    check in this step is redundant to the X509_check_host check. If so,
  //    we can simplify by removing those checks here.)

  // First, let's check dns names
  for (auto name = dns_names.first; name != dns_names.second; ++name) {
    if (name->first.length() > 0 &&
        CheckCertNames(host_parts, name->second)) {
      return 0;
    }
  }

  // Then, check uri names
  for (auto name = uri_names.first; name != uri_names.second; ++name) {
    if (name->first.length() > 0 &&
        CheckCertNames(host_parts, name->second, false)) {
      return 0;
    }
  }

  // 4. Failing all of the previous checks, we assume the certificate is
  //    invalid for an unspecified reason.
  return err;
}

int VerifyHostnameIdentity(SSL* ssl, const char* hostname) {
  int err = X509_V_ERR_HOSTNAME_MISMATCH;
  crypto::X509Pointer cert(SSL_get_peer_certificate(ssl));
  if (!cert)
    return err;

  // There are several pieces of information we need from the cert at this point
  // 1. The Subject (if it exists)
  // 2. The collection of Alt Names (if it exists)
  //
  // The certificate may have many Alt Names. We only care about the ones that
  // are prefixed with 'DNS:', 'URI:', or 'IP Address:'. We might check
  // additional ones later but we'll start with these.
  //
  // Ideally, we'd be able to *just* use OpenSSL's built in name checking for
  // this (SSL_set1_host and X509_check_host) but it does not appear to do
  // checking on URI or IP Address Alt names, which is unfortunate. We need
  // both of those to retain compatibility with the peer identity verification
  // Node.js already does elsewhere. At the very least, we'll use
  // X509_check_host here first as a first step. If it is successful, awesome,
  // there's nothing else for us to do. Return and be happy!
  if (X509_check_host(
          cert.get(),
          hostname,
          strlen(hostname),
          X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
          X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS |
          X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
          nullptr) > 0) {
    return 0;
  }

  if (X509_check_ip_asc(
          cert.get(),
          hostname,
          X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) > 0) {
    return 0;
  }

  // If we've made it this far, then we have to perform a more check
  return VerifyHostnameIdentity(
      hostname,
      GetCertificateCN(cert.get()),
      GetCertificateAltNames(cert.get()));
}

const char* X509ErrorCode(int err) {
  const char* code = "UNSPECIFIED";
#define CASE_X509_ERR(CODE) case X509_V_ERR_##CODE: code = #CODE; break;
  switch (err) {
    CASE_X509_ERR(UNABLE_TO_GET_ISSUER_CERT)
    CASE_X509_ERR(UNABLE_TO_GET_CRL)
    CASE_X509_ERR(UNABLE_TO_DECRYPT_CERT_SIGNATURE)
    CASE_X509_ERR(UNABLE_TO_DECRYPT_CRL_SIGNATURE)
    CASE_X509_ERR(UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)
    CASE_X509_ERR(CERT_SIGNATURE_FAILURE)
    CASE_X509_ERR(CRL_SIGNATURE_FAILURE)
    CASE_X509_ERR(CERT_NOT_YET_VALID)
    CASE_X509_ERR(CERT_HAS_EXPIRED)
    CASE_X509_ERR(CRL_NOT_YET_VALID)
    CASE_X509_ERR(CRL_HAS_EXPIRED)
    CASE_X509_ERR(ERROR_IN_CERT_NOT_BEFORE_FIELD)
    CASE_X509_ERR(ERROR_IN_CERT_NOT_AFTER_FIELD)
    CASE_X509_ERR(ERROR_IN_CRL_LAST_UPDATE_FIELD)
    CASE_X509_ERR(ERROR_IN_CRL_NEXT_UPDATE_FIELD)
    CASE_X509_ERR(OUT_OF_MEM)
    CASE_X509_ERR(DEPTH_ZERO_SELF_SIGNED_CERT)
    CASE_X509_ERR(SELF_SIGNED_CERT_IN_CHAIN)
    CASE_X509_ERR(UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    CASE_X509_ERR(UNABLE_TO_VERIFY_LEAF_SIGNATURE)
    CASE_X509_ERR(CERT_CHAIN_TOO_LONG)
    CASE_X509_ERR(CERT_REVOKED)
    CASE_X509_ERR(INVALID_CA)
    CASE_X509_ERR(PATH_LENGTH_EXCEEDED)
    CASE_X509_ERR(INVALID_PURPOSE)
    CASE_X509_ERR(CERT_UNTRUSTED)
    CASE_X509_ERR(CERT_REJECTED)
    CASE_X509_ERR(HOSTNAME_MISMATCH)
  }
#undef CASE_X509_ERR
  return code;
}

// Get the SNI hostname requested by the client for the session
Local<Value> GetServerName(
    Environment* env,
    SSL* ssl,
    const char* host_name) {
  Local<Value> servername;
  if (host_name != nullptr) {
    servername = String::NewFromUtf8(
        env->isolate(),
        host_name,
        v8::NewStringType::kNormal).ToLocalChecked();
  }
  return servername;
}

// Get the ALPN protocol identifier that was negotiated for the session
Local<Value> GetALPNProtocol(Environment* env, SSL* ssl) {
  Local<Value> alpn;
  const unsigned char* alpn_buf = nullptr;
  unsigned int alpnlen;

  SSL_get0_alpn_selected(ssl, &alpn_buf, &alpnlen);
  if (alpnlen == sizeof(NGTCP2_ALPN_H3) - 2 &&
      memcmp(alpn_buf, NGTCP2_ALPN_H3 + 1, sizeof(NGTCP2_ALPN_H3) - 2) == 0) {
    alpn = env->quic_alpn_string();
  } else {
    alpn = OneByteString(env->isolate(), alpn_buf, alpnlen);
  }
  return alpn;
}

Local<Value> GetCipherName(Environment* env, SSL* ssl) {
  Local<Value> cipher;
  const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
  if (c != nullptr) {
    const char* cipher_name = SSL_CIPHER_get_name(c);
    cipher = OneByteString(env->isolate(), cipher_name);
  }
  return cipher;
}

Local<Value> GetCipherVersion(Environment* env, SSL* ssl) {
  Local<Value> version;
  // Get the cipher and version
  const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
  if (c != nullptr) {
    const char* cipher_version = SSL_CIPHER_get_version(c);
    version = OneByteString(env->isolate(), cipher_version);
  }
  return version;
}

}  // namespace quic
}  // namespace node
