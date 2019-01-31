#ifndef SRC_NODE_QUIC_CRYPTO_H_
#define SRC_NODE_QUIC_CRYPTO_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_crypto.h"
#include "node_quic_util.h"
#include "node_url.h"
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

using crypto::EntropySource;

namespace quic {

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
#define NGTCP2_CRYPTO_INITIAL_SECRETLEN 32
#define NGTCP2_CRYPTO_INITIAL_KEYLEN 16
#define NGTCP2_CRYPTO_INITIAL_IVLEN 12
#define NGTCP2_CRYPTO_SECRETLEN 64
#define NGTCP2_CRYPTO_KEYLEN 64
#define NGTCP2_CRYPTO_IVLEN 64
#define NGTCP2_CRYPTO_TOKEN_SECRETLEN 32
#define NGTCP2_CRYPTO_TOKEN_KEYLEN 32
#define NGTCP2_CRYPTO_TOKEN_IVLEN 32

using PKeyCtxPointer = DeleteFnPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using CipherCtxPointer = DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

using InitialSecret = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN>;
using InitialKey = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN>;
using InitialIV = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN>;
using SessionSecret = std::array<uint8_t, NGTCP2_CRYPTO_SECRETLEN>;
using SessionKey = std::array<uint8_t, NGTCP2_CRYPTO_KEYLEN>;
using SessionIV = std::array<uint8_t, NGTCP2_CRYPTO_IVLEN>;
using TokenSecret = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_SECRETLEN>;
using TokenKey = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_KEYLEN>;
using TokenIV = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_IVLEN>;

struct CryptoContext {
  const EVP_CIPHER* aead;
  const EVP_CIPHER* hp;
  const EVP_MD* md;
};

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
enum ngtcp2_crypto_side {
  /**
   * ``NGTCP2_CRYPTO_SIDE_CLIENT`` indicates that the application is
   * client.
   */
  NGTCP2_CRYPTO_SIDE_CLIENT,
  /**
   * ``NGTCP2_CRYPTO_SIDE_SERVER`` indicates that the application is
   * server.
   */
  NGTCP2_CRYPTO_SIDE_SERVER
};

BIO_METHOD* CreateBIOMethod();

// TODO(@jasnell): Replace with ngtcp2_crypto_aead_keylen once
// we move to ngtcp2_crypto.h
size_t aead_key_length(const CryptoContext* ctx);

// TODO(@jasnell): Replace with ngtcp2_crypto_packet_protection_ivlen
// once we move to ngtcp2_crypto.h
size_t packet_protection_ivlen(const CryptoContext* ctx);

// TODO(@jasnell): Replace with ngtcp2_crypto_aead_taglen once
// we move to ngtcp2_crypto.h
size_t aead_tag_length(const CryptoContext* ctx);

// TODO(@jasnell): Replace with ngtcp2_crypto_ctx_initial once
// we move to ngtcp2_crypto.h
void SetupInitialCryptoContext(CryptoContext* context);

// TODO(@jasnell): Replace with ngtcp2_crypto_ctx_tls once
// we move to ngtcp2_crypto
void SetupCryptoContext(CryptoContext* ctx, SSL* ssl);

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
    size_t adlen);

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
    size_t adlen);

// TODO(@jasnell): Replace with ngtcp2_crypto_hp_mask once
// we move to ngtcp2_crypto
ssize_t HP_Mask(
    uint8_t* dest,
    size_t destlen,
    const CryptoContext* ctx,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen);


// TODO(@jasnell): Remove once we move to ngtcp2_crypto
bool DerivePacketProtectionKey(
    uint8_t* key,
    uint8_t* iv,
    uint8_t* hp_key,
    const CryptoContext* ctx,
    const uint8_t* secret,
    size_t secretlen);

// TODO(@jasnell): Replace with ngtcp2_crypto_derive_and_install_initial_key
// once we move to ngtcp2_crypto
bool DeriveAndInstallInitialKey(
  ngtcp2_conn* conn,
  const ngtcp2_cid* dcid,
  ngtcp2_crypto_side side);

// TODO(@jasnell): Replace with ngtcp2_crypto_update_and_install_key
// once we move to ngtcp2_crypto
bool UpdateAndInstallKey(
    ngtcp2_conn* conn,
    std::vector<uint8_t>* current_rx_secret,
    std::vector<uint8_t>* current_tx_secret,
    size_t secretlen,
    const CryptoContext* ctx);

void ClearTLSError();

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
void InstallEarlyKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp);

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
void InstallHandshakeRXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp);

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
void InstallHandshakeTXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp);

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
void InstallRXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp);

// TODO(@jasnell): Remove once we move to ngtcp2_crypto
void InstallTXKeys(
    ngtcp2_conn* connection,
    size_t keylen,
    size_t ivlen,
    const SessionKey& key,
    const SessionIV& iv,
    const SessionKey& hp);

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
    void* arg);

int CertCB(SSL* ssl, void* arg);

// KeyCB provides a hook into the keying process of the TLS handshake,
// triggering registration of the keys associated with the TLS session.
int KeyCB(
    SSL* ssl,
    int name,
    const unsigned char* secret,
    size_t secretlen,
    void* arg);

int ClearTLS(SSL* ssl, bool continue_on_error = false);

int DoTLSHandshake(SSL* ssl);

int DoTLSReadEarlyData(SSL* ssl);

v8::Local<v8::Array> GetClientHelloCiphers(
    Environment* env,
    SSL* ssl);

const char* GetClientHelloServerName(SSL* ssl);

const char* GetClientHelloALPN(SSL* ssl);

int UseSNIContext(SSL* ssl, crypto::SecureContext* context);

int Client_Hello_CB(
    SSL* ssl,
    int* tls_alert,
    void* arg);

int ALPN_Select_Proto_CB(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg);

int Client_Transport_Params_Add_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char** out,
    size_t* outlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* add_arg);

int TLS_Status_Callback(SSL* ssl, void* arg);

int Server_Transport_Params_Add_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char** out,
    size_t* outlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* add_arg);

void Transport_Params_Free_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char* out,
    void* add_arg);

int Client_Transport_Params_Parse_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char* in,
    size_t inlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* parse_arg);

int Server_Transport_Params_Parse_CB(
    SSL* ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char* in,
    size_t inlen,
    X509* x,
    size_t chainidx,
    int* al,
    void* parse_arg);

bool GenerateRetryToken(
    uint8_t* token,
    size_t* tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret);

bool InvalidRetryToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret,
    uint64_t verification_expiration);

int VerifyPeerCertificate(SSL* ssl);

std::string GetCertificateCN(X509* cert);

std::unordered_multimap<std::string, std::string> GetCertificateAltNames(
    X509* cert);

bool SplitHostname(
    const char* hostname,
    std::vector<std::string>* parts,
    const char delim = '.');


bool CheckCertNames(
    const std::vector<std::string>& host_parts,
    const std::string& name,
    bool use_wildcard = true);

int VerifyHostnameIdentity(
    const char* hostname,
    const std::string& cert_cn,
    const std::unordered_multimap<std::string, std::string>& altnames);

int VerifyHostnameIdentity(SSL* ssl, const char* hostname);

const char* X509ErrorCode(int err);

// Get the SNI hostname requested by the client for the session
v8::Local<v8::Value> GetServerName(
    Environment* env,
    SSL* ssl,
    const char* host_name);

// Get the ALPN protocol identifier that was negotiated for the session
v8::Local<v8::Value> GetALPNProtocol(Environment* env, SSL* ssl);

v8::Local<v8::Value> GetCipherName(Environment* env, SSL* ssl);

v8::Local<v8::Value> GetCipherVersion(Environment* env, SSL* ssl);
}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_CRYPTO_H_
