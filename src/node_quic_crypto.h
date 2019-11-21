#ifndef SRC_NODE_QUIC_CRYPTO_H_
#define SRC_NODE_QUIC_CRYPTO_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_crypto.h"
#include "node_quic_util.h"
#include "v8.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>

namespace node {

namespace quic {

// Forward declaration
class QuicSession;

#define NGTCP2_ERR(V) (V != 0)
#define NGTCP2_OK(V) (V == 0)

// Called by QuicSession::OnSecrets when openssl
// delivers crypto secrets to the QuicSession.
// This will derive and install the keys and iv
// for TX and RX at the specified level, and
// generates the QUIC specific keylog events.
bool SetCryptoSecrets(
    QuicSession* session,
    ngtcp2_crypto_level level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen);

// Called by QuicInitSecureContext in node_quic.cc
// to set the TLS groups for the context.
bool SetGroups(crypto::SecureContext* sc, const char* groups);

// Called by QuicInitSecureContext to initialize the
// given SecureContext with the defaults for the given
// QUIC side (client or server).
void InitializeSecureContext(
    crypto::SecureContext* sc,
    ngtcp2_crypto_side side);

// Called in the QuicSession::InitServer and
// QuicSession::InitClient to configure the
// appropriate settings for the SSL* associated
// with the session.
void InitializeTLS(QuicSession* session);

// Called when the client QuicSession is created and
// when the server QuicSession first receives the
// client hello.
bool DeriveAndInstallInitialKey(
    QuicSession* session,
    const ngtcp2_cid* dcid);

// Called when QuicSession::UpdateKey() is called.
bool UpdateKey(
    QuicSession* session,
    uint8_t* rx_key,
    uint8_t* rx_iv,
    uint8_t* tx_key,
    uint8_t* tx_iv,
    std::vector<uint8_t>* current_rx_secret,
    std::vector<uint8_t>* current_tx_secret);

// Get the server name identified in the client hello
const char* GetClientHelloServerName(QuicSession* session);

// Get the alpn protocol identified in the client hello
const char* GetClientHelloALPN(QuicSession* session);

const char* GetServerName(QuicSession* session);

// Replaces the SecureContext to be used in the handshake.
int UseSNIContext(SSL* ssl, crypto::SecureContext* context);

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

// Called by QuicSession::VerifyPeerIdentity to perform basic
// validation checks against the peer provided certificate.
int VerifyPeerCertificate(SSL* ssl);

int VerifyHostnameIdentity(SSL* ssl, const char* hostname);
int VerifyHostnameIdentity(
    const char* hostname,
    const std::string& cert_cn,
    const std::unordered_multimap<std::string, std::string>& altnames);

v8::Local<v8::Value> GetValidationErrorReason(Environment* env, int err);
v8::Local<v8::Value> GetValidationErrorCode(Environment* env, int err);

v8::Local<v8::Value> GetCertificate(QuicSession* session);
v8::Local<v8::Value> GetEphemeralKey(QuicSession* session);

bool SetTLSSession(SSL* ssl, const unsigned char* buf, size_t length);

std::string GetSSLOCSPResponse(SSL* ssl);

// Get the SNI hostname requested by the client for the session
v8::Local<v8::Value> GetServerName(
    Environment* env,
    SSL* ssl,
    const char* host_name);

// Get the list of cipher algorithms advertised in the client hello
v8::Local<v8::Array> GetClientHelloCiphers(QuicSession* Session);

// Get the ALPN protocol identifier that was negotiated for the session
v8::Local<v8::Value> GetALPNProtocol(QuicSession* session);

// Get the negotiated cipher name for the TLS session
v8::Local<v8::Value> GetCipherName(QuicSession* session);

// Get the negotiated cipher version for the TLS session
v8::Local<v8::Value> GetCipherVersion(QuicSession* session);

// Get a JavaScript rendering of the X509 certificate provided by the peer
// TODO(@jasnell): This currently only works for the Client side
v8::Local<v8::Value> GetPeerCertificate(
    QuicSession* session,
    bool abbreviated);

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_CRYPTO_H_
