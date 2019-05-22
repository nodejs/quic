#include "aliased_buffer.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "ngtcp2/ngtcp2.h"
#include "node.h"
#include "node_buffer.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "node_quic_crypto.h"
#include "node_quic_session.h"
#include "node_quic_socket.h"
#include "node_quic_stream.h"
#include "node_quic_state.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <openssl/ssl.h>

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
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyAttribute;
using v8::String;
using v8::Value;

namespace quic {

// The QuicSessionConfig is a utility class that uses an AliasedBuffer via the
// Environment to collect configuration settings for a QuicSession.

// Reset the QuicSessionConfig to initial defaults. The default values are set
// in the QUICSESSION_CONFIG macro definition in node_quic_session.h
void QuicSessionConfig::ResetToDefaults() {
#define V(idx, name, def) name##_ = def;
  QUICSESSION_CONFIG(V)
#undef V
  max_cid_len_ = NGTCP2_MAX_CIDLEN;
  min_cid_len_ = NGTCP2_MIN_CIDLEN;
}

// Sets the QuicSessionConfig using an AliasedBuffer for efficiency.
void QuicSessionConfig::Set(
    Environment* env,
    const sockaddr* preferred_addr) {
  ResetToDefaults();
  AliasedFloat64Array& buffer =
      env->quic_state()->quicsessionconfig_buffer;
  uint64_t flags = buffer[IDX_QUIC_SESSION_CONFIG_COUNT];

#define V(idx, name, def)                                                      \
  if (flags & (1 << IDX_QUIC_SESSION_##idx))                                   \
    name##_ = static_cast<uint64_t>(buffer[IDX_QUIC_SESSION_##idx]);
  QUICSESSION_CONFIG(V)
#undef V

  if (flags & (1 << IDX_QUIC_SESSION_MAX_CID_LEN)) {
    max_cid_len_ = static_cast<size_t>(buffer[IDX_QUIC_SESSION_MAX_CID_LEN]);
    CHECK_LE(max_cid_len_, NGTCP2_MAX_CIDLEN);
  }

  if (flags & (1 << IDX_QUIC_SESSION_MIN_CID_LEN)) {
    min_cid_len_ = static_cast<size_t>(buffer[IDX_QUIC_SESSION_MIN_CID_LEN]);
    CHECK_GE(min_cid_len_, NGTCP2_MIN_CIDLEN);
  }

  if (preferred_addr != nullptr) {
    preferred_address_set_ = true;
    preferred_address_.Copy(preferred_addr);
  }
}

// Copies the QuicSessionConfig into a ngtcp2_settings object
void QuicSessionConfig::ToSettings(ngtcp2_settings* settings,
                                   ngtcp2_cid* pscid,
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

  if (pscid != nullptr && preferred_address_set_) {
    settings->preferred_address_present = 1;
    const sockaddr* addr = *preferred_address_;
    switch (addr->sa_family) {
      case AF_INET: {
        auto& dest = settings->preferred_address.ipv4_addr;
        memcpy(
            &dest,
            &(reinterpret_cast<const sockaddr_in*>(addr)->sin_addr),
            sizeof(dest));
        settings->preferred_address.ipv4_port = SocketAddress::GetPort(addr);
        break;
      }
      case AF_INET6: {
        auto& dest = settings->preferred_address.ipv6_addr;
        memcpy(
            &dest,
            &(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr),
            sizeof(dest));
        settings->preferred_address.ipv6_port = SocketAddress::GetPort(addr);
        break;
      }
      default:
        UNREACHABLE();
    }

    EntropySource(
        settings->preferred_address.stateless_reset_token,
        arraysize(settings->preferred_address.stateless_reset_token));

    pscid->datalen = NGTCP2_SV_SCIDLEN;
    EntropySource(pscid->data, pscid->datalen);
    settings->preferred_address.cid = *pscid;
  }
}

void QuicSession::CheckAllocatedSize(size_t previous_size) {
  CHECK_GE(current_ngtcp2_memory_, previous_size);
}

void QuicSession::IncrementAllocatedSize(size_t size) {
  current_ngtcp2_memory_ += size;
}

void QuicSession::DecrementAllocatedSize(size_t size) {
  current_ngtcp2_memory_ -= size;
}

// Static ngtcp2 callbacks are registered when ngtcp2 when a new ngtcp2_conn is
// created. These are static functions that, for the most part, simply defer to
// a QuicSession instance that is passed through as user_data.

// Called by ngtcp2 upon creation of a new client connection
// to initiate the TLS handshake.
int QuicSession::OnClientInitial(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->TLSHandshake(), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 for a new server connection when the initial
// crypto handshake from the client has been received.
int QuicSession::OnReceiveClientInitial(
    ngtcp2_conn* conn,
    const ngtcp2_cid* dcid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ReceiveClientInitial(dcid), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 for both client and server connections when
// TLS handshake data has been received.
int QuicSession::OnReceiveCryptoData(
    ngtcp2_conn* conn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  return session->ReceiveCryptoData(crypto_level, offset, data, datalen);
}

// Called by ngtcp2 for a client connection when the server has
// sent a retry packet.
int QuicSession::OnReceiveRetry(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_hd* hd,
    const ngtcp2_pkt_retry* retry,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ReceiveRetry(), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 for both client and server connections
// when a request to extend the maximum number of bidirectional
// streams has been received.
int QuicSession::OnExtendMaxStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ExtendMaxStreamsBidi(max_streams), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 for both client and server connections
// when a request to extend the maximum number of unidirectional
// streams has been received
int QuicSession::OnExtendMaxStreamsUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->ExtendMaxStreamsUni(max_streams), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

int QuicSession::OnExtendMaxStreamData(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t max_data,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->ExtendMaxStreamData(stream_id, max_data);
  return 0;
}

// Called by ngtcp2 for both client and server connections
// when ngtcp2 has determined that the TLS handshake has
// been completed.
int QuicSession::OnHandshakeCompleted(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->HandshakeCompleted();
  return 0;
}

// Called by ngtcp2 when TLS handshake data needs to be
// encrypted prior to sending.
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

// Called by ngtcp2 when encrypted TLS handshake data has
// been received.
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

// Called by ngtcp2 when non-TLS handshake data needs to be
// encrypted prior to sending.
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

// Called by ngtcp2 when encrypted non-TLS handshake data
// has been received.
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

// Called by ngtcp2 when a chunk of stream data has been
// received.
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
      session->ReceiveStreamData(stream_id, fin, data, datalen), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 when a new stream has been opened
int QuicSession::OnStreamOpen(
    ngtcp2_conn* conn,
    int64_t stream_id,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->StreamOpen(stream_id), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 when an acknowledgement for a chunk of
// TLS handshake data has been received.
int QuicSession::OnAckedCryptoOffset(
    ngtcp2_conn* conn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    size_t datalen,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->AckedCryptoOffset(crypto_level, offset, datalen);
  return 0;
}

// Called by ngtcp2 when an acknowledgement for a chunk of
// stream data has been received.
int QuicSession::OnAckedStreamDataOffset(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t offset,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->AckedStreamDataOffset(stream_id, offset, datalen);
  return 0;
}

// Called by ngtcp2 for a client connection when the server
// has indicated a preferred address in the transport
// params.
// For now, there are two modes: we can accept the preferred address
// or we can reject it. Later, we may want to implement a callback
// to ask the user if they want to accept the preferred address or
// not.
int QuicSession::OnSelectPreferredAddress(
    ngtcp2_conn* conn,
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(
      session->SelectPreferredAddress(dest, paddr), 0,
      NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// Called by ngtcp2 when a stream has been closed for any
// reason.
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

// Called by ngtcp2 when it needs to generate some random data
int QuicSession::OnRand(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    ngtcp2_rand_ctx ctx,
    void* user_data) {
  EntropySource(dest, destlen);
  return 0;
}

// When a new client connection is established, ngtcp2 will call
// this multiple times to generate a pool of connection IDs to use.
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

// Called by ngtcp2 to trigger a key update for the connection.
int QuicSession::OnUpdateKey(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(session->UpdateKey(), 0, NGTCP2_ERR_CALLBACK_FAILURE);
  return 0;
}

// When a connection is closed, ngtcp2 will call this multiple
// times to remove connection IDs.
int QuicSession::OnRemoveConnectionID(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->RemoveConnectionID(cid);
  return 0;
}

// Called by ngtcp2 to perform path validation. Path validation
// is necessary to ensure that a packet is originating from the
// expected source.
int QuicSession::OnPathValidation(
    ngtcp2_conn* conn,
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  RETURN_IF_FAIL(session->PathValidation(path, res), 0, -1);
  return 0;
}

void QuicSession::OnKeylog(const SSL* ssl, const char* line) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  session->Keylog(line);
}

void QuicSession::SetupTokenContext(CryptoContext* context) {
  aead_aes_128_gcm(context);
  prf_sha256(context);
}

int QuicSession::GenerateRetryToken(
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

  RETURN_IF_FAIL(GenerateRandData(rand_data.data(), rand_data.size()), 0, -1);

  RETURN_IF_FAIL(
      DeriveTokenKey(
          &params,
          rand_data.data(),
          rand_data.size(),
          token_crypto_ctx,
          token_secret), 0, -1);

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

int QuicSession::VerifyRetryToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    CryptoContext* token_crypto_ctx,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret,
    uint64_t verification_expiration) {

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
          token_secret), 0, -1);

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

  // 10-second window by default, but configurable for each
  // QuicSocket instance with a MIN_RETRYTOKEN_EXPIRATION second
  // minimum and a MAX_RETRYTOKEN_EXPIRATION second maximum.
  if (t + verification_expiration * NGTCP2_SECONDS < now) {
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
    AsyncWrap::ProviderType type,
    const std::string& alpn) :
    AsyncWrap(socket->env(), wrap, type),
    rx_crypto_level_(NGTCP2_CRYPTO_LEVEL_INITIAL),
    tx_crypto_level_(NGTCP2_CRYPTO_LEVEL_INITIAL),
    closing_(false),
    destroyed_(false),
    initial_(true),
    connection_(nullptr),
    tls_alert_(0),
    max_pktlen_(0),
    idle_timer_(nullptr),
    socket_(socket),
    nkey_update_(0),
    hs_crypto_ctx_{},
    crypto_ctx_{},
    txbuf_(new QuicBuffer()),
    ncread_(0),
    state_(env()->isolate(), IDX_QUIC_SESSION_STATE_COUNT),
    monitor_scheduled_(false),
    allow_retransmit_(false),
    current_ngtcp2_memory_(0),
    max_cid_len_(NGTCP2_MAX_CIDLEN),
    min_cid_len_(NGTCP2_MIN_CIDLEN),
    alpn_(alpn),
    allocator_(this) {
  ssl_.reset(SSL_new(ctx->ctx_.get()));
  SSL_CTX_set_keylog_callback(ctx->ctx_.get(), OnKeylog);
  CHECK(ssl_);

  USE(wrap->DefineOwnProperty(
      env()->context(),
      env()->state_string(),
      state_.GetJSArray(),
      PropertyAttribute::ReadOnly));

  // TODO(@jasnell): memory accounting
  // env_->isolate()->AdjustAmountOfExternalAllocatedMemory(kExternalSize);
}

QuicSession::~QuicSession() {
  CHECK(destroyed_);
  ssl_.reset();
  ngtcp2_conn_del(connection_);
}

const std::string& QuicSession::GetALPN() {
  return alpn_;
}

void QuicSession::Keylog(const char* line) {
  if (LIKELY(state_[IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED] == 0))
    return;

  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  const size_t size = strlen(line);
  Local<Value> line_bf = Buffer::Copy(env(), line, 1 + size).ToLocalChecked();
  char* data = Buffer::Data(line_bf);
  data[size] = '\n';
  MakeCallback(env()->quic_on_session_keylog_function(), 1, &line_bf);
}

void QuicSession::AssociateCID(ngtcp2_cid* cid) {
  QuicCID id(cid);
  QuicCID scid(scid_);
  Socket()->AssociateCID(&id, &scid);
}

// Because of the fire-and-forget nature of UDP, the QuicSession must retain
// the data sent as packets until the recipient has acknowledged that data.
// This applies to TLS Handshake data as well as stream data. Once acknowledged,
// the buffered data can be released. This function is called only by the
// OnAckedCryptoOffset ngtcp2 callback function.
void QuicSession::AckedCryptoOffset(
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this,
        "Received acknowledgement for crypto data. Offset %llu, Length %d",
        offset, datalen);
  handshake_.Consume(datalen);
}

// Because of the fire-and-forget nature of UDP, the QuicSession must retain
// the data sent as packets until the recipient has acknowledged that data.
// This applies to TLS Handshake data as well as stream data. Once acknowledged,
// the buffered data can be released. This function is called only by the
// OnAckedStreamDataOffset ngtcp2 callback function.
void QuicSession::AckedStreamDataOffset(
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
}

// Add the given QuicStream to this QuicSession's collection of streams. All
// streams added must be removed before the QuicSession instance is freed.
void QuicSession::AddStream(QuicStream* stream) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
  Debug(this, "Adding stream %llu to session.", stream->GetID());
  streams_.emplace(stream->GetID(), stream);
}

void QuicSession::ExtendMaxStreamData(
    int64_t stream_id,
    uint64_t max_data) {
  // TODO(@jasnell): Extend max stream data
}

// Forwards detailed debugging information from ngtcp2.
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

// Destroy the QuicSession and free it. The QuicSession
// cannot be safely used after this is called.
void QuicSession::Destroy() {
  if (IsDestroyed())
    return;

  // Streams should have already been closed and destroyed by this point...
  CHECK(streams_.empty());

  Debug(this, "Destroying a %s QuicSession.", IsServer() ? "server" : "client");

  // The first step is to transmit a CONNECTION_CLOSE to the connected peer.
  // This is going to be fire-and-forget because we're not going to wait
  // around for it to be received.
  // TODO(@jasnell): Error code...
  SendConnectionClose(0);

  // Hold on to a reference until the function exits
  // so the instance is not prematurely deleted when
  // the session is removed from the socket.
  std::shared_ptr<QuicSession> ptr = shared_from_this();

  StopIdleTimer();
  StopRetransmitTimer();

  sendbuf_.Cancel();
  handshake_.Cancel();
  txbuf_->Cancel();

  // Removing from the socket will free the shared_ptr there
  // that is keeping this alive.
  RemoveFromSocket();
  socket_ = nullptr;
  destroyed_ = true;
  closing_ = false;

  // TODO(@jasnell): Memory accounting
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
QuicStream* QuicSession::FindStream(int64_t id) {
  auto it = streams_.find(id);
  if (it == std::end(streams_))
    return nullptr;
  return (*it).second;
}

// destroyed_ will only be set when the QuicSession::Destroy()
// method is called.
bool QuicSession::IsDestroyed() {
  return destroyed_;
}

// closing_ will only be set when the QuicSession::Closing()
// method is called.
bool QuicSession::IsClosing() {
  return closing_;
}

int QuicSession::PathValidation(
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res) {
  if (res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
    Debug(this,
          "Path validation succeeded. Updating local and remote addresses");
    SetLocalAddress(&path->local);
    remote_address_.Update(&path->remote);
  }

  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  Local<Value> argv[] = {
    Integer::New(env()->isolate(), res),
    AddressToJS(env(), reinterpret_cast<const sockaddr*>(path->local.addr)),
    AddressToJS(env(), reinterpret_cast<const sockaddr*>(path->remote.addr))
  };
  MakeCallback(
      env()->quic_on_session_path_validation_function(),
      arraysize(argv),
      argv);

  return 0;
}

// Setting the closing_ flag disables the ability to open or accept
// new streams for this Session. Existing streams are allowed to
// close gracefully on their own. Once called, the QuicSession will
// be destroyed once there are no remaining streams. Note that no
// notification is given to the connecting peer that we're in a
// closing state. A CONNECTION_CLOSE will be sent when the
// QuicSession is destroyed.
void QuicSession::Closing() {
  closing_ = true;
}

// Copies the local transport params into the given struct
// for serialization.
void QuicSession::GetLocalTransportParams(ngtcp2_transport_params* params) {
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

// Generates and associates a new connection ID for this QuicSession.
// ngtcp2 will call this multiple times at the start of a new connection
// in order to build a pool of available CIDs.
// TODO(@jasnell): It's possible that we could improve performance by
// generating a large pool of random data to use for CIDs when the
// session is created, then simply creating slices off that here.
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

// Returns the associated peer's address. Note that this
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

// This differs from IsClosing in that IsClosing indicates
// only that we've started a graceful shutdown of the QuicSession,
// while IsInClosingPeriod reflects the state of the underlying
// ngtcp2 connection.
bool QuicSession::IsInClosingPeriod() {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_is_in_closing_period(connection_);
}

bool QuicSession::IsInDrainingPeriod() {
  CHECK(!IsDestroyed());
  return ngtcp2_conn_is_in_draining_period(connection_);
}

void QuicSession::OnIdleTimeout(
    uv_timer_t* timer) {
  QuicSession* session = static_cast<QuicSession*>(timer->data);
  CHECK_NOT_NULL(session);
  session->OnIdleTimeout();
}

// Reads a chunk of received peer TLS handshake data for processing
size_t QuicSession::ReadPeerHandshake(uint8_t* buf, size_t buflen) {
  CHECK(!IsDestroyed());
  size_t n = std::min(buflen, peer_handshake_.size() - ncread_);
  std::copy_n(std::begin(peer_handshake_) + ncread_, n, buf);
  ncread_ += n;
  return n;
}

// The ReceiveClientInitial function is called by ngtcp2 when
// a new connection has been initiated. The very first step to
// establishing a communication channel is to setup the keys
// that will be used to secure the communication.
int QuicSession::ReceiveClientInitial(const ngtcp2_cid* dcid) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving client initial parameters.");

  CryptoInitialParams params;

  RETURN_IF_FAIL(
      DeriveInitialSecret(
          &params,
          dcid,
          reinterpret_cast<const uint8_t *>(NGTCP2_INITIAL_SALT),
          strsize(NGTCP2_INITIAL_SALT)), 0, -1);

  SetupTokenContext(&hs_crypto_ctx_);

  RETURN_IF_FAIL(SetupServerSecret(&params, &hs_crypto_ctx_), 0, -1);
  InstallKeys<ngtcp2_conn_install_initial_tx_keys>(connection_, params);

  RETURN_IF_FAIL(SetupClientSecret(&params, &hs_crypto_ctx_), 0, -1);
  InstallKeys<ngtcp2_conn_install_initial_rx_keys>(connection_, params);

  return 0;
}

// The HandshakeCompleted function is called by ngtcp2 once it
// determines that the TLS Handshake is done. The only thing we
// need to do at this point is let the javascript side know.
void QuicSession::HandshakeCompleted() {
  SetLocalCryptoLevel(NGTCP2_CRYPTO_LEVEL_APP);
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
  if (alpnlen == sizeof(NGTCP2_ALPN_H3) - 2 &&
      memcmp(alpn_buf, NGTCP2_ALPN_H3 + 1, sizeof(NGTCP2_ALPN_H3) - 2) == 0) {
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

  Local<Value> maxPacketLength = Integer::New(env()->isolate(), max_pktlen_);

  Local<Value> argv[] = {
    servername,
    alpn,
    cipher,
    version,
    maxPacketLength
  };

  MakeCallback(env()->quic_on_session_handshake_function(),
               arraysize(argv),
               argv);
}

// Serialize and send a chunk of TLS Handshake data to the peer.
// This is called multiple times until the internal buffer is cleared.
int QuicSession::DoHandshakeWriteOnce() {
  MallocedBuffer<uint8_t> data(max_pktlen_);
  ssize_t nwrite =
      ngtcp2_conn_write_handshake(
          connection_,
          data.data,
          max_pktlen_,
          uv_hrtime());
  if (nwrite <= 0)
    return 0;

  data.Realloc(nwrite);
  sendbuf_.Push(std::move(data));

  return SendPacket();
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
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Receiving %d bytes of crypto data.", datalen);
  int err = WritePeerHandshake(crypto_level, data, datalen);
  if (err != 0)
    return err;
  if (!IsHandshakeCompleted()) {
    err = TLSHandshake();
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
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);

  QuicStream* stream = FindStream(stream_id);
  if (stream == nullptr) {
    if (IsClosing()) {
      return ngtcp2_conn_shutdown_stream(
          connection_,
          stream_id,
          NGTCP2_ERR_CLOSING);
    }
    stream = CreateStream(stream_id);
  }
  CHECK_NOT_NULL(stream);
  stream->ReceiveData(fin, data, datalen);

  ngtcp2_conn_extend_max_stream_offset(connection_, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(connection_, datalen);

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

// Write any packets current pending for the ngtcp2 connection
int QuicSession::WritePackets() {
  QuicPathStorage path;
  for ( ;; ) {
    MallocedBuffer<uint8_t> data(max_pktlen_);
    ssize_t nwrite =
        ngtcp2_conn_write_pkt(
            connection_,
            &path.path,
            data.data,
            max_pktlen_,
            uv_hrtime());
    if (nwrite <= 0)
      return nwrite;
    data.Realloc(nwrite);
    remote_address_.Update(&path.path.remote);
    sendbuf_.Push(std::move(data));
    RETURN_RET_IF_FAIL(SendPacket(), 0);
  }
}

namespace {
void Consume(ngtcp2_vec** pvec, size_t* pcnt, size_t len) {
  ngtcp2_vec* v = *pvec;
  size_t cnt = *pcnt;

  for (; cnt > 0; --cnt, ++v) {
    if (v->len > len) {
      v->len -= len;
      v->base += len;
      break;
    }
    len -= v->len;
  }

  *pvec = v;
  *pcnt = cnt;
}

int Empty(const ngtcp2_vec* vec, size_t cnt) {
  size_t i;
  for (i = 0; i < cnt && vec[i].len == 0; ++i) {}
  return i == cnt;
}
}  // namespace

// Sends 0RTT stream data.
int QuicSession::Send0RTTStreamData(
    QuicStream* stream,
    QuicBuffer::drain_from from) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen = 0;

  std::vector<ngtcp2_vec> vec;
  size_t count = stream->DrainInto(&vec, from);
  size_t c = count;
  ngtcp2_vec* v = vec.data();

  for (;;) {
    MallocedBuffer<uint8_t> dest(max_pktlen_);
    ssize_t nwrite = ngtcp2_conn_client_write_handshake(
        connection_,
        dest.data,
        max_pktlen_,
        &ndatalen,
        stream->GetID(),
        stream->IsWritable() ? 0 : 1,
        reinterpret_cast<const ngtcp2_vec*>(v),
        c,
        uv_hrtime());

    if (nwrite < 0) {
      auto should_break = false;
      switch (nwrite) {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
        case NGTCP2_ERR_STREAM_SHUT_WR:
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          should_break = true;
          break;
      }
      if (should_break)
        break;
      return HandleError(nwrite);
    }

    if (nwrite == 0)
      return 0;

    if (ndatalen > 0)
      Consume(&v, &c, ndatalen);

    dest.Realloc(nwrite);
    sendbuf_.Push(std::move(dest));

    RETURN_RET_IF_FAIL(SendPacket(), 0);
    if (Empty(v, c))
      break;
  }

  // Advance the read head of the source buffer
  stream->Commit(count);

  return 0;
}

// Sends buffered stream data.
int QuicSession::SendStreamData(
    QuicStream* stream,
    QuicBuffer::drain_from from) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen = 0;
  QuicPathStorage path;

  std::vector<ngtcp2_vec> vec;
  size_t count = stream->DrainInto(&vec, from);

  size_t c = vec.size();
  ngtcp2_vec* v = vec.data();

  // Event if there's no data to write, we iterate through just in case
  // ngtcp2 has other frames that it needs to encode.
  for (;;) {
    MallocedBuffer<uint8_t> dest(max_pktlen_);
    ssize_t nwrite =
        ngtcp2_conn_writev_stream(
            connection_,
            &path.path,
            dest.data,
            max_pktlen_,
            &ndatalen,
            stream->GetID(),
            stream->IsWritable() ? 0 : 1,
            reinterpret_cast<const ngtcp2_vec*>(v),
            c,
            uv_hrtime());

    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
          nwrite == NGTCP2_ERR_EARLY_DATA_REJECTED ||
          nwrite == NGTCP2_ERR_STREAM_SHUT_WR ||
          nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
        break;
      }
      return HandleError(nwrite);
    }

    if (nwrite == 0)
      return 0;

    if (ndatalen > 0)
      Consume(&v, &c, ndatalen);

    dest.Realloc(nwrite);
    sendbuf_.Push(std::move(dest));
    remote_address_.Update(&path.path.remote);

    RETURN_RET_IF_FAIL(SendPacket(), 0);
    if (Empty(v, c))
      break;
  }

  // Advance the read head of the source buffer
  stream->Commit(count);

  return 0;
}

// Transmits the current contents of the internal sendbuf_ to the peer
// By default, SendPacket will drain from the txbuf_ read head. If
// retransmit is true, the entire contents of txbuf_ will be drained.
int QuicSession::SendPacket(bool retransmit) {
  CHECK(!IsDestroyed());
  // Move the contents of sendbuf_ to the tail of txbuf_ and reset sendbuf_
  if (sendbuf_.Length() > 0)
    *txbuf_ += std::move(sendbuf_);
  Debug(this, "There are %llu bytes in txbuf_ to send", txbuf_->Length());
  return Socket()->SendPacket(
      &remote_address_,
      txbuf_,
      retransmit ? QuicBuffer::DRAIN_FROM_ROOT : QuicBuffer::DRAIN_FROM_HEAD);
}

// Set the transport parameters received from the remote peer
int QuicSession::SetRemoteTransportParams(ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  StoreRemoteTransportParams(params);
  return ngtcp2_conn_set_remote_transport_params(connection_, params);
}

inline void QuicSession::ScheduleMonitor() {
  // If the monitor is already scheduled, do nothing
  if (monitor_scheduled_)
    return;
  Debug(this, "Scheduling retransmission monitor");
  monitor_scheduled_ = true;
  allow_retransmit_ = true;
  env()->quic_monitor()->Schedule(shared_from_this());
}

// Notifies the ngtcp2_conn that the TLS handshake is completed.
void QuicSession::SetHandshakeCompleted() {
  CHECK(!IsDestroyed());
  ngtcp2_conn_handshake_completed(connection_);
}

void QuicSession::SetLocalAddress(const ngtcp2_addr* addr) {
  ngtcp2_conn_set_local_addr(connection_, addr);
}

void QuicSession::SetTLSAlert(int err) {
  tls_alert_ = err;
}

// Creates a new stream object and passes it off to the javascript side.
QuicStream* QuicSession::CreateStream(int64_t stream_id) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
  Debug(this, "Stream %llu is new. Creating.", stream_id);
  QuicStream* stream = QuicStream::New(this, stream_id);
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
// TODO(@jasnell): Currently, this will cause the stream object to be
// created, but we might want to wait to create the stream object until
// we receive the first packet of data for the stream... doing so ensures
// that we are not committing resources until we actually need to.
int QuicSession::StreamOpen(int64_t stream_id) {
  CHECK(!IsDestroyed());
  if (IsClosing()) {
    return ngtcp2_conn_shutdown_stream(
        connection_,
        stream_id,
        NGTCP2_ERR_CLOSING);
  }
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

// Called by ngtcp2 when a stream has been reset. Resetting a streams
// allows it's state to be completely reset for the purposes of canceling
// transmission of stream data.
void QuicSession::StreamReset(
    int64_t stream_id,
    uint64_t final_size,
    uint16_t app_error_code) {
  CHECK(!IsDestroyed());
  QuicStream* stream = FindStream(stream_id);
  if (stream != nullptr)
    stream->Reset(final_size, app_error_code);
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
  CHECK(!IsClosing());
  int err = ngtcp2_conn_open_uni_stream(connection_, stream_id, nullptr);
  ngtcp2_conn_shutdown_stream_read(connection_, *stream_id, 0);
  return err;
}

int QuicSession::OpenBidirectionalStream(int64_t* stream_id) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
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

void QuicSession::StopRetransmitTimer() {
  allow_retransmit_ = false;
}

// Called by ngtcp2 when a stream has been closed. If the stream does
// not exist, the close is ignored.
void QuicSession::StreamClose(int64_t stream_id, uint16_t app_error_code) {
  // Ignore if the session has already been destroyed
  if (IsDestroyed())
    return;
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

  if (initial_)
    RETURN_RET_IF_FAIL(TLSHandshake_Initial(), 0);

  int err = DoTLSHandshake(ssl());
  if (err > 0) {
    RETURN_RET_IF_FAIL(TLSHandshake_Complete(), 0);
    Debug(this, "TLS Handshake completed.");
    SetHandshakeCompleted();
    err = 0;
  }
  return err;
}

// It's possible for TLS handshake to contain extra data that is not
// consumed by ngtcp2. That's ok and the data is just extraneous. We just
// read it and throw it away, unless there's an error.
int QuicServerSession::TLSRead() {
  CHECK(!IsDestroyed());
  ClearTLSError();
  return ClearTLS(ssl());
}

// Called by ngtcp2 when the QuicSession keys need to be updated. This may
// happen multiple times through the lifetime of the QuicSession.
int QuicSession::UpdateKey() {
  CHECK(!IsDestroyed());
  Debug(this, "Updating keys.");

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

  RETURN_IF_FAIL(
      ngtcp2_conn_update_tx_key(
          connection_,
          params.key.data(),
          params.keylen,
          params.iv.data(),
          params.ivlen), 0, -1);

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

  RETURN_IF_FAIL(
      ngtcp2_conn_update_rx_key(
          connection_,
          params.key.data(),
          params.keylen,
          params.iv.data(),
          params.ivlen), 0, -1);

  return 0;
}

// Writes peer handshake data to the internal buffer
int QuicSession::WritePeerHandshake(
    ngtcp2_crypto_level crypto_level,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  if (rx_crypto_level_ != crypto_level)
    return -1;
  Debug(this, "Writing %d bytes of peer handshake data.", datalen);
  std::copy_n(data, datalen, std::back_inserter(peer_handshake_));
  return 0;
}

void QuicSession::WriteHandshake(const uint8_t* data, size_t datalen) {
  CHECK(!IsDestroyed());
  Debug(this, "Writing %d bytes of handshake data.", datalen);
  MallocedBuffer<uint8_t> buffer(datalen);
  memcpy(buffer.data, data, datalen);
  CHECK_EQ(
      ngtcp2_conn_submit_crypto_data(
          connection_,
          tx_crypto_level_,
          buffer.data, datalen), 0);
  handshake_.Push(std::move(buffer));
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
    const ngtcp2_cid* rcid,
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version,
    const std::string& alpn) :
    QuicSession(
        socket,
        wrap,
        socket->GetServerSecureContext(),
        AsyncWrap::PROVIDER_QUICSERVERSESSION,
        alpn),
    pscid_{},
    rcid_(*rcid),
    draining_(false) {
  Init(addr, dcid, ocid, version);
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
  RETURN_RET_IF_FAIL(SendPacket(), 0);
  ssize_t nwrite;
  for (;;) {
    if ((nwrite = DoHandshakeWriteOnce()) <= 0)
      return nwrite;
  }
}

void QuicServerSession::AddToSocket(QuicSocket* socket) {
  QuicCID scid(scid_);
  QuicCID rcid(rcid_);
  socket->AddSession(&scid, shared_from_this());
  socket->AssociateCID(&rcid, &scid);

  if (pscid_.datalen) {
    QuicCID pscid(pscid_);
    socket->AssociateCID(&pscid, &scid);
  }
}

int QuicServerSession::HandleError(int error) {
  return SendConnectionClose(error);
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

  RETURN_IF_FAIL(SetupKeys(secret, secretlen, &params, &crypto_ctx_), 0, -1);

  ngtcp2_conn_set_aead_overhead(
      connection_,
      aead_tag_length(&crypto_ctx_));

  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_early_keys>(connection_, params);
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_rx_keys>(connection_, params);
      SetClientCryptoLevel(NGTCP2_CRYPTO_LEVEL_HANDSHAKE);
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_rx_keys>(connection_, params);
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_tx_keys>(connection_, params);
      SetServerCryptoLevel(NGTCP2_CRYPTO_LEVEL_HANDSHAKE);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_tx_keys>(connection_, params);
      SetServerCryptoLevel(NGTCP2_CRYPTO_LEVEL_APP);
    break;
  }

  return 0;
}

void QuicServerSession::InitTLS_Post() {
  SSL_set_accept_state(ssl());
}

void QuicServerSession::Init(
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version) {

  CHECK_NULL(connection_);

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS();

  ngtcp2_settings settings{};
  Socket()->SetServerSessionSettings(this->pscid(), &settings);

  EntropySource(scid_.data, NGTCP2_SV_SCIDLEN);
  scid_.datalen = NGTCP2_SV_SCIDLEN;

  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  CHECK_EQ(
      ngtcp2_conn_server_new(
          &connection_,
          dcid,
          &scid_,
          *path,
          version,
          &callbacks_,
          &settings,
          *allocator_,
          static_cast<QuicSession*>(this)), 0);

  if (ocid)
    ngtcp2_conn_set_retry_ocid(connection_, ocid);

  StartIdleTimer(settings.idle_timeout);
}

bool QuicServerSession::IsDraining() {
  return draining_;
}

std::shared_ptr<QuicSession> QuicServerSession::New(
    QuicSocket* socket,
    const ngtcp2_cid* rcid,
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version,
    const std::string& alpn) {
  std::shared_ptr<QuicSession> session;
  Local<Object> obj;
  if (!socket->env()
             ->quicserversession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return session;
  }
  session.reset(
      new QuicServerSession(
          socket,
          obj,
          rcid,
          addr,
          dcid,
          ocid,
          version,
          alpn));

  session->AddToSocket(socket);
  return session;
}

void QuicServerSession::OnIdleTimeout() {
  if (connection_ == nullptr)
    return;

  if (IsInClosingPeriod() || IsDraining())
    return Close();

  StartDrainingPeriod();
}

bool QuicServerSession::MaybeTimeout() {
  CHECK(monitor_scheduled_);
  uint64_t now = uv_hrtime();

  uint64_t expiry = static_cast<uint64_t>(ngtcp2_conn_get_expiry(connection_));
  if (expiry > now) return false;

  if (allow_retransmit_ &&
      ngtcp2_conn_loss_detection_expiry(connection_) <= now) {
    Debug(this, "Retransmitting due to loss detection");
    CHECK_EQ(ngtcp2_conn_on_loss_detection_timer(connection_, now), 0);
    SendPendingData(true);
  } else if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Transmitting due to ack delay");
    SendPendingData();
  }

  allow_retransmit_ = false;
  monitor_scheduled_ = false;
  return true;
}

int QuicServerSession::Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  CHECK(!IsDestroyed());

  SendScope scope(this);

  int err;

  // Closing period starts once ngtcp2 has detected that the session
  // is being shutdown locally. Note that this is different that the
  // IsClosing() function, which indicates a graceful shutdown that
  // allows the session and streams to finish naturally. When
  // IsInClosingPeriod is true, ngtcp2 is actively in the process
  // of shutting down the connection and a CONNECTION_CLOSE has
  // already been sent. The only thing we can do at this point is
  // either ignore the packet or send another CONNECTION_CLOSE.
  //
  // TODO(@jasnell): Currently, send a CONNECTION_CLOSE on every
  // packet received. To be a bit nicer, however, we could
  // use an exponential backoff.
  if (IsInClosingPeriod())
    return SendConnectionClose(0);

  // Draining period starts once we've detected an idle timeout on
  // this session and we're in the process of shutting down. We
  // don't want to accept any new packets during this time, so we
  // simply ignore them.
  if (IsDraining())
    return 0;

  // With QUIC, it is possible for the remote address to change
  // from one packet to the next.
  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  if (!IsHandshakeCompleted()) {
    err = DoHandshake(*path, data, nread);
    if (err != 0)
      SendConnectionClose(err);
    return 0;
  }

  err = ngtcp2_conn_read_pkt(
      connection_,
      *path,
      data, nread,
      uv_hrtime());
  if (err != 0) {
    if (err == NGTCP2_ERR_DRAINING) {
      StartDrainingPeriod();
      return -1;  // Closing
    }
    SendConnectionClose(err);
  }

  return 0;
}

// The QuicSocket maintains a map of std::shared_ptr's that keep
// the QuicSession instance alive. Once socket_->RemoveSession()
// is called, the QuicSession instance will be freed if there are
// no other references being held.
void QuicServerSession::RemoveFromSocket() {
  QuicCID rcid(rcid_);
  socket_->DisassociateCID(&rcid);

  if (pscid_.datalen > 0) {
    QuicCID pscid(pscid_);
    socket_->DisassociateCID(&pscid);
  }

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());

  for (const ngtcp2_cid& cid : cids) {
    QuicCID id(&cid);
    socket_->DisassociateCID(&id);
  }

  QuicCID scid(scid_);
  socket_->RemoveSession(&scid, **GetRemoteAddress());
}

// Transmits the CONNECTION_CLOSE to the peer, signaling
// the end of this QuicSession.
int QuicServerSession::SendConnectionClose(int error) {
  CHECK(!IsDestroyed());
  RETURN_IF_FAIL(StartClosingPeriod(error), 0, -1);
  StartIdleTimer(-1);
  CHECK_GT(conn_closebuf_.size, 0);
  sendbuf_.Cancel();
  // We don't use std::move here because we do not want
  // to reset conn_closebuf_.
  uv_buf_t buf =
      uv_buf_init(
          reinterpret_cast<char*>(conn_closebuf_.data),
          conn_closebuf_.size);
  sendbuf_.Push(&buf, 1);
  ScheduleMonitor();
  return SendPacket();
}

int QuicServerSession::SendPendingData(bool retransmit) {
  if (IsDestroyed())
    return 0;

  Debug(this, "Sending pending data for server session");
  int err;

  // If we're in the process of closing or draining the connection, do nothing.
  if (IsInClosingPeriod() || IsInDrainingPeriod())
    return 0;

  // If there's anything currently in the sendbuf_, send it.
  RETURN_RET_IF_FAIL(SendPacket(), 0);

  // If the handshake is not yet complete, perform the handshake
  if (!IsHandshakeCompleted()) {
    err = DoHandshake(nullptr, nullptr, 0);
    if (err == 0)
      ScheduleMonitor();
    return err;
  }

  // For every stream, transmit the stream data, returning
  // early if we're unable to send stream data for some
  // reason.
  for (auto stream : streams_) {
    RETURN_RET_IF_FAIL(
        SendStreamData(
            stream.second,
            retransmit ?
                QuicBuffer::DRAIN_FROM_ROOT : QuicBuffer::DRAIN_FROM_HEAD), 0);
  }

  err = WritePackets();
  if (err < 0)
    return HandleError(err);

  ScheduleMonitor();
  return 0;
}

int QuicServerSession::StartClosingPeriod(int error) {
  CHECK(!IsDestroyed());
  if (IsInClosingPeriod())
    return 0;

  Debug(this, "Closing period has started. Error %d", error);

  StopRetransmitTimer();
  StartIdleTimer(-1);

  sendbuf_.Cancel();

  uint16_t err_code;
  if (tls_alert_) {
    err_code = NGTCP2_CRYPTO_ERROR | tls_alert_;
  } else {
    err_code = ngtcp2_err_infer_quic_transport_error_code(error);
  }

  // Once the CONNECTION_CLOSE packet is written,
  // IsInClosingPeriod will return true.
  conn_closebuf_ = MallocedBuffer<uint8_t>(max_pktlen_);
  ssize_t nwrite =
      ngtcp2_conn_write_connection_close(
          connection_,
          nullptr,
          conn_closebuf_.data,
          max_pktlen_,
          err_code,
          uv_hrtime());
  if (nwrite < 0)
    return -1;
  conn_closebuf_.Realloc(nwrite);
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
  initial_ = false;
  return DoTLSReadEarlyData(ssl());
}

int QuicServerSession::TLSHandshake_Complete() {
  return 0;
}

ngtcp2_cid* QuicServerSession::pscid() {
  return &pscid_;
}

const ngtcp2_cid* QuicServerSession::rcid() const {
  return &rcid_;
}


ngtcp2_crypto_level QuicServerSession::GetServerCryptoLevel() {
  return tx_crypto_level_;
}

ngtcp2_crypto_level QuicServerSession::GetClientCryptoLevel() {
  return rx_crypto_level_;
}

void QuicServerSession::SetServerCryptoLevel(ngtcp2_crypto_level level) {
  tx_crypto_level_ = level;
}

void QuicServerSession::SetClientCryptoLevel(ngtcp2_crypto_level level) {
  rx_crypto_level_ = level;
}

ngtcp2_crypto_level QuicClientSession::GetServerCryptoLevel() {
  return rx_crypto_level_;
}

ngtcp2_crypto_level QuicClientSession::GetClientCryptoLevel() {
  return tx_crypto_level_;
}

void QuicClientSession::SetServerCryptoLevel(ngtcp2_crypto_level level) {
  rx_crypto_level_ = level;
}

void QuicClientSession::SetClientCryptoLevel(ngtcp2_crypto_level level) {
  tx_crypto_level_ = level;
}

void QuicServerSession::SetLocalCryptoLevel(ngtcp2_crypto_level level) {
  SetServerCryptoLevel(level);
}

void QuicClientSession::SetLocalCryptoLevel(ngtcp2_crypto_level level) {
  SetClientCryptoLevel(level);
}

// The QuicClientSession class provides a specialization of QuicSession that
// implements client-specific behaviors. Most of the client-specific stuff is
// limited to TLS and early data
std::shared_ptr<QuicSession> QuicClientSession::New(
    QuicSocket* socket,
    const struct sockaddr* addr,
    uint32_t version,
    SecureContext* context,
    const char* hostname,
    uint32_t port,
    Local<Value> early_transport_params,
    Local<Value> session_ticket,
    Local<Value> dcid,
    int select_preferred_address_policy,
    const std::string& alpn) {
  std::shared_ptr<QuicSession> session;
  Local<Object> obj;
  if (!socket->env()
             ->quicclientsession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return session;
  }

  session =
      std::make_shared<QuicClientSession>(
          socket,
          obj,
          addr,
          version,
          context,
          hostname,
          port,
          early_transport_params,
          session_ticket,
          dcid,
          select_preferred_address_policy,
          alpn);

  session->AddToSocket(socket);
  session->Start();

  return session;
}

QuicClientSession::QuicClientSession(
    QuicSocket* socket,
    v8::Local<v8::Object> wrap,
    const struct sockaddr* addr,
    uint32_t version,
    SecureContext* context,
    const char* hostname,
    uint32_t port,
    Local<Value> early_transport_params,
    Local<Value> session_ticket,
    Local<Value> dcid,
    int select_preferred_address_policy,
    const std::string& alpn) :
    QuicSession(
        socket,
        wrap,
        context,
        AsyncWrap::PROVIDER_QUICCLIENTSESSION,
        alpn),
    resumption_(false),
    hostname_(hostname),
    select_preferred_address_policy_(select_preferred_address_policy) {
  Init(addr, version, early_transport_params, session_ticket, dcid);
}

int QuicClientSession::Init(
    const struct sockaddr* addr,
    uint32_t version,
    Local<Value> early_transport_params,
    Local<Value> session_ticket,
    Local<Value> dcid_value) {

  CHECK_NULL(connection_);

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS();

  ngtcp2_settings settings{};
  QuicSessionConfig client_session_config;
  client_session_config.Set(env());
  client_session_config.ToSettings(&settings, nullptr);
  max_cid_len_ = client_session_config.GetMaxCidLen();
  min_cid_len_ = client_session_config.GetMinCidLen();

  scid_.datalen = max_cid_len_;
  EntropySource(scid_.data, scid_.datalen);

  ngtcp2_cid dcid;
  if (dcid_value->IsArrayBufferView()) {
    ArrayBufferViewContents<uint8_t> sbuf(
        dcid_value.As<ArrayBufferView>());
    CHECK_LE(sbuf.length(), max_cid_len_);
    CHECK_GE(sbuf.length(), min_cid_len_);
    memcpy(dcid.data, sbuf.data(), sbuf.length());
    dcid.datalen = sbuf.length();
  } else {
    dcid.datalen = max_cid_len_;
    EntropySource(dcid.data, dcid.datalen);
  }

  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  RETURN_RET_IF_FAIL(
      ngtcp2_conn_client_new(
          &connection_,
          &dcid,
          &scid_,
          *path,
          version,
          &callbacks_,
          &settings,
          *allocator_,
          static_cast<QuicSession*>(this)), 0);

  RETURN_RET_IF_FAIL(SetupInitialCryptoContext(), 0);

  // Remote Transport Params
  if (early_transport_params->IsArrayBufferView())
    RETURN_RET_IF_FAIL(SetEarlyTransportParams(early_transport_params), 0);

  // Session Ticket
  if (session_ticket->IsArrayBufferView())
    RETURN_RET_IF_FAIL(SetSession(session_ticket), 0);

  StartIdleTimer(settings.idle_timeout);
  return 0;
}

int QuicClientSession::SelectPreferredAddress(
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr) {
  switch (select_preferred_address_policy_) {
    case QUIC_PREFERRED_ADDRESS_ACCEPT: {
      SocketAddress* local_address = Socket()->GetLocalAddress();
      uv_getaddrinfo_t req;

      RETURN_IF_FAIL(
          SocketAddress::ResolvePreferredAddress(
              env(),
              local_address->GetFamily(),
              paddr,
              &req), 0, -1);

      if (req.addrinfo == nullptr)
        return -1;

      dest->addrlen = req.addrinfo->ai_addrlen;
      memcpy(dest->addr, req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);
      uv_freeaddrinfo(req.addrinfo);
      break;
    }
    case QUIC_PREFERRED_ADDRESS_IGNORE:
      // Fall-through
      break;
  }
  return 0;
}

int QuicClientSession::Start() {
  for (auto stream : streams_)
    RETURN_RET_IF_FAIL(Send0RTTStreamData(stream.second), 0);
  return DoHandshakeWriteOnce();
}

void QuicClientSession::AddToSocket(QuicSocket* socket) {
  QuicCID scid(scid_);
  socket->AddSession(&scid, shared_from_this());

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());
  for (const ngtcp2_cid& cid : cids) {
    QuicCID id(&cid);
    socket->AssociateCID(&id, &scid);
  }
}

int QuicClientSession::SetSocket(
    QuicSocket* socket,
    bool nat_rebinding) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
  if (socket == nullptr || socket == socket_)
    return 0;

  // Step 1: Add this Session to the given Socket
  AddToSocket(socket);

  // Step 2: Remove this Session from the current Socket
  RemoveFromSocket();

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
       0, -1);
  }

  return SendPendingData();
}

void QuicClientSession::StoreRemoteTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  transportParams_.AllocateSufficientStorage(sizeof(ngtcp2_transport_params));
  memcpy(*transportParams_, params, sizeof(ngtcp2_transport_params));
}

int QuicClientSession::SetSession(SSL_SESSION* session) {
  CHECK(!IsDestroyed());
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

  const uint8_t* alpn = reinterpret_cast<const uint8_t*>(GetALPN().c_str());
  size_t alpnlen = GetALPN().length();
  SSL_set_alpn_protos(ssl(), alpn, alpnlen);

  // If the hostname is an IP address and we have no additional
  // information, use localhost.
  if (SocketAddress::numeric_host(hostname_)) {
    SSL_set_tlsext_host_name(ssl(), "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl(), hostname_);
  }
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

  RETURN_IF_FAIL(SetupKeys(secret, secretlen, &params, &crypto_ctx_), 0, -1);

  ngtcp2_conn_set_aead_overhead(
      connection_,
      aead_tag_length(&crypto_ctx_));

  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_early_keys>(connection_, params);
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_tx_keys>(connection_, params);
      SetClientCryptoLevel(NGTCP2_CRYPTO_LEVEL_HANDSHAKE);
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_tx_keys>(connection_, params);
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_handshake_rx_keys>(connection_, params);
      SetServerCryptoLevel(NGTCP2_CRYPTO_LEVEL_HANDSHAKE);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      InstallKeys<ngtcp2_conn_install_rx_keys>(connection_, params);
      SetServerCryptoLevel(NGTCP2_CRYPTO_LEVEL_APP);
    break;
  }

  return 0;
}

int QuicClientSession::TLSRead() {
  CHECK(!IsDestroyed());
  ClearTLSError();
  return ClearTLS(ssl(), true);
}

int QuicClientSession::DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {

  CHECK(!IsDestroyed());

  RETURN_RET_IF_FAIL(SendPacket(), 0);

  int err = DoHandshakeReadOnce(path, data, datalen);
  if (err != 0) {
    Close();
    return -1;
  }

  // Zero Round Trip
  for (auto stream : streams_)
    RETURN_RET_IF_FAIL(Send0RTTStreamData(stream.second), 0);

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

  sendbuf_.Cancel();

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
  StartIdleTimer(-1);
  MallocedBuffer<uint8_t> data(max_pktlen_);
  sendbuf_.Cancel();
  ssize_t nwrite =
      ngtcp2_conn_write_connection_close(
        connection_,
        nullptr,
        data.data,
        max_pktlen_,
        error,
        uv_hrtime());
  if (nwrite < 0) {
    Debug(this, "Error writing connection close: %d", nwrite);
    return -1;
  }
  data.Realloc(nwrite);
  sendbuf_.Push(std::move(data));
  ScheduleMonitor();
  return SendPacket();
}

void QuicClientSession::OnIdleTimeout() {
  if (connection_ == nullptr)
    return;
  Debug(this, "Idle timeout");
  Close();
}

bool QuicClientSession::MaybeTimeout() {
  CHECK(monitor_scheduled_);
  int err;
  uint64_t now = uv_hrtime();

  uint64_t expiry =
    static_cast<uint64_t>(ngtcp2_conn_get_expiry(connection_));
  if (expiry > now)
    return false;

  if (ngtcp2_conn_loss_detection_expiry(connection_) <= now) {
    CHECK_EQ(ngtcp2_conn_on_loss_detection_timer(connection_, now), 0);
    Debug(this, "Retransmitting due to loss detection");
    err = SendPendingData(true);
    if (err != 0)
      HandleError(err);
  } else if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Transmitting due to ack delay");
    err = SendPendingData();
    if (err != 0)
      HandleError(err);
  }
  allow_retransmit_ = false;
  monitor_scheduled_ = false;
  return true;
}

int QuicClientSession::Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  CHECK(!IsDestroyed());

  SendScope scope(this);

  // It's possible for the remote address to change from one
  // packet to the next
  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  if (!IsHandshakeCompleted())
    return DoHandshake(*path, data, nread);

  int err = ngtcp2_conn_read_pkt(
      connection_,
      *path,
      data, nread,
      uv_hrtime());
  if (err != 0) {
    Close();
    return err;
  }

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

void QuicClientSession::RemoveFromSocket() {
  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection_));
  ngtcp2_conn_get_scid(connection_, cids.data());

  for (auto &cid : cids) {
    QuicCID id(&cid);
    socket_->DisassociateCID(&id);
  }

  Debug(this, "Remove this QuicClientSession from the QuicSocket.");
  QuicCID scid(scid_);
  socket_->RemoveSession(&scid, **GetRemoteAddress());
}

int QuicClientSession::SendPendingData(bool retransmit) {
  if (IsDestroyed())
    return 0;
  Debug(this, "Sending pending data for client session");

  // First, send any data currently sitting in the sendbuf_ buffer
  RETURN_RET_IF_FAIL(SendPacket(), 0);

  int err;
  // If we're retransmitting, reset the loss detection timer
  if (retransmit) {
    err = ngtcp2_conn_on_loss_detection_timer(connection_, uv_hrtime());
    if (err != 0) {
      Debug(this, "Error resetting loss detection timer. Error %d", err);
      // TODO(@jasnell): Close with error code
      Close();
      return -1;
    }
  }

  // If the TLS handshake is not yet complete, do that and return.
  if (!IsHandshakeCompleted()) {
    Debug(this, "Handshake is not completed");
    err = DoHandshake(nullptr, nullptr, 0);
    ScheduleMonitor();
    return err;
  }

  err = WritePackets();
  if (err < 0)
    return HandleError(err);

  if (!retransmit) {
    // For each stream, send any pending data
    for (auto stream : streams_)
      RETURN_RET_IF_FAIL(SendStreamData(stream.second), 0);
  }

  ScheduleMonitor();
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
          strsize(NGTCP2_INITIAL_SALT)), 0, -1);

  RETURN_IF_FAIL(SetupClientSecret(&params, &hs_crypto_ctx_), 0, -1);
  InstallKeys<ngtcp2_conn_install_initial_tx_keys>(connection_, params);

  RETURN_IF_FAIL(SetupServerSecret(&params, &hs_crypto_ctx_), 0, -1);
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
  if (s == nullptr || SSL_set_session(ssl_.get(), s.get()) != 1)
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

// Closing the QuicSession flips a flag that prevents new local streams
// from being opened and new remote streams from being received. It is
// important to note that this does *NOT* send a CONNECTION_CLOSE packet
// to the peer. Existing streams are permitted to close gracefully.
void QuicSessionClose(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Closing();
}

// Destroying the QuicSession will trigger sending of a CONNECTION_CLOSE
// packet, after which the QuicSession will be immediately torn down.
void QuicSessionDestroy(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  int error_code = 0;
  USE(args[0]->Int32Value(env->context()).To(&error_code));
  // Use the error code
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
    result =
        crypto::X509ToObject(
            env,
            cert ? cert.get() : sk_X509_value(ssl_certs, 0));
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

  // Secure Context
  CHECK(args[5]->IsObject());
  SecureContext* sc;
  ASSIGN_OR_RETURN_UNWRAP(&sc, args[5].As<Object>());

  // SNI Servername
  node::Utf8Value servername(args.GetIsolate(), args[6]);

  sockaddr_storage addr;
  int err = SocketAddress::ToSockAddr(family, *address, port, &addr);
  if (err != 0)
    return args.GetReturnValue().Set(err);

  int select_preferred_address_policy = QUIC_PREFERRED_ADDRESS_IGNORE;
  USE(args[10]->Int32Value(
    env->context()).To(&select_preferred_address_policy));

  std::string alpn(NGTCP2_ALPN_H3);
  if (args[11]->IsString()) {
    Utf8Value val(env->isolate(), args[11]);
    alpn = val.length();
    alpn += *val;
  }

  socket->ReceiveStart();

  std::shared_ptr<QuicSession> session =
      QuicClientSession::New(
          socket,
          const_cast<const sockaddr*>(reinterpret_cast<sockaddr*>(&addr)),
          NGTCP2_PROTO_VER, sc,
          *servername,
          port,
          args[7],
          args[8],
          args[9],
          select_preferred_address_policy,
          alpn);

  session->SendPendingData();

  args.GetReturnValue().Set(session->object());
}

// Add methods that are shared by both QuicServerSession and
// QuicClientSession
void AddMethods(Environment* env, Local<FunctionTemplate> session) {
  env->SetProtoMethod(session, "close", QuicSessionClose);
  env->SetProtoMethod(session, "destroy", QuicSessionDestroy);
  env->SetProtoMethod(session, "getCertificate", QuicSessionGetCertificate);
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
