#ifndef SRC_NODE_QUIC_SESSION_H_
#define SRC_NODE_QUIC_SESSION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_buffer.h"
#include "async_wrap.h"
#include "env.h"
#include "handle_wrap.h"
#include "node.h"
#include "node_crypto.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

#include <deque>
#include <map>
#include <string>
#include <vector>

namespace node {
namespace quic {

class QuicServerSession;
class QuicSocket;
class QuicStream;

constexpr int ERR_INVALID_REMOTE_TRANSPORT_PARAMS = -1;
constexpr int ERR_INVALID_TLS_SESSION_TICKET = -2;

#define QUICSESSION_CONFIG(V)                                                 \
  V(MAX_STREAM_DATA_BIDI_LOCAL, max_stream_data_bidi_local, 256_k)            \
  V(MAX_STREAM_DATA_BIDI_REMOTE, max_stream_data_bidi_remote, 256_k)          \
  V(MAX_STREAM_DATA_UNI, max_stream_data_uni, 256_k)                          \
  V(MAX_DATA, max_data, 1_m)                                                  \
  V(MAX_STREAMS_BIDI, max_streams_bidi, 100)                                  \
  V(MAX_STREAMS_UNI, max_streams_uni, 3)                                      \
  V(IDLE_TIMEOUT, idle_timeout, 10 * 1000)                                    \
  V(MAX_PACKET_SIZE, max_packet_size, NGTCP2_MAX_PKT_SIZE)

#define V(idx, name, def)                                                     \
  constexpr uint64_t IDX_QUIC_SESSION_## idx ##_DEFAULT = def;
  QUICSESSION_CONFIG(V)
#undef V

class QuicSessionConfig {
 public:
  QuicSessionConfig() {}

  void ResetToDefaults();
  void Set(Environment* env);
  void ToSettings(ngtcp2_settings* settings,
                  bool stateless_reset_token = false);

 private:
#define V(idx, name, def) uint64_t name##_ = def;
  QUICSESSION_CONFIG(V)
#undef V
};

enum QuicSessionState {
  IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT,
  IDX_QUIC_SESSION_STATE_COUNT
};

class QuicSession : public AsyncWrap {
 public:
  static const int kInitialClientBufferLength = 4096;

  QuicSession(QuicSocket* socket,
              v8::Local<v8::Object> wrap,
              crypto::SecureContext* ctx,
              AsyncWrap::ProviderType provider);
  virtual ~QuicSession();

  void AckedCryptoOffset(
    uint64_t offset,
    size_t datalen);
  int AckedStreamDataOffset(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen);
  void AddStream(
    QuicStream* stream);
  void AssociateCID(
    ngtcp2_cid* cid);
  void Close();
  void Destroy();
  QuicStream* FindStream(
    int64_t id);
  void GetLocalTransportParams(
    ngtcp2_transport_params* params);
  uint32_t GetNegotiatedVersion();
  SocketAddress* GetRemoteAddress();
  void HandshakeCompleted();
  void InitTLS();
  bool IsDestroyed();
  bool IsHandshakeCompleted();
  int OpenBidirectionalStream(int64_t* stream_id);
  int OpenUnidirectionalStream(int64_t* stream_id);
  size_t ReadHandshake(
    const uint8_t** pdest);
  size_t ReadPeerHandshake(
    uint8_t* buf,
    size_t buflen);
  int ReceiveStreamData(
    int64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen);
  void RemoveStream(
    int64_t stream_id);
  void ScheduleRetransmit();
  int Send0RTTStreamData(
      QuicStream* stream,
      int fin,
      QuicBuffer* data);
  int SendStreamData(
      QuicStream* stream,
      int fin,
      QuicBuffer* data);
  int SetRemoteTransportParams(
    ngtcp2_transport_params* params);
  void SetTLSAlert(
    int err);
  int ShutdownStreamRead(
    int64_t stream_id,
    uint16_t code = NGTCP2_APP_NOERROR);
  int ShutdownStreamWrite(
    int64_t stream_id,
    uint16_t code = NGTCP2_APP_NOERROR);
  QuicSocket* Socket();
  SSL* ssl() { return ssl_.get(); }
  void StartIdleTimer(
    uint64_t idle_timeout);
  void StopIdleTimer();
  void StopRetransmitTimer();
  int StreamOpen(
    int64_t stream_id);
  int TLSHandshake();
  void WritePeerHandshake(
    const uint8_t* data,
    size_t datalen);
  void WriteHandshake(
    const uint8_t* data,
    size_t datalen);

  const ngtcp2_cid* scid() const;

  // These may be implemented by QuicSession types
  virtual void Cleanup() {}
  virtual void DisassociateCID(
    const ngtcp2_cid* cid) {}
  virtual int ExtendMaxStreamsUni(
    uint64_t max_streams) { return 0; }
  virtual int ExtendMaxStreamsBidi(
    uint64_t max_streams) { return 0; }
  virtual bool IsServer() const { return false; }
  virtual int ReceiveRetry() { return 0; }
  virtual void StoreRemoteTransportParams(ngtcp2_transport_params* params) {}

  // These must be implemented by QuicSession types
  virtual int DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) = 0;
  virtual int HandleError(int code) = 0;
  virtual void InitTLS_Post() = 0;
  virtual void OnIdleTimeout() = 0;
  virtual int OnKey(
    int name,
    const uint8_t* secret,
    size_t secretlen) = 0;
  virtual void OnRetransmitTimeout() = 0;
  virtual int Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) = 0;
  virtual void Remove() = 0;
  virtual int SendConnectionClose(int error) = 0;
  virtual int SendPendingData(
    bool retransmit = false) = 0;
  virtual int TLSHandshake_Complete() = 0;
  virtual int TLSHandshake_Initial() = 0;
  virtual int TLSRead() = 0;

  static void SetupTokenContext(CryptoContext* context);
  static int GenerateToken(
    uint8_t* token,
    size_t* tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    CryptoContext* context,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret);
  static int VerifyToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    CryptoContext* context,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret);

  static void DebugLog(void* user_data, const char* fmt, ...);

 protected:
  int DoHandshakeReadOnce(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen);
  int DoHandshakeWriteOnce();
  inline bool IsInClosingPeriod();
  inline int SendPacket();
  inline void SetHandshakeCompleted();

 private:
  // ngtcp2 callbacks
  static int OnClientInitial(
    ngtcp2_conn* conn,
    void* user_data);
  static int OnReceiveClientInitial(
    ngtcp2_conn* conn,
    const ngtcp2_cid* dcid,
    void* user_data);
  static int OnReceiveCryptoData(
    ngtcp2_conn* conn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data);
  static int OnHandshakeCompleted(
    ngtcp2_conn* conn,
    void* user_data);
  static ssize_t OnDoHSEncrypt(
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
    void* user_data);
  static ssize_t OnDoHSDecrypt(
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
    void* user_data);
  static ssize_t OnDoEncrypt(
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
    void* user_data);
  static ssize_t OnDoDecrypt(
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
    void* user_data);
  static ssize_t OnDoInHPMask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data);
  static ssize_t OnDoHPMask(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen,
    void* user_data);
  static int OnReceiveStreamData(
    ngtcp2_conn* conn,
    int64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data);
  static int OnReceiveRetry(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_hd* hd,
    const ngtcp2_pkt_retry* retry,
    void* user_data);
  static int OnAckedCryptoOffset(
    ngtcp2_conn* conn,
    uint64_t offset,
    size_t datalen,
    void* user_data);
  static int OnAckedStreamDataOffset(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t offset,
    size_t datalen,
    void* user_data,
    void* stream_user_data);
  static int OnStreamClose(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data);
  static int OnStreamOpen(
    ngtcp2_conn* conn,
    int64_t stream_id,
    void* user_data);
  static int OnStreamReset(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t final_size,
    uint16_t app_error_code,
    void* user_data,
    void* stream_user_data);
  static int OnRand(
    ngtcp2_conn* conn,
    uint8_t* dest,
    size_t destlen,
    ngtcp2_rand_ctx ctx,
    void* user_data);
  static int OnGetNewConnectionID(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data);
  static int OnRemoveConnectionID(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data);
  static int OnUpdateKey(
    ngtcp2_conn* conn,
    void* user_data);
  static int OnPathValidation(
    ngtcp2_conn* conn,
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res,
    void* user_data);
  static void OnIdleTimeout(
    uv_timer_t* timer);
  static void OnRetransmitTimeout(
    uv_timer_t* timer);
  static int OnExtendMaxStreamsUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data);
  static int OnExtendMaxStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data);
  static int OnExtendMaxRemoteStreamsUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data);
  static int OnExtendMaxRemoteStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data);

  int ReceiveClientInitial(
    const ngtcp2_cid* dcid);
  int ReceiveCryptoData(
    uint64_t offset,
    const uint8_t* data,
    size_t datalen);
  ssize_t DoHSEncrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen);
  ssize_t DoHSDecrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen);
  ssize_t DoEncrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* plaintext,
    size_t plaintextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen);
  ssize_t DoDecrypt(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* ciphertext,
    size_t ciphertextlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* nonce,
    size_t noncelen,
    const uint8_t* ad,
    size_t adlen);
  ssize_t DoInHPMask(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen);
  ssize_t DoHPMask(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen);
  void StreamClose(
    int64_t stream_id,
    uint16_t app_error_code);
  void StreamReset(
    int64_t stream_id,
    uint64_t final_size,
    uint16_t app_error_code);
  int UpdateKey();
  void RemoveConnectionID(
    const ngtcp2_cid* cid);
  inline int GetNewConnectionID(
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen);

  inline QuicStream* CreateStream(int64_t stream_id);
  void WriteHandshake(std::deque<QuicBuffer>* dest,
                      size_t* idx,
                      const uint8_t* data,
                      size_t datalen);

  void SetLocalAddress(const ngtcp2_addr* addr);

  bool initial_;
  crypto::SSLPointer ssl_;
  ngtcp2_conn* connection_;
  SocketAddress remote_address_;
  uint8_t tls_alert_;
  size_t max_pktlen_;
  uv_timer_t* idle_timer_;
  uv_timer_t* retransmit_timer_;
  QuicSocket* socket_;
  size_t nkey_update_;
  CryptoContext hs_crypto_ctx_;
  CryptoContext crypto_ctx_;
  std::vector<uint8_t> tx_secret_;
  std::vector<uint8_t> rx_secret_;
  ngtcp2_cid scid_;

  QuicBuffer sendbuf_;
  std::vector<uint8_t> peer_handshake_;
  std::deque<QuicBuffer> handshake_;
  size_t handshake_idx_;
  size_t ncread_;
  uint64_t tx_crypto_offset_;

  std::map<int64_t, QuicStream*> streams_;

  AliasedFloat64Array state_;

  friend class QuicServerSession;
  friend class QuicClientSession;
};

class QuicServerSession : public QuicSession {
 public:
  static void Initialize(Environment* env,
                         v8::Local<v8::Object> target,
                         v8::Local<v8::Context> context);

  static QuicServerSession* New(
    QuicSocket* socket,
    const ngtcp2_cid* rcid);

  virtual void Cleanup() override;

  virtual void DisassociateCID(
    const ngtcp2_cid* cid) override;

  virtual int DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) override;

  virtual int HandleError(
    int code) override;

  virtual bool IsServer() const override { return true; }

  virtual int OnKey(
    int name,
    const uint8_t* secret,
    size_t secretlen) override;

  virtual void InitTLS_Post() override;

  virtual int TLSRead() override;

  int Init(
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version);

  bool IsDraining();
  virtual void OnIdleTimeout() override;
  virtual void OnRetransmitTimeout() override;
  virtual int Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) override;
  virtual void Remove() override;
  virtual int SendConnectionClose(int error) override;
  virtual int SendPendingData(bool retransmit = false) override;
  virtual int TLSHandshake_Complete() override;
  virtual int TLSHandshake_Initial() override;

  const ngtcp2_cid* rcid() const;
  const ngtcp2_cid* pscid() const;

  void MemoryInfo(MemoryTracker* tracker) const override {}
  SET_MEMORY_INFO_NAME(QuicServerSession)
  SET_SELF_SIZE(QuicServerSession)

 private:
  QuicServerSession(
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      const ngtcp2_cid* rcid);

  int StartClosingPeriod(int error);
  void StartDrainingPeriod();

  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  std::vector<uint8_t> chandshake_;
  bool draining_;
  std::unique_ptr<QuicBuffer> conn_closebuf_;

  const ngtcp2_conn_callbacks callbacks_ = {
    nullptr,
    OnReceiveClientInitial,
    OnReceiveCryptoData,
    OnHandshakeCompleted,
    nullptr,  // recv_version_negotiation
    OnDoHSEncrypt,
    OnDoHSDecrypt,
    OnDoEncrypt,
    OnDoDecrypt,
    OnDoInHPMask,
    OnDoHPMask,
    OnReceiveStreamData,
    OnAckedCryptoOffset,
    OnAckedStreamDataOffset,
    OnStreamOpen,
    OnStreamClose,
    nullptr,  // recv_stateless_reset
    nullptr,  // recv_retry
    nullptr,  // extend_max_streams_bidi
    nullptr,  // extend_max_streams_uni
    OnRand,
    OnGetNewConnectionID,
    OnRemoveConnectionID,
    OnUpdateKey,
    OnPathValidation,
    nullptr,  // select_preferred_addr
    OnStreamReset,
    OnExtendMaxStreamsBidi,
    OnExtendMaxStreamsUni,
    //  nullptr  // extend_max_stream_data
  };
};

class QuicClientSession : public QuicSession {
 public:
  static void Initialize(Environment* env,
                         v8::Local<v8::Object> target,
                         v8::Local<v8::Context> context);

  static QuicClientSession* New(
    QuicSocket* socket,
    const struct sockaddr* addr,
    uint32_t version,
    crypto::SecureContext* context,
    const char* hostname,
    uint32_t port);

  QuicClientSession(
    QuicSocket* socket,
    v8::Local<v8::Object> wrap,
    const struct sockaddr* addr,
    uint32_t version,
    crypto::SecureContext* context,
    const char* hostname,
    uint32_t port);

  virtual int DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) override;

  virtual int HandleError(
    int code) override;

  virtual int OnKey(
    int name,
    const uint8_t* secret,
    size_t secretlen) override;

  int SetSocket(QuicSocket* socket, bool nat_rebinding = false);

  virtual void StoreRemoteTransportParams(
    ngtcp2_transport_params* params) override;

  virtual int TLSRead() override;

  int Init(
    const struct sockaddr* addr,
    uint32_t version);

  virtual void InitTLS_Post() override;

  virtual int ExtendMaxStreamsUni(
    uint64_t max_streams) override;
  virtual int ExtendMaxStreamsBidi(
    uint64_t max_streams) override;

  virtual void OnIdleTimeout() override;
  virtual void OnRetransmitTimeout() override;
  virtual int Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) override;
  virtual int ReceiveRetry() override;
  virtual void Remove() override;
  virtual int SendConnectionClose(int error) override;
  virtual int SendPendingData(bool retransmit = false) override;
  virtual int TLSHandshake_Complete() override;
  virtual int TLSHandshake_Initial() override;

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicClientSession)
  SET_SELF_SIZE(QuicClientSession)

  int SetSession(SSL_SESSION* session);
  v8::MaybeLocal<v8::Object> GetRemoteTransportParamsBuffer();
  v8::MaybeLocal<v8::Object> GetSessionTicketBuffer();
  int SetEarlyTransportParams(v8::Local<v8::Value> buffer);
  int SetSession(v8::Local<v8::Value> buffer);

 private:
  int ExtendMaxStreams(
    bool bidi,
    uint64_t max_streams);

  int SetupInitialCryptoContext();

  bool resumption_;
  const char* hostname_;
  uint32_t port_;

  MaybeStackBuffer<char> transportParams_;

  const ngtcp2_conn_callbacks callbacks_ = {
      OnClientInitial,
      nullptr,
      OnReceiveCryptoData,
      OnHandshakeCompleted,
      nullptr,
      OnDoHSEncrypt,
      OnDoHSDecrypt,
      OnDoEncrypt,
      OnDoDecrypt,
      OnDoInHPMask,
      OnDoHPMask,
      OnReceiveStreamData,
      OnAckedCryptoOffset,
      OnAckedStreamDataOffset,
      OnStreamOpen,
      OnStreamClose,
      nullptr,
      OnReceiveRetry,
      OnExtendMaxStreamsBidi,
      OnExtendMaxStreamsUni,
      OnRand,
      OnGetNewConnectionID,
      OnRemoveConnectionID,
      OnUpdateKey,
      OnPathValidation,
      nullptr,  // select_preferred_addr;
      nullptr,  // stream_reset;
      nullptr,  // extend_max_remote_streams_bidi;
      nullptr   // extend_max_remote_streams_uni;
  };
};

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

}  // namespace

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_SESSION_H_
