#ifndef SRC_NODE_QUIC_SESSION_H_
#define SRC_NODE_QUIC_SESSION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_buffer.h"
#include "async_wrap.h"
#include "env.h"
#include "handle_wrap.h"
#include "node.h"
#include "node_crypto.h"
#include "node_mem.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

#include <map>
#include <vector>

namespace node {
namespace quic {

class QuicClientSession;
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
  V(MAX_PACKET_SIZE, max_packet_size, NGTCP2_MAX_PKT_SIZE)                    \
  V(MAX_ACK_DELAY, max_ack_delay, NGTCP2_DEFAULT_MAX_ACK_DELAY)

#define V(idx, name, def)                                                     \
  constexpr uint64_t IDX_QUIC_SESSION_## idx ##_DEFAULT = def;
  QUICSESSION_CONFIG(V)
#undef V

class QuicSessionConfig {
 public:
  QuicSessionConfig() = default;

  void ResetToDefaults();
  void Set(
      Environment* env,
      const struct sockaddr* preferred_addr = nullptr);
  void ToSettings(
      ngtcp2_settings* settings,
      ngtcp2_cid* pscid,
      bool stateless_reset_token = false);

 private:
#define V(idx, name, def) uint64_t name##_ = def;
  QUICSESSION_CONFIG(V)
#undef V
  bool preferred_address_set_ = false;
  SocketAddress preferred_address_;
};

enum QuicSessionState {
  IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT,
  IDX_QUIC_SESSION_STATE_COUNT
};

class QuicSession : public AsyncWrap,
                    public std::enable_shared_from_this<QuicSession>,
                    public mem::Tracker {
 public:
  static const int kInitialClientBufferLength = 4096;

  QuicSession(
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      crypto::SecureContext* ctx,
      AsyncWrap::ProviderType provider);
  ~QuicSession() override;

  void AddStream(QuicStream* stream);
  void Close();
  void Closing();
  void Destroy();
  void GetLocalTransportParams(
      ngtcp2_transport_params* params);
  uint32_t GetNegotiatedVersion();
  SocketAddress* GetRemoteAddress();
  bool IsClosing();
  bool IsDestroyed();
  bool IsHandshakeCompleted();
  int OpenBidirectionalStream(
      int64_t* stream_id);
  int OpenUnidirectionalStream(
      int64_t* stream_id);
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
  int Send0RTTStreamData(
      QuicStream* stream,
      int fin,
      QuicBuffer* data,
      QuicBuffer::drain_from from = QuicBuffer::DRAIN_FROM_HEAD);
  int SendStreamData(
      QuicStream* stream,
      int fin,
      QuicBuffer* data,
      QuicBuffer::drain_from from = QuicBuffer::DRAIN_FROM_HEAD);
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
  void WriteHandshake(
      const uint8_t* data,
      size_t datalen);

  const ngtcp2_cid* scid() const;

  // These may be implemented by QuicSession types
  virtual bool IsServer() const { return false; }

  // These must be implemented by QuicSession types
  virtual void AddToSocket(QuicSocket* socket) = 0;
  virtual int DoHandshake(
      const ngtcp2_path* path,
      const uint8_t* data,
      size_t datalen) = 0;
  virtual int HandleError(
      int code) = 0;
  virtual bool MaybeTimeout() = 0;
  virtual void OnIdleTimeout() = 0;
  virtual int OnKey(
      int name,
      const uint8_t* secret,
      size_t secretlen) = 0;
  virtual int Receive(
      ngtcp2_pkt_hd* hd,
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags) = 0;
  virtual void RemoveFromSocket() = 0;
  virtual int SendConnectionClose(
      int error) = 0;
  virtual int SendPendingData(
      bool retransmit = false) = 0;
  virtual int TLSHandshake_Complete() = 0;
  virtual int TLSHandshake_Initial() = 0;
  virtual int TLSRead() = 0;

  static void SetupTokenContext(
      CryptoContext* context);
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

  static void DebugLog(
      void* user_data,
      const char* fmt, ...);

  void CheckAllocatedSize(size_t previous_size) override;
  void IncrementAllocatedSize(size_t size) override;
  void DecrementAllocatedSize(size_t size) override;

 private:
  void AckedCryptoOffset(
      ngtcp2_crypto_level crypto_level,
      uint64_t offset,
      size_t datalen);
  int AckedStreamDataOffset(
      int64_t stream_id,
      uint64_t offset,
      size_t datalen);
  void AssociateCID(
      ngtcp2_cid* cid);
  int DoHandshakeReadOnce(
      const ngtcp2_path* path,
      const uint8_t* data,
      size_t datalen);
  int DoHandshakeWriteOnce();
  QuicStream* FindStream(
      int64_t id);
  void HandshakeCompleted();
  inline bool IsInClosingPeriod();
  inline void ScheduleMonitor();
  inline int SendPacket(bool retransmit = false);
  inline void SetHandshakeCompleted();
  void StartIdleTimer(
      uint64_t idle_timeout);
  void StopIdleTimer();
  void StopRetransmitTimer();
  int StreamOpen(
      int64_t stream_id);
  int TLSHandshake();
  int WritePeerHandshake(
      ngtcp2_crypto_level crypto_level,
      const uint8_t* data,
      size_t datalen);

  virtual void DisassociateCID(
      const ngtcp2_cid* cid) {}
  virtual int ExtendMaxStreamsUni(
      uint64_t max_streams) { return 0; }
  virtual int ExtendMaxStreamsBidi(
      uint64_t max_streams) { return 0; }
  virtual int ReceiveRetry() { return 0; }
  virtual void StoreRemoteTransportParams(
      ngtcp2_transport_params* params) {}


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
      ngtcp2_crypto_level crypto_level,
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
  static int OnSelectPreferredAddress(
      ngtcp2_conn* conn,
      ngtcp2_addr* dest,
      const ngtcp2_preferred_addr* paddr,
      void* user_data);
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
  static int OnExtendMaxStreamsUni(
      ngtcp2_conn* conn,
      uint64_t max_streams,
      void* user_data);
  static int OnExtendMaxStreamsBidi(
      ngtcp2_conn* conn,
      uint64_t max_streams,
      void* user_data);

  virtual void InitTLS_Post() = 0;

  int ReceiveClientInitial(
      const ngtcp2_cid* dcid);
  int ReceiveCryptoData(
      ngtcp2_crypto_level crypto_level,
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
  void InitTLS();
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

  inline QuicStream* CreateStream(
      int64_t stream_id);

  void SetLocalAddress(
      const ngtcp2_addr* addr);

  virtual ngtcp2_crypto_level GetServerCryptoLevel() = 0;
  virtual ngtcp2_crypto_level GetClientCryptoLevel() = 0;
  virtual void SetServerCryptoLevel(ngtcp2_crypto_level level) = 0;
  virtual void SetClientCryptoLevel(ngtcp2_crypto_level level) = 0;
  virtual void SetLocalCryptoLevel(ngtcp2_crypto_level level) = 0;
  virtual int Start() { return 0; }

  ngtcp2_crypto_level rx_crypto_level_;
  ngtcp2_crypto_level tx_crypto_level_;
  bool closing_;
  bool destroyed_;
  bool initial_;
  crypto::SSLPointer ssl_;
  ngtcp2_conn* connection_;
  SocketAddress remote_address_;
  uint8_t tls_alert_;
  size_t max_pktlen_;
  uv_timer_t* idle_timer_;
  QuicSocket* socket_;
  size_t nkey_update_;
  CryptoContext hs_crypto_ctx_;
  CryptoContext crypto_ctx_;
  std::vector<uint8_t> tx_secret_;
  std::vector<uint8_t> rx_secret_;
  ngtcp2_cid scid_;

  // The sendbuf_ is a temporary holding for data being collected
  // to send. On send, the contents of the sendbuf_ will be
  // transfered to the txbuf_
  QuicBuffer sendbuf_;

  // The handshake_ is a temporary holding for outbound TLS handshake
  // data. On send, the contents of the handshake_ will be
  // transfered to the txbuf_
  QuicBuffer handshake_;

  // The txbuf_ contains all of the data that has been passed off
  // to the QuicSocket. The data will remain in the txbuf_ until
  // it is successfully sent. This is a std::shared_ptr because
  // references of txbuf_ are shared with QuicSocket::SendWrap
  // instances that are responsible for actually sending the data.
  // Each QuicSocket::SendWrap uses a std::weak_ptr. When the
  // QuicSession object is destroyed, those QuicSocket::SendWrap
  // instances may still be alive but will not invoke the Done
  // callback.
  std::shared_ptr<QuicBuffer> txbuf_;

  // Temporary holding for inbound TLS handshake data.
  std::vector<uint8_t> peer_handshake_;
  size_t ncread_;

  std::map<int64_t, QuicStream*> streams_;

  AliasedFloat64Array state_;

  bool monitor_scheduled_;
  bool allow_retransmit_;

  // The amount of memory allocated by ngtcp2 internals
  uint64_t current_ngtcp2_memory_;

  mem::Allocator<ngtcp2_mem> allocator_;

  friend class QuicServerSession;
  friend class QuicClientSession;
};

class QuicServerSession : public QuicSession {
 public:
  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target,
      v8::Local<v8::Context> context);

  static std::shared_ptr<QuicSession> New(
      QuicSocket* socket,
      const ngtcp2_cid* rcid,
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version);

  void AddToSocket(QuicSocket* socket) override;

  void Init(
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version);

  bool IsDraining();
  bool IsServer() const override { return true; }

  bool MaybeTimeout() override;

  const ngtcp2_cid* rcid() const;
  ngtcp2_cid* pscid();

  void MemoryInfo(MemoryTracker* tracker) const override {}
  SET_MEMORY_INFO_NAME(QuicServerSession)
  SET_SELF_SIZE(QuicServerSession)

 private:
  QuicServerSession(
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      const ngtcp2_cid* rcid,
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version);

  void DisassociateCID(
      const ngtcp2_cid* cid) override;
  int DoHandshake(
      const ngtcp2_path* path,
      const uint8_t* data,
      size_t datalen) override;
  int HandleError(
      int code) override;
  void InitTLS_Post() override;
  void OnIdleTimeout() override;
  int OnKey(
      int name,
      const uint8_t* secret,
      size_t secretlen) override;
  int Receive(
      ngtcp2_pkt_hd* hd,
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags) override;
  void RemoveFromSocket() override;
  int SendConnectionClose(
      int error) override;
  int SendPendingData(
      bool retransmit = false) override;
  int TLSHandshake_Complete() override;
  int TLSHandshake_Initial() override;
  int TLSRead() override;

  int StartClosingPeriod(int error);
  void StartDrainingPeriod();

  ngtcp2_crypto_level GetServerCryptoLevel() override;
  ngtcp2_crypto_level GetClientCryptoLevel() override;
  void SetServerCryptoLevel(ngtcp2_crypto_level level) override;
  void SetClientCryptoLevel(ngtcp2_crypto_level level) override;
  void SetLocalCryptoLevel(ngtcp2_crypto_level level) override;

  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  bool draining_;

  MallocedBuffer<uint8_t> conn_closebuf_;

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
    nullptr  // extend_max_stream_data
  };

  friend class QuicSession;
};

class QuicClientSession : public QuicSession {
 public:
  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target,
      v8::Local<v8::Context> context);

  static std::shared_ptr<QuicSession> New(
      QuicSocket* socket,
      const struct sockaddr* addr,
      uint32_t version,
      crypto::SecureContext* context,
      const char* hostname,
      uint32_t port,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket);

  QuicClientSession(
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      const struct sockaddr* addr,
      uint32_t version,
      crypto::SecureContext* context,
      const char* hostname,
      uint32_t port,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket);

  void AddToSocket(QuicSocket* socket) override;

  bool MaybeTimeout() override;

  int SetSocket(
      QuicSocket* socket,
      bool nat_rebinding = false);
  int SetSession(
      SSL_SESSION* session);
  int SetEarlyTransportParams(
      v8::Local<v8::Value> buffer);
  int SetSession(
      v8::Local<v8::Value> buffer);

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicClientSession)
  SET_SELF_SIZE(QuicClientSession)

 private:
  int DoHandshake(
      const ngtcp2_path* path,
      const uint8_t* data,
      size_t datalen) override;
  int ExtendMaxStreamsUni(
      uint64_t max_streams) override;
  int ExtendMaxStreamsBidi(
      uint64_t max_streams) override;
  int HandleError(
      int code) override;
  void InitTLS_Post() override;
  void OnIdleTimeout() override;
  int OnKey(
      int name,
      const uint8_t* secret,
      size_t secretlen) override;
  int Receive(
      ngtcp2_pkt_hd* hd,
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags) override;
  int ReceiveRetry() override;
  void RemoveFromSocket() override;
  int SendConnectionClose(
      int error) override;
  int SendPendingData(
      bool retransmit = false) override;
  int Start() override;
  void StoreRemoteTransportParams(
      ngtcp2_transport_params* params) override;
  int TLSHandshake_Complete() override;
  int TLSHandshake_Initial() override;
  int TLSRead() override;

  int Init(
      const struct sockaddr* addr,
      uint32_t version,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket);
  int ExtendMaxStreams(
      bool bidi,
      uint64_t max_streams);
  int SetupInitialCryptoContext();

  bool resumption_;
  const char* hostname_;
  uint32_t port_;

  ngtcp2_crypto_level GetServerCryptoLevel() override;
  ngtcp2_crypto_level GetClientCryptoLevel() override;
  void SetServerCryptoLevel(ngtcp2_crypto_level level) override;
  void SetClientCryptoLevel(ngtcp2_crypto_level level) override;
  void SetLocalCryptoLevel(ngtcp2_crypto_level level) override;

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
    OnSelectPreferredAddress,  // select_preferred_addr
    nullptr,  // stream_reset
    nullptr,  // extend_max_remote_streams_bidi
    nullptr,  // extend_max_remote_streams_uni
    nullptr  // extend_max_stream_data
  };

  friend class QuicSession;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_SESSION_H_
