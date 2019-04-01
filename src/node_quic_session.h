#ifndef SRC_NODE_QUIC_SESSION_H_
#define SRC_NODE_QUIC_SESSION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

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

#define QUICSESSION_CONFIG(V)                                                 \
  V(MAX_STREAM_DATA_BIDI_LOCAL, max_stream_data_bidi_local, 256_k)            \
  V(MAX_STREAM_DATA_BIDI_REMOTE, max_stream_data_bidi_remote, 256_k)          \
  V(MAX_STREAM_DATA_UNI, max_stream_data_uni, 256_k)                          \
  V(MAX_DATA, max_data, 1_m)                                                  \
  V(MAX_STREAMS_BIDI, max_streams_bidi, 100)                                  \
  V(MAX_STREAMS_UNI, max_streams_uni, 1)                                      \
  V(IDLE_TIMEOUT, idle_timeout, 10 * 1000)                                    \
  V(MAX_PACKET_SIZE, max_packet_size, NGTCP2_MAX_PKT_SIZE)

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

class QuicSession : public AsyncWrap {
 public:
  static const int kInitialClientBufferLength = 4096;

  QuicSession(QuicSocket* socket,
              v8::Local<v8::Object> wrap,
              crypto::SecureContext* ctx,
              AsyncWrap::ProviderType provider);
  virtual ~QuicSession();

  virtual void AckedCryptoOffset(
    uint64_t offset,
    size_t datalen);
  virtual void AddStream(
    QuicStream* stream);
  virtual int AckedStreamDataOffset(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen);
  virtual void AssociateCID(
    ngtcp2_cid* cid) {}
  virtual void Close();
  virtual void Destroy();
  virtual void DisassociateCID(
    const ngtcp2_cid* cid) {}
  virtual QuicStream* FindStream(
    uint64_t id);
  virtual int ExtendMaxStreamsUni(
    uint64_t max_streams) { return 0; }
  virtual int ExtendMaxStreamsBidi(
    uint64_t max_streams) { return 0; }
  virtual uint32_t GetNegotiatedVersion();
  virtual SocketAddress* GetRemoteAddress();
  virtual void HandshakeCompleted();

  virtual bool IsHandshakeCompleted();
  virtual int OpenBidirectionalStream(int64_t* stream_id);
  virtual int OpenUnidirectionalStream(int64_t* stream_id);
  virtual size_t ReadPeerHandshake(
    uint8_t* buf,
    size_t buflen);
  virtual size_t ReadHandshake(
    const uint8_t** pdest);
  virtual int ReceiveStreamData(
    int64_t stream_id,
    int fin,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen);
  virtual int ReceiveRetry() { return 0; }
  virtual void RemoveStream(
    int64_t stream_id);
  virtual void ScheduleRetransmit();
  virtual int Send0RTTStreamData(
      QuicStream* stream,
      int fin,
      QuicBuffer& data);
  virtual int SendStreamData(
      QuicStream* stream,
      int fin,
      QuicBuffer& data);
  virtual void SetTLSAlert(
    int err);
  virtual int ShutdownStreamRead(
    int64_t stream_id,
    uint16_t code = NGTCP2_APP_NOERROR);
  virtual int ShutdownStreamWrite(
    int64_t stream_id,
    uint16_t code = NGTCP2_APP_NOERROR);
  virtual QuicSocket* Socket();
  virtual void StartIdleTimer(
    uint64_t idle_timeout);
  virtual void StopIdleTimer();
  virtual void StopRetransmitTimer();
  virtual int StreamOpen(
    int64_t stream_id);
  virtual int TLSHandshake();
  virtual void WritePeerHandshake(
    const uint8_t* data,
    size_t datalen);
  virtual void WriteHandshake(
    const uint8_t* data,
    size_t datalen);

  inline bool IsDestroyed();
  inline void InitTLS(SSL* ssl);

  int SetRemoteTransportParams(
    ngtcp2_transport_params* params);
  void GetLocalTransportParams(
    ngtcp2_transport_params* params);



  static void SetupTokenContext(CryptoContext& context);
  static int GenerateToken(
    uint8_t* token,
    size_t& tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    CryptoContext& context,
    std::array<uint8_t, TOKEN_SECRETLEN>& token_secret);
  static int VerifyToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    CryptoContext& context,
    std::array<uint8_t, TOKEN_SECRETLEN>& token_secret);

  // These must be implemented by QuicSession types
  virtual int DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) = 0;
  virtual int HandleError(int code) = 0;
  virtual void InitTLS_Post(SSL* ssl) = 0;
  virtual void OnIdleTimeout() = 0;
  virtual int OnKey(
    int name,
    const uint8_t *secret,
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

  SSL* ssl() { return ssl_.get(); }

  static void DebugLog(void* user_data, const char* fmt, ...);

 protected:

  void SetHandshakeCompleted();
  int SendPacket();
  bool IsInClosingPeriod();

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
    ngtcp2_conn *conn,
    const ngtcp2_pkt_hd *hd,
    const ngtcp2_pkt_retry *retry,
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
  int UpdateKey();
  void RemoveConnectionID(
    const ngtcp2_cid* cid);
  int GetNewConnectionID(
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen);

  QuicStream* CreateStream(int64_t stream_id);
  void WriteHandshake(std::deque<QuicBuffer> &dest,
                      size_t& idx,
                      const uint8_t* data,
                      size_t datalen);

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

  std::map<uint64_t, QuicStream*> streams_;

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

  void AssociateCID(
    ngtcp2_cid* cid) override;

  void DisassociateCID(
    const ngtcp2_cid* cid) override;

  int DoHandshake(
    const ngtcp2_path *path,
    const uint8_t* data,
    size_t datalen) override;

  int HandleError(
    int code) override;

  int OnKey(
    int name,
    const uint8_t *secret,
    size_t secretlen) override;

  void InitTLS_Post(SSL* ssl) override;

  int TLSRead() override;

  int Init(
    const struct sockaddr* addr,
    const ngtcp2_cid *dcid,
    const ngtcp2_cid *ocid,
    uint32_t version);
  bool IsDraining();
  void NewSessionDoneCb();
  void OnIdleTimeout() override;
  void OnRetransmitTimeout() override;
  int Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) override;
  void Remove() override;
  int SendConnectionClose(int error) override;
  int SendPendingData(bool retransmit = false) override;
  int TLSHandshake_Complete() override;
  int TLSHandshake_Initial() override;

  const ngtcp2_cid* rcid() const;
  const ngtcp2_cid* scid() const;

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

  ngtcp2_cid rcid_;
  std::vector<uint8_t> chandshake_;
  bool draining_;
  std::unique_ptr<QuicBuffer> conn_closebuf_;

  const ngtcp2_conn_callbacks callbacks_ = {
    nullptr,
    OnReceiveClientInitial,
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
    nullptr,  // recv_stateless_reset
    nullptr,  // recv_retry
    nullptr,  // extend_max_streams_bidi
    nullptr,  // extend_max_streams_uni
    OnRand,
    OnGetNewConnectionID,
    OnRemoveConnectionID,
    OnUpdateKey,
    OnPathValidation
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

  int DoHandshake(
    const ngtcp2_path *path,
    const uint8_t* data,
    size_t datalen) override;

  int HandleError(
    int code) override;

  int OnKey(
    int name,
    const uint8_t *secret,
    size_t secretlen) override;

  int TLSRead() override;

  int Init(
    const struct sockaddr* addr,
    uint32_t version);

  void InitTLS_Post(SSL* ssl) override;

  int ExtendMaxStreams(
    bool bidi,
    uint64_t max_streams);
  int ExtendMaxStreamsUni(
    uint64_t max_streams) override;
  int ExtendMaxStreamsBidi(
    uint64_t max_streams) override;

  void NewSessionDoneCb();
  void OnIdleTimeout() override;
  void OnRetransmitTimeout() override;
  int Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) override;
  int ReceiveRetry() override;
  void Remove() override;
  int SendConnectionClose(int error) override;
  int SendPendingData(bool retransmit = false) override;
  int TLSHandshake_Complete() override;
  int TLSHandshake_Initial() override;

  void MemoryInfo(MemoryTracker* tracker) const override {}

  SET_MEMORY_INFO_NAME(QuicClientSession)
  SET_SELF_SIZE(QuicClientSession)

 private:
  int SetupInitialCryptoContext();
  int DoHandshakeWriteOnce();

  bool resumption_;
  const char* hostname_;
  // uint32_t port_;

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
  };
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_SESSION_H_
