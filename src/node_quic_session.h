#ifndef SRC_NODE_QUIC_SESSION_H_
#define SRC_NODE_QUIC_SESSION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_buffer.h"
#include "async_wrap.h"
#include "env.h"
#include "handle_wrap.h"
#include "histogram-inl.h"
#include "node.h"
#include "node_crypto.h"
#include "node_mem.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

#include <functional>
#include <map>
#include <vector>

namespace node {
namespace quic {

using ConnectionPointer = DeleteFnPtr<ngtcp2_conn, ngtcp2_conn_del>;

class QuicClientSession;
class QuicServerSession;
class QuicSocket;
class QuicStream;

constexpr int ERR_INVALID_REMOTE_TRANSPORT_PARAMS = -1;
constexpr int ERR_INVALID_TLS_SESSION_TICKET = -2;

constexpr uint64_t MINIMUM_MAX_CRYPTO_BUFFER = 4096;
constexpr uint64_t DEFAULT_MAX_CRYPTO_BUFFER = MINIMUM_MAX_CRYPTO_BUFFER * 4;
constexpr uint64_t DEFAULT_ACTIVE_CONNECTION_ID_LIMIT = 10;

// The QuicSessionConfig class holds the initial transport parameters and
// configuration options set by the JavaScript side when either a
// QuicClientSession or QuicServerSession is created. Instances are
// stack created and use a combination of an AliasedBuffer to pass
// the numeric settings quickly (see node_quic_state.h) and passed
// in non-numeric settings (e.g. preferred_addr).
class QuicSessionConfig {
 public:
  QuicSessionConfig() = default;

  inline void ResetToDefaults();

  // QuicSessionConfig::Set() is where the magic happens. It pulls
  // values out of the AliasedBuffer defined in node_quic_state.h
  // and stores the values. If the preferred_addr is set, it will
  // be copied into preferred_address_.
  inline void Set(
      Environment* env,
      const struct sockaddr* preferred_addr = nullptr);

  // When a ngtcp2 connection is created, ToSettings is used to
  // populate the given ngtcp2_settings object with the stored
  // parameters. These are translated into QUIC transport params.
  inline void ToSettings(
      ngtcp2_settings* settings,
      ngtcp2_cid* pscid,
      bool stateless_reset_token = false);

  uint64_t GetMaxCryptoBuffer() { return max_crypto_buffer_; }

 private:
  uint64_t active_connection_id_limit_ = DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  uint64_t max_stream_data_bidi_local_ = 256 * 1024;
  uint64_t max_stream_data_bidi_remote_ = 256 * 1024;
  uint64_t max_stream_data_uni_ = 256 * 1024;
  uint64_t max_data_ = 1 * 1024 * 1024;
  uint64_t max_streams_bidi_ = 100;
  uint64_t max_streams_uni_ = 3;
  uint64_t idle_timeout_ = 10 * 1000;
  uint64_t max_packet_size_ = NGTCP2_MAX_PKT_SIZE;
  uint64_t max_ack_delay_ = NGTCP2_DEFAULT_MAX_ACK_DELAY;
  uint64_t max_crypto_buffer_ = DEFAULT_MAX_CRYPTO_BUFFER;

  bool preferred_address_set_ = false;

  SocketAddress preferred_address_;
};

// The QuicSessionState enums are used with the QuicSession's
// private state_ array. This is exposed to JavaScript via an
// aliased buffer and is used to communicate various types of
// state efficiently across the native/JS boundary.
enum QuicSessionState {
  // Communicates the number of available connection ID's that
  // have been created and associated with the session. This
  // is used, for instance, to enable migration of a QuicSession
  // from one QuicSocket to another (when count > 0).
  IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT,

  // Communicates whether a 'keylog' event listener has been
  // registered on the JavaScript QuicSession object. The
  // value will be either 1 or 0. When set to 1, the native
  // code will emit TLS keylog entries to the JavaScript
  // side triggering the 'keylog' event once for each line.
  IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED,

  // Communicates whether a 'clientHello' event listener has
  // been registered on the JavaScript QuicServerSession.
  // The value will be either 1 or 0. When set to 1, the
  // native code will callout to the JavaScript side causing
  // the 'clientHello' event to be emitted. This is only
  // used on QuicServerSession instances.
  IDX_QUIC_SESSION_STATE_CLIENT_HELLO_ENABLED,

  // Communicates whether a 'cert' event listener has been
  // registered on the JavaScript QuicSession. The value will
  // be either 1 or 0. When set to 1, then native code will
  // callout to the JavaScript side causing the 'cert' event
  // to be emitted.
  IDX_QUIC_SESSION_STATE_CERT_ENABLED,

  // Just the number of session state enums for use when
  // creating the AliasedBuffer.
  IDX_QUIC_SESSION_STATE_COUNT
};

// The QuicSession class is an virtual class that serves as
// the basis for both QuicServerSession and QuicClientSession.
// It implements the functionality that is shared for both
// QUIC clients and servers.
//
// QUIC sessions are virtual connections that exchange data
// back and forth between peer endpoints via UDP. Every QuicSession
// has an associated TLS context and all data transfered between
// the peers is always encrypted. Unlike TLS over TCP, however,
// The QuicSession uses a session identifier that is independent
// of both the local *and* peer IP address, allowing a QuicSession
// to persist across changes in the network (one of the key features
// of QUIC). QUIC sessions also support 0RTT, implement error
// correction mechanisms to recover from lost packets, and flow
// control. In other words, there's quite a bit going on within
// a QuicSession object.
class QuicSession : public AsyncWrap,
                    public std::enable_shared_from_this<QuicSession>,
                    public mem::Tracker {
 public:
  static const int kInitialClientBufferLength = 4096;

  QuicSession(
      // The QuicSocket that created this session. Note that
      // it is possible to replace this socket later, after
      // the TLS handshake has completed. The QuicSession
      // should never assume that the socket will always
      // remain the same.
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      crypto::SecureContext* ctx,
      AsyncWrap::ProviderType provider,
      // QUIC is generally just a transport. The ALPN identifier
      // is used to specify the application protocol that is
      // layered on top. If not specified, this will default
      // to the HTTP/3 identifier.
      const std::string& alpn);
  ~QuicSession() override;

  std::string diagnostic_name() const override;

  inline QuicError GetLastError();

  // Returns true if StartGracefulClose() has been called and the
  // QuicSession is currently in the process of a graceful close.
  inline bool IsGracefullyClosing();

  // Returns true if Destroy() has been called and the
  // QuicSession is no longer usable.
  inline bool IsDestroyed();

  // Starting a GracefulClose disables the ability to open or accept
  // new streams for this session. Existing streams are allowed to
  // close naturally on their own. Once called, the QuicSession will
  // be immediately closed once there are no remaining streams. Note
  // that no notification is given to the connecting peer that we're
  // in a graceful closing state. A CONNECTION_CLOSE will be sent only
  // once ImmediateClose() is called.
  inline void StartGracefulClose();
  inline void SetTLSAlert(int err);

  const std::string& GetALPN() { return alpn_; }

  // Returns the associated peer's address. Note that this
  // value can change over the lifetime of the QuicSession.
  // The fact that the session is not tied intrinsically to
  // a single address is one of the benefits of QUIC.
  SocketAddress* GetRemoteAddress() { return &remote_address_; }
  const ngtcp2_cid* scid() const { return &scid_; }
  QuicSocket* Socket() { return socket_; }
  SSL* ssl() { return ssl_.get(); }
  ngtcp2_conn* connection() { return connection_.get(); }

  void AddStream(QuicStream* stream);

  // Immediately discards the state of the QuicSession
  // and renders the QuicSession instance completely
  // unusable.
  void Destroy();
  void ExtendStreamOffset(QuicStream* stream, size_t amount);
  void GetLocalTransportParams(ngtcp2_transport_params* params);
  uint32_t GetNegotiatedVersion();
  bool IsHandshakeCompleted();
  void OnIdleTimeout();
  int OpenBidirectionalStream(int64_t* stream_id);
  int OpenUnidirectionalStream(int64_t* stream_id);
  size_t ReadPeerHandshake(uint8_t* buf, size_t buflen);
  void ReceiveStreamData(
      int64_t stream_id,
      int fin,
      const uint8_t* data,
      size_t datalen,
      uint64_t offset);
  void RemoveStream(int64_t stream_id);
  ssize_t SendPendingData();
  ssize_t SendStreamData(QuicStream* stream);
  inline void SetLastError(
      QuicError error = {
          QUIC_ERROR_SESSION,
          NGTCP2_NO_ERROR
      });
  inline void SetLastError(QuicErrorFamily family, uint64_t error_code);
  int SetRemoteTransportParams(ngtcp2_transport_params* params);

  // ShutdownStream will cause ngtcp2 to queue a
  // RESET_STREAM and STOP_SENDING frame, as appropriate,
  // for the given stream_id. For a locally-initiated
  // unidirectional stream, only a RESET_STREAM frame
  // will be scheduled and the stream will be immediately
  // closed. For a bi-directional stream, a STOP_SENDING
  // frame will be sent.
  //
  // It is important to note that the QuicStream is
  // not destroyed immediately following ShutdownStream.
  // The sending QuicSession will not close the stream
  // until the RESET_STREAM is acknowledged.
  //
  // Once the RESET_STREAM is sent, the QuicSession
  // should not send any new frames for the stream,
  // and all inbound stream frames should be discarded.
  // Once ngtcp2 receives the appropriate notification
  // that the RESET_STREAM has been acknowledged, the
  // stream will be closed.
  //
  // Once the stream has been closed, it will be
  // destroyed and memory will be freed. User code
  // can request that a stream be immediately and
  // abruptly destroyed without calling ShutdownStream.
  // Likewise, an idle timeout may cause the stream
  // to be silently destroyed without calling
  // ShutdownStream.
  int ShutdownStream(
      int64_t stream_id,
      uint64_t error_code = NGTCP2_APP_NOERROR);
  int TLSRead();
  void WriteHandshake(const uint8_t* data, size_t datalen);

  // These may be implemented by QuicSession types
  virtual bool IsServer() const { return false; }
  virtual int OnClientHello() { return 0; }
  virtual void OnClientHelloDone() {}
  virtual int OnCert() { return 1; }
  virtual void OnCertDone(
      crypto::SecureContext* context,
      v8::Local<v8::Value> ocsp_response) {}
  virtual void RemoveFromSocket();
  virtual int TLSHandshake_Complete() { return 0; }

  // These must be implemented by QuicSession types
  virtual void AddToSocket(QuicSocket* socket) = 0;
  virtual int HandleError() = 0;
  virtual void MaybeTimeout() = 0;
  virtual int OnKey(
      int name,
      const uint8_t* secret,
      size_t secretlen) = 0;
  virtual int OnTLSStatus() = 0;
  virtual int Receive(
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags) = 0;
  virtual bool SendConnectionClose() = 0;
  virtual int TLSHandshake_Initial() = 0;

  // Implementation for mem::Tracker
  inline void CheckAllocatedSize(size_t previous_size) override;
  inline void IncrementAllocatedSize(size_t size) override;
  inline void DecrementAllocatedSize(size_t size) override;

  // Tracks whether or not we are currently within an ngtcp2 callback
  // function. Certain ngtcp2 APIs are not supposed to be called when
  // within a callback. We use this as a gate to check.
  class Ngtcp2CallbackScope {
   public:
    explicit Ngtcp2CallbackScope(QuicSession* session) : session_(session) {
      CHECK(!session_->is_ngtcp2_callback_);
      session_->is_ngtcp2_callback_ = true;
    }

    ~Ngtcp2CallbackScope() {
      session_->is_ngtcp2_callback_ = false;
    }

    static bool InNgtcp2CallbackScope(QuicSession* session) {
      return session->is_ngtcp2_callback_;
    }

   private:
    QuicSession* session_;
  };

 private:
  // Returns true if the QuicSession has entered the
  // closing period following a call to ImmediateClose.
  // While true, the QuicSession is only permitted to
  // transmit CONNECTION_CLOSE frames until either the
  // idle timeout period elapses or until the QuicSession
  // is explicitly destroyed.
  inline bool IsInClosingPeriod();

  // Returns true if the QuicSession has received a
  // CONNECTION_CLOSE frame from the peer. Once in
  // the draining period, the QuicSession is not
  // permitted to send any frames to the peer. The
  // QuicSession will be silently closed after either
  // the idle timeout period elapses or until the
  // QuicSession is explicitly destroyed.
  inline bool IsInDrainingPeriod();
  inline QuicStream* FindStream(int64_t id);

  bool IsHandshakeSuspended() {
    return client_hello_cb_running_ || cert_cb_running_;
  }

  void AckedCryptoOffset(
      ngtcp2_crypto_level crypto_level,
      uint64_t offset,
      size_t datalen);
  void AckedStreamDataOffset(
      int64_t stream_id,
      uint64_t offset,
      size_t datalen);
  void AssociateCID(ngtcp2_cid* cid);

  // Immediately close the QuicSession. All currently open
  // streams are implicitly reset and closed with RESET_STREAM
  // and STOP_SENDING frames transmitted as necessary. A
  // CONNECTION_CLOSE frame will be sent and the session
  // will enter the closing period until either the idle
  // timeout period elapses or until the QuicSession is
  // explicitly destroyed. During the closing period,
  // the only frames that may be transmitted to the peer
  // are repeats of the already sent CONNECTION_CLOSE.
  //
  // The CONNECTION_CLOSE will use the error code set using
  // the most recent call to SetLastError()
  void ImmediateClose();

  // Silently, and immediately close the QuicSession. This is
  // generally only done during an idle timeout. That is, per
  // the QUIC specification, if the session remains idle for
  // longer than both the advertised idle timeout and three
  // times the current probe timeout (PTO). In such cases, all
  // currently open streams are implicitly reset and closed
  // without sending corresponding RESET_STREAM and
  // STOP_SENDING frames, the connection state is
  // discarded, and the QuicSession is destroyed without
  // sending a CONNECTION_CLOSE frame.
  //
  // Silent close may also be used to explicitly destroy
  // a QuicSession that has either already entered the
  // closing or draining periods; or in response to user
  // code requests to forcefully terminate a QuicSession
  // without transmitting any additional frames to the
  // peer.
  void SilentClose();
  QuicStream* CreateStream(int64_t stream_id);
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
  void ExtendMaxStreamData(int64_t stream_id, uint64_t max_data);
  int ExtendMaxStreams(bool bidi, uint64_t max_streams);
  int GetNewConnectionID(ngtcp2_cid* cid, uint8_t* token, size_t cidlen);
  void HandshakeCompleted();
  void InitTLS();
  void Keylog(const char* line);
  int PathValidation(
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res);
  int ReceiveClientInitial(const ngtcp2_cid* dcid);
  int ReceiveCryptoData(
      ngtcp2_crypto_level crypto_level,
      uint64_t offset,
      const uint8_t* data,
      size_t datalen);
  int ReceivePacket(QuicPath* path, const uint8_t* data, ssize_t nread);
  void RemoveConnectionID(const ngtcp2_cid* cid);
  void ScheduleRetransmit();
  int SendPacket();
  void SetHandshakeCompleted();
  void SetLocalAddress(const ngtcp2_addr* addr);
  void StreamClose(int64_t stream_id, uint64_t app_error_code);
  void StreamOpen(int64_t stream_id);
  void StreamReset(
      int64_t stream_id,
      uint64_t final_size,
      uint64_t app_error_code);
  int TLSHandshake();
  bool UpdateKey();
  ssize_t WritePackets();
  int WritePeerHandshake(
      ngtcp2_crypto_level crypto_level,
      const uint8_t* data,
      size_t datalen);
  void UpdateRecoveryStats();

  virtual void DisassociateCID(const ngtcp2_cid* cid) {}
  virtual int ExtendMaxStreamsUni(uint64_t max_streams);
  virtual int ExtendMaxStreamsBidi(uint64_t max_streams);
  virtual int ReceiveRetry() { return 0; }
  virtual int SelectPreferredAddress(
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr) { return 0; }
  virtual void StoreRemoteTransportParams(ngtcp2_transport_params* params) {}
  virtual void VersionNegotiation(
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv) {}

  virtual void InitTLS_Post() = 0;
  virtual ngtcp2_crypto_level GetServerCryptoLevel() = 0;
  virtual ngtcp2_crypto_level GetClientCryptoLevel() = 0;
  virtual void SetServerCryptoLevel(ngtcp2_crypto_level level) = 0;
  virtual void SetClientCryptoLevel(ngtcp2_crypto_level level) = 0;
  virtual void SetLocalCryptoLevel(ngtcp2_crypto_level level) = 0;
  virtual int VerifyPeerIdentity(const char* hostname) = 0;

  // static ngtcp2 callbacks
  static inline int OnClientInitial(
      ngtcp2_conn* conn,
      void* user_data);
  static inline int OnReceiveClientInitial(
      ngtcp2_conn* conn,
      const ngtcp2_cid* dcid,
      void* user_data);
  static inline int OnReceiveCryptoData(
      ngtcp2_conn* conn,
      ngtcp2_crypto_level crypto_level,
      uint64_t offset,
      const uint8_t* data,
      size_t datalen,
      void* user_data);
  static inline int OnHandshakeCompleted(
      ngtcp2_conn* conn,
      void* user_data);
  static inline ssize_t OnDoHSEncrypt(
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
  static inline ssize_t OnDoHSDecrypt(
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
  static inline ssize_t OnDoEncrypt(
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
  static inline ssize_t OnDoDecrypt(
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
  static inline ssize_t OnDoInHPMask(
      ngtcp2_conn* conn,
      uint8_t* dest,
      size_t destlen,
      const uint8_t* key,
      size_t keylen,
      const uint8_t* sample,
      size_t samplelen,
      void* user_data);
  static inline ssize_t OnDoHPMask(
      ngtcp2_conn* conn,
      uint8_t* dest,
      size_t destlen,
      const uint8_t* key,
      size_t keylen,
      const uint8_t* sample,
      size_t samplelen,
      void* user_data);
  static inline int OnReceiveStreamData(
      ngtcp2_conn* conn,
      int64_t stream_id,
      int fin,
      uint64_t offset,
      const uint8_t* data,
      size_t datalen,
      void* user_data,
      void* stream_user_data);
  static inline int OnReceiveRetry(
      ngtcp2_conn* conn,
      const ngtcp2_pkt_hd* hd,
      const ngtcp2_pkt_retry* retry,
      void* user_data);
  static inline int OnAckedCryptoOffset(
      ngtcp2_conn* conn,
      ngtcp2_crypto_level crypto_level,
      uint64_t offset,
      size_t datalen,
      void* user_data);
  static inline int OnAckedStreamDataOffset(
      ngtcp2_conn* conn,
      int64_t stream_id,
      uint64_t offset,
      size_t datalen,
      void* user_data,
      void* stream_user_data);
  static inline int OnSelectPreferredAddress(
      ngtcp2_conn* conn,
      ngtcp2_addr* dest,
      const ngtcp2_preferred_addr* paddr,
      void* user_data);
  static inline int OnStreamClose(
      ngtcp2_conn* conn,
      int64_t stream_id,
      uint64_t app_error_code,
      void* user_data,
      void* stream_user_data);
  static inline int OnStreamOpen(
      ngtcp2_conn* conn,
      int64_t stream_id,
      void* user_data);
  static inline int OnStreamReset(
      ngtcp2_conn* conn,
      int64_t stream_id,
      uint64_t final_size,
      uint64_t app_error_code,
      void* user_data,
      void* stream_user_data);
  static inline int OnRand(
      ngtcp2_conn* conn,
      uint8_t* dest,
      size_t destlen,
      ngtcp2_rand_ctx ctx,
      void* user_data);
  static inline int OnGetNewConnectionID(
      ngtcp2_conn* conn,
      ngtcp2_cid* cid,
      uint8_t* token,
      size_t cidlen,
      void* user_data);
  static inline int OnRemoveConnectionID(
      ngtcp2_conn* conn,
      const ngtcp2_cid* cid,
      void* user_data);
  static inline int OnUpdateKey(
      ngtcp2_conn* conn,
      void* user_data);
  static inline int OnPathValidation(
      ngtcp2_conn* conn,
      const ngtcp2_path* path,
      ngtcp2_path_validation_result res,
      void* user_data);
  static inline void OnIdleTimeout(
      uv_timer_t* timer);
  static inline int OnExtendMaxStreamsUni(
      ngtcp2_conn* conn,
      uint64_t max_streams,
      void* user_data);
  static inline int OnExtendMaxStreamsBidi(
      ngtcp2_conn* conn,
      uint64_t max_streams,
      void* user_data);
  static inline int OnExtendMaxStreamData(
      ngtcp2_conn* conn,
      int64_t stream_id,
      uint64_t max_data,
      void* user_data,
      void* stream_user_data);
  static inline int OnVersionNegotiation(
      ngtcp2_conn* conn,
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv,
      void* user_data);
  static inline void OnKeylog(const SSL* ssl, const char* line);

  void UpdateIdleTimer(uint64_t timeout);
  void UpdateRetransmitTimer(uint64_t timeout);
  void StopRetransmitTimer();
  void StopIdleTimer();

  typedef ssize_t(*ngtcp2_close_fn)(
    ngtcp2_conn* conn,
    ngtcp2_path* path,
    uint8_t* dest,
    size_t destlen,
    uint64_t error_code,
    ngtcp2_tstamp ts);

  static inline ngtcp2_close_fn SelectCloseFn(QuicErrorFamily family) {
    if (family == QUIC_ERROR_APPLICATION)
      return ngtcp2_conn_write_application_close;
    return ngtcp2_conn_write_connection_close;
  }

  ngtcp2_crypto_level rx_crypto_level_;
  ngtcp2_crypto_level tx_crypto_level_;
  QuicError last_error_;
  bool closing_;
  bool destroyed_;
  bool initial_;
  crypto::SSLPointer ssl_;
  ConnectionPointer connection_;
  SocketAddress remote_address_;
  size_t max_pktlen_;
  uint64_t idle_timeout_;

  Timer* idle_;
  Timer* retransmit_;

  QuicSocket* socket_;
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
  // it is successfully sent.
  QuicBuffer txbuf_;

  // Temporary holding for inbound TLS handshake data.
  std::vector<uint8_t> peer_handshake_;
  size_t ncread_;

  std::map<int64_t, std::shared_ptr<QuicStream>> streams_;

  AliasedFloat64Array state_;

  // The amount of memory allocated by ngtcp2 internals
  uint64_t current_ngtcp2_memory_;
  uint64_t max_crypto_buffer_;

  std::string alpn_;

  mem::Allocator<ngtcp2_mem> allocator_;
  bool cert_cb_running_;
  bool client_hello_cb_running_;
  bool is_tls_callback_;
  bool is_ngtcp2_callback_;

  struct session_stats {
    // The timestamp at which the session was created
    uint64_t created_at;
    // The timestamp at which the handshake was started
    uint64_t handshake_start_at;
    // The timestamp at which the most recent handshake
    // message was sent
    uint64_t handshake_send_at;
    // The timestamp at which the most recent handshake
    // message was received
    uint64_t handshake_continue_at;
    // The timestamp at which handshake completed
    uint64_t handshake_completed_at;
    // The timestamp at which the handshake was most recently acked
    uint64_t handshake_acked_at;
    // The timestamp at which the most recently sent
    // non-handshake packets were sent
    uint64_t session_sent_at;
    // The timestamp at which the most recently received
    // non-handshake packets were received
    uint64_t session_received_at;
    // The timestamp at which a graceful close was started
    uint64_t closing_at;
    // The total number of bytes received (and not ignored)
    // by this QuicSession
    uint64_t bytes_received;
    // The total number of bytes sent by this QuicSession
    uint64_t bytes_sent;
    // The total bidirectional stream count
    uint64_t bidi_stream_count;
    // The total unidirectional stream count
    uint64_t uni_stream_count;
    // The total number of peer-initiated streams
    uint64_t streams_in_count;
    // The total number of local-initiated streams
    uint64_t streams_out_count;
    // The total number of keyupdates
    uint64_t keyupdate_count;
    // The total number of retries received
    uint64_t retry_count;
  };
  session_stats session_stats_{
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  // crypto_rx_ack_ measures the elapsed time between crypto acks
  // for this stream. This data can be used to detect peers that are
  // generally taking too long to acknowledge crypto data.
  Histogram crypto_rx_ack_;

  // crypto_handshake_rate_ measures the elapsed time between
  // crypto continuation steps. This data can be used to detect
  // peers that are generally taking too long to carry out the
  // handshake
  Histogram crypto_handshake_rate_;

  struct recovery_stats {
    double min_rtt;
    double latest_rtt;
    double smoothed_rtt;
  };
  recovery_stats recovery_stats_{0, 0, 0};

  AliasedBigUint64Array stats_buffer_;
  AliasedFloat64Array recovery_stats_buffer_;

  template <typename... Members>
  void IncrementSocketStat(
      uint64_t amount,
      session_stats* a,
      Members... mems) {
    IncrementStat<session_stats, Members...>(amount, a, mems...);
  }

  class TLSHandshakeCallbackScope {
   public:
    explicit TLSHandshakeCallbackScope(QuicSession* session) :
        session_(session) {
      session_->is_tls_callback_ = true;
    }

    ~TLSHandshakeCallbackScope() {
      session_->is_tls_callback_ = false;
    }

    static bool IsInTLSHandshakeCallback(QuicSession* session) {
      return session->is_tls_callback_;
    }

   private:
    QuicSession* session_;
  };

  class TLSHandshakeScope {
   public:
    TLSHandshakeScope(QuicSession* session, bool* monitor) :
        session_{session},
        monitor_(monitor) {}

    ~TLSHandshakeScope() {
      if (session_->IsHandshakeSuspended()) {
        // There are a couple of monitor fields in QuicSession
        // (cert_cb_running_ and client_hello_cb_running_).
        // When one of those are true, IsHandshakeSuspended
        // will be true. We set the monitor to false so we
        // can keep the handshake going when the TLS Handshake
        // is continued.
        *monitor_ = false;
        // Only continue the TLS handshake if we are not currently running
        // synchronously within the TLS handshake function. This can happen
        // when the callback function passed to the clientHello and cert
        // event handlers is called synchronously. If the function is called
        // asynchronously, then we have to manually continue the handshake.
        if (!TLSHandshakeCallbackScope::IsInTLSHandshakeCallback(session_)) {
          session_->TLSHandshake();
          session_->SendPendingData();
        }
      }
    }

   private:
    QuicSession* session_;
    bool* monitor_;
  };

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
      uint32_t version,
      const std::string& alpn = NGTCP2_ALPN_H3,
      bool reject_unauthorized = true,
      bool request_cert_ = true);

  void AddToSocket(QuicSocket* socket) override;
  void Init(
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version);
  bool IsServer() const override { return true; }
  int OnCert() override;
  void OnCertDone(
      crypto::SecureContext* context,
      v8::Local<v8::Value> ocsp_response) override;
  int OnClientHello() override;
  void OnClientHelloDone() override;
  int OnTLSStatus() override;
  void MaybeTimeout() override;

  // Serializes and sends a CONNECTION_CLOSE frame as appropriate.
  bool SendConnectionClose() override;

  const ngtcp2_cid* rcid() const { return &rcid_; }
  ngtcp2_cid* pscid() { return &pscid_; }

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
      uint32_t version,
      const std::string& alpn,
      bool reject_unauthorized,
      bool request_cert);

  void DisassociateCID(const ngtcp2_cid* cid) override;
  int HandleError() override;
  void InitTLS_Post() override;
  int OnKey(
      int name,
      const uint8_t* secret,
      size_t secretlen) override;
  int Receive(
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags) override;
  void RemoveFromSocket() override;

  int TLSHandshake_Initial() override;
  int VerifyPeerIdentity(const char* hostname) override;

  int StartClosingPeriod();
  void StartDrainingPeriod();

  ngtcp2_crypto_level GetServerCryptoLevel() override {
    return tx_crypto_level_;
  }

  ngtcp2_crypto_level GetClientCryptoLevel() override {
    return rx_crypto_level_;
  }

  void SetServerCryptoLevel(ngtcp2_crypto_level level) override {
    tx_crypto_level_ = level;
  }

  void SetClientCryptoLevel(ngtcp2_crypto_level level) override {
    rx_crypto_level_ = level;
  }

  void SetLocalCryptoLevel(ngtcp2_crypto_level level) override {
    SetServerCryptoLevel(level);
  }

  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  bool reject_unauthorized_;
  bool request_cert_;

  MallocedBuffer<uint8_t> conn_closebuf_;
  v8::Global<v8::ArrayBufferView> ocsp_response_;

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
    OnExtendMaxStreamData
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
      v8::Local<v8::Value> session_ticket,
      v8::Local<v8::Value> dcid,
      int select_preferred_address_policy =
          QUIC_PREFERRED_ADDRESS_IGNORE,
      const std::string& alpn = NGTCP2_ALPN_H3,
      bool request_ocsp = false,
      bool verify_hostname_identity = true);

  QuicClientSession(
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      const struct sockaddr* addr,
      uint32_t version,
      crypto::SecureContext* context,
      const char* hostname,
      uint32_t port,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket,
      v8::Local<v8::Value> dcid,
      int select_preferred_address_policy,
      const std::string& alpn,
      bool request_ocsp,
      bool verify_hostname_identity);

  void AddToSocket(QuicSocket* socket) override;
  void MaybeTimeout() override;
  int OnTLSStatus() override;

  int SetEarlyTransportParams(v8::Local<v8::Value> buffer);
  ssize_t SetSocket(QuicSocket* socket, bool nat_rebinding = false);
  int SetSession(SSL_SESSION* session);
  int SetSession(v8::Local<v8::Value> buffer);

  bool SendConnectionClose() override;

  void MemoryInfo(MemoryTracker* tracker) const override {}
  SET_MEMORY_INFO_NAME(QuicClientSession)
  SET_SELF_SIZE(QuicClientSession)

 private:
  int HandleError() override;
  void InitTLS_Post() override;
  int OnKey(int name, const uint8_t* secret, size_t secretlen) override;
  int Receive(
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags) override;
  int ReceiveRetry() override;
  int SelectPreferredAddress(
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr) override;
  void StoreRemoteTransportParams(ngtcp2_transport_params* params) override;
  int TLSHandshake_Complete() override;
  int TLSHandshake_Initial() override;
  int VerifyPeerIdentity(const char* hostname) override;

  int Init(
      const struct sockaddr* addr,
      uint32_t version,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket,
      v8::Local<v8::Value> dcid);
  int SetupInitialCryptoContext();

  ngtcp2_crypto_level GetServerCryptoLevel() override {
    return rx_crypto_level_;
  }

  ngtcp2_crypto_level GetClientCryptoLevel() override {
    return tx_crypto_level_;
  }

  void SetServerCryptoLevel(ngtcp2_crypto_level level) override {
    rx_crypto_level_ = level;
  }

  void SetClientCryptoLevel(ngtcp2_crypto_level level) override {
    tx_crypto_level_ = level;
  }

  void SetLocalCryptoLevel(ngtcp2_crypto_level level) override {
    SetClientCryptoLevel(level);
  }

  void VersionNegotiation(
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv) override;

  uint32_t version_;
  bool resumption_;
  std::string hostname_;
  uint32_t port_;

  MaybeStackBuffer<char> transportParams_;
  int select_preferred_address_policy_;
  bool request_ocsp_;
  bool verify_hostname_identity_;

  const ngtcp2_conn_callbacks callbacks_ = {
    OnClientInitial,
    nullptr,
    OnReceiveCryptoData,
    OnHandshakeCompleted,
    OnVersionNegotiation,
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
    OnSelectPreferredAddress,
    OnStreamReset,
    OnExtendMaxStreamsBidi,
    OnExtendMaxStreamsUni,
    OnExtendMaxStreamData
  };

  friend class QuicSession;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_SESSION_H_
