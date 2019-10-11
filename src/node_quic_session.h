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
#include "node_quic_crypto.h"
#include "node_quic_util.h"
#include "v8.h"
#include "uv.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>

#include <functional>
#include <map>
#include <vector>

namespace node {
namespace quic {

using ConnectionPointer = DeleteFnPtr<ngtcp2_conn, ngtcp2_conn_del>;

class QuicSocket;
class QuicStream;

// The QuicSessionConfig class holds the initial transport parameters and
// configuration options set by the JavaScript side when either a
// client or server QuicSession is created. Instances are
// stack created and use a combination of an AliasedBuffer to pass
// the numeric settings quickly (see node_quic_state.h) and passed
// in non-numeric settings (e.g. preferred_addr).
class QuicSessionConfig {
 public:
  QuicSessionConfig() {
    ResetToDefaults();
  }

  explicit QuicSessionConfig(Environment* env) : QuicSessionConfig() {
    Set(env);
  }

  QuicSessionConfig(const QuicSessionConfig& config) {
    settings_ = config.settings_;
    max_crypto_buffer_ = config.max_crypto_buffer_;
    settings_.initial_ts = uv_hrtime();
  }

  void ResetToDefaults();

  // QuicSessionConfig::Set() pulls values out of the AliasedBuffer
  // defined in node_quic_state.h and stores the values in settings_.
  // If preferred_addr is not nullptr, it is copied into the
  // settings_.preferred_addr field
  void Set(Environment* env,
           const struct sockaddr* preferred_addr = nullptr);

  void SetOriginalConnectionID(const ngtcp2_cid* ocid);

  // Generates the stateless reset token for the settings_
  void GenerateStatelessResetToken();

  // If the preferred address is set, generates the associated tokens
  void GeneratePreferredAddressToken(ngtcp2_cid* pscid);

  uint64_t GetMaxCryptoBuffer() const { return max_crypto_buffer_; }

  const ngtcp2_settings* operator*() const { return &settings_; }

 private:
  uint64_t max_crypto_buffer_ = DEFAULT_MAX_CRYPTO_BUFFER;
  ngtcp2_settings settings_;
};

// Options to alter the behavior of various functions on the
// server QuicSession. These are set on the QuicSocket when
// the listen() function is called and are passed to the
// constructor of the server QuicSession.
enum QuicServerSessionOptions : uint32_t {
  // When set, instructs the server QuicSession to reject
  // client authentication certs that cannot be verified.
  QUICSERVERSESSION_OPTION_REJECT_UNAUTHORIZED = 0x1,

  // When set, instructs the server QuicSession to request
  // a client authentication cert
  QUICSERVERSESSION_OPTION_REQUEST_CERT = 0x2
};

// Options to alter the behavior of various functions on the
// client QuicSession. These are set on the client QuicSession
// constructor.
enum QuicClientSessionOptions : uint32_t {
  // When set, instructs the client QuicSession to include an
  // OCSP request in the initial TLS handshake
  QUICCLIENTSESSION_OPTION_REQUEST_OCSP = 0x1,

  // When set, instructs the client QuicSession to verify the
  // hostname identity. This is required by QUIC and enabled
  // by default. We allow disabling it only for debugging
  // purposes.
  QUICCLIENTSESSION_OPTION_VERIFY_HOSTNAME_IDENTITY = 0x2,

  // When set, instructs the client QuicSession to perform
  // additional checks on TLS session resumption.
  QUICCLIENTSESSION_OPTION_RESUME = 0x4
};


// The QuicSessionState enums are used with the QuicSession's
// private state_ array. This is exposed to JavaScript via an
// aliased buffer and is used to communicate various types of
// state efficiently across the native/JS boundary.
enum QuicSessionState : int {
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
  // used on server QuicSession instances.
  IDX_QUIC_SESSION_STATE_CLIENT_HELLO_ENABLED,

  // Communicates whether a 'cert' event listener has been
  // registered on the JavaScript QuicSession. The value will
  // be either 1 or 0. When set to 1, the native code will
  // callout to the JavaScript side causing the 'cert' event
  // to be emitted.
  IDX_QUIC_SESSION_STATE_CERT_ENABLED,

  // Communicates whether a 'pathValidation' event listener
  // has been registered on the JavaScript QuicSession. The
  // value will be either 1 or 0. When set to 1, the native
  // code will callout to the JavaScript side causing the
  // 'pathValidation' event to be emitted
  IDX_QUIC_SESSION_STATE_PATH_VALIDATED_ENABLED,

  // Communicates the current max cumulative number of
  // bidi and uni streams that may be opened on the session
  IDX_QUIC_SESSION_STATE_MAX_STREAMS_BIDI,
  IDX_QUIC_SESSION_STATE_MAX_STREAMS_UNI,

  // Just the number of session state enums for use when
  // creating the AliasedBuffer.
  IDX_QUIC_SESSION_STATE_COUNT
};

class QuicCryptoContext : public MemoryRetainer {
 public:
  SSL* operator*() { return ssl_.get(); }

  uint64_t Cancel();

  void AcknowledgeCryptoData(ngtcp2_crypto_level level, size_t datalen);

  void EnableTrace();

  std::string GetOCSPResponse();

  ngtcp2_crypto_level GetReadCryptoLevel();

  ngtcp2_crypto_level GetWriteCryptoLevel();

  bool IsOptionSet(uint32_t option) const {
    return options_ & option;
  }

  void Keylog(const char* line);

  int OnClientHello();

  void OnClientHelloDone();

  int OnOCSP();

  void OnOCSPDone(
      crypto::SecureContext* context,
      v8::Local<v8::Value> ocsp_response);

  bool OnSecrets(
      ngtcp2_crypto_level level,
      const uint8_t* rx_secret,
      const uint8_t* tx_secret,
      size_t secretlen);

  int OnTLSStatus();

  int Receive(
      ngtcp2_crypto_level crypto_level,
      uint64_t offset,
      const uint8_t* data,
      size_t datalen);

  void ResumeHandshake();

  void SetOption(uint32_t option, bool on = true) {
    if (on)
      options_ |= option;
    else
      options_ &= ~option;
  }

  bool SetSession(const unsigned char* data, size_t len);

  void SetTLSAlert(int err);

  bool SetupInitialKey(const ngtcp2_cid* dcid);

  ngtcp2_crypto_side Side() const { return side_; }

  SSL* ssl() { return ssl_.get(); }

  void WriteHandshake(
      ngtcp2_crypto_level level,
      const uint8_t* data,
      size_t datalen);

  bool UpdateKey(bool initiate = true);

  int VerifyPeerIdentity(const char* hostname);

  void MemoryInfo(MemoryTracker* tracker) const override;

  SET_MEMORY_INFO_NAME(QuicCryptoContext)
  SET_SELF_SIZE(QuicCryptoContext)

 private:
  QuicCryptoContext(
      QuicSession* session,
      crypto::SecureContext* ctx,
      ngtcp2_crypto_side side,
      uint32_t options);

  QuicSession* session_;
  ngtcp2_crypto_side side_;
  crypto::SSLPointer ssl_;
  std::vector<uint8_t> tx_secret_;
  std::vector<uint8_t> rx_secret_;
  QuicBuffer handshake_[3];
  bool in_tls_callback_ = false;
  bool in_key_update_ = false;
  bool in_ocsp_request_ = false;
  bool in_client_hello_ = false;
  uint32_t options_;

  v8::Global<v8::ArrayBufferView> ocsp_response_;
  crypto::BIOPointer bio_trace_;

  class TLSCallbackScope {
   public:
    explicit TLSCallbackScope(QuicCryptoContext* context) :
        context_(context) {
      context_->in_tls_callback_ = true;
    }

    ~TLSCallbackScope() {
      context_->in_tls_callback_ = false;
    }

    static bool IsInCallback(QuicCryptoContext* context) {
      return context->in_tls_callback_;
    }

   private:
    QuicCryptoContext* context_;
  };

  class TLSHandshakeScope {
   public:
    TLSHandshakeScope(
        QuicCryptoContext* context,
        bool* monitor) :
        context_(context),
        monitor_(monitor) {}

    ~TLSHandshakeScope() {
      if (!IsHandshakeSuspended())
        return;

      *monitor_ = false;
      // Only continue the TLS handshake if we are not currently running
      // synchronously within the TLS handshake function. This can happen
      // when the callback function passed to the clientHello and cert
      // event handlers is called synchronously. If the function is called
      // asynchronously, then we have to manually continue the handshake.
      if (!TLSCallbackScope::IsInCallback(context_))
        context_->ResumeHandshake();
    }

   private:
    bool IsHandshakeSuspended() const {
      return context_->in_ocsp_request_ || context_->in_client_hello_;
    }


    QuicCryptoContext* context_;
    bool* monitor_;
  };

  friend class QuicSession;
};

// A QuicApplication encapsulates the specific details of
// working with a specific QUIC application (e.g. http/3).
class QuicApplication {
 public:
  explicit QuicApplication(QuicSession* session);

  virtual bool Initialize() = 0;
 protected:
  QuicSession* Session() { return session_; }
  bool NeedsInit() { return needs_init_; }
  void SetInitDone() { needs_init_ = false; }

 private:
  QuicSession* session_;
  bool needs_init_ = true;
};

// The QuicSession class is an virtual class that serves as
// the basis for both client and server QuicSession.
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
                    public mem::NgLibMemoryManager<QuicSession, ngtcp2_mem> {
 public:
  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target,
      v8::Local<v8::Context> context);

  static BaseObjectPtr<QuicSession> CreateServer(
      QuicSocket* socket,
      QuicSessionConfig* config,
      const ngtcp2_cid* rcid,
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version,
      const std::string& alpn = NGTCP2_ALPN_H3,
      uint32_t options = 0,
      uint64_t initial_connection_close = NGTCP2_NO_ERROR);

  static BaseObjectPtr<QuicSession> CreateClient(
      QuicSocket* socket,
      const struct sockaddr* addr,
      crypto::SecureContext* context,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket,
      v8::Local<v8::Value> dcid,
      SelectPreferredAddressPolicy select_preferred_address_policy =
          QUIC_PREFERRED_ADDRESS_IGNORE,
      const std::string& alpn = NGTCP2_ALPN_H3,
      const std::string& hostname = "",
      uint32_t options = 0);

  static const int kInitialClientBufferLength = 4096;

  // The QuiSession::CryptoContext encapsulates all details of the
  // TLS context on behalf of the QuicSession.
  QuicSession(
      ngtcp2_crypto_side side,
      // The QuicSocket that created this session. Note that
      // it is possible to replace this socket later, after
      // the TLS handshake has completed. The QuicSession
      // should never assume that the socket will always
      // remain the same.
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      crypto::SecureContext* ctx,
      AsyncWrap::ProviderType provider_type,
      // QUIC is generally just a transport. The ALPN identifier
      // is used to specify the application protocol that is
      // layered on top. If not specified, this will default
      // to the HTTP/3 identifier. For QUIC, the alpn identifier
      // is always required.
      const std::string& alpn,
      const std::string& hostname,
      const ngtcp2_cid* rcid,
      uint32_t options = 0,
      SelectPreferredAddressPolicy select_preferred_address_policy =
          QUIC_PREFERRED_ADDRESS_ACCEPT,
      uint64_t initial_connection_close = NGTCP2_NO_ERROR);

  // Server Constructor
  QuicSession(
      QuicSocket* socket,
      QuicSessionConfig* config,
      v8::Local<v8::Object> wrap,
      const ngtcp2_cid* rcid,
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version,
      const std::string& alpn,
      uint32_t options,
      uint64_t initial_connection_close);

  // Client Constructor
  QuicSession(
      QuicSocket* socket,
      v8::Local<v8::Object> wrap,
      const struct sockaddr* addr,
      crypto::SecureContext* context,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket,
      v8::Local<v8::Value> dcid,
      SelectPreferredAddressPolicy select_preferred_address_policy,
      const std::string& alpn,
      const std::string& hostname,
      uint32_t options);

  ~QuicSession() override;

  std::string diagnostic_name() const override;

  enum InitialPacketResult : int {
    PACKET_OK,
    PACKET_IGNORE,
    PACKET_VERSION
  };

  static InitialPacketResult Accept(
    ngtcp2_pkt_hd* hd,
    uint32_t version,
    const uint8_t* data,
    ssize_t nread);

  QuicCryptoContext* CryptoContext() { return crypto_context_.get(); }

  QuicStream* FindStream(int64_t id);
  inline bool HasStream(int64_t id);

  inline QuicError GetLastError() const;

  // Returns true if StartGracefulClose() has been called and the
  // QuicSession is currently in the process of a graceful close.
  inline bool IsGracefullyClosing() const;

  // Returns true if Destroy() has been called and the
  // QuicSession is no longer usable.
  inline bool IsDestroyed() const;

  inline bool IsServer() const;

  // Starting a GracefulClose disables the ability to open or accept
  // new streams for this session. Existing streams are allowed to
  // close naturally on their own. Once called, the QuicSession will
  // be immediately closed once there are no remaining streams. Note
  // that no notification is given to the connecting peer that we're
  // in a graceful closing state. A CONNECTION_CLOSE will be sent only
  // once ImmediateClose() is called.
  inline void StartGracefulClose();

  // Get the ALPN protocol identifier configured for this QuicSession.
  // For server sessions, this will be compared against the client requested
  // ALPN identifier to determine if there is a protocol match.
  const std::string& GetALPN() const { return alpn_; }

  // Get the hostname configured for this QuicSession. This is generally
  // only used by client sessions.
  const std::string& GetHostname() const { return hostname_; }

  // Returns the associated peer's address. Note that this
  // value can change over the lifetime of the QuicSession.
  // The fact that the session is not tied intrinsically to
  // a single address is one of the benefits of QUIC.
  const SocketAddress* GetRemoteAddress() const { return &remote_address_; }

  const ngtcp2_cid* scid() const { return &scid_; }

  // Only used with server sessions
  ngtcp2_cid* pscid() { return &pscid_; }

  // Only used with server sessions
  const ngtcp2_cid* rcid() const { return &rcid_; }

  inline QuicSocket* Socket() const;

  ngtcp2_conn* Connection() { return connection_.get(); }

  void AddStream(BaseObjectPtr<QuicStream> stream);
  void AddToSocket(QuicSocket* socket);

  // Immediately discards the state of the QuicSession
  // and renders the QuicSession instance completely
  // unusable.
  void Destroy();

  // Extends the QUIC stream flow control window. This is
  // called after received data has been consumed and we
  // want to allow the peer to send more data.
  void ExtendStreamOffset(QuicStream* stream, size_t amount);

  // Retrieve the local transport parameters established for
  // this ngtcp2_conn
  void GetLocalTransportParams(ngtcp2_transport_params* params);

  // The QUIC version that has been negotiated for this session
  uint32_t GetNegotiatedVersion();

  // True only if ngtcp2 considers the TLS handshake to be completed
  bool IsHandshakeCompleted();

  // Checks to see if data needs to be retransmitted
  void MaybeTimeout();

  // Called when the session has been determined to have been
  // idle for too long and needs to be torn down.
  void OnIdleTimeout();

  bool OpenBidirectionalStream(int64_t* stream_id);
  bool OpenUnidirectionalStream(int64_t* stream_id);

  // Ping causes the QuicSession to serialize any currently
  // pending frames in it's queue, including any necessary
  // PROBE packets. This is a best attempt, fire-and-forget
  // type of operation. There is no way to listen for a ping
  // response. The main intent of using Ping is to either keep
  // the connection from becoming idle or to update RTT stats.
  void Ping();

  // Receive and process a QUIC packet received from the peer
  bool Receive(
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags);

  // Receive a chunk of QUIC stream data received from the peer
  void ReceiveStreamData(
      int64_t stream_id,
      int fin,
      const uint8_t* data,
      size_t datalen,
      uint64_t offset);

  void RemoveStream(int64_t stream_id);
  void RemoveFromSocket();

  // Causes pending ngtcp2 frames to be serialized and sent
  void SendPendingData();

  // Causes pending QuicStream data to be serialized and sent
  bool SendStreamData(QuicStream* stream);

  inline void SetLastError(
      QuicError error = {
          QUIC_ERROR_SESSION,
          NGTCP2_NO_ERROR
      });
  inline void SetLastError(QuicErrorFamily family, uint64_t error_code);
  inline void SetLastError(QuicErrorFamily family, int error_code);

  inline uint64_t GetMaxLocalStreamsUni();

  int SetRemoteTransportParams(ngtcp2_transport_params* params);
  bool SetEarlyTransportParams(v8::Local<v8::Value> buffer);
  bool SetSocket(QuicSocket* socket, bool nat_rebinding = false);
  int SetSession(SSL_SESSION* session);
  bool SetSession(v8::Local<v8::Value> buffer);

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

  // Error handling for the QuicSession. client and server
  // instances will do different things here, but ultimately
  // an error means that the QuicSession
  // should be torn down.
  void HandleError();

  bool SendConnectionClose();

  // Implementation for mem::NgLibMemoryManager
  inline void CheckAllocatedSize(size_t previous_size) const;
  inline void IncreaseAllocatedSize(size_t size);
  inline void DecreaseAllocatedSize(size_t size);

  // Tracks whether or not we are currently within an ngtcp2 callback
  // function. Certain ngtcp2 APIs are not supposed to be called when
  // within a callback. We use this as a gate to check.
  class Ngtcp2CallbackScope {
   public:
    explicit Ngtcp2CallbackScope(QuicSession* session) : session_(session) {
      CHECK(!InNgtcp2CallbackScope(session));
      session_->SetFlag(QUICSESSION_FLAG_NGTCP2_CALLBACK);
    }

    ~Ngtcp2CallbackScope() {
      session_->SetFlag(QUICSESSION_FLAG_NGTCP2_CALLBACK, false);
    }

    static bool InNgtcp2CallbackScope(QuicSession* session) {
      return session->IsFlagSet(QUICSESSION_FLAG_NGTCP2_CALLBACK);
    }

   private:
    QuicSession* session_;
  };

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(QuicSession)
  SET_SELF_SIZE(QuicSession)

 private:
  // Initialize the QuicSession as a server
  void InitServer(
      QuicSessionConfig* config,
      const struct sockaddr* addr,
      const ngtcp2_cid* dcid,
      const ngtcp2_cid* ocid,
      uint32_t version);

  // Initialize the QuicSession as a client
  bool InitClient(
      const struct sockaddr* addr,
      v8::Local<v8::Value> early_transport_params,
      v8::Local<v8::Value> session_ticket,
      v8::Local<v8::Value> dcid);

  void InitApplication();

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
  void SilentClose(bool stateless_reset = false);
  QuicStream* CreateStream(int64_t stream_id);

  void DisassociateCID(const ngtcp2_cid* cid);
  void ExtendMaxStreamData(int64_t stream_id, uint64_t max_data);
  void ExtendMaxStreams(bool bidi, uint64_t max_streams);
  void ExtendMaxStreamsUni(uint64_t max_streams);
  void ExtendMaxStreamsBidi(uint64_t max_streams);
  int GetNewConnectionID(ngtcp2_cid* cid, uint8_t* token, size_t cidlen);
  void HandshakeCompleted();
  void PathValidation(
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res);
  bool ReceiveClientInitial(const ngtcp2_cid* dcid);
  bool ReceivePacket(QuicPath* path, const uint8_t* data, ssize_t nread);
  bool ReceiveRetry();
  void RemoveConnectionID(const ngtcp2_cid* cid);
  void ScheduleRetransmit();
  bool SelectPreferredAddress(
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr);
  bool SendPacket(const char* diagnostic_label = nullptr);
  void SetLocalAddress(const ngtcp2_addr* addr);
  void StreamClose(int64_t stream_id, uint64_t app_error_code);
  void StreamOpen(int64_t stream_id);
  void StreamReset(
      int64_t stream_id,
      uint64_t final_size,
      uint64_t app_error_code);
  bool WritePackets(const char* diagnostic_label = nullptr);
  void UpdateRecoveryStats();

  void VersionNegotiation(
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv);

  // static ngtcp2 callbacks
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
  static int OnEncrypt(
      ngtcp2_conn* conn,
      uint8_t* dest,
      const ngtcp2_crypto_aead* aead,
      const uint8_t* plaintext,
      size_t plaintextlen,
      const uint8_t* key,
      const uint8_t* nonce,
      size_t noncelen,
      const uint8_t* ad,
      size_t adlen,
      void* user_data);
  static int OnDecrypt(
      ngtcp2_conn* conn,
      uint8_t* dest,
      const ngtcp2_crypto_aead* aead,
      const uint8_t* ciphertext,
      size_t ciphertextlen,
      const uint8_t* key,
      const uint8_t* nonce,
      size_t noncelen,
      const uint8_t* ad,
      size_t adlen,
      void* user_data);
  static int OnHPMask(
      ngtcp2_conn* conn,
      uint8_t* dest,
      const ngtcp2_crypto_cipher* hp,
      const uint8_t* hp_key,
      const uint8_t* sample,
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
      uint64_t app_error_code,
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
      uint64_t app_error_code,
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
  static int OnExtendMaxStreamsUni(
      ngtcp2_conn* conn,
      uint64_t max_streams,
      void* user_data);
  static int OnExtendMaxStreamsBidi(
      ngtcp2_conn* conn,
      uint64_t max_streams,
      void* user_data);
  static int OnExtendMaxStreamData(
      ngtcp2_conn* conn,
      int64_t stream_id,
      uint64_t max_data,
      void* user_data,
      void* stream_user_data);
  static int OnVersionNegotiation(
      ngtcp2_conn* conn,
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv,
      void* user_data);
  static int OnStatelessReset(
      ngtcp2_conn* conn,
      const ngtcp2_pkt_stateless_reset* sr,
      void* user_data);

  void UpdateIdleTimer();
  void UpdateRetransmitTimer(uint64_t timeout);
  void StopRetransmitTimer();
  void StopIdleTimer();
  bool StartClosingPeriod();

  enum QuicSessionFlags : uint32_t {
    // Initial state when a QuicSession is created but nothing yet done.
    QUICSESSION_FLAG_INITIAL = 0x1,

    // Set while the QuicSession is in the process of an Immediate
    // or silent close.
    QUICSESSION_FLAG_CLOSING = 0x2,

    // Set while the QuicSession is in the process of a graceful close.
    QUICSESSION_FLAG_GRACEFUL_CLOSING = 0x4,

    // Set when the QuicSession has been destroyed (but not
    // yet freed)
    QUICSESSION_FLAG_DESTROYED = 0x8,

    QUICSESSION_FLAG_HAS_TRANSPORT_PARAMS = 0x10,

    // Set while the QuicSession is executing an ngtcp2 callback
    QUICSESSION_FLAG_NGTCP2_CALLBACK = 0x100,

    // Set if the QuicSession is in the middle of a silent close
    // (that is, a CONNECTION_CLOSE should not be sent)
    QUICSESSION_FLAG_SILENT_CLOSE = 0x200,

    QUICSESSION_FLAG_HANDSHAKE_RX = 0x400,
    QUICSESSION_FLAG_HANDSHAKE_TX = 0x800,
    QUICSESSION_FLAG_HANDSHAKE_KEYS =
        QUICSESSION_FLAG_HANDSHAKE_RX |
        QUICSESSION_FLAG_HANDSHAKE_TX,
    QUICSESSION_FLAG_SESSION_RX = 0x1000,
    QUICSESSION_FLAG_SESSION_TX = 0x2000,
    QUICSESSION_FLAG_SESSION_KEYS =
        QUICSESSION_FLAG_SESSION_RX |
        QUICSESSION_FLAG_SESSION_TX
  };

  void SetFlag(QuicSessionFlags flag, bool on = true) {
    if (on)
      flags_ |= flag;
    else
      flags_ &= ~flag;
  }

  bool IsFlagSet(QuicSessionFlags flag) const {
    return (flags_ & flag) == flag;
  }

  void IncrementConnectionCloseAttempts() {
    if (connection_close_attempts_ < kMaxSizeT)
      connection_close_attempts_++;
  }

  bool ShouldAttemptConnectionClose() {
    if (connection_close_attempts_ == connection_close_limit_) {
      if (connection_close_limit_ * 2 <= kMaxSizeT)
        connection_close_limit_ *= 2;
      else
        connection_close_limit_ = kMaxSizeT;
      return true;
    }
    return false;
  }

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

  // Select the QUIC Application based on the configured ALPN identifier
  QuicApplication* SelectApplication(QuicSession* session);

  ngtcp2_mem alloc_info_;
  std::unique_ptr<QuicCryptoContext> crypto_context_;
  std::unique_ptr<QuicApplication> application_;
  BaseObjectWeakPtr<QuicSocket> socket_;
  std::string alpn_;
  std::string hostname_;
  QuicError last_error_ = { QUIC_ERROR_SESSION, NGTCP2_NO_ERROR };
  ConnectionPointer connection_;
  SocketAddress remote_address_;
  uint32_t flags_ = 0;
  uint64_t initial_connection_close_ = NGTCP2_NO_ERROR;
  size_t max_pktlen_ = 0;
  size_t max_crypto_buffer_ = DEFAULT_MAX_CRYPTO_BUFFER;
  size_t current_ngtcp2_memory_ = 0;
  size_t connection_close_attempts_ = 0;
  size_t connection_close_limit_ = 1;

  TimerPointer idle_;
  TimerPointer retransmit_;

  ngtcp2_cid scid_;
  ngtcp2_cid rcid_;
  ngtcp2_cid pscid_{};
  ngtcp2_transport_params transport_params_;
  SelectPreferredAddressPolicy select_preferred_address_policy_;

  // The sendbuf_ is a temporary holding for data being collected
  // to send. On send, the contents of the sendbuf_ will be
  // transfered to the txbuf_
  QuicBuffer sendbuf_;

  // The txbuf_ contains all of the data that has been passed off
  // to the QuicSocket. The data will remain in the txbuf_ until
  // it is successfully sent.
  QuicBuffer txbuf_;

  MallocedBuffer<uint8_t> conn_closebuf_;

  std::map<int64_t, BaseObjectPtr<QuicStream>> streams_;

  AliasedFloat64Array state_;

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
    // The total number of loss detection retransmissions
    uint64_t loss_retransmit_count;
    // The total number of ack delay retransmissions
    uint64_t ack_delay_retransmit_count;
    // The total number of successful path validations
    uint64_t path_validation_success_count;
    // The total number of failed path validations
    uint64_t path_validation_failure_count;
  };
  session_stats session_stats_{};

  // crypto_rx_ack_ measures the elapsed time between crypto acks
  // for this stream. This data can be used to detect peers that are
  // generally taking too long to acknowledge crypto data.
  BaseObjectPtr<HistogramBase> crypto_rx_ack_;

  // crypto_handshake_rate_ measures the elapsed time between
  // crypto continuation steps. This data can be used to detect
  // peers that are generally taking too long to carry out the
  // handshake
  BaseObjectPtr<HistogramBase> crypto_handshake_rate_;

  struct recovery_stats {
    double min_rtt;
    double latest_rtt;
    double smoothed_rtt;
  };
  recovery_stats recovery_stats_{};

  AliasedBigUint64Array stats_buffer_;
  AliasedFloat64Array recovery_stats_buffer_;

  static const ngtcp2_conn_callbacks callbacks[2];

  friend class QuicCryptoContext;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_SESSION_H_
