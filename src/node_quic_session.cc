#include "aliased_buffer.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "ngtcp2/ngtcp2.h"
#include "node.h"
#include "node_buffer.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "node_quic_crypto.h"
#include "node_quic_session.h"  // NOLINT(build/include_inline)
#include "node_quic_session-inl.h"
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

using v8::Array;
using v8::ArrayBufferView;
using v8::Context;
using v8::Function;
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
using v8::Undefined;
using v8::Value;

namespace quic {

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
    last_error_(QUIC_ERROR_SESSION, NGTCP2_NO_ERROR),
    closing_(false),
    destroyed_(false),
    initial_(true),
    connection_(nullptr),
    max_pktlen_(0),
    idle_timeout_(10 * 1000),
    socket_(socket),
    hs_crypto_ctx_{},
    crypto_ctx_{},
    txbuf_(new QuicBuffer()),
    ncread_(0),
    state_(env()->isolate(), IDX_QUIC_SESSION_STATE_COUNT),
    current_ngtcp2_memory_(0),
    max_crypto_buffer_(DEFAULT_MAX_CRYPTO_BUFFER),
    alpn_(alpn),
    allocator_(this),
    cert_cb_running_(false),
    client_hello_cb_running_(false),
    is_tls_callback_(false),
    stats_buffer_(
      socket->env()->isolate(),
      sizeof(session_stats_) / sizeof(uint64_t),
      reinterpret_cast<uint64_t*>(&session_stats_)),
    recovery_stats_buffer_(
      socket->env()->isolate(),
      sizeof(recovery_stats_) / sizeof(double),
      reinterpret_cast<double*>(&recovery_stats_)) {
  ssl_.reset(SSL_new(ctx->ctx_.get()));
  SSL_CTX_set_keylog_callback(ctx->ctx_.get(), OnKeylog);
  CHECK(ssl_);

  idle_ = new Timer(env(), [](void* data) {
    QuicSession* session = static_cast<QuicSession*>(data);
    session->OnIdleTimeout();
  }, this);

  retransmit_ = new Timer(env(), [](void* data) {
    QuicSession* session = static_cast<QuicSession*>(data);
    session->MaybeTimeout();
  }, this);

  USE(wrap->DefineOwnProperty(
      env()->context(),
      env()->state_string(),
      state_.GetJSArray(),
      PropertyAttribute::ReadOnly));

  session_stats_.created_at = uv_hrtime();

  USE(wrap->DefineOwnProperty(
      env()->context(),
      env()->stats_string(),
      stats_buffer_.GetJSArray(),
      PropertyAttribute::ReadOnly));

  USE(wrap->DefineOwnProperty(
      env()->context(),
      FIXED_ONE_BYTE_STRING(env()->isolate(), "recoveryStats"),
      recovery_stats_buffer_.GetJSArray(),
      PropertyAttribute::ReadOnly));

  // TODO(@jasnell): memory accounting
  // env_->isolate()->AdjustAmountOfExternalAllocatedMemory(kExternalSize);
}

QuicSession::~QuicSession() {
  CHECK(destroyed_);
  ssl_.reset();
  ngtcp2_conn_del(connection_);
  uint64_t now = uv_hrtime();
  Debug(this,
        "Quic%sSession destroyed.\n"
        "  Duration: %llu\n"
        "  Handshake Started: %llu\n"
        "  Handshake Completed: %llu\n"
        "  Bytes Received: %llu\n"
        "  Bytes Sent: %llu\n"
        "  Bidi Stream Count: %llu\n"
        "  Uni Stream Count: %llu\n"
        "  Streams In Count: %llu\n"
        "  Streams Out Count: %llu\n",
        IsServer() ? "Server" : "Client",
        now - session_stats_.created_at,
        session_stats_.handshake_start_at,
        session_stats_.handshake_completed_at,
        session_stats_.bytes_received,
        session_stats_.bytes_sent,
        session_stats_.bidi_stream_count,
        session_stats_.uni_stream_count,
        session_stats_.streams_in_count,
        session_stats_.streams_out_count);
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
  if (IsDestroyed())
    return;
  Debug(this, "Received acknowledgement for %d bytes of crypto data.", datalen);
  handshake_.Consume(datalen);
  // TODO(@jasnell): Check session_stats_.handshake_send_at to see how long
  // handshake ack has taken. We will want to guard against Slow Handshake
  // as a DOS vector.
  // Likewise, we need to guard against malicious acknowledgements that trickle
  // in acknowledgements with small datalen values. These could cause the
  // session to retain memory and/or send extraneous retransmissions.
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
  if (IsDestroyed())
    return;
  Debug(this, "Received acknowledgement for %d bytes of stream %llu data",
        datalen, stream_id);
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

  switch (stream->GetOrigin()) {
    case QuicStream::QuicStreamOrigin::QUIC_STREAM_CLIENT:
      if (IsServer())
        IncrementStat(1, &session_stats_, &session_stats::streams_in_count);
      else
        IncrementStat(1, &session_stats_, &session_stats::streams_out_count);
      break;
    case QuicStream::QuicStreamOrigin::QUIC_STREAM_SERVER:
      if (IsServer())
        IncrementStat(1, &session_stats_, &session_stats::streams_out_count);
      else
        IncrementStat(1, &session_stats_, &session_stats::streams_in_count);
  }
  IncrementStat(1, &session_stats_, &session_stats::streams_out_count);
  switch (stream->GetDirection()) {
    case QuicStream::QuicStreamDirection::QUIC_STREAM_BIRECTIONAL:
      IncrementStat(1, &session_stats_, &session_stats::bidi_stream_count);
      break;
    case QuicStream::QuicStreamDirection::QUIC_STREAM_UNIDIRECTIONAL:
      IncrementStat(1, &session_stats_, &session_stats::uni_stream_count);
      break;
  }
}

// Every QUIC session will have multiple CIDs associated with it.
void QuicSession::AssociateCID(ngtcp2_cid* cid) {
  QuicCID id(cid);
  QuicCID scid(scid_);
  Socket()->AssociateCID(&id, &scid);
}

// Called when the QuicSession is closed and we need to let the javascript
// side know. The error may be either a QUIC connection error code or an
// application error code, with the type differentiating between the two.
// The default type is QUIC_CLOSE_CONNECTION.
void QuicSession::Close() {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  QuicError last_error = GetLastError();
  Local<Value> argv[] = {
    Integer::New(env()->isolate(), last_error.code),
    Integer::New(env()->isolate(), last_error.family)
  };
  MakeCallback(env()->quic_on_session_close_function(), arraysize(argv), argv);
}

// Creates a new stream object and passes it off to the javascript side.
// This has to be called from within a handlescope/contextscope.
QuicStream* QuicSession::CreateStream(int64_t stream_id) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
  QuicStream* stream = QuicStream::New(this, stream_id);
  CHECK_NOT_NULL(stream);
  Local<Value> argv[] = {
    stream->object(),
    Number::New(env()->isolate(), static_cast<double>(stream_id))
  };
  MakeCallback(env()->quic_on_stream_ready_function(), arraysize(argv), argv);
  return stream;
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
  SendConnectionClose();

  // Hold on to a reference until the function exits
  // so the instance is not prematurely deleted when
  // the session is removed from the socket.
  std::shared_ptr<QuicSession> ptr = shared_from_this();

  idle_->Stop();
  idle_ = nullptr;

  retransmit_->Stop();
  retransmit_ = nullptr;

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

// Reads a chunk of handshake data into the ngtcp2_conn for processing.
int QuicSession::DoHandshakeReadOnce(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {
  if (LIKELY(datalen > 0)) {
    RETURN_RET_IF_FAIL(
        ngtcp2_conn_read_handshake(
            connection_,
            path,
            data,
            datalen,
            uv_hrtime()), 0);
  }
  return 0;
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
    return nwrite;

  data.Realloc(nwrite);
  sendbuf_.Push(std::move(data));

  session_stats_.handshake_send_at = uv_hrtime();
  return SendPacket();
}

void QuicSession::ExtendMaxStreamData(
    int64_t stream_id,
    uint64_t max_data) {
  // TODO(@jasnell): Extend max stream data
}

int QuicSession::ExtendMaxStreams(bool bidi, uint64_t max_streams) {
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

int QuicSession::ExtendMaxStreamsUni(uint64_t max_streams) {
  CHECK(!IsDestroyed());
  return ExtendMaxStreams(false, max_streams);
}

int QuicSession::ExtendMaxStreamsBidi(uint64_t max_streams) {
  CHECK(!IsDestroyed());
  return ExtendMaxStreams(true, max_streams);
}

void QuicSession::ExtendStreamOffset(QuicStream* stream, size_t amount) {
  ngtcp2_conn_extend_max_stream_offset(connection_, stream->GetID(), amount);
}

// Copies the local transport params into the given struct
// for serialization.
void QuicSession::GetLocalTransportParams(ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  ngtcp2_conn_get_local_transport_params(connection_, params);
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

// The HandshakeCompleted function is called by ngtcp2 once it
// determines that the TLS Handshake is done. The only thing we
// need to do at this point is let the javascript side know.
void QuicSession::HandshakeCompleted() {
  session_stats_.handshake_completed_at = uv_hrtime();

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

  // Verify the identity of the peer (this check varies based on whether
  // or not this is a client or server session. See the specific implementation
  // of VerifyPeerIdentity() for either.
  Local<Value> verifyErrorReason = v8::Null(env()->isolate());
  Local<Value> verifyErrorCode = v8::Null(env()->isolate());
  int verifyError = VerifyPeerIdentity(host_name);
  if (verifyError != 0) {
    const char* reason = X509_verify_cert_error_string(verifyError);
    verifyErrorReason = OneByteString(env()->isolate(), reason);
    verifyErrorCode =
        OneByteString(env()->isolate(), X509ErrorCode(verifyError));
  }

  Local<Value> argv[] = {
    servername,
    alpn,
    cipher,
    version,
    maxPacketLength,
    verifyErrorReason,
    verifyErrorCode
  };

  MakeCallback(env()->quic_on_session_handshake_function(),
               arraysize(argv),
               argv);
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
  SSL_set_cert_cb(ssl(), CertCB, this);
  // The verification may be overriden in InitTLS_Post
  SSL_set_verify(ssl(), SSL_VERIFY_NONE, crypto::VerifyCallback);

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

// TLS Keylogging is enabled per-QuicSession by attaching an handler to the
// "keylog" event. Each keylog line is emitted to JavaScript where it can
// be routed to whatever destination makes sense. Typically, this will be
// to a keylog file that can be consumed by tools like Wireshark to intercept
// and decrypt QUIC network traffic.
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

int QuicSession::OpenBidirectionalStream(int64_t* stream_id) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
  return ngtcp2_conn_open_bidi_stream(connection_, stream_id, nullptr);
}

int QuicSession::OpenUnidirectionalStream(int64_t* stream_id) {
  CHECK(!IsDestroyed());
  CHECK(!IsClosing());
  int err = ngtcp2_conn_open_uni_stream(connection_, stream_id, nullptr);
  ngtcp2_conn_shutdown_stream_read(connection_, *stream_id, 0);
  return err;
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

// Reads a chunk of received peer TLS handshake data for processing
size_t QuicSession::ReadPeerHandshake(uint8_t* buf, size_t buflen) {
  CHECK(!IsDestroyed());
  size_t n = std::min(buflen, peer_handshake_.size() - ncread_);
  std::copy_n(std::begin(peer_handshake_) + ncread_, n, buf);
  ncread_ += n;
  return n;
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
  RETURN_RET_IF_FAIL(WritePeerHandshake(crypto_level, data, datalen), 0);
  // If the handshake is not yet completed, incrementally advance
  // the handshake process.
  if (!IsHandshakeCompleted()) {
    RETURN_RET_IF_FAIL(TLSHandshake(), 0);
    return 0;
  }
  // It's possible that not all of the data was consumed. Anything
  // that's remaining needs to be read but it not used.
  return TLSRead();
}

// The ReceiveClientInitial function is called by ngtcp2 when
// a new connection has been initiated. The very first step to
// establishing a communication channel is to setup the keys
// that will be used to secure the communication.
int QuicSession::ReceiveClientInitial(const ngtcp2_cid* dcid) {
  CHECK(!IsDestroyed());
  CHECK(IsServer());
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

int QuicSession::ReceivePacket(
    QuicPath* path,
    const uint8_t* data,
    ssize_t nread) {
  uint64_t now = uv_hrtime();
  session_stats_.session_received_at = now;
  return ngtcp2_conn_read_pkt(
      connection_,
      **path,
      data, nread,
      now);
}

// Called by ngtcp2 when a chunk of stream data has been received. If
// the stream does not yet exist, it is created, then the data is
// forwarded on.
int QuicSession::ReceiveStreamData(
    int64_t stream_id,
    int fin,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  // QUIC does not permit zero-length stream packets if
  // fin is not set. ngtcp2 prevents these from coming
  // through but just in case of regression in that impl,
  // let's double check and simply ignore such packets
  // so we do not commit any resources.
  if (UNLIKELY(fin == 0 && datalen == 0))
    return 0;

  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  QuicStream* stream = FindStream(stream_id);
  if (stream == nullptr) {
    // Shutdown the stream explicitly if the session is being closed.
    if (IsClosing()) {
      return ngtcp2_conn_shutdown_stream(
          connection_,
          stream_id,
          NGTCP2_ERR_CLOSING);
    }
    // One potential DOS attack vector is to send a bunch of
    // empty stream frames to commit resources. Check that
    // here. Essentially, we only want to create a new stream
    // if the datalen is greater than 0, otherwise, we ignore
    // the packet.
    if (datalen == 0)
      return 0;

    // TODO(@jasnell): One bad behavior we need to watch out
    // for here is a malicious client opening a large number
    // of streams objects. There need to be strict limits
    // placed on the number of streams that can be opened
    // concurrently (which is already handled in the configuration
    // settings). We need to verify that ngtcp2 implements
    // appropriate checks for the existing limit per session,
    // and we need to make sure there are additional checks
    // implemented in case of distributed DOS type attacks.
    stream = CreateStream(stream_id);
  }
  CHECK_NOT_NULL(stream);
  stream->ReceiveData(fin, data, datalen, offset);

  // This extends the flow control window for the entire session
  // but not for the individual Stream. Stream flow control is
  // only expanded as data is read on the JavaScript side.
  ngtcp2_conn_extend_max_offset(connection_, datalen);

  return 0;
}

// Removes the given connection id from the QuicSession.
void QuicSession::RemoveConnectionID(const ngtcp2_cid* cid) {
  CHECK(!IsDestroyed());
  state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] =
    state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] - 1;
  CHECK_GE(state_[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT], 0);
  DisassociateCID(cid);
}

// Removes the QuicSession from the current socket. This is
// done with when the session is being destroyed or being
// migrated to another QuicSocket. It is important to keep in mind
// that the QuicSocket uses a shared_ptr for the QuicSession.
// If the session is removed and there are no other references held,
// the session object will be destroyed automatically.
void QuicSession::RemoveFromSocket() {
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

// Removes the given stream from the QuicSession. All streams must
// be removed before the QuicSession is destroyed.
void QuicSession::RemoveStream(int64_t stream_id) {
  CHECK(!IsDestroyed());
  Debug(this, "Removing stream %llu", stream_id);
  streams_.erase(stream_id);
}

// Schedule the retransmission timer
void QuicSession::ScheduleRetransmit() {
  uint64_t now = uv_hrtime();
  uint64_t expiry = ngtcp2_conn_get_expiry(connection_);
  uint64_t interval = (expiry < now) ? 1 : (expiry - now);
  retransmit_->Update(interval);
}

// Sends 0RTT stream data.
int QuicSession::Send0RTTStreamData(
    QuicStream* stream) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen = 0;

  std::vector<ngtcp2_vec> vec;
  size_t count = stream->DrainInto(&vec);
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
      SetLastError(QUIC_ERROR_CRYPTO, nwrite);
      return HandleError();
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
    QuicStream* stream) {
  CHECK(!IsDestroyed());
  ssize_t ndatalen = 0;
  QuicPathStorage path;

  // If we are blocked from sending any data because of
  // flow control, don't try.
  if (ngtcp2_conn_get_max_data_left(connection_) == 0)
    return 0;

  std::vector<ngtcp2_vec> vec;
  size_t count = stream->DrainInto(&vec);

  size_t c = vec.size();
  ngtcp2_vec* v = vec.data();

  // If there is no stream data and we're not sending fin,
  // then just write any pending queued packets and don't
  // attempt to send any stream data to avoid sending empty
  // Stream frames.
  if (c == 0 && stream->IsWritable())
    return WritePackets();

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
      SetLastError(QUIC_ERROR_SESSION, nwrite);
      return HandleError();
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

// Transmits the current contents of the internal sendbuf_ to the peer.
int QuicSession::SendPacket() {
  CHECK(!IsDestroyed());
  // Move the contents of sendbuf_ to the tail of txbuf_ and reset sendbuf_
  if (sendbuf_.Length() > 0) {
    IncrementStat(
        sendbuf_.Length(),
        &session_stats_,
        &session_stats::bytes_sent);
    *txbuf_ += std::move(sendbuf_);
  }
  // There's nothing to send, so let's not try
  if (txbuf_->Length() == 0)
    return 0;
  Debug(this, "There are %llu bytes in txbuf_ to send", txbuf_->Length());
  session_stats_.session_sent_at = uv_hrtime();
  ScheduleRetransmit();
  return Socket()->SendPacket(&remote_address_, txbuf_);
}

// Sends any pending handshake or session packet data.
int QuicSession::SendPendingData() {
  if (UNLIKELY(IsDestroyed()))
    return 0;

  // If the server is in the process of closing or draining
  // the connection, do nothing.
  if (IsServer() && (IsInClosingPeriod() || IsInDrainingPeriod()))
    return 0;

  // If there's anything currently in the sendbuf_, send it.
  RETURN_RET_IF_FAIL(SendPacket(), 0);

  // If the handshake is not yet complete, perform the handshake.
  if (!IsHandshakeCompleted())
    return DoHandshake(nullptr, nullptr, 0);

  // Otherwise, serialize and send any packets waiting in the queue.
  int err = WritePackets();
  if (err < 0) {
    SetLastError(QUIC_ERROR_SESSION, err);
    HandleError();
  }

  return 0;
}

// Notifies the ngtcp2_conn that the TLS handshake is completed.
void QuicSession::SetHandshakeCompleted() {
  CHECK(!IsDestroyed());
  ngtcp2_conn_handshake_completed(connection_);
}

void QuicSession::SetLocalAddress(const ngtcp2_addr* addr) {
  ngtcp2_conn_set_local_addr(connection_, addr);
}

// Set the transport parameters received from the remote peer
int QuicSession::SetRemoteTransportParams(ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  StoreRemoteTransportParams(params);
  return ngtcp2_conn_set_remote_transport_params(connection_, params);
}

int QuicSession::ShutdownStream(int64_t stream_id, uint16_t code) {
  CHECK(!IsDestroyed());
  RETURN_RET_IF_FAIL(
      ngtcp2_conn_shutdown_stream(
          connection_,
          stream_id,
          code), 0);
  return WritePackets();
}

// Called by ngtcp2 when a stream has been closed. If the stream does
// not exist, the close is ignored.
void QuicSession::StreamClose(int64_t stream_id, uint16_t app_error_code) {
  // Ignore if the session has already been destroyed
  if (IsDestroyed())
    return;
  Debug(this, "Closing stream %llu with code %d", stream_id, app_error_code);
  QuicStream* stream = FindStream(stream_id);
  if (stream != nullptr)
    stream->Close(app_error_code);
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
  idle_->Update(idle_timeout_);
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

// Incrementally performs the TLS handshake. This function is called
// multiple times while handshake data is being passed back and forth
// between the peers.
int QuicSession::TLSHandshake() {
  CHECK(!IsDestroyed());
  Debug(this, "TLS handshake %s", initial_ ? "starting" : "continuing");

  if (initial_) {
    session_stats_.handshake_start_at = uv_hrtime();
  } else {
    // TODO(@jasnell): Check handshake_continue_at to guard against slow
    // handshake attack
  }
  session_stats_.handshake_continue_at = uv_hrtime();
  ClearTLSError();

  if (initial_)
    RETURN_RET_IF_FAIL(TLSHandshake_Initial(), 0);

  int err = DoTLSHandshake(ssl());
  if (err <= 0)
    return err;

  RETURN_RET_IF_FAIL(TLSHandshake_Complete(), 0);
  Debug(this, "TLS Handshake completed.");
  SetHandshakeCompleted();
  return 0;
}

// It's possible for TLS handshake to contain extra data that is not
// consumed by ngtcp2. That's ok and the data is just extraneous. We just
// read it and throw it away, unless there's an error.
int QuicSession::TLSRead() {
  CHECK(!IsDestroyed());
  ClearTLSError();
  return ClearTLS(ssl(), !IsServer());
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

// Write any packets current pending for the ngtcp2 connection
int QuicSession::WritePackets() {
  QuicPathStorage path;
  for (;;) {
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

// Writes peer handshake data to the internal buffer
int QuicSession::WritePeerHandshake(
    ngtcp2_crypto_level crypto_level,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  if (rx_crypto_level_ != crypto_level)
    return -1;
  if (peer_handshake_.size() + datalen > max_crypto_buffer_)
    return NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED;
  Debug(this, "Writing %d bytes of peer handshake data.", datalen);
  std::copy_n(data, datalen, std::back_inserter(peer_handshake_));
  return 0;
}

// Called by ngtcp2 when the QuicSession keys need to be updated. This may
// happen multiple times through the lifetime of the QuicSession.
int QuicSession::UpdateKey() {
  CHECK(!IsDestroyed());
  Debug(this, "Updating keys.");

  std::array<uint8_t, 64> secret;
  ssize_t secretlen;
  CryptoParams params;

  IncrementStat(1, &session_stats_, &session_stats::keyupdate_count);

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


// QuicServerSession

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
    const std::string& alpn,
    bool reject_unauthorized,
    bool request_cert) :
    QuicSession(
        socket,
        wrap,
        socket->GetServerSecureContext(),
        AsyncWrap::PROVIDER_QUICSERVERSESSION,
        alpn),
    pscid_{},
    rcid_(*rcid),
    draining_(false),
    reject_unauthorized_(reject_unauthorized),
    request_cert_(request_cert) {
  Init(addr, dcid, ocid, version);
}

std::shared_ptr<QuicSession> QuicServerSession::New(
    QuicSocket* socket,
    const ngtcp2_cid* rcid,
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version,
    const std::string& alpn,
    bool reject_unauthorized,
    bool request_cert) {
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
          alpn,
          reject_unauthorized,
          request_cert));

  session->AddToSocket(socket);
  return session;
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

void QuicServerSession::DisassociateCID(const ngtcp2_cid* cid) {
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

int QuicServerSession::HandleError() {
  if (!SendConnectionClose()) {
    SetLastError(QUIC_ERROR_SESSION, NGTCP2_ERR_INTERNAL);
    Close();
  }
  return 0;
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
  Socket()->SetServerSessionSettings(
      this->pscid(),
      &settings,
      &max_crypto_buffer_);
  idle_timeout_ = settings.idle_timeout;

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

  idle_->Update(idle_timeout_);
}

void QuicServerSession::InitTLS_Post() {
  SSL_set_accept_state(ssl());

  if (request_cert_) {
    int verify_mode = SSL_VERIFY_PEER;
    if (reject_unauthorized_)
      verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_set_verify(ssl(), verify_mode, crypto::VerifyCallback);
  }
}

void QuicServerSession::MaybeTimeout() {
  uint64_t now = uv_hrtime();
  if (ngtcp2_conn_loss_detection_expiry(connection_) <= now) {
    CHECK_EQ(ngtcp2_conn_on_loss_detection_timer(connection_, uv_hrtime()), 0);
    SendPendingData();
  } else if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    SendPendingData();
  }
}

namespace {
void OnServerClientHelloCB(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->OnClientHelloDone();
}
}  // namespace

void QuicServerSession::OnClientHelloDone() {
  // Continue the TLS handshake when this function exits
  // otherwise it will stall and fail.
  TLSHandshakeScope handshake_scope(this, &client_hello_cb_running_);
  // Disable the callback at this point so we don't loop continuously
  state_[IDX_QUIC_SESSION_STATE_CLIENT_HELLO_ENABLED] = 0;
}

// If a 'clientHello' event listener is registered on the JavaScript
// QuicServerSession object, the STATE_CLIENT_HELLO_ENABLED state
// will be set and the OnClientHello will cause the 'clientHello'
// event to be emitted.
//
// The 'clientHello' callback will be given it's own callback function
// that must be called when the client has completed handling the event.
// The handshake will not continue until it is called.
//
// The intent here is to allow user code the ability to modify or
// replace the SecurityContext based on the server name, ALPN, or
// other handshake characteristics.
//
// The user can also set a 'cert' event handler that will be called
// when the peer certificate is received, allowing additional tweaks
// and verifications to be performed.
int QuicServerSession::OnClientHello() {
  if (LIKELY(state_[IDX_QUIC_SESSION_STATE_CLIENT_HELLO_ENABLED] == 0))
    return 0;

  TLSHandshakeCallbackScope callback_scope(this);

  // Not an error but does suspend the handshake until we're ready to go.
  // A callback function is passed to the JavaScript function below that
  // must be called in order to set client_hello_cb_running_ to false.
  // Once that callback is invoked, the TLS Handshake will resume.
  // It is recommended that the user not take a long time to invoke the
  // callback in order to avoid stalling out the QUIC connection.
  if (client_hello_cb_running_)
    return -1;

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  client_hello_cb_running_ = true;

  const char* server_name;
  const char* alpn;
  int* exts;
  size_t len;
  SSL_client_hello_get1_extensions_present(ssl(), &exts, &len);
  for (size_t n = 0; n < len; n++) {
    switch (exts[n]) {
      case TLSEXT_TYPE_server_name:
        server_name = GetClientHelloServerName(ssl());
        break;
      case TLSEXT_TYPE_application_layer_protocol_negotiation:
        alpn = GetClientHelloALPN(ssl());
        break;
    }
  }

  Local<Value> argv[] = {
    Undefined(env()->isolate()),
    Undefined(env()->isolate()),
    GetClientHelloCiphers(env(), ssl()),
    Function::New(
        env()->context(),
        OnServerClientHelloCB,
        object(), 0,
        v8::ConstructorBehavior::kThrow,
        v8::SideEffectType::kHasNoSideEffect).ToLocalChecked()
  };

  if (alpn != nullptr) {
    argv[0] = String::NewFromUtf8(
        env()->isolate(),
        alpn,
        v8::NewStringType::kNormal).ToLocalChecked();
  }
  if (server_name != nullptr) {
    argv[1] = String::NewFromUtf8(
        env()->isolate(),
        server_name,
        v8::NewStringType::kNormal).ToLocalChecked();
  }

  MakeCallback(
      env()->quic_on_session_client_hello_function(),
      arraysize(argv), argv);

  OPENSSL_free(exts);
  return client_hello_cb_running_ ? -1 : 0;
}

namespace {
// This callback is invoked by user code after completing handling
// of the 'OCSPRequest' event. The callback is invoked with two
// possible arguments, both of which are optional
//   1. A replacement SecureContext
//   2. An OCSP response
void OnServerCertCB(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicServerSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  Local<FunctionTemplate> cons = env->secure_context_constructor_template();
  crypto::SecureContext* context = nullptr;
  if (args[0]->IsObject() && cons->HasInstance(args[0]))
    ASSIGN_OR_RETURN_UNWRAP(&context, args[0].As<Object>());
  session->OnCertDone(context, args[1]);
}
}  // namespace

// The OnCertDone function is called by the OnServerCertCB
// function when usercode is done handling the OCSPRequest event.
void QuicServerSession::OnCertDone(
    crypto::SecureContext* context,
    Local<Value> ocsp_response) {
  Debug(this, "OCSPRequest completed. Context Provided? %s, OCSP Provided? %s",
        context != nullptr ? "Yes" : "No",
        ocsp_response->IsArrayBufferView() ? "Yes" : "No");
  // Continue the TLS handshake when this function exits
  // otherwise it will stall and fail.
  TLSHandshakeScope handshake_scope(this, &cert_cb_running_);
  // Disable the callback at this point so we don't loop continuously
  state_[IDX_QUIC_SESSION_STATE_CERT_ENABLED] = 0;

  if (context != nullptr) {
    int err = UseSNIContext(ssl(), context);
    if (!err) {
      unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
      if (!err)
        return env()->ThrowError("CertCbDone");  // TODO(@jasnell): revisit
      return crypto::ThrowCryptoError(env(), err);
    }
  }

  if (ocsp_response->IsArrayBufferView())
    ocsp_response_.Reset(env()->isolate(), ocsp_response.As<ArrayBufferView>());
}

// The OnCert callback provides an opportunity to prompt the server to
// perform on OCSP request on behalf of the client (when the client
// requests it). If there is a listener for the 'OCSPRequest' event
// on the JavaScript side, the IDX_QUIC_SESSION_STATE_CERT_ENABLED
// session state slot will equal 1, which will cause the callback to
// be invoked. The callback will be given a reference to a JavaScript
// function that must be called in order for the TLS handshake to
// continue.
int QuicServerSession::OnCert() {
  Debug(this, "Is there an OCSPRequest handler registered? %s",
        state_[IDX_QUIC_SESSION_STATE_CERT_ENABLED] == 0 ? "No" : "Yes");
  if (LIKELY(state_[IDX_QUIC_SESSION_STATE_CERT_ENABLED] == 0))
    return 1;

  TLSHandshakeCallbackScope callback_scope(this);

  // As in node_crypto.cc, this is not an error, but does suspend the
  // handshake to continue when OnCerb is complete.
  if (cert_cb_running_)
    return -1;

  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  Local<Value> servername_str;
  const bool ocsp =
      (SSL_get_tlsext_status_type(ssl()) == TLSEXT_STATUSTYPE_ocsp);
  Debug(this, "Is the client requesting OCSP? %s", ocsp ? "Yes" : "No");

  // If status type is not ocsp, there's nothing further to do here.
  // Save ourselves the callback into JavaScript and continue the
  // handshake.
  if (!ocsp)
    return 1;

  const char* servername = SSL_get_servername(ssl(), TLSEXT_NAMETYPE_host_name);

  cert_cb_running_ = true;
  Local<Value> argv[] = {
    servername == nullptr ?
        String::Empty(env()->isolate()) :
        OneByteString(
            env()->isolate(),
            servername,
            strlen(servername)),
    Function::New(
        env()->context(),
        OnServerCertCB,
        object(), 0,
        v8::ConstructorBehavior::kThrow,
        v8::SideEffectType::kHasNoSideEffect).ToLocalChecked()
  };

  MakeCallback(env()->quic_on_session_cert_function(), arraysize(argv), argv);

  return cert_cb_running_ ? -1 : 1;
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

// When the client has requested OSCP, this function will be called to provide
// the OSCP response. The OnCert() callback should have already been called
// by this point if any data is to be provided. If it hasn't, and ocsp_response_
// is empty, no OCSP response will be sent.
int QuicServerSession::OnTLSStatus() {
  Debug(this, "Asking for OCSP status to send. Is there a response? %s",
        ocsp_response_.IsEmpty() ? "No" : "Yes");

  if (ocsp_response_.IsEmpty())
    return SSL_TLSEXT_ERR_NOACK;

  HandleScope scope(env()->isolate());

  Local<ArrayBufferView> obj =
      PersistentToLocal::Default(
        env()->isolate(),
        ocsp_response_);
  size_t len = obj->ByteLength();

  unsigned char* data = crypto::MallocOpenSSL<unsigned char>(len);
  obj->CopyContents(data, len);

  Debug(this, "The OCSP Response is %d bytes in length.", len);

  if (!SSL_set_tlsext_status_ocsp_resp(ssl(), data, len))
    OPENSSL_free(data);
  ocsp_response_.Reset();

  return SSL_TLSEXT_ERR_OK;
}

void QuicServerSession::OnIdleTimeout() {
  if (connection_ == nullptr)
    return;

  if (IsInClosingPeriod() || IsDraining())
    return Close();

  StartDrainingPeriod();
}

int QuicServerSession::Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  CHECK(!IsDestroyed());

  SendScope scope(this);
  IncrementStat(nread, &session_stats_, &session_stats::bytes_received);

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
  if (IsInClosingPeriod()) {
    SetLastError(QUIC_ERROR_SESSION, NGTCP2_ERR_CLOSING);
    return HandleError();
  }

  // Draining period starts once we've detected an idle timeout on
  // this session and we're in the process of shutting down. We
  // don't want to accept any new packets during this time, so we
  // simply ignore them.
  if (IsDraining())
    return 0;

  // It's possible for the remote address to change from one
  // packet to the next so we have to look at the addr on
  // every packet.
  // TODO(@jasnell): Currently, this requires us to memcopy on
  // every packet, which is expensive. It would be ideal to have
  // a cheap/easy way of detecting if there is a change and only
  // copy when necessary.
  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  int err;
  if (!IsHandshakeCompleted()) {
    err = DoHandshake(*path, data, nread);
    if (err != 0) {
      SetLastError(InitQuicError(QUIC_ERROR_CRYPTO, err));
      HandleError();
    }
  } else {
    err = ReceivePacket(&path, data, nread);
    if (err == NGTCP2_ERR_DRAINING) {
      StartDrainingPeriod();
      return -1;
    } else if (ngtcp2_err_is_fatal(err)) {
      SetLastError(QUIC_ERROR_SESSION, err);
      HandleError();
    }
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

  QuicSession::RemoveFromSocket();
}

// Transmits the CONNECTION_CLOSE to the peer, signaling
// the end of this QuicSession.
bool QuicServerSession::SendConnectionClose() {
  CHECK(!IsDestroyed());
  RETURN_IF_FAIL(StartClosingPeriod(), 0, false);
  idle_->Update(idle_timeout_);
  CHECK_GT(conn_closebuf_.size, 0);
  sendbuf_.Cancel();
  // We don't use std::move here because we do not want
  // to reset conn_closebuf_.
  uv_buf_t buf =
      uv_buf_init(
          reinterpret_cast<char*>(conn_closebuf_.data),
          conn_closebuf_.size);
  sendbuf_.Push(&buf, 1);
  return SendPacket() == 0;
}

int QuicServerSession::StartClosingPeriod() {
  CHECK(!IsDestroyed());
  if (IsInClosingPeriod())
    return 0;

  retransmit_->Stop();
  idle_->Update(idle_timeout_);

  sendbuf_.Cancel();

  QuicError error = GetLastError();
  Debug(this, "Closing period has started. Error %d", error.code);

  // Once the CONNECTION_CLOSE packet is written,
  // IsInClosingPeriod will return true.
  conn_closebuf_ = MallocedBuffer<uint8_t>(max_pktlen_);
  ssize_t nwrite =
      SelectCloseFn(error.family)(
          connection_,
          nullptr,
          conn_closebuf_.data,
          max_pktlen_,
          error.code,
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
  retransmit_->Stop();
  draining_ = true;
  idle_->Update(idle_timeout_);
}

int QuicServerSession::TLSHandshake_Initial() {
  initial_ = false;
  return DoTLSReadEarlyData(ssl());
}

// For the server-side, we only care that the client provided
// certificate is signed by some entity the server trusts.
// Any additional checks can be performed in usercode on the
// JavaScript side.
int QuicServerSession::VerifyPeerIdentity(const char* hostname) {
  return VerifyPeerCertificate(ssl());
}


// QuicClientSession

// The QuicClientSession class provides a specialization of QuicSession that
// implements client-specific behaviors. Most of the client-specific stuff is
// limited to TLS and early data
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
    const std::string& alpn,
    bool request_ocsp) :
    QuicSession(
        socket,
        wrap,
        context,
        AsyncWrap::PROVIDER_QUICCLIENTSESSION,
        alpn),
    version_(version),
    resumption_(false),
    hostname_(hostname),
    select_preferred_address_policy_(select_preferred_address_policy),
    request_ocsp_(request_ocsp) {
  // TODO(@jasnell): Init may fail. Need to handle the error conditions
  Init(addr, version, early_transport_params, session_ticket, dcid);
}

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
    const std::string& alpn,
    bool request_ocsp) {
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
          alpn,
          request_ocsp);

  session->AddToSocket(socket);
  session->Start();

  return session;
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

void QuicClientSession::VersionNegotiation(
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv) {
  CHECK(!IsDestroyed());
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);

  Local<Array> versions = Array::New(env()->isolate(), nsv);
  for (size_t n = 0; n < nsv; n++) {
    versions->Set(
        env()->context(), n,
        Integer::New(env()->isolate(), sv[n]));
  }

  Local<Array> supportedVersions = Array::New(env()->isolate(), 1);
  supportedVersions->Set(
      env()->context(), 0,
      Integer::New(env()->isolate(), NGTCP2_PROTO_VER));

  Local<Value> argv[] = {
    Integer::New(env()->isolate(), version_),
    versions,
    supportedVersions
  };

  MakeCallback(
      env()->quic_on_session_version_negotiation_function(),
      arraysize(argv), argv);
}

int QuicClientSession::DoHandshake(
    const ngtcp2_path* path,
    const uint8_t* data,
    size_t datalen) {
  CHECK(!IsDestroyed());
  RETURN_RET_IF_FAIL(SendPacket(), 0);
  int err = DoHandshakeReadOnce(path, data, datalen);
  if (err == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    SetLastError(QUIC_ERROR_SESSION, err);
    Close();
    return -1;
  } else if (err != 0) {
    SetLastError(QUIC_ERROR_CRYPTO, err);
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

int QuicClientSession::HandleError() {
  if (!connection_ || IsInClosingPeriod())
    return 0;

  sendbuf_.Cancel();

  if (GetLastError().code == NGTCP2_ERR_RECV_VERSION_NEGOTIATION)
    return 0;

  if (!SendConnectionClose()) {
    SetLastError(QUIC_ERROR_SESSION, NGTCP2_ERR_INTERNAL);
    Close();
  }
  return 0;
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
  max_crypto_buffer_ = client_session_config.GetMaxCryptoBuffer();

  scid_.datalen = NGTCP2_MAX_CIDLEN;
  EntropySource(scid_.data, scid_.datalen);

  ngtcp2_cid dcid;
  if (dcid_value->IsArrayBufferView()) {
    ArrayBufferViewContents<uint8_t> sbuf(
        dcid_value.As<ArrayBufferView>());
    CHECK_LE(sbuf.length(), NGTCP2_MAX_CIDLEN);
    CHECK_GE(sbuf.length(), NGTCP2_MIN_CIDLEN);
    memcpy(dcid.data, sbuf.data(), sbuf.length());
    dcid.datalen = sbuf.length();
  } else {
    dcid.datalen = NGTCP2_MAX_CIDLEN;
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

  idle_->Update(settings.idle_timeout);
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

int QuicClientSession::Start() {
  for (auto stream : streams_)
    RETURN_RET_IF_FAIL(Send0RTTStreamData(stream.second), 0);
  return DoHandshakeWriteOnce();
}

void QuicClientSession::StoreRemoteTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsDestroyed());
  transportParams_.AllocateSufficientStorage(sizeof(ngtcp2_transport_params));
  memcpy(*transportParams_, params, sizeof(ngtcp2_transport_params));
}

void QuicClientSession::InitTLS_Post() {
  SSL_set_connect_state(ssl());

  Debug(this, "Using %s as the ALPN protocol.", GetALPN().c_str() + 1);
  const uint8_t* alpn = reinterpret_cast<const uint8_t*>(GetALPN().c_str());
  size_t alpnlen = GetALPN().length();
  SSL_set_alpn_protos(ssl(), alpn, alpnlen);

  // If the hostname is an IP address and we have no additional
  // information, use localhost.

  if (SocketAddress::numeric_host(hostname_.c_str())) {
    // TODO(@jasnell): Should we do this at all? If the host is numeric,
    // the we likely shouldn't set the SNI at all.
    Debug(this, "Using localhost as fallback hostname.");
    SSL_set_tlsext_host_name(ssl(), "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl(), hostname_.c_str());
  }

  // Are we going to request OCSP status?
  if (request_ocsp_) {
    Debug(this, "Request OCSP status from the server.");
    SSL_set_tlsext_status_type(ssl(), TLSEXT_STATUSTYPE_ocsp);
  }
}

void QuicClientSession::MaybeTimeout() {
  int err;
  uint64_t now = uv_hrtime();
  if (ngtcp2_conn_loss_detection_expiry(connection_) <= now) {
    CHECK_EQ(ngtcp2_conn_on_loss_detection_timer(connection_, now), 0);
    Debug(this, "Retransmitting due to loss detection");
    err = SendPendingData();
    if (err != 0) {
      SetLastError(QUIC_ERROR_SESSION, err);
      HandleError();
    }
  } else if (ngtcp2_conn_ack_delay_expiry(connection_) <= now) {
    Debug(this, "Transmitting due to ack delay");
    err = SendPendingData();
    if (err != 0) {
      SetLastError(QUIC_ERROR_SESSION, err);
      HandleError();
    }
  }
}

void QuicClientSession::OnIdleTimeout() {
  if (connection_ == nullptr)
    return;
  Debug(this, "Idle timeout");
  Close();
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

// During TLS handshake, if the client has requested OCSP status, this
// function will be invoked when the response has been received from
// the server.
int QuicClientSession::OnTLSStatus() {
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  const unsigned char* resp;
  int len = SSL_get_tlsext_status_ocsp_resp(ssl(), &resp);
  Debug(this, "An OCSP Response of %d bytes has been received.", len);
  Local<Value> arg;
  if (resp == nullptr) {
    arg = Undefined(env()->isolate());
  } else {
    arg = Buffer::Copy(env(), reinterpret_cast<const char*>(resp), len)
        .ToLocalChecked();
  }

  MakeCallback(env()->quic_on_session_status_function(), 1, &arg);
  return 1;
}

int QuicClientSession::Receive(
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  CHECK(!IsDestroyed());

  SendScope scope(this);
  IncrementStat(nread, &session_stats_, &session_stats::bytes_received);

  // It's possible for the remote address to change from one
  // packet to the next so we have to look at the addr on
  // every packet.
  // TODO(@jasnell): Currently, this requires us to memcopy on
  // every packet, which is expensive. It would be ideal to have
  // a cheap/easy way of detecting if there is a change and only
  // copy when necessary.
  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  if (!IsHandshakeCompleted())
    return DoHandshake(*path, data, nread);

  int err = ReceivePacket(&path, data, nread);
  if (ngtcp2_err_is_fatal(err)) {
    Close();
    return err;
  }

  return 0;
}

// A HelloRetry will effectively restart the TLS handshake process
// by generating new initial crypto material.
int QuicClientSession::ReceiveRetry() {
  CHECK(!IsDestroyed());
  Debug(this, "A retry packet was received. Restarting the handshake.");
  IncrementStat(1, &session_stats_, &session_stats::retry_count);
  return SetupInitialCryptoContext();
}

// Transmits either a protocol or application connection
// close to the peer. The choice of which is send is
// based on the current value of last_error_.
bool QuicClientSession::SendConnectionClose() {
  CHECK(!IsDestroyed());
  idle_->Update(idle_timeout_);
  MallocedBuffer<uint8_t> data(max_pktlen_);
  sendbuf_.Cancel();
  QuicError error = GetLastError();

  // Do not send a connection close for version negotiation
  if (error.family == QUIC_ERROR_SESSION &&
      error.code == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    return 0;
  }
  ssize_t nwrite =
      SelectCloseFn(error.family)(
        connection_,
        nullptr,
        data.data,
        max_pktlen_,
        error.code,
        uv_hrtime());
  if (nwrite < 0) {
    Debug(this, "Error writing connection close: %d", nwrite);
    return -1;
  }
  data.Realloc(nwrite);
  sendbuf_.Push(std::move(data));
  return SendPacket() == 0;
}

// When resuming a client session, the serialized transport parameters from
// the prior session must be provided. This is set during construction
// of the QuicClientSession object.
int QuicClientSession::SetEarlyTransportParams(Local<Value> buffer) {
  ArrayBufferViewContents<uint8_t> sbuf(buffer.As<ArrayBufferView>());
  ngtcp2_transport_params params;
  if (sbuf.length() != sizeof(ngtcp2_transport_params))
    return ERR_INVALID_REMOTE_TRANSPORT_PARAMS;
  memcpy(&params, sbuf.data(), sizeof(ngtcp2_transport_params));
  ngtcp2_conn_set_early_remote_transport_params(connection_, &params);
  return 0;
}

// When resuming a client session, the serialized session ticket from
// the prior session must be provided. This is set during construction
// of the QuicClientSession object.
int QuicClientSession::SetSession(Local<Value> buffer) {
  ArrayBufferViewContents<unsigned char> sbuf(buffer.As<ArrayBufferView>());
  const unsigned char* p = sbuf.data();
  crypto::SSLSessionPointer s(d2i_SSL_SESSION(nullptr, &p, sbuf.length()));
  if (s == nullptr || SSL_set_session(ssl_.get(), s.get()) != 1)
    return ERR_INVALID_TLS_SESSION_TICKET;
  return 0;
}

// The TLS handshake kicks off when the QuicClientSession is created.
// The very first step is to setup the initial crypto context on the
// client side by creating the initial keying material.
int QuicClientSession::SetupInitialCryptoContext() {
  CHECK(!IsDestroyed());
  Debug(this, "Setting up initial crypto context");

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

int QuicClientSession::VerifyPeerIdentity(const char* hostname) {
  // First, check that the certificate is signed by an entity the client
  // trusts (as configured in the secure context). If not, return early.
  int err = VerifyPeerCertificate(ssl());
  if (err)
    return err;

  // Second, check that the hostname matches the cert subject/altnames
  // TODO(@jasnell): This check is a QUIC requirement. However, for
  // debugging purposes, we should allow it to be turned off via config.
  // When turned off, a process warning should be emitted.
  return VerifyHostnameIdentity(
      ssl(),
      hostname != nullptr ? hostname : hostname_.c_str());
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
  session->SetClosing();
}

// Destroying the QuicSession will trigger sending of a CONNECTION_CLOSE
// packet, after which the QuicSession will be immediately torn down.
void QuicSessionDestroy(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  int code = 0;
  int family = QUIC_ERROR_SESSION;
  USE(args[0]->Int32Value(env->context()).To(&code));
  USE(args[1]->Int32Value(env->context()).To(&family));
  session->SetLastError(static_cast<QuicErrorFamily>(family), code);
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

void QuicSessionGetRemoteAddress(
    const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();
  CHECK(args[0]->IsObject());
  args.GetReturnValue().Set(
      AddressToJS(env, **session->GetRemoteAddress(), args[0].As<Object>()));
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
          alpn,
          args[12]->IsTrue());    // request_oscp

  session->SendPendingData();

  args.GetReturnValue().Set(session->object());
}

// Add methods that are shared by both QuicServerSession and
// QuicClientSession
void AddMethods(Environment* env, Local<FunctionTemplate> session) {
  env->SetProtoMethod(session, "close", QuicSessionClose);
  env->SetProtoMethod(session, "destroy", QuicSessionDestroy);
  env->SetProtoMethod(session, "getRemoteAddress", QuicSessionGetRemoteAddress);
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
