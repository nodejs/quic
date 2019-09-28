#include "aliased_buffer.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "ngtcp2/ngtcp2.h"
#include "node.h"
#include "node_buffer.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "node_mem-inl.h"
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
#include <string>
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

// Forwards detailed(verbose) debugging information from ngtcp2. Enabled using
// the NODE_DEBUG_NATIVE=NGTCP2_DEBUG category.
static void Ngtcp2DebugLog(void* user_data, const char* fmt, ...) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  va_list ap;
  va_start(ap, fmt);
  std::string format(fmt, strlen(fmt) + 1);
  format[strlen(fmt)] = '\n';
  Debug(session->env(), DebugCategory::NGTCP2_DEBUG, format, ap);
  va_end(ap);
}

inline void SetConfig(Environment* env, int idx, uint64_t* val) {
  AliasedFloat64Array& buffer = env->quic_state()->quicsessionconfig_buffer;
  uint64_t flags = static_cast<uint64_t>(buffer[IDX_QUIC_SESSION_CONFIG_COUNT]);
  if (flags & (1ULL << idx))
    *val = static_cast<uint64_t>(buffer[idx]);
}

void QuicSessionConfig::ResetToDefaults() {
  ngtcp2_settings_default(&settings_);
  settings_.initial_ts = uv_hrtime();
  settings_.log_printf = Ngtcp2DebugLog;
  settings_.active_connection_id_limit = DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
  settings_.max_stream_data_bidi_local = DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL;
  settings_.max_stream_data_bidi_remote = DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE;
  settings_.max_stream_data_uni = DEFAULT_MAX_STREAM_DATA_UNI;
  settings_.max_data = DEFAULT_MAX_DATA;
  settings_.max_streams_bidi = DEFAULT_MAX_STREAMS_BIDI;
  settings_.max_streams_uni = DEFAULT_MAX_STREAMS_UNI;
  settings_.idle_timeout = DEFAULT_IDLE_TIMEOUT;
  settings_.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  settings_.max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
  settings_.disable_migration = 0;
  settings_.preferred_address_present = 0;
  settings_.stateless_reset_token_present = 0;
  max_crypto_buffer_ = DEFAULT_MAX_CRYPTO_BUFFER;
}

// Sets the QuicSessionConfig using an AliasedBuffer for efficiency.
void QuicSessionConfig::Set(Environment* env,
                            const sockaddr* preferred_addr) {
  ResetToDefaults();

  SetConfig(env, IDX_QUIC_SESSION_ACTIVE_CONNECTION_ID_LIMIT,
            &settings_.active_connection_id_limit);
  SetConfig(env, IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL,
            &settings_.max_stream_data_bidi_local);
  SetConfig(env, IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE,
            &settings_.max_stream_data_bidi_remote);
  SetConfig(env, IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI,
            &settings_.max_stream_data_uni);
  SetConfig(env, IDX_QUIC_SESSION_MAX_DATA,
            &settings_.max_data);
  SetConfig(env, IDX_QUIC_SESSION_MAX_STREAMS_BIDI,
            &settings_.max_streams_bidi);
  SetConfig(env, IDX_QUIC_SESSION_MAX_STREAMS_UNI,
            &settings_.max_streams_uni);
  SetConfig(env, IDX_QUIC_SESSION_IDLE_TIMEOUT,
            &settings_.idle_timeout);
  SetConfig(env, IDX_QUIC_SESSION_MAX_PACKET_SIZE,
            &settings_.max_packet_size);
  SetConfig(env, IDX_QUIC_SESSION_MAX_ACK_DELAY,
            &settings_.max_ack_delay);

  SetConfig(env, IDX_QUIC_SESSION_MAX_CRYPTO_BUFFER,
            &max_crypto_buffer_);
  max_crypto_buffer_ = std::max(max_crypto_buffer_, MIN_MAX_CRYPTO_BUFFER);

  if (preferred_addr != nullptr) {
    settings_.preferred_address_present = 1;
    switch (preferred_addr->sa_family) {
      case AF_INET: {
        auto& dest = settings_.preferred_address.ipv4_addr;
        memcpy(
            &dest,
            &(reinterpret_cast<const sockaddr_in*>(preferred_addr)->sin_addr),
            sizeof(dest));
        settings_.preferred_address.ipv4_port =
            SocketAddress::GetPort(preferred_addr);
        break;
      }
      case AF_INET6: {
        auto& dest = settings_.preferred_address.ipv6_addr;
        memcpy(
            &dest,
            &(reinterpret_cast<const sockaddr_in6*>(preferred_addr)->sin6_addr),
            sizeof(dest));
        settings_.preferred_address.ipv6_port =
            SocketAddress::GetPort(preferred_addr);
        break;
      }
      default:
        UNREACHABLE();
    }
  }
}

void QuicSessionConfig::GenerateStatelessResetToken() {
  settings_.stateless_reset_token_present = 1;
  EntropySource(
      settings_.stateless_reset_token,
      arraysize(settings_.stateless_reset_token));
}

void QuicSessionConfig::GeneratePreferredAddressToken(ngtcp2_cid* pscid) {
  if (!settings_.preferred_address_present)
    return;
  EntropySource(
      settings_.preferred_address.stateless_reset_token,
      arraysize(settings_.preferred_address.stateless_reset_token));

  pscid->datalen = NGTCP2_SV_SCIDLEN;
  EntropySource(pscid->data, pscid->datalen);
  settings_.preferred_address.cid = *pscid;
}

// QuicSession is an abstract base class that defines the code used by both
// server and client sessions.
QuicSession::QuicSession(
    ngtcp2_crypto_side side,
    QuicSocket* socket,
    Local<Object> wrap,
    SecureContext* ctx,
    AsyncWrap::ProviderType provider_type,
    const std::string& alpn,
    uint32_t options,
    uint64_t initial_connection_close)
  : AsyncWrap(socket->env(), wrap, provider_type),
    alloc_info_(MakeAllocator()),
    side_(side),
    socket_(socket),
    alpn_(alpn),
    options_(options),
    initial_connection_close_(initial_connection_close),
    idle_(new Timer(socket->env(), [this]() { OnIdleTimeout(); })),
    retransmit_(new Timer(socket->env(), [this]() { MaybeTimeout(); })),
    state_(env()->isolate(), IDX_QUIC_SESSION_STATE_COUNT),
    crypto_rx_ack_(
        HistogramBase::New(
            socket->env(),
            1, std::numeric_limits<int64_t>::max())),
    crypto_handshake_rate_(
        HistogramBase::New(
            socket->env(),
            1, std::numeric_limits<int64_t>::max())),
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

  session_stats_.created_at = uv_hrtime();

  if (wrap->DefineOwnProperty(
          env()->context(),
          env()->state_string(),
          state_.GetJSArray(),
          PropertyAttribute::ReadOnly).IsNothing()) return;

  if (wrap->DefineOwnProperty(
          env()->context(),
          env()->stats_string(),
          stats_buffer_.GetJSArray(),
          PropertyAttribute::ReadOnly).IsNothing()) return;

  if (wrap->DefineOwnProperty(
          env()->context(),
          env()->recovery_stats_string(),
          recovery_stats_buffer_.GetJSArray(),
          PropertyAttribute::ReadOnly).IsNothing()) return;

  if (wrap->DefineOwnProperty(
          env()->context(),
          FIXED_ONE_BYTE_STRING(env()->isolate(), "crypto_rx_ack"),
          crypto_rx_ack_->object(),
          PropertyAttribute::ReadOnly).IsNothing()) return;

  if (wrap->DefineOwnProperty(
          env()->context(),
          FIXED_ONE_BYTE_STRING(env()->isolate(), "crypto_handshake_rate"),
          crypto_handshake_rate_->object(),
          PropertyAttribute::ReadOnly).IsNothing()) return;

  // TODO(@jasnell): memory accounting
  // env_->isolate()->AdjustAmountOfExternalAllocatedMemory(kExternalSize);
}

QuicSession::~QuicSession() {
  CHECK(!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this));

  uint64_t sendbuf_length = sendbuf_.Cancel();
  uint64_t handshake_length = handshake_.Cancel();
  uint64_t txbuf_length = txbuf_.Cancel();

  Debug(this,
        "Destroyed.\n"
        "  Duration: %" PRIu64 "\n"
        "  Handshake Started: %" PRIu64 "\n"
        "  Handshake Completed: %" PRIu64 "\n"
        "  Bytes Received: %" PRIu64 "\n"
        "  Bytes Sent: %" PRIu64 "\n"
        "  Bidi Stream Count: %" PRIu64 "\n"
        "  Uni Stream Count: %" PRIu64 "\n"
        "  Streams In Count: %" PRIu64 "\n"
        "  Streams Out Count: %" PRIu64 "\n"
        "  Remaining sendbuf_: %" PRIu64 "\n"
        "  Remaining handshake_: %" PRIu64 "\n"
        "  Remaining txbuf_: %" PRIu64 "\n",
        uv_hrtime() - session_stats_.created_at,
        session_stats_.handshake_start_at,
        session_stats_.handshake_completed_at,
        session_stats_.bytes_received,
        session_stats_.bytes_sent,
        session_stats_.bidi_stream_count,
        session_stats_.uni_stream_count,
        session_stats_.streams_in_count,
        session_stats_.streams_out_count,
        sendbuf_length,
        handshake_length,
        txbuf_length);
}

std::string QuicSession::diagnostic_name() const {
  return std::string("QuicSession ") +
      (Side() == NGTCP2_CRYPTO_SIDE_SERVER ? "Server" : "Client") +
      " (" + std::to_string(static_cast<int64_t>(get_async_id())) + ")";
}

// Locate the QuicStream with the given id or return nullptr
QuicStream* QuicSession::FindStream(int64_t id) {
  auto it = streams_.find(id);
  if (it == std::end(streams_))
    return nullptr;
  return it->second.get();
}

void QuicSession::AckedCryptoOffset(size_t datalen) {
  // It is possible for the QuicSession to have been destroyed but not yet
  // deconstructed. In such cases, we want to ignore the callback as there
  // is nothing to do but wait for further cleanup to happen.
  if (UNLIKELY(IsFlagSet(QUICSESSION_FLAG_DESTROYED)))
    return;
  Debug(this, "Acknowledging %d crypto bytes", datalen);

  // Consumes (frees) the given number of bytes in the handshake buffer.
  handshake_.Consume(datalen);

  // Update the statistics for the handshake, allowing us to track
  // how long the handshake is taking to be acknowledged. A malicious
  // peer could potentially force the QuicSession to hold on to
  // crypto data for a long time by not sending an acknowledgement.
  // The histogram will allow us to track the time periods between
  // acknowlegements.
  uint64_t now = uv_hrtime();
  if (session_stats_.handshake_acked_at > 0)
    crypto_rx_ack_->Record(now - session_stats_.handshake_acked_at);
  session_stats_.handshake_acked_at = now;
}

void QuicSession::AckedStreamDataOffset(
    int64_t stream_id,
    uint64_t offset,
    size_t datalen) {
  // It is possible for the QuicSession to have been destroyed but not yet
  // deconstructed. In such cases, we want to ignore the callback as there
  // is nothing to do but wait for further cleanup to happen.
  if (UNLIKELY(IsFlagSet(QUICSESSION_FLAG_DESTROYED)))
    return;
  Debug(this,
        "Received acknowledgement for %" PRIu64
        " bytes of stream %" PRId64 " data",
        datalen, stream_id);

  QuicStream* stream = FindStream(stream_id);
  // It is possible that the QuicStream has already been destroyed and
  // removed from the collection. In such cases, we want to ignore the
  // callback as there is nothing further to do.
  if (LIKELY(stream != nullptr))
    stream->AckedDataOffset(offset, datalen);
}

// Add the given QuicStream to this QuicSession's collection of streams. All
// streams added must be removed before the QuicSession instance is freed.
void QuicSession::AddStream(BaseObjectPtr<QuicStream> stream) {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING));
  Debug(this, "Adding stream %" PRId64 " to session.", stream->GetID());
  streams_.emplace(stream->GetID(), stream);

  // Update tracking statistics for the number of streams associated with
  // this session.
  switch (stream->GetOrigin()) {
    case QuicStream::QuicStreamOrigin::QUIC_STREAM_CLIENT:
      if (Side() == NGTCP2_CRYPTO_SIDE_SERVER)
        IncrementStat(1, &session_stats_, &session_stats::streams_in_count);
      else
        IncrementStat(1, &session_stats_, &session_stats::streams_out_count);
      break;
    case QuicStream::QuicStreamOrigin::QUIC_STREAM_SERVER:
      if (Side() == NGTCP2_CRYPTO_SIDE_SERVER)
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

// Like the silent close, the immediate close must start with
// the JavaScript side, first shutting down any existing
// streams before entering the closing period. Unlike silent
// close, however, all streams are closed using proper
// STOP_SENDING and RESET_STREAM frames and a CONNECTION_CLOSE
// frame is ultimately sent to the peer. This makes the
// naming a bit of a misnomer in that the connection is
// not immediately torn down, but is allowed to drain
// properly per the QUIC spec description of "immediate close".
void QuicSession::ImmediateClose() {
  // Calling either ImmediateClose or SilentClose will cause
  // the QUICSESSION_FLAG_CLOSING to be set. In either case,
  // we should never re-enter ImmediateClose or SilentClose.
  CHECK(!IsFlagSet(QUICSESSION_FLAG_CLOSING));
  SetFlag(QUICSESSION_FLAG_CLOSING);

  QuicError last_error = GetLastError();
  Debug(this, "Immediate close with code %" PRIu64 " (%s)",
        last_error.code,
        ErrorFamilyName(last_error.family));

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(last_error.code)),
    Integer::New(env()->isolate(), last_error.family)
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_session_close_function(), arraysize(argv), argv);
}

// Creates a new stream object and passes it off to the javascript side.
// This has to be called from within a handlescope/contextscope.
QuicStream* QuicSession::CreateStream(int64_t stream_id) {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  CHECK(!IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING));
  CHECK(!IsFlagSet(QUICSESSION_FLAG_CLOSING));

  BaseObjectPtr<QuicStream> stream = QuicStream::New(this, stream_id);
  CHECK(stream);
  Local<Value> argv[] = {
    stream->object(),
    Number::New(env()->isolate(), static_cast<double>(stream_id))
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_stream_ready_function(), arraysize(argv), argv);
  return stream.get();
}

// Mark the QuicSession instance destroyed. After this is called,
// the QuicSession instance will be generally unusable but most
// likely will not be immediately freed.
void QuicSession::Destroy() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;
  Debug(this, "Destroying");

  // If we're not in the closing or draining periods,
  // then we should at least attempt to send a connection
  // close to the peer.
  // TODO(@jasnell): If the connection close happens to occur
  // while we're still at the start of the TLS handshake, a
  // CONNECTION_CLOSE is not going to be sent because ngtcp2
  // currently does not yet support it. That will need to be
  // addressed.
  if (!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this) &&
      !IsInClosingPeriod() &&
      !IsInDrainingPeriod()) {
    Debug(this, "Making attempt to send a connection close");
    SetLastError(QUIC_ERROR_SESSION, NGTCP2_NO_ERROR);
    SendConnectionClose();
  }

  // Streams should have already been destroyed by this point.
  CHECK(streams_.empty());

  // Mark the session destroyed.
  SetFlag(QUICSESSION_FLAG_DESTROYED);
  SetFlag(QUICSESSION_FLAG_CLOSING, false);
  SetFlag(QUICSESSION_FLAG_GRACEFUL_CLOSING, false);

  // Stop and free the idle and retransmission timers if they are active.
  StopIdleTimer();
  StopRetransmitTimer();

  // The QuicSession instances are kept alive using
  // BaseObjectPtr. The only persistent BaseObjectPtr
  // is the map in the associated QuicSocket. Removing
  // the QuicSession from the QuicSocket will free
  // that pointer, allowing the QuicSession to be
  // deconstructed once the stack unwinds and any
  // remaining shared_ptr instances fall out of scope.
  RemoveFromSocket();
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
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  ssize_t nwrite = Decrypt(
      dest, destlen,
      ciphertext, ciphertextlen,
      &crypto_ctx_,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
  return nwrite >= 0 ?
      nwrite :
      static_cast<ssize_t>(NGTCP2_ERR_TLS_DECRYPT);
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
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  ssize_t nwrite = Encrypt(
      dest, destlen,
      plaintext, plaintextlen,
      &crypto_ctx_,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
  return nwrite >= 0 ?
      nwrite :
      static_cast<ssize_t>(NGTCP2_ERR_CALLBACK_FAILURE);
}

ssize_t QuicSession::DoHPMask(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  ssize_t nwrite = HP_Mask(
      dest, destlen,
      &crypto_ctx_,
      key, keylen,
      sample, samplelen);
  return nwrite >= 0 ?
      nwrite :
      static_cast<ssize_t>(NGTCP2_ERR_CALLBACK_FAILURE);
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
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);
  ssize_t nwrite = Decrypt(
      dest, destlen,
      ciphertext, ciphertextlen,
      &ctx,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
  return nwrite >= 0 ?
      nwrite :
      static_cast<ssize_t>(NGTCP2_ERR_TLS_DECRYPT);
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
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);
  ssize_t nwrite = Encrypt(
      dest, destlen,
      plaintext, plaintextlen,
      &ctx,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
  return nwrite >= 0 ?
      nwrite :
      static_cast<ssize_t>(NGTCP2_ERR_CALLBACK_FAILURE);
}

ssize_t QuicSession::DoInHPMask(
    uint8_t* dest,
    size_t destlen,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* sample,
    size_t samplelen) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  CryptoContext ctx;
  SetupInitialCryptoContext(&ctx);
  ssize_t nwrite = HP_Mask(
      dest, destlen,
      &ctx,
      key, keylen,
      sample, samplelen);
  return nwrite >= 0 ?
      nwrite :
      static_cast<ssize_t>(NGTCP2_ERR_CALLBACK_FAILURE);
}

void QuicSession::ExtendMaxStreamData(int64_t stream_id, uint64_t max_data) {
  Debug(this,
        "Extending max stream %" PRId64 " data to %" PRIu64,
        stream_id, max_data);
}

void QuicSession::ExtendMaxStreamsUni(uint64_t max_streams) {
  Debug(this, "Setting max unidirectional streams to %" PRIu64, max_streams);
  state_[IDX_QUIC_SESSION_STATE_MAX_STREAMS_UNI] =
      static_cast<double>(max_streams);
}

void QuicSession::ExtendMaxStreamsBidi(uint64_t max_streams) {
  Debug(this, "Setting max bidirectional streams to %" PRIu64, max_streams);
  state_[IDX_QUIC_SESSION_STATE_MAX_STREAMS_BIDI] =
      static_cast<double>(max_streams);
}

void QuicSession::ExtendStreamOffset(QuicStream* stream, size_t amount) {
  Debug(this, "Extending max stream %" PRId64 " offset by %d bytes",
        stream->GetID(), amount);
  ngtcp2_conn_extend_max_stream_offset(
      Connection(),
      stream->GetID(),
      amount);
}

// Copies the local transport params into the given struct for serialization.
void QuicSession::GetLocalTransportParams(ngtcp2_transport_params* params) {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  ngtcp2_conn_get_local_transport_params(Connection(), params);
}

// Gets the QUIC version negotiated for this QuicSession
uint32_t QuicSession::GetNegotiatedVersion() {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  return ngtcp2_conn_get_negotiated_version(Connection());
}

// Generates and associates a new connection ID for this QuicSession.
// ngtcp2 will call this multiple times at the start of a new connection
// in order to build a pool of available CIDs.
int QuicSession::GetNewConnectionID(
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen) {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  cid->datalen = cidlen;
  // cidlen shouldn't ever be zero here but just in case that
  // behavior changes in ngtcp2 in the future...
  if (cidlen > 0)
    EntropySource(cid->data, cidlen);
  EntropySource(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  AssociateCID(cid);
  return 0;
}

void QuicSession::HandleError() {
  sendbuf_.Cancel();
  if (!SendConnectionClose()) {
    SetLastError(QUIC_ERROR_SESSION, NGTCP2_ERR_INTERNAL);
    ImmediateClose();
  }
}

// The HandshakeCompleted function is called by ngtcp2 once it
// determines that the TLS Handshake is done. The only thing we
// need to do at this point is let the javascript side know.
void QuicSession::HandshakeCompleted() {
  session_stats_.handshake_completed_at = uv_hrtime();

  SetLocalCryptoLevel(NGTCP2_CRYPTO_LEVEL_APP);
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  const char* host_name =
      SSL_get_servername(
          ssl_.get(),
          TLSEXT_NAMETYPE_host_name);

  Local<Value> servername = GetServerName(env(), ssl_.get(), host_name);
  Local<Value> alpn = GetALPNProtocol(env(), ssl_.get());
  Local<Value> cipher = GetCipherName(env(), ssl_.get());
  Local<Value> version = GetCipherVersion(env(), ssl_.get());
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

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_session_handshake_function(),
               arraysize(argv),
               argv);
}

bool QuicSession::InitiateUpdateKey() {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_CLOSING));
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_KEYUPDATE));
  Debug(this, "Initiating a key update");
  return UpdateKey() && ngtcp2_conn_initiate_key_update(Connection()) == 0;
  // TODO(@jasnell): If we're not within a ngtcp2 callback when this is
  // called, we likely need to manually trigger a send operation. Need
  // to verify.
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
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  return ngtcp2_conn_get_handshake_completed(Connection());
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

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_session_keylog_function(), 1, &line_bf);
}

// When a QuicSession hits the idle timeout, it is to be silently and
// immediately closed without attempting to send any additional data to
// the peer. All existing streams are abandoned and closed.
void QuicSession::OnIdleTimeout() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;
  Debug(this, "Idle timeout");
  return SilentClose();
}

// Once OpenSSL adopts the BoringSSL QUIC apis (and we're able to pick those
// up) then we will get rx and tx keys in a single callback and this entire
// method will change. For now, we have to handle the keys one at a time,
// which is going to make working with the ngtcp2 api a bit more difficult
// since it's moving to a model where it assumes both rx and tx keys are
// available at the same time.
bool QuicSession::OnKey(int name, const uint8_t* secret, size_t secretlen) {
  typedef void (*install_fn)(ngtcp2_conn* conn,
                             size_t keylen,
                             size_t ivlen,
                             const SessionKey& key,
                             const SessionIV& iv,
                             const SessionKey& hp);
  std::vector<uint8_t>* client_secret;
  std::vector<uint8_t>* server_secret;
  install_fn install_server_handshake_key;
  install_fn install_client_handshake_key;
  install_fn install_server_key;
  install_fn install_client_key;
  SessionKey key;
  SessionIV iv;
  SessionKey hp;

  SetupCryptoContext(&crypto_ctx_, ssl());
  size_t keylen = aead_key_length(&crypto_ctx_);
  size_t ivlen = packet_protection_ivlen(&crypto_ctx_);

  switch (Side()) {
    case NGTCP2_CRYPTO_SIDE_SERVER:
      client_secret = &rx_secret_;
      server_secret = &tx_secret_;
      install_server_handshake_key = InstallHandshakeTXKeys;
      install_client_handshake_key = InstallHandshakeRXKeys;
      install_server_key = InstallTXKeys;
      install_client_key = InstallRXKeys;
      break;
    case NGTCP2_CRYPTO_SIDE_CLIENT:
      client_secret = &tx_secret_;
      server_secret = &rx_secret_;
      install_server_handshake_key = InstallHandshakeRXKeys;
      install_client_handshake_key = InstallHandshakeTXKeys;
      install_server_key = InstallRXKeys;
      install_client_key = InstallTXKeys;
      break;
    default:
      UNREACHABLE();
  }

  if (!DerivePacketProtectionKey(
          key.data(),
          iv.data(),
          hp.data(),
          &crypto_ctx_,
          secret,
          secretlen)) {
    return false;
  }
  ngtcp2_conn_set_aead_overhead(Connection(), aead_tag_length(&crypto_ctx_));

  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      InstallEarlyKeys(Connection(), keylen, ivlen, key, iv, hp);
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      install_client_handshake_key(Connection(), keylen, ivlen, key, iv, hp);
      SetClientCryptoLevel(NGTCP2_CRYPTO_LEVEL_HANDSHAKE);
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      client_secret->assign(secret, secret + secretlen);
      install_client_key(Connection(), keylen, ivlen, key, iv, hp);
      SetClientCryptoLevel(NGTCP2_CRYPTO_LEVEL_APP);
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      install_server_handshake_key(Connection(), keylen, ivlen, key, iv, hp);
      SetServerCryptoLevel(NGTCP2_CRYPTO_LEVEL_HANDSHAKE);
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      server_secret->assign(secret, secret + secretlen);
      install_server_key(Connection(), keylen, ivlen, key, iv, hp);
      SetServerCryptoLevel(NGTCP2_CRYPTO_LEVEL_APP);
    break;
  }

  return true;
}


void QuicSession::MaybeTimeout() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;
  uint64_t now = uv_hrtime();
  bool transmit = false;
  if (ngtcp2_conn_loss_detection_expiry(Connection()) <= now) {
    Debug(this, "Retransmitting due to loss detection");
    CHECK_EQ(ngtcp2_conn_on_loss_detection_timer(Connection(), now), 0);
    IncrementStat(
        1, &session_stats_,
        &session_stats::loss_retransmit_count);
    transmit = true;
  } else if (ngtcp2_conn_ack_delay_expiry(Connection()) <= now) {
    Debug(this, "Retransmitting due to ack delay");
    ngtcp2_conn_cancel_expired_ack_delay_timer(Connection(), now);
    IncrementStat(
        1, &session_stats_,
        &session_stats::ack_delay_retransmit_count);
    transmit = true;
  }
  if (transmit)
    SendPendingData();
}

bool QuicSession::OpenBidirectionalStream(int64_t* stream_id) {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_CLOSING));
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING));
  return ngtcp2_conn_open_bidi_stream(Connection(), stream_id, nullptr) == 0;
}

bool QuicSession::OpenUnidirectionalStream(int64_t* stream_id) {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_CLOSING));
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING));
  if (ngtcp2_conn_open_uni_stream(Connection(), stream_id, nullptr))
    return false;
  ngtcp2_conn_shutdown_stream_read(Connection(), *stream_id, 0);
  return true;
}

void QuicSession::PathValidation(
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res) {
  if (res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
    Debug(this,
          "Path validation succeeded. Updating local and remote addresses");
    SetLocalAddress(&path->local);
    remote_address_.Update(&path->remote);
    IncrementStat(
        1, &session_stats_,
        &session_stats::path_validation_success_count);
  } else {
    IncrementStat(
        1, &session_stats_,
        &session_stats::path_validation_failure_count);
  }

  // Only emit the callback if there is a handler for the pathValidation
  // event on the JavaScript QuicSession object.
  if (LIKELY(state_[IDX_QUIC_SESSION_STATE_PATH_VALIDATED_ENABLED] == 0))
    return;

  // This is a fairly expensive operation because both the local and
  // remote addresses have to converted into JavaScript objects. We
  // only do this if a pathValidation handler is registered.
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  Local<Value> argv[] = {
    Integer::New(env()->isolate(), res),
    AddressToJS(env(), reinterpret_cast<const sockaddr*>(path->local.addr)),
    AddressToJS(env(), reinterpret_cast<const sockaddr*>(path->remote.addr))
  };
  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(
      env()->quic_on_session_path_validation_function(),
      arraysize(argv),
      argv);
}

// Calling Ping will trigger the ngtcp2_conn to serialize any
// packets it currently has pending along with a probe frame
// that should keep the connection alive. This is a fire and
// forget and any errors that may occur will be ignored. The
// idle_timeout and retransmit timers will be updated. If Ping
// is called while processing an ngtcp2 callback, or if the
// closing or draining period has started, this is a non-op.
void QuicSession::Ping() {
  if (Ngtcp2CallbackScope::InNgtcp2CallbackScope(this) ||
      IsFlagSet(QUICSESSION_FLAG_DESTROYED) ||
      IsFlagSet(QUICSESSION_FLAG_CLOSING) ||
      IsInClosingPeriod() ||
      IsInDrainingPeriod()) {
    return;
  }
  // TODO(@jasnell): We might want to revisit whether to handle
  // errors right here. For now, we're ignoring them with the
  // intent of capturing them elsewhere.
  WritePackets("ping");
  UpdateIdleTimer();
  ScheduleRetransmit();
}

// Reads a chunk of received peer TLS handshake data for processing
size_t QuicSession::ReadPeerHandshake(uint8_t* buf, size_t buflen) {
  size_t n = std::min(buflen, peer_handshake_.size() - ncread_);
  std::copy_n(std::begin(peer_handshake_) + ncread_, n, buf);
  ncread_ += n;
  return n;
}

bool QuicSession::Receive(
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED)) {
    Debug(this, "Ignoring packet because session is destroyed");
    return false;
  }

  Debug(this, "Receiving QUIC packet.");
  IncrementStat(nread, &session_stats_, &session_stats::bytes_received);

  // Closing period starts once ngtcp2 has detected that the session
  // is being shutdown locally. Note that this is different that the
  // IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING) function, which
  // indicates a graceful shutdown that allows the session and streams
  // to finish naturally. When IsInClosingPeriod is true, ngtcp2 is
  // actively in the process of shutting down the connection and a
  // CONNECTION_CLOSE has already been sent. The only thing we can do
  // at this point is either ignore the packet or send another
  // CONNECTION_CLOSE.
  if (IsInClosingPeriod()) {
    Debug(this, "QUIC packet received while in closing period.");
    IncrementConnectionCloseAttempts();
    if (!ShouldAttemptConnectionClose()) {
      Debug(this, "Not sending connection close");
      return false;
    }
    Debug(this, "Sending connection close");
    return SendConnectionClose();
  }

  // When IsInDrainingPeriod is true, ngtcp2 has received a
  // connection close and we are simply discarding received packets.
  // No outbound packets may be sent. Return true here because
  // the packet was correctly processed, even tho it is being
  // ignored.
  if (IsInDrainingPeriod()) {
    Debug(this, "QUIC packet received while in draining period.");
    return true;
  }

  // It's possible for the remote address to change from one
  // packet to the next so we have to look at the addr on
  // every packet.
  remote_address_.Copy(addr);
  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  {
    // These are within a scope to ensure that the InternalCallbackScope
    // and HandleScope are both exited before continuing on with the
    // function. This allows any nextTicks and queued tasks to be processed
    // before we continue.
    Debug(this, "Processing received packet");
    HandleScope handle_scope(env()->isolate());
    InternalCallbackScope callback_scope(this);
    if (!ReceivePacket(&path, data, nread)) {
      if (initial_connection_close_ == NGTCP2_NO_ERROR) {
        Debug(this, "Failure processing received packet (code %" PRIu64 ")",
              GetLastError().code);
        HandleError();
        return false;
      } else {
        // When initial_connection_close_ is some value other than
        // NGTCP2_NO_ERROR, then the QuicSession is going to be
        // immediately responded to with a CONNECTION_CLOSE and
        // no additional processing will be performed.
        Debug(this, "Initial connection close with code %" PRIu64,
              initial_connection_close_);
        SetLastError(QUIC_ERROR_SESSION, initial_connection_close_);
        SendConnectionClose();
        return true;
      }
    }
  }

  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED)) {
    Debug(this, "Session was destroyed while processing the received packet");
    // If the QuicSession has been destroyed but it is not
    // in the closing period, a CONNECTION_CLOSE has not yet
    // been sent to the peer. Let's attempt to send one.
    if (!IsInClosingPeriod() && !IsInDrainingPeriod()) {
      Debug(this, "Attempting to send connection close");
      SetLastError(QUIC_ERROR_SESSION, NGTCP2_NO_ERROR);
      SendConnectionClose();
    }
    return true;
  }

  // Only send pending data if we haven't entered draining mode.
  // We enter the draining period when a CONNECTION_CLOSE has been
  // received from the remote peer.
  if (IsInDrainingPeriod()) {
    Debug(this, "In draining period after processing packet");
    // If processing the packet puts us into draining period, there's
    // absolutely nothing left for us to do except silently close
    // and destroy this QuicSession.
    SilentClose();
    return true;
  } else {
    Debug(this, "Sending pending data after processing packet");
    SendPendingData();
  }

  UpdateIdleTimer();
  UpdateRecoveryStats();
  Debug(this, "Successfully processed received packet");
  return true;
}

// Called by ngtcp2 when a chunk of peer TLS handshake data is received.
// For every chunk, we move the TLS handshake further along until it
// is complete.
int QuicSession::ReceiveCryptoData(
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  Debug(this, "Receiving %d bytes of crypto data.", datalen);

  int err = WritePeerHandshake(crypto_level, data, datalen);
  if (err < 0)
    return err;

  // If the handshake is not yet completed, incrementally advance
  // the handshake process.
  if (!IsHandshakeCompleted())
    return TLSHandshake();

  // It's possible that not all of the data was consumed. Anything
  // that's remaining needs to be read but is not used.
  return TLSRead();
}

// The ReceiveClientInitial function is called by ngtcp2 when
// a new connection has been initiated. The very first step to
// establishing a communication channel is to setup the keys
// that will be used to secure the communication.
bool QuicSession::ReceiveClientInitial(const ngtcp2_cid* dcid) {
  if (UNLIKELY(IsFlagSet(QUICSESSION_FLAG_DESTROYED)))
    return false;
  Debug(this, "Receiving client initial parameters.");
  return DeriveAndInstallInitialKey(
    Connection(),
    dcid,
    NGTCP2_CRYPTO_SIDE_SERVER) &&
    initial_connection_close_ == NGTCP2_NO_ERROR;
}

bool QuicSession::ReceivePacket(
    QuicPath* path,
    const uint8_t* data,
    ssize_t nread) {
  DCHECK(!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this));

  // If the QuicSession has been destroyed, we're not going
  // to process any more packets for it.
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return true;

  uint64_t now = uv_hrtime();
  session_stats_.session_received_at = now;
  int err = ngtcp2_conn_read_pkt(Connection(), **path, data, nread, now);
  if (err < 0) {
    switch (err) {
      case NGTCP2_ERR_DRAINING:
      case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
        break;
      default:
        SetLastError(QUIC_ERROR_SESSION, err);
        return false;
    }
  }
  return true;
}

// Called by ngtcp2 when a chunk of stream data has been received. If
// the stream does not yet exist, it is created, then the data is
// forwarded on.
void QuicSession::ReceiveStreamData(
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
    return;

  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;

  OnScopeLeave leave([&]() {
    // This extends the flow control window for the entire session
    // but not for the individual Stream. Stream flow control is
    // only expanded as data is read on the JavaScript side.
    ngtcp2_conn_extend_max_offset(Connection(), datalen);
  });

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  QuicStream* stream = FindStream(stream_id);
  if (stream == nullptr) {
    // Shutdown the stream explicitly if the session is being closed.
    if (IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING)) {
      ngtcp2_conn_shutdown_stream(Connection(), stream_id, NGTCP2_ERR_CLOSING);
      return;
    }

    // One potential DOS attack vector is to send a bunch of
    // empty stream frames to commit resources. Check that
    // here. Essentially, we only want to create a new stream
    // if the datalen is greater than 0, otherwise, we ignore
    // the packet.
    if (datalen == 0)
      return;

    stream = CreateStream(stream_id);
  }
  CHECK_NOT_NULL(stream);
  stream->ReceiveData(fin, data, datalen, offset);
}

// Removes the given connection id from the QuicSession.
void QuicSession::RemoveConnectionID(const ngtcp2_cid* cid) {
  if (!IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    DisassociateCID(cid);
}

// Removes the QuicSession from the current socket. This is
// done with when the session is being destroyed or being
// migrated to another QuicSocket. It is important to keep in mind
// that the QuicSocket uses a BaseObjectPtr for the QuicSession.
// If the session is removed and there are no other references held,
// the session object will be destroyed automatically.
void QuicSession::RemoveFromSocket() {
  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(Connection()));
  ngtcp2_conn_get_scid(Connection(), cids.data());

  for (auto &cid : cids) {
    QuicCID id(&cid);
    socket_->DisassociateCID(&id);
  }

  Debug(this, "Removed from the QuicSocket.");
  QuicCID scid(scid_);
  socket_->RemoveSession(&scid, **GetRemoteAddress());
  socket_.reset();
}

// Removes the given stream from the QuicSession. All streams must
// be removed before the QuicSession is destroyed.
void QuicSession::RemoveStream(int64_t stream_id) {
  Debug(this, "Removing stream %" PRId64, stream_id);

  // This will have the side effect of destroying the QuicStream
  // instance.
  streams_.erase(stream_id);
  // Ensure that the stream state is closed and discarded by ngtcp2
  // Be sure to call this after removing the stream from the map
  // above so that when ngtcp2 closes the stream, the callback does
  // not attempt to loop back around and destroy the already removed
  // QuicStream instance. Typically, the stream is already going to
  // be closed by this point.
  ngtcp2_conn_shutdown_stream(Connection(), stream_id, NGTCP2_NO_ERROR);
}

// Schedule the retransmission timer
void QuicSession::ScheduleRetransmit() {
  uint64_t now = uv_hrtime();
  uint64_t expiry = ngtcp2_conn_get_expiry(Connection());
  uint64_t interval = (expiry < now) ? 1 : ((expiry - now) / 1000000UL);
  Debug(this, "Scheduling the retransmit timer for %" PRIu64, interval);
  UpdateRetransmitTimer(interval);
}

void QuicSession::UpdateRetransmitTimer(uint64_t timeout) {
  DCHECK_NOT_NULL(retransmit_);
  retransmit_->Update(timeout);
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

int IsEmpty(const ngtcp2_vec* vec, size_t cnt) {
  size_t i;
  for (i = 0; i < cnt && vec[i].len == 0; ++i) {}
  return i == cnt;
}
}  // anonymous namespace

// Sends buffered stream data.
bool QuicSession::SendStreamData(QuicStream* stream) {
  // Because SendStreamData calls ngtcp2_conn_writev_streams,
  // it is not permitted to be called while we are running within
  // an ngtcp2 callback function.
  CHECK(!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this));

  // No stream data may be serialized and sent if:
  //   - the QuicSession is destroyed
  //   - the QuicStream was never writable,
  //   - a final stream frame has already been sent,
  //   - the QuicSession is in the draining period,
  //   - the QuicSession is in the closing period, or
  //   - we are blocked from sending any data because of flow control
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED) ||
      !stream->WasEverWritable() ||
      stream->HasSentFin() ||
      IsInDrainingPeriod() ||
      IsInClosingPeriod() ||
      ngtcp2_conn_get_max_data_left(Connection()) == 0) {
    return true;
  }

  ssize_t ndatalen = 0;
  QuicPathStorage path;

  std::vector<ngtcp2_vec> vec;

  // remaining is the total number of bytes stored in the vector
  // that are remaining to be serialized.
  size_t remaining = stream->DrainInto(&vec);
  Debug(stream, "Sending %d bytes of stream data. Still writable? %s",
        remaining,
        stream->IsWritable()?"yes":"no");

  // c and v are used to track the current serialization position
  // for each iteration of the for(;;) loop below.
  size_t c = vec.size();
  ngtcp2_vec* v = vec.data();

  // If there is no stream data and we're not sending fin,
  // Just return without doing anything.
  if (c == 0 && stream->IsWritable()) {
    Debug(stream, "There is no stream data to send");
    return true;
  }

  for (;;) {
    Debug(stream, "Starting packet serialization. Remaining? %d", remaining);
    MallocedBuffer<uint8_t> dest(max_pktlen_);
    ssize_t nwrite =
        ngtcp2_conn_writev_stream(
            Connection(),
            &path.path,
            dest.data,
            max_pktlen_,
            &ndatalen,
            NGTCP2_WRITE_STREAM_FLAG_NONE,
            stream->GetID(),
            stream->IsWritable() ? 0 : 1,
            reinterpret_cast<const ngtcp2_vec*>(v),
            c,
            uv_hrtime());

    if (nwrite <= 0) {
      switch (nwrite) {
        case 0:
          // If zero is returned, we've hit congestion limits. We need to stop
          // serializing data and try again later to empty the queue once the
          // congestion window has expanded.
          Debug(stream, "Congestion limit reached");
          return true;
        case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
          // There is a finite number of packets that can be sent
          // per connection. Once those are exhausted, there's
          // absolutely nothing we can do except immediately
          // and silently tear down the QuicSession. This has
          // to be silent because we can't even send a
          // CONNECTION_CLOSE since even those require a
          // packet number.
          SilentClose();
          return false;
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          Debug(stream, "Stream data blocked");
          return true;
        case NGTCP2_ERR_EARLY_DATA_REJECTED:
          Debug(stream, "Early data rejected");
          return true;
        case NGTCP2_ERR_STREAM_SHUT_WR:
          Debug(stream, "Stream writable side is closed");
          return true;
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          Debug(stream, "Stream does not exist");
          return true;
        default:
          Debug(stream, "Error writing packet. Code %" PRIu64, nwrite);
          SetLastError(QUIC_ERROR_SESSION, static_cast<int>(nwrite));
          return false;
      }
    }

    if (ndatalen > 0) {
      remaining -= ndatalen;
      Debug(stream,
            "%" PRIu64 " stream bytes serialized into packet. %d remaining",
            ndatalen,
            remaining);
      Consume(&v, &c, ndatalen);
      stream->Commit(ndatalen);
    }

    Debug(stream, "Sending %" PRIu64 " bytes in serialized packet", nwrite);
    dest.Realloc(nwrite);
    sendbuf_.Push(std::move(dest));
    remote_address_.Update(&path.path.remote);

    if (!SendPacket("stream data"))
      return false;

    if (IsEmpty(v, c)) {
      // fin will have been set if all of the data has been
      // encoded in the packet and IsWritable() returns false.
      if (!stream->IsWritable()) {
        Debug(stream, "Final stream has been sent");
        stream->SetFinSent();
      }
      break;
    }
  }

  return true;
}

// Transmits the current contents of the internal sendbuf_ to the peer.
bool QuicSession::SendPacket(const char* diagnostic_label) {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  CHECK(!IsInDrainingPeriod());
  // Move the contents of sendbuf_ to the tail of txbuf_ and reset sendbuf_
  if (sendbuf_.Length() > 0) {
    IncrementStat(
        sendbuf_.Length(),
        &session_stats_,
        &session_stats::bytes_sent);
    txbuf_ += std::move(sendbuf_);
  }
  // There's nothing to send, so let's not try
  if (txbuf_.Length() == 0)
    return true;
  Debug(this, "There are %" PRIu64 " bytes in txbuf_ to send", txbuf_.Length());
  session_stats_.session_sent_at = uv_hrtime();
  ScheduleRetransmit();
  int err = Socket()->SendPacket(
      *remote_address_,
      &txbuf_,
      BaseObjectPtr<QuicSession>(this),
      diagnostic_label);
  if (err != 0) {
    SetLastError(QUIC_ERROR_SESSION, err);
    return false;
  }
  return true;
}

// Sends any pending handshake or session packet data.
void QuicSession::SendPendingData() {
  // Do not proceed if:
  //  * We are in the ngtcp2 callback scope
  //  * The QuicSession has been destroyed
  //  * The QuicSession is in the draining period
  //  * The QuicSession is a server in the closing period
  if (Ngtcp2CallbackScope::InNgtcp2CallbackScope(this) ||
      IsFlagSet(QUICSESSION_FLAG_DESTROYED) ||
      IsInDrainingPeriod() ||
      (Side() == NGTCP2_CRYPTO_SIDE_SERVER && IsInClosingPeriod())) {
    return;
  }

  // If there's anything currently in the sendbuf_, send it before
  // serializing anything else.
  if (!SendPacket("pending session data"))
    return HandleError();

  // Try purging any pending stream data
  // TODO(@jasnell): Right now this iterates through the streams
  // in the order they were created. Later, we'll want to implement
  // a prioritization scheme to allow higher priority streams to
  // be serialized first.
  for (const auto& stream : streams_) {
    if (!SendStreamData(stream.second.get()))
      return HandleError();

    // Check to make sure QuicSession state did not change in this
    // iteration
    if (IsInDrainingPeriod() ||
        IsInClosingPeriod() ||
        IsFlagSet(QUICSESSION_FLAG_DESTROYED)) {
      return;
    }
  }

  // Otherwise, serialize and send any packets waiting in the queue.
  if (!WritePackets("pending session data - write packets"))
    HandleError();
}

// Notifies the ngtcp2_conn that the TLS handshake is completed.
void QuicSession::SetHandshakeCompleted() {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  ngtcp2_conn_handshake_completed(Connection());
}

void QuicSession::SetLocalAddress(const ngtcp2_addr* addr) {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  ngtcp2_conn_set_local_addr(Connection(), addr);
}

// Set the transport parameters received from the remote peer
int QuicSession::SetRemoteTransportParams(ngtcp2_transport_params* params) {
  DCHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  StoreRemoteTransportParams(params);
  return ngtcp2_conn_set_remote_transport_params(Connection(), params);
}

int QuicSession::ShutdownStream(int64_t stream_id, uint64_t code) {
  // First, update the internal ngtcp2 state of the given stream
  // and schedule the STOP_SENDING and RESET_STREAM frames as
  // appropriate.
  CHECK_EQ(
      ngtcp2_conn_shutdown_stream(
          Connection(),
          stream_id,
          code), 0);

  // If ShutdownStream is called outside of an ngtcp2 callback,
  // we need to trigger SendPendingData manually to cause the
  // RESET_STREAM and STOP_SENDING frames to be transmitted.
  if (!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this))
    SendPendingData();

  return 0;
}

// Silent Close must start with the JavaScript side, which must
// clean up state, abort any still existing QuicSessions, then
// destroy the handle when done. The most important characteristic
// of the SilentClose is that no frames are sent to the peer.
//
// When a valid stateless reset is received, the connection is
// immediately and unrecoverably closed at the ngtcp2 level.
// Specifically, it will be put into the draining_period so
// absolutely no frames can be sent. What we need to do is
// notify the JavaScript side and destroy the connection with
// a flag set that indicates stateless reset.
void QuicSession::SilentClose(bool stateless_reset) {
  // Calling either ImmediateClose or SilentClose will cause
  // the QUICSESSION_FLAG_CLOSING to be set. In either case,
  // we should never re-enter ImmediateClose or SilentClose.
  CHECK(!IsFlagSet(QUICSESSION_FLAG_CLOSING));
  SetFlag(QUICSESSION_FLAG_SILENT_CLOSE);
  SetFlag(QUICSESSION_FLAG_CLOSING);

  QuicError last_error = GetLastError();
  Debug(this,
        "Silent close with %s code %" PRIu64 " (stateless reset? %s)",
        ErrorFamilyName(last_error.family),
        last_error.code,
        stateless_reset ? "yes" : "no");

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  Local<Value> argv[] = {
    stateless_reset ? v8::True(env()->isolate()) : v8::False(env()->isolate()),
    Number::New(env()->isolate(), static_cast<double>(last_error.code)),
    Integer::New(env()->isolate(), last_error.family)
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(
      env()->quic_on_session_silent_close_function(), arraysize(argv), argv);
}

// Called by ngtcp2 when a stream has been closed. If the stream does
// not exist, the close is ignored.
void QuicSession::StreamClose(int64_t stream_id, uint64_t app_error_code) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;

  if (!HasStream(stream_id))
    return;

  Debug(this, "Closing stream %" PRId64 " with code %" PRIu64,
        stream_id,
        app_error_code);

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(stream_id)),
    Number::New(env()->isolate(), static_cast<double>(app_error_code))
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_stream_close_function(), arraysize(argv), argv);
}

void QuicSession::StopIdleTimer() {
  CHECK_NOT_NULL(idle_);
  idle_->Stop();
}

void QuicSession::StopRetransmitTimer() {
  CHECK_NOT_NULL(retransmit_);
  retransmit_->Stop();
}

// Called by ngtcp2 when a stream has been opened. All we do is log
// the activity here. We do not want to actually commit any resources
// until data is received for the stream. This allows us to prevent
// a stream commitment attack. The only exception is shutting the
// stream down explicitly if we are in a graceful close period.
void QuicSession::StreamOpen(int64_t stream_id) {
  if (IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING)) {
    ngtcp2_conn_shutdown_stream(
        Connection(),
        stream_id,
        NGTCP2_ERR_CLOSING);
  }
  Debug(this, "Stream %" PRId64 " opened but not yet created.", stream_id);
}

// Called when the QuicSession has received a RESET_STREAM frame from the
// peer, indicating that it will no longer send additional frames for the
// stream. If the stream is not yet known, reset is ignored. If the stream
// has already received a STREAM frame with fin set, the stream reset is
// ignored (the QUIC spec permits implementations to handle this situation
// however they want.) If the stream has not yet received a STREAM frame
// with the fin set, then the RESET_STREAM causes the readable side of the
// stream to be abruptly closed and any additional stream frames that may
// be received will be discarded if their offset is greater than final_size.
// On the JavaScript side, receiving a C is undistinguishable from
// a normal end-of-stream. No additional data events will be emitted, the
// end event will be emitted, and the readable side of the duplex will be
// closed.
//
// If the stream is still writable, no additional action is taken. If,
// however, the writable side of the stream has been closed (or was never
// open in the first place as in the case of peer-initiated unidirectional
// streams), the reset will cause the stream to be immediately destroyed.
void QuicSession::StreamReset(
    int64_t stream_id,
    uint64_t final_size,
    uint64_t app_error_code) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;

  if (!HasStream(stream_id))
    return;

  Debug(this,
        "Reset stream %" PRId64 " with code %" PRIu64
        " and final size %" PRIu64,
        stream_id,
        app_error_code,
        final_size);

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(stream_id)),
    Number::New(env()->isolate(), static_cast<double>(app_error_code)),
    Number::New(env()->isolate(), static_cast<double>(final_size))
  };
  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_stream_reset_function(), arraysize(argv), argv);
}

// Incrementally performs the TLS handshake. This function is called
// multiple times while handshake data is being passed back and forth
// between the peers.
int QuicSession::TLSHandshake() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return 0;

  ClearTLSError();

  int err;
  uint64_t now = uv_hrtime();
  if (!IsFlagSet(QUICSESSION_FLAG_INITIAL)) {
    Debug(this, "TLS handshake starting");
    session_stats_.handshake_start_at = now;
    err = TLSHandshake_Initial();
    if (err != 0)
      return err;
  } else {
    Debug(this, "TLS handshake continuing");
    uint64_t ts =
        session_stats_.handshake_continue_at > 0 ?
            session_stats_.handshake_continue_at :
            session_stats_.handshake_start_at;
    crypto_handshake_rate_->Record(now - ts);
  }
  session_stats_.handshake_continue_at = now;

  // If DoTLSHandshake returns 0 or negative, the handshake
  // is not yet complete.
  err = DoTLSHandshake(ssl());
  if (err <= 0)
    return err;

  err = TLSHandshake_Complete();
  if (err != 0)
    return err;

  Debug(this, "TLS Handshake completed.");
  SetHandshakeCompleted();
  return 0;
}

// It's possible for TLS handshake to contain extra data that is not
// consumed by ngtcp2. That's ok and the data is just extraneous. We just
// read it and throw it away, unless there's an error.
int QuicSession::TLSRead() {
  ClearTLSError();
  return ClearTLS(ssl(), Side() != NGTCP2_CRYPTO_SIDE_SERVER);
}

void QuicSession::UpdateIdleTimer() {
  CHECK_NOT_NULL(idle_);
  uint64_t timeout = ngtcp2_conn_get_idle_timeout(Connection()) / 1000000UL;
  Debug(this, "Updating idle timeout to %" PRIu64, timeout);
  idle_->Update(timeout);
}

void QuicSession::WriteHandshake(const uint8_t* data, size_t datalen) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;
  Debug(this, "Writing %d bytes of handshake data.", datalen);
  MallocedBuffer<uint8_t> buffer(datalen);
  memcpy(buffer.data, data, datalen);
  CHECK_EQ(
      ngtcp2_conn_submit_crypto_data(
          Connection(),
          tx_crypto_level_,
          buffer.data, datalen), 0);
  handshake_.Push(std::move(buffer));
}

// Write any packets current pending for the ngtcp2 connection based on
// the current state of the QuicSession. If the QuicSession is in the
// closing period, only CONNECTION_CLOSE packets may be written. If the
// QuicSession is in the draining period, no packets may be written.
//
// Packets are flushed to the underlying QuicSocket uv_udp_t as soon
// as they are written. The WritePackets method may cause zero or more
// packets to be serialized.
//
// If there are any acks or retransmissions pending, those will be
// serialized at this point as well. However, WritePackets does not
// serialize stream data that is being sent initially.
bool QuicSession::WritePackets(const char* diagnostic_label) {
  CHECK(!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this));
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));

  // During the draining period, we must not send any frames at all.
  if (IsInDrainingPeriod())
    return true;

  // During the closing period, we are only permitted to send
  // CONNECTION_CLOSE frames.
  if (IsInClosingPeriod())
    return SendConnectionClose();

  // Otherwise, serialize and send pending frames
  QuicPathStorage path;
  for (;;) {
    MallocedBuffer<uint8_t> data(max_pktlen_);
    ssize_t nwrite =
        ngtcp2_conn_write_pkt(
            Connection(),
            &path.path,
            data.data,
            max_pktlen_,
            uv_hrtime());
    if (nwrite <= 0) {
      switch (nwrite) {
        case 0:
          return true;
        case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
          // There is a finite number of packets that can be sent
          // per connection. Once those are exhausted, there's
          // absolutely nothing we can do except immediately
          // and silently tear down the QuicSession. This has
          // to be silent because we can't even send a
          // CONNECTION_CLOSE since even those require a
          // packet number.
          SilentClose();
          return false;
        default:
          SetLastError(QUIC_ERROR_SESSION, static_cast<int>(nwrite));
          return false;
      }
    }

    data.Realloc(nwrite);
    remote_address_.Update(&path.path.remote);
    sendbuf_.Push(std::move(data));
    if (!SendPacket(diagnostic_label))
      return false;
  }
}

// Writes peer handshake data to the internal buffer
int QuicSession::WritePeerHandshake(
    ngtcp2_crypto_level crypto_level,
    const uint8_t* data,
    size_t datalen) {
  if (rx_crypto_level_ != crypto_level)
    return NGTCP2_ERR_CRYPTO;
  if (peer_handshake_.size() + datalen > max_crypto_buffer_)
    return NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED;
  Debug(this, "Writing %d bytes of peer handshake data.", datalen);
  std::copy_n(data, datalen, std::back_inserter(peer_handshake_));
  return 0;
}

// Called by ngtcp2 when the QuicSession keys need to be updated. This may
// happen multiple times through the lifetime of the QuicSession.
bool QuicSession::UpdateKey() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return false;

  // There's no user code that should be able to run while UpdateKey
  // is running, but we need to gate on it just to be safe.
  OnScopeLeave leave([&]() { SetFlag(QUICSESSION_FLAG_KEYUPDATE, false); });
  CHECK(!IsFlagSet(QUICSESSION_FLAG_KEYUPDATE));
  SetFlag(QUICSESSION_FLAG_KEYUPDATE);
  Debug(this, "Updating keys.");

  IncrementStat(1, &session_stats_, &session_stats::keyupdate_count);

  return UpdateAndInstallKey(
      Connection(),
      &rx_secret_,
      &tx_secret_,
      rx_secret_.size(),
      &crypto_ctx_);
}


// QuicServerSession
QuicServerSession::InitialPacketResult QuicServerSession::Accept(
    ngtcp2_pkt_hd* hd,
    const uint8_t* data,
    ssize_t nread) {
  // The initial packet is too short and not a valid QUIC packet.
  if (static_cast<size_t>(nread) < MIN_INITIAL_QUIC_PKT_SIZE)
    return PACKET_IGNORE;

  switch (ngtcp2_accept(hd, data, nread)) {
    case -1:
      return PACKET_IGNORE;
    case 1:
      return PACKET_VERSION;
  }
  return PACKET_OK;
}

// The QuicServerSession specializes the QuicSession with server specific
// behaviors. The key differentiator between client and server lies with
// the TLS Handshake and certain aspects of stream state management.
// Fortunately, ngtcp2 takes care of most of the differences for us,
// so most of the overrides here deal with TLS handshake differences.
QuicServerSession::QuicServerSession(
    QuicSocket* socket,
    QuicSessionConfig* config,
    Local<Object> wrap,
    const ngtcp2_cid* rcid,
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version,
    const std::string& alpn,
    uint32_t options,
    uint64_t initial_connection_close) :
    QuicSession(
        NGTCP2_CRYPTO_SIDE_SERVER,
        socket,
        wrap,
        socket->GetServerSecureContext(),
        AsyncWrap::PROVIDER_QUICSERVERSESSION,
        alpn,
        options,
        initial_connection_close),
    rcid_(*rcid) {
  Init(config, addr, dcid, ocid, version);
}

BaseObjectPtr<QuicSession> QuicServerSession::New(
    QuicSocket* socket,
    QuicSessionConfig* config,
    const ngtcp2_cid* rcid,
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version,
    const std::string& alpn,
    uint32_t options,
    uint64_t initial_connection_close) {
  Local<Object> obj;
  if (!socket->env()
             ->quicserversession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return {};
  }
  BaseObjectPtr<QuicSession> session =
      MakeDetachedBaseObject<QuicServerSession>(
          socket,
          config,
          obj,
          rcid,
          addr,
          dcid,
          ocid,
          version,
          alpn,
          options,
          initial_connection_close);

  session->AddToSocket(socket);
  return session;
}


void QuicServerSession::AddToSocket(QuicSocket* socket) {
  QuicCID scid(scid_);
  QuicCID rcid(rcid_);
  socket->AddSession(&scid, BaseObjectPtr<QuicSession>(this));
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

void QuicServerSession::Init(
    QuicSessionConfig* config,
    const struct sockaddr* addr,
    const ngtcp2_cid* dcid,
    const ngtcp2_cid* ocid,
    uint32_t version) {

  CHECK_NULL(connection_);

  ExtendMaxStreamsBidi(config->max_streams_bidi());
  ExtendMaxStreamsUni(config->max_streams_uni());

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS();

  QuicSessionConfig cfg = *config;
  cfg.GenerateStatelessResetToken();
  cfg.GeneratePreferredAddressToken(pscid());
  max_crypto_buffer_ = cfg.GetMaxCryptoBuffer();

  EntropySource(scid_.data, NGTCP2_SV_SCIDLEN);
  scid_.datalen = NGTCP2_SV_SCIDLEN;

  QuicPath path(Socket()->GetLocalAddress(), &remote_address_);

  ngtcp2_conn* conn;
  CHECK_EQ(
      ngtcp2_conn_server_new(
          &conn,
          dcid,
          &scid_,
          *path,
          version,
          &callbacks,
          *cfg,
          &alloc_info_,
          static_cast<QuicSession*>(this)), 0);

  if (ocid)
    ngtcp2_conn_set_retry_ocid(conn, ocid);
  connection_.reset(conn);

  UpdateIdleTimer();
}

void QuicServerSession::InitTLS_Post() {
  SSL_set_accept_state(ssl());

  if (IsOptionSet(QUICSERVERSESSION_OPTION_REQUEST_CERT)) {
    int verify_mode = SSL_VERIFY_PEER;
    if (IsOptionSet(QUICSERVERSESSION_OPTION_REJECT_UNAUTHORIZED))
      verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_set_verify(ssl(), verify_mode, crypto::VerifyCallback);
  }
}

void QuicSessionOnClientHelloDone(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->OnClientHelloDone();
}

void QuicServerSession::OnClientHelloDone() {
  // Continue the TLS handshake when this function exits
  // otherwise it will stall and fail.
  TLSHandshakeScope handshake(this, QUICSESSION_FLAG_CLIENT_HELLO_CB_RUNNING);
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
  // must be called in order to turn QUICSESSION_FLAG_CLIENT_HELLO_CB_RUNNING
  // off. Once that callback is invoked, the TLS Handshake will resume.
  // It is recommended that the user not take a long time to invoke the
  // callback in order to avoid stalling out the QUIC connection.
  if (IsFlagSet(QUICSESSION_FLAG_CLIENT_HELLO_CB_RUNNING))
    return -1;

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  SetFlag(QUICSESSION_FLAG_CLIENT_HELLO_CB_RUNNING);

  const char* server_name = nullptr;
  const char* alpn = nullptr;
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
  OPENSSL_free(exts);

  Local<Value> argv[] = {
    Undefined(env()->isolate()),
    Undefined(env()->isolate()),
    GetClientHelloCiphers(env(), ssl())
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

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(
      env()->quic_on_session_client_hello_function(),
      arraysize(argv), argv);

  return IsFlagSet(QUICSESSION_FLAG_CLIENT_HELLO_CB_RUNNING) ? -1 : 0;
}

// This callback is invoked by user code after completing handling
// of the 'OCSPRequest' event. The callback is invoked with two
// possible arguments, both of which are optional
//   1. A replacement SecureContext
//   2. An OCSP response
void QuicSessionOnCertDone(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicServerSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  Local<FunctionTemplate> cons = env->secure_context_constructor_template();
  crypto::SecureContext* context = nullptr;
  if (args[0]->IsObject() && cons->HasInstance(args[0]))
    context = Unwrap<crypto::SecureContext>(args[0].As<Object>());
  session->OnCertDone(context, args[1]);
}

// The OnCertDone function is called by the QuicSessionOnCertDone
// function when usercode is done handling the OCSPRequest event.
void QuicServerSession::OnCertDone(
    crypto::SecureContext* context,
    Local<Value> ocsp_response) {
  Debug(this, "OCSPRequest completed. Context Provided? %s, OCSP Provided? %s",
        context != nullptr ? "Yes" : "No",
        ocsp_response->IsArrayBufferView() ? "Yes" : "No");
  // Continue the TLS handshake when this function exits
  // otherwise it will stall and fail.
  TLSHandshakeScope handshake_scope(this, QUICSESSION_FLAG_CERT_CB_RUNNING);
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
  if (IsFlagSet(QUICSESSION_FLAG_CERT_CB_RUNNING))
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

  SetFlag(QUICSESSION_FLAG_CERT_CB_RUNNING);
  Local<Value> argv[] = {
    servername == nullptr ?
        String::Empty(env()->isolate()) :
        OneByteString(
            env()->isolate(),
            servername,
            strlen(servername))
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_session_cert_function(), arraysize(argv), argv);

  return IsFlagSet(QUICSESSION_FLAG_CERT_CB_RUNNING) ? -1 : 1;
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

void QuicSession::UpdateRecoveryStats() {
  ngtcp2_rcvry_stat stat;
  ngtcp2_conn_get_rcvry_stat(Connection(), &stat);
  recovery_stats_.min_rtt = static_cast<double>(stat.min_rtt);
  recovery_stats_.latest_rtt = static_cast<double>(stat.latest_rtt);
  recovery_stats_.smoothed_rtt = static_cast<double>(stat.smoothed_rtt);
}

// The QuicSocket maintains a map of BaseObjectPtr's that keep
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
  CHECK(!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this));

  // Do not send any frames at all if we're in the draining period
  // or in the middle of a silent close
  if (IsInDrainingPeriod() || IsFlagSet(QUICSESSION_FLAG_SILENT_CLOSE))
    return true;

  // If we're not already in the closing period,
  // first attempt to write any pending packets, then
  // start the closing period. If closing period has
  // already started, skip this.
  if (!IsInClosingPeriod() &&
      (!WritePackets("server connection close - write packets") ||
       !StartClosingPeriod())) {
      return false;
  }

  UpdateIdleTimer();
  CHECK_GT(conn_closebuf_.size, 0);
  sendbuf_.Cancel();
  // We don't use std::move here because we do not want
  // to reset conn_closebuf_. Instead, we keep it around
  // so we can send it again if we have to.
  uv_buf_t buf =
      uv_buf_init(
          reinterpret_cast<char*>(conn_closebuf_.data),
          conn_closebuf_.size);
  sendbuf_.Push(&buf, 1);
  return SendPacket("server connection close");
}

bool QuicServerSession::StartClosingPeriod() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return false;
  if (IsInClosingPeriod())
    return true;

  StopRetransmitTimer();
  UpdateIdleTimer();

  sendbuf_.Cancel();

  QuicError error = GetLastError();
  Debug(this, "Closing period has started. Error %d", error.code);

  // Once the CONNECTION_CLOSE packet is written,
  // IsInClosingPeriod will return true.
  conn_closebuf_ = MallocedBuffer<uint8_t>(max_pktlen_);
  ssize_t nwrite =
      SelectCloseFn(error.family)(
          Connection(),
          nullptr,
          conn_closebuf_.data,
          max_pktlen_,
          error.code,
          uv_hrtime());
  if (nwrite < 0) {
    if (nwrite == NGTCP2_ERR_PKT_NUM_EXHAUSTED)
      SilentClose();
    else
      SetLastError(QUIC_ERROR_SESSION, static_cast<int>(nwrite));
    return false;
  }
  conn_closebuf_.Realloc(nwrite);
  return true;
}

int QuicServerSession::TLSHandshake_Initial() {
  SetFlag(QUICSESSION_FLAG_INITIAL);
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
    SelectPreferredAddressPolicy select_preferred_address_policy,
    const std::string& alpn,
    uint32_t options) :
    QuicSession(
        NGTCP2_CRYPTO_SIDE_CLIENT,
        socket,
        wrap,
        context,
        AsyncWrap::PROVIDER_QUICCLIENTSESSION,
        alpn,
        options),
    version_(version),
    port_(port),
    select_preferred_address_policy_(select_preferred_address_policy),
    hostname_(hostname) {
  CHECK(Init(addr, version, early_transport_params, session_ticket, dcid));
}

BaseObjectPtr<QuicSession> QuicClientSession::New(
    QuicSocket* socket,
    const struct sockaddr* addr,
    uint32_t version,
    SecureContext* context,
    const char* hostname,
    uint32_t port,
    Local<Value> early_transport_params,
    Local<Value> session_ticket,
    Local<Value> dcid,
    SelectPreferredAddressPolicy select_preferred_address_policy,
    const std::string& alpn,
    uint32_t options) {
  Local<Object> obj;
  if (!socket->env()
             ->quicclientsession_constructor_template()
             ->NewInstance(socket->env()->context()).ToLocal(&obj)) {
    return {};
  }

  BaseObjectPtr<QuicSession> session =
      MakeDetachedBaseObject<QuicClientSession>(
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
          options);

  session->AddToSocket(socket);
  session->TLSHandshake();
  return session;
}

void QuicClientSession::AddToSocket(QuicSocket* socket) {
  QuicCID scid(scid_);
  socket->AddSession(&scid, BaseObjectPtr<QuicSession>(this));

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(Connection()));
  ngtcp2_conn_get_scid(Connection(), cids.data());
  for (const ngtcp2_cid& cid : cids) {
    QuicCID id(&cid);
    socket->AssociateCID(&id, &scid);
  }
}

void QuicClientSession::VersionNegotiation(
      const ngtcp2_pkt_hd* hd,
      const uint32_t* sv,
      size_t nsv) {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return;
  HandleScope scope(env()->isolate());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);

  Local<Array> versions = Array::New(env()->isolate(), nsv);
  for (size_t n = 0; n < nsv; n++) {
    USE(versions->Set(
        env()->context(), n,
        Integer::New(env()->isolate(), sv[n])));
  }

  Local<Array> supportedVersions = Array::New(env()->isolate(), 1);
  USE(supportedVersions->Set(
      env()->context(), 0,
      Integer::New(env()->isolate(), NGTCP2_PROTO_VER)));

  Local<Value> argv[] = {
    Integer::New(env()->isolate(), version_),
    versions,
    supportedVersions
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(
      env()->quic_on_session_version_negotiation_function(),
      arraysize(argv), argv);
}

void QuicClientSession::HandleError() {
  if (connection_ && !IsInClosingPeriod()) {
    QuicSession::HandleError();
  }
}

bool QuicClientSession::Init(
    const struct sockaddr* addr,
    uint32_t version,
    Local<Value> early_transport_params,
    Local<Value> session_ticket,
    Local<Value> dcid_value) {

  CHECK_NULL(connection_);

  remote_address_.Copy(addr);
  max_pktlen_ = SocketAddress::GetMaxPktLen(addr);

  InitTLS();

  QuicSessionConfig config(env());
  max_crypto_buffer_ = config.GetMaxCryptoBuffer();
  ExtendMaxStreamsBidi(config.max_streams_bidi());
  ExtendMaxStreamsUni(config.max_streams_uni());

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

  ngtcp2_conn* conn;
  CHECK_EQ(
      ngtcp2_conn_client_new(
          &conn,
          &dcid,
          &scid_,
          *path,
          version,
          &callbacks,
          *config,
          &alloc_info_,
          static_cast<QuicSession*>(this)), 0);

  connection_.reset(conn);

  CHECK(SetupInitialCryptoContext());

  // Remote Transport Params
  if (early_transport_params->IsArrayBufferView()) {
    if (SetEarlyTransportParams(early_transport_params)) {
      Debug(this, "Using provided early transport params.");
      SetOption(QUICCLIENTSESSION_OPTION_RESUME);
    } else {
      Debug(this, "Ignoring invalid early transport params.");
    }
  }

  // Session Ticket
  if (session_ticket->IsArrayBufferView()) {
    if (SetSession(session_ticket)) {
      Debug(this, "Using provided session ticket.");
      SetOption(QUICCLIENTSESSION_OPTION_RESUME);
    } else {
      Debug(this, "Ignoring provided session ticket.");
    }
  }

  UpdateIdleTimer();
  return true;
}

bool QuicClientSession::SelectPreferredAddress(
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr) {
  switch (select_preferred_address_policy_) {
    case QUIC_PREFERRED_ADDRESS_ACCEPT: {
      SocketAddress* local_address = Socket()->GetLocalAddress();
      uv_getaddrinfo_t req;

      if (!SocketAddress::ResolvePreferredAddress(
              env(), local_address->GetFamily(),
              paddr, &req)) {
        return false;
      }

      if (req.addrinfo == nullptr)
        return false;

      dest->addrlen = req.addrinfo->ai_addrlen;
      memcpy(dest->addr, req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);
      uv_freeaddrinfo(req.addrinfo);
      break;
    }
    case QUIC_PREFERRED_ADDRESS_IGNORE:
      // Fall-through
      break;
  }
  return true;
}

int QuicClientSession::SetSession(SSL_SESSION* session) {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
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

  AllocatedBuffer session_ticket = env()->AllocateManaged(size);
  unsigned char* session_data =
    reinterpret_cast<unsigned char*>(session_ticket.data());
  memset(session_data, 0, size);
  i2d_SSL_SESSION(session, &session_data);
  if (!session_ticket.empty())
    argv[1] = session_ticket.ToBuffer().ToLocalChecked();

  if (transportParams_.length() > 0) {
    argv[2] = Buffer::New(
        env(),
        *transportParams_,
        transportParams_.length(),
        [](char* data, void* hint) {}, nullptr).ToLocalChecked();
  }
  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_session_ticket_function(), arraysize(argv), argv);

  return 1;
}

bool QuicClientSession::SetSocket(QuicSocket* socket, bool nat_rebinding) {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
  CHECK(!IsFlagSet(QUICSESSION_FLAG_GRACEFUL_CLOSING));
  if (socket == nullptr || socket == socket_.get())
    return true;

  // Step 1: Add this Session to the given Socket
  AddToSocket(socket);

  // Step 2: Remove this Session from the current Socket
  RemoveFromSocket();

  // Step 3: Update the internal references
  socket_.reset(socket);
  socket->ReceiveStart();

  // Step 4: Update ngtcp2
  SocketAddress* local_address = socket->GetLocalAddress();
  if (nat_rebinding) {
    ngtcp2_addr addr = local_address->ToAddr();
    ngtcp2_conn_set_local_addr(Connection(), &addr);
  } else {
    QuicPath path(local_address, &remote_address_);
    if (ngtcp2_conn_initiate_migration(
            Connection(),
            *path,
            uv_hrtime()) != 0) {
      return false;
    }
  }

  SendPendingData();
  return true;
}

void QuicClientSession::StoreRemoteTransportParams(
    ngtcp2_transport_params* params) {
  CHECK(!IsFlagSet(QUICSESSION_FLAG_DESTROYED));
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
  if (IsOptionSet(QUICCLIENTSESSION_OPTION_REQUEST_OCSP)) {
    Debug(this, "Request OCSP status from the server.");
    SSL_set_tlsext_status_type(ssl(), TLSEXT_STATUSTYPE_ocsp);
  }
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
  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<QuicSession> ptr(this);
  MakeCallback(env()->quic_on_session_status_function(), 1, &arg);
  return 1;
}

// A HelloRetry will effectively restart the TLS handshake process
// by generating new initial crypto material.
bool QuicClientSession::ReceiveRetry() {
  if (IsFlagSet(QUICSESSION_FLAG_DESTROYED))
    return false;
  Debug(this, "A retry packet was received. Restarting the handshake.");
  IncrementStat(1, &session_stats_, &session_stats::retry_count);
  return SetupInitialCryptoContext();
}

// Transmits either a protocol or application connection
// close to the peer. The choice of which is send is
// based on the current value of last_error_.
bool QuicClientSession::SendConnectionClose() {
  CHECK(!Ngtcp2CallbackScope::InNgtcp2CallbackScope(this));

  // Do not send any frames if we are in the draining period or
  // if we're in middle of a silent close
  if (IsInDrainingPeriod() || IsFlagSet(QUICSESSION_FLAG_SILENT_CLOSE))
    return true;

  UpdateIdleTimer();
  MallocedBuffer<uint8_t> data(max_pktlen_);
  sendbuf_.Cancel();
  QuicError error = GetLastError();

  if (!WritePackets("client connection close - write packets"))
    return false;

  ssize_t nwrite =
      SelectCloseFn(error.family)(
        Connection(),
        nullptr,
        data.data,
        max_pktlen_,
        error.code,
        uv_hrtime());
  if (nwrite < 0) {
    Debug(this, "Error writing connection close: %d", nwrite);
    SetLastError(QUIC_ERROR_SESSION, static_cast<int>(nwrite));
    return false;
  }
  data.Realloc(nwrite);
  sendbuf_.Push(std::move(data));
  return SendPacket("client connection close");
}

// When resuming a client session, the serialized transport parameters from
// the prior session must be provided. This is set during construction
// of the QuicClientSession object.
bool QuicClientSession::SetEarlyTransportParams(Local<Value> buffer) {
  ArrayBufferViewContents<uint8_t> sbuf(buffer.As<ArrayBufferView>());
  ngtcp2_transport_params params;
  if (sbuf.length() != sizeof(ngtcp2_transport_params))
    return false;
  memcpy(&params, sbuf.data(), sizeof(ngtcp2_transport_params));
  ngtcp2_conn_set_early_remote_transport_params(Connection(), &params);
  return true;
}

// When resuming a client session, the serialized session ticket from
// the prior session must be provided. This is set during construction
// of the QuicClientSession object.
bool QuicClientSession::SetSession(Local<Value> buffer) {
  ArrayBufferViewContents<unsigned char> sbuf(buffer.As<ArrayBufferView>());
  const unsigned char* p = sbuf.data();
  crypto::SSLSessionPointer s(d2i_SSL_SESSION(nullptr, &p, sbuf.length()));
  return s != nullptr && SSL_set_session(ssl_.get(), s.get()) == 1;
}

// The TLS handshake kicks off when the QuicClientSession is created.
// The very first step is to setup the initial crypto context on the
// client side by creating the initial keying material.
bool QuicClientSession::SetupInitialCryptoContext() {
  Debug(this, "Setting up initial crypto context");
  return DeriveAndInstallInitialKey(
      Connection(),
      ngtcp2_conn_get_dcid(Connection()),
      NGTCP2_CRYPTO_SIDE_CLIENT);
}

int QuicClientSession::TLSHandshake_Complete() {
  if (IsOptionSet(QUICCLIENTSESSION_OPTION_RESUME) &&
      SSL_get_early_data_status(ssl()) != SSL_EARLY_DATA_ACCEPTED) {
    Debug(this, "Early data was rejected.");
    int err = ngtcp2_conn_early_data_rejected(Connection());
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
  if (IsOptionSet(QUICCLIENTSESSION_OPTION_RESUME) &&
      SSL_SESSION_get_max_early_data(SSL_get_session(ssl()))) {
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
  SetFlag(QUICSESSION_FLAG_INITIAL);
  return 0;
}

int QuicClientSession::VerifyPeerIdentity(const char* hostname) {
  // First, check that the certificate is signed by an entity the client
  // trusts (as configured in the secure context). If not, return early.
  int err = VerifyPeerCertificate(ssl());
  if (err)
    return err;

  // Second, check that the hostname matches the cert subject/altnames
  // This check is a QUIC requirement. However, for debugging purposes,
  // we allow it to be turned off via config. When turned off, a process
  // warning should be emitted.
  if (LIKELY(IsOptionSet(QUICCLIENTSESSION_OPTION_VERIFY_HOSTNAME_IDENTITY))) {
    return VerifyHostnameIdentity(
        ssl(),
        hostname != nullptr ? hostname : hostname_.c_str());
  }
  return 0;
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->TLSHandshake() == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

// Called by ngtcp2 for a new server connection when the initial
// crypto handshake from the client has been received.
int QuicSession::OnReceiveClientInitial(
    ngtcp2_conn* conn,
    const ngtcp2_cid* dcid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->ReceiveClientInitial(dcid) ?
      0 : NGTCP2_ERR_CALLBACK_FAILURE;
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return static_cast<int>(
    session->ReceiveCryptoData(crypto_level, offset, data, datalen));
}

// Called by ngtcp2 for a client connection when the server has
// sent a retry packet.
int QuicSession::OnReceiveRetry(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_hd* hd,
    const ngtcp2_pkt_retry* retry,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->ReceiveRetry() ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

// Called by ngtcp2 for both client and server connections
// when a request to extend the maximum number of bidirectional
// streams has been received.
int QuicSession::OnExtendMaxStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->ExtendMaxStreamsBidi(max_streams);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->ExtendMaxStreamsUni(max_streams);
  return 0;
}

int QuicSession::OnExtendMaxStreamData(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t max_data,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->DoHSEncrypt(
      dest, destlen,
      plaintext, plaintextlen,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->DoHSDecrypt(
      dest, destlen,
      ciphertext, ciphertextlen,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->DoEncrypt(
      dest, destlen,
      plaintext, plaintextlen,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->DoDecrypt(
      dest, destlen,
      ciphertext, ciphertextlen,
      key, keylen,
      nonce, noncelen,
      ad, adlen);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->DoInHPMask(
      dest, destlen,
      key, keylen,
      sample, samplelen);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->DoHPMask(
      dest, destlen,
      key, keylen,
      sample, samplelen);
}

// Called by ngtcp2 when a chunk of stream data has been received.
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->ReceiveStreamData(stream_id, fin, data, datalen, offset);
  return 0;
}

// Called by ngtcp2 when a new stream has been opened
int QuicSession::OnStreamOpen(
    ngtcp2_conn* conn,
    int64_t stream_id,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->StreamOpen(stream_id);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->AckedCryptoOffset(datalen);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->SelectPreferredAddress(dest, paddr) ?
      0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

// Called by ngtcp2 when a stream has been closed for any reason.
int QuicSession::OnStreamClose(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->StreamClose(stream_id, app_error_code);
  return 0;
}

int QuicSession::OnStreamReset(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t final_size,
    uint64_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->GetNewConnectionID(cid, token, cidlen);
  return 0;
}

// Called by ngtcp2 to trigger a key update for the connection.
int QuicSession::OnUpdateKey(
    ngtcp2_conn* conn,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  return session->UpdateKey() ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

// When a connection is closed, ngtcp2 will call this multiple
// times to remove connection IDs.
int QuicSession::OnRemoveConnectionID(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
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
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->PathValidation(path, res);
  return 0;
}

int QuicSession::OnVersionNegotiation(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_hd* hd,
    const uint32_t* sv,
    size_t nsv,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  QuicSession::Ngtcp2CallbackScope callback_scope(session);
  session->VersionNegotiation(hd, sv, nsv);
  return 0;
}

void QuicSession::OnKeylog(const SSL* ssl, const char* line) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  session->Keylog(line);
}

int QuicSession::OnStatelessReset(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_stateless_reset* sr,
    void* user_data) {
  QuicSession* session = static_cast<QuicSession*>(user_data);
  session->SilentClose(true);
  return 0;
}

const ngtcp2_conn_callbacks QuicServerSession::callbacks = {
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
  OnStatelessReset,
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

const ngtcp2_conn_callbacks QuicClientSession::callbacks = {
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
  OnStatelessReset,
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

// Perform an immediate close on the QuicSession, causing a
// CONNECTION_CLOSE frame to be scheduled and sent and starting
// the closing period for this session. The name "ImmediateClose"
// is a bit of an unfortunate misnomer as the session will not
// be immediately shutdown. The naming is pulled from the QUIC
// spec to indicate a state where the session immediately enters
// the closing period, but the session will not be destroyed
// until either the idle timeout fires or destroy is explicitly
// called.
void QuicSessionClose(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  int family = QUIC_ERROR_SESSION;
  uint64_t code = ExtractErrorCode(env, args[0]);
  if (!args[1]->Int32Value(env->context()).To(&family)) return;
  session->SetLastError(static_cast<QuicErrorFamily>(family), code);
  session->SendConnectionClose();
}

// GracefulClose flips a flag that prevents new local streams
// from being opened and new remote streams from being received. It is
// important to note that this does *NOT* send a CONNECTION_CLOSE packet
// to the peer. Existing streams are permitted to close gracefully.
void QuicSessionGracefulClose(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->StartGracefulClose();
}

// Destroying the QuicSession will trigger sending of a CONNECTION_CLOSE
// packet, after which the QuicSession will be immediately torn down.
void QuicSessionDestroy(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  int code = 0;
  int family = QUIC_ERROR_SESSION;
  if (!args[0]->Int32Value(env->context()).To(&code)) return;
  if (!args[1]->Int32Value(env->context()).To(&family)) return;
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
      session->Side() == NGTCP2_CRYPTO_SIDE_SERVER ?
          SSL_get_peer_certificate(session->ssl()) : nullptr);
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

void QuicSessionPing(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Ping();
}

void QuicSessionUpdateKey(const FunctionCallbackInfo<Value>& args) {
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  args.GetReturnValue().Set(session->InitiateUpdateKey());
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
  if (!args[10]->Int32Value(env->context())
      .To(&select_preferred_address_policy)) return;

  std::string alpn(NGTCP2_ALPN_H3);
  if (args[11]->IsString()) {
    Utf8Value val(env->isolate(), args[11]);
    alpn = val.length();
    alpn += *val;
  }

  uint32_t options = QUICCLIENTSESSION_OPTION_VERIFY_HOSTNAME_IDENTITY;
  if (!args[12]->Uint32Value(env->context()).To(&options)) return;

  socket->ReceiveStart();

  BaseObjectPtr<QuicSession> session =
      QuicClientSession::New(
          socket,
          const_cast<const sockaddr*>(reinterpret_cast<sockaddr*>(&addr)),
          NGTCP2_PROTO_VER, sc,
          *servername,
          port,
          args[7],
          args[8],
          args[9],
          static_cast<SelectPreferredAddressPolicy>
              (select_preferred_address_policy),
          alpn,
          options);

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
  env->SetProtoMethod(session, "getPeerCertificate",
                      QuicSessionGetPeerCertificate);
  env->SetProtoMethod(session, "gracefulClose", QuicSessionGracefulClose);
  env->SetProtoMethod(session, "updateKey", QuicSessionUpdateKey);
  env->SetProtoMethod(session, "ping", QuicSessionPing);
  env->SetProtoMethod(session, "onClientHelloDone",
                      QuicSessionOnClientHelloDone);
  env->SetProtoMethod(session, "onCertDone", QuicSessionOnCertDone);
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
