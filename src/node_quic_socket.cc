#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "nghttp2/nghttp2.h"
#include "node.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "node_quic_crypto.h"
#include "node_quic_session-inl.h"
#include "node_quic_socket.h"
#include "node_quic_util.h"
#include "util.h"
#include "uv.h"
#include "v8.h"

#include <random>

namespace node {

using crypto::EntropySource;
using crypto::SecureContext;

using v8::Boolean;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::PropertyAttribute;
using v8::String;
using v8::Value;

namespace quic {

namespace {
inline uint32_t GenerateReservedVersion(
    const sockaddr* addr,
    uint32_t version) {
  socklen_t addrlen = SocketAddress::GetAddressLen(addr);
  uint32_t h = 0x811C9DC5u;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);
  const uint8_t* ep = p + addrlen;
  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }
  version = htonl(version);
  p =  reinterpret_cast<const uint8_t*>(&version);
  ep = p + sizeof(version);
  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }
  h &= 0xf0f0f0f0u;
  h |= 0x0a0a0a0au;
  return h;
}
}  // namespace

QuicSocket::QuicSocket(
    Environment* env,
    Local<Object> wrap,
    uint64_t retry_token_expiration,
    size_t max_connections_per_host,
    uint32_t options) :
    HandleWrap(env, wrap,
               reinterpret_cast<uv_handle_t*>(&handle_),
               AsyncWrap::PROVIDER_QUICSOCKET),
    flags_(QUICSOCKET_FLAGS_NONE),
    options_(options),
    pending_callbacks_(0),
    max_connections_per_host_(max_connections_per_host),
    current_ngtcp2_memory_(0),
    retry_token_expiration_(retry_token_expiration),
    rx_loss_(0.0),
    tx_loss_(0.0),
    server_secure_context_(nullptr),
    server_alpn_(NGTCP2_ALPN_H3),
    token_crypto_ctx_{},
    stats_buffer_(
      env->isolate(),
      sizeof(socket_stats_) / sizeof(uint64_t),
      reinterpret_cast<uint64_t*>(&socket_stats_)) {
  CHECK_EQ(uv_udp_init(env->event_loop(), &handle_), 0);
  Debug(this, "New QuicSocket created.");

  SetupTokenContext(&token_crypto_ctx_);
  EntropySource(token_secret_.data(), token_secret_.size());
  socket_stats_.created_at = uv_hrtime();

  USE(wrap->DefineOwnProperty(
      env->context(),
      env->stats_string(),
      stats_buffer_.GetJSArray(),
      PropertyAttribute::ReadOnly));
}

QuicSocket::~QuicSocket() {
  CHECK(sessions_.empty());
  CHECK(dcid_to_scid_.empty());
  uint64_t now = uv_hrtime();
  Debug(this,
        "QuicSocket destroyed.\n"
        "  Duration: %" PRIu64 "\n"
        "  Bound Duration: %" PRIu64 "\n"
        "  Listen Duration: %" PRIu64 "\n"
        "  Bytes Received: %" PRIu64 "\n"
        "  Bytes Sent: %" PRIu64 "\n"
        "  Packets Received: %" PRIu64 "\n"
        "  Packets Sent: %" PRIu64 "\n"
        "  Packets Ignored: %" PRIu64 "\n"
        "  Server Sessions: %" PRIu64 "\n"
        "  Client Sessions: %" PRIu64 "\n",
        now - socket_stats_.created_at,
        socket_stats_.bound_at > 0 ? now - socket_stats_.bound_at : 0,
        socket_stats_.listen_at > 0 ? now - socket_stats_.listen_at : 0,
        socket_stats_.bytes_received,
        socket_stats_.bytes_sent,
        socket_stats_.packets_received,
        socket_stats_.packets_sent,
        socket_stats_.packets_ignored,
        socket_stats_.server_sessions,
        socket_stats_.client_sessions);
}

void QuicSocket::MemoryInfo(MemoryTracker* tracker) const {
  // TODO(@jasnell): Implement memory tracking information
}

void QuicSocket::AddSession(
    QuicCID* cid,
    std::shared_ptr<QuicSession> session) {
  sessions_[cid->ToStr()] = session;
  IncrementSocketAddressCounter(**session->GetRemoteAddress());
  IncrementSocketStat(
      1, &socket_stats_,
      session->Type() == QUICSESSION_TYPE_SERVER ?
          &socket_stats::server_sessions :
          &socket_stats::client_sessions);
}

void QuicSocket::AssociateCID(
    QuicCID* cid,
    QuicCID* scid) {
  dcid_to_scid_.emplace(cid->ToStr(), scid->ToStr());
}

int QuicSocket::Bind(
    const char* address,
    uint32_t port,
    uint32_t flags,
    int family) {
  Debug(this,
        "Binding to address %s, port %d, with flags %d, and family %d",
        address, port, flags, family);

  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  sockaddr_storage addr;
  int err = SocketAddress::ToSockAddr(family, address, port, &addr);
  if (err != 0)
    return err;

  Local<Value> arg = Undefined(env()->isolate());

  err =
      uv_udp_bind(
          &handle_,
          reinterpret_cast<const sockaddr*>(&addr),
          flags);
  if (err != 0) {
    Debug(this, "Bind failed. Error %d", err);
    arg = Integer::New(env()->isolate(), err);
    MakeCallback(env()->quic_on_socket_error_function(), 1, &arg);
    return 0;
  }

  local_address_.Set(&handle_);

#if !defined(_WIN32)
  int fd = UV_EBADF;
  uv_fileno(reinterpret_cast<uv_handle_t*>(&handle_), &fd);
  if (fd != UV_EBADF)
    arg = Integer::New(env()->isolate(), fd);
#endif

  MakeCallback(env()->quic_on_socket_ready_function(), 1, &arg);
  socket_stats_.bound_at = uv_hrtime();
  return 0;
}

// If there are no pending QuicSocket::SendWrap callbacks, the
// QuicSocket instance will be closed immediately and the
// close callback will be invoked. Otherwise, the QuicSocket
// will be marked as pending close and will close as soon as
// the final remaining QuicSocket::SendWrap callback is invoked.
// This design ensures that packets that have been sent down to
// the libuv level are processed even tho we are shutting down.
//
// TODO(@jasnell): We will want to implement an additional function
// that will close things down immediately, canceling any still
// pending operations.
void QuicSocket::Close(Local<Value> close_callback) {
  if (!IsInitialized() || IsFlagSet(QUICSOCKET_FLAGS_PENDING_CLOSE))
    return;
  SetFlag(QUICSOCKET_FLAGS_PENDING_CLOSE);
  Debug(this, "Closing");

  CHECK_EQ(false, persistent().IsEmpty());
  if (!close_callback.IsEmpty() && close_callback->IsFunction()) {
    object()->Set(env()->context(),
                  env()->handle_onclose_symbol(),
                  close_callback).Check();
  }

  // Attempt to close immediately.
  MaybeClose();
}

// A QuicSocket can close if there are no pending udp send
// callbacks and QuicSocket::Close() has been called.
void QuicSocket::MaybeClose() {
  if (!IsInitialized() ||
      !IsFlagSet(QUICSOCKET_FLAGS_PENDING_CLOSE) ||
      HasPendingCallbacks())
    return;

  CHECK_EQ(false, persistent().IsEmpty());

  Debug(this, "Closing the libuv handle");

  // Close the libuv handle first. The OnClose handler
  // will free the QuicSocket instance after it invokes
  // the close callback, letting the JavaScript side know
  // that the handle is being freed.
  uv_close(GetHandle(), OnClose);
  MarkAsClosing();
}


void QuicSocket::DisassociateCID(QuicCID* cid) {
  Debug(this, "Removing associations for cid %s", cid->ToHex().c_str());
  dcid_to_scid_.erase(cid->ToStr());
}

void QuicSocket::Listen(
    SecureContext* sc,
    const sockaddr* preferred_address,
    const std::string& alpn,
    uint32_t options) {
  CHECK_NOT_NULL(sc);
  CHECK_NULL(server_secure_context_);
  CHECK(!IsFlagSet(QUICSOCKET_FLAGS_SERVER_LISTENING));
  Debug(this, "Starting to listen.");
  server_session_config_.Set(env(), preferred_address);
  server_secure_context_ = sc;
  server_alpn_ = alpn;
  server_options_ = options;
  SetFlag(QUICSOCKET_FLAGS_SERVER_LISTENING);
  socket_stats_.listen_at = uv_hrtime();
  ReceiveStart();
}

// StopListening is called when the QuicSocket is no longer
// accepting new server connections. Typically, this is called
// when the QuicSocket enters a graceful closing state where
// existing sessions are allowed to close naturally but new
// sessions are rejected.
void QuicSocket::StopListening() {
  if (!IsFlagSet(QUICSOCKET_FLAGS_SERVER_LISTENING))
    return;
  Debug(this, "Stop listening.");
  SetFlag(QUICSOCKET_FLAGS_SERVER_LISTENING, false);
}

void QuicSocket::OnAlloc(
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf) {
  buf->base = node::Malloc(suggested_size);
  buf->len = suggested_size;
}

void QuicSocket::OnRecv(
    uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const struct sockaddr* addr,
    unsigned int flags) {
  OnScopeLeave on_scope_leave([&]() {
    if (buf->base != nullptr)
      free(buf->base);
  });

  QuicSocket* socket = static_cast<QuicSocket*>(handle->data);
  CHECK_NOT_NULL(socket);

  if (nread == 0)
    return;

  if (nread < 0) {
    Debug(socket, "Reading data from UDP socket failed. Error %d", nread);
    Environment* env = socket->env();
    HandleScope scope(env->isolate());
    Context::Scope context_scope(env->context());
    Local<Value> arg = Number::New(env->isolate(), static_cast<double>(nread));
    socket->MakeCallback(env->quic_on_socket_error_function(), 1, &arg);
    return;
  }

  socket->Receive(nread, buf, addr, flags);
}

void QuicSocket::Receive(
    ssize_t nread,
    const uv_buf_t* buf,
    const struct sockaddr* addr,
    unsigned int flags) {
  Debug(this, "Receiving %d bytes from the UDP socket.", nread);

  // When diagnostic packet loss is enabled, the packet will be randomly
  // dropped based on the rx_loss_ probability.
  if (UNLIKELY(IsDiagnosticPacketLoss(rx_loss_))) {
    Debug(this, "Simulating received packet loss.");
    return;
  }

  IncrementSocketStat(nread, &socket_stats_, &socket_stats::bytes_received);

  const uint8_t* data = reinterpret_cast<const uint8_t*>(buf->base);

  uint32_t pversion;
  const uint8_t* pdcid;
  size_t pdcidlen;
  const uint8_t* pscid;
  size_t pscidlen;

  if (ngtcp2_pkt_decode_version_cid(
        &pversion,
        &pdcid,
        &pdcidlen,
        &pscid,
        &pscidlen,
        data, nread, NGTCP2_SV_SCIDLEN) < 0) {
    // There's nothing we can do here but ignore the packet. The packet
    // is likely not a QUIC packet or is malformed in some way.
    IncrementSocketStat(1, &socket_stats_, &socket_stats::packets_ignored);
    return;
  }

  if (pdcidlen > NGTCP2_MAX_CIDLEN || pscidlen > NGTCP2_MAX_CIDLEN) {
    // QUIC currently requires CID lengths of max NGTCP2_MAX_CIDLEN. The
    // ngtcp2 API allows non-standard lengths, and we may want to allow
    // non-standard lengths later. But for now, we're going to ignore any
    // packet with a non-standard CID length.
    IncrementSocketStat(1, &socket_stats_, &socket_stats::packets_ignored);
    return;
  }

  QuicCID dcid(pdcid, pdcidlen);
  QuicCID scid(pscid, pscidlen);

  auto dcid_hex = dcid.ToHex();
  auto dcid_str = dcid.ToStr();
  Debug(this, "Received a QUIC packet for dcid %s", dcid_hex.c_str());

  // Grabbing a shared pointer to prevent the QuicSession from
  // desconstructing while we're still using it. The session may
  // end up being destroyed, however, so we have to make sure
  // we're checking for that.
  std::shared_ptr<QuicSession> session;

  // Identify the appropriate handler
  auto session_it = sessions_.find(dcid_str);
  if (session_it == std::end(sessions_)) {
    auto scid_it = dcid_to_scid_.find(dcid_str);
    if (scid_it == std::end(dcid_to_scid_)) {
      Debug(this, "There is no existing session for dcid %s", dcid_hex.c_str());

      // TODO(@jasnell): If the DCID was previously known, and there is a
      // known stateless reset token, then we should we ought to be able
      // to send a stateless reset at this point. It's likely that the
      // endpoint crashed and the peer is still trying to send data.
      // Currently, however, we don't keep track of previously used CID's
      // and their reset tokens so we can't implement this yet. A proper
      // implementation will track CIDs and reset tokens but only across
      // a single restart. These will be associated with the local address
      // (that is, a QuicSocket bound to one local port should never use
      // the CIDs and reset tokens from a QuicSocket bound to another).
      // It's not entirely clear how this should be implemented.

      // AcceptInitialPacket will first validate that the packet can be
      // accepted, then create a new QuicServerSession instance if able
      // to do so. If a new instance cannot be created (for any reason),
      // the session shared_ptr will be empty on return.
      session = AcceptInitialPacket(
          pversion,
          &dcid,
          &scid,
          nread,
          data,
          addr,
          flags);

      // There are many reasons why a QuicServerSession could not be
      // created. The most common will be invalid packets or incorrect
      // QUIC version. In any of these cases, however, to prevent a
      // potential attacker from causing us to consume resources,
      // we're just going to ignore the packet. It is possible that
      // the AcceptInitialPacket sent a version negotiation packet,
      // or (in the future) a CONNECTION_CLOSE packet.
      if (!session) {
        Debug(this, "Could not initialize a new QuicServerSession.");
        IncrementSocketStat(1, &socket_stats_, &socket_stats::packets_ignored);
        return;
      }
    } else {
      session_it = sessions_.find((*scid_it).second);
      session = (*session_it).second;
      CHECK_NE(session_it, std::end(sessions_));
    }
  } else {
    session = (*session_it).second;
  }

  CHECK_NOT_NULL(session);

  // If the packet could not successfully processed for any reason (possibly
  // due to being malformed or malicious in some way) we ignore it completely.
  if (!session->Receive(nread, data, addr, flags)) {
    IncrementSocketStat(1, &socket_stats_, &socket_stats::packets_ignored);
    return;
  }

  IncrementSocketStat(1, &socket_stats_, &socket_stats::packets_received);
}

int QuicSocket::ReceiveStart() {
  int err = uv_udp_recv_start(&handle_, OnAlloc, OnRecv);
  if (err == UV_EALREADY)
    err = 0;
  return err;
}

int QuicSocket::ReceiveStop() {
  return uv_udp_recv_stop(&handle_);
}

void QuicSocket::RemoveSession(QuicCID* cid, const sockaddr* addr) {
  sessions_.erase(cid->ToStr());
  DecrementSocketAddressCounter(addr);
}

void QuicSocket::ReportSendError(int error) {
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  Local<Value> arg = Integer::New(env()->isolate(), error);
  MakeCallback(env()->quic_on_socket_error_function(), 1, &arg);
  return;
}

void QuicSocket::SendInitialConnectionClose(
    uint32_t version,
    uint64_t error_code,
    QuicCID* dcid,
    const sockaddr* addr) {

  // ngtcp2 currently does not provide a convenient API for serializing
  // CONNECTION_CLOSE packets on an initial frame that does not have
  // a ngtcp2_conn initialized, so we have to create one with a simple
  // default configuration and use it to serialize the frame.

  ngtcp2_cid scid;
  EntropySource(scid.data, NGTCP2_SV_SCIDLEN);
  scid.datalen = NGTCP2_SV_SCIDLEN;

  SocketAddress remote_address;
  remote_address.Copy(addr);
  QuicPath path(GetLocalAddress(), &remote_address);

  ngtcp2_conn_callbacks callbacks;

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);

  mem::Allocator<ngtcp2_mem> allocator(this);

  ngtcp2_conn* conn;
  ngtcp2_conn_server_new(
    &conn,
    **dcid,
    &scid,
    *path,
    version,
    &callbacks,
    &settings,
    *allocator,
    nullptr);

  SendWrapStack* req =
      new SendWrapStack(
          this,
          addr,
          NGTCP2_MAX_PKTLEN_IPV6,
          "initial cc");

  ssize_t nwrite =
      ngtcp2_conn_write_connection_close(
          conn,
          *path,
          req->buffer(),
          NGTCP2_MAX_PKTLEN_IPV6,
          error_code,
          uv_hrtime());

  // Be sure the delete the connection pointer once the connection frame
  // is serialized. We won't be using this one any longer.
  ngtcp2_conn_del(conn);

  if (nwrite > 0) {
    req->SetLength(nwrite);
    req->Send();
  }
}

void QuicSocket::SendVersionNegotiation(
      uint32_t version,
      QuicCID* dcid,
      QuicCID* scid,
      const sockaddr* addr) {
  SendWrapStack* req =
      new SendWrapStack(
          this,
          addr,
          NGTCP2_MAX_PKTLEN_IPV6,
          "version negotiation");

  std::array<uint32_t, 2> sv;
  sv[0] = GenerateReservedVersion(addr, version);
  sv[1] = NGTCP2_PROTO_VER;

  uint8_t unused_random;
  EntropySource(&unused_random, 1);

  ssize_t nwrite = ngtcp2_pkt_write_version_negotiation(
      req->buffer(),
      NGTCP2_MAX_PKTLEN_IPV6,
      unused_random,
      dcid->data(),
      dcid->length(),
      scid->data(),
      scid->length(),
      sv.data(),
      sv.size());
  if (nwrite < 0)
    return;
  req->SetLength(nwrite);
  req->Send();
}

ssize_t QuicSocket::SendRetry(
    uint32_t version,
    QuicCID* dcid,
    QuicCID* scid,
    const sockaddr* addr) {
  SendWrapStack* req =
      new SendWrapStack(
          this,
          addr,
          NGTCP2_MAX_PKTLEN_IPV6,
          "retry");

  std::array<uint8_t, 256> token;
  size_t tokenlen = token.size();

  if (!GenerateRetryToken(
          token.data(), &tokenlen,
          addr,
          **dcid,
          &token_crypto_ctx_,
          &token_secret_)) {
    return -1;
  }

  ngtcp2_pkt_hd hd;
  hd.version = version;
  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.type = NGTCP2_PKT_RETRY;
  hd.pkt_num = 0;
  hd.token = nullptr;
  hd.tokenlen = 0;
  hd.len = 0;
  hd.dcid = ***scid;
  hd.scid.datalen = NGTCP2_SV_SCIDLEN;

  EntropySource(hd.scid.data, NGTCP2_SV_SCIDLEN);

  ssize_t nwrite =
      ngtcp2_pkt_write_retry(
          req->buffer(),
          NGTCP2_MAX_PKTLEN_IPV4,
          &hd,
          **dcid,
          token.data(),
          tokenlen);
  if (nwrite <= 0)
    return nwrite;
  req->SetLength(nwrite);

  return req->Send();
}

namespace {
  SocketAddress::Hash addr_hash;
};

void QuicSocket::SetValidatedAddress(const sockaddr* addr) {
  if (IsOptionSet(QUICSOCKET_OPTIONS_VALIDATE_ADDRESS_LRU)) {
    // Remove the oldest item if we've hit the LRU limit
    validated_addrs_.push_back(addr_hash(addr));
    if (validated_addrs_.size() > MAX_VALIDATE_ADDRESS_LRU)
      validated_addrs_.pop_front();
  }
}

bool QuicSocket::IsValidatedAddress(const sockaddr* addr) {
  if (IsOptionSet(QUICSOCKET_OPTIONS_VALIDATE_ADDRESS_LRU)) {
    auto res = std::find(std::begin(validated_addrs_),
                         std::end(validated_addrs_),
                         addr_hash((addr)));
    return res != std::end(validated_addrs_);
  }
  return false;
}

std::shared_ptr<QuicSession> QuicSocket::AcceptInitialPacket(
    uint32_t version,
    QuicCID* dcid,
    QuicCID* scid,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {
  std::shared_ptr<QuicSession> session;
  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  ngtcp2_pkt_hd hd;
  ngtcp2_cid ocid;
  ngtcp2_cid* ocid_ptr = nullptr;
  uint64_t initial_connection_close = NGTCP2_NO_ERROR;

  if (!IsFlagSet(QUICSOCKET_FLAGS_SERVER_LISTENING)) {
    Debug(this, "QuicSocket is not listening");
    return session;
  }

  // Perform some initial checks on the packet to see if it is an
  // acceptable initial packet with the right QUIC version.
  switch (QuicServerSession::Accept(&hd, data, nread)) {
    case QuicServerSession::InitialPacketResult::PACKET_VERSION:
      SendVersionNegotiation(version, dcid, scid, addr);
      // Fall-through to ignore packet
    case QuicServerSession::InitialPacketResult::PACKET_IGNORE:
      return session;
    case QuicServerSession::InitialPacketResult::PACKET_OK:
      // Fall-through
      break;
  }

  // If the server is busy, new connections will be shut down immediately
  // after the initial keys are installed.
  if (IsFlagSet(QUICSOCKET_FLAGS_SERVER_BUSY)) {
    Debug(this, "QuicSocket is busy");
    initial_connection_close = NGTCP2_SERVER_BUSY;
  }

  // Check to see if the number of connections for this peer has been exceeded.
  // If the count has been exceeded, shutdown the connection immediately
  // after the initial keys are installed.
  if (GetCurrentSocketAddressCounter(addr) >= max_connections_per_host_) {
    Debug(this, "Connection count for address exceeded");
    initial_connection_close = NGTCP2_SERVER_BUSY;
  }

  // QUIC has address validation built in to the handshake but allows for
  // an additional explicit validation request using RETRY frames. If we
  // are using explicit validation, we check for the existence of a valid
  // retry token in the packet. If one does not exist, we send a retry with
  // a new token. If it does exist, and if it's valid, we grab the original
  // cid and continue.
  //
  // If initial_connection_close is not NGTCP2_NO_ERROR, skip address
  // validation since we're going to reject the connection anyway.
  if (initial_connection_close == NGTCP2_NO_ERROR &&
      IsOptionSet(QUICSOCKET_OPTIONS_VALIDATE_ADDRESS) &&
      hd.type == NGTCP2_PKT_INITIAL) {
      // If the VALIDATE_ADDRESS_LRU option is set, IsValidatedAddress
      // will check to see if the given address is in the validated_addrs_
      // LRU cache. If it is, we'll skip the validation step entirely.
      // The VALIDATE_ADDRESS_LRU option is disable by default.
    if (!IsValidatedAddress(addr)) {
      Debug(this, "Performing explicit address validation.");
      if (InvalidRetryToken(
              env(),
              &ocid,
              &hd,
              addr,
              &token_crypto_ctx_,
              &token_secret_,
              retry_token_expiration_)) {
        Debug(this, "A valid retry token was not found. Sending retry.");
        SendRetry(version, dcid, scid, addr);
        return session;
      }
      Debug(this, "A valid retry token was found. Continuing.");
      SetValidatedAddress(addr);
      ocid_ptr = &ocid;
    } else {
      Debug(this, "Skipping validation for recently validated address.");
    }
  }

  session =
      QuicServerSession::New(
          this,
          &server_session_config_,
          **dcid,
          addr,
          **scid,
          ocid_ptr,
          version,
          server_alpn_,
          server_options_,
          initial_connection_close);
  Local<Value> arg = session->object();
  MakeCallback(env()->quic_on_session_ready_function(), 1, &arg);

  // The above MakeCallback will notify the JavaScript side that a new
  // QuicServerSession has been created in an event emitted on nextTick.
  // The user may destroy() the QuicServerSession in that event but that
  // won't impact the code here.

  return session;
}

void QuicSocket::IncrementSocketAddressCounter(const sockaddr* addr) {
  addr_counts_[addr]++;
}

void QuicSocket::DecrementSocketAddressCounter(const sockaddr* addr) {
  auto it = addr_counts_.find(addr);
  if (it == std::end(addr_counts_))
    return;
  it->second--;
  // Remove the address if the counter reaches zero again.
  if (it->second == 0)
    addr_counts_.erase(addr);
}

size_t QuicSocket::GetCurrentSocketAddressCounter(const sockaddr* addr) {
  auto it = addr_counts_.find(addr);
  if (it == std::end(addr_counts_))
    return 0;
  return (*it).second;
}

void QuicSocket::SetServerBusy(bool on) {
  Debug(this, "Turning Server Busy Response %s", on ? "on" : "off");
  SetFlag(QUICSOCKET_FLAGS_SERVER_BUSY, on);

  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  Local<Value> arg = Boolean::New(env()->isolate(), on);
  MakeCallback(env()->quic_on_socket_server_busy_function(), 1, &arg);
}

int QuicSocket::SetTTL(int ttl) {
  Debug(this, "Setting UDP TTL to %d", ttl);
  return uv_udp_set_ttl(&handle_, ttl);
}

int QuicSocket::SetMulticastTTL(int ttl) {
  Debug(this, "Setting UDP Multicast TTL to %d", ttl);
  return uv_udp_set_multicast_ttl(&handle_, ttl);
}

int QuicSocket::SetBroadcast(bool on) {
  Debug(this, "Turning UDP Broadcast %s", on ? "on" : "off");
  return uv_udp_set_broadcast(&handle_, on ? 1 : 0);
}

int QuicSocket::SetMulticastLoopback(bool on) {
  Debug(this, "Turning UDP Multicast Loopback %s", on ? "on" : "off");
  return uv_udp_set_multicast_loop(&handle_, on ? 1 : 0);
}

int QuicSocket::SetMulticastInterface(const char* iface) {
  Debug(this, "Setting the UDP Multicast Interface to %s", iface);
  return uv_udp_set_multicast_interface(&handle_, iface);
}

int QuicSocket::AddMembership(const char* address, const char* iface) {
  Debug(this, "Joining UDP group: address %s, iface %s", address, iface);
  return uv_udp_set_membership(&handle_, address, iface, UV_JOIN_GROUP);
}

int QuicSocket::DropMembership(const char* address, const char* iface) {
  Debug(this, "Leaving UDP group: address %s, iface %s", address, iface);
  return uv_udp_set_membership(&handle_, address, iface, UV_LEAVE_GROUP);
}

int QuicSocket::SendPacket(
    const sockaddr* dest,
    QuicBuffer* buffer,
    std::shared_ptr<QuicSession> session,
    const char* diagnostic_label) {
  // If there is no data in the buffer,
  // or no data remaining to be read,
  // do nothing to avoid allocating
  // a SendWrap...
  if (buffer->Length() == 0 || buffer->RemainingLength() == 0)
    return 0;

  char* host;
  SocketAddress::GetAddress(dest, &host);
  Debug(this, "Sending to %s at port %d", host, SocketAddress::GetPort(dest));

  QuicSocket::SendWrap* wrap =
      new QuicSocket::SendWrap(
          this,
          dest,
          buffer,
          session,
          diagnostic_label);
  return wrap->Send();
}

void QuicSocket::OnSend(
    int status,
    size_t length,
    const char* diagnostic_label) {
  IncrementSocketStat(
    length,
    &socket_stats_,
    &socket_stats::bytes_sent);
  IncrementSocketStat(
    1,
    &socket_stats_,
    &socket_stats::packets_sent);

  Debug(this, "Packet sent status: %d (label: %s)",
        status,
        diagnostic_label != nullptr ? diagnostic_label : "unspecified");

  DecrementPendingCallbacks();
  MaybeClose();
}

QuicSocket::SendWrapBase::SendWrapBase(
    QuicSocket* socket,
    const sockaddr* dest,
    const char* diagnostic_label) :
    socket_(socket),
    diagnostic_label_(diagnostic_label) {
  req_.data = this;
  address_.Copy(dest);
  socket->IncrementPendingCallbacks();
}


void QuicSocket::SendWrapBase::OnSend(uv_udp_send_t* req, int status) {
  std::unique_ptr<QuicSocket::SendWrapBase> wrap(
      static_cast<QuicSocket::SendWrapBase*>(req->data));
  wrap->Done(status);
}

bool QuicSocket::SendWrapBase::IsDiagnosticPacketLoss() {
  if (Socket()->IsDiagnosticPacketLoss(Socket()->tx_loss_)) {
    Debug(Socket(), "Simulating transmitted packet loss.");
    Done(0);
    return true;
  }
  return false;
}

void QuicSocket::SendWrapBase::Done(int status) {
  socket_->OnSend(status, Length(), diagnostic_label());
}

QuicSocket::SendWrapStack::SendWrapStack(
    QuicSocket* socket,
    const sockaddr* dest,
    size_t len,
    const char* diagnostic_label) :
    SendWrapBase(socket, dest, diagnostic_label) {
  buf_.AllocateSufficientStorage(len);
}

int QuicSocket::SendWrapStack::Send() {
  Debug(Socket(), "Sending %" PRIu64 " bytes (label: %s)",
        buf_.length(),
        diagnostic_label());

  CHECK_GT(buf_.length(), 0);

  // If DiagnosticPacketLoss returns true, it will call Done() internally
  if (UNLIKELY(IsDiagnosticPacketLoss()))
    return 0;

  uv_buf_t buf =
      uv_buf_init(
          reinterpret_cast<char*>(*buf_),
          buf_.length());

  return uv_udp_send(
      req(),
      &Socket()->handle_,
      &buf, 1,
      **Address(),
      OnSend);
}

// The QuicSocket::SendWrap will maintain a std::weak_ref
// pointer to the buffer given to it.
QuicSocket::SendWrap::SendWrap(
    QuicSocket* socket,
    SocketAddress* dest,
    QuicBuffer* buffer,
    std::shared_ptr<QuicSession> session,
    const char* diagnostic_label) :
    SendWrapBase(socket, **dest, diagnostic_label),
    buffer_(buffer),
    session_(session) {}

QuicSocket::SendWrap::SendWrap(
    QuicSocket* socket,
    const sockaddr* dest,
    QuicBuffer* buffer,
    std::shared_ptr<QuicSession> session,
    const char* diagnostic_label) :
    SendWrapBase(socket, dest, diagnostic_label),
    buffer_(buffer),
    session_(session) {}

void QuicSocket::SendWrap::Done(int status) {
  // If the weak_ref to the QuicBuffer is still valid
  // consume the data, otherwise, do nothing
  if (status == 0) {
    Debug(Socket(), "Consuming %" PRId64 " bytes (label: %s)",
          length_,
          diagnostic_label());
    buffer_->Consume(length_);
  } else {
    Debug(Socket(), "Cancelling %" PRId64 " bytes (status: %d, label: %s)",
          length_,
          status,
          diagnostic_label());
    buffer_->Cancel(status);
  }
  SendWrapBase::Done(status);
}

// Sending will take the current content of the QuicBuffer
// and forward it off to the uv_udp_t handle.
int QuicSocket::SendWrap::Send() {
  // Remaining Length should never be zero at this point
  CHECK_GT(buffer_->RemainingLength(), 0);

  std::vector<uv_buf_t> vec;
  size_t len = buffer_->DrainInto(&vec, &length_);

  // len should never be zero
  CHECK_GT(len, 0);

  Debug(Socket(),
        "Sending %" PRIu64 " bytes (label: %s)",
        length_,
        diagnostic_label());

  // If DiagnosticPacketLoss returns true, it will call Done() internally
  if (UNLIKELY(IsDiagnosticPacketLoss()))
    return 0;

  int err = uv_udp_send(
      req(),
      &(Socket()->handle_),
      vec.data(),
      vec.size(),
      **Address(),
      OnSend);

  if (err == 0) {
    Debug(Socket(), "Advancing read head %" PRIu64, length_);
    buffer_->SeekHeadOffset(length_);
  }
  return err;
}



bool QuicSocket::IsDiagnosticPacketLoss(double prob) {
  if (LIKELY(prob == 0.0)) return false;
  unsigned char c = 255;
  EntropySource(&c, 1);
  return (static_cast<double>(c) / 255) < prob;
}

void QuicSocket::SetDiagnosticPacketLoss(double rx, double tx) {
  rx_loss_ = rx;
  tx_loss_ = tx;
}

inline void QuicSocket::CheckAllocatedSize(size_t previous_size) {
  CHECK_GE(current_ngtcp2_memory_, previous_size);
}

inline void QuicSocket::IncrementAllocatedSize(size_t size) {
  current_ngtcp2_memory_ += size;
}

inline void QuicSocket::DecrementAllocatedSize(size_t size) {
  current_ngtcp2_memory_ -= size;
}


// JavaScript API
namespace {
void NewQuicSocket(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());

  uint32_t options = 0;
  USE(args[0]->Uint32Value(env->context()).To(&options));
  uint32_t retry_token_expiration = DEFAULT_RETRYTOKEN_EXPIRATION;
  uint32_t max_connections_per_host = DEFAULT_MAX_CONNECTIONS_PER_HOST;
  USE(args[1]->Uint32Value(env->context()).To(&retry_token_expiration));
  USE(args[2]->Uint32Value(env->context()).To(&max_connections_per_host));
  CHECK_GE(retry_token_expiration, MIN_RETRYTOKEN_EXPIRATION);
  CHECK_LE(retry_token_expiration, MAX_RETRYTOKEN_EXPIRATION);

  new QuicSocket(
      env,
      args.This(),
      retry_token_expiration,
      max_connections_per_host,
      options);
}

// Enabling diagnostic packet loss enables a mode where the QuicSocket
// instance will randomly ignore received packets in order to simulate
// packet loss. This is not an API that should be enabled in production
// but is useful when debugging and diagnosing performance issues.
// Diagnostic packet loss is enabled by setting either the tx or rx
// arguments to a value between 0.0 and 1.0. Setting both values to 0.0
// disables the mechanism.
void QuicSocketSetDiagnosticPacketLoss(
  const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder());
  double rx = 0.0f;
  double tx = 0.0f;
  USE(args[0]->NumberValue(env->context()).To(&rx));
  USE(args[1]->NumberValue(env->context()).To(&tx));
  CHECK_GE(rx, 0.0f);
  CHECK_GE(tx, 0.0f);
  CHECK_LE(rx, 1.0f);
  CHECK_LE(tx, 1.0f);
  socket->SetDiagnosticPacketLoss(rx, tx);
}

void QuicSocketAddMembership(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 2);
  CHECK(args[0]->IsString());
  CHECK(args[1]->IsString());

  Utf8Value address(env->isolate(), args[0]);
  Utf8Value iface(env->isolate(), args[1]);
  args.GetReturnValue().Set(socket->AddMembership(*address, *iface));
}

void QuicSocketBind(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));

  CHECK_EQ(args.Length(), 4);

  node::Utf8Value address(args.GetIsolate(), args[1]);
  int32_t type;
  uint32_t port, flags;
  if (!args[0]->Int32Value(env->context()).To(&type) ||
      !args[2]->Uint32Value(env->context()).To(&port) ||
      !args[3]->Uint32Value(env->context()).To(&flags))
    return;
  CHECK(type == AF_INET || type == AF_INET6);

  args.GetReturnValue().Set(socket->Bind(*address, port, flags, type));
}

void QuicSocketDestroy(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder());
  socket->ReceiveStop();
}

void QuicSocketDropMembership(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 2);
  CHECK(args[0]->IsString());
  CHECK(args[1]->IsString());

  Utf8Value address(env->isolate(), args[0]);
  Utf8Value iface(env->isolate(), args[1]);
  args.GetReturnValue().Set(socket->DropMembership(*address, *iface));
}

void QuicSocketListen(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK(args[0]->IsObject());  // Secure Context
  SecureContext* sc;
  ASSIGN_OR_RETURN_UNWRAP(&sc, args[0].As<Object>(),
                          args.GetReturnValue().Set(UV_EBADF));

  SocketAddress* local = socket->GetLocalAddress();
  sockaddr_storage preferred_address_storage;
  const sockaddr* preferred_address = local != nullptr ? **local : nullptr;
  if (args[1]->IsString()) {
    node::Utf8Value preferred_address_host(args.GetIsolate(), args[1]);
    int32_t preferred_address_family;
    uint32_t preferred_address_port;
    if (args[2]->Int32Value(env->context()).To(&preferred_address_family) &&
        args[3]->Uint32Value(env->context()).To(&preferred_address_port) &&
        SocketAddress::ToSockAddr(
            preferred_address_family,
            *preferred_address_host,
            preferred_address_port,
            &preferred_address_storage) == 0) {
      preferred_address =
          reinterpret_cast<const sockaddr*>(&preferred_address_storage);
    }
  }

  std::string alpn(NGTCP2_ALPN_H3);
  if (args[4]->IsString()) {
    Utf8Value val(env->isolate(), args[4]);
    alpn = val.length();
    alpn += *val;
  }

  uint32_t options = 0;
  USE(args[5]->Uint32Value(env->context()).To(&options));

  socket->Listen(sc, preferred_address, alpn, options);
}

void QuicSocketStopListening(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder());
  socket->StopListening();
}

void QuicSocketReceiveStart(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  args.GetReturnValue().Set(socket->ReceiveStart());
}

void QuicSocketReceiveStop(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  args.GetReturnValue().Set(socket->ReceiveStop());
}

void QuicSocketSetBroadcast(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  args.GetReturnValue().Set(socket->SetBroadcast(args[0]->IsTrue()));
}

void QuicSocketSetMulticastInterface(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  CHECK(args[0]->IsString());

  Utf8Value iface(env->isolate(), args[0]);
  args.GetReturnValue().Set(socket->SetMulticastInterface(*iface));
}

void QuicSocketSetMulticastLoopback(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  args.GetReturnValue().Set(socket->SetMulticastLoopback(args[0]->IsTrue()));
}

void QuicSocketSetServerBusy(const FunctionCallbackInfo<Value>& args) {
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder());
  CHECK_EQ(args.Length(), 1);
  socket->SetServerBusy(args[0]->IsTrue());
}

void QuicSocketSetMulticastTTL(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  int ttl;
  if (!args[0]->Int32Value(env->context()).To(&ttl))
    return;
  args.GetReturnValue().Set(socket->SetMulticastTTL(ttl));
}

void QuicSocketSetTTL(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicSocket* socket;
  ASSIGN_OR_RETURN_UNWRAP(&socket, args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK_EQ(args.Length(), 1);
  int ttl;
  if (!args[0]->Int32Value(env->context()).To(&ttl))
    return;
  args.GetReturnValue().Set(socket->SetTTL(ttl));
}
}  // namespace

void QuicSocket::Initialize(
    Environment* env,
    Local<Object> target,
    Local<Context> context) {
  Isolate* isolate = env->isolate();
  Local<String> class_name = FIXED_ONE_BYTE_STRING(isolate, "QuicSocket");
  Local<FunctionTemplate> socket = env->NewFunctionTemplate(NewQuicSocket);
  socket->SetClassName(class_name);
  socket->InstanceTemplate()->SetInternalFieldCount(1);
  socket->InstanceTemplate()->Set(env->owner_symbol(), Null(isolate));
  env->SetProtoMethod(socket,
                      "addMembership",
                      QuicSocketAddMembership);
  env->SetProtoMethod(socket,
                      "bind",
                      QuicSocketBind);
  env->SetProtoMethod(socket,
                      "destroy",
                      QuicSocketDestroy);
  env->SetProtoMethod(socket,
                      "dropMembership",
                      QuicSocketDropMembership);
  env->SetProtoMethod(socket,
                      "getsockname",
                      node::GetSockOrPeerName<QuicSocket, uv_udp_getsockname>);
  env->SetProtoMethod(socket,
                      "listen",
                      QuicSocketListen);
  env->SetProtoMethod(socket,
                      "receiveStart",
                      QuicSocketReceiveStart);
  env->SetProtoMethod(socket,
                      "receiveStop",
                      QuicSocketReceiveStop);
  env->SetProtoMethod(socket,
                      "setDiagnosticPacketLoss",
                      QuicSocketSetDiagnosticPacketLoss);
  env->SetProtoMethod(socket,
                      "setTTL",
                      QuicSocketSetTTL);
  env->SetProtoMethod(socket,
                      "setBroadcast",
                      QuicSocketSetBroadcast);
  env->SetProtoMethod(socket,
                      "setMulticastInterface",
                      QuicSocketSetMulticastInterface);
  env->SetProtoMethod(socket,
                      "setMulticastTTL",
                      QuicSocketSetMulticastTTL);
  env->SetProtoMethod(socket,
                      "setMulticastLoopback",
                      QuicSocketSetMulticastLoopback);
  env->SetProtoMethod(socket,
                      "setServerBusy",
                      QuicSocketSetServerBusy);
  env->SetProtoMethod(socket,
                      "stopListening",
                      QuicSocketStopListening);
  socket->Inherit(HandleWrap::GetConstructorTemplate(env));
  target->Set(context, class_name,
              socket->GetFunction(env->context()).ToLocalChecked()).FromJust();
}

}  // namespace quic
}  // namespace node
