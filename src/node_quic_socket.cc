#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "env-inl.h"
#include "nghttp2/nghttp2.h"
#include "node.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "node_quic_socket.h"
#include "node_quic_util.h"
#include "util.h"
#include "uv.h"
#include "v8.h"

namespace node {

using crypto::EntropySource;
using crypto::SecureContext;

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
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
    Local<Object> wrap) :
    HandleWrap(env, wrap,
               reinterpret_cast<uv_handle_t*>(&handle_),
               AsyncWrap::PROVIDER_QUICSOCKET),
               server_listening_(false),
               validate_addr_(false),
               server_secure_context_(nullptr),
               token_crypto_ctx_{} {
  CHECK_EQ(uv_udp_init(env->event_loop(), &handle_), 0);
  Debug(this, "New QuicSocket created.");

  QuicSession::SetupTokenContext(&token_crypto_ctx_);
  EntropySource(token_secret_.data(), token_secret_.size());
}

QuicSocket::~QuicSocket() {
  CHECK(sessions_.empty());
  CHECK(dcid_to_scid_.empty());
  Debug(this,
        "QuicSocket destroyed.\n"
        "  Bytes Received: %llu\n"
        "  Bytes Sent: %llu\n"
        "  Packets Received: %llu\n"
        "  Packets Sent: %llu\n"
        "  Server Sessions: %llu\n"
        "  Client Sessions: %llu\n"
        "  Retransmit Count: %llu",
        socket_stats_.bytes_received,
        socket_stats_.bytes_sent,
        socket_stats_.packets_received,
        socket_stats_.packets_sent,
        socket_stats_.server_sessions,
        socket_stats_.client_sessions,
        socket_stats_.retransmit_count);
}

void QuicSocket::MemoryInfo(MemoryTracker* tracker) const {
}

void QuicSocket::AddSession(
    QuicCID* cid,
    QuicSession* session) {
  sessions_.emplace(cid->ToStr(), session);
  Debug(this, "QuicSession %s added to the QuicSocket.", cid->ToHex().c_str());
}

void QuicSocket::AssociateCID(
    QuicCID* cid,
    QuicSession* session) {
  QuicCID scid(session->scid());
  Debug(this, "Associating scid %s with cid %s.",
        scid.ToHex().c_str(), cid->ToHex().c_str());
  dcid_to_scid_.emplace(cid->ToStr(), scid.ToStr());
}

int QuicSocket::Bind(
    const char* address,
    uint32_t port,
    uint32_t flags,
    int family) {
  Debug(this,
        "Binding to address %s, port %d, with flags %d, and family %d",
        address, port, flags, family);

  sockaddr_storage addr;
  int err = SocketAddress::ToSockAddr(family, address, port, &addr);
  if (err != 0)
    return err;

  Local<Value> arg;

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
  int fd = UV_EBADF;
#if !defined(_WIN32)
  uv_fileno(reinterpret_cast<uv_handle_t*>(&handle_), &fd);
#endif
  arg = Integer::New(env()->isolate(), fd);
  MakeCallback(env()->quic_on_socket_ready_function(), 1, &arg);
  Debug(this, "Bind successful.");
  return 0;
}

void QuicSocket::DisassociateCID(QuicCID* cid) {
  Debug(this, "Removing associations for cid %s", cid->ToHex().c_str());
  dcid_to_scid_.erase(cid->ToStr());
}

SocketAddress* QuicSocket::GetLocalAddress() {
  return &local_address_;
}

void QuicSocket::Listen(
    SecureContext* sc,
    const sockaddr* preferred_address) {
  // TODO(@jasnell): Should we allow calling listen multiple times?
  // For now, we guard against it, but we may want to allow it later.
  CHECK_NOT_NULL(sc);
  CHECK_NULL(server_secure_context_);
  CHECK(!server_listening_);
  Debug(this, "Starting to listen.");
  server_session_config_.Set(env(), preferred_address);
  server_secure_context_ = sc;
  server_listening_ = true;
  ReceiveStart();
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

  if (nread == 0)
    return;

  QuicSocket* socket = static_cast<QuicSocket*>(handle->data);
  CHECK_NOT_NULL(socket);

  if (nread < 0) {
    Debug(socket,
          "An error occurred while reading data from the UDP socket. Error %d",
          nread);
    // TODO(@jasnell): Should this be fatal for the QuicSocket?
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
  ngtcp2_pkt_hd hd;
  int err;

  const uint8_t* data = reinterpret_cast<const uint8_t*>(buf->base);

  // Parse the packet header...
  err = (buf->base[0] & 0x80) ?
      ngtcp2_pkt_decode_hd_long(&hd, data, nread) :
      ngtcp2_pkt_decode_hd_short(&hd, data, nread, NGTCP2_SV_SCIDLEN);

  if (err < 0) {
    // There's nothing we should really do here but return. The packet is
    // likely not a QUIC packet. If this is sent by an attacker, returning
    // and doing nothing is likely best but we also might want to keep some
    // stats or record of the failure.
    Debug(this, "Could not decode a QUIC packet header.");
    return;
  }

  // Extract the DCID
  QuicCID dcid(hd.dcid);
  auto dcid_hex = dcid.ToHex();
  auto dcid_str = dcid.ToStr();
  Debug(this, "Received a QUIC packet for dcid %s", dcid_hex.c_str());

  QuicSession* session = nullptr;

  // Identify the appropriate handler
  auto session_it = sessions_.find(dcid_str);
  if (session_it == std::end(sessions_)) {
    auto scid_it = dcid_to_scid_.find(dcid_str);
    if (scid_it == std::end(dcid_to_scid_)) {
      Debug(this, "There is no existing session for dcid %s", dcid_hex.c_str());
      if (!server_listening_) {
        Debug(this, "Ignoring unhandled packet.");
        return;
      }
      Debug(this, "Dispatching packet to server.");
      session = ServerReceive(&dcid, &hd, nread, data, addr, flags);
      if (session == nullptr) {
        Debug(this, "Could not initialize a new QuicServerSession.");
        // TODO(@jasnell): What should we do here?
        return;
      }
      IncrementSocketStat(1, &socket_stats_, &socket_stats::server_sessions);
    } else {
      Debug(this, "An existing QuicSession for this packet was found.");
      session_it = sessions_.find((*scid_it).second);
      session = (*session_it).second;
      CHECK_NE(session_it, std::end(sessions_));
    }
  } else {
    Debug(this, "An existing QuicSession for this packet was found.");
    session = (*session_it).second;
  }

  CHECK_NOT_NULL(session);
  // An appropriate handler was found! Dispatch the data
  Debug(this, "Dispatching packet to session for dcid %s", dcid_hex.c_str());
  err = session->Receive(&hd, nread, data, addr, flags);
  if (err != 0) {
    Debug(this,
          "The QuicSession failed to process the packet successfully. Error %d",
          err);
    // TODO(@jasnell): Is removing the right thing to do here?
    // Probably not
    session->Remove();
    return;
  }

  IncrementSocketStat(nread, &socket_stats_, &socket_stats::bytes_received);
  IncrementSocketStat(1, &socket_stats_, &socket_stats::packets_received);

  SendPendingData();
}

int QuicSocket::ReceiveStart() {
  Debug(this, "Starting to receive packets on the UDP socket.");
  int err = uv_udp_recv_start(&handle_, OnAlloc, OnRecv);
  if (err == UV_EALREADY)
    err = 0;
  return err;
}

int QuicSocket::ReceiveStop() {
  Debug(this, "No longer receiving packets on this UDP socket.");
  return uv_udp_recv_stop(&handle_);
}

void QuicSocket::RemoveSession(QuicCID* cid) {
  Debug(this, "Removing QuicSession for cid %s.", cid->ToHex().c_str());
  sessions_.erase(cid->ToStr());
}

void QuicSocket::ReportSendError(int error) {
  Debug(this, "There was an error sending the UDP packet. Error %d", error);
  // TODO(@jasnell): Handle this correctly
}

void QuicSocket::SendPendingData(
    bool retransmit) {

  HandleScope handle_scope(env()->isolate());
  InternalCallbackScope callback_scope(this);

  // TODO(@jasnell): Explore scheduled writes similar to how we do
  // it with http2, except as soon as possible rather than on event
  // loop turn over.
  Debug(this, "Sending pending data. Retransmit? %s",
        retransmit ? "yes" : "no");
  for (auto session : sessions_) {
    int err = session.second->SendPendingData(retransmit);
    if (err != 0) {
      // TODO(@jasnell): handle error
    }
  }
}

int QuicSocket::SendVersionNegotiation(
    const ngtcp2_pkt_hd* chd,
    const sockaddr* addr) {
  Debug(this, "Sending version negotiation packet.");

  SendWrapStack* req = new SendWrapStack(this, addr, NGTCP2_MAX_PKTLEN_IPV6);

  std::array<uint32_t, 2> sv;
  sv[0] = GenerateReservedVersion(addr, chd->version);
  sv[1] = NGTCP2_PROTO_VER_D19;

  uint8_t unused_random;
  EntropySource(&unused_random, 1);

  ssize_t nwrite = ngtcp2_pkt_write_version_negotiation(
      **req,
      NGTCP2_MAX_PKTLEN_IPV6,
      unused_random,
      &chd->scid,
      &chd->dcid,
      sv.data(),
      sv.size());
  if (nwrite < 0) {
    Debug(this, "Error writing version negotiation packet. Error %d", nwrite);
    return -1;
  }
  req->SetLength(nwrite);

  return req->Send();
}

int QuicSocket::SendRetry(
    const ngtcp2_pkt_hd* chd,
    const sockaddr* addr) {

  SendWrapStack* req = new SendWrapStack(this, addr, NGTCP2_MAX_PKTLEN_IPV6);

  std::array<uint8_t, 256> token;
  size_t tokenlen = token.size();

  if (QuicSession::GenerateToken(
          token.data(), &tokenlen,
          addr,
          &chd->dcid,
          &token_crypto_ctx_,
          &token_secret_) != 0) {
    return -1;
  }

  ngtcp2_pkt_hd hd;
  hd.version = chd->version;
  hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
  hd.type = NGTCP2_PKT_RETRY;
  hd.pkt_num = 0;
  hd.token = nullptr;
  hd.tokenlen = 0;
  hd.len = 0;
  hd.dcid = chd->scid;
  hd.scid.datalen = NGTCP2_SV_SCIDLEN;

  EntropySource(hd.scid.data, hd.scid.datalen);

  ssize_t nwrite =
      ngtcp2_pkt_write_retry(
          **req,
          NGTCP2_MAX_PKTLEN_IPV6,
          &hd,
          &chd->dcid,
          token.data(),
          tokenlen);
  if (nwrite <= 0)
    return nwrite;

  return req->Send();
}

QuicSession* QuicSocket::ServerReceive(
    QuicCID* dcid,
    ngtcp2_pkt_hd* hd,
    ssize_t nread,
    const uint8_t* data,
    const struct sockaddr* addr,
    unsigned int flags) {

  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  if (static_cast<size_t>(nread) < MIN_INITIAL_QUIC_PKT_SIZE) {
    Debug(this, "Ignoring initial packet that is too short");
    return nullptr;
  }

  int err;
  err = ngtcp2_accept(hd, data, nread);
  if (err == -1) {
    // Ignore to prevent malicious senders from accomplishing anything bad.
    Debug(this, "Ignoring unexpected QUIC packet.");
    return nullptr;
  }
  if (err == 1) {
    Debug(this, "Unexpected QUIC version.");
    SendVersionNegotiation(hd, addr);
    return nullptr;
  }

  ngtcp2_cid ocid;
  ngtcp2_cid* pocid = nullptr;
  if (validate_addr_ && hd->type == NGTCP2_PKT_INITIAL) {
    Debug(this, "Stateless address validation.");
    if (hd->tokenlen == 0 ||
        QuicSession::VerifyToken(
            env(), &ocid,
            hd, addr,
            &token_crypto_ctx_,
            &token_secret_) != 0) {
      Debug(this, "Invalid token. Sending retry");
      SendRetry(hd, addr);
      return nullptr;
    }
    pocid = &ocid;
  }

  Debug(this, "Creating and initializing a new QuicServerSession.");
  QuicServerSession* session = QuicServerSession::New(this, &hd->dcid);
  // TODO(@jasnell): Should we assert at this point? Need to determine if there
  // is a way for an attacker to trigger this. If there is, we likely just want
  // to gracefully ignore this case. That said, something bad has happened if
  // we cannot create this so crashing is likely the best option. We'll stick
  // with that for now.
  CHECK_NOT_NULL(session);
  err = session->Init(addr, &hd->scid, pocid, hd->version);
  if (err < 0) {
    // TODO(@jasnell): Similar to above, it's not clear what we should do
    // at this point. The session was created but it can't be used for
    // some reason. This is most likely because of some bad QUIC packet
    // so the safest thing to do here is to just ignore and move on as if
    // nothing happened.
    Debug(this, "The QuicSession could not be initialized. Error %d", err);
    delete session;
    return nullptr;
  }

  QuicCID scid(session->scid());
  Debug(this, "The new QuicServerSession was created successfully. scid %s",
        scid.ToHex().c_str());
  AddSession(&scid, session);
  AssociateCID(dcid, session);

  if (session->pscid()->datalen) {
    QuicCID pscid(session->pscid());
    AssociateCID(&pscid, session);
  }

  // Notify the JavaScript side that a new server session has been created
  Debug(this, "Notifying JavaScript about QuicServerSession creation.");
  Local<Value> arg = session->object();
  MakeCallback(env()->quic_on_session_ready_function(), 1, &arg);

  return session;
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
    SocketAddress* dest,
    std::shared_ptr<QuicBuffer> buffer,
    QuicBuffer::drain_from drain_from) {
  return (new QuicSocket::SendWrap(this, dest, buffer, drain_from))->Send();
}

int QuicSocket::SendPacket(
    const sockaddr* dest,
    std::shared_ptr<QuicBuffer> buffer,
    QuicBuffer::drain_from drain_from) {
  return (new QuicSocket::SendWrap(this, dest, buffer, drain_from))->Send();
}

void QuicSocket::SetServerSessionSettings(
    QuicSession* session,
    ngtcp2_settings* settings) {
  ngtcp2_cid* pscid = nullptr;
  if (session->IsServer()) {
    QuicServerSession* server_session =
        static_cast<QuicServerSession*>(session);
    pscid = server_session->pscid();
  }
  server_session_config_.ToSettings(settings, pscid, true);
}

QuicSocket::SendWrapStack::SendWrapStack(
    QuicSocket* socket,
    const sockaddr* dest,
    size_t len) :
    socket_(socket) {
  req_.data = this;
  buf_.AllocateSufficientStorage(len);
  address_.Copy(dest);
}

void QuicSocket::SendWrapStack::OnSend(
    uv_udp_send_t* req,
    int status) {
  std::unique_ptr<QuicSocket::SendWrapStack> wrap(
      static_cast<QuicSocket::SendWrapStack*>(req->data));

  wrap->Socket()->IncrementSocketStat(
    wrap->Length(),
    &wrap->socket_->socket_stats_,
    &QuicSocket::socket_stats::bytes_sent);
  wrap->socket_->IncrementSocketStat(
    1,
    &wrap->socket_->socket_stats_,
    &QuicSocket::socket_stats::packets_sent);
}

int QuicSocket::SendWrapStack::Send() {
  if (buf_.length() == 0)
    return 0;
  uv_buf_t buf =
      uv_buf_init(
          reinterpret_cast<char*>(*buf_),
          buf_.length());
  return uv_udp_send(
      &req_,
      &socket_->handle_,
      &buf, 1,
      *address_,
      OnSend
  );
}

// The QuicSocket::SendWrap will maintain a std::weak_ref
// pointer to the buffer given to it.
QuicSocket::SendWrap::SendWrap(
    QuicSocket* socket,
    SocketAddress* dest,
    std::shared_ptr<QuicBuffer> buffer,
    QuicBuffer::drain_from drain_from) :
    socket_(socket),
    buffer_(buffer),
    drain_from_(drain_from) {
  req_.data = this;
  address_.Copy(dest);
}

QuicSocket::SendWrap::SendWrap(
    QuicSocket* socket,
    const sockaddr* dest,
    std::shared_ptr<QuicBuffer> buffer,
    QuicBuffer::drain_from drain_from) :
    socket_(socket),
    buffer_(buffer),
    drain_from_(drain_from) {
  req_.data = this;
  address_.Copy(dest);
}

void QuicSocket::SendWrap::Done(int status) {
  // If the weak_ref to the QuicBuffer is still valid
  // consume the data, otherwise, do nothing
  if (auto buf = buffer_.lock()) {
    if (status == 0)
      buf->Consume(length_);
    else
      buf->Cancel(status);
  }
}

void QuicSocket::SendWrap::OnSend(
    uv_udp_send_t* req,
    int status) {
  std::unique_ptr<QuicSocket::SendWrap> wrap(
      static_cast<QuicSocket::SendWrap*>(req->data));
  wrap->Done(status);

  wrap->Socket()->IncrementSocketStat(
    wrap->length_,
    &wrap->socket_->socket_stats_,
    &QuicSocket::socket_stats::bytes_sent);
  wrap->socket_->IncrementSocketStat(
    1,
    &wrap->socket_->socket_stats_,
    &QuicSocket::socket_stats::packets_sent);
}

// Sending will take the current content of the QuicBuffer
// and forward it off to the uv_udp_t handle.
int QuicSocket::SendWrap::Send() {
  std::vector<uv_buf_t> vec;
  if (auto buf = buffer_.lock()) {
    size_t len = buf->DrainInto(&vec, drain_from_, &length_);
    Debug(socket_, "Sending %llu bytes (%d buffers of %d remaining)",
          length_, len, buf->ReadRemaining());
    if (len == 0) return 0;
    int err = uv_udp_send(
        &req_,
        &socket_->handle_,
        vec.data(),
        vec.size(),
        *address_,
        OnSend);
    // If sending was successful, advance the read head
    if (err == 0)
      buf->SeekHead(len);
    return err;
  }
  return -1;
}

// JavaScript API
namespace {
void NewQuicSocket(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  new QuicSocket(env, args.This());
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
  delete socket;
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

  socket->Listen(sc, preferred_address);
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
  socket->Inherit(HandleWrap::GetConstructorTemplate(env));
  target->Set(context, class_name,
              socket->GetFunction(env->context()).ToLocalChecked()).FromJust();
}

}  // namespace quic
}  // namespace node
