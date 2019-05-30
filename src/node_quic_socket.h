#ifndef SRC_NODE_QUIC_SOCKET_H_
#define SRC_NODE_QUIC_SOCKET_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "node_crypto.h"  // SSLWrap
#include "node_internals.h"
#include "ngtcp2/ngtcp2.h"
#include "node_quic_session.h"
#include "node_quic_util.h"
#include "env.h"
#include "handle_wrap.h"
#include "v8.h"
#include "uv.h"

#include <map>
#include <string>
#include <vector>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Value;

namespace quic {

class QuicSocket : public HandleWrap {
 public:
  static void Initialize(
      Environment* env,
      Local<Object> target,
      Local<Context> context);

  QuicSocket(
      Environment* env,
      Local<Object> wrap,
      bool verify_address,
      uint64_t retry_token_expiration,
      size_t max_connections_per_host);
  ~QuicSocket() override;

  int AddMembership(
      const char* address,
      const char* iface);
  void AddSession(
      QuicCID* cid,
      std::shared_ptr<QuicSession> session);
  void AssociateCID(
      QuicCID* cid,
      QuicCID* scid);
  int Bind(
      const char* address,
      uint32_t port,
      uint32_t flags,
      int family);
  void DisassociateCID(
      QuicCID* cid);
  int DropMembership(
      const char* address,
      const char* iface);
  SocketAddress* GetLocalAddress();
  void Listen(
      crypto::SecureContext* context,
      const sockaddr* preferred_address = nullptr,
      const std::string& alpn = NGTCP2_ALPN_H3);
  int ReceiveStart();
  int ReceiveStop();
  void RemoveSession(
      QuicCID* cid,
      const sockaddr* addr);
  void ReportSendError(
      int error);
  int SetBroadcast(
      bool on);
  int SetMulticastInterface(
      const char* iface);
  int SetMulticastLoopback(
      bool on);
  int SetMulticastTTL(
      int ttl);
  int SetTTL(
      int ttl);
  int SendPacket(
      SocketAddress* dest,
      std::shared_ptr<QuicBuffer> buf,
      QuicBuffer::drain_from drain_from = QuicBuffer::DRAIN_FROM_HEAD);
  int SendPacket(
      const sockaddr* dest,
      std::shared_ptr<QuicBuffer> buf,
      QuicBuffer::drain_from drain_from = QuicBuffer::DRAIN_FROM_HEAD);
  void SetServerSessionSettings(
      ngtcp2_cid* pscid,
      ngtcp2_settings* settings);

  crypto::SecureContext* GetServerSecureContext() {
    return server_secure_context_;
  }

  const uv_udp_t* operator*() const { return &handle_; }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(QuicSocket)
  SET_SELF_SIZE(QuicSocket)

 private:
  static void OnAlloc(
      uv_handle_t* handle,
      size_t suggested_size,
      uv_buf_t* buf);

  static void OnRecv(
      uv_udp_t* handle,
      ssize_t nread,
      const uv_buf_t* buf,
      const struct sockaddr* addr,
      unsigned int flags);

  void Receive(
      ssize_t nread,
      const uv_buf_t* buf,
      const struct sockaddr* addr,
      unsigned int flags);

  int SendVersionNegotiation(
      const ngtcp2_pkt_hd* chd,
      const sockaddr* addr);

  std::shared_ptr<QuicSession> ServerReceive(
      QuicCID* dcid,
      ngtcp2_pkt_hd* hd,
      ssize_t nread,
      const uint8_t* data,
      const struct sockaddr* addr,
      unsigned int flags);
  int SendRetry(
      const ngtcp2_pkt_hd* chd,
      const sockaddr* addr);

  void IncrementSocketAddressCounter(const sockaddr* addr);
  void DecrementSocketAddressCounter(const sockaddr* addr);
  size_t GetCurrentSocketAddressCounter(const sockaddr* addr);

  template <typename T,
            int (*F)(const typename T::HandleType*, sockaddr*, int*)>
  friend void node::GetSockOrPeerName(
      const v8::FunctionCallbackInfo<v8::Value>&);

  // Fields and TypeDefs
  typedef uv_udp_t HandleType;

  uv_udp_t handle_;
  SocketAddress local_address_;
  bool server_listening_;
  bool validate_addr_;
  size_t max_connections_per_host_;
  QuicSessionConfig server_session_config_;
  crypto::SecureContext* server_secure_context_;
  std::string server_alpn_;
  std::unordered_map<std::string, std::shared_ptr<QuicSession>> sessions_;
  std::unordered_map<std::string, std::string> dcid_to_scid_;
  CryptoContext token_crypto_ctx_;
  std::array<uint8_t, TOKEN_SECRETLEN> token_secret_;
  uint64_t retry_token_expiration_;

  // Counts the number of active connections per remote
  // address. A custom std::hash specialization for
  // sockaddr instances is used. Values are incremented
  // when a QuicSession is added to the socket, and
  // decremented when the QuicSession is removed. If the
  // value reaches the value of max_connections_per_host_,
  // attempts to create new connections will be ignored
  // until the value falls back below the limit.
  std::unordered_map<const sockaddr*, size_t, SocketAddress::Hash>
    addr_counts_;

  struct socket_stats {
    // The timestamp at which the socket was created
    uint64_t created_at;
    // The timestamp at which the socket was bound
    uint64_t bound_at;
    // The timestamp at which the socket began listening
    uint64_t listen_at;
    // The total number of bytes received (and not ignored)
    // by this QuicSocket instance.
    uint64_t bytes_received;

    // The total number of bytes successfully sent by this
    // QuicSocket instance.
    uint64_t bytes_sent;

    // The total number of packets received (and not ignored)
    // by this QuicSocket instance.
    uint64_t packets_received;

    // The total number of packets successfully sent by this
    // QuicSocket instance.
    uint64_t packets_sent;

    // The total number of QuicServerSessions that have been
    // associated with this QuicSocket instance.
    uint64_t server_sessions;

    // The total number of QuicClientSessions that have been
    // associated with this QuicSocket instance.
    uint64_t client_sessions;

    // The total number of times packets have had to be
    // retransmitted by this QuicSocket instance.
    uint64_t retransmit_count;
  };
  socket_stats socket_stats_{0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  AliasedBigUint64Array stats_buffer_;

  template <typename... Members>
  void IncrementSocketStat(
      uint64_t amount,
      socket_stats* a,
      Members... mems) {
    static uint64_t max = std::numeric_limits<uint64_t>::max();
    uint64_t current = access(a, mems...);
    uint64_t delta = std::min(amount, max - current);
    access(a, mems...) += delta;
  }

  // The SendWrap drains the given QuicBuffer and sends it to the
  // uv_udp_t handle. When the async operation completes, the done_cb
  // is invoked with the status and the user_data forwarded on.
  class SendWrap {
   public:
    SendWrap(
        QuicSocket* socket,
        SocketAddress* dest,
        std::shared_ptr<QuicBuffer> buffer,
        QuicBuffer::drain_from drain_from = QuicBuffer::DRAIN_FROM_HEAD);

    SendWrap(
        QuicSocket* socket,
        const sockaddr* dest,
        std::shared_ptr<QuicBuffer> buffer,
        QuicBuffer::drain_from drain_from = QuicBuffer::DRAIN_FROM_HEAD);

    static void OnSend(
        uv_udp_send_t* req,
        int status);

    void Done(int status);

    int Send();

    QuicSocket* Socket() const { return socket_; }

   private:
    uv_udp_send_t req_;
    QuicSocket* socket_;
    std::weak_ptr<QuicBuffer> buffer_;
    QuicBuffer::drain_from drain_from_;
    uint64_t length_ = 0;
    SocketAddress address_;
  };

  class SendWrapStack {
   public:
    SendWrapStack(
        QuicSocket* socket,
        const sockaddr* dest,
        size_t len);

    static void OnSend(
        uv_udp_send_t* req,
        int status);

    int Send();

    uint8_t* operator*() { return *buf_; }

    void SetLength(size_t len) {
      buf_.SetLength(len);
    }

    size_t Length() {
      return buf_.length();
    }

    QuicSocket* Socket() const { return socket_; }

   private:
    uv_udp_send_t req_;
    QuicSocket* socket_;
    MaybeStackBuffer<uint8_t> buf_;
    SocketAddress address_;
  };
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_SOCKET_H_
