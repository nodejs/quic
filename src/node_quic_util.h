#ifndef SRC_NODE_QUIC_UTIL_H_
#define SRC_NODE_QUIC_UTIL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "string_bytes.h"
#include "uv.h"
#include "v8.h"

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

#include <functional>
#include <string>
#include <vector>

namespace node {
namespace quic {

namespace {

constexpr unsigned long long operator"" _k(unsigned long long k) {
  return k * 1024;
}

constexpr unsigned long long operator"" _m(unsigned long long m) {
  return m * 1024 * 1024;
}

constexpr unsigned long long operator"" _g(unsigned long long g) {
  return g * 1024 * 1024 * 1024;
}

}

constexpr uint16_t NGTCP2_APP_NOERROR = 0xff00;

constexpr size_t MIN_INITIAL_QUIC_PKT_SIZE = 1200;
constexpr size_t NGTCP2_SV_SCIDLEN = 18;
constexpr size_t TOKEN_RAND_DATALEN = 16;
constexpr size_t TOKEN_SECRETLEN = 16;
constexpr size_t DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL = 256_k;

class SocketAddress {
 public:
   static bool numeric_host(const char *hostname) {
     return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
   }

  static bool numeric_host(const char *hostname, int family) {
    std::array<uint8_t, sizeof(struct in6_addr)> dst;
    int err = inet_pton(family, hostname, dst.data());
    return err == 1;
  }

  static size_t GetMaxPktLen(const sockaddr* addr) {
    return addr->sa_family ? NGTCP2_MAX_PKTLEN_IPV6 : NGTCP2_MAX_PKTLEN_IPV4;
  }

  static int ToSockAddr(
      int32_t family,
      const char* host,
      uint32_t port,
      sockaddr_storage* addr) {
    CHECK(family == AF_INET || family == AF_INET6);
    int err = 0;
    switch (family) {
       case AF_INET:
        err = uv_ip4_addr(host, port, reinterpret_cast<sockaddr_in*>(addr));
        break;
      case AF_INET6:
        err = uv_ip6_addr(host, port, reinterpret_cast<sockaddr_in6*>(addr));
         break;
       default:
        CHECK(0 && "unexpected address family");
    }
    return err;
  }

  static int GetPort(const sockaddr* addr) {
    return ntohs(addr->sa_family == AF_INET ?
        reinterpret_cast<const sockaddr_in*>(addr)->sin_port :
        reinterpret_cast<const sockaddr_in6*>(addr)->sin6_port);
  }

  static void GetAddress(const sockaddr* addr, char** host) {
    char hostbuf[INET6_ADDRSTRLEN];
    const void* src = addr->sa_family == AF_INET ?
        static_cast<const void*>(
            &(reinterpret_cast<const sockaddr_in*>(addr)->sin_addr)) :
        static_cast<const void*>(
            &(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr));
    if (uv_inet_ntop(addr->sa_family, src, hostbuf, sizeof(hostbuf)) == 0) {
      *host = hostbuf;
    }
  }

  static size_t GetAddressLen(const sockaddr* addr) {
    return
        addr->sa_family == AF_INET6 ?
            sizeof(sockaddr_in6) :
            sizeof(sockaddr_in);
  }

  static size_t GetAddressLen(const sockaddr_storage* addr) {
    return
        addr->ss_family == AF_INET6 ?
            sizeof(sockaddr_in6) :
            sizeof(sockaddr_in);
  }

  void Copy(SocketAddress* addr) {
    memcpy(&address_, **addr, addr->Size());
  }

  void Copy(const sockaddr* source) {
    memcpy(&address_, source, GetAddressLen(source));
  }

  void Set(uv_udp_t* handle) {
    int addrlen = sizeof(address_);
    CHECK_EQ(uv_udp_getsockname(
      handle,
      reinterpret_cast<sockaddr*  >(&address_),
      &addrlen), 0);
  }

  void Update(const ngtcp2_addr* addr) {
    memcpy(&address_, addr->addr, sizeof(addr->addrlen));
  }

  const sockaddr* operator*() {
    return reinterpret_cast<const sockaddr*>(&address_);
  }

  ngtcp2_addr ToAddr() {
    return ngtcp2_addr{Size(), reinterpret_cast<uint8_t*>(&address_), nullptr};
  }

  size_t Size() {
    return GetAddressLen(&address_);
  }

 private:
  sockaddr_storage address_;
};

class QuicPath {
 public:
  QuicPath(
    SocketAddress* local,
    SocketAddress* remote) :
    path_({ local->ToAddr(), remote->ToAddr() }) {}

  ngtcp2_path* operator*() { return &path_; }

 private:
  ngtcp2_path path_;
};

// The implementation of this is taken directly from the ngtcp2
// examples but modified to be a class rather than a struct.
class QuicBuffer {
 public:
  static size_t Cancel(std::deque<QuicBuffer>& d, int status = UV_ECANCELED) {
    size_t len = 0;
    while (!d.empty()) {
      auto& v = d.front();
      v.Done(status, v.bufsize());
      d.pop_front();
    }
    return len;
  }

  static size_t AckData(
      std::deque<QuicBuffer>& d,
      size_t& idx,
      uint64_t& tx_offset,
      uint64_t offset) {
    size_t len = 0;
    for (; !d.empty() && tx_offset + d.front().bufsize() <= offset;) {
      --idx;
      auto& v = d.front();
      len += v.bufsize();
      tx_offset += v.bufsize();
      v.Done(0, v.bufsize());
      d.pop_front();
    }
    return len;
  }

  QuicBuffer(
    const uint8_t* data,
    size_t datalen,
    std::function<void(
        int status,
        void* user_data,
        size_t len)> done_cb = default_done,
    void* user_data = nullptr,
    v8::Local<v8::Object> obj = v8::Local<v8::Object>()) :
      buf_{data, data + datalen},
      begin_(buf_.data()),
      head_(begin_),
      tail_(begin_ + datalen),
      done_cb_(done_cb),
      user_data_(user_data),
      done_(false) {
    if (!obj.IsEmpty())
      keep_alive_.Reset(obj->GetIsolate(), obj);
  }

  QuicBuffer(
    uint8_t* begin,
    uint8_t* end,
    std::function<void(
        int status,
        void* user_data,
        size_t len)> done_cb = default_done,
    void* user_data = nullptr,
    v8::Local<v8::Object> obj = v8::Local<v8::Object>()) :
      begin_(begin),
      head_(begin),
      tail_(end),
      done_cb_(done_cb),
      user_data_(user_data),
      done_(false) {
    if (!obj.IsEmpty())
      keep_alive_.Reset(obj->GetIsolate(), obj);
  }

  QuicBuffer(
    size_t datalen,
    std::function<void(
        int status,
        void* user_data,
        size_t len)> done_cb = default_done,
    void* user_data = nullptr,
    v8::Local<v8::Object> obj = v8::Local<v8::Object>()) :
      buf_(datalen),
      begin_(buf_.data()),
      head_(begin_),
      tail_(begin_),
      done_cb_(done_cb),
      user_data_(user_data),
      done_(false) {
    if (!obj.IsEmpty())
      keep_alive_.Reset(obj->GetIsolate(), obj);
  }

  QuicBuffer(
    std::function<void(
        int status,
        void* user_data,
        size_t len)> done_cb = default_done,
    void* user_data = nullptr,
    v8::Local<v8::Object> obj = v8::Local<v8::Object>()) :
      begin_(buf_.data()),
      head_(begin_),
      tail_(begin_),
      done_cb_(done_cb),
      user_data_(user_data),
      done_(false) {
    if (!obj.IsEmpty())
      keep_alive_.Reset(obj->GetIsolate(), obj);
  }

  ~QuicBuffer() {
    CHECK(done_);
  }

  void Done(int status, size_t len) {
    reset(true);
    done_cb_(status, user_data_, len);
  }

  bool WantsAck() {
    return !done_;
  }

  size_t size() const { return tail_ - head_; }

  size_t left() const { return buf_.data() + buf_.size() - tail_; }

  // TODO(@jasnell): the current definition has a compiler warning
  uint8_t* wpos() { return tail_; }

  const uint8_t* rpos() const { return head_; }

  void seek(size_t len) { head_ += len; }

  void push(size_t len) { tail_ += len; }

  void reset(bool done = false) {
    // Note: reset should not be used for QuicBuffer instances created
    // by stream writes from JS because it will reset without calling
    // the callback and notifying that the buffer has been reset.
    // TODO(@jasnell): Revisit this.
    head_ = begin_;
    tail_ = begin_;
    done_ = done;
  }

  size_t bufsize() const { return tail_ - begin_; }

  uv_buf_t toBuffer() {
    return uv_buf_init(reinterpret_cast<char*>(begin_), bufsize());
  }

 private:
  static void default_done(int status, void* user_data, size_t len) {}

  // TODO(@jasnell): Switch to MaybeStackBuffer?
  std::vector<uint8_t> buf_;
  uint8_t* begin_;
  uint8_t* head_;
  uint8_t* tail_;
  std::function<void(int status, void* user_data, size_t len)> done_cb_;
  void* user_data_;
  v8::Global<v8::Object> keep_alive_;
  bool done_;
};

struct QuicPathStorage {
  QuicPathStorage() {
    path.local.addr = local_addrbuf.data();
    path.remote.addr = remote_addrbuf.data();
  }

  ngtcp2_path path;
  std::array<uint8_t, sizeof(sockaddr_storage)> local_addrbuf;
  std::array<uint8_t, sizeof(sockaddr_storage)> remote_addrbuf;
};

class QuicCID {
 public:
  explicit QuicCID(ngtcp2_cid* cid) : cid_(cid) {}
  explicit QuicCID(const ngtcp2_cid* cid) : cid_(cid) {}
  explicit QuicCID(const ngtcp2_cid& cid) : cid_(&cid) {}

  std::string ToStr() {
    return std::string(cid_->data, cid_->data + cid_->datalen);
  }

  std::string ToHex() {
    MaybeStackBuffer<char, 64> dest;
    dest.AllocateSufficientStorage(cid_->datalen * 2);
    dest.SetLengthAndZeroTerminate(cid_->datalen * 2);
    size_t written = StringBytes::hex_encode(
        reinterpret_cast<const char*>(cid_->data),
        cid_->datalen,
        *dest,
        dest.length());
    return std::string(*dest, written);
  }

  const ngtcp2_cid* operator*() const { return cid_; }

 private:
  const ngtcp2_cid* cid_;
};

// https://stackoverflow.com/questions/33701430/template-function-to-access-struct-members
template <typename C, typename T>
decltype(auto) access(C& cls, T C::*member) {
  return (cls.*member);
}

template <typename C, typename T, typename... Mems>
decltype(auto) access(C& cls, T C::*member, Mems... rest) {
  return access((cls.*member), rest...);
}

typedef int(*install_fn)(
    ngtcp2_conn* conn,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* iv,
    size_t ivlen,
    const uint8_t* pn,
    size_t pnlen);

typedef void(*set_ssl_state_fn)(SSL* ssl);

struct CryptoContext {
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *prf;
  std::array<uint8_t, 64> tx_secret;
  std::array<uint8_t, 64> rx_secret;
  size_t secretlen;
};

struct CryptoInitialParams {
  std::array<uint8_t, 32> initial_secret;
  std::array<uint8_t, 32> secret;
  std::array<uint8_t, 16> key;
  std::array<uint8_t, 16> iv;
  std::array<uint8_t, 16> hp;
  ssize_t keylen;
  ssize_t ivlen;
  ssize_t hplen;
};

struct CryptoParams {
  std::array<uint8_t, 64> key;
  std::array<uint8_t, 64> iv;
  std::array<uint8_t, 64> hp;
  ssize_t keylen;
  ssize_t ivlen;
  ssize_t hplen;
};

struct CryptoToken {
  std::array<uint8_t, 32> key;
  std::array<uint8_t, 32> iv;
  size_t keylen;
  size_t ivlen;
  CryptoToken() : keylen(key.size()), ivlen(iv.size()) {}
};

}  // namespace quic
}  // namespace node

#endif  // NOE_WANT_INTERNALS

#endif // SRC_NODE_QUIC_UTIL_H_
