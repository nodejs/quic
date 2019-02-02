#ifndef SRC_NODE_QUIC_UTIL_H_
#define SRC_NODE_QUIC_UTIL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

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
constexpr size_t DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL = 256_k;

class SocketAddress {
 public:
  void Copy(SocketAddress* addr) {
    memcpy(&address_, **addr, addr->Size());
  }

  void Copy(const sockaddr* source) {
    switch (source->sa_family) {
      case AF_INET6:
        memcpy(&address_, source, sizeof(sockaddr_in6));
        break;
      case AF_INET:
        memcpy(&address_, source, sizeof(sockaddr_in));
        break;
      default:
        UNREACHABLE();
    }
  }

  void Set(uv_udp_t* handle) {
    int addrlen = sizeof(address_);
    CHECK_EQ(uv_udp_getsockname(
      handle,
      reinterpret_cast<sockaddr*  >(&address_),
      &addrlen), 0);
  }

  void Update(const ngtcp2_addr* addr) {
    // TODO(@jasnell): Is this right?
    memcpy(&address_, addr->addr, sizeof(addr->len));
  }

  const sockaddr* operator*() {
    return reinterpret_cast<const sockaddr*>(&address_);
  }

  ngtcp2_addr ToAddr() {
    return ngtcp2_addr{Size(), reinterpret_cast<uint8_t*>(&address_)};
  }

  size_t Size() {
    switch (address_.ss_family) {
      case AF_INET6:
        return sizeof(sockaddr_in6);
      case AF_INET:
        return sizeof(sockaddr_in);
        break;
      default:
        UNREACHABLE();
    }
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
      v.Done(status);
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
      v.Done(0);
      d.pop_front();
    }
    return len;
  }

  QuicBuffer(
    const uint8_t* data,
    size_t datalen,
    std::function<void(int status, void* user_data)> done_cb = default_done,
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
    std::function<void(int status, void* user_data)> done_cb = default_done,
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
    std::function<void(int status, void* user_data)> done_cb = default_done,
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
    std::function<void(int status, void* user_data)> done_cb = default_done,
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

  void Done(int status) {
    reset(true);
    done_cb_(status, user_data_);
  }

  bool WantsAck() {
    return !done_;
  }

  size_t size() const { return tail_ - head_; }

  size_t left() const { return buf_.data() + buf_.size() - tail_; }

  // TODO(@jasnell): the current definition has a compiler warning
  uint8_t* const wpos() { return tail_; }

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
  static void default_done(int status, void* user_data) {}

  // TODO(@jasnell): Switch to MaybeStackBuffer?
  std::vector<uint8_t> buf_;
  uint8_t* begin_;
  uint8_t* head_;
  uint8_t* tail_;
  std::function<void(int status, void* user_data)> done_cb_;
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

struct CryptoContext {
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *prf;
  std::array<uint8_t, 64> tx_secret, rx_secret;
  size_t secretlen;
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


}  // namespace quic
}  // namespace node

#endif  // NOE_WANT_INTERNALS

#endif // SRC_NODE_QUIC_UTIL_H_
