#ifndef SRC_NODE_QUIC_UTIL_H_
#define SRC_NODE_QUIC_UTIL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_quic_buffer.h"
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

constexpr uint64_t NGTCP2_APP_NOERROR = 0xff00;

constexpr size_t MIN_INITIAL_QUIC_PKT_SIZE = 1200;
constexpr size_t NGTCP2_SV_SCIDLEN = NGTCP2_MAX_CIDLEN;
constexpr size_t TOKEN_RAND_DATALEN = 16;
constexpr size_t TOKEN_SECRETLEN = 16;

constexpr size_t kMaxSizeT = std::numeric_limits<size_t>::max();
constexpr size_t DEFAULT_MAX_CONNECTIONS_PER_HOST = 100;
constexpr uint64_t MIN_MAX_CRYPTO_BUFFER = 4096;
constexpr uint64_t MIN_RETRYTOKEN_EXPIRATION = 1;
constexpr uint64_t MAX_RETRYTOKEN_EXPIRATION = 60;
constexpr uint64_t DEFAULT_MAX_CRYPTO_BUFFER = MIN_MAX_CRYPTO_BUFFER * 4;
constexpr uint64_t DEFAULT_ACTIVE_CONNECTION_ID_LIMIT = 10;
constexpr uint64_t DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL = 256 * 1024;
constexpr uint64_t DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE = 256 * 1024;
constexpr uint64_t DEFAULT_MAX_STREAM_DATA_UNI = 256 * 1024;
constexpr uint64_t DEFAULT_MAX_DATA = 1 * 1024 * 1024;
constexpr uint64_t DEFAULT_MAX_STREAMS_BIDI = 100;
constexpr uint64_t DEFAULT_MAX_STREAMS_UNI = 3;
constexpr uint64_t DEFAULT_IDLE_TIMEOUT = 10 * 1000;
constexpr uint64_t DEFAULT_RETRYTOKEN_EXPIRATION = 10ULL;

#define RETURN_IF_FAIL(test, success, ret)                                     \
  do {                                                                         \
    if (UNLIKELY((test) != (success))) return (ret);                           \
  } while (0)

#define RETURN_IF_FAIL_OPENSSL(test) RETURN_IF_FAIL(test, 1, -1)

typedef enum SelectPreferredAddressPolicy : int {
  // Ignore the server-provided preferred address
  QUIC_PREFERRED_ADDRESS_IGNORE,
  // Accept the server-provided preferred address
  QUIC_PREFERRED_ADDRESS_ACCEPT
} SelectPreferredAddressPolicy;

// Fun hash combine trick based on a variadic template that
// I came across a while back but can't remember where. Will add an attribution
// if I can find the source.
inline void hash_combine(size_t* seed) { }

template <typename T, typename... Args>
inline void hash_combine(size_t* seed, const T& value, Args... rest) {
    *seed ^= std::hash<T>{}(value) + 0x9e3779b9 + (*seed << 6) + (*seed >> 2);
    hash_combine(seed, rest...);
}

// QUIC error codes generally fall into two distinct namespaces:
// Connection Errors and Application Errors. Connection errors
// are further subdivided into Crypto and non-Crypto. Application
// errors are entirely specific to the QUIC application being
// used. An easy rule of thumb is that Application errors are
// semantically associated with the ALPN identifier negotiated
// for the QuicSession. So, if a connection is closed with
// family: QUIC_ERROR_APPLICATION and code: 123, you have to
// look at the ALPN identifier to determine exactly what it
// means. Connection (Session) and Crypto errors, on the other
// hand, share the same meaning regardless of the ALPN.
typedef enum QuicErrorFamily : int {
  QUIC_ERROR_SESSION,
  QUIC_ERROR_CRYPTO,
  QUIC_ERROR_APPLICATION
} QuicErrorFamily;

struct QuicError {
  QuicErrorFamily family;
  uint64_t code;
  inline QuicError(
      QuicErrorFamily family_ = QUIC_ERROR_SESSION,
      uint64_t code_ = NGTCP2_NO_ERROR) :
      family(family_), code(code_) {}
};

inline QuicError InitQuicError(
    QuicErrorFamily family = QUIC_ERROR_SESSION,
    int code_ = NGTCP2_NO_ERROR) {
  QuicError error;
  error.family = family;
  switch (family) {
    case QUIC_ERROR_CRYPTO:
      code_ |= NGTCP2_CRYPTO_ERROR;
      // Fall-through...
    case QUIC_ERROR_SESSION:
      error.code = ngtcp2_err_infer_quic_transport_error_code(code_);
      break;
    case QUIC_ERROR_APPLICATION:
      error.code = code_;
  }
  return error;
}

inline uint64_t ExtractErrorCode(Environment* env, v8::Local<v8::Value> arg) {
  uint64_t code = NGTCP2_APP_NOERROR;
  if (arg->IsBigInt()) {
    code = arg.As<v8::BigInt>()->Int64Value();
  } else if (arg->IsNumber()) {
    double num = 0;
    USE(arg->NumberValue(env->context()).To(&num));
    code = static_cast<uint64_t>(num);
  }
  return code;
}

inline const char* ErrorFamilyName(QuicErrorFamily family) {
  switch (family) {
    case QUIC_ERROR_SESSION:
      return "Session";
    case QUIC_ERROR_APPLICATION:
      return "Application";
    case QUIC_ERROR_CRYPTO:
      return "Crypto";
    default:
      return "<unknown>";
  }
}

class SocketAddress {
 public:
  // std::hash specialization for sockaddr instances (ipv4 or ipv6) used
  // for tracking the number of connections per client.
  struct Hash {
    size_t operator()(const sockaddr* addr) const {
      size_t hash = 0;
      switch (addr->sa_family) {
        case AF_INET: {
          const sockaddr_in* ipv4 =
              reinterpret_cast<const sockaddr_in*>(addr);
          hash_combine(&hash, ipv4->sin_port, ipv4->sin_addr.s_addr);
          break;
        }
        case AF_INET6: {
          const sockaddr_in6* ipv6 =
              reinterpret_cast<const sockaddr_in6*>(addr);
          const uint64_t* a =
              reinterpret_cast<const uint64_t*>(&ipv6->sin6_addr);
          hash_combine(&hash, ipv6->sin6_port, a[0], a[1]);
          break;
        }
        default:
          UNREACHABLE();
      }
      return hash;
    }
  };

  static bool numeric_host(const char* hostname) {
    return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
  }

  static bool numeric_host(const char* hostname, int family) {
    std::array<uint8_t, sizeof(struct in6_addr)> dst;
    int err = inet_pton(family, hostname, dst.data());
    return err == 1;
  }

  static size_t GetMaxPktLen(const sockaddr* addr) {
    return addr->sa_family == AF_INET6 ?
        NGTCP2_MAX_PKTLEN_IPV6 :
        NGTCP2_MAX_PKTLEN_IPV4;
  }

  static bool ResolvePreferredAddress(
      Environment* env,
      int local_address_family,
      const ngtcp2_preferred_addr* paddr,
      uv_getaddrinfo_t* req) {
    int af;
    const uint8_t* binaddr;
    uint16_t port;
    constexpr uint8_t empty_addr[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0};

    if (local_address_family == AF_INET &&
        memcmp(empty_addr, paddr->ipv4_addr, sizeof(paddr->ipv4_addr)) != 0) {
      af = AF_INET;
      binaddr = paddr->ipv4_addr;
      port = paddr->ipv4_port;
    } else if (local_address_family == AF_INET6 &&
               memcmp(empty_addr,
                      paddr->ipv6_addr,
                      sizeof(paddr->ipv6_addr)) != 0) {
      af = AF_INET6;
      binaddr = paddr->ipv6_addr;
      port = paddr->ipv6_port;
    } else {
      return false;
    }

    char host[NI_MAXHOST];
    if (uv_inet_ntop(af, binaddr, host, sizeof(host)) == 0)
      return false;

    addrinfo hints{};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;

    return
        uv_getaddrinfo(
            env->event_loop(),
            req,
            nullptr,
            host,
            std::to_string(port).c_str(),
            &hints) == 0;
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
    if (memcmp(&address_, **addr, addr->Size()) != 0)
      memcpy(&address_, **addr, addr->Size());
  }

  void Copy(const sockaddr* source) {
    if (memcmp(&address_, source, GetAddressLen(source)) != 0)
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
    if (memcmp(&address_, addr->addr, addr->addrlen) != 0)
      memcpy(&address_, addr->addr, addr->addrlen);
  }

  const sockaddr* operator*() const {
    return reinterpret_cast<const sockaddr*>(&address_);
  }

  ngtcp2_addr ToAddr() {
    return ngtcp2_addr{Size(), reinterpret_cast<uint8_t*>(&address_), nullptr};
  }

  size_t Size() {
    return GetAddressLen(&address_);
  }

  int GetFamily() { return address_.ss_family; }

 private:
  sockaddr_storage address_;
};

class SocketAddressLRU : public MemoryRetainer {
 public:
 private:
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
  explicit QuicCID(ngtcp2_cid* cid) : cid_(*cid) {}
  explicit QuicCID(const ngtcp2_cid* cid) : cid_(*cid) {}
  explicit QuicCID(const ngtcp2_cid& cid) : cid_(cid) {}
  QuicCID(const uint8_t* cid, size_t len) {
    ngtcp2_cid_init(&cid_, cid, len);
  }

  std::string ToStr() {
    return std::string(cid_.data, cid_.data + cid_.datalen);
  }

  std::string ToHex() {
    MaybeStackBuffer<char, 64> dest;
    dest.AllocateSufficientStorage(cid_.datalen * 2);
    dest.SetLengthAndZeroTerminate(cid_.datalen * 2);
    size_t written = StringBytes::hex_encode(
        reinterpret_cast<const char*>(cid_.data),
        cid_.datalen,
        *dest,
        dest.length());
    return std::string(*dest, written);
  }

  const ngtcp2_cid* operator*() const { return &cid_; }

  uint8_t* data() { return cid_.data; }

  size_t length() { return cid_.datalen; }

 private:
  ngtcp2_cid cid_;
};

// https://stackoverflow.com/questions/33701430/template-function-to-access-struct-members
template <typename C, typename T>
decltype(auto) access(C* cls, T C::*member) {
  return (cls->*member);
}

template <typename C, typename T, typename... Mems>
decltype(auto) access(C* cls, T C::*member, Mems... rest) {
  return access((cls->*member), rest...);
}

template <typename A, typename... Members>
void IncrementStat(
    uint64_t amount,
    A* a,
    Members... mems) {
  static uint64_t max = std::numeric_limits<uint64_t>::max();
  uint64_t current = access(a, mems...);
  uint64_t delta = std::min(amount, max - current);
  access(a, mems...) += delta;
}

typedef int(*update_fn)(
    ngtcp2_conn* conn,
    const uint8_t* key,
    size_t keylen,
    const uint8_t* iv,
    size_t ivlen);

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
  const EVP_CIPHER* aead;
  const EVP_CIPHER* hp;
  const EVP_MD* prf;
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
  size_t keylen;
  size_t ivlen;
  size_t hplen;
};

struct CryptoParams {
  std::array<uint8_t, 64> key;
  std::array<uint8_t, 64> iv;
  std::array<uint8_t, 64> hp;
  size_t keylen;
  size_t ivlen;
  size_t hplen;
};

struct CryptoToken {
  std::array<uint8_t, 32> key;
  std::array<uint8_t, 32> iv;
  size_t keylen;
  size_t ivlen;
  CryptoToken() : keylen(key.size()), ivlen(iv.size()) {}
};

  // Simple timer wrapper that is used to implement the internals
  // for idle and retransmission timeouts. Call Update to start or
  // reset the timer; Stop to halt the timer.
class Timer {
 public:
  inline explicit Timer(
      Environment* env,
      std::function<void(void* data)> fn,
      void* data = nullptr) :
      stopped_(false),
      env_(env),
      fn_(fn),
      data_(data) {
    uv_timer_init(env_->event_loop(), &timer_);
    timer_.data = this;
    env->AddCleanupHook(CleanupHook, this);
  }

  inline ~Timer() = default;

  // Stops the timer with the side effect of the timer no longer being usable.
  // It will be cleaned up and the Timer object will be destroyed.
  inline void Stop() {
    if (stopped_)
      return;
    stopped_ = true;
    env_->RemoveCleanupHook(CleanupHook, this);

    if (timer_.data == this) {
      timer_.data = nullptr;
      uv_timer_stop(&timer_);
      env_->CloseHandle(
          reinterpret_cast<uv_handle_t*>(&timer_),
          TimerClosedCb);
    }
  }

  // If the timer is not currently active, interval must be either 0 or greater.
  // If the timer is already active, interval is ignored.
  inline void Update(uint64_t interval) {
    if (stopped_)
      return;
    uv_timer_start(&timer_, OnTimeout, interval, interval);
    uv_unref(reinterpret_cast<uv_handle_t*>(&timer_));
  }

 private:
  inline void OnTimeout() {
    fn_(data_);
  }

  static void OnTimeout(uv_timer_t* timer) {
    Timer* t =
        ContainerOf(
            &Timer::timer_,
            reinterpret_cast<uv_timer_t*>(timer));
    t->OnTimeout();
  }

  static void CleanupHook(void* data) {
    static_cast<Timer*>(data)->Stop();
  }

  static void TimerClosedCb(uv_handle_t* timer) {
    std::unique_ptr<Timer> t(
        ContainerOf(
            &Timer::timer_,
            reinterpret_cast<uv_timer_t*>(timer)));
  }

  bool stopped_;
  Environment* env_;
  std::function<void(void* data)> fn_;
  uv_timer_t timer_;
  void* data_;
};

}  // namespace quic
}  // namespace node

#endif  // NOE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_UTIL_H_
