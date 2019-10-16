#ifndef SRC_NODE_HTTP_COMMON_H_
#define SRC_NODE_HTTP_COMMON_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "v8.h"

namespace node {

class Environment;

#define HTTP_SPECIAL_HEADERS(V)                                               \
  V(STATUS, ":status")                                                        \
  V(METHOD, ":method")                                                        \
  V(AUTHORITY, ":authority")                                                  \
  V(SCHEME, ":scheme")                                                        \
  V(PATH, ":path")                                                            \
  V(PROTOCOL, ":protocol")

// These are provided strictly as a convenience to users and are exposed via the
// require('http2').constants objects
#define HTTP_REGULAR_HEADERS(V)                                               \
  V(ACCEPT_ENCODING, "accept-encoding")                                       \
  V(ACCEPT_LANGUAGE, "accept-language")                                       \
  V(ACCEPT_RANGES, "accept-ranges")                                           \
  V(ACCEPT, "accept")                                                         \
  V(ACCESS_CONTROL_ALLOW_CREDENTIALS, "access-control-allow-credentials")     \
  V(ACCESS_CONTROL_ALLOW_HEADERS, "access-control-allow-headers")             \
  V(ACCESS_CONTROL_ALLOW_METHODS, "access-control-allow-methods")             \
  V(ACCESS_CONTROL_ALLOW_ORIGIN, "access-control-allow-origin")               \
  V(ACCESS_CONTROL_EXPOSE_HEADERS, "access-control-expose-headers")           \
  V(ACCESS_CONTROL_REQUEST_HEADERS, "access-control-request-headers")         \
  V(ACCESS_CONTROL_REQUEST_METHOD, "access-control-request-method")           \
  V(AGE, "age")                                                               \
  V(AUTHORIZATION, "authorization")                                           \
  V(CACHE_CONTROL, "cache-control")                                           \
  V(CONNECTION, "connection")                                                 \
  V(CONTENT_DISPOSITION, "content-disposition")                               \
  V(CONTENT_ENCODING, "content-encoding")                                     \
  V(CONTENT_LENGTH, "content-length")                                         \
  V(CONTENT_TYPE, "content-type")                                             \
  V(COOKIE, "cookie")                                                         \
  V(DATE, "date")                                                             \
  V(ETAG, "etag")                                                             \
  V(FORWARDED, "forwarded")                                                   \
  V(HOST, "host")                                                             \
  V(IF_MODIFIED_SINCE, "if-modified-since")                                   \
  V(IF_NONE_MATCH, "if-none-match")                                           \
  V(IF_RANGE, "if-range")                                                     \
  V(LAST_MODIFIED, "last-modified")                                           \
  V(LINK, "link")                                                             \
  V(LOCATION, "location")                                                     \
  V(RANGE, "range")                                                           \
  V(REFERER, "referer")                                                       \
  V(SERVER, "server")                                                         \
  V(SET_COOKIE, "set-cookie")                                                 \
  V(STRICT_TRANSPORT_SECURITY, "strict-transport-security")                   \
  V(TRANSFER_ENCODING, "transfer-encoding")                                   \
  V(TE, "te")                                                                 \
  V(UPGRADE_INSECURE_REQUESTS, "upgrade-insecure-requests")                   \
  V(UPGRADE, "upgrade")                                                       \
  V(USER_AGENT, "user-agent")                                                 \
  V(VARY, "vary")                                                             \
  V(X_CONTENT_TYPE_OPTIONS, "x-content-type-options")                         \
  V(X_FRAME_OPTIONS, "x-frame-options")                                       \
  V(KEEP_ALIVE, "keep-alive")                                                 \
  V(PROXY_CONNECTION, "proxy-connection")                                     \
  V(X_XSS_PROTECTION, "x-xss-protection")                                     \
  V(ALT_SVC, "alt-svc")                                                       \
  V(CONTENT_SECURITY_POLICY, "content-security-policy")                       \
  V(EARLY_DATA, "early-data")                                                 \
  V(EXPECT_CT, "expect-ct")                                                   \
  V(ORIGIN, "origin")                                                         \
  V(PURPOSE, "purpose")                                                       \
  V(TIMING_ALLOW_ORIGIN, "timing-allow-origin")                               \
  V(X_FORWARDED_FOR, "x-forwarded-for")

#define HTTP_ADDITIONAL_HEADERS(V)                                            \
  V(ACCEPT_CHARSET, "accept-charset")                                         \
  V(ACCESS_CONTROL_MAX_AGE, "access-control-max-age")                         \
  V(ALLOW, "allow")                                                           \
  V(CONTENT_LANGUAGE, "content-language")                                     \
  V(CONTENT_LOCATION, "content-location")                                     \
  V(CONTENT_MD5, "content-md5")                                               \
  V(CONTENT_RANGE, "content-range")                                           \
  V(DNT, "dnt")                                                               \
  V(EXPECT, "expect")                                                         \
  V(EXPIRES, "expires")                                                       \
  V(FROM, "from")                                                             \
  V(IF_MATCH, "if-match")                                                     \
  V(IF_UNMODIFIED_SINCE, "if-unmodified-since")                               \
  V(MAX_FORWARDS, "max-forwards")                                             \
  V(PREFER, "prefer")                                                         \
  V(PROXY_AUTHENTICATE, "proxy-authenticate")                                 \
  V(PROXY_AUTHORIZATION, "proxy-authorization")                               \
  V(REFRESH, "refresh")                                                       \
  V(RETRY_AFTER, "retry-after")                                               \
  V(TRAILER, "trailer")                                                       \
  V(TK, "tk")                                                                 \
  V(VIA, "via")                                                               \
  V(WARNING, "warning")                                                       \
  V(WWW_AUTHENTICATE, "www-authenticate")                                     \
  V(HTTP2_SETTINGS, "http2-settings")

// These are provided strictly as a convenience to users and are exposed via the
// require('http2').constants objects
#define HTTP_KNOWN_HEADERS(V)                                                 \
  HTTP_SPECIAL_HEADERS(V)                                                     \
  HTTP_REGULAR_HEADERS(V)                                                     \
  HTTP_ADDITIONAL_HEADERS(V)

enum http_known_headers {
  HTTP_KNOWN_HEADER_MIN,
#define V(name, value) HTTP_HEADER_##name,
  HTTP_KNOWN_HEADERS(V)
#undef V
  HTTP_KNOWN_HEADER_MAX
};

// While some of these codes are used within the HTTP/2 implementation in
// core, they are provided strictly as a convenience to users and are exposed
// via the require('http2').constants object.
#define HTTP_STATUS_CODES(V)                                                  \
  V(CONTINUE, 100)                                                            \
  V(SWITCHING_PROTOCOLS, 101)                                                 \
  V(PROCESSING, 102)                                                          \
  V(EARLY_HINTS, 103)                                                         \
  V(OK, 200)                                                                  \
  V(CREATED, 201)                                                             \
  V(ACCEPTED, 202)                                                            \
  V(NON_AUTHORITATIVE_INFORMATION, 203)                                       \
  V(NO_CONTENT, 204)                                                          \
  V(RESET_CONTENT, 205)                                                       \
  V(PARTIAL_CONTENT, 206)                                                     \
  V(MULTI_STATUS, 207)                                                        \
  V(ALREADY_REPORTED, 208)                                                    \
  V(IM_USED, 226)                                                             \
  V(MULTIPLE_CHOICES, 300)                                                    \
  V(MOVED_PERMANENTLY, 301)                                                   \
  V(FOUND, 302)                                                               \
  V(SEE_OTHER, 303)                                                           \
  V(NOT_MODIFIED, 304)                                                        \
  V(USE_PROXY, 305)                                                           \
  V(TEMPORARY_REDIRECT, 307)                                                  \
  V(PERMANENT_REDIRECT, 308)                                                  \
  V(BAD_REQUEST, 400)                                                         \
  V(UNAUTHORIZED, 401)                                                        \
  V(PAYMENT_REQUIRED, 402)                                                    \
  V(FORBIDDEN, 403)                                                           \
  V(NOT_FOUND, 404)                                                           \
  V(METHOD_NOT_ALLOWED, 405)                                                  \
  V(NOT_ACCEPTABLE, 406)                                                      \
  V(PROXY_AUTHENTICATION_REQUIRED, 407)                                       \
  V(REQUEST_TIMEOUT, 408)                                                     \
  V(CONFLICT, 409)                                                            \
  V(GONE, 410)                                                                \
  V(LENGTH_REQUIRED, 411)                                                     \
  V(PRECONDITION_FAILED, 412)                                                 \
  V(PAYLOAD_TOO_LARGE, 413)                                                   \
  V(URI_TOO_LONG, 414)                                                        \
  V(UNSUPPORTED_MEDIA_TYPE, 415)                                              \
  V(RANGE_NOT_SATISFIABLE, 416)                                               \
  V(EXPECTATION_FAILED, 417)                                                  \
  V(TEAPOT, 418)                                                              \
  V(MISDIRECTED_REQUEST, 421)                                                 \
  V(UNPROCESSABLE_ENTITY, 422)                                                \
  V(LOCKED, 423)                                                              \
  V(FAILED_DEPENDENCY, 424)                                                   \
  V(TOO_EARLY, 425)                                                           \
  V(UPGRADE_REQUIRED, 426)                                                    \
  V(PRECONDITION_REQUIRED, 428)                                               \
  V(TOO_MANY_REQUESTS, 429)                                                   \
  V(REQUEST_HEADER_FIELDS_TOO_LARGE, 431)                                     \
  V(UNAVAILABLE_FOR_LEGAL_REASONS, 451)                                       \
  V(INTERNAL_SERVER_ERROR, 500)                                               \
  V(NOT_IMPLEMENTED, 501)                                                     \
  V(BAD_GATEWAY, 502)                                                         \
  V(SERVICE_UNAVAILABLE, 503)                                                 \
  V(GATEWAY_TIMEOUT, 504)                                                     \
  V(HTTP_VERSION_NOT_SUPPORTED, 505)                                          \
  V(VARIANT_ALSO_NEGOTIATES, 506)                                             \
  V(INSUFFICIENT_STORAGE, 507)                                                \
  V(LOOP_DETECTED, 508)                                                       \
  V(BANDWIDTH_LIMIT_EXCEEDED, 509)                                            \
  V(NOT_EXTENDED, 510)                                                        \
  V(NETWORK_AUTHENTICATION_REQUIRED, 511)

enum http_status_codes {
#define V(name, code) HTTP_STATUS_##name = code,
  HTTP_STATUS_CODES(V)
#undef V
};

// Unlike the HTTP/1 implementation, the HTTP/2 implementation is not limited
// to a fixed number of known supported HTTP methods. These constants, therefore
// are provided strictly as a convenience to users and are exposed via the
// require('http2').constants object.
#define HTTP_KNOWN_METHODS(V)                                                 \
  V(ACL, "ACL")                                                               \
  V(BASELINE_CONTROL, "BASELINE-CONTROL")                                     \
  V(BIND, "BIND")                                                             \
  V(CHECKIN, "CHECKIN")                                                       \
  V(CHECKOUT, "CHECKOUT")                                                     \
  V(CONNECT, "CONNECT")                                                       \
  V(COPY, "COPY")                                                             \
  V(DELETE, "DELETE")                                                         \
  V(GET, "GET")                                                               \
  V(HEAD, "HEAD")                                                             \
  V(LABEL, "LABEL")                                                           \
  V(LINK, "LINK")                                                             \
  V(LOCK, "LOCK")                                                             \
  V(MERGE, "MERGE")                                                           \
  V(MKACTIVITY, "MKACTIVITY")                                                 \
  V(MKCALENDAR, "MKCALENDAR")                                                 \
  V(MKCOL, "MKCOL")                                                           \
  V(MKREDIRECTREF, "MKREDIRECTREF")                                           \
  V(MKWORKSPACE, "MKWORKSPACE")                                               \
  V(MOVE, "MOVE")                                                             \
  V(OPTIONS, "OPTIONS")                                                       \
  V(ORDERPATCH, "ORDERPATCH")                                                 \
  V(PATCH, "PATCH")                                                           \
  V(POST, "POST")                                                             \
  V(PRI, "PRI")                                                               \
  V(PROPFIND, "PROPFIND")                                                     \
  V(PROPPATCH, "PROPPATCH")                                                   \
  V(PUT, "PUT")                                                               \
  V(REBIND, "REBIND")                                                         \
  V(REPORT, "REPORT")                                                         \
  V(SEARCH, "SEARCH")                                                         \
  V(TRACE, "TRACE")                                                           \
  V(UNBIND, "UNBIND")                                                         \
  V(UNCHECKOUT, "UNCHECKOUT")                                                 \
  V(UNLINK, "UNLINK")                                                         \
  V(UNLOCK, "UNLOCK")                                                         \
  V(UPDATE, "UPDATE")                                                         \
  V(UPDATEREDIRECTREF, "UPDATEREDIRECTREF")                                   \
  V(VERSION_CONTROL, "VERSION-CONTROL")

template <typename T>
class NgHeaders {
 public:
  typedef typename T::nv_t nv_t;
  inline NgHeaders(Environment* env, v8::Local<v8::Array> headers);
  ~NgHeaders() = default;

  nv_t* operator*() {
    return reinterpret_cast<nv_t*>(*buf_);
  }

  size_t length() const {
    return count_;
  }

 private:
  size_t count_;
  MaybeStackBuffer<char, 3000> buf_;
};

template <typename T>
class NgRcBufPointer : public MemoryRetainer {
 public:
  typedef typename T::rcbuf_t rcbuf_t;
  typedef typename T::vector_t vector_t;
  NgRcBufPointer() {}

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackFieldWithSize("buf", len(), "buf");
  }

  SET_MEMORY_INFO_NAME(NgRcBufPointer)
  SET_SELF_SIZE(NgRcBufPointer)

  explicit NgRcBufPointer(rcbuf_t* buf) {
    reset(buf);
  }

  template <typename B>
  NgRcBufPointer(const NgRcBufPointer<B>& other) {
    reset(other.get());
  }

  NgRcBufPointer(const NgRcBufPointer& other) {
    reset(other.get());
  }

  template <typename B>
  NgRcBufPointer& operator=(const NgRcBufPointer<B>& other) {
    if (other.get() == get()) return *this;
    this->~NgRcBufPointer();
    return *new (this) NgRcBufPointer(other);
  }

  NgRcBufPointer& operator=(const NgRcBufPointer& other) {
    if (other.get() == get()) return *this;
    this->~NgRcBufPointer();
    return *new (this) NgRcBufPointer(other);
  }

  NgRcBufPointer(NgRcBufPointer&& other) {
    this->~NgRcBufPointer();
    buf_ = other.buf_;
    other.buf_ = nullptr;
  }

  NgRcBufPointer& operator=(NgRcBufPointer&& other) {
    this->~NgRcBufPointer();
    return *new (this) NgRcBufPointer(std::move(other));
  }

  ~NgRcBufPointer() { T::dec(get()); }

  // Returns the underlying ngvec for this rcbuf
  uint8_t* data() const {
    vector_t v = T::get_vec(buf_);
    return v.base;
  }

  size_t len() const {
    vector_t v = T::get_vec(buf_);
    return v.len;
  }

  void reset(rcbuf_t* ptr = nullptr, bool internalizable = false) {
    this->~NgRcBufPointer();
    buf_ = ptr;
    T::inc(ptr);
    internalizable_ = internalizable;
  }
  rcbuf_t* get() const { return buf_; }
  rcbuf_t& operator*() const { return *get(); }
  rcbuf_t* operator->() const { return buf_; }
  operator bool() const { return buf_ != nullptr; }
  bool IsStatic() const { return T::is_static(buf_) != 0; }
  void SetInternalizable() { internalizable_ = true; }
  bool IsInternalizable() { return internalizable_; }

  static inline bool IsZeroLength(rcbuf_t* buf) {
    if (buf == nullptr)
      return true;
    vector_t b = T::get_vec(buf);
    return b.len == 0;
  }

  class External : public v8::String::ExternalOneByteStringResource {
   public:
    explicit External(const NgRcBufPointer<T>& ptr) : ptr_(ptr) {}

    const char* data() const override {
      return const_cast<const char*>(reinterpret_cast<char*>(ptr_.data()));
    }

    size_t length() const override {
      return ptr_.len();
    }

    static inline
    v8::MaybeLocal<v8::String> GetInternalizedString(
        Environment* env,
        const NgRcBufPointer<T>& ptr) {
      return v8::String::NewFromOneByte(
          env->isolate(),
          ptr.data(),
          v8::NewStringType::kInternalized,
          ptr.len());
    }

    static v8::MaybeLocal<v8::String> New(
        Environment* env,
        NgRcBufPointer<T> ptr) {
      if (ptr.IsStatic()) {
        auto& static_str_map = env->isolate_data()->http_static_strs;
        v8::Eternal<v8::String>& eternal = static_str_map[ptr.get()];
        if (eternal.IsEmpty()) {
          v8::Local<v8::String> str =
              GetInternalizedString(env, ptr).ToLocalChecked();
          eternal.Set(env->isolate(), str);
          return str;
        }
        return eternal.Get(env->isolate());
      }

      size_t len = ptr.len();

      if (len == 0) {
        ptr.reset();
        return v8::String::Empty(env->isolate());
      }

      if (ptr.IsInternalizable() && len < 64) {
        v8::MaybeLocal<v8::String> ret = GetInternalizedString(env, ptr);
        ptr.reset();
        return ret;
      }

      External* h_str = new External(std::move(ptr));
      v8::MaybeLocal<v8::String> str =
          v8::String::NewExternalOneByte(env->isolate(), h_str);
      if (str.IsEmpty())
        delete h_str;

      return str;
    }

   private:
    NgRcBufPointer<T> ptr_;
  };

 private:
  rcbuf_t* buf_;
  bool internalizable_ = false;
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP_COMMON_H_
