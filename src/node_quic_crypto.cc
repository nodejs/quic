#include "node_quic_crypto.h"
#include "env-inl.h"
#include "node_crypto.h"
#include "node_quic_session-inl.h"
#include "node_quic_util.h"
#include "node_url.h"
#include "string_bytes.h"
#include "v8.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iterator>
#include <numeric>
#include <unordered_map>
#include <string>
#include <sstream>
#include <vector>

namespace node {

using crypto::EntropySource;
using v8::Array;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace quic {

constexpr int NGTCP2_CRYPTO_SECRETLEN = 64;
constexpr int NGTCP2_CRYPTO_KEYLEN = 64;
constexpr int NGTCP2_CRYPTO_IVLEN = 64;
constexpr int NGTCP2_CRYPTO_TOKEN_SECRETLEN = 32;
constexpr int NGTCP2_CRYPTO_TOKEN_KEYLEN = 32;
constexpr int NGTCP2_CRYPTO_TOKEN_IVLEN = 32;

using InitialSecret = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN>;
using InitialKey = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN>;
using InitialIV = std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN>;
using SessionSecret = std::array<uint8_t, NGTCP2_CRYPTO_SECRETLEN>;
using SessionKey = std::array<uint8_t, NGTCP2_CRYPTO_KEYLEN>;
using SessionIV = std::array<uint8_t, NGTCP2_CRYPTO_IVLEN>;
using TokenSecret = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_SECRETLEN>;
using TokenKey = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_KEYLEN>;
using TokenIV = std::array<uint8_t, NGTCP2_CRYPTO_TOKEN_IVLEN>;

constexpr char QUIC_CLIENT_EARLY_TRAFFIC_SECRET[] =
    "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
constexpr char QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET[] =
    "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
constexpr char QUIC_CLIENT_TRAFFIC_SECRET_0[] =
    "QUIC_CLIENT_TRAFFIC_SECRET_0";
constexpr char QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET[] =
    "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
constexpr char QUIC_SERVER_TRAFFIC_SECRET_0[] =
    "QUIC_SERVER_TRAFFIC_SECRET_0";

bool DeriveTokenKey(
    uint8_t* token_key,
    uint8_t* token_iv,
    const uint8_t* rand_data,
    size_t rand_datalen,
    const ngtcp2_crypto_ctx* ctx,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {
  TokenSecret secret;

  return
      NGTCP2_OK(ngtcp2_crypto_hkdf_extract(
          secret.data(),
          secret.size(),
          &ctx->md,
          token_secret->data(),
          token_secret->size(),
          rand_data,
          rand_datalen)) &&
      NGTCP2_OK(ngtcp2_crypto_derive_packet_protection_key(
          token_key,
          token_iv,
          nullptr,
          &ctx->aead,
          &ctx->md,
          secret.data(),
          secret.size()));
}

bool MessageDigest(
    std::array<uint8_t, 32>* dest,
    const std::array<uint8_t, 16>& rand) {
  const EVP_MD* meth = EVP_sha256();
  DeleteFnPtr<EVP_MD_CTX, EVP_MD_CTX_free> ctx;
  ctx.reset(EVP_MD_CTX_new());
  CHECK(ctx);

  if (EVP_DigestInit_ex(ctx.get(), meth, nullptr) != 1)
    return false;

  if (EVP_DigestUpdate(ctx.get(), rand.data(), rand.size()) != 1)
    return false;

  unsigned int mdlen = EVP_MD_size(meth);

  return EVP_DigestFinal_ex(ctx.get(), dest->data(), &mdlen) == 1;
}

bool GenerateRandData(uint8_t* buf, size_t len) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;
  EntropySource(rand.data(), rand.size());

  if (!MessageDigest(&md, rand))
    return false;

  CHECK_LE(len, md.size());
  std::copy_n(std::begin(md), len, buf);
  return true;
}

Local<Array> GetClientHelloCiphers(QuicSession* session) {
  const unsigned char* buf;
  Environment* env = session->env();
  QuicCryptoContext* ctx = session->CryptoContext();
  size_t len = SSL_client_hello_get0_ciphers(**ctx, &buf);
  std::vector<Local<Value>> ciphers_array;
  for (size_t n = 0; n < len; n += 2) {
    const SSL_CIPHER* cipher = SSL_CIPHER_find(**ctx, buf);
    buf += 2;
    const char* cipher_name = SSL_CIPHER_get_name(cipher);
    const char* cipher_version = SSL_CIPHER_get_version(cipher);
    Local<Object> obj = Object::New(env->isolate());
    obj->Set(
        env->context(),
        env->name_string(),
        OneByteString(env->isolate(), cipher_name)).FromJust();
    obj->Set(
        env->context(),
        env->version_string(),
        OneByteString(env->isolate(), cipher_version)).FromJust();
    ciphers_array.push_back(obj);
  }
  return Array::New(env->isolate(), ciphers_array.data(), ciphers_array.size());
}

const char* GetClientHelloServerName(QuicSession* session) {
    const unsigned char* buf;
    size_t len;
    size_t rem;

    QuicCryptoContext* ctx = session->CryptoContext();

    if (!SSL_client_hello_get0_ext(
            **ctx,
            TLSEXT_TYPE_server_name,
            &buf,
            &rem) || rem <= 2) {
        return nullptr;
    }

    len = *(buf++) << 8;
    len += *(buf++);
    if (len + 2 != rem)
      return nullptr;
    rem = len;

    if (rem == 0 || *buf++ != TLSEXT_NAMETYPE_host_name)
      return nullptr;
    rem--;
    if (rem <= 2)
      return nullptr;
    len = *(buf++) << 8;
    len += *(buf++);
    if (len + 2 > rem)
      return nullptr;
    rem = len;
    return reinterpret_cast<const char*>(buf);
}

const char* GetClientHelloALPN(QuicSession* session) {
    const unsigned char* buf;
    size_t len;
    size_t rem;

    QuicCryptoContext* ctx = session->CryptoContext();

    if (!SSL_client_hello_get0_ext(
            **ctx,
            TLSEXT_TYPE_application_layer_protocol_negotiation,
            &buf, &rem) || rem < 2) {
      return nullptr;
    }

    len = (buf[0] << 8) | buf[1];
    if (len + 2 != rem)
      return nullptr;
    buf += 3;
    return reinterpret_cast<const char*>(buf);
}

int UseSNIContext(SSL* ssl, crypto::SecureContext* context) {
  SSL_CTX* ctx = context->ctx_.get();
  X509* x509 = SSL_CTX_get0_certificate(ctx);
  EVP_PKEY* pkey = SSL_CTX_get0_privatekey(ctx);
  STACK_OF(X509)* chain;

  int err = SSL_CTX_get0_chain_certs(ctx, &chain);
  if (err)
    err = SSL_use_certificate(ssl, x509);
  if (err)
    err = SSL_use_PrivateKey(ssl, pkey);
  if (err && chain != nullptr)
    err = SSL_set1_chain(ssl, chain);
  return err;
}

// The Retry Token is an encrypted token that is sent to the client
// by the server as part of the path validation flow. The plaintext
// format within the token is opaque and only meaningful the server.
// We can structure it any way we want. It needs to:
//   * be hard to guess
//   * be time limited
//   * be specific to the client address
//   * be specific to the original cid
//   * contain random data.
bool GenerateRetryToken(
    uint8_t* token,
    size_t* tokenlen,
    const sockaddr* addr,
    const ngtcp2_cid* ocid,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret) {
  std::array<uint8_t, 4096> plaintext;

  ngtcp2_crypto_ctx ctx;
  ngtcp2_crypto_ctx_initial(&ctx);

  const size_t addrlen = SocketAddress::GetAddressLen(addr);
  size_t ivlen = ngtcp2_crypto_packet_protection_ivlen(&ctx.aead);

  uint64_t now = uv_hrtime();

  auto p = std::begin(plaintext);
  p = std::copy_n(reinterpret_cast<const uint8_t*>(addr), addrlen, p);
  p = std::copy_n(reinterpret_cast<uint8_t*>(&now), sizeof(now), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  TokenKey token_key;
  TokenIV token_iv;

  if (!GenerateRandData(rand_data.data(), TOKEN_RAND_DATALEN))
    return false;

  if (!DeriveTokenKey(
          token_key.data(),
          token_iv.data(),
          rand_data.data(),
          TOKEN_RAND_DATALEN,
          &ctx,
          token_secret)) {
    return false;
  }

  size_t plaintextlen = std::distance(std::begin(plaintext), p);
  if (NGTCP2_ERR(ngtcp2_crypto_encrypt(
          token,
          &ctx.aead,
          plaintext.data(),
          plaintextlen,
          token_key.data(),
          token_iv.data(),
          ivlen,
          reinterpret_cast<const uint8_t *>(addr),
          addrlen))) {
    return false;
  }

  *tokenlen = plaintextlen + ngtcp2_crypto_aead_taglen(&ctx.aead);
  memcpy(token + (*tokenlen), rand_data.data(), rand_data.size());
  *tokenlen += rand_data.size();
  return true;
}

bool InvalidRetryToken(
    Environment* env,
    ngtcp2_cid* ocid,
    const ngtcp2_pkt_hd* hd,
    const sockaddr* addr,
    std::array<uint8_t, TOKEN_SECRETLEN>* token_secret,
    uint64_t verification_expiration) {

  ngtcp2_crypto_ctx ctx;
  ngtcp2_crypto_ctx_initial(&ctx);

  size_t ivlen = ngtcp2_crypto_packet_protection_ivlen(&ctx.aead);
  const size_t addrlen = SocketAddress::GetAddressLen(addr);

  if (hd->tokenlen < TOKEN_RAND_DATALEN)
    return  true;

  uint8_t* rand_data = hd->token + hd->tokenlen - TOKEN_RAND_DATALEN;
  uint8_t* ciphertext = hd->token;
  size_t ciphertextlen = hd->tokenlen - TOKEN_RAND_DATALEN;

  TokenKey token_key;
  TokenIV token_iv;

  if (!DeriveTokenKey(
          token_key.data(),
          token_iv.data(),
          rand_data,
          TOKEN_RAND_DATALEN,
          &ctx,
          token_secret)) {
    return true;
  }

  std::array<uint8_t, 4096> plaintext;

  if (NGTCP2_ERR(ngtcp2_crypto_decrypt(
          plaintext.data(),
          &ctx.aead,
          ciphertext,
          ciphertextlen,
          token_key.data(),
          token_iv.data(),
          ivlen,
          reinterpret_cast<const uint8_t*>(addr), addrlen))) {
    return true;
  }

  size_t plaintextlen = ciphertextlen - ngtcp2_crypto_aead_taglen(&ctx.aead);
  if (plaintextlen < addrlen + sizeof(uint64_t))
    return true;

  ssize_t cil = plaintextlen - addrlen - sizeof(uint64_t);
  if ((cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) ||
      memcmp(plaintext.data(), addr, addrlen) != 0) {
    return true;
  }

  uint64_t t;
  memcpy(&t, plaintext.data() + addrlen, sizeof(uint64_t));

  uint64_t now = uv_hrtime();

  // 10-second window by default, but configurable for each
  // QuicSocket instance with a MIN_RETRYTOKEN_EXPIRATION second
  // minimum and a MAX_RETRYTOKEN_EXPIRATION second maximum.
  if (t + verification_expiration * NGTCP2_SECONDS < now)
    return true;

  ngtcp2_cid_init(ocid, plaintext.data() + addrlen + sizeof(uint64_t), cil);

  return false;
}

int VerifyPeerCertificate(SSL* ssl) {
  int err = X509_V_ERR_UNSPECIFIED;
  if (X509* peer_cert = SSL_get_peer_certificate(ssl)) {
    X509_free(peer_cert);
    err = SSL_get_verify_result(ssl);
  }
  return err;
}

namespace {
std::string GetCertificateCN(X509* cert) {
  X509_NAME* subject = X509_get_subject_name(cert);
  if (subject != nullptr) {
    int nid = OBJ_txt2nid("CN");
    int idx = X509_NAME_get_index_by_NID(subject, nid, -1);
    if (idx != -1) {
      X509_NAME_ENTRY* cn = X509_NAME_get_entry(subject, idx);
      if (cn != nullptr) {
        ASN1_STRING* cn_str = X509_NAME_ENTRY_get_data(cn);
        if (cn_str != nullptr) {
          return std::string(reinterpret_cast<const char*>(
              ASN1_STRING_get0_data(cn_str)));
        }
      }
    }
  }
  return std::string();
}

std::unordered_multimap<std::string, std::string> GetCertificateAltNames(
    X509* cert) {
  std::unordered_multimap<std::string, std::string> map;
  crypto::BIOPointer bio(BIO_new(BIO_s_mem()));
  BUF_MEM* mem;
  int idx = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
  if (idx < 0)  // There is no subject alt name
    return map;

  X509_EXTENSION* ext = X509_get_ext(cert, idx);
  CHECK_NOT_NULL(ext);
  const X509V3_EXT_METHOD* method = X509V3_EXT_get(ext);
  CHECK_EQ(method, X509V3_EXT_get_nid(NID_subject_alt_name));

  GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
  if (names == nullptr)  // There are no names
    return map;

  for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
    USE(BIO_reset(bio.get()));
    GENERAL_NAME* gen = sk_GENERAL_NAME_value(names, i);
    if (gen->type == GEN_DNS) {
      ASN1_IA5STRING* name = gen->d.dNSName;
      BIO_write(bio.get(), name->data, name->length);
      BIO_get_mem_ptr(bio.get(), &mem);
      map.emplace("dns", std::string(mem->data, mem->length));
    } else {
      STACK_OF(CONF_VALUE)* nval = i2v_GENERAL_NAME(
          const_cast<X509V3_EXT_METHOD*>(method), gen, nullptr);
      if (nval == nullptr)
        continue;
      X509V3_EXT_val_prn(bio.get(), nval, 0, 0);
      sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
      BIO_get_mem_ptr(bio.get(), &mem);
      std::string value(mem->data, mem->length);
      if (value.compare(0, 11, "IP Address:") == 0) {
        map.emplace("ip", value.substr(11));
      } else if (value.compare(0, 4, "URI:") == 0) {
        url::URL url(value.substr(4));
        if (url.flags() & url::URL_FLAGS_CANNOT_BE_BASE ||
            url.flags() & url::URL_FLAGS_FAILED) {
          continue;  // Skip this one
        }
        map.emplace("uri", url.host());
      }
    }
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  bio.reset();
  return map;
}

bool SplitHostname(
    const char* hostname,
    std::vector<std::string>* parts,
    const char delim = '.') {
  static std::string check_str =
      "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30"
      "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40"
      "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50"
      "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60"
      "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70"
      "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F";

  std::stringstream str(hostname);
  std::string part;
  while (getline(str, part, delim)) {
    // if (part.length() == 0 ||
    //     part.find_first_not_of(check_str) != std::string::npos) {
    //   return false;
    // }
    for (size_t n = 0; n < part.length(); n++) {
      if (part[n] >= 'A' && part[n] <= 'Z')
        part[n] = (part[n] | 0x20);  // Lower case the letter
      if (check_str.find(part[n]) == std::string::npos)
        return false;
    }
    parts->push_back(part);
  }
  return true;
}

bool CheckCertNames(
    const std::vector<std::string>& host_parts,
    const std::string& name,
    bool use_wildcard = true) {

  if (name.length() == 0)
    return false;

  std::vector<std::string> name_parts;
  if (!SplitHostname(name.c_str(), &name_parts))
    return false;

  if (name_parts.size() != host_parts.size())
    return false;

  for (size_t n = host_parts.size() - 1; n > 0; --n) {
    if (host_parts[n] != name_parts[n])
      return false;
  }

  if (name_parts[0].find("*") == std::string::npos ||
      name_parts[0].find("xn--") != std::string::npos) {
    return host_parts[0] == name_parts[0];
  }

  if (!use_wildcard)
    return false;

  std::vector<std::string> sub_parts;
  SplitHostname(name_parts[0].c_str(), &sub_parts, '*');

  if (sub_parts.size() > 2)
    return false;

  if (name_parts.size() <= 2)
    return false;

  std::string prefix;
  std::string suffix;
  if (sub_parts.size() == 2) {
    prefix = sub_parts[0];
    suffix = sub_parts[1];
  } else {
    prefix = "";
    suffix = sub_parts[0];
  }

  if (prefix.length() + suffix.length() > host_parts[0].length())
    return false;

  if (host_parts[0].compare(0, prefix.length(), prefix))
    return false;

  if (host_parts[0].compare(
          host_parts[0].length() - suffix.length(),
          suffix.length(), suffix)) {
    return false;
  }

  return true;
}


const char* X509ErrorCode(int err) {
  const char* code = "UNSPECIFIED";
#define CASE_X509_ERR(CODE) case X509_V_ERR_##CODE: code = #CODE; break;
  switch (err) {
    CASE_X509_ERR(UNABLE_TO_GET_ISSUER_CERT)
    CASE_X509_ERR(UNABLE_TO_GET_CRL)
    CASE_X509_ERR(UNABLE_TO_DECRYPT_CERT_SIGNATURE)
    CASE_X509_ERR(UNABLE_TO_DECRYPT_CRL_SIGNATURE)
    CASE_X509_ERR(UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)
    CASE_X509_ERR(CERT_SIGNATURE_FAILURE)
    CASE_X509_ERR(CRL_SIGNATURE_FAILURE)
    CASE_X509_ERR(CERT_NOT_YET_VALID)
    CASE_X509_ERR(CERT_HAS_EXPIRED)
    CASE_X509_ERR(CRL_NOT_YET_VALID)
    CASE_X509_ERR(CRL_HAS_EXPIRED)
    CASE_X509_ERR(ERROR_IN_CERT_NOT_BEFORE_FIELD)
    CASE_X509_ERR(ERROR_IN_CERT_NOT_AFTER_FIELD)
    CASE_X509_ERR(ERROR_IN_CRL_LAST_UPDATE_FIELD)
    CASE_X509_ERR(ERROR_IN_CRL_NEXT_UPDATE_FIELD)
    CASE_X509_ERR(OUT_OF_MEM)
    CASE_X509_ERR(DEPTH_ZERO_SELF_SIGNED_CERT)
    CASE_X509_ERR(SELF_SIGNED_CERT_IN_CHAIN)
    CASE_X509_ERR(UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    CASE_X509_ERR(UNABLE_TO_VERIFY_LEAF_SIGNATURE)
    CASE_X509_ERR(CERT_CHAIN_TOO_LONG)
    CASE_X509_ERR(CERT_REVOKED)
    CASE_X509_ERR(INVALID_CA)
    CASE_X509_ERR(PATH_LENGTH_EXCEEDED)
    CASE_X509_ERR(INVALID_PURPOSE)
    CASE_X509_ERR(CERT_UNTRUSTED)
    CASE_X509_ERR(CERT_REJECTED)
    CASE_X509_ERR(HOSTNAME_MISMATCH)
  }
#undef CASE_X509_ERR
  return code;
}

}  // namespace

Local<Value> GetValidationErrorReason(Environment* env, int err) {
  const char* reason = X509_verify_cert_error_string(err);
  return OneByteString(env->isolate(), reason);
}

Local<Value> GetValidationErrorCode(Environment* env, int err) {
  return OneByteString(env->isolate(), X509ErrorCode(err));
}

int VerifyHostnameIdentity(SSL* ssl, const char* hostname) {
  int err = X509_V_ERR_HOSTNAME_MISMATCH;
  crypto::X509Pointer cert(SSL_get_peer_certificate(ssl));
  if (!cert)
    return err;

  // There are several pieces of information we need from the cert at this point
  // 1. The Subject (if it exists)
  // 2. The collection of Alt Names (if it exists)
  //
  // The certificate may have many Alt Names. We only care about the ones that
  // are prefixed with 'DNS:', 'URI:', or 'IP Address:'. We might check
  // additional ones later but we'll start with these.
  //
  // Ideally, we'd be able to *just* use OpenSSL's built in name checking for
  // this (SSL_set1_host and X509_check_host) but it does not appear to do
  // checking on URI or IP Address Alt names, which is unfortunate. We need
  // both of those to retain compatibility with the peer identity verification
  // Node.js already does elsewhere. At the very least, we'll use
  // X509_check_host here first as a first step. If it is successful, awesome,
  // there's nothing else for us to do. Return and be happy!
  if (X509_check_host(
          cert.get(),
          hostname,
          strlen(hostname),
          X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
          X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS |
          X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
          nullptr) > 0) {
    return 0;
  }

  if (X509_check_ip_asc(
          cert.get(),
          hostname,
          X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) > 0) {
    return 0;
  }

  // If we've made it this far, then we have to perform a more check
  return VerifyHostnameIdentity(
      hostname,
      GetCertificateCN(cert.get()),
      GetCertificateAltNames(cert.get()));
}

int VerifyHostnameIdentity(
    const char* hostname,
    const std::string& cert_cn,
    const std::unordered_multimap<std::string, std::string>& altnames) {

  int err = X509_V_ERR_HOSTNAME_MISMATCH;

  // 1. If the hostname is an IP address (v4 or v6), the certificate is valid
  //    if and only if there is an 'IP Address:' alt name specifying the same
  //    IP address. The IP address must be canonicalized to ensure a proper
  //    check. It's possible that the X509_check_ip_asc covers this. If so,
  //    we can remove this check.

  if (SocketAddress::numeric_host(hostname)) {
    auto ips = altnames.equal_range("ip");
    for (auto ip = ips.first; ip != ips.second; ++ip) {
      if (ip->second.compare(hostname) == 0) {
        // Success!
        return 0;
      }
    }
    // No match, and since the hostname is an IP address, skip any
    // further checks
    return err;
  }

  auto dns_names = altnames.equal_range("dns");
  auto uri_names = altnames.equal_range("uri");

  size_t dns_count = std::distance(dns_names.first, dns_names.second);
  size_t uri_count = std::distance(uri_names.first, uri_names.second);

  std::vector<std::string> host_parts;
  SplitHostname(hostname, &host_parts);

  // 2. If there no 'DNS:' or 'URI:' Alt names, if the certificate has a
  //    Subject, then we need to extract the CN field from the Subject. and
  //    check that the hostname matches the CN, taking into consideration
  //    the possibility of a wildcard in the CN. If there is a match, congrats,
  //    we have a valid certificate. Return and be happy.

  if (dns_count == 0 && uri_count == 0) {
    if (cert_cn.length() > 0 && CheckCertNames(host_parts, cert_cn))
        return 0;
    // No match, and since there are no dns or uri entries, return
    return err;
  }

  // 3. If, however, there are 'DNS:' and 'URI:' Alt names, things become more
  //    complicated. Essentially, we need to iterate through each 'DNS:' and
  //    'URI:' Alt name to find one that matches. The 'DNS:' Alt names are
  //    relatively simple but may include wildcards. The 'URI:' Alt names
  //    require the name to be parsed as a URL, then extract the hostname from
  //    the URL, which is then checked against the hostname. If you find a
  //    match, yay! Return and be happy. (Note, it's possible that the 'DNS:'
  //    check in this step is redundant to the X509_check_host check. If so,
  //    we can simplify by removing those checks here.)

  // First, let's check dns names
  for (auto name = dns_names.first; name != dns_names.second; ++name) {
    if (name->first.length() > 0 &&
        CheckCertNames(host_parts, name->second)) {
      return 0;
    }
  }

  // Then, check uri names
  for (auto name = uri_names.first; name != uri_names.second; ++name) {
    if (name->first.length() > 0 &&
        CheckCertNames(host_parts, name->second, false)) {
      return 0;
    }
  }

  // 4. Failing all of the previous checks, we assume the certificate is
  //    invalid for an unspecified reason.
  return err;
}

const char* GetServerName(QuicSession* session) {
  QuicCryptoContext* ctx = session->CryptoContext();
  return SSL_get_servername(**ctx, TLSEXT_NAMETYPE_host_name);
}

// Get the SNI hostname requested by the client for the session
Local<Value> GetServerName(
    Environment* env,
    SSL* ssl,
    const char* host_name) {
  Local<Value> servername;
  if (host_name != nullptr) {
    servername = String::NewFromUtf8(
        env->isolate(),
        host_name,
        v8::NewStringType::kNormal).ToLocalChecked();
  }
  return servername;
}

// Get the ALPN protocol identifier that was negotiated for the session
Local<Value> GetALPNProtocol(QuicSession* session) {
  Local<Value> alpn;
  const unsigned char* alpn_buf = nullptr;
  unsigned int alpnlen;
  QuicCryptoContext* ctx = session->CryptoContext();

  SSL_get0_alpn_selected(**ctx, &alpn_buf, &alpnlen);
  if (alpnlen == sizeof(NGTCP2_ALPN_H3) - 2 &&
      memcmp(alpn_buf, NGTCP2_ALPN_H3 + 1, sizeof(NGTCP2_ALPN_H3) - 2) == 0) {
    alpn = session->env()->quic_alpn_string();
  } else {
    alpn = OneByteString(session->env()->isolate(), alpn_buf, alpnlen);
  }
  return alpn;
}

Local<Value> GetCertificate(QuicSession* session) {
  crypto::ClearErrorOnReturn clear_error_on_return;
  QuicCryptoContext* ctx = session->CryptoContext();
  Local<Value> value = v8::Undefined(session->env()->isolate());
  X509* cert = SSL_get_certificate(**ctx);
  if (cert != nullptr)
    value = crypto::X509ToObject(session->env(), cert);
  return value;
}

Local<Value> GetEphemeralKey(QuicSession* session) {
  Environment* env = session->env();
  Local<Context> context = env->context();

  Local<Object> info = Object::New(env->isolate());
  QuicCryptoContext* ctx = session->CryptoContext();

  EVP_PKEY* raw_key;
  if (SSL_get_server_tmp_key(**ctx, &raw_key)) {
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
                    FIXED_ONE_BYTE_STRING(
                        env->isolate(),
                        "ECDH")).FromJust();
          info->Set(context, env->name_string(),
                    OneByteString(
                        env->isolate(),
                        curve_name)).FromJust();
          info->Set(context, env->size_string(),
                    Integer::New(
                        env->isolate(),
                        EVP_PKEY_bits(key.get()))).FromJust();
        }
        break;
      default:
        break;
    }
  }
  return info;
}

Local<Value> GetCipherName(QuicSession* session) {
  Local<Value> cipher;
  QuicCryptoContext* ctx = session->CryptoContext();
  const SSL_CIPHER* c = SSL_get_current_cipher(**ctx);
  if (c != nullptr) {
    const char* cipher_name = SSL_CIPHER_get_name(c);
    cipher = OneByteString(session->env()->isolate(), cipher_name);
  }
  return cipher;
}

Local<Value> GetCipherVersion(QuicSession* session) {
  Local<Value> version;
  QuicCryptoContext* ctx = session->CryptoContext();
  const SSL_CIPHER* c = SSL_get_current_cipher(**ctx);
  if (c != nullptr) {
    const char* cipher_version = SSL_CIPHER_get_version(c);
    version = OneByteString(session->env()->isolate(), cipher_version);
  }
  return version;
}

bool SetTLSSession(SSL* ssl, const unsigned char* buf, size_t length) {
  crypto::SSLSessionPointer s(d2i_SSL_SESSION(nullptr, &buf, length));
  return s != nullptr && SSL_set_session(ssl, s.get()) == 1;
}

std::string GetSSLOCSPResponse(SSL* ssl) {
  const unsigned char* resp;
  int len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
  if (len < 0) len = 0;
  return std::string(reinterpret_cast<const char*>(resp), len);
}

Local<Value> GetPeerCertificate(
    QuicSession* session,
    bool abbreviated) {
  crypto::ClearErrorOnReturn clear_error_on_return;

  QuicCryptoContext* ctx = session->CryptoContext();

  Local<Value> result = v8::Undefined(session->env()->isolate());
  Local<Object> issuer_chain;

  // NOTE: This is because of the odd OpenSSL behavior. On client `cert_chain`
  // contains the `peer_certificate`, but on server it doesn't.
  crypto::X509Pointer cert(
      session->IsServer() ? SSL_get_peer_certificate(**ctx) : nullptr);
  STACK_OF(X509)* ssl_certs = SSL_get_peer_cert_chain(**ctx);
  if (!cert && (ssl_certs == nullptr || sk_X509_num(ssl_certs) == 0))
    return result;

  // Short result requested.
  if (abbreviated) {
    return
        crypto::X509ToObject(
            session->env(),
            cert ? cert.get() : sk_X509_value(ssl_certs, 0));
  }

  if (auto peer_certs = crypto::CloneSSLCerts(std::move(cert), ssl_certs)) {
    // First and main certificate.
    crypto::X509Pointer cert(sk_X509_value(peer_certs.get(), 0));
    CHECK(cert);
    result = crypto::X509ToObject(session->env(), cert.release());

    Local<Object> issuer_chain =
        crypto::GetLastIssuedCert(
            &cert,
            **ctx,
            crypto::AddIssuerChainToObject(
                &cert,
                result.As<Object>(),
                std::move(peer_certs),
                session->env()),
            session->env());
    // Last certificate should be self-signed.
    if (X509_check_issued(cert.get(), cert.get()) == X509_V_OK)
      USE(issuer_chain->Set(
          session->env()->context(),
          session->env()->issuercert_string(),
          issuer_chain));
  }
  return result;
}

namespace {
int CertCB(SSL* ssl, void* arg) {
  QuicSession* session = static_cast<QuicSession*>(arg);

  int type = SSL_get_tlsext_status_type(ssl);
  switch (type) {
    case TLSEXT_STATUSTYPE_ocsp:
      return session->CryptoContext()->OnOCSP();
    default:
      return 1;
  }
}

void Keylog_CB(const SSL* ssl, const char* line) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  session->CryptoContext()->Keylog(line);
}

int Client_Hello_CB(
    SSL* ssl,
    int* tls_alert,
    void* arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  int ret = session->CryptoContext()->OnClientHello();
  switch (ret) {
    case 0:
      return 1;
    case -1:
      return -1;
    default:
      *tls_alert = ret;
      return 0;
  }
}

int AlpnSelection(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));

  unsigned char* tmp;

  // The QuicServerSession supports exactly one ALPN identifier. If that does
  // not match any of the ALPN identifiers provided in the client request,
  // then we fail here. Note that this will not fail the TLS handshake, so
  // we have to check later if the ALPN matches the expected identifier or not.
  if (SSL_select_next_proto(
          &tmp,
          outlen,
          reinterpret_cast<const unsigned char*>(session->GetALPN().c_str()),
          session->GetALPN().length(),
          in,
          inlen) == OPENSSL_NPN_NO_OVERLAP) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  *out = tmp;
  return SSL_TLSEXT_ERR_OK;
}

int TLS_Status_Callback(SSL* ssl, void* arg) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  return session->CryptoContext()->OnTLSStatus();
}

int New_Session_Callback(SSL* ssl, SSL_SESSION* session) {
  QuicSession* s = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  return s->SetSession(session);
}

int SetEncryptionSecrets(
    SSL* ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t* read_secret,
    const uint8_t* write_secret,
    size_t secret_len) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  return session->CryptoContext()->OnSecrets(
      from_ossl_level(ossl_level),
      read_secret,
      write_secret,
      secret_len) ? 1 : 0;
}

int AddHandshakeData(
    SSL* ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t* data,
    size_t len) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  session->CryptoContext()->WriteHandshake(
      from_ossl_level(ossl_level),
      data,
      len);
  return 1;
}

int FlushFlight(SSL* ssl) { return 1; }

int SendAlert(
    SSL* ssl,
    enum ssl_encryption_level_t level,
    uint8_t alert) {
  QuicSession* session = static_cast<QuicSession*>(SSL_get_app_data(ssl));
  session->CryptoContext()->SetTLSAlert(alert);
  return 1;
}

void SetALPN(SSL* ssl, const std::string& alpn) {
  SSL_set_alpn_protos(
      ssl,
      reinterpret_cast<const uint8_t*>(alpn.c_str()),
      alpn.length());
}

void SetHostname(SSL* ssl, const std::string& hostname) {
  // TODO(@jasnell): Need to determine if setting localhost
  // here is the right thing to do.
  if (hostname.length() == 0 ||
      SocketAddress::numeric_host(hostname.c_str())) {
    SSL_set_tlsext_host_name(ssl, "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
  }
}

bool SetTransportParams(ngtcp2_conn* connection, SSL* ssl) {
  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(connection, &params);
  std::array<uint8_t, 512> buf;
  ssize_t nwrite = ngtcp2_encode_transport_params(
      buf.data(),
      buf.size(),
      NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);
  return nwrite >= 0 &&
      SSL_set_quic_transport_params(ssl, buf.data(), nwrite) == 1;
}

void LogSecret(
    SSL* ssl,
    const char* name,
    const unsigned char* secret,
    size_t secretlen) {
  if (auto keylog_cb = SSL_CTX_get_keylog_callback(SSL_get_SSL_CTX(ssl))) {
    unsigned char crandom[32];
    if (SSL_get_client_random(ssl, crandom, 32) != 32)
      return;
    std::string line = name;
    line += " " + StringBytes::hex_encode(
        reinterpret_cast<const char*>(crandom), 32);
    line += " " + StringBytes::hex_encode(
        reinterpret_cast<const char*>(secret), secretlen);
    keylog_cb(ssl, line.c_str());
  }
}

SSL_QUIC_METHOD quic_method = SSL_QUIC_METHOD{
  SetEncryptionSecrets,
  AddHandshakeData,
  FlushFlight,
  SendAlert
};
}  // namespace

void InitializeTLS(QuicSession* session) {
  QuicCryptoContext* ctx = session->CryptoContext();

  SSL_set_app_data(**ctx, session);
  SSL_set_cert_cb(**ctx, CertCB, session);
  SSL_set_verify(**ctx, SSL_VERIFY_NONE, crypto::VerifyCallback);
  SSL_set_quic_early_data_enabled(**ctx, 1);

  // Enable tracing if the `--trace-tls` command line flag
  // is used. TODO(@jasnell): Add process warning for this
  if (session->env()->options()->trace_tls)
    ctx->EnableTrace();

  switch (ctx->Side()) {
    case NGTCP2_CRYPTO_SIDE_CLIENT: {
      SSL_set_connect_state(**ctx);
      SetALPN(**ctx, session->GetALPN());
      SetHostname(**ctx, session->GetHostname());
      if (ctx->IsOptionSet(QUICCLIENTSESSION_OPTION_REQUEST_OCSP))
        SSL_set_tlsext_status_type(**ctx, TLSEXT_STATUSTYPE_ocsp);
      break;
    }
    case NGTCP2_CRYPTO_SIDE_SERVER: {
      SSL_set_accept_state(**ctx);
      if (ctx->IsOptionSet(QUICSERVERSESSION_OPTION_REQUEST_CERT)) {
        int verify_mode = SSL_VERIFY_PEER;
        if (ctx->IsOptionSet(QUICSERVERSESSION_OPTION_REJECT_UNAUTHORIZED))
          verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_set_verify(**ctx, verify_mode, crypto::VerifyCallback);
      }
      break;
    }
    default:
      UNREACHABLE();
  }

  SetTransportParams(session->Connection(), **ctx);
}

bool SetGroups(crypto::SecureContext* sc, const char* groups) {
  return SSL_CTX_set1_groups_list(**sc, groups) == 1;
}

void InitializeSecureContext(
    crypto::SecureContext* sc,
    ngtcp2_crypto_side side) {
  constexpr auto ssl_server_opts =
      (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
      SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE |
      SSL_OP_NO_ANTI_REPLAY;
  switch (side) {
    case NGTCP2_CRYPTO_SIDE_SERVER:
      SSL_CTX_set_options(**sc, ssl_server_opts);
      SSL_CTX_set_mode(**sc, SSL_MODE_RELEASE_BUFFERS);
      SSL_CTX_set_max_early_data(**sc, std::numeric_limits<uint32_t>::max());
      SSL_CTX_set_alpn_select_cb(**sc, AlpnSelection, nullptr);
      SSL_CTX_set_client_hello_cb(**sc, Client_Hello_CB, nullptr);
      break;
    case NGTCP2_CRYPTO_SIDE_CLIENT:
      SSL_CTX_set_session_cache_mode(
          **sc,
          SSL_SESS_CACHE_CLIENT |
          SSL_SESS_CACHE_NO_INTERNAL_STORE);
      SSL_CTX_sess_set_new_cb(**sc, New_Session_Callback);
      break;
    default:
      UNREACHABLE();
  }
  SSL_CTX_set_min_proto_version(**sc, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(**sc, TLS1_3_VERSION);
  SSL_CTX_set_default_verify_paths(**sc);
  SSL_CTX_set_tlsext_status_cb(**sc, TLS_Status_Callback);
  SSL_CTX_set_keylog_callback(**sc, Keylog_CB);
  SSL_CTX_set_tlsext_status_arg(**sc, nullptr);
  SSL_CTX_set_quic_method(**sc, &quic_method);
}

bool SetCryptoSecrets(
    QuicSession* session,
    ngtcp2_crypto_level level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen) {
  SessionKey rx_key;
  SessionIV rx_iv;
  SessionKey rx_hp;
  SessionKey tx_key;
  SessionIV tx_iv;
  SessionKey tx_hp;

  QuicCryptoContext* ctx = session->CryptoContext();

  if (NGTCP2_ERR(ngtcp2_crypto_derive_and_install_key(
          session->Connection(),
          **ctx,
          rx_key.data(),
          rx_iv.data(),
          rx_hp.data(),
          tx_key.data(),
          tx_iv.data(),
          tx_hp.data(),
          level,
          rx_secret,
          tx_secret,
          secretlen,
          session->CryptoContext()->Side()))) {
    return false;
  }

  switch (level) {
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    LogSecret(
        **ctx,
        QUIC_CLIENT_EARLY_TRAFFIC_SECRET,
        rx_secret,
        secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    LogSecret(
        **ctx,
        QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
        rx_secret,
        secretlen);
    LogSecret(
        **ctx,
        QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET,
        tx_secret,
        secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_APP:
    LogSecret(
        **ctx,
        QUIC_CLIENT_TRAFFIC_SECRET_0,
        rx_secret,
        secretlen);
    LogSecret(
        **ctx,
        QUIC_SERVER_TRAFFIC_SECRET_0,
        tx_secret,
        secretlen);
    break;
  default:
    UNREACHABLE();
  }

  return true;
}

bool DeriveAndInstallInitialKey(
    QuicSession* session,
    const ngtcp2_cid* dcid) {
  InitialSecret initial_secret;
  InitialSecret rx_secret;
  InitialSecret tx_secret;
  InitialKey rx_key;
  InitialIV rx_iv;
  InitialKey rx_hp;
  InitialKey tx_key;
  InitialIV tx_iv;
  InitialKey tx_hp;
  return NGTCP2_OK(ngtcp2_crypto_derive_and_install_initial_key(
      session->Connection(),
      rx_secret.data(),
      tx_secret.data(),
      initial_secret.data(),
      rx_key.data(),
      rx_iv.data(),
      rx_hp.data(),
      tx_key.data(),
      tx_iv.data(),
      tx_hp.data(),
      dcid,
      session->CryptoContext()->Side()));
}

bool UpdateAndInstallKey(
    QuicSession* session,
    std::vector<uint8_t>* current_rx_secret,
    std::vector<uint8_t>* current_tx_secret) {
  SessionSecret rx_secret;
  SessionSecret tx_secret;
  SessionKey rx_key;
  SessionIV rx_iv;
  SessionKey tx_key;
  SessionIV tx_iv;

  if (NGTCP2_ERR(ngtcp2_crypto_update_and_install_key(
         session->Connection(),
         rx_secret.data(),
         tx_secret.data(),
         rx_key.data(),
         rx_iv.data(),
         tx_key.data(),
         tx_iv.data(),
         current_rx_secret->data(),
         current_tx_secret->data(),
         current_rx_secret->size()))) {
    return false;
  }

  current_rx_secret->assign(
      std::begin(rx_secret),
      std::begin(rx_secret) + current_rx_secret->size());

  current_tx_secret->assign(
      std::begin(tx_secret),
      std::begin(tx_secret) + current_tx_secret->size());

  return true;
}

}  // namespace quic
}  // namespace node
