#ifndef SRC_NODE_QUIC_HTTP3_APPLICATION_H_
#define SRC_NODE_QUIC_HTTP3_APPLICATION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_quic_session.h"
#include "node_quic_util.h"
#include "v8.h"
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

namespace node {

namespace quic {

constexpr uint64_t DEFAULT_QPACK_MAX_TABLE_CAPACITY = 4096;
constexpr uint64_t DEFAULT_QPACK_BLOCKED_STREAMS = 100;

using Http3ConnectionPointer = DeleteFnPtr<nghttp3_conn, nghttp3_conn_del>;

class Http3Application : public QuicApplication {
 public:
  explicit Http3Application(QuicSession* session);

  bool Initialize() override;

 private:
  nghttp3_conn* Connection() { return connection_.get(); }

  bool CreateAndBindControlStream();
  bool CreateAndBindQPackStreams();

  void H3AckedStreamData(int64_t stream_id, size_t datalen);
  int H3StreamClose(int64_t stream_id, uint64_t app_error_code);
  int H3ReceiveData(int64_t stream_id, const uint8_t* data, size_t datalen);
  int H3DeferredConsume(int64_t stream_id, size_t consumed);
  int H3BeginHeaders(int64_t stream_id);
  int H3ReceiveHeader(
      int64_t stream_id,
      int32_t token,
      nghttp3_rcbuf* name,
      nghttp3_rcbuf* value,
      uint8_t flags);
  int H3EndHeaders(int64_t stream_id);
  int H3BeginPushPromise(int64_t stream_id, int64_t push_id);
  int H3ReceivePushPromise(
      int64_t stream_id,
      int64_t push_id,
      int32_t token,
      nghttp3_rcbuf* name,
      nghttp3_rcbuf* value,
      uint8_t flags);
  int H3EndPushPromise(int64_t stream_id, int64_t push_id);
  int H3CancelPush(int64_t push_id, int64_t stream_id);
  int H3SendStopSending(int64_t stream_id, uint64_t app_error_code);
  int H3PushStream(int64_t push_id, int64_t stream_id);
  int H3EndStream(int64_t stream_id);

  Http3ConnectionPointer connection_;
  int64_t control_stream_id_;
  int64_t qpack_enc_stream_id_;
  int64_t qpack_dec_stream_id_;

  static nghttp3_conn* CreateConnection(
      Http3Application* application,
      nghttp3_conn_settings* settings);

  static const nghttp3_conn_callbacks callbacks_[2];

  static int OnAckedStreamData(
      nghttp3_conn* conn,
      int64_t stream_id,
      size_t datalen,
      void* conn_user_data,
      void* stream_user_data);

  static int OnStreamClose(
      nghttp3_conn* conn,
      int64_t stream_id,
      uint64_t app_error_code,
      void* conn_user_data,
      void* stream_user_data);

  static int OnReceiveData(
      nghttp3_conn* conn,
      int64_t stream_id,
      const uint8_t* data,
      size_t datalen,
      void* conn_user_data,
      void* stream_user_data);

  static int OnDeferredConsume(
      nghttp3_conn* conn,
      int64_t stream_id,
      size_t consumed,
      void* conn_user_data,
      void* stream_user_data);

  static int OnBeginHeaders(
      nghttp3_conn* conn,
      int64_t stream_id,
      void* conn_user_data,
      void* stream_user_data);

  static int OnReceiveHeader(
      nghttp3_conn* conn,
      int64_t stream_id,
      int32_t token,
      nghttp3_rcbuf* name,
      nghttp3_rcbuf* value,
      uint8_t flags,
      void* conn_user_data,
      void* stream_user_data);

  static int OnEndHeaders(
      nghttp3_conn* conn,
      int64_t stream_id,
      void* conn_user_data,
      void* stream_user_data);

  static int OnBeginPushPromise(
      nghttp3_conn* conn,
      int64_t stream_id,
      int64_t push_id,
      void* conn_user_data,
      void* stream_user_data);

  static int OnReceivePushPromise(
      nghttp3_conn* conn,
      int64_t stream_id,
      int64_t push_id,
      int32_t token,
      nghttp3_rcbuf* name,
      nghttp3_rcbuf* value,
      uint8_t flags,
      void* conn_user_data,
      void* stream_user_data);

  static int OnEndPushPromise(
      nghttp3_conn* conn,
      int64_t stream_id,
      int64_t push_id,
      void* conn_user_data,
      void* stream_user_data);

  static int OnCancelPush(
      nghttp3_conn* conn,
      int64_t push_id,
      int64_t stream_id,
      void* conn_user_data,
      void* stream_user_data);

  static int OnSendStopSending(
      nghttp3_conn* conn,
      int64_t stream_id,
      uint64_t app_error_code,
      void* conn_user_data,
      void* stream_user_data);

  static int OnPushStream(
      nghttp3_conn* conn,
      int64_t push_id,
      int64_t stream_id,
      void* conn_user_data);

  static int OnEndStream(
      nghttp3_conn* conn,
      int64_t stream_id,
      void* conn_user_data,
      void* stream_user_data);
};

}  // namespace quic

}  // namespace node

#endif  // NODE_WANT_INTERNALS
#endif  // SRC_NODE_QUIC_HTTP3_APPLICATION_H_
