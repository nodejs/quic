#include "node_quic_http3_application.h"
#include "node_quic_session-inl.h"
#include "node_quic_stream.h"

namespace node {
namespace quic {

Http3Application::Http3Application(
    QuicSession* session) :
    QuicApplication(session) {}

nghttp3_conn* Http3Application::CreateConnection(
    Http3Application* app,
    nghttp3_conn_settings* settings) {

  typedef int (*new_fn)(
    nghttp3_conn** pconn,
    const nghttp3_conn_callbacks* callbacks,
    const nghttp3_conn_settings* settings,
    const nghttp3_mem* mem,
    void* conn_user_data);

  // TODO(@jasnell): Reconcile with http2 and quic allocator logic
  const nghttp3_mem* mem = nghttp3_mem_default();
  ngtcp2_crypto_side side = app->Session()->CryptoContext()->Side();
  nghttp3_conn* conn;
  new_fn fn;

  switch (side) {
    case NGTCP2_CRYPTO_SIDE_SERVER:
      fn = nghttp3_conn_server_new;
      break;
    case NGTCP2_CRYPTO_SIDE_CLIENT:
      fn = nghttp3_conn_client_new;
  }

  if (fn(&conn, &callbacks_[side], settings, mem, app) != 0)
    return nullptr;

  return conn;
}

bool Http3Application::CreateAndBindControlStream() {
  if (!Session()->OpenUnidirectionalStream(&control_stream_id_))
    return false;
  return nghttp3_conn_bind_control_stream(
      Connection(),
      control_stream_id_) == 0;
}

bool Http3Application::CreateAndBindQPackStreams() {
  if (!Session()->OpenUnidirectionalStream(&qpack_enc_stream_id_) ||
      !Session()->OpenUnidirectionalStream(&qpack_dec_stream_id_)) {
    return false;
  }

  return nghttp3_conn_bind_qpack_streams(
      Connection(),
      qpack_enc_stream_id_,
      qpack_dec_stream_id_) == 0;
}

bool Http3Application::Initialize() {
  if (!NeedsInit())
    return false;

  // The QuicSession must allow for at least three local unidirectional streams.
  // This number is fixed by the http3 specification.
  if (Session()->GetMaxLocalStreamsUni() < 3)
    return false;

  // TODO(@jasnell): How we provide application specific settings...
  nghttp3_conn_settings settings;
  nghttp3_conn_settings_default(&settings);

  // TODO(@jasnell): Make configurable
  settings.qpack_max_table_capacity = DEFAULT_QPACK_MAX_TABLE_CAPACITY;
  settings.qpack_blocked_streams = DEFAULT_QPACK_BLOCKED_STREAMS;

  connection_.reset(CreateConnection(this, &settings));
  CHECK(connection_);

  ngtcp2_transport_params params;
  Session()->GetLocalTransportParams(&params);

  nghttp3_conn_set_max_client_streams_bidi(
      Connection(),
      params.initial_max_streams_bidi);

  if (!CreateAndBindControlStream() ||
      !CreateAndBindQPackStreams()) {
    return false;
  }

  SetInitDone();
  return true;
}

void Http3Application::H3AckedStreamData(
    int64_t stream_id,
    size_t datalen) {
  QuicStream* stream = Session()->FindStream(stream_id);
  if (stream) {
    stream->AckedDataOffset(0, datalen);
    nghttp3_conn_resume_stream(Connection(), stream_id);
  }
}

int Http3Application::H3StreamClose(
    int64_t stream_id,
    uint64_t app_error_code) {
  return 0;
}

int Http3Application::H3ReceiveData(
    int64_t stream_id,
    const uint8_t* data,
    size_t datalen) {
  return 0;
}

int Http3Application::H3DeferredConsume(
    int64_t stream_id,
    size_t consumed) {
  return 0;
}

int Http3Application::H3BeginHeaders(
    int64_t stream_id) {
  return 0;
}

int Http3Application::H3ReceiveHeader(
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags) {
  return 0;
}

int Http3Application::H3EndHeaders(
    int64_t stream_id) {
  return 0;
}

int Http3Application::H3BeginPushPromise(
    int64_t stream_id,
    int64_t push_id) {
  return 0;
}

int Http3Application::H3ReceivePushPromise(
    int64_t stream_id,
    int64_t push_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags) {
  return 0;
}

int Http3Application::H3EndPushPromise(
    int64_t stream_id,
    int64_t push_id) {
  return 0;
}

int Http3Application::H3CancelPush(
    int64_t push_id,
    int64_t stream_id) {
  return 0;
}

int Http3Application::H3SendStopSending(
    int64_t stream_id,
    uint64_t app_error_code) {
  return 0;
}

int Http3Application::H3PushStream(
    int64_t push_id,
    int64_t stream_id) {
  return 0;
}

int Http3Application::H3EndStream(
    int64_t stream_id) {
  return 0;
}

const nghttp3_conn_callbacks Http3Application::callbacks_[2] = {
  // NGTCP2_CRYPTO_SIDE_CLIENT
  {
    OnAckedStreamData,
    OnStreamClose,
    OnReceiveData,
    OnDeferredConsume,
    OnBeginHeaders,
    OnReceiveHeader,
    OnEndHeaders,
    OnBeginHeaders,  // Begin Trailers
    OnReceiveHeader, // Receive Trailer
    OnEndHeaders,    // End Trailers
    OnBeginPushPromise,
    OnReceivePushPromise,
    OnEndPushPromise,
    OnCancelPush,
    OnSendStopSending,
    OnPushStream,
    OnEndStream
  },
  // NGTCP2_CRYPTO_SIDE_SERVER
  {
    OnAckedStreamData,
    OnStreamClose,
    OnReceiveData,
    OnDeferredConsume,
    OnBeginHeaders,
    OnReceiveHeader,
    OnEndHeaders,
    OnBeginHeaders,  // Begin Trailers
    OnReceiveHeader, // Receive Trailer
    OnEndHeaders,    // End Trailers
    OnBeginPushPromise,
    OnReceivePushPromise,
    OnEndPushPromise,
    OnCancelPush,
    OnSendStopSending,
    OnPushStream,
    OnEndStream
  }
};

int Http3Application::OnAckedStreamData(
    nghttp3_conn* conn,
    int64_t stream_id,
    size_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  app->H3AckedStreamData(stream_id, datalen);
  return 0;
}

int Http3Application::OnStreamClose(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3StreamClose(stream_id, app_error_code);
}

int Http3Application::OnReceiveData(
    nghttp3_conn* conn,
    int64_t stream_id,
    const uint8_t* data,
    size_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3ReceiveData(stream_id, data, datalen);
}

int Http3Application::OnDeferredConsume(
    nghttp3_conn* conn,
    int64_t stream_id,
    size_t consumed,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3DeferredConsume(stream_id, consumed);
}

int Http3Application::OnBeginHeaders(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3BeginHeaders(stream_id);
}

int Http3Application::OnReceiveHeader(
    nghttp3_conn* conn,
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3ReceiveHeader(stream_id, token, name, value, flags);
}

int Http3Application::OnEndHeaders(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3EndHeaders(stream_id);
}

int Http3Application::OnBeginPushPromise(
    nghttp3_conn* conn,
    int64_t stream_id,
    int64_t push_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3BeginPushPromise(stream_id, push_id);
}

int Http3Application::OnReceivePushPromise(
    nghttp3_conn* conn,
    int64_t stream_id,
    int64_t push_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3ReceivePushPromise(
      stream_id,
      push_id,
      token,
      name,
      value,
      flags);
}

int Http3Application::OnEndPushPromise(
    nghttp3_conn* conn,
    int64_t stream_id,
    int64_t push_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3EndPushPromise(stream_id, push_id);
}

int Http3Application::OnCancelPush(
    nghttp3_conn* conn,
    int64_t push_id,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3CancelPush(push_id, stream_id);
}

int Http3Application::OnSendStopSending(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3SendStopSending(stream_id, app_error_code);
}

int Http3Application::OnPushStream(
    nghttp3_conn* conn,
    int64_t push_id,
    int64_t stream_id,
    void* conn_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3PushStream(push_id, stream_id);
}

int Http3Application::OnEndStream(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  return app->H3EndStream(stream_id);
}
}  // namespace quic
}  // namespace node
