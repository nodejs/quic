#ifndef SRC_NODE_QUIC_BUFFER_H
#define SRC_NODE_QUIC_BUFFER_H

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "ngtcp2/ngtcp2.h"
#include "node.h"
#include "node_internals.h"
#include "util.h"
#include "uv.h"
#include "v8.h"

#include <algorithm>
#include <functional>
#include <vector>

namespace node {
namespace quic {

// QuicBuffer an internal linked list of uv_buf_t instances
// representing data that is to be sent. All data in the
// Buffer has to be retained until it is Consumed or Canceled.
// For QUIC, the data is not consumed until an explicit ack
// is received or we know that we do not need the data.

typedef std::function<void(int status, void* user_data)> done_cb;

// Default non-op done handler.
inline void default_quic_buffer_chunk_done(int status, void* user_data) {}

#define EMPTY_BUF(buf) (buf.len == 0 || buf.base == nullptr)

// A quic_buffer_chunk contains the actual buffered data
// along with a callback, and optional V8 object that
// should be kept alive as long as the chunk is alive.
struct quic_buffer_chunk : public MemoryRetainer {
  MallocedBuffer<uint8_t> data_buf;
  uv_buf_t buf;
  done_cb done = default_quic_buffer_chunk_done;
  size_t offset = 0;
  void* user_data = nullptr;
  bool done_called = false;
  v8::Global<v8::Object> keep_alive;
  std::unique_ptr<quic_buffer_chunk> next;

  inline quic_buffer_chunk(
    MallocedBuffer<uint8_t>&& buf_,
    done_cb done_,
    void* user_data_,
    v8::Local<v8::Object> keep_alive_) :
    data_buf(std::move(buf_)),
    buf(uv_buf_init(
        reinterpret_cast<char*>(data_buf.data),
        data_buf.size)),
    done(done_),
    user_data(user_data_) {
    if (!keep_alive.IsEmpty())
      keep_alive.Reset(keep_alive_->GetIsolate(), keep_alive_);
  }

  inline explicit quic_buffer_chunk(
    uv_buf_t buf_) :
    buf(buf_) {}

  inline quic_buffer_chunk(
    uv_buf_t buf_,
    done_cb done_,
    void* user_data_,
    v8::Local<v8::Object> keep_alive_) :
    buf(buf_),
    done(done_),
    user_data(user_data_) {
    if (!keep_alive.IsEmpty())
      keep_alive.Reset(keep_alive_->GetIsolate(), keep_alive_);
  }

  inline ~quic_buffer_chunk() override {
    CHECK(done_called);
  }

  void Done(int status) {
    done_called = true;
    done(status, user_data);
  }

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackFieldWithSize("buf", buf.len);
  }

  SET_MEMORY_INFO_NAME(quic_buffer_chunk)
  SET_SELF_SIZE(quic_buffer_chunk)
};

// A QuicBuffer is a linked-list of quic_buffer_chunk instances.
// There are three significant pointers: root_, head_, and tail_.
//   * root_ is the base of the linked list
//   * head_ is a pointer to the current read position of the linked list
//   * tail_ is a pointer to the current write position of the linked list
// Items are dropped from the linked list only when either Consume() or
// Cancel() is called. Consume() will consume a given number of bytes up
// to, but not including the read head_. Cancel() will consume all remaining
// bytes in the linked list. As whole quic_buffer_chunk instances are
// consumed, the corresponding Done callback will be invoked, allowing
// any memory to be freed up.
//
// Use SeekHead(n) to advance the read head_ forward n positions.
//
// DrainInto() will drain the remaining quic_buffer_chunk instances
// into a vector and will advance the read head_ to the end of the
// QuicBuffer. The function will return the number of positions drained
// which would then be passed to SeekHead(n) to advance the read head.
//
// QuicBuffer supports move assignment that will completely reset the source.
// That is,
//  QuicBuffer buf1;
//  QuicBuffer buf2;
//  buf2 = std::move(buf1);
//
// Will reset the state of buf2 to that of buf1, then reset buf1
//
// There is also an overloaded += operator that will append the source
// content to the destination and reset the source.
// That is,
//  QuicBuffer buf1;
//  QuicBuffer buf2;
//  buf2 += std::move(buf1);
//
// Will append the contents of buf1 to buf2, then reset buf1
class QuicBuffer : public MemoryRetainer {
 public:
  enum drain_from {
    DRAIN_FROM_ROOT,
    DRAIN_FROM_HEAD
  };

  inline QuicBuffer() :
    head_(nullptr),
    tail_(nullptr),
    size_(0),
    count_(0),
    length_(0) {}

  inline QuicBuffer(QuicBuffer&& src) noexcept :
    head_(src.head_),
    tail_(src.tail_),
    size_(src.size_),
    count_(src.count_),
    length_(src.length_) {
    root_ = std::move(src.root_);
    src.head_ = nullptr;
    src.tail_ = nullptr;
    src.size_ = 0;
    src.length_ = 0;
  }

  QuicBuffer& operator=(QuicBuffer&& src) noexcept {
    this->~QuicBuffer();
    return *new(this) QuicBuffer(std::move(src));
  }

  QuicBuffer& operator+=(QuicBuffer&& src) noexcept {
    if (!tail_) {
      // If this thing is empty, just do a move...
      this->~QuicBuffer();
      return *new(this) QuicBuffer(std::move(src));
    } else {
      tail_->next = std::move(src.root_);
      // If head_ is null, then it had been read to the
      // end, set the new head_ equal to the appended
      // root.
      if (head_ == nullptr)
        head_ = tail_->next.get();
      tail_ = src.tail_;
      length_ += src.length_;
      size_ += src.size_;
      count_ += src.size_;
      src.head_ = nullptr;
      src.tail_ = nullptr;
      src.size_ = 0;
      src.length_ = 0;
      return *this;
    }
  }

  inline ~QuicBuffer() override {
    Cancel();  // Cancel the remaining data
    CHECK_EQ(length_, 0);
  }

  // Push one or more uv_buf_t instances into the buffer.
  // the done_cb callback will be invoked when the last
  // uv_buf_t in the bufs array is consumed and popped out
  // of the internal linked list. The user_data is passed in to
  // the done_cb. The keep_alive allows a reference to a
  // JS object to be kept around until the final uv_buf_t
  // is consumed.
  inline uint64_t Push(
      uv_buf_t* bufs,
      size_t nbufs,
      done_cb done = default_quic_buffer_chunk_done,
      void* user_data = nullptr,
      v8::Local<v8::Object> keep_alive = v8::Local<v8::Object>()) {
    uint64_t len = 0;
    if (nbufs == 0 ||
        bufs == nullptr ||
        EMPTY_BUF(bufs[0])) {
      done(0, user_data);
      return 0;
    }
    size_t n = 0;
    while (nbufs > 1) {
      if (!EMPTY_BUF(bufs[n])) {
        Push(bufs[n]);
        length_ += bufs[n].len;
        len += bufs[n].len;
      }
      n++;
      nbufs--;
    }
    length_ += bufs[n].len;
    len += bufs[n].len;
    Push(bufs[n], done, user_data, keep_alive);
    return len;
  }

  // Push a single malloc buf into the buffer.
  // The done_cb will be invoked when the buf is consumed
  // and popped out of the internal linked list. The user_data
  // is passed into the done_cb. The keep_alive allows a
  // reference to a JS object to be kept around until the
  // final uv_buf_t is consumed.
  inline uint64_t Push(
      MallocedBuffer<uint8_t>&& buffer,
      done_cb done = default_quic_buffer_chunk_done,
      void* user_data = nullptr,
      v8::Local<v8::Object> keep_alive = v8::Local<v8::Object>()) {
    if (buffer.size == 0) {
      done(0, user_data);
      return 0;
    }
    length_ += buffer.size;
    Push(new quic_buffer_chunk(std::move(buffer), done, user_data, keep_alive));
    return buffer.size;
  }

  // Consume the given number of bytes within the buffer. If amount is
  // negative, all buffered bytes that are available to be consumed are
  // consumed.
  inline void Consume(ssize_t amount = -1) { Consume(0, amount); }

  // Cancels the remaining bytes within the buffer
  inline void Cancel(int status = UV_ECANCELED) { Consume(status, -1); }

  // The total buffered bytes
  inline uint64_t Length() {
    return length_;
  }

  // The total number of buffers
  inline size_t Size() {
    return size_;
  }

  // The number of buffers remaining to be read
  inline size_t ReadRemaining() {
    return count_;
  }

  // Drain the remaining buffers into the given vector. There are
  // two possible starting positions: root_ or head_.
  // DRAIN_FROM_ROOT is used as part of the retransmission
  // mechanism. DRAIN_FROM_HEAD, the default, is used when
  // transmitting packets for the first time.
  //
  // The function will return the number of positions the
  // read head_ can be advanced.
  inline size_t DrainInto(
      std::vector<uv_buf_t>* list,
      drain_from from = DRAIN_FROM_HEAD,
      uint64_t* length = nullptr) {
    size_t len = 0;
    bool seen_head = false;
    quic_buffer_chunk* pos = (from == DRAIN_FROM_ROOT ? root_.get() : head_);
    if (pos == nullptr)
      return 0;
    if (length != nullptr) *length = 0;
    while (pos != nullptr) {
      size_t datalen = pos->buf.len - pos->offset;
      if (length != nullptr) *length += datalen;
      list->push_back(
          uv_buf_init(pos->buf.base + pos->offset, datalen));
      if (pos == head_) seen_head = true;
      if (seen_head) len++;
      pos = pos->next.get();
    }
    return len;
  }

  inline size_t DrainInto(
      std::vector<ngtcp2_vec>* list,
      drain_from from = DRAIN_FROM_HEAD,
      uint64_t* length = nullptr) {
    size_t len = 0;
    bool seen_head = false;
    quic_buffer_chunk* pos = (from == DRAIN_FROM_ROOT ? root_.get() : head_);
    if (pos == nullptr)
      return 0;
    if (length != nullptr) *length = 0;
    while (pos != nullptr) {
      size_t datalen = pos->buf.len - pos->offset;
      if (length != nullptr) *length += datalen;
      list->push_back(ngtcp2_vec{
          reinterpret_cast<uint8_t*>(pos->buf.base) + pos->offset,
          datalen});
      if (pos == head_) seen_head = true;
      if (seen_head) len++;
      pos = pos->next.get();
    }
    return len;
  }

  // Returns the current read head or an empty buffer if
  // we're empty
  inline uv_buf_t Head() {
    if (!head_)
      return uv_buf_init(nullptr, 0);
    return uv_buf_init(
        head_->buf.base + head_->offset,
        head_->buf.len - head_->offset);
  }

  // Moves the current read head forward the given
  // number of buffers. If amount is greater than
  // the number of buffers remaining, move to the
  // end, and return the actual number advanced.
  inline size_t SeekHead(size_t amount = 1) {
    size_t n = 0;
    size_t amt = amount;
    while (head_ && amt > 0) {
      head_ = head_->next.get();
      n++;
      amt--;
      count_--;
    }
    return n;
  }

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackFieldWithSize("length", length_);
  }
  SET_MEMORY_INFO_NAME(QuicBuffer);
  SET_SELF_SIZE(QuicBuffer);

 private:
  inline void Push(quic_buffer_chunk* chunk) {
    size_++;
    count_++;
    if (!tail_) {
      root_.reset(chunk);
      head_ = tail_ = root_.get();
    } else {
      tail_->next.reset(chunk);
      tail_ = tail_->next.get();
      if (!head_)
        head_ = tail_;
    }
  }

  inline void Push(uv_buf_t buf) {
    Push(new quic_buffer_chunk(buf));
  }

  inline void Push(
      uv_buf_t buf,
      done_cb done,
      void* user_data,
      v8::Local<v8::Object> keep_alive) {
    Push(new quic_buffer_chunk(buf, done, user_data, keep_alive));
  }

  inline bool Pop(int status = 0) {
    if (!root_)
      return false;
    std::unique_ptr<quic_buffer_chunk> root(std::move(root_));
    root_ = std::move(root.get()->next);
    size_--;

    if (head_ == root.get())
      head_ = root_.get();
    if (tail_ == root.get())
      tail_ = root_.get();

    root->Done(status);
    return true;
  }

  inline void Consume(int status, ssize_t amount) {
    uint64_t amt = std::min(amount < 0 ? length_ : amount, length_);
    while (root_ && amt > 0) {
      auto root = root_.get();
      // Never allow for partial consumption of head when using a
      // non-cancel status
      if (status == 0 && head_ == root)
        break;
      size_t len = root->buf.len - root->offset;
      if (len > amt) {
        length_ -= amt;
        root->offset += amt;
        break;
      }
      length_ -= len;
      amt -= len;
      Pop(status);
    }
  }

  std::unique_ptr<quic_buffer_chunk> root_;
  quic_buffer_chunk* head_;  // Current Read Position
  quic_buffer_chunk* tail_;  // Current Write Position
  size_t size_;
  size_t count_;
  uint64_t length_;
};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_BUFFER_H
