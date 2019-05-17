#ifndef SRC_NODE_MEM_H_
#define SRC_NODE_MEM_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_internals.h"

namespace node {
namespace mem {

// Both ngtcp2 and nghttp2 allow custom allocators that
// follow exactly the same structure and behavior, but
// use different struct names. To allow for code re-use,
// the Allocator template class can be used for both.

struct Tracker {
  virtual void CheckAllocatedSize(size_t previous_size) = 0;
  virtual void IncrementAllocatedSize(size_t size) = 0;
  virtual void DecrementAllocatedSize(size_t size) = 0;
};

inline static void* MemRealloc(
    void* ptr,
    size_t size,
    void* user_data) {

  Tracker* tracker = static_cast<Tracker*>(user_data);

  size_t previous_size = 0;
  char* original_ptr = nullptr;

  if (size > 0) size += sizeof(size_t);

  if (ptr != nullptr) {
    original_ptr = static_cast<char*>(ptr) - sizeof(size_t);
    previous_size = *reinterpret_cast<size_t*>(original_ptr);
    if (previous_size == 0) {
      char* ret = UncheckedRealloc(original_ptr, size);
      if (ret != nullptr)
        ret += sizeof(size_t);
      return ret;
    }
  }

  tracker->CheckAllocatedSize(previous_size);

  char* mem = UncheckedRealloc(original_ptr, size);

  if (mem != nullptr) {
    tracker->IncrementAllocatedSize(size - previous_size);
    *reinterpret_cast<size_t*>(mem) = size;
    mem += sizeof(size_t);
  } else if (size == 0) {
    tracker->DecrementAllocatedSize(previous_size);
  }
  return mem;
}

inline static void* MemMalloc(
    size_t size,
    void* user_data) {
  return MemRealloc(nullptr, size, user_data);
}

inline static void MemFree(
    void* ptr,
    void* user_data) {
  if (ptr == nullptr) return;
  CHECK_NULL(MemRealloc(ptr, 0, user_data));
}

inline static void* MemCalloc(
    size_t nmemb,
    size_t size,
    void* user_data) {
  size_t real_size = MultiplyWithOverflowCheck(nmemb, size);
  void* mem = MemMalloc(real_size, user_data);
  if (mem != nullptr)
    memset(mem, 0, real_size);
  return mem;
}

inline static void MemStopTracking(Tracker* tracker, void* ptr) {
  size_t* original_ptr = reinterpret_cast<size_t*>(
      static_cast<char*>(ptr) - sizeof(size_t));
  tracker->DecrementAllocatedSize(*original_ptr);
  *original_ptr = 0;
}

template <typename T>
class Allocator {
 public:
  explicit inline Allocator(Tracker* user_data) :
    info_({
      user_data,
      MemMalloc,
      MemFree,
      MemCalloc,
      MemRealloc
    }) {}

  inline T* operator*() { return &info_; }
 private:
  T info_;
};

}  // namespace mem
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_MEM_H_
