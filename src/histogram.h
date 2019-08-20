#ifndef SRC_HISTOGRAM_H_
#define SRC_HISTOGRAM_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "base_object.h"
#include "hdr_histogram.h"
#include <functional>
#include <map>

namespace node {

class Histogram {
 public:
  inline Histogram(int64_t lowest, int64_t highest, int figures = 3);
  inline virtual ~Histogram();

  inline bool Record(int64_t value);
  inline void Reset();
  inline int64_t Min();
  inline int64_t Max();
  inline double Mean();
  inline double Stddev();
  inline double Percentile(double percentile);
  inline void Percentiles(std::function<void(double, double)> fn);

  size_t GetMemorySize() const {
    return hdr_get_memory_size(histogram_);
  }

 private:
  hdr_histogram* histogram_;
};

class HistogramBase : public BaseObject, public Histogram {
 public:
  inline HistogramBase(
      Environment* env,
      v8::Local<v8::Object> wrap,
      int64_t lowest,
      int64_t highest,
      int figures = 3);

  inline virtual ~HistogramBase() {}

  inline virtual void TraceDelta(int64_t delta) {}

  inline virtual void TraceExceeds(int64_t delta) {}

  inline bool RecordDelta();

  inline void ResetState();

  inline int64_t Exceeds() { return exceeds_; }

  inline void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackFieldWithSize("histogram", GetMemorySize());
  }

  SET_MEMORY_INFO_NAME(HistogramBase)
  SET_SELF_SIZE(HistogramBase)

  static inline void HistogramMin(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramMax(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramMean(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramExceeds(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramStddev(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramPercentile(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramPercentiles(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void HistogramReset(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static inline void Initialize(Environment* env);

  static inline HistogramBase* New(
      Environment* env,
      int64_t lowest,
      int64_t highest,
      int figures = 3);

 private:
  int64_t exceeds_ = 0;
  uint64_t prev_ = 0;
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_HISTOGRAM_H_
