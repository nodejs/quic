#ifndef SRC_HISTOGRAM_INL_H_
#define SRC_HISTOGRAM_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "histogram.h"
#include "base_object-inl.h"
#include "node_internals.h"

namespace node {

inline Histogram::Histogram(int64_t lowest, int64_t highest, int figures) {
  CHECK_EQ(0, hdr_init(lowest, highest, figures, &histogram_));
}

inline Histogram::~Histogram() {
  hdr_close(histogram_);
}

inline void Histogram::Reset() {
  hdr_reset(histogram_);
}

inline bool Histogram::Record(int64_t value) {
  return hdr_record_value(histogram_, value);
}

inline int64_t Histogram::Min() {
  return hdr_min(histogram_);
}

inline int64_t Histogram::Max() {
  return hdr_max(histogram_);
}

inline double Histogram::Mean() {
  return hdr_mean(histogram_);
}

inline double Histogram::Stddev() {
  return hdr_stddev(histogram_);
}

inline double Histogram::Percentile(double percentile) {
  CHECK_GT(percentile, 0);
  CHECK_LE(percentile, 100);
  return static_cast<double>(hdr_value_at_percentile(histogram_, percentile));
}

inline void Histogram::Percentiles(std::function<void(double, double)> fn) {
  hdr_iter iter;
  hdr_iter_percentile_init(&iter, histogram_, 1);
  while (hdr_iter_next(&iter)) {
    double key = iter.specifics.percentiles.percentile;
    double value = static_cast<double>(iter.value);
    fn(key, value);
  }
}

inline HistogramBase::HistogramBase(
    Environment* env,
    v8::Local<v8::Object> wrap,
    int64_t lowest,
    int64_t highest,
    int figures) :
    BaseObject(env, wrap),
    Histogram(lowest, highest, figures) {}

inline bool HistogramBase::RecordDelta() {
  uint64_t time = uv_hrtime();
  bool ret = true;
  if (prev_ > 0) {
    int64_t delta = time - prev_;
    if (delta > 0) {
      ret = Record(delta);
      TraceDelta(delta);
      if (!ret) {
        if (exceeds_ < 0xFFFFFFFF)
          exceeds_++;
        TraceExceeds(delta);
      }
    }
  }
  prev_ = time;
  return ret;
}

inline void HistogramBase::ResetState() {
  Reset();
  exceeds_ = 0;
  prev_ = 0;
}

inline void HistogramBase::HistogramMin(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  double value = static_cast<double>(histogram->Min());
  args.GetReturnValue().Set(value);
}

inline void HistogramBase::HistogramMax(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  double value = static_cast<double>(histogram->Max());
  args.GetReturnValue().Set(value);
}

inline void HistogramBase::HistogramMean(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  args.GetReturnValue().Set(histogram->Mean());
}

inline void HistogramBase::HistogramExceeds(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  double value = static_cast<double>(histogram->Exceeds());
  args.GetReturnValue().Set(value);
}

inline void HistogramBase::HistogramStddev(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  args.GetReturnValue().Set(histogram->Stddev());
}

inline void HistogramBase::HistogramPercentile(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  CHECK(args[0]->IsNumber());
  double percentile = args[0].As<v8::Number>()->Value();
  args.GetReturnValue().Set(histogram->Percentile(percentile));
}

inline void HistogramBase::HistogramPercentiles(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  CHECK(args[0]->IsMap());
  v8::Local<v8::Map> map = args[0].As<v8::Map>();
  histogram->Percentiles([&](double key, double value) {
    map->Set(
        env->context(),
        v8::Number::New(env->isolate(), key),
        v8::Number::New(env->isolate(), value)).IsEmpty();
  });
}

inline void HistogramBase::HistogramReset(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  HistogramBase* histogram;
  ASSIGN_OR_RETURN_UNWRAP(&histogram, args.Holder());
  histogram->ResetState();
}

inline void HistogramBase::Initialize(Environment* env) {
  // Guard against multiple initializations
  if (!env->histogram_ctor_template().IsEmpty())
    return;

  v8::Local<v8::String> classname =
      FIXED_ONE_BYTE_STRING(env->isolate(), "Histogram");

  v8::Local<v8::FunctionTemplate> histogram =
    v8::FunctionTemplate::New(env->isolate());
  histogram->SetClassName(classname);

  v8::Local<v8::ObjectTemplate> histogramt =
    histogram->InstanceTemplate();

  histogramt->SetInternalFieldCount(1);
  env->SetProtoMethod(histogram, "exceeds", HistogramExceeds);
  env->SetProtoMethod(histogram, "min", HistogramMin);
  env->SetProtoMethod(histogram, "max", HistogramMax);
  env->SetProtoMethod(histogram, "mean", HistogramMean);
  env->SetProtoMethod(histogram, "stddev", HistogramStddev);
  env->SetProtoMethod(histogram, "percentile", HistogramPercentile);
  env->SetProtoMethod(histogram, "percentiles", HistogramPercentiles);
  env->SetProtoMethod(histogram, "reset", HistogramReset);

  env->set_histogram_ctor_template(histogramt);
}

inline HistogramBase* HistogramBase::New(
    Environment* env,
    int64_t lowest,
    int64_t highest,
    int figures) {
  CHECK_LE(lowest, highest);
  CHECK_GT(figures, 0);
  v8::Local<v8::Object> obj;
  auto tmpl = env->histogram_ctor_template();
  if (!tmpl->NewInstance(env->context()).ToLocal(&obj))
    return nullptr;

  return new HistogramBase(env, obj, lowest, highest, figures);
}

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_HISTOGRAM_INL_H_
