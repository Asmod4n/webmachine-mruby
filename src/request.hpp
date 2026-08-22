// The request object (#116 slice 4): what a RUNTIME callback sees of
// the request that is being answered.
//
// LAZY, not eager - the whole point. There is ONE request object in the
// process, a hidden Data handle rooted at init; per request the C side
// swaps the VIEW it points at, which is a pointer store. Every accessor
// materialises its Ruby value when it is CALLED and never before, so a
// resource that asks nothing allocates nothing, and a konst resource
// (which never enters the VM at all) does not even pay the pointer
// store.
//
// Nothing here memoises across calls: the callback's own frame roots
// what it received, and a second call materialises again. That is the
// same lifetime rule the rendered body already lives under, and it is
// why the object needs no ivars, no pinning and no reset.
#ifndef WEBMACHINE_REQUEST_HPP
#define WEBMACHINE_REQUEST_HPP

#include <mruby.h>

#include <cstddef>
#include <cstdint>

#include "flow_walk.hpp"
#include "router.hpp"

namespace webmachine {

// What one request lends the VM. Pointers into bytes that live at
// least as long as the run frame - the receive buffer for h1, the
// stream's own copy for a parked h2 request (h2.hpp says why: the
// decode buffer is gone by then).
struct ReqView {
  const char* target = nullptr;  // the request-target as it arrived
  size_t target_len = 0;
  size_t path_len = 0;  // target up to '?' - RFC 9110 4.2.1
  flow::Method method = flow::Method::kGet;
  // The method's own bytes, for the one case the enum cannot spell
  // (kOther). Null where they are not lent; the accessor refuses by
  // name rather than inventing a verb.
  const char* method_p = nullptr;
  size_t method_n = 0;
  // Which route answered and what it captured. `table` is the app's,
  // needed for the binding NAMES - the spans hold only the bytes.
  const RouteTable* table = nullptr;
  int route = -1;
  RouteSpans spans {};
  // The head's fields, LENT where they still exist: h1 hands over the
  // phr_header array off its own frame (two stores, and only in the
  // branch that was going to run a resource anyway). Null is the
  // honest state for a parked h2 request, whose decode buffer is gone
  // by the time it answers - request.headers refuses BY NAME there
  // rather than lending a dead pointer. `void*` because this header
  // stays free of picohttpparser; request.cpp is where the shape is
  // known.
  const void* hdrs = nullptr;
  size_t nhdr = 0;
};

// Webmachine::Request, and Webmachine::Resource#request. Defined once
// at gem init.
void request_init(mrb_state* mrb, struct RClass* wm);

// The run frame's in-slot: resource_run points the one object at this
// request before the frame, and at nothing after it.
void request_bind(const ReqView* view);

}  // namespace webmachine

#endif
