// The resource: Webmachine::Resource is the Ruby base class an app
// subclasses. Two kinds of methods, by declaration:
//   class methods  (def self.x) - konst: asked ONCE at setup, folded
//                                 into the compiled vectors
//   instance methods (def x)    - runtime: answered through the VM on
//                                 EVERY request (the budgeted entry,
//                                 95-191ns cached-sym, measured)
#ifndef WEBMACHINE_RESOURCE_HPP
#define WEBMACHINE_RESOURCE_HPP

#include <mruby.h>

#include <cstddef>
#include <cstdint>

#include "flow_walk.hpp"

namespace webmachine {

struct Resource {
  flow::KonstSet konst;
  mrb_state* mrb = nullptr;
  // The one shared instance dynamic callbacks are asked on (resources
  // hold no per-request state; dynamic answers come from the world).
  mrb_value self = {};
  // The class, FROZEN at bind: nobody can redefine a method after
  // routes are added, so everything resolved below stays true forever.
  struct RClass* klass = nullptr;
  uint64_t dynamic = 0;  // nodes answered per request
  mrb_sym node_sym[flow::kNodeCount] = {};  // interned once, never per request
  // Resolved ONCE at bind (aliases unwrapped): a Ruby proc enters
  // directly via mrb_yield_with_class, skipping the funcall machinery;
  // a cfunc or undef falls back to funcall (reproducing vm.c's frame
  // setup is not worth owning).
  mrb_method_t node_m[flow::kNodeCount] = {};
  bool node_fast[flow::kNodeCount] = {};
  bool dynamic_body = false;
  mrb_sym body_sym = {};
  mrb_method_t body_m = {};
  bool body_fast = false;
};

// Loads the app file (its class inherits Webmachine::Resource) and
// folds its answers into `out`. False leaves the reason in err - what
// no tier can honor refuses the start by name, never silently.
bool resource_setup(mrb_state* mrb, const char* path, Resource& out, char* err, size_t errlen);

// Declared here, callable without mruby types via http1.hpp's forward
// declaration: the flow with this resource's dynamic nodes answered
// through the VM (ONE arena cycle for the whole decision). A raising
// callback reads as 500.
uint16_t resource_decide(const Resource& res, const flow::ReqFacts& facts);

// Renders the per-request body and lends out the VM string's bytes:
// *ptr/*len are valid until resource_render_end(arena) - the caller
// copies them ONCE, straight into the sink. False: the handler raised
// (the exception stays pending for resource_exception_begin) - the
// response is a 500 carrying it.
bool resource_render_begin(const Resource& res, const char** ptr, size_t* len, int* arena);
// The pending exception's message, lent the same way: a raising
// callback answers 500 in the negotiated type with the reason as body.
// False: nothing pending.
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len, int* arena);
void resource_render_end(const Resource& res, int arena);

}  // namespace webmachine

#endif
