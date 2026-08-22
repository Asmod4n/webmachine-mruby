// The resource: Webmachine::Resource is the Ruby base class an app
// subclasses. Two kinds of methods, by declaration:
//   class methods  (def self.x) - konst: asked ONCE at setup, folded
//                                 into the compiled vectors
//   instance methods (def x)    - runtime: answered through the VM on
//                                 EVERY request, inside ONE frame
//
// The runtime tier runs the WHOLE flow inside one VM method (a hidden
// class carries it): within that frame mrb->jmp is armed and the arena
// lives until exit, so callbacks are naked yields, values one callback
// returns stay alive for the next one IN THE ARENA (cheaper than any
// ivar), and the rendered body is copied out while the frame roots it.
// This frame IS the memory model - a per-node-entry variant measured
// 26ns faster on one callback (forgecore 230 vs 256ns) and was removed
// anyway: it cannot host cross-callback lifetimes without ivars.
#ifndef WEBMACHINE_RESOURCE_HPP
#define WEBMACHINE_RESOURCE_HPP

#include <mruby.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "flow_walk.hpp"

namespace webmachine {

struct Resource {
  flow::KonstSet konst;
  mrb_state* mrb = nullptr;
  // The one shared instance dynamic callbacks are asked on (resources
  // hold no per-request state; dynamic answers come from the world).
  mrb_value self = {};
  // The class, FROZEN at add_route: nobody can redefine a method after
  // routes are added, so everything resolved below stays true forever.
  struct RClass* klass = nullptr;
  uint64_t dynamic = 0;  // nodes answered per request
  mrb_sym node_sym[flow::kNodeCount] = {};  // presym constants, never interned
  // Resolved ONCE at add_route (aliases unwrapped): a Ruby proc enters
  // directly via mrb_yield_with_class, skipping the funcall machinery;
  // a cfunc or undef falls back to funcall (reproducing vm.c's frame
  // setup is not worth owning).
  mrb_method_t node_m[flow::kNodeCount] = {};
  bool node_fast[flow::kNodeCount] = {};
  bool dynamic_body = false;
  mrb_sym body_sym = {};
  mrb_method_t body_m = {};
  bool body_fast = false;
  // The run method's carrier object (hidden class - no constant, Ruby
  // code cannot reach or reopen it). Its cfunc finds this Resource
  // through the proc's env (a cptr), never through mrb->ud.
  mrb_value run_self = {};
  // The run frame's in/out slots, valid for one resource_run call.
  mutable const flow::ReqFacts* run_facts = nullptr;
  mutable std::string* run_body = nullptr;
  mutable bool run_have_body = false;
  mutable uint16_t run_status = 0;
};

// Loads the app file (its class inherits Webmachine::Resource) and
// folds its answers into `out`. False leaves the reason in err - what
// no tier can honor refuses the start by name, never silently.
// NOTE: `out` must live at its final address (the run env borrows it).
bool resource_setup(mrb_state* mrb, const char* path, Resource& out, char* err, size_t errlen);

// THE runtime path: decision + render inside one VM call. The rendered
// body (if any) is copied into *body while the frame still roots it.
// A raising callback leaves its exception pending and returns 500.
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, std::string* body,
                      bool* have_body);

// The pending exception's message, read straight from RException's
// mesg field and LENT: copy the bytes before the next mruby call - no
// allocation happens in between, so nothing can collect them.
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

}  // namespace webmachine

#endif
