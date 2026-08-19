// The mruby bridge: ONE setup-time conversation with the VM. The app
// file's last expression is the resource class; the bridge instantiates
// it once, asks every konst-able callback exactly once, folds the
// method lists (B12/B10), and hands Http1 a finished KonstSet. After
// this returns, the VM is never consulted for these answers again.
//
// What the konst tier cannot honor yet is a NAMED REFUSAL at startup,
// never a silent misbehavior: value-carrying callbacks (generate_etag,
// last_modified, create_path, process_post, content_types_accepted,
// base_uri, options), redirects with a Location, non-true authorization
// results, empty *_provided lists, and methods outside the compiled
// set. Those arrive with tier 1.
#ifndef WEBMACHINE_BRIDGE_HPP
#define WEBMACHINE_BRIDGE_HPP

#include <mruby.h>

#include <cstddef>

#include "flow_walk.hpp"

namespace webmachine {

// False leaves the reason in err. On success `out` is the bound
// resource, ready for Http1's constructor.
bool bind_resource(mrb_state* mrb, const char* path, flow::KonstSet& out, char* err,
                   size_t errlen);

}  // namespace webmachine

#endif
