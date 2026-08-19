// The resource: Webmachine::Resource is the Ruby base class an app
// subclasses (webmachine-ruby's own shape). Setup asks the subclass
// ONCE for its konst answers and its rendered body; the request path
// never enters the VM for them.
#ifndef WEBMACHINE_RESOURCE_HPP
#define WEBMACHINE_RESOURCE_HPP

#include <mruby.h>

#include <cstddef>

#include "flow_walk.hpp"

namespace webmachine {

// Loads the app file (its class inherits Webmachine::Resource) and
// folds its answers into `out`. False leaves the reason in err - what
// tier 0 cannot honor refuses the start by name, never silently.
bool resource_setup(mrb_state* mrb, const char* path, flow::KonstSet& out, char* err,
                    size_t errlen);

}  // namespace webmachine

#endif
