// The gem's mruby entry points. Empty on purpose: nothing the HTTP
// state model needs lives in the VM yet.
#include <mruby.h>

extern "C" {
void mrb_webmachine_mruby_gem_init(mrb_state*) {}
void mrb_webmachine_mruby_gem_final(mrb_state*) {}
}
