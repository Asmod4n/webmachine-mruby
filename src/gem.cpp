// The gem's mruby entry points. Empty on purpose: the VM gets a surface
// in step 3 (setup-only), and not one symbol sooner.
#include <mruby.h>

extern "C" {
void mrb_webmachine_mruby_gem_init(mrb_state*) {}
void mrb_webmachine_mruby_gem_final(mrb_state*) {}
}
