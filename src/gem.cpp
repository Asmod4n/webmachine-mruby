// The gem's Ruby surface: Webmachine.resource= is how an app hands its
// resource class to the server - the bridge reads it back after loading
// the app file. Nothing here runs on the request path.
#include <mruby.h>
#include <mruby/variable.h>

namespace {

mrb_value wm_resource_set(mrb_state* mrb, mrb_value self) {
  mrb_value klass;
  mrb_get_args(mrb, "C", &klass);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@resource"), klass);
  return klass;
}

mrb_value wm_resource_get(mrb_state* mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@resource"));
}

}  // namespace

extern "C" {

void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module(mrb, "Webmachine");
  mrb_define_module_function(mrb, wm, "resource=", wm_resource_set, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, wm, "resource", wm_resource_get, MRB_ARGS_NONE());
}

void mrb_webmachine_mruby_gem_final(mrb_state*) {}

}  // extern "C"
