// The refusals' own classes. Until now every one of them raised
// RuntimeError - the anonymous catch-all - which made a server's
// refusal indistinguishable from any RuntimeError an app raises
// itself, and left `rescue` no way to mean "webmachine said no".
//
// Three classes, because this tree makes exactly three distinctions:
// a configuration that cannot stand, a route that cannot be built,
// and everything else. More classes than distinctions would be
// decoration. What is genuinely Ruby semantics keeps its Ruby class:
// a TypeError for a wrong return type, a KeyError for a missing key -
// a refusal by the server is a different thing from a mistake in a
// value.
//
// Macros rather than helpers, in the shape the neighbouring gems use
// (mruby-toml's E_TOML_ERROR, mruby-libhydrogen's E_HYDRO_ERROR):
// the lookup is a presym pair and happens only where something is
// already going wrong.
#ifndef WEBMACHINE_ERROR_HPP
#define WEBMACHINE_ERROR_HPP

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/presym.h>

#define E_WM_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Error)))
#define E_WM_CONFIG_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(ConfigError)))
#define E_WM_ROUTE_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(RouteError)))

#endif
