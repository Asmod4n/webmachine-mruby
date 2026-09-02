// The published C++ resource API (#207), as an embedder actually uses
// it: this file IS the example. Four resources answer the same bytes -
// two written in C++ through webmachine::define_native, two written in
// Ruby in examples/cpp_resource.rb - and the routes are declared in
// that same Ruby app, because a route names a CLASS and a C++ class is
// an mruby class like any other.
//
// The three tiers, side by side, are the whole point:
//
//   /cppk, /rbk   a `def self.to_html`. Called ONCE, at fold; its
//                 String is baked into the konst answer. Neither the
//                 VM nor this file is entered again, ever - a C++
//                 static resource and a Ruby one are the same bytes
//                 in the same prebuilt buffer.
//   /cpp          a `def to_html` registered with define_native. Per
//                 request, entered straight from the run engine: no
//                 symbol lookup, no callinfo, no VM.
//   /rb           the same `def to_html` in Ruby. Per request, entered
//                 through mrb_yield_with_class - the irep fast path,
//                 which is what /cpp has to beat.
//
// It is not shipped: the server binary carries no examples, and this
// one is built only where bintest and bench can reach it.
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstring>

#include "../../src/webmachine.hpp"

namespace {
// The body all four resources answer with - one literal, so a byte
// difference on the wire can only come from the dispatch, never from
// the payload. examples/cpp_resource.rb spells the same string.
const char kBody[] = "<html><body>Hello from a C++ resource</body></html>";

// webmachine: a native callback takes its arguments as arguments. It
// never calls mrb_get_args, which is exactly what allows the engine to
// enter it without pushing a callinfo first.
mrb_value body_html(mrb_state* mrb, mrb_value, mrb_int, const mrb_value*) {
  return mrb_str_new_lit(mrb, "<html><body>Hello from a C++ resource</body></html>");
}

// webmachine-ruby allowed_methods: the list this resource answers.
mrb_value allowed_methods(mrb_state* mrb, mrb_value, mrb_int, const mrb_value*) {
  mrb_value a = mrb_ary_new_capa(mrb, 3);
  mrb_ary_push(mrb, a, mrb_str_new_lit(mrb, "GET"));
  mrb_ary_push(mrb, a, mrb_str_new_lit(mrb, "HEAD"));
  mrb_ary_push(mrb, a, mrb_str_new_lit(mrb, "OPTIONS"));
  return a;
}

// webmachine-ruby generate_etag: RFC 9110 8.8.3, spelled by the writer.
mrb_value generate_etag(mrb_state* mrb, mrb_value, mrb_int, const mrb_value*) {
  return mrb_str_new_lit(mrb, "v1");
}

// The two C++ resources. A subclass of Webmachine::Resource is all a
// route needs; define_native is what makes its methods the cheap tier.
void define_resources(mrb_state* mrb) {
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  struct RClass* base = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));

  // Static: the method lives on the class, so the fold runs it once and
  // bakes the String. Registering it natively saves that ONE call - the
  // point here is that the wire answer is identical to Ruby's.
  struct RClass* konst = mrb_define_class_id(mrb, MRB_SYM(CppKonst), base);
  webmachine::define_native(mrb, mrb_singleton_class_ptr(mrb, mrb_obj_value(konst)),
                            {MRB_SYM(to_html), body_html, MRB_ARGS_NONE()});

  // Dynamic: instance methods, run per request.
  struct RClass* run = mrb_define_class_id(mrb, MRB_SYM(CppRun), base);
  webmachine::define_native(mrb, run, {MRB_SYM(to_html), body_html, MRB_ARGS_NONE()});
  webmachine::define_native(mrb, run,
                            {MRB_SYM(allowed_methods), allowed_methods, MRB_ARGS_NONE()});
  webmachine::define_native(mrb, run,
                            {MRB_SYM(generate_etag), generate_etag, MRB_ARGS_NONE()});
}

}

// The CLI is the server's, minus every knob an example does not need.
// What this invocation serves, and what it needs to say so.
struct Invocation {
  webmachine::ServerOptions opts;
  int argc = 0;
  char** argv = nullptr;
};

// run_guarded's shape: what the example serves, once the VM is up. The
// command line is read in here because TypedArgs parses it in Ruby, and
// a malformed flag is a raise like every other start-up refusal (#33).
int serve_body(mrb_state* mrb, void* ud) {
  Invocation& in = *static_cast<Invocation*>(ud);
  webmachine::ServerOptions& opts = in.opts;

  mrb_value av = mrb_ary_new_capa(mrb, in.argc > 1 ? in.argc - 1 : 0);
  for (int i = 1; i < in.argc; i++) {
    mrb_ary_push(mrb, av, mrb_str_new_static_frozen(mrb, in.argv[i], std::strlen(in.argv[i])));
  }
  mrb_obj_freeze(mrb, av);
  mrb_define_const_id(mrb, mrb->object_class, MRB_SYM(ARGV), av);

  const mrb_value h = mrb_funcall_id(mrb, mrb_obj_value(mrb_module_get(mrb, "TypedArgs")),
                                     MRB_SYM(opts), 0);
  mrb_gc_register(mrb, h);

  const mrb_value app = mrb_hash_get(mrb, h, mrb_str_new_lit(mrb, "app"));
  const mrb_value unix_path = mrb_hash_get(mrb, h, mrb_str_new_lit(mrb, "unix"));
  const mrb_value port = mrb_hash_get(mrb, h, mrb_str_new_lit(mrb, "port"));
  if (!mrb_string_p(app)) {
    std::fprintf(stderr,
                 "usage: webmachine-example --app=examples/cpp_resource.mrb\n"
                 "                          (--unix=PATH | --port=N)\n"
                 "\n"
                 "The app file routes CppKonst and CppRun - defined in C++, in\n"
                 "this binary - beside their Ruby twins, so the same bytes can\n"
                 "be asked for over both.\n");
    return 2;
  }
  opts.app_path = mrb_string_cstr(mrb, app);
  opts.cli_unix = mrb_string_p(unix_path) ? mrb_string_cstr(mrb, unix_path) : nullptr;
  opts.cli_port = mrb_integer_p(port) ? static_cast<int>(mrb_integer(port)) : 0;

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  opts.stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);
  webmachine::server_options(opts);

  webmachine::app_load(mrb, opts.app_path);
  if (webmachine::server_entered()) return 0;
  return webmachine::server_run(mrb);
}

int main(int argc, char** argv) {
  Invocation in;
  in.argc = argc;
  in.argv = argv;

  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine-example: mrb_open failed\n");
    return 1;
  }
  define_resources(mrb);

  // #33: reading the flags, loading the app and coming up all refuse by
  // raising, and a raise is a C++ throw that needs a frame to land in.
  // This is it.
  const int rc = webmachine::run_guarded(mrb, {serve_body, &in});
  mrb_close(mrb);
  return rc;
}
