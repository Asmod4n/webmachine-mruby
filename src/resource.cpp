#include "resource.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

// Prediction hints only where the taken side is terminal (see ring.hpp).
#define WM_RES_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {
namespace {

using flow::KonstSet;
using flow::Node;

constexpr const char* kMethodName[6] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

// Class#inherited fires when the app writes
// `class Hello < Webmachine::Resource`; the subclass records itself.
mrb_value resource_inherited(mrb_state* mrb, mrb_value) {
  mrb_value sub;
  mrb_get_args(mrb, "C", &sub);
  struct RClass* wm = mrb_module_get(mrb, "Webmachine");
  mrb_iv_set(mrb, mrb_obj_value(wm), mrb_intern_lit(mrb, "@resource"), sub);
  return mrb_nil_value();
}

void exc_into(mrb_state* mrb, const char* what, char* err, size_t errlen) {
  mrb_value msg = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
  mrb->exc = nullptr;
  std::snprintf(err, errlen, "%s: %.*s", what,
                mrb_string_p(msg) ? static_cast<int>(RSTRING_LEN(msg)) : 0,
                mrb_string_p(msg) ? RSTRING_PTR(msg) : "");
}

// Is `name` defined as an INSTANCE method (runtime, per request)?
bool instance_defined(mrb_state* mrb, mrb_value klass, const char* name) {
  const mrb_value defined = mrb_funcall(mrb, klass, "method_defined?", 1,
                                        mrb_symbol_value(mrb_intern_cstr(mrb, name)));
  return mrb->exc == nullptr && mrb_test(defined);
}

// A konst callback, asked once on the CLASS. Absent -> the default
// stands. Raise -> a named refusal.
bool ask(mrb_state* mrb, mrb_value klass, const char* name, bool defv, bool* out, char* err,
         size_t errlen) {
  if (!mrb_respond_to(mrb, klass, mrb_intern_cstr(mrb, name))) {
    *out = defv;
    return true;
  }
  const mrb_value v = mrb_funcall(mrb, klass, name, 0);
  if (mrb->exc != nullptr) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  *out = mrb_test(v);
  return true;
}

// A method list (known_methods / allowed_methods): asked once, folded
// into per-method bits. Entries outside the compiled set are refused -
// a method the walker cannot name would silently 501.
bool ask_methods(mrb_state* mrb, mrb_value klass, const char* name, bool present[7], char* err,
                 size_t errlen) {
  if (!mrb_respond_to(mrb, klass, mrb_intern_cstr(mrb, name))) return true;
  const mrb_value v = mrb_funcall(mrb, klass, name, 0);
  if (mrb->exc != nullptr) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  if (!mrb_array_p(v)) {
    std::snprintf(err, errlen, "%s must return an Array of method strings", name);
    return false;
  }
  for (uint8_t m = 0; m < 7; m++) present[m] = false;
  for (mrb_int i = 0; i < RARRAY_LEN(v); i++) {
    const mrb_value e = mrb_ary_ref(mrb, v, i);
    bool known = false;
    if (mrb_string_p(e)) {
      for (uint8_t m = 0; m < 6; m++) {
        if (RSTRING_LEN(e) == static_cast<mrb_int>(std::strlen(kMethodName[m])) &&
            std::memcmp(RSTRING_PTR(e), kMethodName[m], RSTRING_LEN(e)) == 0) {
          present[m] = true;
          known = true;
          break;
        }
      }
    }
    if (!known) {
      std::snprintf(err, errlen, "%s entry %d is outside the compiled method set", name,
                    static_cast<int>(i));
      return false;
    }
  }
  return true;
}

// The boolean flow callbacks: node ans = callback truthiness, exactly
// flow.rb's decision_test orientation, already encoded in the table.
struct BoolCb {
  Node node;
  const char* name;
  bool defv;
};
constexpr BoolCb kBools[] = {
    {Node::kB13, "service_available?", true},
    {Node::kB11, "uri_too_long?", false},
    {Node::kB9a, "validate_content_checksum", true},  // nil = not validated reads as pass
    {Node::kB9b, "malformed_request?", false},
    {Node::kB7, "forbidden?", false},
    {Node::kB6, "valid_content_headers?", true},
    {Node::kB5, "known_content_type?", true},
    {Node::kB4, "valid_entity_length?", true},
    {Node::kG7, "resource_exists?", true},
    {Node::kK7, "previously_existed?", false},
    {Node::kM7, "allow_missing_post?", false},
    {Node::kN5, "allow_missing_post?", false},
    {Node::kM20, "delete_resource", false},
    {Node::kM20b, "delete_completed?", true},
    {Node::kO14, "is_conflict?", false},
    {Node::kP3, "is_conflict?", false},
    {Node::kO18b, "multiple_choices?", false},
};

}  // namespace

bool resource_setup(mrb_state* mrb, const char* path, Resource& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  FILE* f = std::fopen(path, "r");
  if (f == nullptr) {
    std::snprintf(err, errlen, "cannot open %s", path);
    return false;
  }
  mrb_load_file(mrb, f);
  std::fclose(f);
  if (mrb->exc != nullptr) {
    exc_into(mrb, "app raised while loading", err, errlen);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  struct RClass* wm = mrb_module_get(mrb, "Webmachine");
  const mrb_value klass = mrb_iv_get(mrb, mrb_obj_value(wm), mrb_intern_lit(mrb, "@resource"));
  if (mrb_type(klass) != MRB_TT_CLASS) {
    std::snprintf(err, errlen, "the app must define a class inheriting Webmachine::Resource");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  out = Resource{};
  out.mrb = mrb;

  // Callbacks whose VALUES the machine cannot speak yet refuse the
  // start by name - konst or runtime alike.
  static const char* kUnhonored[] = {
      "generate_etag", "last_modified", "options", "create_path", "process_post",
      "content_types_accepted", "base_uri", "expires", "variances",
  };
  for (const char* name : kUnhonored) {
    if (mrb_respond_to(mrb, klass, mrb_intern_cstr(mrb, name)) ||
        instance_defined(mrb, klass, name)) {
      std::snprintf(err, errlen, "%s is defined but no tier can honor it yet", name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }
  // These shape the compiled vectors or carry values: class methods only.
  static const char* kKonstOnly[] = {
      "known_methods", "allowed_methods", "content_types_provided", "languages_provided",
      "charsets_provided", "encodings_provided", "is_authorized?", "moved_permanently?",
      "moved_temporarily?",
  };
  for (const char* name : kKonstOnly) {
    if (instance_defined(mrb, klass, name)) {
      std::snprintf(err, errlen, "%s shapes the compiled vectors - declare it konst (def self.%s)",
                    name, name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // The booleans: class method -> konst bit; instance method -> the
  // node goes dynamic and is asked through the VM on every request.
  bool ans[sizeof(kBools) / sizeof(kBools[0])];
  for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
    const BoolCb& cb = kBools[i];
    ans[i] = cb.defv;
    if (instance_defined(mrb, klass, cb.name)) {
      out.dynamic |= uint64_t{1} << static_cast<size_t>(cb.node);
      out.node_sym[static_cast<size_t>(cb.node)] = mrb_intern_cstr(mrb, cb.name);
      continue;
    }
    if (!ask(mrb, klass, cb.name, cb.defv, &ans[i], err, errlen)) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // is_authorized?: only an unconditional true is konst (a 401 with
  // WWW-Authenticate needs the callback's string - a later tier).
  bool authorized = true;
  if (!ask(mrb, klass, "is_authorized?", true, &authorized, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (!authorized) {
    std::snprintf(err, errlen, "is_authorized? not returning true needs a later tier");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  // moved_*: a truthy answer carries a Location URI - a later tier.
  for (const char* name : {"moved_permanently?", "moved_temporarily?"}) {
    bool moved = false;
    if (!ask(mrb, klass, name, false, &moved, err, errlen)) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (moved) {
      std::snprintf(err, errlen, "%s with a Location is not representable yet", name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // The representation. content_types_provided (class method, one
  // [type, handler] pair - value conneg is a later tier) names the
  // handler; default is webmachine's ['text/html', :to_html]. A CLASS
  // handler renders once, here; an INSTANCE handler renders per
  // request through the VM.
  std::string content_type = "text/html";
  mrb_sym handler = mrb_intern_lit(mrb, "to_html");
  if (mrb_respond_to(mrb, klass, mrb_intern_lit(mrb, "content_types_provided"))) {
    const mrb_value v = mrb_funcall(mrb, klass, "content_types_provided", 0);
    if (mrb->exc != nullptr) {
      exc_into(mrb, "content_types_provided", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    mrb_value pair;
    mrb_value type;
    mrb_value h;
    if (!mrb_array_p(v) || RARRAY_LEN(v) != 1 || !mrb_array_p(pair = mrb_ary_ref(mrb, v, 0)) ||
        RARRAY_LEN(pair) != 2 || !mrb_string_p(type = mrb_ary_ref(mrb, pair, 0)) ||
        !mrb_symbol_p(h = mrb_ary_ref(mrb, pair, 1))) {
      std::snprintf(err, errlen,
                    "content_types_provided must hold exactly one [String, Symbol] pair "
                    "(value conneg is a later tier)");
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    content_type.assign(RSTRING_PTR(type), RSTRING_LEN(type));
    handler = mrb_symbol(h);
  }
  const bool body_konst = mrb_respond_to(mrb, klass, handler);
  const bool body_runtime =
      !body_konst && mrb_test(mrb_funcall(mrb, klass, "method_defined?", 1,
                                          mrb_symbol_value(handler)));
  if (mrb->exc != nullptr) {
    exc_into(mrb, "method_defined?", err, errlen);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (body_konst) {
    const mrb_value rendered = mrb_funcall_argv(mrb, klass, handler, 0, nullptr);
    if (mrb->exc != nullptr || !mrb_string_p(rendered)) {
      mrb->exc == nullptr
          ? static_cast<void>(std::snprintf(err, errlen, "the body handler must return a String"))
          : exc_into(mrb, "body handler raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    out.konst.body.assign(RSTRING_PTR(rendered), RSTRING_LEN(rendered));
    out.konst.content_type = content_type;
  } else if (body_runtime) {
    out.dynamic_body = true;
    out.body_sym = handler;
    out.konst.content_type = content_type;
  }

  // The instance dynamic callbacks are asked on: created once, pinned
  // against GC, holding whatever state the app's initialize gave it.
  if (out.dynamic != 0 || out.dynamic_body) {
    out.self = mrb_obj_new(mrb, mrb_class_ptr(klass), 0, nullptr);
    if (mrb->exc != nullptr) {
      exc_into(mrb, "resource initialize raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    mrb_gc_register(mrb, out.self);
  }

  // The method lists, folded (defaults: webmachine's standard known
  // set, GET/HEAD allowed).
  bool known[7] = {true, true, true, true, true, true, false};
  if (!ask_methods(mrb, klass, "known_methods", known, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  bool allowed[7] = {true, true, false, false, false, false, false};
  if (!ask_methods(mrb, klass, "allowed_methods", allowed, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  // Fold everything into the per-method vectors, and spell the Allow
  // line B10's 405 will speak (RFC 9110 10.2.1).
  out.konst.allow.clear();
  for (uint8_t m = 0; m < 6; m++) {
    if (allowed[m]) {
      if (!out.konst.allow.empty()) out.konst.allow.append(", ");
      out.konst.allow.append(kMethodName[m]);
    }
  }
  for (uint8_t m = 0; m < 7; m++) {
    flow::KonstAnswers& k = out.konst.per_method[m];
    k.ans[static_cast<size_t>(Node::kB12)] = known[m];
    k.ans[static_cast<size_t>(Node::kB10)] = allowed[m];
    for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
      k.ans[static_cast<size_t>(kBools[i].node)] = ans[i];
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

uint16_t resource_decide(const Resource& res, const flow::ReqFacts& facts) {
  const flow::KonstAnswers& k = res.konst.per_method[static_cast<size_t>(facts.method)];
  flow::Node n = flow::Node::kB13;
  for (;;) {  // terminates: proven acyclic in flow.hpp
    const flow::FlowNode& f = flow::kFlow[static_cast<size_t>(n)];
    bool ans;
    if (f.kind == flow::Kind::kRequest) {
      ans = flow::eval_request(n, facts);
    } else if ((res.dynamic >> static_cast<size_t>(n)) & 1) {
      // The budgeted entry: this node's answer lives in the world, the
      // VM is asked on every request. A raise ends in 500, never in a
      // dead process (the VM boundary is always protected).
      const int ai = mrb_gc_arena_save(res.mrb);
      const mrb_value v =
          mrb_funcall_argv(res.mrb, res.self, res.node_sym[static_cast<size_t>(n)], 0, nullptr);
      if (WM_RES_UNLIKELY(res.mrb->exc != nullptr)) {
        res.mrb->exc = nullptr;
        mrb_gc_arena_restore(res.mrb, ai);
        return 500;
      }
      ans = mrb_test(v);
      mrb_gc_arena_restore(res.mrb, ai);
    } else {
      ans = k.ans[static_cast<size_t>(n)];
    }
    const flow::Target& t = ans ? f.on_true : f.on_false;
    if (t.status != 0) return t.status;
    n = t.node;
  }
}

bool resource_render(const Resource& res, std::string& body) {
  // The copy floor in production: render in the VM, copy out, restore
  // the arena - the VM keeps nothing.
  const int ai = mrb_gc_arena_save(res.mrb);
  const mrb_value v = mrb_funcall_argv(res.mrb, res.self, res.body_sym, 0, nullptr);
  if (WM_RES_UNLIKELY(res.mrb->exc != nullptr) || !mrb_string_p(v)) {
    res.mrb->exc = nullptr;
    mrb_gc_arena_restore(res.mrb, ai);
    return false;
  }
  body.assign(RSTRING_PTR(v), RSTRING_LEN(v));
  mrb_gc_arena_restore(res.mrb, ai);
  return true;
}

}  // namespace webmachine

// The gem's Ruby surface: the Webmachine::Resource base class an app
// subclasses; Class#inherited records the subclass for resource_setup.
extern "C" {

void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module(mrb, "Webmachine");
  struct RClass* res = mrb_define_class_under(mrb, wm, "Resource", mrb->object_class);
  mrb_define_class_method(mrb, res, "inherited", webmachine::resource_inherited, MRB_ARGS_REQ(1));
}

void mrb_webmachine_mruby_gem_final(mrb_state*) {}

}  // extern "C"
