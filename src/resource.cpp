#include "resource.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

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

// One callback, asked once. Absent -> the default stands. Raise -> a
// named refusal (a setup that cannot answer cannot serve).
bool ask(mrb_state* mrb, mrb_value res, const char* name, bool defv, bool* out, char* err,
         size_t errlen) {
  if (!mrb_respond_to(mrb, res, mrb_intern_cstr(mrb, name))) {
    *out = defv;
    return true;
  }
  const mrb_value v = mrb_funcall(mrb, res, name, 0);
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
bool ask_methods(mrb_state* mrb, mrb_value res, const char* name, bool present[7], char* err,
                 size_t errlen) {
  if (!mrb_respond_to(mrb, res, mrb_intern_cstr(mrb, name))) return true;
  const mrb_value v = mrb_funcall(mrb, res, name, 0);
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

}  // namespace

bool resource_setup(mrb_state* mrb, const char* path, KonstSet& out, char* err, size_t errlen) {
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
  // Konst is DECLARED, not guessed: a class method (def self.x) belongs
  // to the class, not to a request - only those are asked, once, here.
  // An INSTANCE method on any flow callback is per-request semantics;
  // that tier does not exist yet, so it refuses the start by name.
  static const char* kAllCallbacks[] = {
      "service_available?", "known_methods", "uri_too_long?", "allowed_methods",
      "validate_content_checksum", "malformed_request?", "is_authorized?", "forbidden?",
      "valid_content_headers?", "known_content_type?", "valid_entity_length?", "options",
      "content_types_provided", "languages_provided", "charsets_provided",
      "encodings_provided", "resource_exists?", "generate_etag", "last_modified",
      "moved_permanently?", "moved_temporarily?", "previously_existed?",
      "allow_missing_post?", "delete_resource", "delete_completed?", "post_is_create?",
      "create_path", "process_post", "content_types_accepted", "is_conflict?",
      "multiple_choices?", "base_uri", "expires", "variances", "to_html",
  };
  for (const char* name : kAllCallbacks) {
    const mrb_value defined = mrb_funcall(mrb, klass, "method_defined?", 1,
                                          mrb_symbol_value(mrb_intern_cstr(mrb, name)));
    if (mrb->exc != nullptr) {
      exc_into(mrb, "method_defined?", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (mrb_test(defined)) {
      std::snprintf(err, errlen,
                    "%s is an instance method - per-request answers need a tier that does "
                    "not exist yet; declare it konst as a class method (def self.%s)",
                    name, name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }
  const mrb_value res = klass;  // class methods answer for the class

  // Callbacks only a later tier can honor refuse the start by name.
  static const char* kUnhonored[] = {
      "generate_etag", "last_modified", "options", "create_path", "process_post",
      "content_types_accepted", "base_uri", "expires", "variances",
  };
  for (const char* name : kUnhonored) {
    if (mrb_respond_to(mrb, res, mrb_intern_cstr(mrb, name))) {
      std::snprintf(err, errlen, "%s is defined but only a later tier can honor it", name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // The plain booleans: node ans = callback truthiness, exactly
  // flow.rb's decision_test orientation, already encoded in the table.
  struct BoolCb {
    Node node;
    const char* name;
    bool defv;
  };
  static const BoolCb kBools[] = {
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
  bool ans[sizeof(kBools) / sizeof(kBools[0])];
  for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
    if (!ask(mrb, res, kBools[i].name, kBools[i].defv, &ans[i], err, errlen)) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // is_authorized?: only an unconditional true is konst (a 401 with
  // WWW-Authenticate needs the callback's string - a later tier).
  bool authorized = true;
  if (!ask(mrb, res, "is_authorized?", true, &authorized, err, errlen)) {
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
    if (!ask(mrb, res, name, false, &moved, err, errlen)) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (moved) {
      std::snprintf(err, errlen, "%s with a Location is not konst-representable yet", name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // content_types_provided: exactly one [type, handler] pair is konst
  // (value conneg between several is a later tier). The handler runs
  // ONCE, here - its bytes become the prebuilt 200.
  std::string content_type;
  std::string body;
  bool have_body = false;
  if (mrb_respond_to(mrb, res, mrb_intern_lit(mrb, "content_types_provided")) ||
      mrb_respond_to(mrb, res, mrb_intern_lit(mrb, "to_html"))) {
    mrb_value pair_type = mrb_nil_value();
    mrb_sym handler = mrb_intern_lit(mrb, "to_html");  // webmachine's default pair
    content_type = "text/html";
    if (mrb_respond_to(mrb, res, mrb_intern_lit(mrb, "content_types_provided"))) {
      const mrb_value v = mrb_funcall(mrb, res, "content_types_provided", 0);
      if (mrb->exc != nullptr) {
        exc_into(mrb, "content_types_provided", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      if (!mrb_array_p(v) || RARRAY_LEN(v) != 1) {
        std::snprintf(err, errlen,
                      "content_types_provided must hold exactly one [type, handler] pair "
                      "(value conneg is a later tier)");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      const mrb_value pair = mrb_ary_ref(mrb, v, 0);
      if (!mrb_array_p(pair) || RARRAY_LEN(pair) != 2) {
        std::snprintf(err, errlen, "content_types_provided pair must be [String, Symbol]");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      pair_type = mrb_ary_ref(mrb, pair, 0);
      const mrb_value h = mrb_ary_ref(mrb, pair, 1);
      if (!mrb_string_p(pair_type) || !mrb_symbol_p(h)) {
        std::snprintf(err, errlen, "content_types_provided pair must be [String, Symbol]");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      content_type.assign(RSTRING_PTR(pair_type), RSTRING_LEN(pair_type));
      handler = mrb_symbol(h);
    }
    const mrb_value rendered = mrb_funcall_argv(mrb, res, handler, 0, nullptr);
    if (mrb->exc != nullptr) {
      exc_into(mrb, "body handler raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (!mrb_string_p(rendered)) {
      std::snprintf(err, errlen, "the body handler must return a String");
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    body.assign(RSTRING_PTR(rendered), RSTRING_LEN(rendered));
    have_body = true;
  }

  // The method lists, folded (defaults: webmachine's standard known
  // set, GET/HEAD allowed).
  bool known[7] = {true, true, true, true, true, true, false};
  if (!ask_methods(mrb, res, "known_methods", known, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  bool allowed[7] = {true, true, false, false, false, false, false};
  if (!ask_methods(mrb, res, "allowed_methods", allowed, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  // Fold everything into the per-method vectors, and spell the Allow
  // line B10's 405 will speak (RFC 9110 10.2.1).
  out = KonstSet{};
  if (have_body) {
    out.body = body;
    out.content_type = content_type;
  }
  out.allow.clear();
  for (uint8_t m = 0; m < 6; m++) {
    if (allowed[m]) {
      if (!out.allow.empty()) out.allow.append(", ");
      out.allow.append(kMethodName[m]);
    }
  }
  for (uint8_t m = 0; m < 7; m++) {
    flow::KonstAnswers& k = out.per_method[m];
    k.ans[static_cast<size_t>(Node::kB12)] = known[m];
    k.ans[static_cast<size_t>(Node::kB10)] = allowed[m];
    for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
      k.ans[static_cast<size_t>(kBools[i].node)] = ans[i];
    }
  }
  mrb_gc_arena_restore(mrb, ai);
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
