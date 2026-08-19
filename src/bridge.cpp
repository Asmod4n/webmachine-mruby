#include "bridge.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/string.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace webmachine {
namespace {

using flow::KonstSet;
using flow::Method;
using flow::Node;

constexpr const char* kMethodName[7] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", nullptr};

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
bool ask_methods(mrb_state* mrb, mrb_value res, const char* name, bool present[7],
                 bool* defined, char* err, size_t errlen) {
  *defined = mrb_respond_to(mrb, res, mrb_intern_cstr(mrb, name));
  if (!*defined) return true;
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
    if (!mrb_string_p(e)) {
      std::snprintf(err, errlen, "%s: entry %d is not a String", name, static_cast<int>(i));
      return false;
    }
    bool known = false;
    for (uint8_t m = 0; m < 6; m++) {
      if (RSTRING_LEN(e) == static_cast<mrb_int>(std::strlen(kMethodName[m])) &&
          std::memcmp(RSTRING_PTR(e), kMethodName[m], RSTRING_LEN(e)) == 0) {
        present[m] = true;
        known = true;
        break;
      }
    }
    if (!known) {
      std::snprintf(err, errlen, "%s names '%.*s' - outside the compiled method set (tier 1)",
                    name, static_cast<int>(RSTRING_LEN(e)), RSTRING_PTR(e));
      return false;
    }
  }
  return true;
}

// A *_provided list: konst-representable only as "negotiates" (non-empty);
// value conneg is a later tier, an empty list a refusal.
bool ask_provided(mrb_state* mrb, mrb_value res, const char* name, char* err, size_t errlen) {
  if (!mrb_respond_to(mrb, res, mrb_intern_cstr(mrb, name))) return true;
  const mrb_value v = mrb_funcall(mrb, res, name, 0);
  if (mrb->exc != nullptr) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  if (!mrb_array_p(v) || RARRAY_LEN(v) == 0) {
    std::snprintf(err, errlen, "%s must return a non-empty Array (value conneg is tier 1)", name);
    return false;
  }
  return true;
}

}  // namespace

bool bind_resource(mrb_state* mrb, const char* path, KonstSet& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  FILE* f = std::fopen(path, "r");
  if (f == nullptr) {
    std::snprintf(err, errlen, "cannot open %s", path);
    return false;
  }
  const mrb_value klass = mrb_load_file(mrb, f);
  std::fclose(f);
  if (mrb->exc != nullptr) {
    exc_into(mrb, "app raised while loading", err, errlen);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (mrb_type(klass) != MRB_TT_CLASS) {
    std::snprintf(err, errlen, "the app file must end with its resource class");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  const mrb_value res = mrb_obj_new(mrb, mrb_class_ptr(klass), 0, nullptr);
  if (mrb->exc != nullptr) {
    exc_into(mrb, "resource initialize raised", err, errlen);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  // Callbacks that only exist in tier 1 refuse the start by name.
  static const char* kUnhonored[] = {
      "generate_etag", "last_modified", "options", "create_path", "process_post",
      "content_types_accepted", "base_uri", "expires", "variances",
  };
  for (const char* name : kUnhonored) {
    if (mrb_respond_to(mrb, res, mrb_intern_cstr(mrb, name))) {
      std::snprintf(err, errlen, "%s is defined but only tier 1 can honor it - not built yet",
                    name);
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
  // WWW-Authenticate needs the callback's string - tier 1).
  bool authorized = true;
  if (!ask(mrb, res, "is_authorized?", true, &authorized, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (!authorized) {
    std::snprintf(err, errlen, "is_authorized? not returning true needs tier 1 (WWW-Authenticate)");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  // moved_*: a truthy answer carries a Location URI - tier 1.
  for (const char* name : {"moved_permanently?", "moved_temporarily?"}) {
    bool moved = false;
    if (!ask(mrb, res, name, false, &moved, err, errlen)) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (moved) {
      std::snprintf(err, errlen, "%s with a Location is not konst-representable - tier 1", name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // Conneg lists: honored as "negotiates".
  for (const char* name : {"content_types_provided", "languages_provided", "charsets_provided",
                           "encodings_provided"}) {
    if (!ask_provided(mrb, res, name, err, errlen)) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // The method lists, folded.
  bool known[7] = {true, true, true, true, true, true, false};
  bool known_defined = false;
  if (!ask_methods(mrb, res, "known_methods", known, &known_defined, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (!known_defined) {
    for (uint8_t m = 0; m < 6; m++) known[m] = true;  // webmachine's standard set
    known[6] = false;
  }
  bool allowed[7] = {true, true, false, false, false, false, false};  // default GET/HEAD
  bool allowed_defined = false;
  if (!ask_methods(mrb, res, "allowed_methods", allowed, &allowed_defined, err, errlen)) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (!allowed_defined) {
    allowed[0] = allowed[1] = true;
    for (uint8_t m = 2; m < 7; m++) allowed[m] = false;
  }

  // Fold everything into the per-method vectors, and spell the Allow
  // line B10's 405 will speak (RFC 9110 10.2.1).
  out = KonstSet{};
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
