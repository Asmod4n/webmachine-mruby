// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/object.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <simdutf.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define WM_RES_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define WM_RES_LIKELY(x) __builtin_expect(!!(x), 1)

// mrb_exc_backtrace and mrb_proc_arity live in mruby's INTERNAL header,
// which a gem may use - a gem is compiled together with mruby, so there
// is no ABI boundary here of the kind an outside consumer would face.
//
// What a gem may NOT do is copy the declarations out. A hand-written
// `extern "C" mrb_int mrb_proc_arity(const struct RProc*)` is a private
// second opinion about a signature nobody promised to keep: mruby is
// cloned fresh from master by the Rakefile, and if one of these changes
// shape, a copied declaration still compiles, still links, and calls
// with the wrong signature - corruption with no diagnostic anywhere.
// Including the header means the compiler checks, and a change upstream
// stops the build instead of the server.
//
// The wrapper is needed because internal.h carries no extern "C" guard
// of its own.
extern "C" {
#include <mruby/internal.h>
}

namespace webmachine {
namespace {
using flow::Node;

constexpr const char* kMethodName[6] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

// mruby: a setup raise becomes a named refusal, printed by the VM itself.
void exc_into(mrb_state* mrb, const char* what, char* err, size_t errlen) {
  std::snprintf(err, errlen, "%s (exception below)", what);
  mrb_print_error(mrb);
  mrb->exc = nullptr;
}

// mruby: unwrap MRB_PROC_ALIAS once, at fold, instead of at every call.
mrb_method_t resolve_alias(mrb_method_t m) {
  if (MRB_METHOD_UNDEF_P(m) || MRB_METHOD_FUNC_P(m)) return m;
  const struct RProc* p = MRB_METHOD_PROC(m);
  while (p != nullptr && MRB_PROC_ALIAS_P(p)) p = p->upper;
  if (p == nullptr) return m;
  mrb_method_t out = m;
  MRB_METHOD_FROM_PROC(out, p);
  return out;
}

// One name looked up on one class: what mruby found, whether anything
// answers, whether it is an irep (so the proc may be entered directly),
// our own C++ body where there is one, and the name it was found by - the
// funcall fallback needs it, and passing it separately let it disagree.
struct Resolved {
  mrb_method_t m = {};
  mrb_sym sym = 0;
  bool defined = false;
  bool irep = false;
  NativeCb native = nullptr;
};

// The receiver a call enters on, and the class its method was found on -
// mruby needs both to enter an irep without a second method search.
struct On {
  mrb_value self;
  struct RClass* c;
};

// Which (class, name) pairs were registered as C++ callbacks. Consulted
// at FOLD time only - the answer is copied into the slot, so a request
// never looks anything up. A vector because an app has a handful of
// these and a hash would cost more to build than it ever saves.
struct NativeEntry {
  struct RClass* c;
  mrb_sym sym;
  NativeCb fn;
};
std::vector<NativeEntry>& native_table() {
  static std::vector<NativeEntry> t;
  return t;
}

// Ruby must be able to call the same method, so an ordinary cfunc is
// registered too; it collects the arguments the normal way and hands
// them on. The engine skips this wrapper entirely.
mrb_value native_shim(mrb_state* mrb, mrb_value self) {
  mrb_value* argv = nullptr;
  mrb_int argc = 0;
  mrb_get_args(mrb, "*", &argv, &argc);
  struct RClass* c = mrb_class(mrb, self);
  const mrb_sym mid = mrb->c->ci->mid;
  for (struct RClass* k = c; k != nullptr; k = k->super) {
    for (const NativeEntry& e : native_table()) {
      if (e.c == k && e.sym == mid) return e.fn(mrb, self, argc, argv);
    }
  }
  mrb_raisef(mrb, E_WM_ERROR(mrb), "%s lost its native body", mrb_sym_name(mrb, mid));
  return mrb_nil_value();
}

// The one place a native callback is looked up by (class, name).
NativeCb native_of(struct RClass* c, mrb_sym sym) {
  for (struct RClass* k = c; k != nullptr; k = k->super) {
    for (const NativeEntry& e : native_table()) {
      if (e.c == k && e.sym == sym) return e.fn;
    }
  }
  return nullptr;
}

// mruby: where does this symbol answer, and may we enter its proc directly?
Resolved resolve(mrb_state* mrb, struct RClass* c, mrb_sym sym) {
  Resolved r;
  r.sym = sym;
  struct RClass* owner = c;
  r.m = resolve_alias(mrb_method_search_vm(mrb, &owner, sym));
  r.defined = !MRB_METHOD_UNDEF_P(r.m);
  r.irep = r.defined && !MRB_METHOD_CFUNC_P(r.m);
  // Ours? Then the slot carries the function itself and the engine
  // enters it directly - no lookup, no callinfo, no VM.
  if (r.defined && !r.irep) r.native = native_of(owner, sym);
  return r;
}

// mruby: is this a runtime callback? A direct look into the method table.
bool instance_defined(mrb_state* mrb, mrb_value klass, mrb_sym sym) {
  return resolve(mrb, mrb_class_ptr(klass), sym).defined;
}

// mruby: how many arguments the method DECLARED, capped at what its node offers.
uint8_t argc_of(mrb_method_t m, uint8_t most) {
  int a = most;
  if (!MRB_METHOD_FUNC_P(m)) {
    const struct RProc* p = MRB_METHOD_PROC(m);
    if (p != nullptr) {
      const mrb_int ar = mrb_proc_arity(p);
      if (ar >= 0) a = static_cast<int>(ar) < most ? static_cast<int>(ar) : most;
    }
  }
  return static_cast<uint8_t>(a);
}

// cb.rb: what to look for - the name, and whether a `def self.` with no
// instance method beside it counts as an answer.
struct Wanted {
  mrb_sym sym;
  bool class_fallback;
};

// cb.rb: a value callback - the instance method wins; a class-only version is
// kept with an undef method slot and funcalled on the class at runtime.
Resource::ValueCb value_cb(mrb_state* mrb, mrb_value klass, Wanted w) {
  const mrb_sym sym = w.sym;
  const bool class_fallback = w.class_fallback;
  Resource::ValueCb cb;
  cb.sym = sym;
  const Resolved inst = resolve(mrb, mrb_class_ptr(klass), sym);
  if (inst.defined) {
    cb.has = true;
    cb.m = inst.m;
    cb.irep = inst.irep;
    cb.native = inst.native;
    cb.argc = argc_of(inst.m, 0);
    return cb;
  }
  if (!class_fallback) return cb;
  const Resolved meta = resolve(mrb, mrb_class(mrb, klass), sym);
  if (meta.defined) {
    cb.has = true;
    cb.m = meta.m;
    cb.irep = meta.irep;
    cb.native = meta.native;
    cb.on_class = true;
    cb.argc = argc_of(meta.m, 0);
  }
  return cb;
}

struct SetupCall {
  const struct RProc* proc;
  mrb_sym sym;
  mrb_value self;
  struct RClass* c;
};

// mruby: the yield body a setup call runs under mrb_protect_error.
mrb_value setup_call_body(mrb_state* mrb, void* ud) {
  const SetupCall* c = static_cast<const SetupCall*>(ud);
  mrb_callinfo* ci = mrb->c->ci;
  const mrb_sym saved_mid = ci->mid;
  ci->mid = c->sym;
  mrb_value r = mrb_yield_with_class(mrb, mrb_obj_value(const_cast<struct RProc*>(c->proc)), 0,
                                     nullptr, c->self, c->c);
  ci->mid = saved_mid;
  return r;
}

// mruby: invoke a resolved method at SETUP time; a raise stays pending.
struct NativeCall {
  NativeCb fn;
  mrb_value self;
  mrb_int argc;
  const mrb_value* argv;
};

// The yield body a native call runs under mrb_protect_error - a C++
// callback may raise like any other, and an unguarded raise here would
// unwind through frames that are not ready for it.
mrb_value native_call_body(mrb_state* mrb, void* ud) {
  const NativeCall* c = static_cast<const NativeCall*>(ud);
  return c->fn(mrb, c->self, c->argc, c->argv);
}

// mruby: mrb_protect_error hands back WHATEVER was pending (vm.c: it
// returns mrb_obj_value(mrb->exc) and clears it), and mrb->exc is a
// struct RObject* - so only an exception object may be stored there.
// mrb_obj_ptr on anything else reads a Fixnum's bits as a pointer, and
// mruby's immediates (Integer, Symbol, nil, true, false) carry no
// object at all. Checked once, here, for every protected call.
void take_pending(mrb_state* mrb, mrb_value v) {
  if (!WM_RES_UNLIKELY(!mrb_exception_p(v))) {
    mrb->exc = mrb_obj_ptr(v);
    return;
  }
  mrb->exc = mrb_obj_ptr(
      mrb_exc_new_lit(mrb, E_WM_ERROR(mrb), "a callback ended without an exception object"));
}

mrb_value call_native(mrb_state* mrb, NativeCall call) {
  mrb_bool raised = FALSE;
  mrb_value v = mrb_protect_error(mrb, native_call_body, &call, &raised);
  if (WM_RES_UNLIKELY(raised)) {
    take_pending(mrb, v);
    return mrb_nil_value();
  }
  mrb_gc_protect(mrb, v);
  return v;
}

mrb_value call_resolved(mrb_state* mrb, const Resolved& r, On on) {
  if (r.native != nullptr) return call_native(mrb, {r.native, on.self, 0, nullptr});
  if (!r.irep) return mrb_funcall_argv(mrb, on.self, r.sym, 0, nullptr);
  SetupCall ctx{MRB_METHOD_PROC(r.m), r.sym, on.self, on.c};
  mrb_bool raised = FALSE;
  mrb_value v = mrb_protect_error(mrb, setup_call_body, &ctx, &raised);
  if (WM_RES_UNLIKELY(raised)) {
    take_pending(mrb, v);
    return mrb_nil_value();
  }
  mrb_gc_protect(mrb, v);
  return v;
}

// The class being folded, and where a refusal about it is spelled.
struct Folding {
  mrb_state* mrb;
  mrb_value klass;
  char* err;
  size_t errlen;
};

// One callback fold time asks: the symbol it is found by, and the name a
// refusal spells it with.
struct Asked {
  mrb_sym sym;
  const char* name;
};

// RFC 9110: one konst flow callback, asked once on the class.
bool ask(const Folding& f, Asked a, bool defv, bool* out) {
  mrb_state* const mrb = f.mrb;
  const Resolved r = resolve(mrb, mrb_class(mrb, f.klass), a.sym);
  if (!r.defined) {
    *out = defv;
    return true;
  }
  const mrb_value v = call_resolved(mrb, r, {f.klass, mrb_class(mrb, f.klass)});
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, a.name, f.err, f.errlen);
    return false;
  }
  *out = mrb_test(v);
  return true;
}

// #202: a `def self.x` is asked HERE, once, and its answer is kept for the
// life of the process - that is the whole reason the class form exists.
// The class is frozen right after, so the answer cannot go stale.
// `spell` turns a String answer into an ETag (RFC 9110 8.8.3); without it
// the answer is read as a moment (RFC 9110 5.6.7), the way the date fields
// need it.
// One class-form answer: where it comes from, what it is called in a
// refusal, whether it is spelled as an ETag, and the slot it is kept in
// for the life of the process.
struct BakedValue {
  const Resource::ValueCb& cb;
  const char* name;
  bool spell;
  Resource::KonstValue& out;
};

bool bake_value(const Folding& f, const BakedValue& bake) {
  mrb_state* const mrb = f.mrb;
  const Resource::ValueCb& cb = bake.cb;
  Resource::KonstValue& out = bake.out;
  if (!cb.has || !cb.on_class) return true;
  out.asked = true;
  Resolved r;
  r.m = cb.m;
  r.irep = cb.irep;
  r.native = cb.native;
  r.defined = true;
  mrb_value v = call_resolved(mrb, r, {f.klass, mrb_class(mrb, f.klass)});
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, bake.name, f.err, f.errlen);
    return false;
  }
  if (mrb_nil_p(v) || mrb_false_p(v)) return true;
  if (bake.spell) {
    if (!mrb_string_p(v)) v = mrb_obj_as_string(mrb, v);
    http::etag_spell(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)), out.text);
    out.present = true;
    return true;
  }
  if (!mrb_integer_p(v)) v = mrb_funcall_argv(mrb, v, MRB_SYM(to_i), 0, nullptr);
  if (WM_RES_UNLIKELY(!mrb_integer_p(v) || mrb->exc != nullptr)) {
    std::snprintf(f.err, f.errlen, "%s must answer a Time or an epoch Integer", bake.name);
    mrb->exc = nullptr;
    return false;
  }
  out.epoch = static_cast<int64_t>(mrb_integer(v));
  out.present = true;
  return true;
}

// One run of space- or comma-separated method tokens, marked off in seen[].
bool mark_tokens(const Folding& f, Asked a, mrb_value v, bool seen[7]) {
  const char* p = RSTRING_PTR(v);
  const char* const end = p + RSTRING_LEN(v);
  while (p < end) {
    while (p < end && (*p == ' ' || *p == ',')) p++;
    const char* tok = p;
    while (p < end && *p != ' ' && *p != ',') p++;
    if (tok == p) break;
    bool known = false;
    for (uint8_t m = 0; m < 6; m++) {
      const size_t n = std::strlen(kMethodName[m]);
      if (static_cast<size_t>(p - tok) == n && std::memcmp(tok, kMethodName[m], n) == 0) {
        seen[m] = true;
        known = true;
        break;
      }
    }
    if (WM_RES_UNLIKELY(!known)) {
      std::snprintf(f.err, f.errlen, "%s names '%.*s' - outside the compiled method set",
                    a.name, static_cast<int>(p - tok), tok);
      return false;
    }
  }
  return true;
}

// RFC 9110 9.1: known_methods / allowed_methods as one String of tokens or
// webmachine-ruby's Array-of-Strings form.
bool ask_methods(const Folding& f, Asked a, bool seen[7]) {
  mrb_state* const mrb = f.mrb;
  const Resolved r = resolve(mrb, mrb_class(mrb, f.klass), a.sym);
  if (!r.defined) return true;
  const mrb_value v = call_resolved(mrb, r, {f.klass, mrb_class(mrb, f.klass)});
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, a.name, f.err, f.errlen);
    return false;
  }
  for (uint8_t m = 0; m < 7; m++) seen[m] = false;
  if (mrb_string_p(v)) return mark_tokens(f, a, v, seen);
  if (mrb_array_p(v)) {
    for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
      const mrb_value s = RARRAY_PTR(v)[j];
      if (WM_RES_UNLIKELY(!mrb_string_p(s))) {
        std::snprintf(f.err, f.errlen, "%s must return method Strings", a.name);
        return false;
      }
      if (!mark_tokens(f, a, s, seen)) return false;
    }
    return true;
  }
  std::snprintf(f.err, f.errlen,
                "%s must return an Array of Strings or a String like 'GET HEAD'", a.name);
  return false;
}

struct BoolCb {
  Node node;
  mrb_sym sym;
  const char* name;
  bool defv;
  uint8_t maxargs;
};
const BoolCb kBools[] = {
    {Node::kB13, MRB_SYM_Q(service_available), "service_available?", true, 0},
    {Node::kB11, MRB_SYM_Q(uri_too_long), "uri_too_long?", false, 1},
    {Node::kB9b, MRB_SYM_Q(malformed_request), "malformed_request?", false, 0},
    {Node::kB7, MRB_SYM_Q(forbidden), "forbidden?", false, 0},
    {Node::kB6, MRB_SYM_Q(valid_content_headers), "valid_content_headers?", true, 1},
    {Node::kB5, MRB_SYM_Q(known_content_type), "known_content_type?", true, 1},
    {Node::kB4, MRB_SYM_Q(valid_entity_length), "valid_entity_length?", true, 1},
    {Node::kG7, MRB_SYM_Q(resource_exists), "resource_exists?", true, 0},
    {Node::kK7, MRB_SYM_Q(previously_existed), "previously_existed?", false, 0},
    {Node::kM7, MRB_SYM_Q(allow_missing_post), "allow_missing_post?", false, 0},
    {Node::kN5, MRB_SYM_Q(allow_missing_post), "allow_missing_post?", false, 0},
    {Node::kM20, MRB_SYM(delete_resource), "delete_resource", false, 0},
    {Node::kM20b, MRB_SYM_Q(delete_completed), "delete_completed?", true, 0},
    {Node::kO14, MRB_SYM_Q(is_conflict), "is_conflict?", false, 0},
    {Node::kP3, MRB_SYM_Q(is_conflict), "is_conflict?", false, 0},
    {Node::kO18b, MRB_SYM_Q(multiple_choices), "multiple_choices?", false, 0},
};

// flow.rb b8: a value-semantics node riding the node tables; a class-only
// version keeps an undef method slot and is funcalled on the class.
struct NodeValueCb {
  Node node;
  mrb_sym sym;
  uint8_t maxargs;
};
const NodeValueCb kNodeValues[] = {
    {Node::kB8, MRB_SYM_Q(is_authorized), 1},
};

struct NamedSym {
  mrb_sym sym;
  const char* name;
};
const NamedSym kUnhonored[] = {
    {MRB_SYM(languages_provided), "languages_provided"},
    {MRB_SYM(charsets_provided), "charsets_provided"},
    {MRB_SYM(language_chosen), "language_chosen"},
};
const NamedSym kKonstOnly[] = {
    {MRB_SYM(encodings_provided), "encodings_provided"},
};

// The mirror of kKonstOnly. `def self.x` means, everywhere in this tree,
// "asked ONCE while the app is being set up, and the answer is frozen with
// the class". That is right for a QUESTION and wrong for these five: they
// do WORK, and work asked once at setup is work that never happens again -
// a class-level process_post would handle exactly zero POSTs, silently.
// So the fold refuses them by name instead of folding them.
const NamedSym kWorkOnly[] = {
    {MRB_SYM(delete_resource), "delete_resource"},
    {MRB_SYM(create_path), "create_path"},
    {MRB_SYM(process_post), "process_post"},
    {MRB_SYM(finish_request), "finish_request"},
};

// RFC 9110 5.1: case-insensitive token equality, neither side canonical.
bool ci_eq(const char* a, size_t an, const char* b, size_t bn) {
  if (an != bn) return false;
  for (size_t i = 0; i < an; i++) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x + 32);
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y + 32);
    if (x != y) return false;
  }
  return true;
}

// RFC 9110 10.2.2: does this run's header block already carry a Location line?
bool headers_has_location(const std::string& h) {
  size_t at = 0;
  while (at < h.size()) {
    size_t eol = h.find("\r\n", at);
    if (eol == std::string::npos) eol = h.size();
    if (eol - at > 9 && http::tok_eq(h.data() + at, 9, "location:", 9)) return true;
    at = eol + 2;
  }
  return false;
}

// RFC 9110: THE runtime tier - webmachine-ruby's value semantics for the
// whole flow (flow.rb + helpers.rb, 1:1) inside one VM frame.
// RFC 9110: one request's walk through the flow. Entered as a C++ call
// from resource_run - a Ruby frame around it would cost a method lookup
// per request and leave a class in the GC's mark set.
struct RescueCtx {
  const Resource* res;
  mrb_value exc;
};

// fsm.rb: the raise path - finish_request, inside its own guarded frame.
// handle_exception is NOT here: it lives on Webmachine::ErrorResource and
// nowhere else (#210), because what an exception says on the wire is one
// decision for the server rather than a per-route one. A resource that
// defines its own is ignored.
mrb_value run_rescue_body(mrb_state* mrb, void* ud) {
  RescueCtx& rc = *static_cast<RescueCtx*>(ud);
  const Resource& res = *rc.res;
  if (res.cb_finish_request.has && !mrb_nil_p(res.live)) {
    const mrb_value frecv =
        MRB_METHOD_UNDEF_P(res.cb_finish_request.m) ? mrb_obj_value(res.klass) : res.live;
    mrb_funcall_argv(mrb, frecv, res.cb_finish_request.sym, 0, nullptr);
  }
  return mrb_nil_value();
}

// fsm.rb: everything one run carries from one node to the next. It is a
// struct and not a row of stack locals because the arms that are not the
// straight line live in functions of their own, and this is what they
// are handed (.DESIGN.md "The happy path is the straight line").
//
// `facts` and `k` are references into `res` rather than lookups repeated
// at each use; `chosen` is written where the content type is negotiated
// and read where the body is produced, which is why it outlives an arm.
struct Run {
  mrb_state* mrb;
  const Resource& res;
  const flow::ReqFacts& facts;
  const flow::KonstAnswers& k;
  const http::ReqValues* vals;
  std::string& hdrs;
  Node n;
  uint16_t status;
  bool halted;
  int chosen;
  bool ct_dyn;
};

// flow.rb decision_test: ANY callback may halt with an Integer status.
uint16_t halt_of(Run& r, mrb_value v, mrb_sym sym) {
  mrb_state* mrb = r.mrb;
  const mrb_int code = mrb_integer(v);
  if (WM_RES_LIKELY(code >= 100 && code <= 599)) {
    return static_cast<uint16_t>(code);
  } else {
    mrb_raisef(mrb, E_RANGE_ERROR, "%s answered %i, which is not an HTTP status",
               mrb_sym_name(mrb, sym), code);
  }
  __builtin_unreachable();
}

// RFC 9110 9.1: the method token as the request spelled it, or the name
// of the one the parse settled on.
void method_name(Run& r, const char** p, size_t* len) {
  if (WM_RES_LIKELY(r.res.run_req != nullptr && r.res.run_req->method_token != nullptr)) {
    *p = r.res.run_req->method_token;
    *len = r.res.run_req->method_token_len;
  } else {
    const size_t m = static_cast<size_t>(r.facts.method);
    *p = m < 6 ? kMethodName[m] : "";
    *len = m < 6 ? std::strlen(kMethodName[m]) : 0;
  }
}

// flow.rb b10/b12: is this request's method in the list the resource just
// answered with?
bool methods_contain(Run& r) {
  const char* mp;
  size_t mn;
  method_name(r, &mp, &mn);
  for (const std::string& s : r.res.run_methods) {
    if (s.size() == mn && std::memcmp(s.data(), mp, mn) == 0) return true;
  }
  return false;
}

// RFC 9110 12.5.1: the list c3/c4 negotiate against - the run's own where
// the resource answered per request, the folded one otherwise.
const std::vector<Resource::TypedHandler>& active_ct(Run& r) {
  return r.ct_dyn ? r.res.run_content_types_provided : r.res.content_types_provided;
}

// RFC 9110 5.6.2 / 5.5: the gate for everything an app puts into the head -
// an ETag, a Location, a WWW-Authenticate, a Vary member, and with
// options() the field NAME too. Here because here is the only place that
// spells a field; a raise inside the run frame is a 500, which is the
// honest answer to a resource that made an unspellable one.
void field(Run& r, const char* name, size_t nlen, const char* value, size_t vlen) {
  mrb_state* mrb = r.mrb;
  if (WM_RES_LIKELY(http::field_name_ok(name, nlen) && http::field_value_ok(value, vlen))) {
    r.hdrs.append(name, nlen);
    r.hdrs.append(": ", 2);
    r.hdrs.append(value, vlen);
    r.hdrs.append("\r\n", 2);
  } else {
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "a field this resource produced is not spellable: the name must be a token "
              "(RFC 9110 5.6.2) and the value must carry no CR, LF or NUL (5.5)");
  }
}

// RFC 9110 5.6.7: one HTTP-date field, IMF-fixdate.
void date_line(Run& r, const char* name, size_t nlen, int64_t epoch) {
  struct tm tmv {};
  const time_t t = static_cast<time_t>(epoch);
  gmtime_r(&t, &tmv);
  char buf[http::kDateLen];
  http::date_core(buf, tmv);
  field(r, name, nlen, buf, http::kDateLen);
}

// RFC 9110 12.5.2/12.5.3/12.5.4: what follows the Accept nodes. d4, e5 and
// f6 each ask whether the request named their field, and the conneg node
// behind each is reachable only through it, so a request naming none of the
// three walks d4 -> e5 -> f6 -> g7 and cannot say a word on the way.
Node after_accept(const flow::ReqFacts& facts) {
  return facts.has_accept_language || facts.has_accept_charset || facts.has_accept_encoding
             ? Node::kD4
             : Node::kG7;
}

// fsm.rb run: one step's edge, out of the graph table.
void take_edge(Node& n, uint16_t& status, bool& halted, const flow::FlowNode& f, bool a) {
  const flow::Target& t = a ? f.on_true : f.on_false;
  if (t.status != 0) {
    status = t.status;
    halted = true;
  } else {
    n = t.node;
  }
}

// The same step for the callers that do not already hold the node's row.
// The generic node path does - it reads f.kind first - and calls the form
// above rather than pay for a second flow::kFlow[n] lookup of the same node.
void take_edge(Node& n, uint16_t& status, bool& halted, bool a) {
  take_edge(n, status, halted, flow::kFlow[static_cast<size_t>(n)], a);
}

// One list-valued field line: its name, the value that always leads where
// there is one, and the app Strings that follow it - Allow's methods,
// Vary's variances.
struct FieldList {
  std::string_view name;
  std::string_view head;
  const std::vector<std::string>& tail;
};

// RFC 9110 5.6.7: one date field of a resource - where its answer comes
// from (the per-request callback, or what #202 baked at setup) and the
// three slots that remember what it said this round.
struct DateField {
  const Resource::ValueCb& cb;
  const Resource::KonstValue& konst;
  bool* asked;
  bool* present;
  int64_t* epoch;
};

// One method already found: what mruby resolved for the name, whether it
// is an irep (so the fast entry applies), our own C++ body where there is
// one, and the name itself for the funcall the slow path falls back to.
struct Bound {
  mrb_method_t m;
  bool irep;
  NativeCb native;
  mrb_sym sym;
};

// What one call carries. mruby wants (argc, argv); this is that pair with
// a name, and {} is the call that carries nothing.
using Args = std::span<const mrb_value>;

mrb_value naked(Run& r, Bound b, Args args = {});
mrb_value naked_class(Run& r, Bound b, Args args = {});
mrb_value cbv(Run& r, const Resource::ValueCb& cb, Args args = {});
mrb_value nodecall(Run& r, Node nd, Args args);
mrb_value arg_for(Run& r, Node nd);
void marshal_methods(Run& r, const Resource::ValueCb& cb);
void field_list(Run& r, const FieldList& f);
void allow_line(Run& r);
void marshal_ct(Run& r);
int ensure_etag(Run& r);
void epoch_memo(Run& r, const DateField& d);
int add_caching(Run& r);
bool param_find(const char* s, size_t n, const char* key, size_t kn, const char** vout, size_t* vn);
int accept_helper(Run& r);
int run_n11(Run& r);

mrb_value naked(Run& r, Bound b, Args args) {
    const mrb_int argc = static_cast<mrb_int>(args.size());
    const mrb_value* const argv = args.data();
    const NativeCb native = b.native;
    const mrb_sym sym = b.sym;
    // The cheapest of the three tiers: our own C++ body, entered with the
    // arguments in hand. It never reads the callinfo, so there is nothing
    // to build for it.
    if (native != nullptr) return call_native(r.mrb, {native, r.res.live, argc, argv});
    if (WM_RES_UNLIKELY(!b.irep || mrb_obj_ptr(r.res.live)->c != r.res.klass)) {
      return mrb_funcall_argv(r.mrb, r.res.live, sym, argc, argv);
    }
    mrb_callinfo* ci = r.mrb->c->ci;
    const mrb_sym saved = ci->mid;
    ci->mid = sym;
    mrb_value answer = mrb_yield_with_class(
        r.mrb, mrb_obj_value(const_cast<struct RProc*>(MRB_METHOD_PROC(b.m))), argc, argv,
        r.res.live,
        r.res.klass);
    ci->mid = saved;
    return answer;
}

mrb_value naked_class(Run& r, Bound b, Args args) {
    const mrb_int argc = static_cast<mrb_int>(args.size());
    const mrb_value* const argv = args.data();
    const NativeCb native = b.native;
    const mrb_sym sym = b.sym;
    const mrb_value self = mrb_obj_value(r.res.klass);
    if (native != nullptr) return call_native(r.mrb, {native, self, argc, argv});
    // mrb_obj_ptr(self)->c, not mrb_class(r.mrb, self): the latter is an
    // out-of-line call into another translation unit, and this build has no
    // LTO - a call to read one pointer, on the path whose whole point is
    // not calling anything.
    if (WM_RES_UNLIKELY(!b.irep || mrb_obj_ptr(self)->c != r.res.meta_klass)) {
      return mrb_funcall_argv(r.mrb, self, sym, argc, argv);
    }
    mrb_callinfo* ci = r.mrb->c->ci;
    const mrb_sym saved = ci->mid;
    ci->mid = sym;
    mrb_value answer = mrb_yield_with_class(
        r.mrb, mrb_obj_value(const_cast<struct RProc*>(MRB_METHOD_PROC(b.m))), argc, argv, self,
        r.res.meta_klass);
    ci->mid = saved;
    return answer;
}

mrb_value cbv(Run& r, const Resource::ValueCb& cb, Args args) {
    const Bound b = {cb.m, cb.irep, cb.native, cb.sym};
    if (cb.on_class) return naked_class(r, b, args);
    return naked(r, b, args);
}

mrb_value nodecall(Run& r, Node nd, Args args) {
    const size_t i = static_cast<size_t>(nd);
    const Bound b = {r.res.node_m[i], r.res.node_irep[i], r.res.node_native[i],
                     r.res.node_sym[i]};
    if ((r.res.node_on_class >> i) & 1) return naked_class(r, b, args);
    return naked(r, b, args);
}

mrb_value arg_for(Run& r, Node nd) {
    switch (nd) {
      case Node::kB8:
        return r.vals != nullptr && r.vals->authorization != nullptr
                   ? mrb_str_new(r.mrb, r.vals->authorization, r.vals->authorization_len)
                   : mrb_nil_value();
      case Node::kB11:
        return r.res.run_req != nullptr && r.res.run_req->request_target != nullptr
                   ? mrb_str_new(r.mrb, r.res.run_req->request_target, r.res.run_req->request_target_len)
                   : mrb_nil_value();
      case Node::kB6: {
        const mrb_value rq = mrb_funcall_argv(r.mrb, r.res.live, MRB_SYM(request), 0, nullptr);
        const mrb_value hs = mrb_funcall_argv(r.mrb, rq, MRB_SYM(headers), 0, nullptr);
        const mrb_value out = mrb_hash_new(r.mrb);
        if (mrb_hash_p(hs)) {
          const mrb_value keys = mrb_hash_keys(r.mrb, hs);
          for (mrb_int j = 0; j < RARRAY_LEN(keys); j++) {
            const mrb_value key = RARRAY_PTR(keys)[j];
            if (!mrb_string_p(key) || RSTRING_LEN(key) < 8) continue;
            if (!http::tok_eq(RSTRING_PTR(key), 8, "content-", 8)) continue;
            mrb_hash_set(r.mrb, out, key, mrb_hash_get(r.mrb, hs, key));
          }
        }
        return out;
      }
      case Node::kB5:
        return r.vals != nullptr && r.vals->content_type != nullptr
                   ? mrb_str_new(r.mrb, r.vals->content_type, r.vals->content_type_len)
                   : mrb_nil_value();
      case Node::kB4:
        return mrb_int_value(
            r.mrb, static_cast<mrb_int>(r.res.run_req != nullptr ? r.res.run_req->content_len : 0));
      default:
        return mrb_nil_value();
    }
}

void marshal_methods(Run& r, const Resource::ValueCb& cb) {
  mrb_state* mrb = r.mrb;
  r.res.run_methods.clear();
  const mrb_value v = cbv(r, cb);
  if (mrb_array_p(v)) {
    for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
      const mrb_value s = RARRAY_PTR(v)[j];
      if (WM_RES_UNLIKELY(!mrb_string_p(s))) {
        mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer method Strings",
                   mrb_sym_name(mrb, cb.sym));
      }
      r.res.run_methods.emplace_back(RSTRING_PTR(s), static_cast<size_t>(RSTRING_LEN(s)));
    }
    return;
  }
  if (WM_RES_UNLIKELY(!mrb_string_p(v))) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer an Array of Strings or a String",
               mrb_sym_name(mrb, cb.sym));
  }
  const char* p = RSTRING_PTR(v);
  const char* end = p + RSTRING_LEN(v);
  while (p < end) {
    while (p < end && (*p == ' ' || *p == ',')) p++;
    const char* tok = p;
    while (p < end && *p != ' ' && *p != ',') p++;
    if (tok != p) r.res.run_methods.emplace_back(tok, static_cast<size_t>(p - tok));
  }
}

void field_list(Run& r, const FieldList& f) {
  mrb_state* mrb = r.mrb;
  r.hdrs.append(f.name);
  r.hdrs.append(": ", 2);
  bool first = true;
  if (!f.head.empty()) {
    r.hdrs.append(f.head);
    first = false;
  }
  for (const std::string& s : f.tail) {
    // Same gate, one member at a time: Allow's members come from
    // allowed_methods and Vary's from variances, both app Strings.
    if (WM_RES_UNLIKELY(!http::field_value_ok(s.data(), s.size()))) {
      mrb_raise(mrb, E_WM_ERROR(mrb),
                "a list field this resource produced carries CR, LF or NUL (RFC 9110 5.5)");
    }
    if (!first) r.hdrs.append(", ", 2);
    r.hdrs.append(s);
    first = false;
  }
  r.hdrs.append("\r\n", 2);
}

void allow_line(Run& r) {
    if (r.res.cb_allowed_methods.has) {
      field_list(r, {"Allow", {}, r.res.run_methods});
    } else {
      field(r, "Allow", 5, r.res.konst.allow.data(), r.res.konst.allow.size());
    }
}

void marshal_ct(Run& r) {
  mrb_state* mrb = r.mrb;
  if (!r.ct_dyn || r.res.run_content_types_marshalled) return;
  r.res.run_content_types_marshalled = true;
  const mrb_value v = cbv(r, r.res.cb_content_types_provided);
  if (WM_RES_UNLIKELY(!mrb_array_p(v) || RARRAY_LEN(v) == 0)) {
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "content_types_provided must answer [[type, handler]] pairs");
  }
  const mrb_int count = RARRAY_LEN(v);
  // The app answered what it answered last time: the vector already holds
  // it, resolutions included, and nothing has to be rebuilt or searched
  // for. A pair that is not [String, Symbol] simply fails to match and
  // falls into the rebuild below, which names the refusal.
  std::vector<Resource::TypedHandler>& cur = r.res.run_content_types_provided;
  bool same = cur.size() == static_cast<size_t>(count);
  for (mrb_int j = 0; same && j < count; j++) {
    const mrb_value pair = RARRAY_PTR(v)[j];
    same = mrb_array_p(pair) && RARRAY_LEN(pair) >= 2 && mrb_string_p(RARRAY_PTR(pair)[0]) &&
           mrb_symbol_p(RARRAY_PTR(pair)[1]) &&
           mrb_symbol(RARRAY_PTR(pair)[1]) == cur[static_cast<size_t>(j)].handler &&
           cur[static_cast<size_t>(j)].type.size() ==
               static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0])) &&
           std::memcmp(cur[static_cast<size_t>(j)].type.data(),
                       RSTRING_PTR(RARRAY_PTR(pair)[0]),
                       cur[static_cast<size_t>(j)].type.size()) == 0;
  }
  if (same) return;
  cur.clear();
  for (mrb_int j = 0; j < count; j++) {
    const mrb_value pair = RARRAY_PTR(v)[j];
    if (WM_RES_UNLIKELY(!mrb_array_p(pair) || RARRAY_LEN(pair) < 2 ||
                        !mrb_string_p(RARRAY_PTR(pair)[0]) ||
                        !mrb_symbol_p(RARRAY_PTR(pair)[1]))) {
      mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided pairs are [String, Symbol]");
    }
    Resource::TypedHandler th;
    th.type.assign(RSTRING_PTR(RARRAY_PTR(pair)[0]),
                   static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0])));
    th.handler = mrb_symbol(RARRAY_PTR(pair)[1]);
    // Resolved HERE, once, not searched for at every render.
    const Resolved hr = resolve(mrb, r.res.klass, th.handler);
    th.m = hr.m;
    th.irep = hr.irep;
    th.native = hr.native;
    cur.push_back(std::move(th));
  }
}

int ensure_etag(Run& r) {
    if (r.res.etag_asked) return -1;
    r.res.etag_asked = true;
    // #202: the class form answered at setup - there is nothing to ask.
    if (r.res.konst_etag.asked) {
      if (r.res.konst_etag.present) {
        r.res.etag_value = r.res.konst_etag.text;
        r.res.etag_present = true;
      }
      return -1;
    }
    if (!r.res.cb_generate_etag.has) return -1;
    mrb_value v = cbv(r, r.res.cb_generate_etag);
    if (mrb_integer_p(v)) return halt_of(r, v, r.res.cb_generate_etag.sym);
    if (mrb_nil_p(v) || mrb_false_p(v)) return -1;
    if (!mrb_string_p(v)) v = mrb_obj_as_string(r.mrb, v);
    http::etag_spell(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)), r.res.etag_value);
    r.res.etag_present = true;
    return -1;
}

void epoch_memo(Run& r, const DateField& d) {
  mrb_state* mrb = r.mrb;
  const Resource::ValueCb& cb = d.cb;
  const Resource::KonstValue& konst = d.konst;
  if (*d.asked) return;
  *d.asked = true;
  // #202: same as ensure_etag - a class form is a setup answer.
  if (konst.asked) {
    if (konst.present) {
      *d.epoch = konst.epoch;
      *d.present = true;
    }
    return;
  }
  if (!cb.has) return;
  mrb_value v = cbv(r, cb);
  if (mrb_nil_p(v) || mrb_false_p(v)) return;
  if (!mrb_integer_p(v)) v = mrb_funcall_argv(mrb, v, MRB_SYM(to_i), 0, nullptr);
  if (WM_RES_UNLIKELY(!mrb_integer_p(v))) {
    mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer a Time or an epoch Integer",
               mrb_sym_name(mrb, cb.sym));
  }
  *d.epoch = static_cast<int64_t>(mrb_integer(v));
  *d.present = true;
}

int add_caching(Run& r) {
    // #202: a resource with none of the three answers has nothing to ask
    // for, and o18 asks on every GET. Three calls that could only answer
    // "no" are three calls that do not happen.
    if (!r.res.has_caching) return -1;
    const int h = ensure_etag(r);
    if (h >= 0) return h;
    if (r.res.etag_present) {
      field(r, "ETag", 4, r.res.etag_value.data(), r.res.etag_value.size());
    }
    epoch_memo(r, {r.res.cb_expires, r.res.konst_expires, &r.res.expires_asked,
                   &r.res.expires_present, &r.res.expires_epoch});
    if (r.res.expires_present) date_line(r, "Expires", 7, r.res.expires_epoch);
    epoch_memo(r, {r.res.cb_last_modified, r.res.konst_last_modified,
                   &r.res.last_modified_asked, &r.res.last_modified_present,
                   &r.res.last_modified_epoch});
    if (r.res.last_modified_present) date_line(r, "Last-Modified", 13, r.res.last_modified_epoch);
    return -1;
}

bool param_find(const char* s, size_t n, const char* key, size_t kn, const char** vout, size_t* vn) {
    size_t i = 0;
    while (i < n && s[i] != ';') i++;
    while (i < n) {
      i++;
      while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
      size_t ks = i;
      while (i < n && s[i] != '=' && s[i] != ';') i++;
      size_t ke = i;
      while (ke > ks && (s[ke - 1] == ' ' || s[ke - 1] == '\t')) ke--;
      const char* v = nullptr;
      size_t vlen = 0;
      if (i < n && s[i] == '=') {
        i++;
        size_t vs = i;
        while (i < n && s[i] != ';') i++;
        size_t vend = i;
        while (vend > vs && (s[vend - 1] == ' ' || s[vend - 1] == '\t')) vend--;
        v = s + vs;
        vlen = vend - vs;
      }
      if (ci_eq(s + ks, ke - ks, key, kn)) {
        *vout = v;
        *vn = vlen;
        return true;
      }
    }
    return false;
}

int accept_helper(Run& r) {
  mrb_state* mrb = r.mrb;
  const char* ct = "application/octet-stream";
  size_t ct_full = 24;
  if (r.vals != nullptr && r.vals->content_type != nullptr) {
    ct = r.vals->content_type;
    ct_full = r.vals->content_type_len;
  }
  size_t ctn = 0;
  while (ctn < ct_full && ct[ctn] != ';') ctn++;
  while (ctn > 0 && (ct[ctn - 1] == ' ' || ct[ctn - 1] == '\t')) ctn--;
  if (!r.res.cb_content_types_accepted.has) return 415;
  const mrb_value v = cbv(r, r.res.cb_content_types_accepted);
  if (WM_RES_UNLIKELY(!mrb_array_p(v))) {
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "content_types_accepted must answer [[type, Symbol]] pairs");
  }
  for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
    const mrb_value pair = RARRAY_PTR(v)[j];
    if (WM_RES_UNLIKELY(!mrb_array_p(pair) || RARRAY_LEN(pair) < 2 ||
                        !mrb_string_p(RARRAY_PTR(pair)[0]) ||
                        !mrb_symbol_p(RARRAY_PTR(pair)[1]))) {
      mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_accepted pairs are [String, Symbol]");
    }
    const char* pt = RSTRING_PTR(RARRAY_PTR(pair)[0]);
    const size_t pt_full = static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0]));
    size_t pn = 0;
    while (pn < pt_full && pt[pn] != ';') pn++;
    while (pn > 0 && (pt[pn - 1] == ' ' || pt[pn - 1] == '\t')) pn--;
    bool hit;
    if (pn == 3 && pt[0] == '*' && pt[1] == '/' && pt[2] == '*') {
      hit = true;
    } else if (pn >= 2 && pt[pn - 1] == '*' && pt[pn - 2] == '/') {
      size_t slash = 0;
      while (slash < ctn && ct[slash] != '/') slash++;
      hit = slash == pn - 2 && ci_eq(pt, pn - 2, ct, slash);
    } else {
      hit = ci_eq(pt, pn, ct, ctn);
    }
    if (hit && pn < pt_full) {
      size_t i = pn;
      while (i < pt_full && pt[i] != ';') i++;
      while (hit && i < pt_full) {
        i++;
        while (i < pt_full && (pt[i] == ' ' || pt[i] == '\t')) i++;
        size_t ks = i;
        while (i < pt_full && pt[i] != '=' && pt[i] != ';') i++;
        size_t ke = i;
        while (ke > ks && (pt[ke - 1] == ' ' || pt[ke - 1] == '\t')) ke--;
        const char* pv = nullptr;
        size_t pvn = 0;
        if (i < pt_full && pt[i] == '=') {
          i++;
          size_t vs = i;
          while (i < pt_full && pt[i] != ';') i++;
          size_t vend = i;
          while (vend > vs && (pt[vend - 1] == ' ' || pt[vend - 1] == '\t')) vend--;
          pv = pt + vs;
          pvn = vend - vs;
        }
        if (ke == ks) continue;
        const char* rv = nullptr;
        size_t rvn = 0;
        hit = param_find(ct, ct_full, pt + ks, ke - ks, &rv, &rvn) &&
              rvn == pvn && (pvn == 0 || std::memcmp(rv, pv, pvn) == 0);
      }
    }
    if (!hit) continue;
    const mrb_sym hs = mrb_symbol(RARRAY_PTR(pair)[1]);
    const mrb_value answer = mrb_funcall_argv(mrb, r.res.live, hs, 0, nullptr);
    if (mrb_integer_p(answer)) return halt_of(r, answer, hs);
    return -1;
  }
  return 415;
}

int run_n11(Run& r) {
  mrb_state* mrb = r.mrb;
  mrb_value pic = mrb_false_value();
  if (r.res.cb_post_is_create.has) pic = cbv(r, r.res.cb_post_is_create);
  if (mrb_test(pic)) {
    if (WM_RES_UNLIKELY(!r.res.cb_create_path.has)) {
      mrb_raise(mrb, E_WM_ERROR(mrb), "post_is_create? is true but create_path answered nil");
    }
    const mrb_value cp = cbv(r, r.res.cb_create_path);
    if (mrb_integer_p(cp)) return halt_of(r, cp, r.res.cb_create_path.sym);
    if (WM_RES_UNLIKELY(mrb_nil_p(cp))) {
      mrb_raise(mrb, E_WM_ERROR(mrb), "post_is_create? is true but create_path answered nil");
    }
    if (WM_RES_UNLIKELY(!mrb_string_p(cp))) {
      mrb_raise(mrb, E_TYPE_ERROR, "create_path must answer a String path");
    }
    mrb_value base = mrb_nil_value();
    if (r.res.cb_base_uri.has) base = cbv(r, r.res.cb_base_uri);
    {
      std::string b;
      if (mrb_string_p(base)) {
        b.assign(RSTRING_PTR(base), static_cast<size_t>(RSTRING_LEN(base)));
      } else {
        b.assign("http://");
        if (r.vals != nullptr && r.vals->host != nullptr) {
          b.append(r.vals->host, r.vals->host_len);
        } else {
          b.append("localhost");
        }
        b.push_back('/');
      }
      std::string uri;
      http::uri_join({b, {RSTRING_PTR(cp), static_cast<size_t>(RSTRING_LEN(cp))}}, uri);
      size_t at = 0;
      if (uri.size() >= 8 && uri.compare(0, 4, "http") == 0) {
        const size_t ss = uri.find("://");
        if (ss != std::string::npos) {
          const size_t sl = uri.find('/', ss + 3);
          at = sl == std::string::npos ? uri.size() : sl;
        }
      }
      const size_t plen = http::path_only(uri.data() + at, uri.size() - at);
      r.res.run_disp_path.assign(uri.data() + at, plen);
      r.res.run_disp_set = true;
      request_disp_override(uri.data() + at, plen);
      field(r, "Location", 8, uri.data(), uri.size());
    }
    const int h = accept_helper(r);
    if (h >= 0) return h;
  } else {
    if (WM_RES_UNLIKELY(!r.res.cb_process_post.has)) {
      mrb_raise(mrb, E_WM_ERROR(mrb), "process_post answered false, which is invalid");
    }
    const mrb_value pp = cbv(r, r.res.cb_process_post);
    if (mrb_integer_p(pp)) return halt_of(r, pp, r.res.cb_process_post.sym);
    if (WM_RES_UNLIKELY(!mrb_true_p(pp))) {
      mrb_raise(mrb, E_WM_ERROR(mrb), "process_post must answer true or a response code");
    }
  }
  if (r.res.run_redirect) {
    if (headers_has_location(r.hdrs)) return 303;
    mrb_raise(mrb, E_WM_ERROR(mrb), "do_redirect requires a Location header");
  }
  return -1;
}

mrb_value run_engine(mrb_state* mrb, const Resource& res);

// mruby: the ONE guarded entry per request. Without a jmpbuf on the
// state a raise reaches mrb_exc_raise with mrb->jmp NULL, which prints
// and calls abort() - so the frame is not optional. mrb_protect_error
// buys it for a C function pointer, with no method lookup and no
// object to construct.
mrb_value run_engine_body(mrb_state* mrb, void* ud) {
  return run_engine(mrb, *static_cast<const Resource*>(ud));
}

mrb_value run_engine(mrb_state* mrb, const Resource& res) {
  // #181: the resource instance belongs to ONE request. Allocate it and
  // nothing else - mrb_obj_new would search for initialize twice per
  // request (mrb_func_basic_p, then mrb_funcall_argv) to arrive where the
  // fold already stands. The call itself, when one is owed, is below,
  // where the direct-entry path exists.
  res.live = mrb_obj_value(mrb_obj_alloc(mrb, res.live_tt, res.klass));
  Run r{mrb,
        res,
        *res.run_facts,
        res.konst.per_method[static_cast<size_t>(res.run_facts->method)],
        res.run_vals,
        *res.run_headers,
        Node::kB13,
        0,
        false,
        0,
        res.cb_content_types_provided.has};
  const flow::ReqFacts& facts = r.facts;
  const flow::KonstAnswers& k = r.k;
  const http::ReqValues* vals = r.vals;
  std::string& hdrs = r.hdrs;


  // #181: the app's own initialize, entered through the resolved method
  // rather than looked up again. init_needed is false for every resource
  // that did not override Object's - the implicit one is not a reason to
  // run anything.
  if (WM_RES_UNLIKELY(res.init_needed)) {
    naked(r, {res.init_m, res.init_irep, nullptr, MRB_SYM(initialize)});
  }

  // cb.rb: the same direct entry as naked, for a `def self.x` - the
  // receiver is the class and the frame's class is the class's own, which
  // is where the fold found the method.

  // cb.rb: a value callback - on_class says which receiver, and the method
  // itself came from the fold either way. It used to be searched again per
  // request whenever it lived on the class.

  // flow.rb: one node's callback out of the node tables, either receiver.

  // flow.rb decision_test: ANY callback may halt with an Integer status.

  // RFC 9110: what ONE node's callback is handed. webmachine-ruby's
  // signatures decide this, and a method that declared the parameter must
  // not be called with nothing; one that declared none gets nothing.

  // RFC 9110 9.1: this request's method, by name.

  // RFC 9110 9.1: one method-list answer (Array or token String), marshalled
  // once into run_methods.

  // flow.rb b10/b12: include?(request.method) over the marshalled list.

  // RFC 9112 5: field-line = field-name ":" OWS field-value OWS CRLF. A
  // node decides WHICH field it produces; this is the only place that
  // knows how one is spelled. Every node below used to spell its own,
  // which is why "Allow: " and "ETag: " carried the colon inside the
  // literal and every site ended with its own append("\r\n", 2).

  // RFC 9110 5.6.1: a field whose value is a #rule - a comma-separated
  // list. The members go in one at a time, so a list never needs a string
  // built to hold it: `head` is the member that is not in `tail`, empty
  // when there is none.

  // RFC 9110 10.2.1: the Allow value, from the dynamic list or the konst join.

  // cb.rb content_types_provided: the dynamic answer, marshalled once.
  // RFC 9110 12.5.1: the list conneg runs against - dynamic or konst-folded.

  // cb.rb generate_etag: asked at most once per run; g11, k13 and the
  // caching headers all read the same memo.

  // cb.rb last_modified/expires: asked at most once - a Time answers via
  // to_i, an Integer is the epoch, nil is not present.

  // RFC 9110 5.6.7: one dated field, IMF-fixdate.

  // helpers.rb add_caching_headers: ETag, Expires, Last-Modified.

  // helpers.rb accept_helper: the request's Content-Type against
  // content_types_accepted - exact, type/* or */* - then yield the handler.
  // MediaType#match?: every parameter the accepted type carries must be
  // present with an equal value in the request's Content-Type.

  // flow.rb n11: post_is_create?/create_path/base_uri or process_post; the
  // 303 answer needs a Location the run already set.

  Node n = Node::kB13;
  uint16_t status = 0;
  bool halted = false;
  int& chosen = r.chosen;
  while (!halted) {
    switch (n) {
      case Node::kB12: {
        if (!res.cb_known_methods.has) break;
        marshal_methods(r, res.cb_known_methods);
        take_edge(n, status, halted, methods_contain(r));
        continue;
      }
      case Node::kB10: {
        if (!res.cb_allowed_methods.has) break;
        marshal_methods(r, res.cb_allowed_methods);
        const bool ok = methods_contain(r);
        if (!ok) allow_line(r);
        take_edge(n, status, halted, ok);
        continue;
      }
      case Node::kB8: {
        if (((res.dynamic >> static_cast<size_t>(Node::kB8)) & 1) == 0) break;
        const size_t i = static_cast<size_t>(Node::kB8);
        mrb_value a = mrb_nil_value();
        if (res.node_argc[i] != 0) a = arg_for(r, n);
        const mrb_value v = nodecall(r, n, {&a, static_cast<size_t>(res.node_argc[i])});
        if (mrb_true_p(v)) {
          take_edge(n, status, halted, true);
          continue;
        }
        if (mrb_integer_p(v)) {
          status = halt_of(r, v, res.node_sym[i]);
          halted = true;
          continue;
        }
        if (mrb_string_p(v)) {
          field(r, "WWW-Authenticate", 16, RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
        }
        status = 401;
        halted = true;
        continue;
      }
      case Node::kB3: {
        if (facts.method != flow::Method::kOptions) {
          n = Node::kC3;
          continue;
        }
        if (res.cb_options.has) {
          const mrb_value v = cbv(r, res.cb_options);
          if (WM_RES_UNLIKELY(!mrb_hash_p(v))) {
            mrb_raise(mrb, E_TYPE_ERROR, "options must answer a Hash of header fields");
          }
          const mrb_value keys = mrb_hash_keys(mrb, v);
          for (mrb_int j = 0; j < RARRAY_LEN(keys); j++) {
            const mrb_value key = RARRAY_PTR(keys)[j];
            const mrb_value val = mrb_hash_get(mrb, v, key);
            if (!mrb_string_p(key) || !mrb_string_p(val)) continue;
            field(r, RSTRING_PTR(key), static_cast<size_t>(RSTRING_LEN(key)), RSTRING_PTR(val),
                  static_cast<size_t>(RSTRING_LEN(val)));
          }
        } else {
          allow_line(r);
        }
        status = 200;
        halted = true;
        continue;
      }
      case Node::kC3: {
        marshal_ct(r);
        if (WM_RES_UNLIKELY(active_ct(r).empty())) {
          mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided answered no pairs");
        }
        if (!facts.has_accept) {
          chosen = 0;
          if (r.ct_dyn) {
            res.run_content_type = active_ct(r)[0].type;
          }
          n = after_accept(facts);
          continue;
        }
        n = Node::kC4;
        continue;
      }
      case Node::kC4: {
        const std::vector<Resource::TypedHandler>& cts = active_ct(r);
        int idx = -1;
        {
          std::vector<std::string> names;
          names.reserve(cts.size());
          for (const Resource::TypedHandler& th : cts) names.push_back(th.type);
          idx = http::choose_media_type(names.data(), names.size(),
                                        vals != nullptr ? vals->accept : nullptr,
                                        vals != nullptr ? vals->accept_len : 0);
        }
        if (idx < 0) {
          status = 406;
          halted = true;
          continue;
        }
        chosen = idx;
        if (idx != 0 || r.ct_dyn) {
          res.run_content_type = cts[static_cast<size_t>(idx)].type;
        }
        n = after_accept(facts);
        continue;
      }
      case Node::kG7: {
        if (res.cb_variances.has) {
          const mrb_value v = cbv(r, res.cb_variances);
          if (WM_RES_UNLIKELY(!mrb_array_p(v))) {
            mrb_raise(mrb, E_TYPE_ERROR, "variances must answer an Array of Strings");
          }
          res.run_variances.clear();
          for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
            const mrb_value s = RARRAY_PTR(v)[j];
            if (mrb_string_p(s)) {
              res.run_variances.emplace_back(RSTRING_PTR(s),
                                             static_cast<size_t>(RSTRING_LEN(s)));
            }
          }
        }
        const bool accept_varies = active_ct(r).size() > 1;
        if (accept_varies || !res.run_variances.empty()) {
          field_list(r, {"Vary", accept_varies ? "Accept" : std::string_view(),
                         res.run_variances});
        }
        break;
      }
      case Node::kG11: {
        const int h = ensure_etag(r);
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
          continue;
        }
        take_edge(n, status, halted, res.etag_present && vals != nullptr && vals->if_match != nullptr &&
             http::etag_list_match(vals->if_match, vals->if_match_len, res.etag_value.data(),
                                   res.etag_value.size(), false));
        continue;
      }
      case Node::kK13: {
        const int h = ensure_etag(r);
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
          continue;
        }
        take_edge(n, status, halted, res.etag_present && vals != nullptr && vals->if_none_match != nullptr &&
             http::etag_list_match(vals->if_none_match, vals->if_none_match_len,
                                   res.etag_value.data(), res.etag_value.size(), true));
        continue;
      }
      case Node::kH12: {
        epoch_memo(r, {res.cb_last_modified, res.konst_last_modified, &res.last_modified_asked,
                       &res.last_modified_present, &res.last_modified_epoch});
        take_edge(n, status, halted, res.last_modified_present && vals != nullptr &&
             res.last_modified_epoch > vals->if_unmodified_since_epoch);
        continue;
      }
      case Node::kL17: {
        epoch_memo(r, {res.cb_last_modified, res.konst_last_modified, &res.last_modified_asked,
                       &res.last_modified_present, &res.last_modified_epoch});
        take_edge(n, status, halted, !res.last_modified_present || vals == nullptr ||
             res.last_modified_epoch > vals->if_modified_since_epoch);
        continue;
      }
      case Node::kI4:
      case Node::kK5:
      case Node::kL5: {
        const Resource::ValueCb& cb =
            n == Node::kL5 ? res.cb_moved_temporarily : res.cb_moved_permanently;
        if (!cb.has) break;
        const mrb_value v = cbv(r, cb);
        if (mrb_string_p(v)) {
          field(r, "Location", 8, RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
          status = n == Node::kL5 ? 307 : 301;
          halted = true;
          continue;
        }
        if (mrb_integer_p(v)) {
          status = halt_of(r, v, cb.sym);
          halted = true;
          continue;
        }
        take_edge(n, status, halted, false);
        continue;
      }
      case Node::kN11: {
        const int h = run_n11(r);
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
        } else {
          n = Node::kP11;
        }
        continue;
      }
      case Node::kO14:
      case Node::kP3: {
        const size_t i = static_cast<size_t>(n);
        bool conflict;
        if ((res.dynamic >> i) & 1) {
          const mrb_value v = nodecall(r, n, {});
          if (mrb_integer_p(v)) {
            status = halt_of(r, v, res.node_sym[i]);
            halted = true;
            continue;
          }
          conflict = mrb_test(v);
        } else {
          conflict = k.ans[i];
        }
        if (conflict) {
          status = 409;
          halted = true;
          continue;
        }
        const int h = accept_helper(r);
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
        } else {
          n = Node::kP11;
        }
        continue;
      }
      case Node::kO18: {
        if (facts.method == flow::Method::kGet || facts.method == flow::Method::kHead) {
          const int h = add_caching(r);
          if (h >= 0) {
            status = static_cast<uint16_t>(h);
            halted = true;
            continue;
          }
          const std::vector<Resource::TypedHandler>& cts = active_ct(r);
          const size_t idx =
              static_cast<size_t>(chosen) < cts.size() ? static_cast<size_t>(chosen) : 0;
          const Resource::TypedHandler& th = cts[idx];
          const bool prebuilt = !r.ct_dyn && idx == 0 && !res.dynamic_body;
          if (prebuilt) {
            // The writers own this case: the first pair's body sits in the
            // bundle's prebuilt 200, head and all, and nothing here improves
            // on it.
          } else if (th.has_baked) {
            // A negotiated pair whose handler is a `def self.` - the answer
            // was rendered at setup, and o18 is only where it is handed over.
            res.run_body->assign(th.baked);
            res.run_have_body = true;
          } else {
            mrb_value v;
            if (!MRB_METHOD_UNDEF_P(th.m)) {
              v = naked(r, {th.m, th.irep, th.native, th.handler});
            } else if (r.ct_dyn) {
              v = mrb_funcall_argv(mrb, res.live, th.handler, 0, nullptr);
            } else {
              v = mrb_funcall_argv(mrb, mrb_obj_value(res.klass), th.handler, 0, nullptr);
            }
            if (mrb_integer_p(v)) {
              status = halt_of(r, v, th.handler);
              halted = true;
              continue;
            }
            if (WM_RES_UNLIKELY(!mrb_string_p(v))) {
              mrb_raise(mrb, E_TYPE_ERROR, "the body handler must return a String");
            }
            // response.file= and response.error_asset already named the
            // answer - this String (the handler's own '' by convention) is
            // dead on arrival, so neither the freeze+register interlock nor
            // the copy is worth taking. The caller reads run_have_file and
            // run_asset first and never looks at run_body/run_have_body for
            // this run.
            if (!res.run_have_file && res.run_asset == nullptr) {
              const size_t blen = static_cast<size_t>(RSTRING_LEN(v));
              // Already frozen means the app kept this String, so a second
              // connection may be holding it too - and the release would
              // lift a freeze that was not ours. Our own freeze is
              // therefore also the interlock: one lend per String at a
              // time, everything else copies.
              if (res.run_zc_min != 0 && blen >= res.run_zc_min &&
                  !mrb_frozen_p(mrb_basic_ptr(v))) {
                // Frozen so mrb_str_modify cannot realloc the bytes out
                // from under a send in flight, rooted so the GC cannot
                // take them; the writer hands RSTRING_PTR straight to the
                // kernel.
                mrb_obj_freeze(mrb, v);
                mrb_gc_register(mrb, v);
                res.run_zc = v;
                res.run_zc_have = true;
                res.run_body->clear();
              } else {
                res.run_body->assign(RSTRING_PTR(v), blen);
              }
              res.run_have_body = true;
            }
          }
        }
        n = Node::kO18b;
        continue;
      }
      case Node::kG8: {
        // RFC 9110 13: g9/g11, h11/h12, i13/k13/j18 and l14/l15/l17 all hang
        // off their own has_*, so a request naming none of the four
        // conditional fields walks g8 -> h10 -> i12 -> l13 -> m16.
        if (!facts.names_a_conditional_field()) {
          n = Node::kM16;
          continue;
        }
        break;
      }
      case Node::kO20: {
        take_edge(n, status, halted, res.run_have_body);
        continue;
      }
      case Node::kP11: {
        take_edge(n, status, halted, headers_has_location(hdrs));
        continue;
      }
      default:
        break;
    }

    const flow::FlowNode& f = flow::kFlow[static_cast<size_t>(n)];
    bool ans;
    if (f.kind == flow::Kind::kRequest) {
      ans = flow::eval_request(n, facts);
    } else if ((res.dynamic >> static_cast<size_t>(n)) & 1) {
      const size_t i = static_cast<size_t>(n);
      mrb_value a = mrb_nil_value();
      if (res.node_argc[i] != 0) a = arg_for(r, n);
      const mrb_value v = nodecall(r, n, {&a, static_cast<size_t>(res.node_argc[i])});
      // ANY callback may answer with an Integer, and then that integer
      // IS the response status - webmachine-ruby's own convention.
      if (WM_RES_UNLIKELY(mrb_integer_p(v))) {
        status = halt_of(r, v, res.node_sym[i]);
        halted = true;
        continue;
      }
      ans = mrb_test(v);
    } else {
      ans = k.ans[static_cast<size_t>(n)];
    }
    take_edge(n, status, halted, f, ans);
  }

  // fsm.rb respond: a 304 sheds Content-Type at the writer and carries the
  // caching headers; finish_request runs LAST and may rename the status
  // through response.code=.
  if (status == 304) {
    const int h = add_caching(r);
    if (h >= 0) status = static_cast<uint16_t>(h);
  }
  res.run_resp_code = status;
  res.run_status = status;
  if (res.cb_finish_request.has) cbv(r, res.cb_finish_request);
  res.run_status = res.run_resp_code;
  return mrb_nil_value();
}
}

// RFC 9110: fold one resource class - every konst callback asked once,
// every dynamic callback resolved, the class frozen.
bool resource_fold(mrb_state* mrb, mrb_value klass, Resource& out, char* err, size_t errlen) {
  const Folding fold = {mrb, klass, err, errlen};
  const int ai = mrb_gc_arena_save(mrb);
  out = Resource{};
  out.mrb = mrb;

  for (const NamedSym& cb : kUnhonored) {
    if (WM_RES_UNLIKELY(resolve(mrb, mrb_class(mrb, klass), cb.sym).defined ||
                        instance_defined(mrb, klass, cb.sym))) {
      std::snprintf(err, errlen,
                    "%s is defined but i18n/charset conversion does not exist in this tree",
                    cb.name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }
  for (const NamedSym& cb : kKonstOnly) {
    if (WM_RES_UNLIKELY(instance_defined(mrb, klass, cb.sym))) {
      std::snprintf(err, errlen, "%s shapes the compiled vectors - declare it konst (def self.%s)",
                    cb.name, cb.name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }
  for (const NamedSym& cb : kWorkOnly) {
    if (WM_RES_UNLIKELY(resolve(mrb, mrb_class(mrb, klass), cb.sym).defined)) {
      std::snprintf(err, errlen,
                    "%s does work, so it runs per request - declare it on the instance (def %s), "
                    "not on the class: def self.%s would be asked once at setup and never again",
                    cb.name, cb.name, cb.name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  bool ans[sizeof(kBools) / sizeof(kBools[0])];
  for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
    const BoolCb& cb = kBools[i];
    ans[i] = cb.defv;
    const Resolved inst = resolve(mrb, mrb_class_ptr(klass), cb.sym);
    if (inst.defined) {
      const size_t at = static_cast<size_t>(cb.node);
      out.dynamic |= uint64_t{1} << at;
      out.node_sym[at] = cb.sym;
      out.node_m[at] = inst.m;
      out.node_irep[at] = inst.irep;
      out.node_native[at] = inst.native;
      out.node_argc[at] = argc_of(inst.m, cb.maxargs);
      continue;
    }
    if (WM_RES_UNLIKELY(!ask(fold, {cb.sym, cb.name}, cb.defv, &ans[i]))) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // flow.rb b8: a value-semantics node - instance method into the node
  // tables, a class-only one as an undef slot the engine funcalls on the class.
  for (const NodeValueCb& cb : kNodeValues) {
    const size_t at = static_cast<size_t>(cb.node);
    const Resolved inst = resolve(mrb, mrb_class_ptr(klass), cb.sym);
    if (inst.defined) {
      out.dynamic |= uint64_t{1} << at;
      out.node_sym[at] = cb.sym;
      out.node_m[at] = inst.m;
      out.node_irep[at] = inst.irep;
      out.node_native[at] = inst.native;
      out.node_argc[at] = argc_of(inst.m, cb.maxargs);
      continue;
    }
    const Resolved meta = resolve(mrb, mrb_class(mrb, klass), cb.sym);
    if (meta.defined) {
      out.dynamic |= uint64_t{1} << at;
      out.node_sym[at] = cb.sym;
      out.node_m[at] = meta.m;
      out.node_irep[at] = meta.irep;
      out.node_on_class |= uint64_t{1} << at;
      out.node_argc[at] = argc_of(meta.m, cb.maxargs);
    }
  }

  // cb.rb: the value callbacks; known/allowed/content_types_provided keep their konst
  // twin on the class, everything else may live on either side.
  out.cb_known_methods = value_cb(mrb, klass, {MRB_SYM(known_methods), false});
  out.cb_allowed_methods = value_cb(mrb, klass, {MRB_SYM(allowed_methods), false});
  out.cb_content_types_provided = value_cb(mrb, klass, {MRB_SYM(content_types_provided), false});
  out.cb_content_types_accepted = value_cb(mrb, klass, {MRB_SYM(content_types_accepted), true});
  out.cb_options = value_cb(mrb, klass, {MRB_SYM(options), true});
  out.cb_variances = value_cb(mrb, klass, {MRB_SYM(variances), true});
  out.cb_generate_etag = value_cb(mrb, klass, {MRB_SYM(generate_etag), true});
  out.cb_last_modified = value_cb(mrb, klass, {MRB_SYM(last_modified), true});
  out.cb_expires = value_cb(mrb, klass, {MRB_SYM(expires), true});
  // #202: the class forms of the three caching answers are asked once, now.
  if (WM_RES_UNLIKELY(
          !bake_value(fold, {out.cb_generate_etag, "generate_etag", true, out.konst_etag}) ||
          !bake_value(fold, {out.cb_last_modified, "last_modified", false,
                             out.konst_last_modified}) ||
          !bake_value(fold, {out.cb_expires, "expires", false, out.konst_expires}))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  // A konst that was asked and answered nothing is an answer: the
  // callback behind it is not asked again. So there is something to say
  // only where a konst holds a value, or where no konst was taken and a
  // callback is still there to ask.
  out.has_caching =
      out.konst_etag.present || (!out.konst_etag.asked && out.cb_generate_etag.has) ||
      out.konst_last_modified.present ||
      (!out.konst_last_modified.asked && out.cb_last_modified.has) ||
      out.konst_expires.present || (!out.konst_expires.asked && out.cb_expires.has);
  out.cb_moved_permanently = value_cb(mrb, klass, {MRB_SYM_Q(moved_permanently), true});
  out.cb_moved_temporarily = value_cb(mrb, klass, {MRB_SYM_Q(moved_temporarily), true});
  out.cb_post_is_create = value_cb(mrb, klass, {MRB_SYM_Q(post_is_create), true});
  out.cb_create_path = value_cb(mrb, klass, {MRB_SYM(create_path), false});
  out.cb_base_uri = value_cb(mrb, klass, {MRB_SYM(base_uri), true});
  out.cb_process_post = value_cb(mrb, klass, {MRB_SYM(process_post), false});
  out.cb_finish_request = value_cb(mrb, klass, {MRB_SYM(finish_request), false});
  // The fast part: one bit per ValueCb above, set once here so every run
  // asks "does X exist" with one load instead of touching X's own struct.
  out.cb_mask = 0;
  if (out.cb_known_methods.has) out.cb_mask |= Resource::kCbKnownMethods;
  if (out.cb_allowed_methods.has) out.cb_mask |= Resource::kCbAllowedMethods;
  if (out.cb_content_types_provided.has) out.cb_mask |= Resource::kCbContentTypesProvided;
  if (out.cb_content_types_accepted.has) out.cb_mask |= Resource::kCbContentTypesAccepted;
  if (out.cb_options.has) out.cb_mask |= Resource::kCbOptions;
  if (out.cb_variances.has) out.cb_mask |= Resource::kCbVariances;
  if (out.cb_generate_etag.has) out.cb_mask |= Resource::kCbGenerateEtag;
  if (out.cb_last_modified.has) out.cb_mask |= Resource::kCbLastModified;
  if (out.cb_expires.has) out.cb_mask |= Resource::kCbExpires;
  if (out.cb_moved_permanently.has) out.cb_mask |= Resource::kCbMovedPermanently;
  if (out.cb_moved_temporarily.has) out.cb_mask |= Resource::kCbMovedTemporarily;
  if (out.cb_post_is_create.has) out.cb_mask |= Resource::kCbPostIsCreate;
  if (out.cb_create_path.has) out.cb_mask |= Resource::kCbCreatePath;
  if (out.cb_base_uri.has) out.cb_mask |= Resource::kCbBaseUri;
  if (out.cb_process_post.has) out.cb_mask |= Resource::kCbProcessPost;
  if (out.cb_finish_request.has) out.cb_mask |= Resource::kCbFinishRequest;
  // kC3 is a request-kind node: its dynamic bit forces the run tier without
  // touching any konst answer.
  if (out.cb_mask != 0) out.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);

  std::string content_type = "text/html";
  {
    const Resolved ct = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_type));
    if (ct.defined) {
      const mrb_value v = call_resolved(mrb, ct, {klass, mrb_class(mrb, klass)});
      if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(v))) {
        mrb->exc == nullptr
            ? static_cast<void>(std::snprintf(err, errlen, "content_type must return a String"))
            : exc_into(mrb, "content_type", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      content_type.assign(RSTRING_PTR(v), RSTRING_LEN(v));
      // RFC 9110 8.3 / 12.5.1: a resource that names no media type cannot
      // be negotiated with, and c4 would have nothing to weigh an Accept
      // against. Said here, once, instead of guarded on every request.
      if (WM_RES_UNLIKELY(content_type.empty())) {
        std::snprintf(err, errlen, "content_type must name a media type, not an empty String");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
    }
  }

  // cb.rb content_types_provided: the konst pairs; a class-level answer
  // wins, otherwise [[content_type-or-text/html, :to_html]].
  {
    const Resolved ctp = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_provided));
    if (ctp.defined) {
      const mrb_value v = call_resolved(mrb, ctp, {klass, mrb_class(mrb, klass)});
      if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
        exc_into(mrb, "content_types_provided", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      if (WM_RES_UNLIKELY(!mrb_array_p(v) || RARRAY_LEN(v) == 0)) {
        std::snprintf(err, errlen,
                      "content_types_provided must return [[type, handler]] pairs");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
        const mrb_value pair = RARRAY_PTR(v)[j];
        if (WM_RES_UNLIKELY(!mrb_array_p(pair) || RARRAY_LEN(pair) < 2 ||
                            !mrb_string_p(RARRAY_PTR(pair)[0]) ||
                            !mrb_symbol_p(RARRAY_PTR(pair)[1]))) {
          std::snprintf(err, errlen, "content_types_provided pairs are [String, Symbol]");
          mrb_gc_arena_restore(mrb, ai);
          return false;
        }
        Resource::TypedHandler th;
        th.type.assign(RSTRING_PTR(RARRAY_PTR(pair)[0]),
                       static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0])));
        th.handler = mrb_symbol(RARRAY_PTR(pair)[1]);
        const Resolved hr = resolve(mrb, mrb_class_ptr(klass), th.handler);
        if (hr.defined) {
          th.m = hr.m;
          th.irep = hr.irep;
          th.native = hr.native;
        }
        // cb.rb: the class form is answered once, here - for EVERY pair, not
        // just the first. Asked per request it would be looked up on the
        // instance, where the name may belong to somebody else entirely.
        const Resolved hk = resolve(mrb, mrb_class(mrb, klass), th.handler);
        if (hk.defined) {
          const mrb_value rendered = call_resolved(mrb, hk, {klass, mrb_class(mrb, klass)});
          if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(rendered))) {
            mrb->exc == nullptr
                ? static_cast<void>(std::snprintf(err, errlen,
                                                  "the body handler must return a String"))
                : exc_into(mrb, "body handler raised", err, errlen);
            mrb_gc_arena_restore(mrb, ai);
            return false;
          }
          th.baked.assign(RSTRING_PTR(rendered), static_cast<size_t>(RSTRING_LEN(rendered)));
          th.has_baked = true;
        }
        out.content_types_provided.push_back(std::move(th));
      }
    } else {
      Resource::TypedHandler th;
      th.type = content_type;
      th.handler = MRB_SYM(to_html);
      const Resolved hr = resolve(mrb, mrb_class_ptr(klass), MRB_SYM(to_html));
      if (hr.defined) {
        th.m = hr.m;
        th.irep = hr.irep;
        th.native = hr.native;
      }
      out.content_types_provided.push_back(std::move(th));
    }
  }

  {
    const Resolved enc = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(encodings_provided));
    if (enc.defined) {
      const mrb_value v = call_resolved(mrb, enc, {klass, mrb_class(mrb, klass)});
      if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_hash_p(v))) {
        mrb->exc == nullptr
            ? static_cast<void>(
                  std::snprintf(err, errlen, "encodings_provided must return a Hash"))
            : exc_into(mrb, "encodings_provided", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      out.gzip_offered = mrb_hash_key_p(mrb, v, mrb_str_new_lit(mrb, "gzip"));
    }
  }

  // helpers.rb encode_body: the default body path - content_types_provided[0]'s handler
  // pre-renders when it lives on the class, runs per request when it is an
  // instance method.
  {
    const Resource::TypedHandler& first = out.content_types_provided[0];
    const Resolved body_k = resolve(mrb, mrb_class(mrb, klass), first.handler);
    if (body_k.defined) {
      const mrb_value rendered =
          call_resolved(mrb, body_k, {klass, mrb_class(mrb, klass)});
      if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(rendered))) {
        mrb->exc == nullptr
            ? static_cast<void>(std::snprintf(err, errlen, "the body handler must return a String"))
            : exc_into(mrb, "body handler raised", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      out.konst.body.assign(RSTRING_PTR(rendered), RSTRING_LEN(rendered));
    } else if (!MRB_METHOD_UNDEF_P(first.m)) {
      out.dynamic_body = true;
    }
  }
  out.konst.content_type = out.content_types_provided[0].type;
  // RFC 9110 12.5.1: the fold bakes ONE body, from content_types_provided[0].
  // A resource offering a second type can be asked for it, and the answer to
  // that is a body the fold never rendered - so it runs.
  if (out.content_types_provided.size() > 1) {
    out.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
  }

  bool known[7] = {true, true, true, true, true, true, false};
  if (!out.cb_known_methods.has &&
      WM_RES_UNLIKELY(!ask_methods(fold, {MRB_SYM(known_methods), "known_methods"}, known))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  bool allowed[7] = {true, true, false, false, false, false, false};
  if (!out.cb_allowed_methods.has &&
      WM_RES_UNLIKELY(
          !ask_methods(fold, {MRB_SYM(allowed_methods), "allowed_methods"}, allowed))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  // RFC 9110 9.3.3 / 9.3.4: n11 and o14/p3 are action nodes, and every action
  // they could take is a callback - process_post, post_is_create?,
  // content_types_accepted. A resource that allows POST or PUT with not one
  // callback defined has only the engine's answer (500 at n11, 415 at p3),
  // and the fold cannot bake an action it will not perform.
  if (out.cb_mask == 0 &&
      (allowed[static_cast<size_t>(flow::Method::kPost)] ||
       allowed[static_cast<size_t>(flow::Method::kPut)])) {
    out.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
  }

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
  out.konst.resolve_shortcuts();

  out.klass = mrb_class_ptr(klass);
  out.meta_klass = mrb_class(mrb, klass);
  mrb_obj_freeze(mrb, klass);

  // What building the per-request instance costs, decided once: the
  // allocation's type, and whether the author wrote an initialize at all.
  // Object's is undef'd on Webmachine::Resource (see gem_init), so this is
  // a plain "is it defined" and no longer a comparison against a method
  // every object has.
  out.live_tt = MRB_INSTANCE_TT(out.klass) != 0 ? MRB_INSTANCE_TT(out.klass) : MRB_TT_OBJECT;
  const Resolved init = resolve(mrb, out.klass, MRB_SYM(initialize));
  out.init_needed = init.defined;
  out.init_m = init.m;
  out.init_irep = init.irep;
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

// RFC 9110: decision + render for one request inside one bound frame; the
// respond order is fsm.rb's - halt seeds the code, finish_request may rename
// it, and a raise leaves the exception pending for the error resource.
uint16_t resource_run(const Resource& res, const BoundRequest& asked,
                      const RunAnswer& answer) {
  mrb_state* mrb = res.mrb;
  request_bind(asked.req);
  response_bind(&res);
  res.run_facts = &asked.facts;
  res.run_vals = asked.vals;
  res.run_req = asked.req;
  res.run_headers = answer.headers;
  answer.headers->clear();
  res.run_body = answer.body;
  res.run_have_body = false;
  res.run_asset = nullptr;
  res.run_zc_min = asked.zc_min;
  res.run_zc_have = false;
  res.run_status = 0;
  res.run_resp_code = 0;
  res.run_redirect = false;
  res.run_content_type.clear();
  res.run_disp_path.clear();
  res.run_disp_set = false;
  res.run_have_file = false;
  res.run_file_bad = false;
  res.etag_asked = false;
  res.etag_present = false;
  res.etag_value.clear();
  res.last_modified_asked = false;
  res.last_modified_present = false;
  res.last_modified_epoch = 0;
  res.expires_asked = false;
  res.expires_present = false;
  res.expires_epoch = 0;
  res.run_content_types_marshalled = false;
  res.run_methods.clear();
  res.run_variances.clear();
  mrb_bool raised = FALSE;
  const mrb_value thrown =
      mrb_protect_error(mrb, run_engine_body, const_cast<Resource*>(&res), &raised);
  uint16_t status = res.run_resp_code;
  // A raise voids whatever the run lent: the rescue path spells its own
  // body, and a root nobody comes back for outlives the process.
  if (WM_RES_UNLIKELY(res.run_zc_have && raised != FALSE)) {
    resource_body_unlend(mrb, res.run_zc);
    res.run_zc_have = false;
  }
  if (WM_RES_UNLIKELY(raised != FALSE)) {
    // fsm.rb: finish_request still runs on the raise path, and it may
    // raise again, so it gets its own guarded frame - the rare path pays
    // for a second one.
    RescueCtx rc = {&res, thrown};
    mrb_bool again = FALSE;
    const mrb_value second = mrb_protect_error(mrb, run_rescue_body, &rc, &again);
    // The writer's contract (resource_exception_take): the exception is
    // still pending when this returns, because the error resource is what
    // turns it into words.
    if (again != FALSE) {
      if (mrb_exception_p(second)) mrb->exc = mrb_obj_ptr(second);
    } else if (mrb_exception_p(thrown)) {
      mrb->exc = mrb_obj_ptr(thrown);
    }
    status = res.run_resp_code != 0 ? res.run_resp_code : 500;
  }
  request_bind(nullptr);
  response_bind(nullptr);
  res.live = mrb_nil_value();
  res.run_vals = nullptr;
  res.run_req = nullptr;
  res.run_headers = nullptr;
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    if (res.run_zc_have) {
      resource_body_unlend(mrb, res.run_zc);
      res.run_zc_have = false;
    }
    *answer.have_body = false;
    return 500;
  }
  *answer.have_body = res.run_have_body;
  res.run_status = status;
  return status;
}

// The lend window OPENS here for the caller: the run is over, so the value
// has to leave the Resource - the next request through it resets the slot.
bool resource_body_lent(const Resource& res, mrb_value* v, const char** ptr, size_t* len) {
  if (!res.run_zc_have) return false;
  res.run_zc_have = false;
  *v = res.run_zc;
  *ptr = RSTRING_PTR(res.run_zc);
  *len = static_cast<size_t>(RSTRING_LEN(res.run_zc));
  return true;
}

// response.file, handed over the same way: the run is over, so the name
// leaves the Resource before the next request through it resets the slot.
bool resource_file_wanted(const Resource& res, const char** ptr, size_t* len, bool* bad) {
  if (!res.run_have_file) return false;
  res.run_have_file = false;
  *ptr = res.run_file.data();
  *len = res.run_file.size();
  *bad = res.run_file_bad;
  return true;
}

// And it CLOSES here: unrooted so the GC may take it, and the freeze lifted
// - it was ours for the in-flight window, and Ruby has no #unfreeze.
void resource_body_unlend(mrb_state* mrb, mrb_value v) {
  mrb_gc_unregister(mrb, v);
  mrb_basic_ptr(v)->frozen = 0;
}

// RFC 9110 15.6.1: the pending exception ITSELF, for the error resource's
// handle_exception (#210) - what an exception says is one decision for
// the server, made in Ruby, not a message some resource already made.
// Rooted in the arena on the way out: clearing mrb->exc unroots it, and
// everything the caller does next allocates.
bool resource_exception_take(const Resource& res, mrb_value* out) {
  if (res.mrb->exc == nullptr) return false;
  *out = mrb_obj_value(res.mrb->exc);
  res.mrb->exc = nullptr;
  mrb_gc_protect(res.mrb, *out);
  return true;
}

// mruby: one raise as one error-log record - class, message, backtrace.
void exception_facts(mrb_state* mrb, ErrFacts& f, std::string& backtrace) {
  if (mrb->exc == nullptr) return;
  const mrb_value exc = mrb_obj_value(mrb->exc);
  f.exception_class = mrb_obj_classname(mrb, exc);
  f.exception_class_len = std::strlen(f.exception_class);
  struct RException* e = reinterpret_cast<struct RException*>(mrb->exc);
  if (e->mesg != nullptr && e->mesg->tt == MRB_TT_STRING) {
    const mrb_value mesg = mrb_obj_value(e->mesg);
    f.message = RSTRING_PTR(mesg);
    f.message_len = static_cast<size_t>(RSTRING_LEN(mesg));
  }
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value bt = mrb_exc_backtrace(mrb, exc);
  if (mrb_array_p(bt)) {
    const mrb_int n = RARRAY_LEN(bt);
    for (mrb_int i = 0; i < n; i++) {
      const mrb_value f = RARRAY_PTR(bt)[i];
      if (!mrb_string_p(f)) continue;
      if (!backtrace.empty()) backtrace.push_back('\n');
      backtrace.append(RSTRING_PTR(f), static_cast<size_t>(RSTRING_LEN(f)));
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  f.backtrace = backtrace.data();
  f.backtrace_len = backtrace.size();
}

// The public door for a C++ resource callback (#207). The wrapper keeps
// the method callable from Ruby - an app may still subclass and call
// super, and a bintest may poke it - while the fold records the raw
// pointer so the engine never goes through the wrapper at all.
void define_native(mrb_state* mrb, struct RClass* c, Native n) {
  native_table().push_back(NativeEntry{c, n.sym, n.fn});
  mrb_define_method_id(mrb, c, n.sym, native_shim, n.aspec);
}
}


// #181: a resource instance belongs to ONE request and the server makes it.
// Ruby may not - a route names the CLASS, and C++ allocates from it with
// mrb_obj_alloc. Without this, Resource.new would fail on the undef'd
// initialize with "undefined method", which says nothing about why.
mrb_value resource_new_refused(mrb_state* mrb, mrb_value self) {
  mrb_raise(mrb, E_WM_ERROR(mrb),
            "a resource is the server's to build, one per request - name the class in a "
            "route, never an instance");
  return self;
}

extern "C" {
// mruby: the gem's Ruby surface - the base classes and the loop's three doors.
void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
  struct RClass* err =
      mrb_define_class_under_id(mrb, wm, MRB_SYM(Error), mrb->eStandardError_class);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(ConfigError), err);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(RouteError), err);
  // mruby: EVERY object carries initialize on the instance, inherited from
  // Object, unless it is undef'd - so "does this resource define one" could
  // never be asked, only "does it differ from Object's". Undef it here and
  // the question becomes the honest one: an initialize on a resource exists
  // exactly when its author wrote it. The fold then stores the resolved
  // method and the run enters it directly; mrb_obj_new is not used at all,
  // because it would search for the same method twice per request.
  // Webmachine::WebsocketResource and SseResource keep theirs: there
  // initialize is the documented open hook, it runs once per connection
  // rather than per request, and sse_open/ws_admit call it unconditionally.
  struct RClass* res_class =
      mrb_define_class_under_id(mrb, wm, MRB_SYM(Resource), mrb->object_class);
  mrb_undef_method_id(mrb, res_class, MRB_SYM(initialize));
  mrb_define_class_method_id(mrb, res_class, MRB_SYM(new), resource_new_refused,
                             MRB_ARGS_ANY());
  webmachine::ws_init(mrb, wm);
  webmachine::sse_init(mrb, wm);
  webmachine::application_init(mrb, wm);
  webmachine::request_init(mrb, wm);
  webmachine::response_init(mrb, wm);
  webmachine::watcher_init_class(mrb, wm);
  webmachine::server_init(mrb, wm);
}

// mruby: nothing outlives the VM here.
void mrb_webmachine_mruby_gem_final(mrb_state*) {}
}
