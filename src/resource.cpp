#include "ruby_value.hpp"

#include <mruby/proc_irep_ext.h>

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>

#include <unistd.h>

#include <algorithm>
#include <mruby/object.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <simdutf.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace webmachine
{
namespace
{
using flow::Node;

// RFC 9110 9.1: the name of every flow::Method the parse can settle on.
// kOther is the method this server did not compile, and it has no name of
// its own, so the table stops before it.
constexpr std::string_view kMethodName[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

// One answer per flow::Method, kOther included. The walk keeps a table of
// this width, so a set of method answers is this wide as well.
constexpr size_t kMethodCount = static_cast<size_t>(flow::Method::kOther) + 1;
static_assert(std::size(kMethodName) + 1 == kMethodCount,
              "every flow::Method but kOther has a name");

// One flag per flow::Method. An array carries its own width, which a
// `bool x[7]` parameter does not: that one decays to a pointer, and the 7
// tells the compiler nothing.
using MethodFlags = std::array<bool, kMethodCount>;

// mruby: unwrap MRB_PROC_ALIAS once, at fold, instead of at every call.
mrb_method_t method_unwrap_alias(mrb_method_t method)
{
    if (MRB_METHOD_UNDEF_P(method) || MRB_METHOD_FUNC_P(method))
        return method;
    const struct RProc *cursor = MRB_METHOD_PROC(method);
    while (cursor != nullptr && MRB_PROC_ALIAS_P(cursor))
        cursor = cursor->upper;
    if (cursor == nullptr)
        return method;
    mrb_method_t out_value = method;
    MRB_METHOD_FROM_PROC(out_value, cursor);
    return out_value;
}

// One name looked up on one class: what mruby found, whether anything
// answers, whether it is an irep (so the proc may be entered directly),
// our own C++ body where there is one, and the name it was found by.
// The name travels with the rest so the funcall fallback cannot use a
// different one.
struct Resolved {
    mrb_method_t method = {};
    mrb_sym method_name = 0;
    bool defined = false;
    bool irep = false;
    NativeCb native = nullptr;
};

// The receiver a call enters on, and the class its method was found on -
// mruby needs both to enter an irep without a second method search.
struct On {
    mrb_value self;
    struct RClass *klass;
};

// Which (class, name) pairs were registered as C++ callbacks. Consulted
// at fold time only - the answer is copied into the slot, so a request
// never looks anything up. A vector because an app has a handful of
// these and a hash would cost more to build than it ever saves.
struct NativeEntry {
    struct RClass *klass;
    mrb_sym method_name;
    NativeCb function;
};
std::vector<NativeEntry> &native_table_of_this_process()
{
    static std::vector<NativeEntry> thrown;
    return thrown;
}

// Ruby must be able to call the same method, so an ordinary cfunc is
// registered too; it collects the arguments the normal way and hands
// them on. The engine skips this wrapper entirely.
mrb_value native_call_from_ruby(mrb_state *mrb, mrb_value self)
{
    mrb_value *argv = nullptr;
    mrb_int argc = 0;
    mrb_get_args(mrb, "*", &argv, &argc);
    struct RClass *klass = mrb_class(mrb, self);
    const mrb_sym called_name = mrb->c->ci->mid;
    for (struct RClass *k = klass; k != nullptr; k = k->super) {
        for (const NativeEntry &e : native_table_of_this_process()) {
            if (e.klass == k && e.method_name == called_name)
                return e.function(mrb, self, argc, argv);
        }
    }
    mrb_raisef(mrb, E_WM_ERROR(mrb), "%s lost its native body", mrb_sym_name(mrb, called_name));
    return mrb_nil_value();
}

// The one place a native callback is looked up by (class, name).
NativeCb native_body_of(struct RClass *klass, mrb_sym method_name)
{
    for (struct RClass *k = klass; k != nullptr; k = k->super) {
        for (const NativeEntry &e : native_table_of_this_process()) {
            if (e.klass == k && e.method_name == method_name)
                return e.function;
        }
    }
    return nullptr;
}

// mruby: where does this symbol answer, and may we enter its proc directly?
Resolved method_resolve(mrb_state *mrb, struct RClass *klass, mrb_sym method_name)
{
    Resolved run;
    run.method_name = method_name;
    struct RClass *owner = klass;
    run.method = method_unwrap_alias(mrb_method_search_vm(mrb, &owner, method_name));
    run.defined = !MRB_METHOD_UNDEF_P(run.method);
    run.irep = run.defined && !MRB_METHOD_CFUNC_P(run.method);
    // Ours? Then the slot carries the function itself and the engine
    // enters it directly - no lookup, no callinfo, no VM.
    if (run.defined && !run.irep)
        run.native = native_body_of(owner, method_name);
    return run;
}

// mruby: is this a runtime callback? A direct look into the method table.
bool instance_method_is_defined(mrb_state *mrb, mrb_value klass, mrb_sym method_name)
{
    return method_resolve(mrb, mrb_class_ptr(klass), method_name).defined;
}

// cb.rb: what to look for - the name, and whether a `def self.` with no
// instance method beside it counts as an answer.
struct Wanted {
    mrb_sym method_name;
    bool class_fallback;
};

// cb.rb: a value callback - the instance method wins; a class-only version is
// kept with an undef method slot and funcalled on the class at runtime.
Resource::ValueCb value_callback_resolve(mrb_state *mrb, mrb_value klass, Wanted wanted)
{
    const mrb_sym method_name = wanted.method_name;
    const bool class_fallback = wanted.class_fallback;
    Resource::ValueCb callback;
    callback.sym = method_name;
    const Resolved inst = method_resolve(mrb, mrb_class_ptr(klass), method_name);
    if (inst.defined) {
        callback.has = true;
        callback.m = inst.method;
        callback.irep = inst.irep;
        callback.native = inst.native;
        return callback;
    }
    if (!class_fallback)
        return callback;
    const Resolved meta = method_resolve(mrb, mrb_class(mrb, klass), method_name);
    if (meta.defined) {
        callback.has = true;
        callback.m = meta.method;
        callback.irep = meta.irep;
        callback.native = meta.native;
        callback.on_class = true;
    }
    return callback;
}

struct SetupCall {
    const struct RProc *proc;
    mrb_sym method_name;
    mrb_value self;
    struct RClass *klass;
};

// mruby: the yield body a setup call runs under mrb_protect_error.
mrb_value setup_call_in_protected_call(mrb_state *mrb, void *user_data)
{
    const SetupCall *klass = static_cast<const SetupCall *>(user_data);
    mrb_callinfo *callback_index = mrb->c->ci;
    const mrb_sym saved_mid = callback_index->mid;
    callback_index->mid = klass->method_name;
    mrb_value run =
        mrb_yield_with_class(mrb, mrb_obj_value(const_cast<struct RProc *>(klass->proc)), 0,
                             nullptr, klass->self, klass->klass);
    callback_index->mid = saved_mid;
    return run;
}

// mruby: invoke a resolved method at setup time; a raise stays pending.
struct NativeCall {
    NativeCb function;
    mrb_value self;
    mrb_int argc;
    const mrb_value *argv;
};

// The yield body a native call runs under mrb_protect_error - a C++
// callback may raise like any other, and an unguarded raise here would
// unwind through frames that are not ready for it.
mrb_value native_call_in_protected_call(mrb_state *mrb, void *user_data)
{
    const NativeCall *klass = static_cast<const NativeCall *>(user_data);
    return klass->function(mrb, klass->self, klass->argc, klass->argv);
}

// mruby: mrb_protect_error hands back whatever was pending (vm.c: it
// returns mrb_obj_value(mrb->exc) and clears it), and mrb->exc is a
// struct RObject* - so only an exception object may be stored there.
// mrb_obj_ptr on anything else reads a Fixnum's bits as a pointer, and
// mruby's immediates (Integer, Symbol, nil, true, false) carry no
// object at all. Checked once, here, for every protected call.
//
// No branch hint: both callers reach this from inside their own
// mrb_unlikely(raised), so every path through here is already cold,
// and a hint here only bought a second negation to read past.
void pending_exception_take(mrb_state *mrb, mrb_value value)
{
    if (!mrb_exception_p(value)) {
        mrb->exc = mrb_obj_ptr(
            mrb_exc_new_lit(mrb, E_WM_ERROR(mrb), "a callback ended without an exception object"));
        return;
    }
    mrb->exc = mrb_obj_ptr(value);
}

mrb_value native_call(mrb_state *mrb, NativeCall call)
{
    mrb_bool raised = FALSE;
    mrb_value value = mrb_protect_error(mrb, native_call_in_protected_call, &call, &raised);
    if (mrb_unlikely(raised)) {
        pending_exception_take(mrb, value);
        return mrb_nil_value();
    }
    mrb_gc_protect(mrb, value);
    return value;
}

mrb_value resolved_call(mrb_state *mrb, const Resolved &run, On receiver)
{
    if (run.native != nullptr)
        return native_call(mrb, {run.native, receiver.self, 0, nullptr});
    if (!run.irep)
        return mrb_funcall_argv(mrb, receiver.self, run.method_name, 0, nullptr);
    SetupCall ctx{MRB_METHOD_PROC(run.method), run.method_name, receiver.self, receiver.klass};
    mrb_bool raised = FALSE;
    mrb_value value = mrb_protect_error(mrb, setup_call_in_protected_call, &ctx, &raised);
    if (mrb_unlikely(raised)) {
        pending_exception_take(mrb, value);
        return mrb_nil_value();
    }
    mrb_gc_protect(mrb, value);
    return value;
}

// The class being folded, and where a refusal about it is spelled.
struct Folding {
    mrb_state *mrb;
    mrb_value klass;
};

// One callback fold time asks: the symbol it is found by, and the name a
// refusal spells it with.
struct Asked {
    mrb_sym method_name;
    const char *name;
};

// RFC 9110: one konst flow callback, asked once on the class.
void callback_ask_bool(const Folding &folding, Asked answer, bool defv, bool *out_value)
{
    mrb_state *const mrb = folding.mrb;
    const Resolved run = method_resolve(mrb, mrb_class(mrb, folding.klass), answer.method_name);
    if (!run.defined) {
        *out_value = defv;
        return;
    }
    const mrb_value value = resolved_call(mrb, run, {folding.klass, mrb_class(mrb, folding.klass)});
    if (mrb_unlikely(mrb->exc != nullptr))
        rethrow(mrb);
    *out_value = mrb_test(value);
}

// #202: a `def self.x` is asked here, once, and its answer is kept for the
// life of the process - that is the whole reason the class form exists.
// The class is frozen right after, so the answer cannot go stale.
// `spell` turns a String answer into an ETag (RFC 9110 8.8.3); without it
// the answer is read as a moment (RFC 9110 5.6.7), the way the date fields
// need it.
// One class-form answer: where it comes from, what it is called in a
// refusal, whether it is spelled as an ETag, and the slot it is kept in
// for the life of the process.
struct BakedValue {
    const Resource::ValueCb &callback;
    const char *name;
    bool spell;
    Resource::KonstValue &out_value;
};

void value_bake_at_start(const Folding &folding, const BakedValue &bake)
{
    mrb_state *const mrb = folding.mrb;
    const Resource::ValueCb &callback = bake.callback;
    Resource::KonstValue &out_value = bake.out_value;
    if (!callback.has || !callback.on_class)
        return;
    out_value.asked = true;
    Resolved run;
    run.method = callback.m;
    run.irep = callback.irep;
    run.native = callback.native;
    run.defined = true;
    mrb_value value = resolved_call(mrb, run, {folding.klass, mrb_class(mrb, folding.klass)});
    if (mrb_unlikely(mrb->exc != nullptr))
        rethrow(mrb);
    if (mrb_nil_p(value) || mrb_false_p(value))
        return;
    if (bake.spell) {
        if (!mrb_string_p(value))
            value = mrb_obj_as_string(mrb, value);
        const std::string_view etag = ruby_string_bytes(value);
        http::etag_spell(etag.data(), etag.size(), out_value.text);
        out_value.present = true;
        return;
    }
    // Same conversion as epoch_memo's, and the same reason for the _check
    // form: mruby's own TypeError names the value and #to_i, never the
    // callback whose class form has to be fixed.
    const mrb_value count = mrb_type_convert_check(mrb, value, MRB_TT_INTEGER, MRB_SYM(to_i));
    if (mrb_unlikely(mrb_nil_p(count))) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%s must answer a Time or an epoch Integer, not %v",
                   bake.name, value);
    }
    out_value.epoch = static_cast<int64_t>(mrb_integer(count));
    out_value.present = true;
}

// RFC 9110 9.1: the methods that one run of space- or comma-separated
// tokens names. http::parse_method reads one token: it switches on the
// length and compares once. The request line reads its method with the
// same function, so a resource's list and a request agree by construction.
// A token that function does not know raises, because the walk answers per
// method and this server compiles six of them.
void mark_named_methods(const Folding &folding, Asked answer, mrb_value value, MethodFlags &named)
{
    std::string_view rest = ruby_string_bytes(value);
    for (;;) {
        const size_t from = rest.find_first_not_of(" ,");
        if (from == std::string_view::npos)
            return;
        rest.remove_prefix(from);
        const size_t target = rest.find_first_of(" ,");
        const std::string_view token = rest.substr(0, target);
        const flow::Method method = http::parse_method(token.data(), token.size());
        if (mrb_unlikely(method == flow::Method::kOther)) {
            mrb_raisef(folding.mrb, E_WM_ROUTE_ERROR(folding.mrb),
                       "%s names '%l' - outside the compiled method set", answer.name, token.data(),
                       token.size());
        }
        named[static_cast<size_t>(method)] = true;
        if (target == std::string_view::npos)
            return;
        rest.remove_prefix(target);
    }
}

// RFC 9110 9.1: known_methods / allowed_methods as one String of tokens or
// webmachine-ruby's Array-of-Strings form.
void ask_methods(const Folding &folding, Asked answer, MethodFlags &named)
{
    mrb_state *const mrb = folding.mrb;
    const Resolved run = method_resolve(mrb, mrb_class(mrb, folding.klass), answer.method_name);
    if (!run.defined)
        return;
    const mrb_value value = resolved_call(mrb, run, {folding.klass, mrb_class(mrb, folding.klass)});
    if (mrb_unlikely(mrb->exc != nullptr))
        rethrow(mrb);
    named.fill(false);
    if (mrb_string_p(value)) {
        mark_named_methods(folding, answer, value, named);
        return;
    }
    if (mrb_unlikely(!mrb_array_p(value))) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s must return an Array of Strings or a String like 'GET HEAD', not %v",
                   answer.name, value);
    }
    for (size_t j = 0; j < ruby_array_length(value); j++) {
        const mrb_value entry = ruby_array_entry(value, j);
        if (mrb_unlikely(!mrb_string_p(entry))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                       "%s must return method Strings, and %v is not one", answer.name, entry);
        }
        mark_named_methods(folding, answer, entry, named);
    }
}

struct BoolCb {
    Node node;
    mrb_sym method_name;
    const char *name;
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
    mrb_sym method_name;
    uint8_t maxargs;
};
const NodeValueCb kNodeValues[] = {
    {Node::kB8, MRB_SYM_Q(is_authorized), 1},
};

// The node whose own callback carries this name, or flow::kNodeCount for
// a name that is no node's callback. `compute`, `watch` and
// `run_together` all ask the same question, and this is the one answer.
size_t node_index_of_callback(mrb_sym want)
{
    for (const BoolCb &cb : kBools) {
        if (cb.method_name == want)
            return static_cast<size_t>(cb.node);
    }
    for (const NodeValueCb &cb : kNodeValues) {
        if (cb.method_name == want)
            return static_cast<size_t>(cb.node);
    }
    return flow::kNodeCount;
}

struct NamedSym {
    mrb_sym method_name;
    const char *name;
};
const NamedSym kUnhonored[] = {
    {MRB_SYM(languages_provided), "languages_provided"},
    {MRB_SYM(charsets_provided), "charsets_provided"},
    {MRB_SYM(language_chosen), "language_chosen"},
};
const NamedSym kKonstOnly[] = {
    {MRB_SYM(encodings_provided), "encodings_provided"},
    {MRB_SYM(max_body), "max_body"},
};

// The mirror of kKonstOnly. `def self.x` means, everywhere in this tree,
// "asked once while the app is being set up, and the answer is frozen with
// the class". That is right for a question and wrong for these four: they
// do work, and work asked once at setup is work that never happens again -
// a class-level process_post would handle exactly zero POSTs, silently.
// So the fold refuses them by name instead of folding them.
const NamedSym kWorkOnly[] = {
    {MRB_SYM(delete_resource), "delete_resource"},
    {MRB_SYM(create_path), "create_path"},
    {MRB_SYM(process_post), "process_post"},
    {MRB_SYM(finish_request), "finish_request"},
};

// RFC 9110 5.1: case-insensitive token equality with neither side
// canonical - both are folded. Not http::ci_eq, which folds one side
// because the other is a lowercase literal in this source.
bool text_is_same_ignoring_case(std::string_view answer, std::string_view bound)
{
    if (answer.size() != bound.size())
        return false;
    for (size_t i = 0; i < answer.size(); i++) {
        char one = answer[i];
        char other = bound[i];
        if (one >= 'A' && one <= 'Z')
            one = static_cast<char>(one + 32);
        if (other >= 'A' && other <= 'Z')
            other = static_cast<char>(other + 32);
        if (one != other)
            return false;
    }
    return true;
}

// RFC 9110 5.6.3: OWS around a value is not part of the value.
std::string_view text_trim_optional_space(std::string_view text)
{
    size_t index = 0;
    size_t text_end = text.size();
    while (index < text_end && (text[index] == ' ' || text[index] == '\t'))
        index++;
    while (text_end > index && (text[text_end - 1] == ' ' || text[text_end - 1] == '\t'))
        text_end--;
    return text.substr(index, text_end - index);
}

// RFC 9110 5.6.6: a field value up to its first parameter - the media
// type itself, without the space a sender may leave before the ';'.
std::string_view media_type_base(std::string_view value)
{
    return text_trim_optional_space(value.substr(0, value.find(';')));
}

// RFC 9110 5.6.6: what follows that first ';' - the parameter list, or
// nothing at all when the value carries none.
std::string_view media_type_params(std::string_view value)
{
    const size_t semi = value.find(';');
    return semi == std::string_view::npos ? std::string_view{} : value.substr(semi + 1);
}

// RFC 9110 5.6.6: one parameter taken off the front of a list, and the
// list that is left. A parameter with no '=' has an empty value, which is
// not the same as one that is not there; a nameless one is a stray ';'.
struct NextParam {
    http::Field param;
    std::string_view rest;
};

NextParam param_take_next(std::string_view list)
{
    const size_t semi = list.find(';');
    const std::string_view entry = list.substr(0, semi);
    const std::string_view rest =
        semi == std::string_view::npos ? std::string_view{} : list.substr(semi + 1);
    const size_t is_same = entry.find('=');
    if (is_same == std::string_view::npos)
        return {{text_trim_optional_space(entry), {}}, rest};
    return {{text_trim_optional_space(entry.substr(0, is_same)),
             text_trim_optional_space(entry.substr(is_same + 1))},
            rest};
}

// RFC 9110 10.2.2: does this run's header block already carry a Location line?
bool headers_hold_location(const std::string &headers)
{
    size_t index = 0;
    while (index < headers.size()) {
        size_t line_end = headers.find("\r\n", index);
        if (line_end == std::string::npos)
            line_end = headers.size();
        if (line_end - index > 9 && http::tok_eq({headers.data() + index, 9}, "location:"))
            return true;
        index = line_end + 2;
    }
    return false;
}

// RFC 9110: the runtime tier - webmachine-ruby's value semantics for the
// whole flow (flow.rb + helpers.rb, 1:1) inside one VM frame.
// RFC 9110: one request's walk through the flow. Entered as a C++ call
// from resource_run - a Ruby frame around it would cost a method lookup
// per request and leave a class in the GC's mark set.
struct RescueCtx {
    const Resource *resource;
    mrb_value exception;
};

// fsm.rb: the raise path - finish_request, inside its own guarded frame.
// handle_exception is not here: it lives on Webmachine::ErrorResource and
// nowhere else (#210), because what an exception says on the wire is one
// decision for the server rather than a per-route one. A resource that
// defines its own is ignored.
mrb_value run_rescue_in_protected_call(mrb_state *mrb, void *user_data)
{
    RescueCtx &status = *static_cast<RescueCtx *>(user_data);
    const Resource &resource = *status.resource;
    if (resource.cb_finish_request.has && !mrb_nil_p(resource.run.live)) {
        const mrb_value frecv = MRB_METHOD_UNDEF_P(resource.cb_finish_request.m)
                                    ? mrb_obj_value(resource.klass)
                                    : resource.run.live;
        mrb_funcall_argv(mrb, frecv, resource.cb_finish_request.sym, 0, nullptr);
    }
    return mrb_nil_value();
}

// fsm.rb: everything one run carries from one node to the next.
//
// A struct rather than a row of locals, because the arms off the
// straight line are functions of their own and this is what they take.
//
// `facts` and `k` are references into `res` rather than lookups repeated
// at each use; `chosen` is written where the content type is negotiated
// and read where the body is produced, which is why it outlives an arm.
struct Run {
    mrb_state *mrb;
    const Resource &resource;
    const flow::ReqFacts &facts;
    const flow::KonstAnswers &k;
    const http::ReqValues *vals;
    std::string &hdrs;
    Node count;
    uint16_t status;
    bool halted;
    int chosen;
    bool ct_dyn;
};

// flow.rb decision_test: any callback may halt with an Integer status.
uint16_t halt_status_of(Run &run, mrb_value value, mrb_sym method_name)
{
    mrb_state *mrb = run.mrb;
    const mrb_int code = mrb_integer(value);
    if (mrb_likely(code >= 100 && code <= 599)) {
        return static_cast<uint16_t>(code);
    } else {
        mrb_raisef(mrb, E_RANGE_ERROR, "%s answered %i, which is not an HTTP status",
                   mrb_sym_name(mrb, method_name), code);
    }
    WM_UNREACHABLE();
}

// RFC 9110 9.1: the method token as the request spelled it, or the name
// of the one the parse settled on.
void run_method_name(Run &run, const char **cursor, size_t *out_length)
{
    if (mrb_likely(run.resource.run.req != nullptr &&
                   run.resource.run.req->method_token != nullptr)) {
        *cursor = run.resource.run.req->method_token;
        *out_length = run.resource.run.req->method_token_len;
    } else {
        const size_t method = static_cast<size_t>(run.facts.method);
        const bool named = method < std::size(kMethodName);
        *cursor = named ? kMethodName[method].data() : "";
        *out_length = named ? kMethodName[method].size() : 0;
    }
}

// flow.rb b10/b12: is this request's method in the list the resource just
// answered with?
bool method_list_holds_this_method(Run &run)
{
    const char *method_bytes;
    size_t method_length;
    run_method_name(run, &method_bytes, &method_length);
    for (const std::string &s : run.resource.run.methods) {
        if (s.size() == method_length && std::memcmp(s.data(), method_bytes, method_length) == 0)
            return true;
    }
    return false;
}

// RFC 9110 12.5.1: the list c3/c4 negotiate against - the run's own where
// the resource answered per request, the folded one otherwise.
const std::vector<Resource::TypedHandler> &content_types_active(Run &run)
{
    return run.ct_dyn ? run.resource.run.content_types_provided
                      : run.resource.content_types_provided;
}

// RFC 9110 5.6.2 / 5.5: the gate for everything an app puts into the head -
// an ETag, a Location, a WWW-Authenticate, a Vary member, and with
// options() the field name too. Here because here is the only place that
// spells a field; a raise inside the run frame is a 500, which is the
// honest answer to a resource that made an unspellable one.
void run_append_field(Run &run, http::Field flow_node)
{
    mrb_state *mrb = run.mrb;
    const char *const name = flow_node.name.data();
    const size_t nlen = flow_node.name.size();
    const char *const value = flow_node.value.data();
    const size_t vlen = flow_node.value.size();
    if (mrb_unlikely(http::field_name_is_the_servers(name, nlen))) {
        // The name is one of the seven this server spells itself, so the
        // copy is short and it is a token.
        const std::string shown(name, nlen);
        mrb_raisef(mrb, E_WM_ERROR(mrb),
                   "a field this resource produced is the server's to spell: %s says how the "
                   "message is framed or what this hop does, and a second copy of it is what a "
                   "proxy in front of this server reads differently",
                   shown.c_str());
    }
    if (mrb_likely(http::field_name_ok(name, nlen) && http::field_value_ok(value, vlen))) {
        run.hdrs.append(name, nlen);
        run.hdrs.append(": ", 2);
        run.hdrs.append(value, vlen);
        run.hdrs.append("\r\n", 2);
    } else {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "a field this resource produced is not spellable: the name must be a token "
                  "(RFC 9110 5.6.2) and the value must carry no CR, LF or NUL (5.5)");
    }
}

// RFC 9110 5.6.7: one HTTP-date field, IMF-fixdate.
void run_append_date_line(Run &run, std::string_view name, int64_t epoch)
{
    struct tm tmv {
    };
    const time_t thrown = static_cast<time_t>(epoch);
    gmtime_r(&thrown, &tmv);
    char chunk[http::kDateLen];
    http::date_core(chunk, tmv);
    run_append_field(run, {name, {chunk, http::kDateLen}});
}

// RFC 9110 12.5.2/12.5.3/12.5.4: what follows the Accept nodes.
//
// d4, e5 and f6 each ask whether the request named their field, and the
// conneg node behind each is reachable only through it. A request that
// names none of the three walks straight to g7.
Node node_after_accept(const flow::ReqFacts &facts)
{
    return facts.has_accept_language || facts.has_accept_charset || facts.has_accept_encoding
               ? Node::kD4
               : Node::kG7;
}

// Where the flow walk stands: the node it is on, the status it has
// reached, and whether an edge has halted it.
struct At {
    Node &node;
    uint16_t &status;
    bool &halted;
};

// fsm.rb run: one step's edge, out of the graph table.
void edge_take(At index, const flow::FlowNode &flow_node, bool answer)
{
    Node &count = index.node;
    uint16_t &status = index.status;
    bool &halted = index.halted;
    const flow::Target &thrown = answer ? flow_node.on_true : flow_node.on_false;
    if (thrown.status != 0) {
        status = thrown.status;
        halted = true;
    } else {
        count = thrown.node;
    }
}

// The same step for the callers that do not already hold the node's row.
// The generic node path does - it reads f.kind first - and calls the form
// above rather than pay for a second flow::kFlow[n] lookup of the same node.
void take_edge(At index, bool answer)
{
    edge_take(index, flow::kFlow[static_cast<size_t>(index.node)], answer);
}

// One list-valued field line: its name, the value that always leads where
// there is one, and the app Strings that follow it - Allow's methods,
// Vary's variances.
struct FieldList {
    std::string_view name;
    std::string_view head;
    const std::vector<std::string> &tail;
};

// RFC 9110 5.6.7: one date field of a resource - where its answer comes
// from (the per-request callback, or what #202 baked at setup) and the
// three slots that remember what it said this round.
struct DateField {
    const Resource::ValueCb &callback;
    const Resource::KonstValue &konst;
    bool *asked;
    bool *present;
    int64_t *epoch;
};

// One method already found: what mruby resolved for the name, whether it
// is an irep (so the fast entry applies), our own C++ body where there is
// one, and the name itself for the funcall the slow path falls back to.
struct Bound {
    mrb_method_t method;
    bool irep;
    NativeCb native;
    mrb_sym method_name;
};

// What one call carries. mruby wants (argc, argv); this is that pair with
// a name, and {} is the call that carries nothing.
using Args = std::span<const mrb_value>;

mrb_value direct_call(Run &run, Bound bound, Args args = {});
mrb_value class_call(Run &run, Bound bound, Args args = {});
mrb_value value_callback_call_raw(Run &run, const Resource::ValueCb &callback, Args args = {});
mrb_value value_callback_call(Run &run, const Resource::ValueCb &callback, Args args = {});
mrb_value node_call(Run &run, Node node, Args args);
mrb_value node_argument(Run &run, Node node);
void methods_marshal_from_callback(Run &run, const Resource::ValueCb &callback);
void run_append_field_list(Run &run, const FieldList &flow_node);
void run_append_allow(Run &run);
void content_types_marshal(Run &run);
int etag_make_sure_it_is_there(Run &run);
void date_field_memo(Run &run, const DateField &date_field);
int caching_fields_add(Run &run);
// #30: the value round. generate_etag, last_modified and expires choose
// no edge - the flow only reads what they answer - so a run starts every
// declared one at the first node that needs any of them, and waits once.
bool value_round_begin(Run &run, Node count, uint16_t status);
void value_round_answer_take(const Resource &resource, uint8_t what, mrb_value value);
// RFC 9110 5.6.6: one parameter of a field value - the value to search,
// and the parameter's name.
struct Param {
    std::string_view incoming;
    std::string_view name;
};
bool param_find_named(Param cursor, std::string_view &value);
int accept_negotiate(Run &run);
int run_node_n11(Run &run);

mrb_value direct_call(Run &run, Bound bound, Args args)
{
    const mrb_int argc = static_cast<mrb_int>(args.size());
    const mrb_value *const argv = args.data();
    const NativeCb native = bound.native;
    const mrb_sym method_name = bound.method_name;
    // The cheapest of the three tiers: our own C++ body, entered with the
    // arguments in hand. It never reads the callinfo, so there is nothing
    // to build for it.
    if (native != nullptr)
        return native_call(run.mrb, {native, run.resource.run.live, argc, argv});
    if (mrb_unlikely(!bound.irep || mrb_obj_ptr(run.resource.run.live)->c != run.resource.klass)) {
        return mrb_funcall_argv(run.mrb, run.resource.run.live, method_name, argc, argv);
    }
    mrb_callinfo *callback_index = run.mrb->c->ci;
    const mrb_sym saved = callback_index->mid;
    callback_index->mid = method_name;
    mrb_value answer = mrb_yield_with_class(
        run.mrb, mrb_obj_value(const_cast<struct RProc *>(MRB_METHOD_PROC(bound.method))), argc,
        argv, run.resource.run.live, run.resource.klass);
    callback_index->mid = saved;
    return answer;
}

mrb_value class_call(Run &run, Bound bound, Args args)
{
    const mrb_int argc = static_cast<mrb_int>(args.size());
    const mrb_value *const argv = args.data();
    const NativeCb native = bound.native;
    const mrb_sym method_name = bound.method_name;
    const mrb_value self = mrb_obj_value(run.resource.klass);
    if (native != nullptr)
        return native_call(run.mrb, {native, self, argc, argv});
    // mrb_obj_ptr(self)->c, not mrb_class(r.mrb, self): the latter is an
    // out-of-line call into another translation unit, and this build has no
    // LTO - a call to read one pointer, on the path whose whole point is
    // not calling anything.
    if (mrb_unlikely(!bound.irep || mrb_obj_ptr(self)->c != run.resource.meta_klass)) {
        return mrb_funcall_argv(run.mrb, self, method_name, argc, argv);
    }
    mrb_callinfo *callback_index = run.mrb->c->ci;
    const mrb_sym saved = callback_index->mid;
    callback_index->mid = method_name;
    mrb_value answer = mrb_yield_with_class(
        run.mrb, mrb_obj_value(const_cast<struct RProc *>(MRB_METHOD_PROC(bound.method))), argc,
        argv, self, run.resource.meta_klass);
    callback_index->mid = saved;
    return answer;
}

mrb_value value_callback_call_raw(Run &run, const Resource::ValueCb &callback, Args args)
{
    const Bound bound = {callback.m, callback.irep, callback.native, callback.sym};
    if (callback.on_class)
        return class_call(run, bound, args);
    return direct_call(run, bound, args);
}

mrb_value value_callback_call(Run &run, const Resource::ValueCb &callback, Args args)
{
    const mrb_value value = value_callback_call_raw(run, callback, args);
    // #30: the same missing declaration a node can have. This callback
    // said nothing, so the reader ahead takes the object for an ETag, a
    // moment or a type list and never runs the block.
    if (mrb_unlikely(mrb_data_p(value))) {
        ComputeTaskAsk call_ask;
        if (mrb_unlikely(compute_task_read_from_value(run.mrb, value, &call_ask))) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n answered a Webmachine::ComputeTask and never declared one - write "
                       "`compute %n`",
                       callback.sym, callback.sym);
        }
        if (mrb_unlikely(value_is_watcher(run.mrb, value))) {
            mrb_raisef(
                run.mrb, E_WM_ERROR(run.mrb),
                "%n answered a Webmachine::Watcher and never declared one - write `watch %n`",
                callback.sym, callback.sym);
        }
    }
    return value;
}

mrb_value node_call(Run &run, Node node, Args args)
{
    const size_t i = static_cast<size_t>(node);
    const Bound bound = {run.resource.node_m[i], run.resource.node_irep[i],
                         run.resource.node_native[i], run.resource.node_sym[i]};
    if ((run.resource.node_on_class >> i) & 1)
        return class_call(run, bound, args);
    return direct_call(run, bound, args);
}

// #80: a node whose answer a worker may give. Three ways out, and the
// caller reads which by the return value:
//
//   - the answer is already here (the worker gave it) - it is handed
//     back and the memo is cleared, so the node cannot read it twice;
//   - the node is declared `compute` and this run may park - the walk's place is
//     written down, the argument is kept for the reactor, and the walk
//     returns. Nothing of a Ruby stack needs saving, because the stop is
//     between callbacks;
//   - neither - the callback is called here, on this thread, exactly as
//     it always was. That is every node of every resource that never
//     said `compute`, and it costs one predicted branch.
bool node_answer(Run &run, Node node, Args args, uint16_t status, mrb_value *out_value)
{
    const Resource &resource = run.resource;
    const size_t i = static_cast<size_t>(node);
    if (mrb_unlikely(resource.run.answered)) {
        resource.run.answered = false;
        *out_value = resource.run.answer;
        resource.run.answer = mrb_nil_value();
        return true;
    }
    // A declared node is called like any other, and its class method is
    // cheap by construction: it only builds the arguments this request
    // has to hand. What it answers must be a Webmachine::ComputeTask
    // - a callback that declared one owes one.
    const mrb_value value = node_call(run, node, args);
    if (mrb_unlikely(((resource.compute >> i) & 1) != 0)) {
        ComputeTaskAsk call_ask;
        if (mrb_unlikely(!compute_task_read_from_value(run.mrb, value, &call_ask))) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n is declared `compute` and answered %v - it owes a "
                       "Webmachine::ComputeTask",
                       resource.node_sym[i], value);
        }
        // Nobody can park this run: the caller holds no frame that could
        // keep a stopped one. So the block runs here, on this thread. It
        // is the same block with the same arguments, and the only thing
        // lost is that the reactor waits for it.
        if (mrb_unlikely(!resource.run.can_park)) {
            *out_value = mrb_yield_argv(run.mrb, call_ask.block,
                                        static_cast<mrb_int>(ruby_array_length(call_ask.args)),
                                        ruby_array_items(call_ask.args));
            return true;
        }
        resource.run.stop_node = node;
        resource.run.stop_status = status;
        resource.run.chosen = run.chosen;
        resource.run.compute_task[0] = {call_ask.block, call_ask.args, call_ask.max_runtime,
                                        kJobNode};
        resource.run.compute_task_count = 1;
        resource.run.stopped = true;
        return false;
    }
    // #30: a node the resource declared with `watch` answers with a
    // Webmachine::Watcher. The run then stops until the descriptor says
    // something and the block says the wait is over.
    if (mrb_unlikely(((resource.watch >> i) & 1) != 0)) {
        if (mrb_unlikely(!mrb_data_p(value) || !value_is_watcher(run.mrb, value))) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n is declared `watch` and answered %v - it owes a Webmachine::Watcher",
                       resource.node_sym[i], value);
        }
        if (mrb_unlikely(!resource.run.can_park)) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n answered a Webmachine::Watcher, and this run cannot stop",
                       resource.node_sym[i]);
        }
        resource.run.stop_node = node;
        resource.run.stop_status = status;
        resource.run.chosen = run.chosen;
        resource.run.watch[0] = value;
        resource.run.watch_what[0] = kJobNode;
        resource.run.watch_count = 1;
        resource.run.stopped = true;
        return false;
    }
    // #80: this node declared nothing, so its answer is read as an answer -
    // and every object is true. A ComputeTask or a Watcher here is a
    // missing declaration, and the flow would take the true edge without
    // ever running the block. Name it instead.
    if (mrb_unlikely(mrb_data_p(value))) {
        ComputeTaskAsk call_ask;
        if (mrb_unlikely(compute_task_read_from_value(run.mrb, value, &call_ask))) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n answered a Webmachine::ComputeTask and never declared one - write "
                       "`compute %n`",
                       resource.node_sym[i], resource.node_sym[i]);
        }
        if (mrb_unlikely(value_is_watcher(run.mrb, value))) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n answered a Webmachine::Watcher and never declared one - write "
                       "`watch %n`",
                       resource.node_sym[i], resource.node_sym[i]);
        }
    }
    *out_value = value;
    return true;
}

mrb_value node_argument(Run &run, Node node)
{
    switch (node) {
        case Node::kB8:
            return run.vals != nullptr && run.vals->authorization != nullptr
                       ? mrb_str_new(run.mrb, run.vals->authorization, run.vals->authorization_len)
                       : mrb_nil_value();
        case Node::kB11:
            return run.resource.run.req != nullptr &&
                           run.resource.run.req->request_target != nullptr
                       ? mrb_str_new(run.mrb, run.resource.run.req->request_target,
                                     run.resource.run.req->request_target_len)
                       : mrb_nil_value();
        case Node::kB6: {
            const mrb_value request_facts =
                mrb_funcall_argv(run.mrb, run.resource.run.live, MRB_SYM(request), 0, nullptr);
            const mrb_value handler_name =
                mrb_funcall_argv(run.mrb, request_facts, MRB_SYM(headers), 0, nullptr);
            const mrb_value out_value = mrb_hash_new(run.mrb);
            if (mrb_hash_p(handler_name)) {
                const mrb_value keys = mrb_hash_keys(run.mrb, handler_name);
                for (size_t j = 0; j < ruby_array_length(keys); j++) {
                    const mrb_value key_name = ruby_array_entry(keys, j);
                    if (!mrb_string_p(key_name) || ruby_string_length(key_name) < 8)
                        continue;
                    if (!http::tok_eq(ruby_string_bytes(key_name).substr(0, 8), "content-"))
                        continue;
                    mrb_hash_set(run.mrb, out_value, key_name,
                                 mrb_hash_get(run.mrb, handler_name, key_name));
                }
            }
            return out_value;
        }
        case Node::kB5:
            return run.vals != nullptr && run.vals->content_type != nullptr
                       ? mrb_str_new(run.mrb, run.vals->content_type, run.vals->content_type_len)
                       : mrb_nil_value();
        case Node::kB4:
            // The declared length, not the bound one: B4 runs at the head,
            // and the body may still be on the wire there.
            return mrb_int_value(run.mrb,
                                 static_cast<mrb_int>(run.resource.run.req != nullptr
                                                          ? run.resource.run.req->declared_len
                                                          : 0));
        default:
            return mrb_nil_value();
    }
}

void methods_marshal_from_callback(Run &run, const Resource::ValueCb &callback)
{
    mrb_state *mrb = run.mrb;
    run.resource.run.methods.clear();
    const mrb_value value = value_callback_call(run, callback);
    if (mrb_array_p(value)) {
        for (size_t j = 0; j < ruby_array_length(value); j++) {
            const mrb_value text = ruby_array_entry(value, j);
            if (mrb_unlikely(!mrb_string_p(text))) {
                mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer method Strings",
                           mrb_sym_name(mrb, callback.sym));
            }
            run.resource.run.methods.emplace_back(ruby_string_bytes(text));
        }
        return;
    }
    if (mrb_unlikely(!mrb_string_p(value))) {
        mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer an Array of Strings or a String",
                   mrb_sym_name(mrb, callback.sym));
    }
    const std::string_view text = ruby_string_bytes(value);
    const char *cursor = text.data();
    const char *text_end = cursor + text.size();
    while (cursor < text_end) {
        while (cursor < text_end && (*cursor == ' ' || *cursor == ','))
            cursor++;
        const char *token = cursor;
        while (cursor < text_end && *cursor != ' ' && *cursor != ',')
            cursor++;
        if (token != cursor)
            run.resource.run.methods.emplace_back(token, static_cast<size_t>(cursor - token));
    }
}

void run_append_field_list(Run &run, const FieldList &field_list)
{
    mrb_state *mrb = run.mrb;
    run.hdrs.append(field_list.name);
    run.hdrs.append(": ", 2);
    bool first = true;
    if (!field_list.head.empty()) {
        run.hdrs.append(field_list.head);
        first = false;
    }
    for (const std::string &s : field_list.tail) {
        // Same gate, one member at a time: Allow's members come from
        // allowed_methods and Vary's from variances, both app Strings.
        if (mrb_unlikely(!http::field_value_ok(s.data(), s.size()))) {
            mrb_raise(mrb, E_WM_ERROR(mrb),
                      "a list field this resource produced carries CR, LF or NUL (RFC 9110 5.5)");
        }
        if (!first)
            run.hdrs.append(", ", 2);
        run.hdrs.append(s);
        first = false;
    }
    run.hdrs.append("\r\n", 2);
}

void run_append_allow(Run &run)
{
    if (run.resource.cb_allowed_methods.has) {
        run_append_field_list(run, {"Allow", {}, run.resource.run.methods});
    } else {
        run_append_field(run, {"Allow", run.resource.konst.allow});
    }
}

void content_types_marshal(Run &run)
{
    mrb_state *mrb = run.mrb;
    if (!run.ct_dyn || run.resource.run.content_types_marshalled)
        return;
    run.resource.run.content_types_marshalled = true;
    const mrb_value value = value_callback_call(run, run.resource.cb_content_types_provided);
    if (mrb_unlikely(!mrb_array_p(value) || ruby_array_length(value) == 0)) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "content_types_provided must answer [[type, handler]] pairs");
    }
    const size_t count = ruby_array_length(value);
    // The app answered what it answered last time: the vector already holds
    // it, resolutions included, and nothing has to be rebuilt or searched
    // for. A pair that is not [String, Symbol] simply fails to match and
    // falls into the rebuild below, which names the refusal.
    std::vector<Resource::TypedHandler> &current = run.resource.run.content_types_provided;
    bool same = current.size() == static_cast<size_t>(count);
    for (size_t j = 0; same && j < count; j++) {
        const mrb_value pair = ruby_array_entry(value, j);
        same = mrb_array_p(pair) && ruby_array_length(pair) >= 2 &&
               mrb_string_p(ruby_array_entry(pair, 0)) && mrb_symbol_p(ruby_array_entry(pair, 1)) &&
               mrb_symbol(ruby_array_entry(pair, 1)) == current[static_cast<size_t>(j)].handler &&
               current[static_cast<size_t>(j)].type.size() ==
                   ruby_string_length(ruby_array_entry(pair, 0)) &&
               std::memcmp(current[static_cast<size_t>(j)].type.data(),
                           ruby_string_bytes(ruby_array_entry(pair, 0)).data(),
                           current[static_cast<size_t>(j)].type.size()) == 0;
    }
    if (same)
        return;
    current.clear();
    for (size_t j = 0; j < count; j++) {
        const mrb_value pair = ruby_array_entry(value, j);
        if (mrb_unlikely(!mrb_array_p(pair) || ruby_array_length(pair) < 2 ||
                         !mrb_string_p(ruby_array_entry(pair, 0)) ||
                         !mrb_symbol_p(ruby_array_entry(pair, 1)))) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided pairs are [String, Symbol]");
        }
        Resource::TypedHandler typed_handler;
        typed_handler.type.assign(ruby_string_bytes(ruby_array_entry(pair, 0)));
        typed_handler.handler = mrb_symbol(ruby_array_entry(pair, 1));
        // Resolved here, once, not searched for at every render.
        const Resolved handler = method_resolve(mrb, run.resource.klass, typed_handler.handler);
        typed_handler.m = handler.method;
        typed_handler.irep = handler.irep;
        typed_handler.native = handler.native;
        current.push_back(std::move(typed_handler));
    }
}

int etag_make_sure_it_is_there(Run &run)
{
    if (run.resource.run.etag_asked)
        return -1;
    run.resource.run.etag_asked = true;
    // #202: the class form answered at setup - there is nothing to ask.
    if (run.resource.konst_etag.asked) {
        if (run.resource.konst_etag.present) {
            run.resource.run.etag_value = run.resource.konst_etag.text;
            run.resource.run.etag_present = true;
        }
        return -1;
    }
    if (!run.resource.cb_generate_etag.has)
        return -1;
    // #30: a worker answers this one. If the memo is empty here, no
    // round ever started, and there is nothing to say.
    if (((run.resource.value_jobs | run.resource.value_watch) & (1u << kJobEtag)) != 0)
        return -1;
    mrb_value value = value_callback_call(run, run.resource.cb_generate_etag);
    if (mrb_integer_p(value))
        return halt_status_of(run, value, run.resource.cb_generate_etag.sym);
    if (mrb_nil_p(value) || mrb_false_p(value))
        return -1;
    if (!mrb_string_p(value))
        value = mrb_obj_as_string(run.mrb, value);
    const std::string_view etag = ruby_string_bytes(value);
    http::etag_spell(etag.data(), etag.size(), run.resource.run.etag_value);
    run.resource.run.etag_present = true;
    return -1;
}

void date_field_memo(Run &run, const DateField &date_field)
{
    mrb_state *mrb = run.mrb;
    const Resource::ValueCb &callback = date_field.callback;
    const Resource::KonstValue &konst = date_field.konst;
    if (*date_field.asked)
        return;
    *date_field.asked = true;
    // #202: same as ensure_etag - a class form is a setup answer.
    if (konst.asked) {
        if (konst.present) {
            *date_field.epoch = konst.epoch;
            *date_field.present = true;
        }
        return;
    }
    if (!callback.has)
        return;
    // #30: the same for the two dates - only a round answers one that a
    // worker was declared for.
    const uint8_t what = callback.sym == MRB_SYM(last_modified) ? kJobLastModified : kJobExpires;
    if (((run.resource.value_jobs | run.resource.value_watch) & (1u << what)) != 0)
        return;
    mrb_value value = value_callback_call(run, callback);
    if (mrb_nil_p(value) || mrb_false_p(value))
        return;
    // mruby owns this conversion already: Integer straight through, Time
    // and anything else through #to_i, nil back when the answer is neither.
    // The _check form is the one that returns rather than raises, and it is
    // taken for the message - mruby's own would name the value and #to_i,
    // and never the callback the author has to go and fix.
    const mrb_value count = mrb_type_convert_check(mrb, value, MRB_TT_INTEGER, MRB_SYM(to_i));
    if (mrb_unlikely(mrb_nil_p(count))) {
        mrb_raisef(mrb, E_TYPE_ERROR, "%n must answer a Time or an epoch Integer, not %v",
                   callback.sym, value);
    }
    *date_field.epoch = static_cast<int64_t>(mrb_integer(count));
    *date_field.present = true;
}

int caching_fields_add(Run &run)
{
    // #202: a resource with none of the three answers has nothing to ask
    // for, and o18 asks on every GET. Three calls that could only answer
    // "no" are three calls that do not happen.
    if (!run.resource.has_caching)
        return -1;
    const int headers = etag_make_sure_it_is_there(run);
    if (headers >= 0)
        return headers;
    if (run.resource.run.etag_present) {
        run_append_field(run, {"ETag", run.resource.run.etag_value});
    }
    date_field_memo(run, {run.resource.cb_expires, run.resource.konst_expires,
                          &run.resource.run.expires_asked, &run.resource.run.expires_present,
                          &run.resource.run.expires_epoch});
    if (run.resource.run.expires_present)
        run_append_date_line(run, "Expires", run.resource.run.expires_epoch);
    date_field_memo(run,
                    {run.resource.cb_last_modified, run.resource.konst_last_modified,
                     &run.resource.run.last_modified_asked, &run.resource.run.last_modified_present,
                     &run.resource.run.last_modified_epoch});
    if (run.resource.run.last_modified_present)
        run_append_date_line(run, "Last-Modified", run.resource.run.last_modified_epoch);
    return -1;
}

// #30: one answer of a value round, into the memo the walk reads. The
// walk then meets a value that is already asked, which is exactly what
// it meets when the callback answered on this thread.
void value_round_answer_take(const Resource &resource, uint8_t what, mrb_value value)
{
    mrb_state *const mrb = resource.mrb;
    if (what == kJobEtag) {
        resource.run.etag_asked = true;
        if (mrb_nil_p(value) || mrb_false_p(value))
            return;
        if (!mrb_string_p(value))
            value = mrb_obj_as_string(mrb, value);
        const std::string_view etag = ruby_string_bytes(value);
        http::etag_spell(etag.data(), etag.size(), resource.run.etag_value);
        resource.run.etag_present = true;
        return;
    }
    const bool is_lm = what == kJobLastModified;
    bool *const asked = is_lm ? &resource.run.last_modified_asked : &resource.run.expires_asked;
    bool *const present =
        is_lm ? &resource.run.last_modified_present : &resource.run.expires_present;
    int64_t *const epoch = is_lm ? &resource.run.last_modified_epoch : &resource.run.expires_epoch;
    *asked = true;
    if (mrb_nil_p(value) || mrb_false_p(value))
        return;
    const mrb_value count = mrb_type_convert_check(mrb, value, MRB_TT_INTEGER, MRB_SYM(to_i));
    if (mrb_unlikely(mrb_nil_p(count))) {
        mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer a Time or an epoch Integer, not %v",
                   is_lm ? "last_modified" : "expires", value);
    }
    *epoch = static_cast<int64_t>(mrb_integer(count));
    *present = true;
}

// #30: the round starts here. Every declared value callback is asked
// for its ComputeTask now, and all of them go to the pool together.
// The walk stops once, before the node that needed the first answer.
bool value_round_begin(Run &run, Node n, uint16_t status)
{
    const Resource &resource = run.resource;
    resource.run.values_started = true;
    const struct Want {
        uint8_t what;
        const Resource::ValueCb *callback;
    } wants[] = {{kJobEtag, &resource.cb_generate_etag},
                 {kJobLastModified, &resource.cb_last_modified},
                 {kJobExpires, &resource.cb_expires}};
    uint8_t count = 0;
    uint8_t watchers = 0;
    for (const Want &w : wants) {
        const bool watched = (resource.value_watch & (1u << w.what)) != 0;
        if ((resource.value_jobs & (1u << w.what)) == 0 && !watched)
            continue;
        const mrb_value value = value_callback_call_raw(run, *w.callback);
        // #30: a watcher answers this one. It waits beside the tasks - a
        // descriptor and a worker are two ways to the same round.
        if (watched) {
            if (mrb_unlikely(!mrb_data_p(value) || !value_is_watcher(run.mrb, value))) {
                mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                           "%n is declared `watch` and answered %v - it owes a Webmachine::Watcher",
                           w.callback->sym, value);
            }
            if (mrb_unlikely(!resource.run.can_park)) {
                mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                           "%n answered a Webmachine::Watcher, and this run cannot stop",
                           w.callback->sym);
            }
            resource.run.watch[watchers] = value;
            resource.run.watch_what[watchers] = w.what;
            watchers++;
            continue;
        }
        ComputeTaskAsk call_ask;
        if (mrb_unlikely(!compute_task_read_from_value(run.mrb, value, &call_ask))) {
            mrb_raisef(
                run.mrb, E_WM_ERROR(run.mrb),
                "%n is declared `compute` and answered %v - it owes a Webmachine::ComputeTask",
                w.callback->sym, value);
        }
        // Nobody can park this run, so the block runs here - the same block
        // with the same arguments, and only the waiting is lost.
        if (mrb_unlikely(!resource.run.can_park)) {
            const mrb_value said = mrb_yield_argv(
                run.mrb, call_ask.block, static_cast<mrb_int>(ruby_array_length(call_ask.args)),
                ruby_array_items(call_ask.args));
            value_round_answer_take(resource, w.what, said);
            continue;
        }
        resource.run.compute_task[count] = {call_ask.block, call_ask.args, call_ask.max_runtime,
                                            w.what};
        count++;
    }
    resource.run.watch_count = watchers;
    if (count == 0 && watchers == 0)
        return false;
    resource.run.compute_task_count = count;
    resource.run.stop_node = n;
    resource.run.stop_status = status;
    resource.run.chosen = run.chosen;
    resource.run.stopped = true;
    return true;
}

bool param_find_named(Param cursor, std::string_view &value)
{
    std::string_view list = media_type_params(cursor.incoming);
    while (!list.empty()) {
        const NextParam next = param_take_next(list);
        list = next.rest;
        if (text_is_same_ignoring_case(next.param.name, cursor.name)) {
            value = next.param.value;
            return true;
        }
    }
    return false;
}

// RFC 9110 12.5.1: a type pattern against the type that arrived - */*,
// type/*, or the two tokens themselves. Parameters are not part of this
// question; params_agree is.
bool media_type_pattern_matches(std::string_view pattern, std::string_view arrived)
{
    if (pattern == "*/*")
        return true;
    if (pattern.size() >= 2 && pattern.substr(pattern.size() - 2) == "/*") {
        const size_t slash = arrived.find('/');
        if (slash == std::string_view::npos)
            return false;
        return text_is_same_ignoring_case(pattern.substr(0, pattern.size() - 2),
                                          arrived.substr(0, slash));
    }
    return text_is_same_ignoring_case(pattern, arrived);
}

// RFC 9110 12.5.1: every parameter the offered type names has to be on
// the type that arrived, with the same bytes. A nameless one is a stray
// ';' and names nothing to disagree about.
bool media_params_agree(std::string_view offered, std::string_view arrived)
{
    std::string_view list = media_type_params(offered);
    while (!list.empty()) {
        const NextParam next = param_take_next(list);
        list = next.rest;
        if (next.param.name.empty())
            continue;
        std::string_view found;
        if (!param_find_named({arrived, next.param.name}, found))
            return false;
        if (found != next.param.value)
            return false;
    }
    return true;
}

// `sniff: true` on a content_types_accepted row: do the octets agree
// with the type the head declared? See src/sniff.cpp for the table and
// the rule.
//
// This is the late check, and it is the one that always runs: the row
// is only visible here, when content_types_accepted has answered. A
// resource that writes content_types_accepted on the class gets the
// early check as well, at the first buffer of the body, and that one is
// what saves reading half a gigabyte of a lie.
//
// The first 512 octets are what the table reads. A body in memory has
// them at hand; a body in a file is read once with pread, which is the
// only read this path makes and it is of half a page.
bool sniff_agrees_with_declaration(Run &run, std::string_view declared)
{
    const ReqView *const quality = run.resource.run.req;
    if (quality == nullptr)
        return true;
    char chunk[512];
    std::string_view head;
    if (quality->content != nullptr) {
        head = {quality->content,
                quality->content_len < sizeof(chunk) ? quality->content_len : sizeof(chunk)};
    } else if (quality->content_fd >= 0) {
        const ssize_t read_bytes = ::pread(quality->content_fd, chunk, sizeof(chunk), 0);
        if (read_bytes <= 0)
            return true;
        head = {chunk, static_cast<size_t>(read_bytes)};
    } else {
        return true;
    }
    return sniff::check_declaration(declared, head) != sniff::Verdict::kContradicts;
}

// Does this row ask for the check? The row is [type, handler] and may
// carry a third member, {sniff: true}. Anything else in that place is
// refused by the shape check below, so this only has to read the one
// key it knows.
bool row_asks_for_sniff(mrb_state *mrb, mrb_value pair)
{
    if (ruby_array_length(pair) < 3)
        return false;
    const mrb_value options = ruby_array_entry(pair, 2);
    if (!mrb_hash_p(options))
        return false;
    const mrb_value want = mrb_hash_get(mrb, options, mrb_symbol_value(MRB_SYM(sniff)));
    return mrb_test(want);
}

int accept_negotiate(Run &run)
{
    mrb_state *mrb = run.mrb;
    std::string_view arrived = "application/octet-stream";
    if (run.vals != nullptr && run.vals->content_type != nullptr) {
        arrived = {run.vals->content_type, run.vals->content_type_len};
    }
    const std::string_view arrived_base = media_type_base(arrived);
    if (!run.resource.cb_content_types_accepted.has)
        return 415;
    const mrb_value value = value_callback_call(run, run.resource.cb_content_types_accepted);
    if (mrb_unlikely(!mrb_array_p(value))) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "content_types_accepted must answer [[type, Symbol]] pairs");
    }
    for (size_t j = 0; j < ruby_array_length(value); j++) {
        const mrb_value pair = ruby_array_entry(value, j);
        if (mrb_unlikely(!mrb_array_p(pair) || ruby_array_length(pair) < 2 ||
                         !mrb_string_p(ruby_array_entry(pair, 0)) ||
                         !mrb_symbol_p(ruby_array_entry(pair, 1)))) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_accepted pairs are [String, Symbol]");
        }
        const std::string_view offered = ruby_string_bytes(ruby_array_entry(pair, 0));
        if (!media_type_pattern_matches(media_type_base(offered), arrived_base))
            continue;
        if (!media_params_agree(offered, arrived))
            continue;
        // RFC 9110 8.3: the type is what the head claimed. `sniff: true`
        // asks whether the octets agree with the claim, and 415 is the
        // answer when they do not - the same status an unacceptable type
        // earns, because that is what this is.
        if (mrb_unlikely(row_asks_for_sniff(mrb, pair)) &&
            !sniff_agrees_with_declaration(run, arrived))
            return 415;
        const mrb_sym handler_name = mrb_symbol(ruby_array_entry(pair, 1));
        // #54: this callback is about to get the request body, so it has to
        // have said so. The fold checks every handler a class-level
        // content_types_accepted names; an instance-level one is only
        // readable here, and this is where it is refused.
        if (mrb_unlikely(std::find(run.resource.body_readers.begin(),
                                   run.resource.body_readers.end(),
                                   handler_name) == run.resource.body_readers.end())) {
            mrb_raisef(
                mrb, E_WM_ERROR(mrb),
                "content_types_accepted names %n, and that callback gets the request body - say "
                "`reads_body :%n`",
                handler_name, handler_name);
        }
        const mrb_value answer =
            mrb_funcall_argv(mrb, run.resource.run.live, handler_name, 0, nullptr);
        if (mrb_integer_p(answer))
            return halt_status_of(run, answer, handler_name);
        return -1;
    }
    return 415;
}

int run_node_n11(Run &run)
{
    mrb_state *mrb = run.mrb;
    mrb_value picked = mrb_false_value();
    if (run.resource.cb_post_is_create.has)
        picked = value_callback_call(run, run.resource.cb_post_is_create);
    if (mrb_test(picked)) {
        if (mrb_unlikely(!run.resource.cb_create_path.has)) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "post_is_create? is true but create_path answered nil");
        }
        const mrb_value candidate_path = value_callback_call(run, run.resource.cb_create_path);
        if (mrb_integer_p(candidate_path))
            return halt_status_of(run, candidate_path, run.resource.cb_create_path.sym);
        if (mrb_unlikely(mrb_nil_p(candidate_path))) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "post_is_create? is true but create_path answered nil");
        }
        if (mrb_unlikely(!mrb_string_p(candidate_path))) {
            mrb_raise(mrb, E_TYPE_ERROR, "create_path must answer a String path");
        }
        mrb_value base = mrb_nil_value();
        if (run.resource.cb_base_uri.has)
            base = value_callback_call(run, run.resource.cb_base_uri);
        {
            std::string bound;
            if (mrb_string_p(base)) {
                bound.assign(ruby_string_bytes(base));
            } else {
                bound.assign(run.resource.run.req != nullptr && run.resource.run.req->tls
                                 ? "https://"
                                 : "http://");
                if (run.vals != nullptr && run.vals->host != nullptr) {
                    bound.append(run.vals->host, run.vals->host_len);
                } else {
                    bound.append("localhost");
                }
                bound.push_back('/');
            }
            std::string joined_uri;
            http::uri_join({bound, ruby_string_bytes(candidate_path)}, joined_uri);
            size_t index = 0;
            if (joined_uri.size() >= 8 && joined_uri.compare(0, 4, "http") == 0) {
                const size_t as_string = joined_uri.find("://");
                if (as_string != std::string::npos) {
                    const size_t slot = joined_uri.find('/', as_string + 3);
                    index = slot == std::string::npos ? joined_uri.size() : slot;
                }
            }
            const size_t plen =
                http::path_only(joined_uri.data() + index, joined_uri.size() - index);
            run.resource.run.disp_path.assign(joined_uri.data() + index, plen);
            run.resource.run.disp_set = true;
            request_disp_override(joined_uri.data() + index, plen);
            run_append_field(run, {"Location", joined_uri});
        }
        const int headers = accept_negotiate(run);
        if (headers >= 0)
            return headers;
    } else {
        if (mrb_unlikely(!run.resource.cb_process_post.has)) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "process_post answered false, which is invalid");
        }
        const mrb_value params = value_callback_call(run, run.resource.cb_process_post);
        if (mrb_integer_p(params))
            return halt_status_of(run, params, run.resource.cb_process_post.sym);
        if (mrb_unlikely(!mrb_true_p(params))) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "process_post must answer true or a response code");
        }
    }
    if (run.resource.run.redirect) {
        if (headers_hold_location(run.hdrs))
            return 303;
        mrb_raise(mrb, E_WM_ERROR(mrb), "do_redirect requires a Location header");
    }
    return -1;
}

mrb_value run_engine(mrb_state *mrb, const Resource &resource, bool resuming);

// mruby: the one guarded entry per request. Without a jmpbuf on the
// state a raise reaches mrb_exc_raise with mrb->jmp NULL, which prints
// and calls abort() - so the frame is not optional. mrb_protect_error
// buys it for a C function pointer, with no method lookup and no
// object to construct.
mrb_value run_engine_in_protected_call(mrb_state *mrb, void *user_data)
{
    return run_engine(mrb, *static_cast<const Resource *>(user_data), false);
}

// #80: the same walk, re-entered where it stopped. The instance is
// still here and initialize has already run, so both are skipped - a
// resumed run is the same run, not a second one.
// #30: the answers of a round, and then the walk - both under one frame.
// What a worker said is its own value, and making sense of it is Ruby
// work that can raise.
struct ResumeAsk {
    const Resource *resource;
    const RunRound *round;
};
mrb_value run_resume_in_protected_call(mrb_state *mrb, void *user_data);
mrb_value run_resume_answers_in_protected_call(mrb_state *mrb, void *user_data)
{
    auto *const call_ask = static_cast<ResumeAsk *>(user_data);
    const Resource &resource = *call_ask->resource;
    const RunRound &round = *call_ask->round;
    for (uint8_t i = 0; i < round.n; i++) {
        if (round_at(mrb, round.what, i) == kJobNode) {
            resource.run.answer = round_at(mrb, round.answers, i);
            resource.run.answered = true;
            continue;
        }
        value_round_answer_take(resource, round_at(mrb, round.what, i),
                                round_at(mrb, round.answers, i));
    }
    return run_resume_in_protected_call(mrb, const_cast<Resource *>(&resource));
}

mrb_value run_resume_in_protected_call(mrb_state *mrb, void *user_data)
{
    return run_engine(mrb, *static_cast<const Resource *>(user_data), true);
}

mrb_value run_engine(mrb_state *mrb, const Resource &resource, bool resuming)
{
    // #181: the resource instance belongs to one request. Allocate it and
    // nothing else - mrb_obj_new would search for initialize twice per
    // request (mrb_func_basic_p, then mrb_funcall_argv) to arrive where the
    // fold already stands. The call itself, when one is owed, is below,
    // where the direct-entry path exists.
    //
    // #80: a resumed run keeps the instance it already has. Allocating a
    // second one would throw away everything the first half of the walk
    // wrote on it.
    resource.run.stopped = false;
    if (mrb_likely(!resuming)) {
        resource.run.live = mrb_obj_value(mrb_obj_alloc(mrb, resource.live_tt, resource.klass));
    }
    Run r{mrb,
          resource,
          *resource.run.facts,
          resource.konst.per_method[static_cast<size_t>(resource.run.facts->method)],
          resource.run.vals,
          *resource.run.headers,
          Node::kB13,
          0,
          false,
          0,
          resource.cb_content_types_provided.has};
    const flow::ReqFacts &facts = r.facts;
    const flow::KonstAnswers &k = r.k;
    const http::ReqValues *vals = r.vals;
    std::string &hdrs = r.hdrs;

    // #181: the app's own initialize, entered through the resolved method
    // rather than looked up again. init_needed is false for every resource
    // that did not override Object's - the implicit one is not a reason to
    // run anything.
    if (mrb_unlikely(resource.init_needed && !resuming)) {
        direct_call(r, {resource.init_m, resource.init_irep, nullptr, MRB_SYM(initialize)});
    }

    // cb.rb: the same direct entry as call_direct, for a `def self.x` - the
    // receiver is the class and the frame's class is the class's own, which
    // is where the fold found the method.

    // cb.rb: a value callback - on_class says which receiver, and the method
    // itself came from the fold either way. It used to be searched again per
    // request whenever it lived on the class.

    // flow.rb: one node's callback out of the node tables, either receiver.

    // flow.rb decision_test: any callback may halt with an Integer status.

    // RFC 9110: what one node's callback is handed. webmachine-ruby's
    // signatures decide this, and a method that declared the parameter must
    // not be called with nothing; one that declared none gets nothing.

    // RFC 9110 9.1: this request's method, by name.

    // RFC 9110 9.1: one method-list answer (Array or token String), marshalled
    // once into run_methods.

    // flow.rb b10/b12: include?(request.method) over the marshalled list.

    // RFC 9112 5: field-line = field-name ":" OWS field-value OWS CRLF. A
    // node decides which field it produces; this is the only place that
    // knows how one is spelled, so no node below spells its own.

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

    // #80: where the walk starts. A fresh run starts at the top; a resumed
    // one starts at the node it stopped before, and node_answer hands that
    // node the worker's answer instead of calling its callback.
    Node count = Node::kB13;
    uint16_t status = 0;
    if (mrb_unlikely(resuming)) {
        count = resource.run.stop_node;
        status = resource.run.stop_status;
        r.chosen = resource.run.chosen;
    }
    bool halted = false;
    int &chosen = r.chosen;
    while (!halted) {
        // RFC 9110 6.4: kN11 runs create_path or process_post, and kO14 and
        // kP3 run content_types_accepted. Those three read the request
        // content, and no node above them does - so the walk reaches here
        // on the head alone, and a request refused above never had its body
        // read.
        //
        // #36: the walk stops here while content is still arriving. This
        // stop owes nothing to a worker or to the ring: the connection is
        // already taking the octets, and it makes the round ready again
        // when the last one lands. `resuming` above brings the walk back to
        // this same node.
        //
        // A run that cannot park walks on and reads what arrived - that is
        // the konst tier and the error resource, and neither is called
        // through a frame that could hold a stopped run.
        if (mrb_unlikely(!resource.run.content_seen &&
                         (count == Node::kN11 || count == Node::kO14 || count == Node::kP3))) {
            resource.run.content_seen = true;
            if (mrb_unlikely(resource.run.req != nullptr && !resource.run.req->content_ready &&
                             resource.run.can_park)) {
                resource.run.stop_node = count;
                resource.run.stop_status = status;
                resource.run.chosen = chosen;
                resource.run.wants_body = true;
                resource.run.stopped = true;
                return mrb_nil_value();
            }
        }
        switch (count) {
            case Node::kB12: {
                if (!resource.cb_known_methods.has)
                    break;
                methods_marshal_from_callback(r, resource.cb_known_methods);
                take_edge({count, status, halted}, method_list_holds_this_method(r));
                continue;
            }
            case Node::kB10: {
                if (!resource.cb_allowed_methods.has)
                    break;
                methods_marshal_from_callback(r, resource.cb_allowed_methods);
                const bool accepted = method_list_holds_this_method(r);
                if (!accepted)
                    run_append_allow(r);
                take_edge({count, status, halted}, accepted);
                continue;
            }
            case Node::kB8: {
                if (((resource.dynamic >> static_cast<size_t>(Node::kB8)) & 1) == 0)
                    break;
                const size_t i = static_cast<size_t>(Node::kB8);
                mrb_value answer = mrb_nil_value();
                if (resource.node_argc[i] != 0)
                    answer = node_argument(r, count);
                mrb_value value;
                if (!node_answer(r, count, {&answer, static_cast<size_t>(resource.node_argc[i])},
                                 status, &value)) {
                    return mrb_nil_value();
                }
                if (mrb_true_p(value)) {
                    take_edge({count, status, halted}, true);
                    continue;
                }
                if (mrb_integer_p(value)) {
                    status = halt_status_of(r, value, resource.node_sym[i]);
                    halted = true;
                    continue;
                }
                if (mrb_string_p(value)) {
                    run_append_field(r, {"WWW-Authenticate", ruby_string_bytes(value)});
                }
                status = 401;
                halted = true;
                continue;
            }
            case Node::kB3: {
                if (facts.method != flow::Method::kOptions) {
                    count = Node::kC3;
                    continue;
                }
                if (resource.cb_options.has) {
                    const mrb_value value = value_callback_call(r, resource.cb_options);
                    if (mrb_unlikely(!mrb_hash_p(value))) {
                        mrb_raise(mrb, E_TYPE_ERROR, "options must answer a Hash of header fields");
                    }
                    const mrb_value keys = mrb_hash_keys(mrb, value);
                    for (size_t j = 0; j < ruby_array_length(keys); j++) {
                        const mrb_value key_name = ruby_array_entry(keys, j);
                        const mrb_value field_value = mrb_hash_get(mrb, value, key_name);
                        if (!mrb_string_p(key_name) || !mrb_string_p(field_value))
                            continue;
                        run_append_field(
                            r, {ruby_string_bytes(key_name), ruby_string_bytes(field_value)});
                    }
                } else {
                    run_append_allow(r);
                }
                status = 200;
                halted = true;
                continue;
            }
            case Node::kC3: {
                content_types_marshal(r);
                if (mrb_unlikely(content_types_active(r).empty())) {
                    mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided answered no pairs");
                }
                if (!facts.has_accept) {
                    chosen = 0;
                    if (r.ct_dyn) {
                        resource.run.content_type = content_types_active(r)[0].type;
                    }
                    count = node_after_accept(facts);
                    continue;
                }
                count = Node::kC4;
                continue;
            }
            case Node::kC4: {
                const std::vector<Resource::TypedHandler> &content_types = content_types_active(r);
                int index = -1;
                {
                    std::vector<std::string> names;
                    names.reserve(content_types.size());
                    for (const Resource::TypedHandler &th : content_types)
                        names.push_back(th.type);
                    const std::string_view accept =
                        vals != nullptr ? std::string_view(vals->accept, vals->accept_len)
                                        : std::string_view();
                    index = http::choose_media_type({names, accept});
                }
                if (index < 0) {
                    status = 406;
                    halted = true;
                    continue;
                }
                chosen = index;
                if (index != 0 || r.ct_dyn) {
                    resource.run.content_type = content_types[static_cast<size_t>(index)].type;
                }
                count = node_after_accept(facts);
                continue;
            }
            case Node::kG7: {
                if (resource.cb_variances.has) {
                    const mrb_value value = value_callback_call(r, resource.cb_variances);
                    if (mrb_unlikely(!mrb_array_p(value))) {
                        mrb_raise(mrb, E_TYPE_ERROR, "variances must answer an Array of Strings");
                    }
                    resource.run.variances.clear();
                    for (size_t j = 0; j < ruby_array_length(value); j++) {
                        const mrb_value text = ruby_array_entry(value, j);
                        if (mrb_string_p(text)) {
                            resource.run.variances.emplace_back(ruby_string_bytes(text));
                        }
                    }
                }
                const bool accept_varies = content_types_active(r).size() > 1;
                if (accept_varies || !resource.run.variances.empty()) {
                    run_append_field_list(r, {"Vary", accept_varies ? "Accept" : std::string_view(),
                                              resource.run.variances});
                }
                break;
            }
            case Node::kG11: {
                // #30: the first node that needs a value a worker answers. The
                // whole round starts here, and the walk stops once.
                if (mrb_unlikely((resource.value_jobs | resource.value_watch) != 0 &&
                                 !resource.run.values_started &&
                                 value_round_begin(r, count, status))) {
                    return mrb_nil_value();
                }
                const int headers = etag_make_sure_it_is_there(r);
                if (headers >= 0) {
                    status = static_cast<uint16_t>(headers);
                    halted = true;
                    continue;
                }
                take_edge({count, status, halted},
                          resource.run.etag_present && vals != nullptr &&
                              vals->if_match != nullptr &&
                              http::etag_list_match({{vals->if_match, vals->if_match_len},
                                                     resource.run.etag_value,
                                                     false}));
                continue;
            }
            case Node::kK13: {
                // #30: the first node that needs a value a worker answers. The
                // whole round starts here, and the walk stops once.
                if (mrb_unlikely((resource.value_jobs | resource.value_watch) != 0 &&
                                 !resource.run.values_started &&
                                 value_round_begin(r, count, status))) {
                    return mrb_nil_value();
                }
                const int headers = etag_make_sure_it_is_there(r);
                if (headers >= 0) {
                    status = static_cast<uint16_t>(headers);
                    halted = true;
                    continue;
                }
                {
                    // RFC 9110 5.3: If-None-Match that came on several lines is
                    // one list. Joined only then; the one-pass span serves the rest.
                    std::string_view if_none_match;
                    std::string joined;
                    if (vals != nullptr && vals->if_none_match != nullptr) {
                        if (vals->if_none_match_repeats) {
                            join_repeated_fields(resource.run.req, "if-none-match", ", ", joined);
                            if_none_match = joined;
                        } else {
                            if_none_match = {vals->if_none_match, vals->if_none_match_len};
                        }
                    }
                    take_edge(
                        {count, status, halted},
                        resource.run.etag_present && !if_none_match.empty() &&
                            http::etag_list_match({if_none_match, resource.run.etag_value, true}));
                }
                continue;
            }
            case Node::kH12: {
                // #30: the first node that needs a value a worker answers. The
                // whole round starts here, and the walk stops once.
                if (mrb_unlikely((resource.value_jobs | resource.value_watch) != 0 &&
                                 !resource.run.values_started &&
                                 value_round_begin(r, count, status))) {
                    return mrb_nil_value();
                }
                date_field_memo(r, {resource.cb_last_modified, resource.konst_last_modified,
                                    &resource.run.last_modified_asked,
                                    &resource.run.last_modified_present,
                                    &resource.run.last_modified_epoch});
                take_edge({count, status, halted},
                          resource.run.last_modified_present && vals != nullptr &&
                              resource.run.last_modified_epoch > vals->if_unmodified_since_epoch);
                continue;
            }
            case Node::kL17: {
                // #30: the first node that needs a value a worker answers. The
                // whole round starts here, and the walk stops once.
                if (mrb_unlikely((resource.value_jobs | resource.value_watch) != 0 &&
                                 !resource.run.values_started &&
                                 value_round_begin(r, count, status))) {
                    return mrb_nil_value();
                }
                date_field_memo(r, {resource.cb_last_modified, resource.konst_last_modified,
                                    &resource.run.last_modified_asked,
                                    &resource.run.last_modified_present,
                                    &resource.run.last_modified_epoch});
                take_edge({count, status, halted},
                          !resource.run.last_modified_present || vals == nullptr ||
                              resource.run.last_modified_epoch > vals->if_modified_since_epoch);
                continue;
            }
            case Node::kI4:
            case Node::kK5:
            case Node::kL5: {
                const Resource::ValueCb &callback = count == Node::kL5
                                                        ? resource.cb_moved_temporarily
                                                        : resource.cb_moved_permanently;
                if (!callback.has)
                    break;
                const mrb_value value = value_callback_call(r, callback);
                if (mrb_string_p(value)) {
                    run_append_field(r, {"Location", ruby_string_bytes(value)});
                    status = count == Node::kL5 ? 307 : 301;
                    halted = true;
                    continue;
                }
                if (mrb_integer_p(value)) {
                    status = halt_status_of(r, value, callback.sym);
                    halted = true;
                    continue;
                }
                take_edge({count, status, halted}, false);
                continue;
            }
            case Node::kN11: {
                const int headers = run_node_n11(r);
                if (headers >= 0) {
                    status = static_cast<uint16_t>(headers);
                    halted = true;
                } else {
                    count = Node::kP11;
                }
                continue;
            }
            case Node::kO14:
            case Node::kP3: {
                const size_t i = static_cast<size_t>(count);
                bool conflict;
                if ((resource.dynamic >> i) & 1) {
                    mrb_value value;
                    if (!node_answer(r, count, {}, status, &value))
                        return mrb_nil_value();
                    if (mrb_integer_p(value)) {
                        status = halt_status_of(r, value, resource.node_sym[i]);
                        halted = true;
                        continue;
                    }
                    conflict = mrb_test(value);
                } else {
                    conflict = k.ans[i];
                }
                if (conflict) {
                    status = 409;
                    halted = true;
                    continue;
                }
                const int headers = accept_negotiate(r);
                if (headers >= 0) {
                    status = static_cast<uint16_t>(headers);
                    halted = true;
                } else {
                    count = Node::kP11;
                }
                continue;
            }
            case Node::kO18: {
                if (facts.method == flow::Method::kGet || facts.method == flow::Method::kHead) {
                    // #30: the first node that needs a value a worker answers. The
                    // whole round starts here, and the walk stops once.
                    if (mrb_unlikely((resource.value_jobs | resource.value_watch) != 0 &&
                                     !resource.run.values_started &&
                                     value_round_begin(r, count, status))) {
                        return mrb_nil_value();
                    }
                    const int headers = caching_fields_add(r);
                    if (headers >= 0) {
                        status = static_cast<uint16_t>(headers);
                        halted = true;
                        continue;
                    }
                    const std::vector<Resource::TypedHandler> &content_types =
                        content_types_active(r);
                    const size_t index = static_cast<size_t>(chosen) < content_types.size()
                                             ? static_cast<size_t>(chosen)
                                             : 0;
                    const Resource::TypedHandler &typed_handler = content_types[index];
                    const bool prebuilt = !r.ct_dyn && index == 0 && !resource.dynamic_body;
                    if (prebuilt) {
                        // The writers own this case: the first pair's body sits in the
                        // bundle's prebuilt 200, head and all, and nothing here improves
                        // on it.
                    } else if (typed_handler.has_baked) {
                        // A negotiated pair whose handler is a `def self.` - the answer
                        // was rendered at setup, and o18 is only where it is handed over.
                        resource.run.body->assign(typed_handler.baked);
                        resource.run.have_body = true;
                    } else {
                        mrb_value value;
                        if (!MRB_METHOD_UNDEF_P(typed_handler.m)) {
                            value = direct_call(r, {typed_handler.m, typed_handler.irep,
                                                    typed_handler.native, typed_handler.handler});
                        } else if (r.ct_dyn) {
                            value = mrb_funcall_argv(mrb, resource.run.live, typed_handler.handler,
                                                     0, nullptr);
                        } else {
                            value = mrb_funcall_argv(mrb, mrb_obj_value(resource.klass),
                                                     typed_handler.handler, 0, nullptr);
                        }
                        if (mrb_integer_p(value)) {
                            status = halt_status_of(r, value, typed_handler.handler);
                            halted = true;
                            continue;
                        }
                        if (mrb_unlikely(!mrb_string_p(value))) {
                            mrb_raise(mrb, E_TYPE_ERROR, "the body handler must return a String");
                        }
                        // response.file= and response.error_asset already named the
                        // answer - this String (the handler's own '' by convention) is
                        // dead on arrival, so neither the freeze+register interlock nor
                        // the copy is worth taking. The caller reads run_have_file and
                        // run_asset first and never looks at run_body/run_have_body for
                        // this run.
                        if (!resource.run.have_file && resource.run.asset == nullptr) {
                            const size_t blen = ruby_string_length(value);
                            // Already frozen means the app kept this String, so a second
                            // connection may be holding it too - and the release would
                            // lift a freeze that was not ours. Our own freeze is
                            // therefore also the interlock: one lend per String at a
                            // time, everything else copies.
                            if (resource.run.zc_min != 0 && blen >= resource.run.zc_min &&
                                !mrb_frozen_p(mrb_basic_ptr(value))) {
                                // Frozen so mrb_str_modify cannot realloc the bytes out
                                // from under a send in flight, rooted so the GC cannot
                                // take them; the writer hands the String's own bytes straight to
                                // the kernel.
                                mrb_obj_freeze(mrb, value);
                                mrb_gc_register(mrb, value);
                                resource.run.zc = value;
                                resource.run.zc_have = true;
                                resource.run.body->clear();
                            } else {
                                resource.run.body->assign(ruby_string_bytes(value));
                            }
                            resource.run.have_body = true;
                        }
                    }
                }
                count = Node::kO18b;
                continue;
            }
            case Node::kG8: {
                // RFC 9110 13: g9/g11, h11/h12, i13/k13/j18 and l14/l15/l17 all hang
                // off their own has_*, so a request naming none of the four
                // conditional fields walks g8 -> h10 -> i12 -> l13 -> m16.
                if (!facts.names_a_conditional_field()) {
                    count = Node::kM16;
                    continue;
                }
                break;
            }
            case Node::kO20: {
                take_edge({count, status, halted}, resource.run.have_body);
                continue;
            }
            case Node::kP11: {
                take_edge({count, status, halted}, headers_hold_location(hdrs));
                continue;
            }
            default:
                break;
        }

        const flow::FlowNode &flow_node = flow::kFlow[static_cast<size_t>(count)];
        bool answers;
        if (flow_node.kind == flow::Kind::kRequest) {
            answers = flow::eval_request(count, facts);
        } else if ((resource.dynamic >> static_cast<size_t>(count)) & 1) {
            const size_t i = static_cast<size_t>(count);
            mrb_value answer = mrb_nil_value();
            if (resource.node_argc[i] != 0)
                answer = node_argument(r, count);
            mrb_value value;
            if (!node_answer(r, count, {&answer, static_cast<size_t>(resource.node_argc[i])},
                             status, &value)) {
                return mrb_nil_value();
            }
            // Any callback may answer with an Integer, and then that integer
            // is the response status - webmachine-ruby's own convention.
            if (mrb_unlikely(mrb_integer_p(value))) {
                status = halt_status_of(r, value, resource.node_sym[i]);
                halted = true;
                continue;
            }
            answers = mrb_test(value);
        } else {
            answers = k.ans[static_cast<size_t>(count)];
        }
        edge_take({count, status, halted}, flow_node, answers);
    }

    // fsm.rb respond: a 304 sheds Content-Type at the writer and carries the
    // caching headers; finish_request runs last and may rename the status
    // through response.code=.
    if (status == 304) {
        const int headers = caching_fields_add(r);
        if (headers >= 0)
            status = static_cast<uint16_t>(headers);
    }
    resource.run.resp_code = status;
    resource.run.status = status;
    if (resource.cb_finish_request.has)
        value_callback_call(r, resource.cb_finish_request);
    resource.run.status = resource.run.resp_code;
    return mrb_nil_value();
}
} // namespace

// RFC 9110: fold one resource class - every konst callback asked once,
// every dynamic callback resolved, the class frozen.
namespace
{
constexpr size_t kBoolCount = sizeof(kBools) / sizeof(kBools[0]);

// The steps of resource_fold, in the order they run. Each one reads and
// writes the Resource being folded; the order matters where a later
// step reads what an earlier one decided, and each says so.

// A callback this tree does not honour, a konst-only one written on the
// instance, or a work-only one written on the class: refused by name.
void fold_refuse_misplaced(mrb_state *mrb, mrb_value klass)
{
    for (const NamedSym &cb : kUnhonored) {
        if (mrb_unlikely(method_resolve(mrb, mrb_class(mrb, klass), cb.method_name).defined ||
                         instance_method_is_defined(mrb, klass, cb.method_name))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                       "%s is defined but i18n/charset conversion does not exist in this tree",
                       cb.name);
        }
    }
    for (const NamedSym &cb : kKonstOnly) {
        if (mrb_unlikely(instance_method_is_defined(mrb, klass, cb.method_name))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                       "%s shapes the compiled vectors - declare it konst (def self.%s)", cb.name,
                       cb.name);
        }
    }
    for (const NamedSym &cb : kWorkOnly) {
        if (mrb_unlikely(method_resolve(mrb, mrb_class(mrb, klass), cb.method_name).defined)) {
            mrb_raisef(
                mrb, E_WM_ROUTE_ERROR(mrb),
                "%s does work, so it runs per request - declare it on the instance (def %s), "
                "not on the class: def self.%s would be asked once at setup and never again",
                cb.name, cb.name, cb.name);
        }
    }
}

// The node callbacks: instance ones into the node tables, class-level
// ones asked once, except the ones a compute or watch declaration names.
void fold_node_callbacks(const Folding &fold, Resource &out_value, bool (&ans)[kBoolCount])
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    // #80: a node callback named in `compute` or `watch` is asked per
    // request, on the class, and never folded: its answer is what a
    // worker or a watcher says, and that changes from request to request.
    uint64_t declared = 0;
    for (const mrb_sym list_name : {MRB_IVSYM(computed), MRB_IVSYM(watched)}) {
        const mrb_value list = mrb_iv_get(mrb, klass, list_name);
        const size_t count = mrb_array_p(list) ? ruby_array_length(list) : 0;
        for (size_t i = 0; i < count; i++) {
            const size_t index = node_index_of_callback(mrb_symbol(ruby_array_entry(list, i)));
            if (index < flow::kNodeCount)
                declared |= uint64_t{1} << index;
        }
    }

    for (size_t i = 0; i < kBoolCount; i++) {
        const BoolCb &callback = kBools[i];
        ans[i] = callback.defv;
        const size_t index = static_cast<size_t>(callback.node);
        const Resolved inst = method_resolve(mrb, mrb_class_ptr(klass), callback.method_name);
        if (inst.defined) {
            out_value.dynamic |= uint64_t{1} << index;
            out_value.node_sym[index] = callback.method_name;
            out_value.node_m[index] = inst.method;
            out_value.node_irep[index] = inst.irep;
            out_value.node_native[index] = inst.native;
            out_value.node_argc[index] = callback.maxargs;
            continue;
        }
        // The contract: a class method runs once, at start, and never sees
        // a request. A callback that carries an argument asks about one -
        // the URI, the fields, the type, the length - so it is an instance
        // method, and a class-level one is refused here rather than asked
        // once with nothing in hand. A callback a worker or a descriptor
        // answers runs per request as well, and the compute and watch
        // checks below say so by name.
        if (callback.maxargs > 0 && ((declared >> index) & 1) == 0) {
            const Resolved meta = method_resolve(mrb, mrb_class(mrb, klass), callback.method_name);
            if (mrb_unlikely(meta.defined)) {
                mrb_raisef(
                    mrb, E_WM_ROUTE_ERROR(mrb),
                    "def self.%n takes an argument, so it asks about a request - a class method "
                    "runs once at start and sees none. Write def %n",
                    callback.method_name, callback.method_name);
            }
        }
        callback_ask_bool(fold, {callback.method_name, callback.name}, callback.defv, &ans[i]);
    }

    // flow.rb b8: a value-semantics node - instance method into the node
    // tables, a class-only one as an undef slot the engine funcalls on the class.
    for (const NodeValueCb &cb : kNodeValues) {
        const size_t index = static_cast<size_t>(cb.node);
        const Resolved inst = method_resolve(mrb, mrb_class_ptr(klass), cb.method_name);
        if (inst.defined) {
            out_value.dynamic |= uint64_t{1} << index;
            out_value.node_sym[index] = cb.method_name;
            out_value.node_m[index] = inst.method;
            out_value.node_irep[index] = inst.irep;
            out_value.node_native[index] = inst.native;
            out_value.node_argc[index] = cb.maxargs;
            continue;
        }
        const Resolved meta = method_resolve(mrb, mrb_class(mrb, klass), cb.method_name);
        if (meta.defined) {
            out_value.dynamic |= uint64_t{1} << index;
            out_value.node_sym[index] = cb.method_name;
            out_value.node_m[index] = meta.method;
            out_value.node_irep[index] = meta.irep;
            out_value.node_on_class |= uint64_t{1} << index;
            out_value.node_argc[index] = cb.maxargs;
        }
    }
}

// The value callbacks the compute and watch folds read.
void fold_value_callbacks(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    // cb.rb: the value callbacks; known/allowed/content_types_provided keep their konst
    // twin on the class, everything else may live on either side.
    out_value.cb_known_methods =
        value_callback_resolve(mrb, klass, {MRB_SYM(known_methods), false});
    out_value.cb_allowed_methods =
        value_callback_resolve(mrb, klass, {MRB_SYM(allowed_methods), false});
    out_value.cb_content_types_provided =
        value_callback_resolve(mrb, klass, {MRB_SYM(content_types_provided), false});
    out_value.cb_content_types_accepted =
        value_callback_resolve(mrb, klass, {MRB_SYM(content_types_accepted), true});
    out_value.cb_options = value_callback_resolve(mrb, klass, {MRB_SYM(options), true});
    out_value.cb_variances = value_callback_resolve(mrb, klass, {MRB_SYM(variances), true});
    out_value.cb_generate_etag = value_callback_resolve(mrb, klass, {MRB_SYM(generate_etag), true});
    out_value.cb_last_modified = value_callback_resolve(mrb, klass, {MRB_SYM(last_modified), true});
    out_value.cb_expires = value_callback_resolve(mrb, klass, {MRB_SYM(expires), true});
}

// `compute :name`, checked against what the fold now knows each name is.
void fold_compute_declarations(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    // #30: both folds read those three, so they come after them and
    // before the bake below: a value a worker or a watcher answers is
    // never baked.
    // #80: `compute :is_authorized`. The names were only written down at
    // class body time; here the fold knows what each one is, so here is
    // where every refusal about one is spelled. A compute declaration is a bit beside
    // `dynamic`, so a run reads both in one load and knows before its
    // first VM entry whether this node can stop.
    //
    // A native callback is not refused. It is a function pointer, and both
    // VMs are the same process, so it is the same number on either side.
    // Nothing is dumped or loaded; only the arguments and the answer
    // cross, as CBOR. That is the cheaper crossing, not the impossible
    // one.
    {
        const mrb_value list = mrb_iv_get(mrb, klass, MRB_IVSYM(computed));
        const size_t count = mrb_array_p(list) ? ruby_array_length(list) : 0;
        for (size_t i = 0; i < count; i++) {
            const mrb_sym want = mrb_symbol(ruby_array_entry(list, i));
            const size_t index = node_index_of_callback(want);
            // #30: a value callback. generate_etag, last_modified and expires
            // choose no edge - the flow only reads what they answer - so a
            // round starts all of them at the same time and stops once. They
            // are named here like a node, and they are not one.
            if (index == flow::kNodeCount) {
                uint8_t what = 0;
                const Resource::ValueCb *callback = nullptr;
                if (want == MRB_SYM(generate_etag)) {
                    what = kJobEtag;
                    callback = &out_value.cb_generate_etag;
                } else if (want == MRB_SYM(last_modified)) {
                    what = kJobLastModified;
                    callback = &out_value.cb_last_modified;
                } else if (want == MRB_SYM(expires)) {
                    what = kJobExpires;
                    callback = &out_value.cb_expires;
                }
                if (mrb_unlikely(callback == nullptr)) {
                    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                               "compute :%n names no callback a worker can answer - a node's own "
                               "callback, "
                               "or generate_etag, last_modified or expires",
                               want);
                }
                if (mrb_unlikely(!callback->has)) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "compute :%n, but %n is not defined - write def %n and answer with a "
                        "Webmachine::ComputeTask",
                        want, want, want);
                }
                // The task is built per request, on the instance, with request
                // in reach. Only its block crosses to a worker, dumped once and
                // reused, and the block sees its arguments and nothing else.
                if (mrb_unlikely(callback->on_class)) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "compute :%n, but %n is defined on the class - a class method runs once at "
                        "start, and a task is built per request. Write def %n",
                        want, want, want);
                }
                out_value.value_jobs |= static_cast<uint8_t>(1u << what);
                continue;
            }
            // A declared callback is an instance method: it builds the task
            // per request, with request in reach, and only the block crosses
            // to a worker. The block is dumped once and reused, and it sees
            // its arguments and nothing else. A class-level one never reached
            // the node tables, so it reads as not defined here, and the
            // message names the form to write.
            if (mrb_unlikely((out_value.dynamic & (uint64_t{1} << index)) == 0)) {
                const Resolved meta = method_resolve(mrb, mrb_class(mrb, klass), want);
                if (meta.defined) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "compute :%n, but %n is defined on the class - a class method runs once "
                        "at start, and a task is built per request. Write def %n",
                        want, want, want);
                }
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "compute :%n, but %n is not defined - write def %n and answer with a "
                           "Webmachine::ComputeTask",
                           want, want, want);
            }
            if (mrb_unlikely((out_value.node_on_class & (uint64_t{1} << index)) != 0)) {
                mrb_raisef(
                    mrb, E_WM_ROUTE_ERROR(mrb),
                    "compute :%n, but %n is defined on the class - a class method runs once at "
                    "start, and a task is built per request. Write def %n",
                    want, want, want);
            }
            out_value.compute |= uint64_t{1} << index;
        }
    }
}

// `watch :name`, the same, for a block that runs in this VM.
void fold_watch_declarations(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    // #30: the same fold for `watch`. A watcher's block is never dumped -
    // it runs in this VM, on this thread - so the callback may live on the
    // instance and keep whatever it closed over. Two things are asked: the
    // name is a flow node, and something answers it.
    {
        const mrb_value list = mrb_iv_get(mrb, klass, MRB_IVSYM(watched));
        const size_t count = mrb_array_p(list) ? ruby_array_length(list) : 0;
        for (size_t i = 0; i < count; i++) {
            const mrb_sym want = mrb_symbol(ruby_array_entry(list, i));
            const size_t index = node_index_of_callback(want);
            // #30: a value a watcher answers. The same three the flow only
            // reads - they choose no edge - so they wait together.
            if (index == flow::kNodeCount) {
                uint8_t what = 0;
                const Resource::ValueCb *callback = nullptr;
                if (want == MRB_SYM(generate_etag)) {
                    what = kJobEtag;
                    callback = &out_value.cb_generate_etag;
                } else if (want == MRB_SYM(last_modified)) {
                    what = kJobLastModified;
                    callback = &out_value.cb_last_modified;
                } else if (want == MRB_SYM(expires)) {
                    what = kJobExpires;
                    callback = &out_value.cb_expires;
                }
                if (mrb_unlikely(callback == nullptr)) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "watch :%n names no callback a watcher can hold - a node's own callback, "
                        "or generate_etag, last_modified or expires",
                        want);
                }
                if (mrb_unlikely(!callback->has)) {
                    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                               "watch :%n, but %n is not defined - write it and answer with a "
                               "Webmachine::Watcher",
                               want, want);
                }
                if (mrb_unlikely((out_value.value_jobs & (1u << what)) != 0)) {
                    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                               "%n is declared both `compute` and `watch` - it answers one way or "
                               "the other",
                               want);
                }
                // A watcher's block runs inside the request, in this VM, with
                // request and response in reach. That is the instance's, so the
                // callback is written on the instance.
                if (mrb_unlikely(callback->on_class)) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "watch :%n, but %n is defined on the class - a watcher runs inside the "
                        "request, so write def %n",
                        want, want, want);
                }
                out_value.value_watch |= static_cast<uint8_t>(1u << what);
                continue;
            }
            if (mrb_unlikely((out_value.dynamic & (uint64_t{1} << index)) == 0)) {
                const Resolved meta = method_resolve(mrb, mrb_class(mrb, klass), want);
                if (meta.defined) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "watch :%n, but %n is defined on the class - a watcher runs inside the "
                        "request, so write def %n",
                        want, want, want);
                }
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "watch :%n, but %n is not defined - write def %n and answer with a "
                           "Webmachine::Watcher",
                           want, want, want);
            }
            if (mrb_unlikely((out_value.node_on_class & (uint64_t{1} << index)) != 0)) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "watch :%n, but %n is defined on the class - a watcher runs inside the "
                           "request, so write def %n",
                           want, want, want);
            }
            out_value.watch |= uint64_t{1} << index;
        }
    }
}

// The class forms of the caching answers, the remaining value callbacks,
// and the one mask every run reads instead of sixteen structs.
// RFC 9110 15.5.14: what this resource accepts as a request body. The
// class answers with `def self.max_body`, and the fold asks once.
//
// Three levels hold a limit, and the nearest one answers: this
// resource, then conf.max_body of the application, then
// kMaxBodyDefault. A resource that takes uploads raises its own number
// and leaves every other route of the application where it was.
//
// An instance method of the same name is refused by kKonstOnly: a limit
// asked per request would be read after the head already decided where
// the octets land.
// `sniff: true`, read once while the app is set up.
//
// Only the class form of content_types_accepted can be read here: the
// fold has no request, so an instance method cannot be called. What
// this finds lets the body path refuse a lie at its first buffer. A
// resource that writes content_types_accepted on the instance keeps the
// check - accept_helper runs it - but pays for the whole body first.
void fold_sniff_types(const Folding &fold, Resource &out_value)
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    if (!method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_accepted)).defined)
        return;
    const mrb_value value =
        mrb_funcall_argv(mrb, klass, MRB_SYM(content_types_accepted), 0, nullptr);
    if (!mrb_array_p(value))
        return;
    for (size_t j = 0; j < ruby_array_length(value); j++) {
        const mrb_value pair = ruby_array_entry(value, j);
        if (!mrb_array_p(pair) || ruby_array_length(pair) < 3)
            continue;
        if (!mrb_string_p(ruby_array_entry(pair, 0)))
            continue;
        if (!row_asks_for_sniff(mrb, pair))
            continue;
        const mrb_value type = ruby_array_entry(pair, 0);
        out_value.sniff_types.emplace_back(ruby_string_bytes(type));
    }
}

// #54: `reads_body`, read once while the app is set up.
//
// Every stop this server makes is declared, and waiting for octets is
// a stop. What may be named is the callback a body reaches:
// process_post, create_path, or a handler that content_types_accepted
// points at. The mapping itself never gets a body - it answers which
// handler does - so naming it is refused with the line to write
// instead.
//
// `save: true` says the callback may call request.body.save, and the
// head reads that before the first octet: the body goes to a file
// whatever its size, so the save is a link.
//
// What the fold can check, it checks here. A handler that
// content_types_accepted names is only visible when that callback is
// on the class; when it is on the instance, the handler is checked at
// the moment the flow would hand it a body - see accept_helper.
void fold_body_readers(const Folding &fold, Resource &out_value)
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    const mrb_value named = mrb_iv_get(mrb, klass, MRB_IVSYM(body_readers));
    const mrb_value savers = mrb_iv_get(mrb, klass, MRB_IVSYM(body_savers));
    const size_t count = mrb_array_p(named) ? ruby_array_length(named) : 0;
    const size_t saver_count = mrb_array_p(savers) ? ruby_array_length(savers) : 0;

    for (size_t i = 0; i < count; i++) {
        const mrb_sym want = mrb_symbol(ruby_array_entry(named, i));
        if (want == MRB_SYM(content_types_accepted)) {
            mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                      "content_types_accepted answers the mapping and never gets a body - name the "
                      "handler it points at");
        }
        if (!instance_method_is_defined(mrb, klass, want)) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                       "reads_body names %n, and this resource does not define it", want);
        }
        out_value.body_readers.push_back(want);
    }
    for (size_t i = 0; i < saver_count; i++) {
        out_value.body_savers.push_back(mrb_symbol(ruby_array_entry(savers, i)));
    }
    out_value.saves_body = !out_value.body_savers.empty();

    // The two that are callbacks of the flow itself: a resource that
    // defines one and named nothing gets the line to write.
    struct FlowOwnCallback {
        mrb_sym method_name;
        const char *name;
        uint32_t mask_bit;
    };
    const FlowOwnCallback kOwn[] = {
        {MRB_SYM(process_post), "process_post", Resource::kCbProcessPost},
        {MRB_SYM(create_path), "create_path", Resource::kCbCreatePath}};
    for (const FlowOwnCallback &d : kOwn) {
        if ((out_value.cb_mask & d.mask_bit) == 0)
            continue;
        if (std::find(out_value.body_readers.begin(), out_value.body_readers.end(),
                      d.method_name) != out_value.body_readers.end()) {
            continue;
        }
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s gets the request body, so the run stops for it - say `reads_body :%s`",
                   d.name, d.name);
    }

    // And every handler the class form of content_types_accepted names.
    // An instance-level one is checked per request instead: the fold
    // cannot call it, because it has no request to call it about.
    if (!method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_accepted)).defined)
        return;
    const mrb_value rows =
        mrb_funcall_argv(mrb, klass, MRB_SYM(content_types_accepted), 0, nullptr);
    if (!mrb_array_p(rows))
        return;
    for (size_t j = 0; j < ruby_array_length(rows); j++) {
        const mrb_value pair = ruby_array_entry(rows, j);
        if (!mrb_array_p(pair) || ruby_array_length(pair) < 2 ||
            !mrb_symbol_p(ruby_array_entry(pair, 1)))
            continue;
        const mrb_sym headers = mrb_symbol(ruby_array_entry(pair, 1));
        if (std::find(out_value.body_readers.begin(), out_value.body_readers.end(), headers) !=
            out_value.body_readers.end()) {
            continue;
        }
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "content_types_accepted names %n, and that callback gets the request body - say "
                   "`reads_body :%n`",
                   headers, headers);
    }
}

void fold_body_limit(const Folding &fold, Resource &out_value)
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    const Resolved meta = method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(max_body));
    if (!meta.defined)
        return;
    const mrb_value value = mrb_funcall_argv(mrb, klass, MRB_SYM(max_body), 0, nullptr);
    if (mrb_unlikely(!mrb_fixnum_p(value))) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "max_body answers a whole number of octets");
    }
    const mrb_int count = mrb_fixnum(value);
    if (mrb_unlikely(count < 0 ||
                     static_cast<long long>(count) > static_cast<long long>(kMaxBodyMax))) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "max_body = %i is outside 0..%i octets", count,
                   static_cast<mrb_int>(kMaxBodyMax));
    }
    out_value.max_body = static_cast<long long>(count);
}

void fold_caching_and_mask(const Folding &fold, Resource &out_value)
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    // #202: the class forms of the three caching answers are asked once, now.
    if (((out_value.value_jobs | out_value.value_watch) & (1u << kJobEtag)) == 0) {
        value_bake_at_start(
            fold, {out_value.cb_generate_etag, "generate_etag", true, out_value.konst_etag});
    }
    if (((out_value.value_jobs | out_value.value_watch) & (1u << kJobLastModified)) == 0) {
        value_bake_at_start(fold, {out_value.cb_last_modified, "last_modified", false,
                                   out_value.konst_last_modified});
    }
    if (((out_value.value_jobs | out_value.value_watch) & (1u << kJobExpires)) == 0) {
        value_bake_at_start(fold,
                            {out_value.cb_expires, "expires", false, out_value.konst_expires});
    }
    // A konst that was asked and answered nothing is an answer: the
    // callback behind it is not asked again. So there is something to say
    // only where a konst holds a value, or where no konst was taken and a
    // callback is still there to ask.
    out_value.has_caching =
        out_value.konst_etag.present ||
        (!out_value.konst_etag.asked && out_value.cb_generate_etag.has) ||
        out_value.konst_last_modified.present ||
        (!out_value.konst_last_modified.asked && out_value.cb_last_modified.has) ||
        out_value.konst_expires.present ||
        (!out_value.konst_expires.asked && out_value.cb_expires.has);
    out_value.cb_moved_permanently =
        value_callback_resolve(mrb, klass, {MRB_SYM_Q(moved_permanently), true});
    out_value.cb_moved_temporarily =
        value_callback_resolve(mrb, klass, {MRB_SYM_Q(moved_temporarily), true});
    out_value.cb_post_is_create =
        value_callback_resolve(mrb, klass, {MRB_SYM_Q(post_is_create), true});
    out_value.cb_create_path = value_callback_resolve(mrb, klass, {MRB_SYM(create_path), false});
    out_value.cb_base_uri = value_callback_resolve(mrb, klass, {MRB_SYM(base_uri), true});
    out_value.cb_process_post = value_callback_resolve(mrb, klass, {MRB_SYM(process_post), false});
    out_value.cb_finish_request =
        value_callback_resolve(mrb, klass, {MRB_SYM(finish_request), false});
    // The fast part: one bit per ValueCb above, set once here so every run
    // asks "does X exist" with one load instead of touching X's own struct.
    out_value.cb_mask = 0;
    if (out_value.cb_known_methods.has)
        out_value.cb_mask |= Resource::kCbKnownMethods;
    if (out_value.cb_allowed_methods.has)
        out_value.cb_mask |= Resource::kCbAllowedMethods;
    if (out_value.cb_content_types_provided.has)
        out_value.cb_mask |= Resource::kCbContentTypesProvided;
    if (out_value.cb_content_types_accepted.has)
        out_value.cb_mask |= Resource::kCbContentTypesAccepted;
    if (out_value.cb_options.has)
        out_value.cb_mask |= Resource::kCbOptions;
    if (out_value.cb_variances.has)
        out_value.cb_mask |= Resource::kCbVariances;
    if (out_value.cb_generate_etag.has)
        out_value.cb_mask |= Resource::kCbGenerateEtag;
    if (out_value.cb_last_modified.has)
        out_value.cb_mask |= Resource::kCbLastModified;
    if (out_value.cb_expires.has)
        out_value.cb_mask |= Resource::kCbExpires;
    if (out_value.cb_moved_permanently.has)
        out_value.cb_mask |= Resource::kCbMovedPermanently;
    if (out_value.cb_moved_temporarily.has)
        out_value.cb_mask |= Resource::kCbMovedTemporarily;
    if (out_value.cb_post_is_create.has)
        out_value.cb_mask |= Resource::kCbPostIsCreate;
    if (out_value.cb_create_path.has)
        out_value.cb_mask |= Resource::kCbCreatePath;
    if (out_value.cb_base_uri.has)
        out_value.cb_mask |= Resource::kCbBaseUri;
    if (out_value.cb_process_post.has)
        out_value.cb_mask |= Resource::kCbProcessPost;
    if (out_value.cb_finish_request.has)
        out_value.cb_mask |= Resource::kCbFinishRequest;
    // RFC 9110 6.4: only these three callbacks read the request body, so a
    // resource without them never asks for one. Both writers read this to
    // step over a body rather than keep it.
    //
    // #54: and the resource has to have said so. A run that waits for
    // octets is a stop like any other, and every stop is declared -
    // fold_body_readers refuses a callback that reads a body it never
    // named.
    out_value.takes_body = (out_value.cb_mask & Resource::kCbBodyReaders) != 0;
    // kC3 is a request-kind node: its dynamic bit forces the run tier without
    // touching any konst answer.
    if (out_value.cb_mask != 0)
        out_value.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
}

// content_type, content_types_provided, encodings_provided, and the
// body the fold bakes from the first pair.
void fold_content_types(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    std::string content_type = "text/html";
    {
        const Resolved content_type_callback =
            method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_type));
        if (content_type_callback.defined) {
            const mrb_value value =
                resolved_call(mrb, content_type_callback, {klass, mrb_class(mrb, klass)});
            if (mrb_unlikely(mrb->exc != nullptr))
                rethrow(mrb);
            if (mrb_unlikely(!mrb_string_p(value))) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "content_type must return a String, not %v",
                           value);
            }
            content_type.assign(ruby_string_bytes(value));
            // RFC 9110 8.3 / 12.5.1: a resource that names no media type cannot
            // be negotiated with, and c4 would have nothing to weigh an Accept
            // against. Said here, once, instead of guarded on every request.
            if (mrb_unlikely(content_type.empty())) {
                mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                          "content_type must name a media type, not an empty String");
            }
        }
    }

    // cb.rb content_types_provided: the konst pairs; a class-level answer
    // wins, otherwise [[content_type-or-text/html, :to_html]].
    {
        const Resolved content_types_provided_callback =
            method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_provided));
        if (content_types_provided_callback.defined) {
            const mrb_value value =
                resolved_call(mrb, content_types_provided_callback, {klass, mrb_class(mrb, klass)});
            if (mrb_unlikely(mrb->exc != nullptr))
                rethrow(mrb);
            if (mrb_unlikely(!mrb_array_p(value) || ruby_array_length(value) == 0)) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "content_types_provided must return [[type, handler]] pairs, not %v",
                           value);
            }
            for (size_t j = 0; j < ruby_array_length(value); j++) {
                const mrb_value pair = ruby_array_entry(value, j);
                if (mrb_unlikely(!mrb_array_p(pair) || ruby_array_length(pair) < 2 ||
                                 !mrb_string_p(ruby_array_entry(pair, 0)) ||
                                 !mrb_symbol_p(ruby_array_entry(pair, 1)))) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "content_types_provided pairs are [String, Symbol], and %v is not one",
                        pair);
                }
                Resource::TypedHandler typed_handler;
                typed_handler.type.assign(ruby_string_bytes(ruby_array_entry(pair, 0)));
                typed_handler.handler = mrb_symbol(ruby_array_entry(pair, 1));
                const Resolved handler =
                    method_resolve(mrb, mrb_class_ptr(klass), typed_handler.handler);
                if (handler.defined) {
                    typed_handler.m = handler.method;
                    typed_handler.irep = handler.irep;
                    typed_handler.native = handler.native;
                }
                // cb.rb: the class form is answered once, here - for every pair, not
                // just the first. Asked per request it would be looked up on the
                // instance, where the name may belong to somebody else entirely.
                const Resolved hook =
                    method_resolve(mrb, mrb_class(mrb, klass), typed_handler.handler);
                if (hook.defined) {
                    const mrb_value rendered =
                        resolved_call(mrb, hook, {klass, mrb_class(mrb, klass)});
                    if (mrb_unlikely(mrb->exc != nullptr))
                        rethrow(mrb);
                    if (mrb_unlikely(!mrb_string_p(rendered))) {
                        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%n must return a String, not %v",
                                   typed_handler.handler, rendered);
                    }
                    typed_handler.baked.assign(ruby_string_bytes(rendered));
                    typed_handler.has_baked = true;
                }
                out_value.content_types_provided.push_back(std::move(typed_handler));
            }
        } else {
            Resource::TypedHandler typed_handler;
            typed_handler.type = content_type;
            typed_handler.handler = MRB_SYM(to_html);
            const Resolved handler = method_resolve(mrb, mrb_class_ptr(klass), MRB_SYM(to_html));
            if (handler.defined) {
                typed_handler.m = handler.method;
                typed_handler.irep = handler.irep;
                typed_handler.native = handler.native;
            }
            out_value.content_types_provided.push_back(std::move(typed_handler));
        }
    }

    {
        const Resolved encoded =
            method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(encodings_provided));
        if (encoded.defined) {
            const mrb_value value = resolved_call(mrb, encoded, {klass, mrb_class(mrb, klass)});
            if (mrb_unlikely(mrb->exc != nullptr))
                rethrow(mrb);
            if (mrb_unlikely(!mrb_hash_p(value))) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "encodings_provided must return a Hash, not %v", value);
            }
            out_value.gzip_offered = mrb_hash_key_p(mrb, value, mrb_str_new_lit(mrb, "gzip"));
        }
    }

    // helpers.rb encode_body: the default body path - content_types_provided[0]'s handler
    // pre-renders when it lives on the class, runs per request when it is an
    // instance method.
    {
        const Resource::TypedHandler &first = out_value.content_types_provided[0];
        const Resolved body_k = method_resolve(mrb, mrb_class(mrb, klass), first.handler);
        if (body_k.defined) {
            const mrb_value rendered = resolved_call(mrb, body_k, {klass, mrb_class(mrb, klass)});
            if (mrb_unlikely(mrb->exc != nullptr))
                rethrow(mrb);
            if (mrb_unlikely(!mrb_string_p(rendered))) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%n must return a String, not %v",
                           first.handler, rendered);
            }
            out_value.konst.body.assign(ruby_string_bytes(rendered));
        } else if (!MRB_METHOD_UNDEF_P(first.m)) {
            out_value.dynamic_body = true;
        }
    }
    out_value.konst.content_type = out_value.content_types_provided[0].type;
    // RFC 9110 12.5.1: the fold bakes one body, from content_types_provided[0].
    // A resource offering a second type can be asked for it, and the answer to
    // that is a body the fold never rendered - so it runs.
    if (out_value.content_types_provided.size() > 1) {
        out_value.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
    }
}

// known and allowed methods, the Allow line, and the per-method answer
// tables the walk reads.
void fold_methods_and_tables(const Folding &fold, Resource &out_value,
                             const bool (&ans)[kBoolCount])
{
    MethodFlags known = {true, true, true, true, true, true, false};
    if (!out_value.cb_known_methods.has) {
        ask_methods(fold, {MRB_SYM(known_methods), "known_methods"}, known);
    }
    MethodFlags allowed = {true, true, false, false, false, false, false};
    if (!out_value.cb_allowed_methods.has) {
        ask_methods(fold, {MRB_SYM(allowed_methods), "allowed_methods"}, allowed);
    }

    // RFC 9110 9.3.3 / 9.3.4: n11 and o14/p3 are action nodes, and every action
    // they could take is a callback - process_post, post_is_create?,
    // content_types_accepted. A resource that allows POST or PUT with not one
    // callback defined has only the engine's answer (500 at n11, 415 at p3),
    // and the fold cannot bake an action it will not perform.
    if (out_value.cb_mask == 0 && (allowed[static_cast<size_t>(flow::Method::kPost)] ||
                                   allowed[static_cast<size_t>(flow::Method::kPut)])) {
        out_value.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
    }

    out_value.konst.allow.clear();
    for (size_t method = 0; method < std::size(kMethodName); method++) {
        if (allowed[method]) {
            if (!out_value.konst.allow.empty())
                out_value.konst.allow.append(", ");
            out_value.konst.allow.append(kMethodName[method]);
        }
    }
    for (size_t method = 0; method < kMethodCount; method++) {
        flow::KonstAnswers &k = out_value.konst.per_method[method];
        k.ans[static_cast<size_t>(Node::kB12)] = known[method];
        k.ans[static_cast<size_t>(Node::kB10)] = allowed[method];
        for (size_t i = 0; i < kBoolCount; i++) {
            k.ans[static_cast<size_t>(kBools[i].node)] = ans[i];
        }
    }
    out_value.konst.resolve_shortcuts();
}

} // namespace

void resource_fold(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    const Folding fold = {mrb, klass};
    const ArenaGuard arena(mrb);
    out_value = Resource{};
    out_value.mrb = mrb;

    fold_refuse_misplaced(mrb, klass);
    bool answers[kBoolCount];
    fold_node_callbacks(fold, out_value, answers);
    fold_value_callbacks(mrb, klass, out_value);
    fold_compute_declarations(mrb, klass, out_value);
    fold_watch_declarations(mrb, klass, out_value);
    fold_caching_and_mask(fold, out_value);
    fold_body_limit(fold, out_value);
    fold_body_readers(fold, out_value);
    fold_sniff_types(fold, out_value);
    fold_content_types(mrb, klass, out_value);
    fold_methods_and_tables(fold, out_value, answers);

    out_value.klass = mrb_class_ptr(klass);
    out_value.meta_klass = mrb_class(mrb, klass);
    mrb_obj_freeze(mrb, klass);

    // What building the per-request instance costs, decided once: the
    // allocation's type, and whether the author wrote an initialize at all.
    // Object's is undef'd on Webmachine::Resource (see gem_init), so this is
    // a plain "is it defined" and no longer a comparison against a method
    // every object has.
    out_value.live_tt =
        MRB_INSTANCE_TT(out_value.klass) != 0 ? MRB_INSTANCE_TT(out_value.klass) : MRB_TT_OBJECT;
    const Resolved init = method_resolve(mrb, out_value.klass, MRB_SYM(initialize));
    out_value.init_needed = init.defined;
    out_value.init_m = init.method;
    out_value.init_irep = init.irep;
}

// RFC 9110: decision + render for one request inside one bound frame; the
// respond order is fsm.rb's - halt seeds the code, finish_request may rename
// it, and a raise leaves the exception pending for the error resource.
// #80: what both entries do once the guarded walk has returned - the
// first one and every resumption after it. It was the tail of
// resource_run, and a second caller is exactly the reason it is a
// function now rather than a block of lines copied twice.
struct Thrown {
    mrb_value value;
    mrb_bool raised;
};

uint16_t run_settle(const Resource &resource, RunAnswer out_value, Thrown t)
{
    mrb_state *mrb = resource.mrb;
    const mrb_value thrown = t.value;
    const mrb_bool raised = t.raised;
    uint16_t status = resource.run.resp_code;
    // A raise voids whatever the run lent: the rescue path spells its own
    // body, and a root nobody comes back for outlives the process.
    if (mrb_unlikely(resource.run.zc_have && raised != FALSE)) {
        resource_body_unlend(mrb, resource.run.zc);
        resource.run.zc_have = false;
    }
    if (mrb_unlikely(raised != FALSE)) {
        // fsm.rb: finish_request still runs on the raise path, and it may
        // raise again, so it gets its own guarded frame - the rare path pays
        // for a second one.
        RescueCtx rescue_context = {&resource, thrown};
        mrb_bool again = FALSE;
        const mrb_value second =
            mrb_protect_error(mrb, run_rescue_in_protected_call, &rescue_context, &again);
        // The writer's contract (resource_exception_take): the exception is
        // still pending when this returns, because the error resource is what
        // turns it into words.
        if (again != FALSE) {
            if (mrb_exception_p(second))
                mrb->exc = mrb_obj_ptr(second);
        } else if (mrb_exception_p(thrown)) {
            mrb->exc = mrb_obj_ptr(thrown);
        }
        status = resource.run.resp_code != 0 ? resource.run.resp_code : 500;
    }
    // #80: it stopped. Everything the walk wrote stays in res.run, and the
    // caller takes that struct with it - so nothing here is cleared and
    // the instance is not let go.
    //
    // It is rooted, though: while the run is parked nothing on the VM's
    // stack names the instance or the argument, and a GC between now and
    // the answer would collect both. The register is paired with the
    // unregister in resource_resume, once per park.
    if (mrb_unlikely(resource.run.stopped && raised == FALSE)) {
        mrb_gc_register(mrb, resource.run.live);
        for (uint8_t i = 0; i < resource.run.compute_task_count; i++) {
            mrb_gc_register(mrb, resource.run.compute_task[i].block);
            mrb_gc_register(mrb, resource.run.compute_task[i].args);
        }
        // #30: a watcher waits for its hash. The connection's hash is what
        // roots it, and the caller fills that hash after this returns -
        // with a CBOR encode and a hash that may grow in between, either of
        // which can run the collector. The root is given back where the
        // task's roots are, in resource_resume and resource_abandon.
        for (uint8_t i = 0; i < resource.run.watch_count; i++) {
            mrb_gc_register(mrb, resource.run.watch[i]);
        }
        // The two bindings are the process's "which request is speaking".
        // The reactor answers other connections while this one waits, so
        // they go now and come back in resource_resume.
        request_bind(nullptr);
        response_bind(nullptr);
        return 0;
    }
    request_bind(nullptr);
    response_bind(nullptr);
    resource.run.live = mrb_nil_value();
    resource.run.vals = nullptr;
    resource.run.req = nullptr;
    resource.run.headers = nullptr;
    if (mrb_unlikely(mrb->exc != nullptr)) {
        if (resource.run.zc_have) {
            resource_body_unlend(mrb, resource.run.zc);
            resource.run.zc_have = false;
        }
        *out_value.have_body = false;
        return 500;
    }
    *out_value.have_body = resource.run.have_body;
    resource.run.status = status;
    return status;
}

// #80: is the run this resource holds a stopped one? The reactor asks
// before it does anything else with the connection.
bool run_stopped(const Resource &resource)
{
    return resource.run.stopped;
}

// #80: the walk, re-entered. `answer` is what the worker said, in this
// VM's values - the crossing back happened before this is called. It
// stands in for the declared node's callback, and the graph carries on
// from that node.
//
// A resumed run may stop again: a resource is free to declare two nodes,
// and the second stop is answered exactly like the first.
// #30: what the last run put in userdata is not the next run's. It goes
// before a walk starts, and before a resumed run takes the resource
// back, so no request can read another's.
void resource_forget_userdata(const Resource &resource)
{
    if (!resource.run.userdata_held)
        return;
    mrb_gc_unregister(resource.mrb, resource.run.userdata);
    resource.run.userdata_held = false;
    resource.run.userdata = mrb_undef_value();
}

// #80: a parked run that never resumes: the connection left, or the
// round was refused. Every root run_settle took for the wait is given
// back, and a lent body is returned. The state is empty afterwards.
void resource_abandon(const Resource &resource, Resource::RunState &state)
{
    mrb_state *const mrb = resource.mrb;
    if (state.stopped) {
        mrb_gc_unregister(mrb, state.live);
        for (uint8_t i = 0; i < state.compute_task_count; i++) {
            mrb_gc_unregister(mrb, state.compute_task[i].block);
            mrb_gc_unregister(mrb, state.compute_task[i].args);
        }
        for (uint8_t i = 0; i < state.watch_count; i++) {
            mrb_gc_unregister(mrb, state.watch[i]);
        }
    }
    if (state.userdata_held)
        mrb_gc_unregister(mrb, state.userdata);
    if (state.zc_have)
        resource_body_unlend(mrb, state.zc);
    state = Resource::RunState{};
}

uint16_t resource_resume(const Resource &resource, RunAnswer out_value, const RunRound &round)
{
    mrb_state *mrb = resource.mrb;
    // What the park took away, back: the bindings, and the roots.
    request_bind(resource.run.req);
    response_bind(&resource);
    resource.run.headers = out_value.headers;
    resource.run.body = out_value.body;
    mrb_gc_unregister(mrb, resource.run.live);
    for (uint8_t i = 0; i < resource.run.compute_task_count; i++) {
        mrb_gc_unregister(mrb, resource.run.compute_task[i].block);
        mrb_gc_unregister(mrb, resource.run.compute_task[i].args);
    }
    resource.run.compute_task_count = 0;
    // #30: the hash holds the watcher now, so the root run_settle took
    // for the crossing goes back here.
    for (uint8_t i = 0; i < resource.run.watch_count; i++) {
        mrb_gc_unregister(mrb, resource.run.watch[i]);
    }
    resource.run.watch_count = 0;
    for (Resource::RunState::HeldTask &t : resource.run.compute_task) {
        t.block = mrb_nil_value();
        t.args = mrb_nil_value();
    }
    // Each job of the round into its own place: a node's own callback is
    // the answer the walk takes at that node, and a value goes straight
    // into the memo the walk reads.
    resource.run.answered = false;
    // #30: response.userdata a worker changed. The run reads its own slot
    // after this, and a round of several jobs takes them in job order -
    // the last worker that changed it is the one that speaks.
    for (uint8_t i = 0; i < round.n; i++) {
        if (!round_at(mrb, round.user_have, i))
            continue;
        if (resource.run.userdata_held)
            mrb_gc_unregister(mrb, resource.run.userdata);
        resource.run.userdata = round_at(mrb, round.user, i);
        mrb_gc_register(mrb, resource.run.userdata);
        resource.run.userdata_held = true;
    }
    // A watcher whose block raised answers with the exception. The run
    // raises it as its own, which is what a raise in a callback is.
    for (uint8_t i = 0; i < round.n; i++) {
        if (mrb_exception_p(round_at(mrb, round.answers, i))) {
            resource.run.stopped = false;
            return run_settle(resource, out_value, {round_at(mrb, round.answers, i), TRUE});
        }
    }
    resource.run.stopped = false;
    // The answers go in under the same frame that protects the walk.
    // value_answer asks Ruby what a worker's word means - to_s on an ETag,
    // an Integer for a date - and a worker is free to answer something
    // that has no such meaning. Applied out here that raise had no frame
    // over it: mrb->jmp belongs to main, so it ended the process instead
    // of the request. One block answering [1] for last_modified was enough.
    ResumeAsk ask{&resource, &round};
    mrb_bool raised = FALSE;
    const mrb_value thrown =
        mrb_protect_error(mrb, run_resume_answers_in_protected_call, &ask, &raised);
    return run_settle(resource, out_value, {thrown, raised});
}

uint16_t resource_run(const Resource &resource, RunAsk call_ask, RunAnswer out_value)
{
    mrb_state *mrb = resource.mrb;
    request_bind(call_ask.req);
    response_bind(&resource);
    resource.run.facts = &call_ask.facts;
    resource.run.vals = call_ask.vals;
    resource.run.req = call_ask.req;
    resource.run.can_park = call_ask.can_park;
    resource_forget_userdata(resource);
    resource.run.stopped = false;
    resource.run.answered = false;
    // #36: both belong to one walk. Left set, the next request on this
    // resource would skip the question at the nodes that read content and
    // reach one of them with nothing bound.
    resource.run.wants_body = false;
    resource.run.content_seen = false;
    resource.run.headers = out_value.headers;
    out_value.headers->clear();
    resource.run.body = out_value.body;
    resource.run.have_body = false;
    resource.run.asset = nullptr;
    resource.run.zc_min = call_ask.zc_min;
    resource.run.zc_have = false;
    resource.run.status = 0;
    resource.run.resp_code = 0;
    resource.run.redirect = false;
    resource.run.content_type.clear();
    resource.run.disp_path.clear();
    resource.run.disp_set = false;
    resource.run.have_file = false;
    resource.run.file_bad = false;
    resource.run.etag_asked = false;
    resource.run.etag_present = false;
    resource.run.etag_value.clear();
    resource.run.last_modified_asked = false;
    resource.run.last_modified_present = false;
    resource.run.last_modified_epoch = 0;
    resource.run.expires_asked = false;
    resource.run.expires_present = false;
    resource.run.expires_epoch = 0;
    resource.run.content_types_marshalled = false;
    resource.run.methods.clear();
    resource.run.variances.clear();
    // #30: the value round is this run's to start. Left set by the last
    // run, no later request would ask a watched or computed value.
    resource.run.values_started = false;
    resource.run.watch_count = 0;
    mrb_bool raised = FALSE;
    const mrb_value thrown = mrb_protect_error(mrb, run_engine_in_protected_call,
                                               const_cast<Resource *>(&resource), &raised);
    return run_settle(resource, out_value, {thrown, raised});
}

// The lend window opens here for the caller: the run is over, so the value
// has to leave the Resource - the next request through it resets the slot.
bool resource_body_lent(const Resource &resource, LentBody &out_value)
{
    if (!resource.run.zc_have)
        return false;
    resource.run.zc_have = false;
    out_value.value = resource.run.zc;
    out_value.bytes = ruby_string_bytes(resource.run.zc);
    return true;
}

// response.file, handed over the same way: the run is over, so the name
// leaves the Resource before the next request through it resets the slot.
bool resource_file_wanted(const Resource &resource, WantedFile &out_value)
{
    if (!resource.run.have_file)
        return false;
    resource.run.have_file = false;
    out_value.name = resource.run.file;
    out_value.bad = resource.run.file_bad;
    return true;
}

// And it closes here: unrooted so the GC may take it, and the freeze lifted
// - it was ours for the in-flight window, and Ruby has no #unfreeze.
void resource_body_unlend(mrb_state *mrb, mrb_value value)
{
    mrb_gc_unregister(mrb, value);
    mrb_basic_ptr(value)->frozen = 0;
}

// RFC 9110 15.6.1: the pending exception itself, for the error resource's
// handle_exception (#210) - what an exception says is one decision for
// the server, made in Ruby, not a message some resource already made.
// Rooted in the arena on the way out: clearing mrb->exc unroots it, and
// everything the caller does next allocates.
bool resource_exception_take(const Resource &resource, mrb_value *out_value)
{
    if (resource.mrb->exc == nullptr)
        return false;
    *out_value = mrb_obj_value(resource.mrb->exc);
    resource.mrb->exc = nullptr;
    mrb_gc_protect(resource.mrb, *out_value);
    return true;
}

// mruby: one raise as one error-log record - class, message, backtrace.
void exception_facts(mrb_state *mrb, Raised out_value)
{
    ErrFacts &facts = out_value.facts;
    std::string &backtrace = out_value.backtrace;
    if (mrb->exc == nullptr)
        return;
    const mrb_value exception = mrb_obj_value(mrb->exc);
    facts.exception_class = mrb_obj_classname(mrb, exception);
    facts.exception_class_len = std::strlen(facts.exception_class);
    struct RException *entry = reinterpret_cast<struct RException *>(mrb->exc);
    if (entry->mesg != nullptr && entry->mesg->tt == MRB_TT_STRING) {
        const mrb_value mesg = mrb_obj_value(entry->mesg);
        const std::string_view message = ruby_string_bytes(mesg);
        facts.message = message.data();
        facts.message_len = message.size();
    }
    // Exception#backtrace answers the array; mrb_exc_backtrace is the same
    // function under its Ruby name. A call does not run with a raise
    // pending, so the exception moves out of mrb->exc for the length of it
    // and goes back afterwards: it is still the caller's to report. The
    // protect is because clearing mrb->exc unroots it.
    const int arena = mrb_gc_arena_save(mrb);
    struct RObject *const pending = mrb->exc;
    mrb->exc = nullptr;
    mrb_gc_protect(mrb, exception);
    const mrb_value backtrace_lines =
        mrb_funcall_argv(mrb, exception, MRB_SYM(backtrace), 0, nullptr);
    const bool answered = mrb->exc == nullptr;
    mrb->exc = pending;
    if (answered && mrb_array_p(backtrace_lines)) {
        const size_t count = ruby_array_length(backtrace_lines);
        for (size_t i = 0; i < count; i++) {
            const mrb_value frame = ruby_array_entry(backtrace_lines, i);
            if (!mrb_string_p(frame))
                continue;
            if (!backtrace.empty())
                backtrace.push_back('\n');
            backtrace.append(ruby_string_bytes(frame));
        }
    }
    mrb_gc_arena_restore(mrb, arena);
    facts.backtrace = backtrace.data();
    facts.backtrace_len = backtrace.size();
}

// The public door for a C++ resource callback (#207). The wrapper keeps
// the method callable from Ruby, so an app may subclass and call super.
// The fold records the raw pointer, so the engine never goes through the
// wrapper at all.
void define_native(mrb_state *mrb, struct RClass *klass, Native count)
{
    native_table_of_this_process().push_back(NativeEntry{klass, count.sym, count.fn});
    mrb_define_method_id(mrb, klass, count.sym, native_call_from_ruby, count.aspec);
}
} // namespace webmachine

// #80: `compute :is_authorized` - the resource naming the callbacks a
// worker answers. It only writes the names here; the fold reads them,
// because only the fold knows whether the name is a flow node and
// whether the author defined it on the instance. Refusing here would
// mean resolving the method before the class is finished, and a
// `compute` above the `def` is the ordinary way to write it.
//
// The list lives on the class, so a subclass that says nothing inherits
// nothing: a compute task is a property of the resource that declared it.
mrb_value resource_compute(mrb_state *mrb, mrb_value self)
{
    const mrb_value *names = nullptr;
    mrb_int count = 0;
    mrb_get_args(mrb, "*", &names, &count);
    if (count == 0) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "compute wants the name of a callback, and got none");
    }
    mrb_value list = mrb_iv_get(mrb, self, MRB_IVSYM(computed));
    if (!mrb_array_p(list)) {
        list = mrb_ary_new_capa(mrb, count);
        mrb_iv_set(mrb, self, MRB_IVSYM(computed), list);
    }
    for (mrb_int i = 0; i < count; i++) {
        if (mrb_unlikely(!mrb_symbol_p(names[i]))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "compute wants a symbol, and got %v", names[i]);
        }
        mrb_ary_push(mrb, list, names[i]);
    }
    return self;
}

// #54: `reads_body :process_post` - the resource naming the callbacks
// that get the request body.
//
// Every stop this server makes is declared. `compute` names the
// callbacks a worker answers, `watch` the ones a descriptor answers,
// and this one the callbacks that wait for octets to arrive. Before
// it, a run stopped for the body whenever the fold found one of the
// three callbacks that can read one, and nothing in the resource said
// so.
//
// `save: true` says this callback may call request.body.save. The head
// reads it before the first octet and puts the body in a file even
// when it is small, so the save is a link and never a second write of
// the octets. Without it the save still works and a small body is
// copied, which is the cost this declaration exists to remove.
//
//   reads_body :process_post
//   reads_body :take, save: true
//
// Only the names are written here. The fold reads them, for the reason
// compute has: refusing here would mean resolving the method before
// the class is finished.
mrb_value resource_reads_body(mrb_state *mrb, mrb_value self)
{
    const mrb_value *argv = nullptr;
    mrb_int count = 0;
    mrb_get_args(mrb, "*", &argv, &count);
    // `save: true` arrives as a Hash in the last place. mruby's keyword
    // form wants a table of the names it will accept, and this accepts
    // one, so reading the last argument is the smaller thing.
    bool saves = false;
    if (count != 0 && mrb_hash_p(argv[count - 1])) {
        saves = mrb_test(mrb_hash_get(mrb, argv[count - 1], mrb_symbol_value(MRB_SYM(save))));
        count--;
    }
    if (count == 0) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                  "reads_body wants the name of a callback, and got none");
    }
    mrb_value list = mrb_iv_get(mrb, self, MRB_IVSYM(body_readers));
    if (!mrb_array_p(list)) {
        list = mrb_ary_new_capa(mrb, count);
        mrb_iv_set(mrb, self, MRB_IVSYM(body_readers), list);
    }
    for (mrb_int i = 0; i < count; i++) {
        if (mrb_unlikely(!mrb_symbol_p(argv[i]))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "reads_body wants a symbol, and got %v",
                       argv[i]);
        }
        mrb_ary_push(mrb, list, argv[i]);
        if (saves) {
            mrb_value slot = mrb_iv_get(mrb, self, MRB_IVSYM(body_savers));
            if (!mrb_array_p(slot)) {
                slot = mrb_ary_new_capa(mrb, count);
                mrb_iv_set(mrb, self, MRB_IVSYM(body_savers), slot);
            }
            mrb_ary_push(mrb, slot, argv[i]);
        }
    }
    return self;
}

// #30: `watch :is_authorized?` - the resource naming the callbacks that
// answer with a Webmachine::Watcher. It only writes the names here; the
// fold reads them, for the same reason `compute` does: refusing here
// would mean resolving the method before the class is finished.
mrb_value resource_watch(mrb_state *mrb, mrb_value self)
{
    const mrb_value *names = nullptr;
    mrb_int count = 0;
    mrb_get_args(mrb, "*", &names, &count);
    if (count == 0) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "watch wants the name of a callback, and got none");
    }
    mrb_value list = mrb_iv_get(mrb, self, MRB_IVSYM(watched));
    if (!mrb_array_p(list)) {
        list = mrb_ary_new_capa(mrb, count);
        mrb_iv_set(mrb, self, MRB_IVSYM(watched), list);
    }
    for (mrb_int i = 0; i < count; i++) {
        if (mrb_unlikely(!mrb_symbol_p(names[i]))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "watch wants a symbol, and got %v", names[i]);
        }
        mrb_ary_push(mrb, list, names[i]);
    }
    return self;
}

// #181: a resource instance belongs to one request and the server makes it.
// Ruby may not - a route names the class, and C++ allocates from it with
// mrb_obj_alloc. Without this, Resource.new would fail on the undef'd
// initialize with "undefined method", which says nothing about why.
mrb_value resource_new_refused(mrb_state *mrb, mrb_value self)
{
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "a resource is the server's to build, one per request - name the class in a "
              "route, never an instance");
    return self;
}

extern "C" {
// mruby: the gem's Ruby surface - the base classes and the loop's three doors.
void mrb_webmachine_mruby_gem_init(mrb_state *mrb)
{
    struct RClass *webmachine_module = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
    struct RClass *out_error = mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Error),
                                                         mrb->eStandardError_class);
    mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(ConfigError), out_error);
    mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(RouteError), out_error);
    // mruby: every object carries initialize on the instance, inherited from
    // Object, unless it is undef'd - so "does this resource define one" could
    // never be asked, only "does it differ from Object's". Undef it here and
    // the question becomes the honest one: an initialize on a resource exists
    // exactly when its author wrote it. The fold then stores the resolved
    // method and the run enters it directly; mrb_obj_new is not used at all,
    // because it would search for the same method twice per request.
    // Webmachine::WebsocketResource and SseResource keep theirs: there
    // initialize is the documented open hook, it runs once per connection
    // rather than per request, and sse_open/ws_admit call it unconditionally.
    struct RClass *res_class =
        mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Resource), mrb->object_class);
    mrb_undef_method_id(mrb, res_class, MRB_SYM(initialize));
    mrb_define_class_method_id(mrb, res_class, MRB_SYM(new), resource_new_refused, MRB_ARGS_ANY());
    mrb_define_class_method_id(mrb, res_class, MRB_SYM(compute), resource_compute, MRB_ARGS_ANY());
    mrb_define_class_method_id(mrb, res_class, MRB_SYM(watch), resource_watch, MRB_ARGS_ANY());
    mrb_define_class_method_id(mrb, res_class, MRB_SYM(reads_body), resource_reads_body,
                               MRB_ARGS_ANY());
    webmachine::ws_init(mrb, webmachine_module);
    webmachine::sse_init(mrb, webmachine_module);
    webmachine::application_init(mrb, webmachine_module);
    webmachine::request_init(mrb, webmachine_module);
    webmachine::response_init(mrb, webmachine_module);
    webmachine::watcher_init_class(mrb, webmachine_module);
    webmachine::compute_task_init_class(mrb, webmachine_module);
    webmachine::passwd_init_class(mrb, webmachine_module);
    webmachine::server_init(mrb, webmachine_module);
}

// mruby: nothing outlives the VM here.
void mrb_webmachine_mruby_gem_final(mrb_state *)
{
}
}
