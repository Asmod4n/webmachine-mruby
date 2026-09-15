#include "webmachine.hpp"
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

// RFC 9110 9.1: kOther has no name, so the table stops before it.
constexpr std::string_view kMethodName[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

constexpr size_t kMethodCount = static_cast<size_t>(flow::Method::kOther) + 1;
static_assert(std::size(kMethodName) + 1 == kMethodCount,
              "every flow::Method but kOther has a name");

// An array carries its own width. A `bool x[7]` parameter decays to a
// pointer.
using MethodFlags = std::array<bool, kMethodCount>;

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

// The name travels with the rest, so the funcall fallback cannot use a
// different one.
struct Resolved {
    mrb_method_t method = {};
    mrb_sym method_name = 0;
    bool defined = false;
    bool irep = false;
    NativeCb native = nullptr;
};

// mruby needs both to enter an irep without a second method search.
struct On {
    mrb_value self;
    struct RClass *klass;
};

// The fold copies the answer into the slot, so a request never looks anything
// up. A vector: an app has a handful of these.
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
// registered too.
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

Resolved method_resolve(mrb_state *mrb, struct RClass *klass, mrb_sym method_name)
{
    Resolved run;
    run.method_name = method_name;
    struct RClass *owner = klass;
    run.method = method_unwrap_alias(mrb_method_search_vm(mrb, &owner, method_name));
    run.defined = !MRB_METHOD_UNDEF_P(run.method);
    run.irep = run.defined && !MRB_METHOD_CFUNC_P(run.method);
    if (run.defined && !run.irep)
        run.native = native_body_of(owner, method_name);
    return run;
}

bool instance_method_is_defined(mrb_state *mrb, mrb_value klass, mrb_sym method_name)
{
    return method_resolve(mrb, mrb_class_ptr(klass), method_name).defined;
}

struct Wanted {
    mrb_sym method_name;
    bool class_fallback;
};

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

struct NativeCall {
    NativeCb function;
    mrb_value self;
    mrb_int argc;
    const mrb_value *argv;
};

// A C++ callback may raise. An unguarded raise here would unwind through
// frames that are not ready for it.
mrb_value native_call_in_protected_call(mrb_state *mrb, void *user_data)
{
    const NativeCall *klass = static_cast<const NativeCall *>(user_data);
    return klass->function(mrb, klass->self, klass->argc, klass->argv);
}

// mrb_protect_error returns mrb_obj_value(mrb->exc) and clears it. mrb->exc
// is a struct RObject*, so only an exception object may go there. mrb_obj_ptr
// on an immediate reads its bits as a pointer.
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

struct Folding {
    mrb_state *mrb;
    mrb_value klass;
};

struct Asked {
    mrb_sym method_name;
    const char *name;
};

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

// A `def self.x` answer is kept for the life of the process. The class is
// frozen right after, so the answer cannot go stale. `spell` turns a String
// answer into an ETag (RFC 9110 8.8.3). Without it the answer is read as a
// moment (RFC 9110 5.6.7).
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
        const std::string_view etag = std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)));
        http::etag_spell(etag.data(), etag.size(), out_value.text);
        out_value.present = true;
        return;
    }
    // The _check form returns nil instead of raising. mruby's own TypeError
    // names the value and #to_i, never the callback.
    const mrb_value count = mrb_type_convert_check(mrb, value, MRB_TT_INTEGER, MRB_SYM(to_i));
    if (mrb_unlikely(mrb_nil_p(count))) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%s must answer a Time or an epoch Integer, not %v",
                   bake.name, value);
    }
    out_value.epoch = static_cast<int64_t>(mrb_integer(count));
    out_value.present = true;
}

// RFC 9110 9.1. http::parse_method also reads the request line, so a
// resource's list and a request agree by construction.
void mark_named_methods(const Folding &folding, Asked answer, mrb_value value, MethodFlags &named)
{
    std::string_view rest = std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)));
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
    for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(value)); j++) {
        const mrb_value entry = mrb_ary_entry(value, static_cast<mrb_int>(j));
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

struct NodeValueCb {
    Node node;
    mrb_sym method_name;
    uint8_t maxargs;
};
const NodeValueCb kNodeValues[] = {
    {Node::kB8, MRB_SYM_Q(is_authorized), 1},
};

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

// `def self.x` is asked once at setup and frozen with the class. These four
// do work per request. A class-level process_post would handle zero POSTs. So
// the fold refuses them by name.
const NamedSym kWorkOnly[] = {
    {MRB_SYM(delete_resource), "delete_resource"},
    {MRB_SYM(create_path), "create_path"},
    {MRB_SYM(process_post), "process_post"},
    {MRB_SYM(finish_request), "finish_request"},
};

// RFC 9110 5.1: both sides are folded, because neither is canonical.
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

std::string_view media_type_base(std::string_view value)
{
    return text_trim_optional_space(value.substr(0, value.find(';')));
}

std::string_view media_type_params(std::string_view value)
{
    const size_t semi = value.find(';');
    return semi == std::string_view::npos ? std::string_view{} : value.substr(semi + 1);
}

// RFC 9110 5.6.6: a parameter with no '=' has an empty value. A nameless one
// is a stray ';'.
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

struct RescueCtx {
    const Resource *resource;
    mrb_value exception;
};

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

// A struct rather than locals: the arms off the straight line are functions
// of their own, and this is what they take. `chosen` is written where the
// content type is negotiated and read where the body is produced.
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

const std::vector<Resource::TypedHandler> &content_types_active(Run &run)
{
    return run.ct_dyn ? run.resource.run.content_types_provided
                      : run.resource.content_types_provided;
}

// RFC 9110 5.6.2 / 5.5. This is the only place that spells a field. A raise
// inside the run frame is a 500, which is the answer to a resource that made
// an unspellable one.
void run_append_field(Run &run, http::Field flow_node)
{
    mrb_state *mrb = run.mrb;
    const char *const name = flow_node.name.data();
    const size_t nlen = flow_node.name.size();
    const char *const value = flow_node.value.data();
    const size_t vlen = flow_node.value.size();
    if (mrb_unlikely(http::field_name_is_the_servers(name, nlen))) {
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

// RFC 9110 12.5.2/12.5.3/12.5.4: the conneg node behind d4, e5 and f6 is
// reachable only through its own has_* test. A request that names none walks
// straight to g7.
Node node_after_accept(const flow::ReqFacts &facts)
{
    return facts.has_accept_language || facts.has_accept_charset || facts.has_accept_encoding
               ? Node::kD4
               : Node::kG7;
}

struct At {
    Node &node;
    uint16_t &status;
    bool &halted;
};

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

void take_edge(At index, bool answer)
{
    edge_take(index, flow::kFlow[static_cast<size_t>(index.node)], answer);
}

struct FieldList {
    std::string_view name;
    std::string_view head;
    const std::vector<std::string> &tail;
};

struct DateField {
    const Resource::ValueCb &callback;
    const Resource::KonstValue &konst;
    bool *asked;
    bool *present;
    int64_t *epoch;
};

struct Bound {
    mrb_method_t method;
    bool irep;
    NativeCb native;
    mrb_sym method_name;
};

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
bool value_round_begin(Run &run, Node count, uint16_t status);
void value_round_answer_take(const Resource &resource, uint8_t what, mrb_value value);
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
    // mrb_obj_ptr(self)->c, not mrb_class: mrb_class is an out-of-line call
    // into another translation unit, and this build has no LTO.
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

// Three ways out. The worker's answer is already here, and the memo is
// cleared so the node cannot read it twice. The node is declared `compute`
// and the run may park, so the walk's place is written down and the walk
// returns. Or the callback runs here. A park saves no Ruby stack, because the
// stop is between callbacks.
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
    const mrb_value value = node_call(run, node, args);
    if (mrb_unlikely(((resource.compute >> i) & 1) != 0)) {
        ComputeTaskAsk call_ask;
        if (mrb_unlikely(!compute_task_read_from_value(run.mrb, value, &call_ask))) {
            mrb_raisef(run.mrb, E_WM_ERROR(run.mrb),
                       "%n is declared `compute` and answered %v - it owes a "
                       "Webmachine::ComputeTask",
                       resource.node_sym[i], value);
        }
        // The caller holds no frame that could keep a stopped run, so the
        // block runs here.
        if (mrb_unlikely(!resource.run.can_park)) {
            *out_value = yield_array_entries(run.mrb, call_ask.block, call_ask.args);
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
    // Every object is true. A ComputeTask or a Watcher here would take the
    // true edge without running the block.
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
                for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(keys)); j++) {
                    const mrb_value key_name = mrb_ary_entry(keys, static_cast<mrb_int>(j));
                    if (!mrb_string_p(key_name) || static_cast<size_t>(RSTRING_LEN(key_name)) < 8)
                        continue;
                    if (!http::tok_eq(std::string_view(RSTRING_PTR(key_name), static_cast<size_t>(RSTRING_LEN(key_name))).substr(0, 8), "content-"))
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
            // and the body may still be on the wire.
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
        for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(value)); j++) {
            const mrb_value text = mrb_ary_entry(value, static_cast<mrb_int>(j));
            if (mrb_unlikely(!mrb_string_p(text))) {
                mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer method Strings",
                           mrb_sym_name(mrb, callback.sym));
            }
            run.resource.run.methods.emplace_back(std::string_view(RSTRING_PTR(text), static_cast<size_t>(RSTRING_LEN(text))));
        }
        return;
    }
    if (mrb_unlikely(!mrb_string_p(value))) {
        mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer an Array of Strings or a String",
                   mrb_sym_name(mrb, callback.sym));
    }
    const std::string_view text = std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)));
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
    if (mrb_unlikely(!mrb_array_p(value) || static_cast<size_t>(RARRAY_LEN(value)) == 0)) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "content_types_provided must answer [[type, handler]] pairs");
    }
    const size_t count = static_cast<size_t>(RARRAY_LEN(value));
    // When the answer matches the last one, the vector already holds the
    // resolutions. A pair that is not [String, Symbol] fails to match and
    // falls into the rebuild, which names the refusal.
    std::vector<Resource::TypedHandler> &current = run.resource.run.content_types_provided;
    bool same = current.size() == static_cast<size_t>(count);
    for (size_t j = 0; same && j < count; j++) {
        const mrb_value pair = mrb_ary_entry(value, static_cast<mrb_int>(j));
        same = mrb_array_p(pair) && static_cast<size_t>(RARRAY_LEN(pair)) >= 2 &&
               mrb_string_p(mrb_ary_entry(pair, static_cast<mrb_int>(0))) && mrb_symbol_p(mrb_ary_entry(pair, static_cast<mrb_int>(1))) &&
               mrb_symbol(mrb_ary_entry(pair, static_cast<mrb_int>(1))) == current[static_cast<size_t>(j)].handler &&
               current[static_cast<size_t>(j)].type ==
                   std::string_view(RSTRING_PTR(mrb_ary_entry(pair, static_cast<mrb_int>(0))),
                                    static_cast<size_t>(RSTRING_LEN(
                                        mrb_ary_entry(pair, static_cast<mrb_int>(0)))));
    }
    if (same)
        return;
    current.clear();
    for (size_t j = 0; j < count; j++) {
        const mrb_value pair = mrb_ary_entry(value, static_cast<mrb_int>(j));
        if (mrb_unlikely(!mrb_array_p(pair) || static_cast<size_t>(RARRAY_LEN(pair)) < 2 ||
                         !mrb_string_p(mrb_ary_entry(pair, static_cast<mrb_int>(0))) ||
                         !mrb_symbol_p(mrb_ary_entry(pair, static_cast<mrb_int>(1))))) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided pairs are [String, Symbol]");
        }
        Resource::TypedHandler typed_handler;
        const mrb_value type_name = mrb_ary_entry(pair, static_cast<mrb_int>(0));
        typed_handler.type.assign(RSTRING_PTR(type_name),
                                  static_cast<size_t>(RSTRING_LEN(type_name)));
        typed_handler.handler = mrb_symbol(mrb_ary_entry(pair, static_cast<mrb_int>(1)));
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
    if (run.resource.konst_etag.asked) {
        if (run.resource.konst_etag.present) {
            run.resource.run.etag_value = run.resource.konst_etag.text;
            run.resource.run.etag_present = true;
        }
        return -1;
    }
    if (!run.resource.cb_generate_etag.has)
        return -1;
    // A worker or a watcher answers this one.
    if (((run.resource.value_jobs | run.resource.value_watch) & (1u << kJobEtag)) != 0)
        return -1;
    mrb_value value = value_callback_call(run, run.resource.cb_generate_etag);
    if (mrb_integer_p(value))
        return halt_status_of(run, value, run.resource.cb_generate_etag.sym);
    if (mrb_nil_p(value) || mrb_false_p(value))
        return -1;
    if (!mrb_string_p(value))
        value = mrb_obj_as_string(run.mrb, value);
    const std::string_view etag = std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)));
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
    if (konst.asked) {
        if (konst.present) {
            *date_field.epoch = konst.epoch;
            *date_field.present = true;
        }
        return;
    }
    if (!callback.has)
        return;
    // A worker or a watcher answers this one.
    const uint8_t what = callback.sym == MRB_SYM(last_modified) ? kJobLastModified : kJobExpires;
    if (((run.resource.value_jobs | run.resource.value_watch) & (1u << what)) != 0)
        return;
    mrb_value value = value_callback_call(run, callback);
    if (mrb_nil_p(value) || mrb_false_p(value))
        return;
    // The _check form returns nil instead of raising, so the message can name
    // the callback rather than the value and #to_i.
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

void value_round_answer_take(const Resource &resource, uint8_t what, mrb_value value)
{
    mrb_state *const mrb = resource.mrb;
    if (what == kJobEtag) {
        resource.run.etag_asked = true;
        if (mrb_nil_p(value) || mrb_false_p(value))
            return;
        if (!mrb_string_p(value))
            value = mrb_obj_as_string(mrb, value);
        const std::string_view etag = std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)));
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

// generate_etag, last_modified and expires choose no edge, so the round
// starts every declared one together and the walk stops once.
bool value_round_begin(Run &run, Node length, uint16_t status)
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
        // The caller holds no frame that could keep a stopped run, so the
        // block runs here.
        if (mrb_unlikely(!resource.run.can_park)) {
            const mrb_value said = yield_array_entries(run.mrb, call_ask.block, call_ask.args);
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
    resource.run.stop_node = length;
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

// RFC 9110 12.5.1: every parameter the offered type names has to be on the
// type that arrived, with the same bytes.
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

// See src/sniff.cpp for the table. This is the late check, and it always
// runs: the row is only visible once content_types_accepted has answered. The
// early check, at the first buffer, needs the class form. The table reads the
// first 512 octets, so a file body costs one pread of half a page.
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

bool row_asks_for_sniff(mrb_state *mrb, mrb_value pair)
{
    if (static_cast<size_t>(RARRAY_LEN(pair)) < 3)
        return false;
    const mrb_value options = mrb_ary_entry(pair, static_cast<mrb_int>(2));
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
    for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(value)); j++) {
        const mrb_value pair = mrb_ary_entry(value, static_cast<mrb_int>(j));
        if (mrb_unlikely(!mrb_array_p(pair) || static_cast<size_t>(RARRAY_LEN(pair)) < 2 ||
                         !mrb_string_p(mrb_ary_entry(pair, static_cast<mrb_int>(0))) ||
                         !mrb_symbol_p(mrb_ary_entry(pair, static_cast<mrb_int>(1))))) {
            mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_accepted pairs are [String, Symbol]");
        }
        const mrb_value offered_name = mrb_ary_entry(pair, static_cast<mrb_int>(0));
        const std::string_view offered(RSTRING_PTR(offered_name),
                                       static_cast<size_t>(RSTRING_LEN(offered_name)));
        if (!media_type_pattern_matches(media_type_base(offered), arrived_base))
            continue;
        if (!media_params_agree(offered, arrived))
            continue;
        // RFC 9110 8.3: 415 is the status an unacceptable type earns. A body
        // that contradicts its declared type is that.
        if (mrb_unlikely(row_asks_for_sniff(mrb, pair)) &&
            !sniff_agrees_with_declaration(run, arrived))
            return 415;
        const mrb_sym handler_name = mrb_symbol(mrb_ary_entry(pair, static_cast<mrb_int>(1)));
        // The fold checks the handlers a class-level content_types_accepted
        // names. An instance-level one is only readable here.
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
                bound.assign(std::string_view(RSTRING_PTR(base), static_cast<size_t>(RSTRING_LEN(base))));
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
            http::uri_join({bound, std::string_view(RSTRING_PTR(candidate_path), static_cast<size_t>(RSTRING_LEN(candidate_path)))}, joined_uri);
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

// Without a jmpbuf on the state, a raise reaches mrb_exc_raise with mrb->jmp
// NULL, which prints and calls abort(). mrb_protect_error supplies the frame
// for a C function pointer.
mrb_value run_engine_in_protected_call(mrb_state *mrb, void *user_data)
{
    return run_engine(mrb, *static_cast<const Resource *>(user_data), false);
}

// The answers of a round go in under the same frame as the walk: reading a
// worker's value is Ruby work that can raise.
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
    // mrb_obj_alloc, not mrb_obj_new: mrb_obj_new searches for initialize
    // twice per request. A resumed run keeps its instance. A second one would
    // lose what the first half of the walk wrote.
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

    // init_needed is false for a resource that wrote no initialize. Object's
    // is undef'd in gem_init.
    if (mrb_unlikely(resource.init_needed && !resuming)) {
        direct_call(r, {resource.init_m, resource.init_irep, nullptr, MRB_SYM(initialize)});
    }

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
        // RFC 9110 6.4: n11, o14 and p3 are the first nodes that read the
        // request content, so a request refused above never had its body
        // read. The stop here owes nothing to a worker: the connection makes
        // the round ready when the last octet lands. A run that cannot park
        // reads what arrived.
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
                    run_append_field(r, {"WWW-Authenticate", std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)))});
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
                    for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(keys)); j++) {
                        const mrb_value key_name = mrb_ary_entry(keys, static_cast<mrb_int>(j));
                        const mrb_value field_value = mrb_hash_get(mrb, value, key_name);
                        if (!mrb_string_p(key_name) || !mrb_string_p(field_value))
                            continue;
                        run_append_field(
                            r, {std::string_view(RSTRING_PTR(key_name), static_cast<size_t>(RSTRING_LEN(key_name))), std::string_view(RSTRING_PTR(field_value), static_cast<size_t>(RSTRING_LEN(field_value)))});
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
                    for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(value)); j++) {
                        const mrb_value text = mrb_ary_entry(value, static_cast<mrb_int>(j));
                        if (mrb_string_p(text)) {
                            resource.run.variances.emplace_back(std::string_view(RSTRING_PTR(text), static_cast<size_t>(RSTRING_LEN(text))));
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
                    // RFC 9110 5.3: If-None-Match on several lines is one
                    // list.
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
                    run_append_field(r, {"Location", std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)))});
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
                        // The bundle's prebuilt 200 already carries this
                        // body.
                    } else if (typed_handler.has_baked) {
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
                        // response.file= or response.error_asset already
                        // named the answer, so this String is dead. The
                        // caller reads run_have_file and run_asset first.
                        if (!resource.run.have_file && resource.run.asset == nullptr) {
                            const size_t blen = static_cast<size_t>(RSTRING_LEN(value));
                            // A String the app already froze may be held by a
                            // second connection, and the unlend would lift a
                            // freeze that was not ours. Our own freeze is the
                            // interlock: one lend per String at a time.
                            if (resource.run.zc_min != 0 && blen >= resource.run.zc_min &&
                                !mrb_frozen_p(mrb_basic_ptr(value))) {
                                // Frozen so mrb_str_modify cannot realloc the
                                // bytes under a send in flight. Rooted so the
                                // GC cannot take them.
                                mrb_obj_freeze(mrb, value);
                                mrb_gc_register(mrb, value);
                                resource.run.zc = value;
                                resource.run.zc_have = true;
                                resource.run.body->clear();
                            } else {
                                resource.run.body->assign(std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value))));
                            }
                            resource.run.have_body = true;
                        }
                    }
                }
                count = Node::kO18b;
                continue;
            }
            case Node::kG8: {
                // RFC 9110 13: every conditional node hangs off its own
                // has_*, so a request that names no conditional field walks
                // g8 -> h10 -> i12 -> l13 -> m16.
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
            // webmachine-ruby's convention: an Integer answer is the response
            // status.
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

namespace
{
constexpr size_t kBoolCount = sizeof(kBools) / sizeof(kBools[0]);

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

void fold_node_callbacks(const Folding &fold, Resource &out_value, bool (&ans)[kBoolCount])
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    // A node named in `compute` or `watch` is never folded: its answer
    // changes per request.
    uint64_t declared = 0;
    for (const mrb_sym list_name : {MRB_SYM(computed), MRB_SYM(watched)}) {
        const mrb_value list = mrb_iv_get(mrb, klass, list_name);
        const size_t count = mrb_array_p(list) ? static_cast<size_t>(RARRAY_LEN(list)) : 0;
        for (size_t i = 0; i < count; i++) {
            const size_t index = node_index_of_callback(mrb_symbol(mrb_ary_entry(list, static_cast<mrb_int>(i))));
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

void fold_value_callbacks(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
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

void fold_compute_declarations(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    // A native callback is a function pointer, and both VMs are one process,
    // so it passes.
    {
        const mrb_value list = mrb_iv_get(mrb, klass, MRB_SYM(computed));
        const size_t count = mrb_array_p(list) ? static_cast<size_t>(RARRAY_LEN(list)) : 0;
        for (size_t i = 0; i < count; i++) {
            const mrb_sym want = mrb_symbol(mrb_ary_entry(list, static_cast<mrb_int>(i)));
            const size_t index = node_index_of_callback(want);
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
            // A class-level callback never reached the node tables, so it
            // reads as not defined here. The message names the form to write.
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

void fold_watch_declarations(mrb_state *mrb, mrb_value klass, Resource &out_value)
{
    // A watcher's block runs in this VM, so it may keep what it closed over.
    {
        const mrb_value list = mrb_iv_get(mrb, klass, MRB_SYM(watched));
        const size_t count = mrb_array_p(list) ? static_cast<size_t>(RARRAY_LEN(list)) : 0;
        for (size_t i = 0; i < count; i++) {
            const mrb_sym want = mrb_symbol(mrb_ary_entry(list, static_cast<mrb_int>(i)));
            const size_t index = node_index_of_callback(want);
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

// Three levels hold a body limit, and the nearest answers: this resource,
// then conf.max_body, then kMaxBodyDefault. Only the class form of
// content_types_accepted is readable here: the fold has no request. What this
// finds lets the body path refuse a lie at its first buffer.
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
    for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(value)); j++) {
        const mrb_value pair = mrb_ary_entry(value, static_cast<mrb_int>(j));
        if (!mrb_array_p(pair) || static_cast<size_t>(RARRAY_LEN(pair)) < 3)
            continue;
        if (!mrb_string_p(mrb_ary_entry(pair, static_cast<mrb_int>(0))))
            continue;
        if (!row_asks_for_sniff(mrb, pair))
            continue;
        const mrb_value type = mrb_ary_entry(pair, static_cast<mrb_int>(0));
        out_value.sniff_types.emplace_back(std::string_view(RSTRING_PTR(type), static_cast<size_t>(RSTRING_LEN(type))));
    }
}

// Every stop this server makes is declared, and waiting for octets is a stop.
// `save: true` makes the head put the body in a file whatever its size, so
// the save is a link.
void fold_body_readers(const Folding &fold, Resource &out_value)
{
    mrb_state *const mrb = fold.mrb;
    const mrb_value klass = fold.klass;
    const mrb_value named = mrb_iv_get(mrb, klass, MRB_SYM(body_readers));
    const mrb_value savers = mrb_iv_get(mrb, klass, MRB_SYM(body_savers));
    const size_t count = mrb_array_p(named) ? static_cast<size_t>(RARRAY_LEN(named)) : 0;
    const size_t saver_count = mrb_array_p(savers) ? static_cast<size_t>(RARRAY_LEN(savers)) : 0;

    for (size_t i = 0; i < count; i++) {
        const mrb_sym want = mrb_symbol(mrb_ary_entry(named, static_cast<mrb_int>(i)));
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
        out_value.body_savers.push_back(mrb_symbol(mrb_ary_entry(savers, static_cast<mrb_int>(i))));
    }
    out_value.saves_body = !out_value.body_savers.empty();

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

    // An instance-level content_types_accepted is checked per request: the
    // fold has no request to call it about.
    if (!method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_accepted)).defined)
        return;
    const mrb_value rows =
        mrb_funcall_argv(mrb, klass, MRB_SYM(content_types_accepted), 0, nullptr);
    if (!mrb_array_p(rows))
        return;
    for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(rows)); j++) {
        const mrb_value pair = mrb_ary_entry(rows, static_cast<mrb_int>(j));
        if (!mrb_array_p(pair) || static_cast<size_t>(RARRAY_LEN(pair)) < 2 ||
            !mrb_symbol_p(mrb_ary_entry(pair, static_cast<mrb_int>(1))))
            continue;
        const mrb_sym headers = mrb_symbol(mrb_ary_entry(pair, static_cast<mrb_int>(1)));
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
    // A konst that was asked and answered nothing is an answer: the callback
    // behind it is not asked again.
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
    // RFC 9110 6.4: only the body readers read the request body. Both writers
    // read this to step over a body rather than keep it.
    out_value.takes_body = (out_value.cb_mask & Resource::kCbBodyReaders) != 0;
    // kC3 is a request-kind node: its dynamic bit forces the run tier without
    // touching any konst answer.
    if (out_value.cb_mask != 0)
        out_value.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
}

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
            content_type.assign(std::string_view(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value))));
            // RFC 9110 8.3 / 12.5.1: c4 needs a media type to weigh an Accept
            // against.
            if (mrb_unlikely(content_type.empty())) {
                mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                          "content_type must name a media type, not an empty String");
            }
        }
    }

    {
        const Resolved content_types_provided_callback =
            method_resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_provided));
        if (content_types_provided_callback.defined) {
            const mrb_value value =
                resolved_call(mrb, content_types_provided_callback, {klass, mrb_class(mrb, klass)});
            if (mrb_unlikely(mrb->exc != nullptr))
                rethrow(mrb);
            if (mrb_unlikely(!mrb_array_p(value) || static_cast<size_t>(RARRAY_LEN(value)) == 0)) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "content_types_provided must return [[type, handler]] pairs, not %v",
                           value);
            }
            for (size_t j = 0; j < static_cast<size_t>(RARRAY_LEN(value)); j++) {
                const mrb_value pair = mrb_ary_entry(value, static_cast<mrb_int>(j));
                if (mrb_unlikely(!mrb_array_p(pair) || static_cast<size_t>(RARRAY_LEN(pair)) < 2 ||
                                 !mrb_string_p(mrb_ary_entry(pair, static_cast<mrb_int>(0))) ||
                                 !mrb_symbol_p(mrb_ary_entry(pair, static_cast<mrb_int>(1))))) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "content_types_provided pairs are [String, Symbol], and %v is not one",
                        pair);
                }
                Resource::TypedHandler typed_handler;
                const mrb_value type_name = mrb_ary_entry(pair, static_cast<mrb_int>(0));
                typed_handler.type.assign(RSTRING_PTR(type_name),
                                          static_cast<size_t>(RSTRING_LEN(type_name)));
                typed_handler.handler = mrb_symbol(mrb_ary_entry(pair, static_cast<mrb_int>(1)));
                const Resolved handler =
                    method_resolve(mrb, mrb_class_ptr(klass), typed_handler.handler);
                if (handler.defined) {
                    typed_handler.m = handler.method;
                    typed_handler.irep = handler.irep;
                    typed_handler.native = handler.native;
                }
                // The class form is baked for every pair. Asked per request
                // it would be looked up on the instance, where the name may
                // belong to another method.
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
                    typed_handler.baked.assign(std::string_view(RSTRING_PTR(rendered), static_cast<size_t>(RSTRING_LEN(rendered))));
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
            out_value.konst.body.assign(std::string_view(RSTRING_PTR(rendered), static_cast<size_t>(RSTRING_LEN(rendered))));
        } else if (!MRB_METHOD_UNDEF_P(first.m)) {
            out_value.dynamic_body = true;
        }
    }
    out_value.konst.content_type = out_value.content_types_provided[0].type;
    // The fold bakes one body. A second offered type is a body the fold never
    // rendered, so the run tier answers it.
    if (out_value.content_types_provided.size() > 1) {
        out_value.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);
    }
}

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

    // RFC 9110 9.3.3 / 9.3.4: n11, o14 and p3 act through callbacks. With
    // none defined, only the engine's answer exists (500 at n11, 415 at p3),
    // and the fold cannot bake it.
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

    // Object's initialize is undef'd on Webmachine::Resource (gem_init), so
    // init.defined is true exactly when the author wrote one.
    out_value.live_tt =
        MRB_INSTANCE_TT(out_value.klass) != 0 ? MRB_INSTANCE_TT(out_value.klass) : MRB_TT_OBJECT;
    const Resolved init = method_resolve(mrb, out_value.klass, MRB_SYM(initialize));
    out_value.init_needed = init.defined;
    out_value.init_m = init.method;
    out_value.init_irep = init.irep;
}

struct Thrown {
    mrb_value value;
    mrb_bool raised;
};

uint16_t run_settle(const Resource &resource, RunAnswer out_value, Thrown text)
{
    mrb_state *mrb = resource.mrb;
    const mrb_value thrown = text.value;
    const mrb_bool raised = text.raised;
    uint16_t status = resource.run.resp_code;
    // A raise voids whatever the run lent: the rescue path spells its own
    // body, and a root nobody comes back for outlives the process.
    if (mrb_unlikely(resource.run.zc_have && raised != FALSE)) {
        resource_body_unlend(mrb, resource.run.zc);
        resource.run.zc_have = false;
    }
    if (mrb_unlikely(raised != FALSE)) {
        // finish_request may raise again, so it gets its own guarded frame.
        RescueCtx rescue_context = {&resource, thrown};
        mrb_bool again = FALSE;
        const mrb_value second =
            mrb_protect_error(mrb, run_rescue_in_protected_call, &rescue_context, &again);
        // The exception is still pending when this returns. The error
        // resource turns it into words.
        if (again != FALSE) {
            if (mrb_exception_p(second))
                mrb->exc = mrb_obj_ptr(second);
        } else if (mrb_exception_p(thrown)) {
            mrb->exc = mrb_obj_ptr(thrown);
        }
        status = resource.run.resp_code != 0 ? resource.run.resp_code : 500;
    }
    // While the run is parked, nothing on the VM stack names the instance or
    // the arguments, so a GC would collect them. Each register here pairs
    // with an unregister in resource_resume or resource_abandon.
    if (mrb_unlikely(resource.run.stopped && raised == FALSE)) {
        mrb_gc_register(mrb, resource.run.live);
        for (uint8_t i = 0; i < resource.run.compute_task_count; i++) {
            mrb_gc_register(mrb, resource.run.compute_task[i].block);
            mrb_gc_register(mrb, resource.run.compute_task[i].args);
        }
        // The caller fills the connection's hash after this returns, and a
        // CBOR encode in between can run the collector.
        for (uint8_t i = 0; i < resource.run.watch_count; i++) {
            mrb_gc_register(mrb, resource.run.watch[i]);
        }
        // The reactor answers other connections while this one waits, so the
        // bindings go now and come back in resource_resume.
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

bool run_stopped(const Resource &resource)
{
    return resource.run.stopped;
}

// Userdata goes before a walk starts and before a resumed run takes the
// resource back, so no request reads another's.
void resource_forget_userdata(const Resource &resource)
{
    if (!resource.run.userdata_held)
        return;
    mrb_gc_unregister(resource.mrb, resource.run.userdata);
    resource.run.userdata_held = false;
    resource.run.userdata = mrb_undef_value();
}

// Every root run_settle took for the wait is given back here.
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
    // The hash holds the watcher now, so its root goes back.
    for (uint8_t i = 0; i < resource.run.watch_count; i++) {
        mrb_gc_unregister(mrb, resource.run.watch[i]);
    }
    resource.run.watch_count = 0;
    for (Resource::RunState::HeldTask &t : resource.run.compute_task) {
        t.block = mrb_nil_value();
        t.args = mrb_nil_value();
    }
    resource.run.answered = false;
    // A watcher whose block raised answers with the exception. The run raises
    // it as its own.
    for (uint8_t i = 0; i < round.n; i++) {
        if (mrb_exception_p(round_at(mrb, round.answers, i))) {
            resource.run.stopped = false;
            return run_settle(resource, out_value, {round_at(mrb, round.answers, i), TRUE});
        }
    }
    resource.run.stopped = false;
    // The answers go in under the walk's frame. Reading a worker's value can
    // raise, and outside a frame mrb->jmp belongs to main, so the raise ends
    // the process.
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
    // Left set, the next request on this resource would skip the content
    // question.
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
    // Left set, no later request would ask a watched or computed value.
    resource.run.values_started = false;
    resource.run.watch_count = 0;
    mrb_bool raised = FALSE;
    const mrb_value thrown = mrb_protect_error(mrb, run_engine_in_protected_call,
                                               const_cast<Resource *>(&resource), &raised);
    return run_settle(resource, out_value, {thrown, raised});
}

// The next request through this Resource resets the slot, so the value leaves
// here.
bool resource_body_lent(const Resource &resource, LentBody &out_value)
{
    if (!resource.run.zc_have)
        return false;
    resource.run.zc_have = false;
    out_value.value = resource.run.zc;
    out_value.bytes = std::string_view(RSTRING_PTR(resource.run.zc), static_cast<size_t>(RSTRING_LEN(resource.run.zc)));
    return true;
}

// The next request through this Resource resets the slot, so the name leaves
// here.
bool resource_file_wanted(const Resource &resource, WantedFile &out_value)
{
    if (!resource.run.have_file)
        return false;
    resource.run.have_file = false;
    out_value.name = resource.run.file;
    out_value.bad = resource.run.file_bad;
    return true;
}

// The freeze was ours for the in-flight window, and Ruby has no #unfreeze.
void resource_body_unlend(mrb_state *mrb, mrb_value value)
{
    mrb_gc_unregister(mrb, value);
    mrb_basic_ptr(value)->frozen = 0;
}

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
        const std::string_view message = std::string_view(RSTRING_PTR(mesg), static_cast<size_t>(RSTRING_LEN(mesg)));
        facts.message = message.data();
        facts.message_len = message.size();
    }
    // A call does not run with a raise pending, so the exception leaves
    // mrb->exc for the length of it and goes back afterwards. Clearing
    // mrb->exc unroots it, hence the protect.
    const int arena = mrb_gc_arena_save(mrb);
    struct RObject *const pending = mrb->exc;
    mrb->exc = nullptr;
    mrb_gc_protect(mrb, exception);
    const mrb_value backtrace_lines =
        mrb_funcall_argv(mrb, exception, MRB_SYM(backtrace), 0, nullptr);
    const bool answered = mrb->exc == nullptr;
    mrb->exc = pending;
    if (answered && mrb_array_p(backtrace_lines)) {
        const size_t count = static_cast<size_t>(RARRAY_LEN(backtrace_lines));
        for (size_t i = 0; i < count; i++) {
            const mrb_value frame = mrb_ary_entry(backtrace_lines, static_cast<mrb_int>(i));
            if (!mrb_string_p(frame))
                continue;
            if (!backtrace.empty())
                backtrace.push_back('\n');
            backtrace.append(std::string_view(RSTRING_PTR(frame), static_cast<size_t>(RSTRING_LEN(frame))));
        }
    }
    mrb_gc_arena_restore(mrb, arena);
    facts.backtrace = backtrace.data();
    facts.backtrace_len = backtrace.size();
}

// The wrapper keeps the method callable from Ruby, so an app may subclass and
// call super. The fold records the raw pointer.
void define_native(mrb_state *mrb, struct RClass *klass, Native count)
{
    native_table_of_this_process().push_back(NativeEntry{klass, count.sym, count.fn});
    mrb_define_method_id(mrb, klass, count.sym, native_call_from_ruby, count.aspec);
}
} // namespace webmachine

// Only the names are written here. The fold reads them: a refusal here would
// resolve the method before the class is finished, and a `compute` above the
// `def` is the ordinary way to write it. The list lives on the class, so a
// subclass that says nothing inherits nothing.
mrb_value resource_compute(mrb_state *mrb, mrb_value self)
{
    const mrb_value *names = nullptr;
    mrb_int count = 0;
    mrb_get_args(mrb, "*", &names, &count);
    if (count == 0) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "compute wants the name of a callback, and got none");
    }
    mrb_value list = mrb_iv_get(mrb, self, MRB_SYM(computed));
    if (!mrb_array_p(list)) {
        list = mrb_ary_new_capa(mrb, count);
        mrb_iv_set(mrb, self, MRB_SYM(computed), list);
    }
    for (mrb_int i = 0; i < count; i++) {
        if (mrb_unlikely(!mrb_symbol_p(names[i]))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "compute wants a symbol, and got %v", names[i]);
        }
        mrb_ary_push(mrb, list, names[i]);
    }
    return self;
}

// Only the names are written here. The fold reads them, for the reason
// `compute` has. `save: true` makes the head put the body in a file before
// the first octet, so request.body.save is a link.
mrb_value resource_reads_body(mrb_state *mrb, mrb_value self)
{
    const mrb_value *argv = nullptr;
    mrb_int count = 0;
    mrb_get_args(mrb, "*", &argv, &count);
    // mruby's keyword form wants a table of accepted names. This accepts one,
    // so reading the last argument is smaller.
    bool saves = false;
    if (count != 0 && mrb_hash_p(argv[count - 1])) {
        saves = mrb_test(mrb_hash_get(mrb, argv[count - 1], mrb_symbol_value(MRB_SYM(save))));
        count--;
    }
    if (count == 0) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                  "reads_body wants the name of a callback, and got none");
    }
    mrb_value list = mrb_iv_get(mrb, self, MRB_SYM(body_readers));
    if (!mrb_array_p(list)) {
        list = mrb_ary_new_capa(mrb, count);
        mrb_iv_set(mrb, self, MRB_SYM(body_readers), list);
    }
    for (mrb_int i = 0; i < count; i++) {
        if (mrb_unlikely(!mrb_symbol_p(argv[i]))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "reads_body wants a symbol, and got %v",
                       argv[i]);
        }
        mrb_ary_push(mrb, list, argv[i]);
        if (saves) {
            mrb_value slot = mrb_iv_get(mrb, self, MRB_SYM(body_savers));
            if (!mrb_array_p(slot)) {
                slot = mrb_ary_new_capa(mrb, count);
                mrb_iv_set(mrb, self, MRB_SYM(body_savers), slot);
            }
            mrb_ary_push(mrb, slot, argv[i]);
        }
    }
    return self;
}

// Only the names are written here. The fold reads them, for the reason
// `compute` has.
mrb_value resource_watch(mrb_state *mrb, mrb_value self)
{
    const mrb_value *names = nullptr;
    mrb_int count = 0;
    mrb_get_args(mrb, "*", &names, &count);
    if (count == 0) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "watch wants the name of a callback, and got none");
    }
    mrb_value list = mrb_iv_get(mrb, self, MRB_SYM(watched));
    if (!mrb_array_p(list)) {
        list = mrb_ary_new_capa(mrb, count);
        mrb_iv_set(mrb, self, MRB_SYM(watched), list);
    }
    for (mrb_int i = 0; i < count; i++) {
        if (mrb_unlikely(!mrb_symbol_p(names[i]))) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "watch wants a symbol, and got %v", names[i]);
        }
        mrb_ary_push(mrb, list, names[i]);
    }
    return self;
}

// A route names the class, and C++ allocates from it with mrb_obj_alloc.
// Without this, Resource.new fails on the undef'd initialize with a message
// that says nothing about why.
mrb_value resource_new_refused(mrb_state *mrb, mrb_value self)
{
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "a resource is the server's to build, one per request - name the class in a "
              "route, never an instance");
    return self;
}

extern "C" {
void mrb_webmachine_mruby_gem_init(mrb_state *mrb)
{
    struct RClass *webmachine_module = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
    struct RClass *out_error = mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Error),
                                                         mrb->eStandardError_class);
    mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(ConfigError), out_error);
    mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(RouteError), out_error);
    // Every object inherits initialize from Object unless it is undef'd, so
    // 'does this resource define one' could only be asked as 'does it differ
    // from Object's'. Undef'd here, an initialize exists exactly when the
    // author wrote it. WebsocketResource and SseResource keep theirs: there
    // initialize is the open hook, once per connection.
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

void mrb_webmachine_mruby_gem_final(mrb_state *)
{
}
}
