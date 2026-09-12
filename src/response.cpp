#include "webmachine.hpp"

#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <string>

namespace webmachine
{
namespace
{

// RFC 9110: this run's Resource, or nothing between runs - exactly
// request.cpp's view_, and set the same way by response_bind below.
const Resource *live_resource_ = nullptr;

// #210: the error assets of this server, or nothing when it found
// none. Bound once at setup by response_bind_error_assets, never per
// run - the zip is open for the server's whole life.
Assets *error_assets_ = nullptr;

// Neither class owns anything: the data pointer is a view over the
// C++ buffers response_bind points cur_ at, never allocated storage of
// its own - so a handle that outlives its run is inert, not dangling.
const struct mrb_data_type kResponseDataType = {"Webmachine::Response", nullptr};
const struct mrb_data_type kHeadersDataType = {"Webmachine::Response::Headers", nullptr};

// RFC 9110: the run a response method is answering for, or a named
// refusal when nothing is being answered right now.
const Resource *resource_of_the_live_run(mrb_state *mrb)
{
    if (live_resource_ == nullptr) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "response outside a run frame");
    }
    return live_resource_;
}

// RFC 9110 6.3: same as live(), plus the field-line buffer a Headers
// method needs - run_headers is null between runs even when cur_ is not.
const Resource *resource_with_a_header_buffer(mrb_state *mrb)
{
    const Resource *r = resource_of_the_live_run(mrb);
    if (r->run.headers == nullptr) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "response.headers: no header buffer is bound for this run");
    }
    return r;
}

// RFC 9110 5.1: header names compare case-insensitively; the query name
// is not a compile-time literal, so it is lowered once here and handed
// to http::tok_eq as the (now lowercase) literal side of the compare.
void lowercase_into(std::string &out, const char *p, size_t n)
{
    out.assign(p, n);
    for (char &c : out) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + 32);
    }
}

// One "Name: Value\r\n" line's spans within the run's header buffer.
struct FieldLine {
    size_t start = 0; // the name's first byte
    size_t end = 0;   // one past the trailing '\n'
    size_t name_len = 0;
    size_t val_off = 0;
    size_t val_len = 0;
};

// RFC 9110 6.3: the next field line at or after `pos`; false at the end
// of the buffer (or on a buffer this code did not itself write).
bool read_field_line_at(std::string_view buf, size_t pos, FieldLine &out)
{
    if (pos >= buf.size())
        return false;
    const size_t colon = buf.find(':', pos);
    const size_t eol = buf.find("\r\n", pos);
    if (colon == std::string_view::npos || eol == std::string_view::npos || colon > eol) {
        return false;
    }
    out.start = pos;
    out.name_len = colon - pos;
    size_t val_off = colon + 1;
    if (val_off < eol && buf[val_off] == ' ')
        val_off++;
    out.val_off = val_off;
    out.val_len = eol - val_off;
    out.end = eol + 2;
    return true;
}

// RFC 9110 6.3: the first line named `name`, case-insensitively.
bool find_field_line_named(std::string_view buf, std::string_view name, FieldLine &out)
{
    std::string lowered;
    lowercase_into(lowered, name.data(), name.size());
    FieldLine h;
    size_t pos = 0;
    while (read_field_line_at(buf, pos, h)) {
        if (http::tok_eq({buf.data() + h.start, h.name_len}, lowered)) {
            out = h;
            return true;
        }
        pos = h.end;
    }
    return false;
}

// RFC 9110 6.3: append one field line - the only place a line is spelled,
// so every writer below goes through it.
void append_field_line(std::string &buf, http::Field f)
{
    buf.append(f.name);
    buf.append(": ", 2);
    buf.append(f.value);
    buf.append("\r\n", 2);
}

// RFC 9110 6.3: Headers#[] - one field, by name, case-insensitively.
//: (String) -> (String | NilClass)
mrb_value headers_field_value(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_with_a_header_buffer(mrb);
    const char *k;
    mrb_int klen;
    mrb_get_args(mrb, "s", &k, &klen);
    FieldLine h;
    if (!find_field_line_named(*r->run.headers, {k, static_cast<size_t>(klen)}, h))
        return mrb_nil_value();
    return mrb_str_new(mrb, r->run.headers->data() + h.val_off, h.val_len);
}

// RFC 9110 6.3: Headers#[]= - a String replaces the line of the same
// name (cut it, append the fresh one) or appends a new one; nil deletes
// it. Anything else is refused by type, not silently dropped.
//: (String, String) -> String
mrb_value headers_set_field(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_with_a_header_buffer(mrb);
    const char *k;
    mrb_int klen;
    mrb_value v;
    mrb_get_args(mrb, "so", &k, &klen, &v);
    std::string &buf = *r->run.headers;
    FieldLine h;
    const bool found = find_field_line_named(buf, {k, static_cast<size_t>(klen)}, h);
    if (mrb_nil_p(v)) {
        if (found)
            buf.erase(h.start, h.end - h.start);
        return v;
    }
    if (!mrb_string_p(v)) {
        mrb_raise(mrb, E_TYPE_ERROR, "response.headers[]= takes a String value, or nil to delete");
    }
    if (!http::field_name_ok(k, static_cast<size_t>(klen))) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "response.headers[]= wants a field name that is a token "
                  "(RFC 9110 5.6.2) - no spaces, no colon, no CR or LF");
    }
    if (!http::field_value_ok(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)))) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "response.headers[]= wants a field value without CR, LF or NUL (RFC 9110 5.5)");
    }
    if (http::field_name_is_the_servers(k, static_cast<size_t>(klen))) {
        mrb_raisef(mrb, E_WM_ERROR(mrb),
                   "response.headers[]= may not set %s - the server spells the framing and the "
                   "connection fields itself, and a second copy is what a proxy in front of it "
                   "reads differently",
                   k);
    }
    if (found)
        buf.erase(h.start, h.end - h.start);
    append_field_line(buf, {{k, static_cast<size_t>(klen)},
                            {RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v))}});
    return v;
}

// RFC 9110 6.3: Headers#key? - is the field there at all?
//: (String) -> (TrueClass | FalseClass)
mrb_value headers_has_field(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_with_a_header_buffer(mrb);
    const char *k;
    mrb_int klen;
    mrb_get_args(mrb, "s", &k, &klen);
    FieldLine h;
    return mrb_bool_value(
        find_field_line_named(*r->run.headers, {k, static_cast<size_t>(klen)}, h));
}

// RFC 9110 6.3: Headers#delete - cut the line, hand back the value it held.
//: (String) -> (String | NilClass)
mrb_value headers_delete_field(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_with_a_header_buffer(mrb);
    const char *k;
    mrb_int klen;
    mrb_get_args(mrb, "s", &k, &klen);
    std::string &buf = *r->run.headers;
    FieldLine h;
    if (!find_field_line_named(buf, {k, static_cast<size_t>(klen)}, h))
        return mrb_nil_value();
    const mrb_value old = mrb_str_new(mrb, buf.data() + h.val_off, h.val_len);
    buf.erase(h.start, h.end - h.start);
    return old;
}

// RFC 9110: Response#headers - the Headers handle is built fresh on
// Every call, never memoised: there is no Ruby Hash behind it, only
// this view over the run's own line buffer.
//: () -> Webmachine::Response::Headers
mrb_value response_headers(mrb_state *mrb, mrb_value self)
{
    resource_of_the_live_run(mrb);
    struct RClass *h = mrb_class_get_under_id(mrb, mrb_class(mrb, self), MRB_SYM(Headers));
    return mrb_obj_value(
        mrb_data_object_alloc(mrb, h, const_cast<Resource *>(live_resource_), &kHeadersDataType));
}

// RFC 9110 15: the status a callback named, or nil while the graph
// still owns the answer (0 = unset).
//: () -> (Integer | NilClass)
mrb_value response_status_code(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    return r->run.resp_code == 0 ? mrb_nil_value() : mrb_fixnum_value(r->run.resp_code);
}

// RFC 9110 15: a callback naming the status itself.
//: (Integer) -> Integer
mrb_value response_set_code(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    mrb_int v;
    mrb_get_args(mrb, "i", &v);
    // RFC 9110 15: a status code is three digits, 100 through 599.
    if (v < 100 || v > 599) {
        mrb_raisef(
            mrb, E_ARGUMENT_ERROR,
            "response.code=: %i is not a status code, which is 100 through 599 (RFC 9110 15)", v);
    }
    r->run.resp_code = static_cast<uint16_t>(v);
    return mrb_fixnum_value(v);
}

// RFC 9110 6.4: the representation a callback built, or nil.
//: () -> (String | NilClass)
mrb_value response_body_value(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    if (!r->run.have_body || r->run.body == nullptr)
        return mrb_nil_value();
    return mrb_str_new(mrb, r->run.body->data(), r->run.body->size());
}

// RFC 9110 6.4: a callback handing the representation over (String), or
// clearing it (nil).
//: (String) -> (String | NilClass)
mrb_value response_set_body(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    mrb_value v;
    mrb_get_args(mrb, "o", &v);
    if (mrb_nil_p(v)) {
        r->run.have_body = false;
        return v;
    }
    if (!mrb_string_p(v)) {
        mrb_raise(mrb, E_TYPE_ERROR, "response.body= takes a String, or nil to clear it");
    }
    if (r->run.body == nullptr) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "response.body=: no body buffer is bound for this run");
    }
    r->run.body->assign(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
    r->run.have_body = true;
    return v;
}

// The file a callback named, or nil.
//: () -> (String | NilClass)
mrb_value response_file_name(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    if (!r->run.have_file)
        return mrb_nil_value();
    return mrb_str_new(mrb, r->run.file.data(), r->run.file.size());
}

// response.file = "rel/path": the name of a file under the configured
// docroot, which the reactor opens and streams through the ring. A callback
// hands over a name and nothing more - no fd, no bytes, no disk syscall
// inside a run.
//
// The missing-docroot refusal fires here, not at config load. Nothing at
// load time can see it coming - response.file= is a runtime call, so "this
// application uses it" is not a static fact worth guessing at. This is the
// earliest honest point and the cheapest one to act on: the raise carries
// the class, the message and the app's own file and line into --error-log,
// where a 500 spelled three ring round-trips later would name nothing.
//: (String) -> (String | NilClass)
mrb_value response_set_file(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    mrb_value v;
    mrb_get_args(mrb, "o", &v);
    if (mrb_nil_p(v)) {
        r->run.have_file = false;
        r->run.file_bad = false;
        return v;
    }
    if (!mrb_string_p(v)) {
        mrb_raise(mrb, E_TYPE_ERROR, "response.file= takes a String, or nil to clear it");
    }
    if (!docroot_ready()) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                  "response.file= needs a docroot and this server has none. Name one: "
                  "conf.docroot in the application's configure block, or --docroot=PATH "
                  "for a standalone server. There is no default - a server that guesses "
                  "which directory to serve files out of serves the wrong one");
    }
    // RESOLVE_BENEATH is the guard, not this. These two are the C-string API's
    // own limits: an embedded NUL would truncate the name openat2 actually
    // sees, and an empty name asks for nothing. Both answer the same 404 a
    // rejected resolve does, so neither is a signal to probe with.
    r->run.file.assign(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
    r->run.file_bad = r->run.file.empty() || r->run.file.find('\0') != std::string::npos;
    r->run.have_file = true;
    return v;
}

// #210: response.error_asset("404.jpg") - an entry of the error assets
// becomes this answer's body, with the media type the file recorded for
// it. Not response.file: nothing is opened and nothing goes through the
// ring, because these bytes are already mapped.
//
// Nothing is copied and nothing new is written: the run records the
// entry, and the writers put it on the wire through the very accessors
// the asset tier uses for a mounted file - Assets::wire_iov/copy_wire
// on h1, Content::Src::kAsset on h2. The zip is mmap'd for as long as
// the server lives, so the handle outlives every stream that parks on
// it.
//: (String) -> (String | NilClass)
mrb_value response_error_asset_entry(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    mrb_value v;
    mrb_get_args(mrb, "o", &v);
    if (mrb_nil_p(v))
        return v;
    if (!mrb_string_p(v)) {
        mrb_raise(mrb, E_TYPE_ERROR, "response.error_asset takes a String");
    }
    if (error_assets_ == nullptr) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                  "response.error_asset needs error assets and this server found none. Name a "
                  "file: --error-assets=FILE.zip, or install one where the system keeps shipped "
                  "data (XDG_DATA_DIRS + /webmachine-mruby/error-assets.zip)");
    }
    char name[kMaxHead];
    const size_t n = static_cast<size_t>(RSTRING_LEN(v));
    if (n == 0 || n + 2 >= sizeof(name)) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "response.error_asset: no such entry");
    }
    name[0] = '/';
    std::memcpy(name + 1, RSTRING_PTR(v), n);
    const AssetEntry *e = error_assets_->find(name, n + 1);
    if (e == nullptr || e->deflated) {
        mrb_raisef(mrb, E_WM_ERROR(mrb), "response.error_asset: the error assets hold no %v", v);
    }
    r->run.content_type.assign(e->content_type);
    r->run.asset = e;
    r->run.have_body = true;
    return v;
}

// RFC 9110 15.4.4: webmachine-ruby's own spelling of a redirect - an
// optional Location plus the flag n11/p11 read back. `redirect_to`
// below is the exact same function under its alias name.
//: (?String) -> TrueClass
mrb_value response_redirect_to(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    mrb_value loc = mrb_nil_value();
    mrb_get_args(mrb, "|o", &loc);
    if (!mrb_nil_p(loc)) {
        if (r->run.headers == nullptr) {
            mrb_raise(mrb, E_RUNTIME_ERROR,
                      "response.do_redirect: no header buffer is bound for this run");
        }
        const mrb_value s = mrb_obj_as_string(mrb, loc);
        // RFC 9110 5.5: a value with CR, LF or NUL would splice a field in.
        if (!http::field_value_ok(RSTRING_PTR(s), static_cast<size_t>(RSTRING_LEN(s)))) {
            mrb_raise(
                mrb, E_ARGUMENT_ERROR,
                "response.redirect_to: the location must carry no CR, LF or NUL (RFC 9110 5.5)");
        }
        std::string &buf = *r->run.headers;
        FieldLine h;
        if (find_field_line_named(buf, "Location", h))
            buf.erase(h.start, h.end - h.start);
        append_field_line(buf, {"Location", {RSTRING_PTR(s), static_cast<size_t>(RSTRING_LEN(s))}});
    }
    r->run.redirect = true;
    return mrb_true_value();
}

// RFC 9110 15.4: has a callback already made this a redirect? A
// predicate, not a bang-method - webmachine-ruby spells it is_redirect?
// and so does this.
//: () -> (TrueClass | FalseClass)
mrb_value response_is_redirect(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(resource_of_the_live_run(mrb)->run.redirect);
}

// App-level only: no C++ run slot backs an error message, so it lives as
// a plain ivar on the handle. Keep one handle and get and set agree on
// it, like any other Ruby attr_accessor.
mrb_value response_error_message(mrb_state *mrb, mrb_value self)
{
    return mrb_iv_get(mrb, self, MRB_IVSYM(error));
}

// App-level only: see resp_error above.
mrb_value response_set_error_message(mrb_state *mrb, mrb_value self)
{
    mrb_value v;
    mrb_get_args(mrb, "o", &v);
    mrb_iv_set(mrb, self, MRB_IVSYM(error), v);
    return v;
}

// RFC 6265 4.1: one Set-Cookie line, spelled by hand from name/value
// plus the optional attributes webmachine-ruby's Cookie#to_s emits.
// Several cookies mean several lines - this always appends, never
// replaces, unlike every other header write in this file.
// RFC 6265 4.1.1: one cookie-av, if the app named it at all.
// RFC 6265 4.1.1: one cookie-av the app may have named - the hash it
// filled, the key the attribute sits under, and the name it goes out with.
struct CookieAttribute {
    mrb_value attrs;
    mrb_sym sym;
    const char *label;
};

void append_cookie_attribute(mrb_state *mrb, std::string &line, CookieAttribute a)
{
    const char *const label = a.label;
    const mrb_value v = mrb_hash_get(mrb, a.attrs, mrb_symbol_value(a.sym));
    if (mrb_nil_p(v))
        return;
    const mrb_value s = mrb_obj_as_string(mrb, v);
    // A semicolon in one attribute spells a second attribute, so the app
    // would write an attribute this call never named.
    if (std::memchr(RSTRING_PTR(s), ';', static_cast<size_t>(RSTRING_LEN(s))) != nullptr) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "response.set_cookie wants no semicolon in an attribute");
    }
    line.append("; ", 2);
    line.append(label);
    line.append(RSTRING_PTR(s), static_cast<size_t>(RSTRING_LEN(s)));
}

//: (String, String, ?Hash) -> NilClass
mrb_value response_set_cookie_line(mrb_state *mrb, mrb_value)
{
    const Resource *r = resource_of_the_live_run(mrb);
    if (r->run.headers == nullptr) {
        mrb_raise(mrb, E_RUNTIME_ERROR,
                  "response.set_cookie: no header buffer is bound for this run");
    }
    mrb_value name, value;
    mrb_value attrs = mrb_nil_value();
    mrb_get_args(mrb, "oo|o", &name, &value, &attrs);
    const mrb_value nstr =
        mrb_symbol_p(name) ? mrb_sym_str(mrb, mrb_symbol(name)) : mrb_obj_as_string(mrb, name);
    if (!mrb_string_p(value)) {
        mrb_raise(mrb, E_TYPE_ERROR, "response.set_cookie's value must be a String");
    }

    // RFC 6265 4.1.1: the name is one token, and the first `=` ends it. A
    // name that carries `=` or `;` names another cookie or an attribute.
    const char *const np = RSTRING_PTR(nstr);
    const size_t nlen = static_cast<size_t>(RSTRING_LEN(nstr));
    if (nlen == 0 || std::memchr(np, '=', nlen) != nullptr ||
        std::memchr(np, ';', nlen) != nullptr) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "response.set_cookie wants a name with no `=` and no semicolon in it");
    }
    // A semicolon in the value ends the value and starts an attribute.
    if (std::memchr(RSTRING_PTR(value), ';', static_cast<size_t>(RSTRING_LEN(value))) != nullptr) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "response.set_cookie wants no semicolon in the value");
    }

    std::string line;
    line.append(np, nlen);
    line.append("=", 1);
    line.append(RSTRING_PTR(value), static_cast<size_t>(RSTRING_LEN(value)));

    if (mrb_hash_p(attrs)) {
        append_cookie_attribute(mrb, line, {attrs, MRB_SYM(path), "Path="});
        append_cookie_attribute(mrb, line, {attrs, MRB_SYM(domain), "Domain="});
        append_cookie_attribute(mrb, line, {attrs, MRB_SYM(max_age), "Max-Age="});
        append_cookie_attribute(mrb, line, {attrs, MRB_SYM(expires), "Expires="});
        if (mrb_test(mrb_hash_get(mrb, attrs, mrb_symbol_value(MRB_SYM(secure))))) {
            line.append("; Secure", 8);
        }
        if (mrb_test(mrb_hash_get(mrb, attrs, mrb_symbol_value(MRB_SYM(httponly))))) {
            line.append("; HttpOnly", 10);
        }
    }
    // Same gate: the cookie's name, value and every attribute came from the
    // app, and they end up in one field value.
    if (!http::field_value_ok(line.data(), line.size())) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "response.set_cookie wants no CR, LF or NUL in name, value or attributes");
    }
    append_field_line(*r->run.headers, {"Set-Cookie", line});
    return mrb_nil_value();
}

// #30: the run's own slot. The application puts what it wants there
// and takes it out in another callback of the same run.
//
// This server never looks at it. Nothing in it means anything to the
// flow, nothing reaches a header, and nothing is folded at setup. It is
// one value with a lifetime, and the lifetime is one run.
mrb_value response_userdata_value(mrb_state *mrb, mrb_value self)
{
    (void)self;
    const Resource *const res = resource_of_the_live_run(mrb);
    // Undef is "nothing was put there". Ruby never sees it.
    if (mrb_undef_p(res->run.userdata))
        return mrb_nil_value();
    return res->run.userdata;
}

mrb_value response_set_userdata(mrb_state *mrb, mrb_value self)
{
    (void)self;
    mrb_value v;
    mrb_get_args(mrb, "o", &v);
    const Resource *const res = resource_of_the_live_run(mrb);
    if (res->run.userdata_held)
        mrb_gc_unregister(mrb, res->run.userdata);
    res->run.userdata = v;
    // Rooted: the run parks, and nothing on the VM's stack names this.
    mrb_gc_register(mrb, v);
    res->run.userdata_held = true;
    return v;
}

// RFC 9110: Resource#response - a fresh Response handle on every call,
// never memoised; whatever GC arena covers this callback's own call
// frame is what keeps the handle alive, same as any other short-lived
// value a cfunc returns.
//: () -> Webmachine::Response
mrb_value resource_response(mrb_state *mrb, mrb_value)
{
    resource_of_the_live_run(mrb);
    struct RClass *wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
    struct RClass *rc = mrb_class_get_under_id(mrb, wm, MRB_SYM(Response));
    return mrb_obj_value(
        mrb_data_object_alloc(mrb, rc, const_cast<Resource *>(live_resource_), &kResponseDataType));
}

} // namespace

// RFC 9110 6.4: the representation, handed over by something that is
// not a callback of the resource. request.body.save uses it: the value
// of its block is the answer's body, the same way the value of
// to_html is.
//
// False when this run has no body buffer bound, which is the caller's
// error rather than a raise from here.
// #54: whether the resource being answered declared that it saves the
// request body. request.body.save asks it, and refuses when it is
// false: a body that was not promised to a save is in memory when it
// is small, and saving it there is a second write of every octet.
bool response_saves_body(mrb_state *mrb)
{
    return resource_of_the_live_run(mrb)->saves_body;
}

bool response_take_body(mrb_state *mrb, std::string_view s)
{
    const Resource *r = resource_of_the_live_run(mrb);
    if (r->run.body == nullptr)
        return false;
    r->run.body->assign(s.data(), s.size());
    r->run.have_body = true;
    return true;
}

// RFC 9110: point the response surface at this run's Resource, or at
// nothing. Same pattern as request_bind, so a stray handle from an
// ended run reads as "outside a run frame" rather than touching
// whichever run is live now.
void response_bind(const Resource *res)
{
    live_resource_ = res;
}

// #210: the error assets, bound once at setup the way response_bind
// binds a resource per run. nullptr when this server found none, and
// response.error_asset then refuses by name rather than answering
// something it does not have.
void response_bind_error_assets(Assets *a)
{
    error_assets_ = a;
}

// RFC 9110: Webmachine::Response and Webmachine::Response::Headers,
// defined once at gem init. Neither is ever `new`'d by an app - the
// run frame is the only thing that builds one, via Resource#response.
void response_init(mrb_state *mrb, struct RClass *wm)
{
    struct RClass *c = mrb_define_class_under_id(mrb, wm, MRB_SYM(Response), mrb->object_class);
    MRB_SET_INSTANCE_TT(c, MRB_TT_CDATA);
    mrb_undef_class_method_id(mrb, c, MRB_SYM(new));
    mrb_define_method_id(mrb, c, MRB_SYM(headers), response_headers, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM(code), response_status_code, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM_E(code), response_set_code, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, c, MRB_SYM(body), response_body_value, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM_E(body), response_set_body, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, c, MRB_SYM(file), response_file_name, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM_E(file), response_set_file, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, c, MRB_SYM(error_asset), response_error_asset_entry, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, c, MRB_SYM(do_redirect), response_redirect_to, MRB_ARGS_OPT(1));
    mrb_define_method_id(mrb, c, MRB_SYM(redirect_to), response_redirect_to, MRB_ARGS_OPT(1));
    mrb_define_method_id(mrb, c, MRB_SYM_Q(is_redirect), response_is_redirect, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM(error), response_error_message, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM_E(error), response_set_error_message, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, c, MRB_SYM(set_cookie), response_set_cookie_line, MRB_ARGS_ARG(2, 1));
    mrb_define_method_id(mrb, c, MRB_SYM(userdata), response_userdata_value, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, c, MRB_SYM_E(userdata), response_set_userdata, MRB_ARGS_REQ(1));

    struct RClass *h = mrb_define_class_under_id(mrb, c, MRB_SYM(Headers), mrb->object_class);
    MRB_SET_INSTANCE_TT(h, MRB_TT_CDATA);
    mrb_undef_class_method_id(mrb, h, MRB_SYM(new));
    mrb_define_method_id(mrb, h, MRB_OPSYM(aref), headers_field_value, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, h, MRB_OPSYM(aset), headers_set_field, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, h, MRB_SYM_Q(key), headers_has_field, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, h, MRB_SYM(delete), headers_delete_field, MRB_ARGS_REQ(1));

    struct RClass *res = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
    mrb_define_method_id(mrb, res, MRB_SYM(response), resource_response, MRB_ARGS_NONE());
}

} // namespace webmachine
