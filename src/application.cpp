#include "ruby_value.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/dump.h>
#include <mruby/error.h>
#include <mruby/irep.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

#include <ada.h>

namespace webmachine
{
namespace
{
std::vector<std::unique_ptr<AppSpec>> specs_;
std::vector<AppSpec *> registered_;

const struct mrb_data_type app_type = {"webmachine.app", nullptr};

// The class of the object `app.routes` yields. It is named under the
// module and looked up in the VM that asks: a worker's VM runs this
// gem's init as well, and a pointer kept here would be the last VM's.
struct RClass *routes_class(mrb_state *mrb)
{
    return mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)),
                                  MRB_SYM(Routes));
}

// Exactly one listener spelling per app; a second refuses by name.
// One form an application may be declared in, and the word that names it.
struct Form {
    AppSpec::Form kind;
    const char *name;
};

void app_claim_form(mrb_state *mrb, AppSpec *spec, Form want)
{
    const AppSpec::Form form = want.kind;
    const char *const name = want.name;
    if (spec->form != AppSpec::Form::kNone && spec->form != form) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.%s: this application already named its listener another way - "
                   "exactly one of port, unix_path or url per application",
                   name);
    }
    spec->form = form;
}

// The whole set of settings a URL or a config file may reach, and the
// reason it is a table and not a name lookup.
//
// The parameters are spelled like the conf setters on purpose - a knob
// is called the same thing everywhere it can be named (AppSpec's own
// comment says so). It would therefore be one line to send the setter
// by that name and be done. That line would be remote code execution:
// whoever writes the URL or the config file would be calling methods on
// the conf object by name, and every method conf ever gains would join
// the attack surface by existing. Routes are Ruby because a route names
// a class; nothing here may name one.
//
// So the names are a convention for people, and the dispatch is this
// switch. What a URL can set is countable by reading it, an unknown key
// is refused, and add_route, add_websocket, add_sse and ready are not
// reachable from here because they are not in it.
enum class Setting : uint8_t {
    kDocroot,
    kSpillDir,
    kAssets,
    kCertificate,
    kPrivateKey,
    kFileMapThreshold,
    kZeroCopyThreshold,
    kDisableHttpCats,
    kMaxBody,
    kUnknown,
};

Setting setting_named(std::string_view k)
{
    if (k == "docroot")
        return Setting::kDocroot;
    if (k == "spill_dir")
        return Setting::kSpillDir;
    if (k == "assets")
        return Setting::kAssets;
    if (k == "certificate")
        return Setting::kCertificate;
    if (k == "private_key")
        return Setting::kPrivateKey;
    if (k == "file_map_threshold")
        return Setting::kFileMapThreshold;
    if (k == "zero_copy_threshold")
        return Setting::kZeroCopyThreshold;
    if (k == "disable_http_cats")
        return Setting::kDisableHttpCats;
    if (k == "max_body")
        return Setting::kMaxBody;
    return Setting::kUnknown;
}

// A whole-string unsigned read: strtoll would accept "8k" and a leading
// '+' or space, and this must not.
bool text_to_whole_number(std::string_view text, long long *out)
{
    if (text.empty() || text.size() > 19)
        return false;
    long long number = 0;
    for (const char c : text) {
        if (c < '0' || c > '9')
            return false;
        number = number * 10 + (c - '0');
    }
    *out = number;
    return true;
}

// RFC-nothing: what an operator writes for a flag. Spelled out rather
// than "anything that is not 0", so a typo is a refusal and not a
// silent true.
bool text_to_flag(std::string_view text, bool *out_flag)
{
    if (text == "1" || text == "true") {
        *out_flag = true;
        return true;
    }
    if (text == "0" || text == "false") {
        *out_flag = false;
        return true;
    }
    return false;
}

// One setting from the URL's query, refused rather than applied twice.
// The bounds are the setters' own - a value that conf.docroot= would
// reject is rejected here in the same words, because there is one rule
// per knob and this is not a second one.
void setting_apply(mrb_state *mrb, AppSpec *spec, std::string_view key_name, std::string_view value)
{
    const Setting what = setting_named(key_name);
    if (what == Setting::kUnknown) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.url: %s is not a setting - a URL may name docroot, assets, certificate, "
                   "private_key, file_map_threshold, zero_copy_threshold, "
                   "disable_http_cats or max_body, and routes stay in Ruby",
                   std::string(key_name).c_str());
    }
    long long number = 0;
    bool flag = false;
    switch (what) {
        case Setting::kDocroot:
            if (value.empty())
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: docroot is empty");
            if (!spec->docroot.empty()) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: docroot was already named");
            }
            spec->docroot.assign(value);
            return;
        case Setting::kSpillDir:
            if (value.empty())
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: spill_dir is empty");
            if (!spec->spill_dir.empty()) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: spill_dir was already named");
            }
            spec->spill_dir.assign(value);
            return;
        case Setting::kAssets:
            if (value.empty())
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: assets is empty");
            if (!spec->assets.empty()) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: assets was already named");
            }
            spec->assets.assign(value);
            return;
        case Setting::kCertificate:
            if (value.empty())
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: certificate is empty");
            if (!spec->cert_path.empty()) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: certificate was already named");
            }
            spec->cert_path.assign(value);
            return;
        case Setting::kPrivateKey:
            if (value.empty())
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: private_key is empty");
            if (!spec->key_path.empty()) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: private_key was already named");
            }
            spec->key_path.assign(value);
            return;
        case Setting::kFileMapThreshold:
            if (!text_to_whole_number(value, &number) ||
                number > static_cast<long long>(kFileMapMax)) {
                mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                           "conf.url: file_map_threshold = %s is outside 0..%i bytes",
                           std::string(value).c_str(), static_cast<mrb_int>(kFileMapMax));
            }
            if (spec->file_map_threshold >= 0) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                          "conf.url: file_map_threshold was already named");
            }
            spec->file_map_threshold = number;
            return;
        case Setting::kZeroCopyThreshold:
            if (!text_to_whole_number(value, &number) ||
                number > static_cast<long long>(kZeroCopyMax)) {
                mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                           "conf.url: zero_copy_threshold = %s is outside 0..%i bytes",
                           std::string(value).c_str(), static_cast<mrb_int>(kZeroCopyMax));
            }
            if (spec->zero_copy_threshold >= 0) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                          "conf.url: zero_copy_threshold was already named");
            }
            spec->zero_copy_threshold = number;
            return;
        case Setting::kMaxBody:
            if (!text_to_whole_number(value, &number) ||
                number > static_cast<long long>(kMaxBodyMax)) {
                mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                           "conf.url: max_body = %s is outside 0..%i bytes",
                           std::string(value).c_str(), static_cast<mrb_int>(kMaxBodyMax));
            }
            if (spec->max_body >= 0) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: max_body was already named");
            }
            spec->max_body = number;
            return;
        case Setting::kDisableHttpCats:
            if (!text_to_flag(value, &flag)) {
                mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                           "conf.url: disable_http_cats = %s is not 1, 0, true or false",
                           std::string(value).c_str());
            }
            if (spec->disable_http_cats >= 0) {
                mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                          "conf.url: disable_http_cats was already named");
            }
            spec->disable_http_cats = flag ? 1 : 0;
            return;
        case Setting::kUnknown:
            break;
    }
    WM_UNREACHABLE();
}

// conf.url = "scheme://host[:port][?setting=value&...]" - webmachine-ruby's
// own spelling, parsed by ada (WHATWG URL Standard) rather than by
// find("://") and rfind(':').
//
// What the hand-rolled one got wrong, and no test covered because every
// test used the same happy shape:
//
//   http://[::1]              refused with "has no usable port" -
//                             rfind(':') landed inside the literal, so
//                             the port read as "1]". A valid absolute
//                             URL whose port is the scheme's 80.
//   http://user@127.0.0.1:80  accepted, and url_host became
//                             "user@127.0.0.1" - userinfo folded into
//                             the host and on into bound_url.
//
// The scheme names the listener - http, https, or unix for a socket
// path - and the query carries the rest of the conf object, under the
// setters' own names. It is an addition: every setter stays, and a knob
// named twice is a ConfigError rather than a precedence rule, the same
// answer claim_form gives a listener named twice.
//
// What may appear there is apply_setting's table and nothing else, for
// the reason written above it: routes name classes and stay in Ruby.
//
// Credentials are refused rather than carried - they name nothing a
// listener can serve. A path is ignored under http and https, as it was
// before: webmachine-ruby's conf.url may carry one and it names no
// listener. Under unix the path is the listener.
void url_apply(mrb_state *mrb, AppSpec *spec, const std::string &url)
{

    auto parsed = ada::parse<ada::url_aggregator>(url);
    if (!parsed) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.url = %s is not scheme://host[:port] or unix:///path", url.c_str());
    }
    // ada spells a scheme with its colon; the message says what was asked
    // for, not what ada calls it.
    const std::string_view proto = parsed->get_protocol();
    const bool unix_form = proto == "unix:";
    const bool wants_tls = proto == "https:";
    if (!unix_form && !wants_tls && proto != "http:") {
        const std::string scheme(proto.substr(0, proto.size() - 1));
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url scheme %s is not http, https or unix",
                   scheme.c_str());
    }
    if (parsed->has_credentials()) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.url = %s carries credentials, which name no listener", url.c_str());
    }

    // The form is the URL's, not the setter's: everything downstream reads
    // it to decide what to bind (server.cpp), which listener collides with
    // which (app_register), and what conf.url reads back. A unix:// URL
    // that claimed kUrl would be bound as a port - port 0, since it never
    // named one.
    app_claim_form(mrb, spec, {unix_form ? AppSpec::Form::kUnix : AppSpec::Form::kUrl, "url"});

    if (unix_form) {
        // A socket path, percent-decoded: ada hands the pathname back in the
        // URL's own spelling, and a path with a space in it is written %20.
        const std::string_view path = parsed->get_pathname();
        const size_t percent = path.find('%');
        const std::string sock = percent == std::string_view::npos
                                     ? std::string(path)
                                     : ada::unicode::percent_decode(path, percent);
        if (sock.empty() || sock == "/") {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s names no socket path",
                       url.c_str());
        }
        spec->tls = false;
        spec->unix_path = sock;
    } else {
        const std::string_view host = parsed->get_hostname();
        if (host.empty())
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s has no host", url.c_str());
        // An absent port is the scheme's default; ada leaves get_port() empty
        // for it rather than writing 80 or 443 back out.
        int port = wants_tls ? 443 : 80;
        const std::string_view port_text = parsed->get_port();
        if (!port_text.empty()) {
            port = 0;
            for (char c : port_text)
                port = port * 10 + (c - '0');
        }
        spec->tls = wants_tls;
        spec->url_host.assign(host);
        spec->port = port;
    }

    const std::string_view search = parsed->get_search();
    if (!search.empty()) {
        // get_search() keeps the '?'; url_search_params wants the query.
        ada::url_search_params params{search.substr(1)};
        for (const auto &kv : params)
            setting_apply(mrb, spec, kv.first, kv.second);
    }
}

// The configuration arrives as one value: the Webmachine::Config struct
// mrblib defines. A Struct in mruby is an array (MRB_TT_STRUCT is struct
// RArray in value.h), so this walks it - through mrb_ary_entry, never by
// reaching into the object - and decides what each slot means.
//
// The order is the contract, and it is written down twice on purpose:
// once as the member list in mrblib/webmachine.rb and once here. The
// length check below is what notices if the two ever drift, at the first
// Application.new rather than in whichever knob happened to move.
//
// Ruby collects; this decides. Every ceiling, every refusal and the
// whole grammar of conf.url are here, in the words they had when they
// were nine separate setters.
enum ConfIdx {
    kConfPort,
    kConfUnixPath,
    kConfUrl,
    kConfDocroot,
    kConfAssets,
    kConfCertificate,
    kConfPrivateKey,
    kConfFileMapThreshold,
    kConfZeroCopyThreshold,
    kConfDisableHttpCats,
    kConfMaxBody,
    kConfSpillDir,
    kConfMax,
};

// A named string slot: absent is nothing said, present and empty is a
// refusal, because an empty path is a mistake and not an answer.
bool conf_read_string(mrb_state *mrb, mrb_value conf, ConfIdx member, const char *name,
                      std::string *out_text)
{
    const mrb_value raw = mrb_ary_entry(conf, member);
    if (mrb_nil_p(raw))
        return false;
    if (!mrb_string_p(raw)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s wants a String", name);
    }
    if (ruby_string_length(raw) == 0) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s is empty", name);
    }
    out_text->assign(ruby_string_bytes(raw));
    return true;
}

// A named whole-number slot, refused by the ceiling that owns it.
bool conf_int(mrb_state *mrb, mrb_value conf, ConfIdx member, const char *name, mrb_int ceiling,
              const char *unit, mrb_int *out_count)
{
    const mrb_value raw = mrb_ary_entry(conf, member);
    if (mrb_nil_p(raw))
        return false;
    if (!mrb_integer_p(raw)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s wants an Integer", name);
    }
    const mrb_int number = mrb_integer(raw);
    if (number < 0 || number > ceiling) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s = %i is outside 0..%i%s", name, number,
                   ceiling, unit);
    }
    *out_count = number;
    return true;
}

void conf_read_all(mrb_state *mrb, mrb_value conf, AppSpec *spec)
{
    // MRB_TT_STRUCT, not MRB_TT_ARRAY: a Struct is struct RArray in memory
    // and mrb_ary_entry reads it, but it carries its own type tag, so
    // mrb_array_p says no. Checked before the first mrb_ary_entry, because
    // that one trusts the tag it was handed.
    if (mrb_type(conf) != MRB_TT_STRUCT || ruby_array_length(conf) != kConfMax) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf is not the %i values Webmachine::Config names - application.cpp's "
                   "ConfIdx and mrblib's Struct member list have drifted apart",
                   static_cast<mrb_int>(kConfMax));
    }

    // The listener first, and exactly one spelling of it: claim_form is
    // what refuses the second, and it refuses in member order now rather
    // than in the order the app happened to write them.
    mrb_int member_count = 0;
    if (conf_int(mrb, conf, kConfPort, "port", 65535, "", &member_count)) {
        app_claim_form(mrb, spec, {AppSpec::Form::kPort, "port"});
        spec->port = static_cast<int>(member_count);
    }
    std::string text;
    if (conf_read_string(mrb, conf, kConfUnixPath, "unix_path", &text)) {
        app_claim_form(mrb, spec, {AppSpec::Form::kUnix, "unix_path"});
        spec->unix_path = text;
    }
    if (conf_read_string(mrb, conf, kConfUrl, "url", &text))
        url_apply(mrb, spec, text);

    if (conf_read_string(mrb, conf, kConfSpillDir, "spill_dir", &text)) {
        if (!spec->spill_dir.empty()) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: spill_dir was already named");
        }
        spec->spill_dir.assign(text);
    }
    if (conf_read_string(mrb, conf, kConfDocroot, "docroot", &text)) {
        if (!spec->docroot.empty()) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: docroot was already named");
        }
        spec->docroot = text;
    }
    if (conf_read_string(mrb, conf, kConfAssets, "assets", &text)) {
        if (!spec->assets.empty()) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: assets was already named");
        }
        spec->assets = text;
    }
    if (conf_read_string(mrb, conf, kConfCertificate, "certificate", &text)) {
        if (!spec->cert_path.empty()) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: certificate was already named");
        }
        spec->cert_path = text;
    }
    if (conf_read_string(mrb, conf, kConfPrivateKey, "private_key", &text)) {
        if (!spec->key_path.empty()) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: private_key was already named");
        }
        spec->key_path = text;
    }
    if (conf_int(mrb, conf, kConfFileMapThreshold, "file_map_threshold",
                 static_cast<mrb_int>(kFileMapMax), " bytes", &member_count)) {
        if (spec->file_map_threshold >= 0) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                      "conf.url: file_map_threshold was already named");
        }
        spec->file_map_threshold = member_count;
    }
    if (conf_int(mrb, conf, kConfZeroCopyThreshold, "zero_copy_threshold",
                 static_cast<mrb_int>(kZeroCopyMax), " bytes", &member_count)) {
        if (spec->zero_copy_threshold >= 0) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                      "conf.url: zero_copy_threshold was already named");
        }
        spec->zero_copy_threshold = member_count;
    }
    if (conf_int(mrb, conf, kConfMaxBody, "max_body", static_cast<mrb_int>(kMaxBodyMax), " bytes",
                 &member_count)) {
        if (spec->max_body >= 0) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: max_body was already named");
        }
        spec->max_body = member_count;
    }
    const mrb_value cats = mrb_ary_entry(conf, kConfDisableHttpCats);
    if (!mrb_nil_p(cats)) {
        const int8_t want = mrb_test(cats) ? 1 : 0;
        if (spec->disable_http_cats >= 0) {
            mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: disable_http_cats was already named");
        }
        spec->disable_http_cats = want;
    }

    // conf.url reads both ways: the ask before the bind, the truth after
    // it. Before the bind there is nothing truer than what was written, so
    // the slot keeps it; app_mark_bound overwrites it with what the
    // listener really became.
    if (mrb_nil_p(mrb_ary_entry(conf, kConfUrl)) && spec->form != AppSpec::Form::kNone) {
        const char *const scheme = spec->tls ? "https" : "http";
        const mrb_value said = spec->form == AppSpec::Form::kUnix
                                   ? mrb_format(mrb, "unix://%s", spec->unix_path.c_str())
                                   : mrb_format(mrb, "%s://0.0.0.0:%d", scheme, spec->port);
        mrb_ary_set(mrb, conf, kConfUrl, said);
    }
}

// The token array crosses the boundary once, here, for all three route kinds.
// The route tokens an app handed over, and the call that handed them -
// which is the word a refusal names.
struct Tokens {
    mrb_value list;
    const char *caller_name;
};

void route_table_walk_tokens(mrb_state *mrb, RouteTable &table, Tokens tokens)
{
    const mrb_value toks = tokens.list;
    const char *const caller_name = tokens.caller_name;
    const size_t count = ruby_array_length(toks);
    for (size_t i = 0; i < count; i++) {
        const mrb_value token = mrb_ary_entry(toks, i);
        if (table.pending_splat()) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                       "%s: :* is the tail of a route - nothing may follow it", caller_name);
        }
        if (mrb_string_p(token)) {
            // RFC 3986 3.3: a path is segments separated by "/", so a segment
            // can never contain one - match() splits on them before a literal
            // is ever compared. A route carrying one therefore matches nothing
            // at all, and the way that showed up was every request 404ing with
            // the routes looking right. ['/'] is the near-universal way to
            // write it wrong: the root is the empty list, because the root has
            // no segments.
            const std::string_view literal = ruby_string_bytes(token);
            const char *literal_bytes = literal.data();
            const size_t litlen = literal.size();
            if (std::memchr(literal_bytes, '/', litlen) != nullptr) {
                if (litlen == 1) {
                    mrb_raisef(
                        mrb, E_WM_ROUTE_ERROR(mrb),
                        "%s: [\"/\"] is a route with one segment named \"/\", which no request "
                        "can have - the root is the empty list, add [], YourResource",
                        caller_name);
                }
                mrb_raisef(
                    mrb, E_WM_ROUTE_ERROR(mrb),
                    "%s: a route token is one path segment, and %v carries a \"/\" - split it "
                    "into one token per segment",
                    caller_name, token);
            }
            if (litlen == 0) {
                mrb_raisef(
                    mrb, E_WM_ROUTE_ERROR(mrb),
                    "%s: an empty token is a segment no request can have - to route the root, "
                    "pass no tokens at all",
                    caller_name);
            }
            if (!table.literal(literal_bytes, litlen)) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%s: a literal token is too long",
                           caller_name);
            }
            continue;
        }
        if (mrb_symbol_p(token)) {
            if (mrb_symbol(token) == MRB_OPSYM(mul)) {
                table.splat();
                continue;
            }
            if (!table.binding(static_cast<uint32_t>(mrb_symbol(token)))) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "%s: too many bindings in one route (16 is the table's width)",
                           caller_name);
            }
            continue;
        }
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s: a token is a String (literal), a Symbol (binding) or :* (tail)",
                   caller_name);
    }
}

// route.add / app.add_route: the flow's table. Folds and freezes the class.
//: (String, Class) -> (Webmachine::Application | Webmachine::Routes)
mrb_value route_add(mrb_state *mrb, mrb_value self)
{
    mrb_value toks, klass;
    mrb_get_args(mrb, "Ao", &toks, &klass);
    AppSpec *spec = static_cast<AppSpec *>(mrb_data_get_ptr(mrb, self, &app_type));

    if (!mrb_class_p(klass)) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                  "route.add wants a class inheriting Webmachine::Resource");
    }
    struct RClass *webmachine_module = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
    struct RClass *base = mrb_class_get_under_id(mrb, webmachine_module, MRB_SYM(Resource));
    bool is_resource = false;
    for (struct RClass *route_class = mrb_class_ptr(klass)->super; route_class != nullptr;
         route_class = route_class->super) {
        if (route_class == base) {
            is_resource = true;
            break;
        }
    }
    if (!is_resource) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "route.add: %v does not inherit Webmachine::Resource", klass);
    }

    OpenRoute route(spec->table);
    route_table_walk_tokens(mrb, spec->table, {toks, "route.add"});

    auto resource_class = std::unique_ptr<Resource>(new Resource());
    resource_fold(mrb, klass, *resource_class);
    route.commit();
    spec->resources.push_back(std::move(resource_class));
    return self;
}

// RFC 6455: route.websocket - the app's own second table.
//: (String, Class) -> (Webmachine::Application | Webmachine::Routes)
mrb_value route_websocket(mrb_state *mrb, mrb_value self)
{
    mrb_value toks, klass;
    mrb_get_args(mrb, "Ao", &toks, &klass);
    AppSpec *spec = static_cast<AppSpec *>(mrb_data_get_ptr(mrb, self, &app_type));

    OpenRoute route(spec->ws_table);
    route_table_walk_tokens(mrb, spec->ws_table, {toks, "route.websocket"});

    std::unique_ptr<WsResource, void (*)(WsResource *)> res(ws_resource_new(), ws_resource_free);
    ws_fold(mrb, klass, *res);
    route.commit();
    spec->ws_resources.push_back(std::move(res));
    return self;
}

// WHATWG HTML: route.sse - the app's own third table.
//: (String, Class) -> (Webmachine::Application | Webmachine::Routes)
mrb_value route_sse(mrb_state *mrb, mrb_value self)
{
    mrb_value toks, klass;
    mrb_get_args(mrb, "Ao", &toks, &klass);
    AppSpec *spec = static_cast<AppSpec *>(mrb_data_get_ptr(mrb, self, &app_type));

    OpenRoute route(spec->sse_table);
    route_table_walk_tokens(mrb, spec->sse_table, {toks, "route.sse"});

    std::unique_ptr<SseResource, void (*)(SseResource *)> res(sse_resource_new(),
                                                              sse_resource_free);
    sse_fold(mrb, klass, *res);
    route.commit();
    spec->sse_resources.push_back(std::move(res));
    return self;
}

// A signpost: assets are configured with --assets and serve unchanged.
//: (*untyped) -> NilClass
mrb_value route_assets(mrb_state *mrb, mrb_value)
{
    mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
              "route.assets is reserved - the asset mount is #170/#115. Assets are configured "
              "with conf.assets and serve unchanged");
    return mrb_nil_value();
}

// Two applications may not name the same listener - compared on the socket.
void register_app(mrb_state *mrb, AppSpec *spec)
{
    if (spec->form == AppSpec::Form::kNone) {
        spec->registered = true;
        registered_.push_back(spec);
        return;
    }
    const bool is_unix = spec->form == AppSpec::Form::kUnix;
    for (AppSpec *other : registered_) {
        if (other->form == AppSpec::Form::kNone)
            continue;
        const bool other_unix = other->form == AppSpec::Form::kUnix;
        if (is_unix != other_unix)
            continue;
        if (is_unix) {
            if (spec->unix_path == other->unix_path) {
                mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                           "two applications claim the same listener: unix %s",
                           spec->unix_path.c_str());
            }
        } else if (spec->port == other->port && spec->port != 0) {
            mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                       "two applications claim the same listener: port %d", spec->port);
        }
    }
    spec->registered = true;
    registered_.push_back(spec);
}

// Webmachine::Application.new { |app| ... } - the app's whole surface.
// initialize, not a hand-rolled .new: Class#new already allocates the
// MRB_TT_CDATA instance and forwards the block here.
//: () { (Webmachine::Application) -> void } -> Webmachine::Application
mrb_value app_initialize(mrb_state *mrb, mrb_value self)
{
    mrb_value block = mrb_nil_value();
    mrb_get_args(mrb, "&", &block);
    specs_.push_back(std::unique_ptr<AppSpec>(new AppSpec()));
    AppSpec *spec = specs_.back().get();
    mrb_data_init(self, spec, &app_type);
    // Looked up here and not at gem init: mrblib runs after the C side, so
    // Webmachine::Config does not exist yet when this file's init does.
    // Looked up in the VM that asks, every time: a pointer kept across
    // VMs would name the class of whichever VM ran this gem's init last.
    struct RClass *const config_class_ =
        mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Config));
    // The conf object is Ruby's: mrblib names the members, this only reads
    // them back at the end of the block. mrb_obj_new and not a hand-built
    // array, so Struct.new's own initialize decides the shape.
    const mrb_value conf = mrb_obj_new(mrb, config_class_, 0, nullptr);
    spec->conf = conf;
    mrb_gc_register(mrb, conf);
    mrb_iv_set(mrb, self, MRB_IVSYM(conf), conf);
    mrb_iv_set(mrb, self, MRB_IVSYM(routes),
               mrb_obj_value(mrb_data_object_alloc(mrb, routes_class(mrb), spec, &app_type)));
    if (mrb_nil_p(block))
        return self;
    mrb_yield(mrb, block, self);
    conf_read_all(mrb, conf, spec);
    register_app(mrb, spec);
    return self;
}

// webmachine-ruby compatibility: configure / config yield the one conf facade.
//: () { (Webmachine::Config) -> void } -> Webmachine::Application
mrb_value app_configure(mrb_state *mrb, mrb_value self)
{
    mrb_value block = mrb_nil_value();
    mrb_get_args(mrb, "&", &block);
    if (mrb_nil_p(block))
        mrb_raise(mrb, E_WM_ERROR(mrb), "app.configure wants a block");
    mrb_yield(mrb, block, mrb_iv_get(mrb, self, MRB_IVSYM(conf)));
    return self;
}

// webmachine-ruby compatibility: routes yields the one route facade.
//: () { (Webmachine::Routes) -> void } -> Webmachine::Application
mrb_value app_routes(mrb_state *mrb, mrb_value self)
{
    mrb_value block = mrb_nil_value();
    mrb_get_args(mrb, "&", &block);
    if (mrb_nil_p(block))
        mrb_raise(mrb, E_WM_ERROR(mrb), "app.routes wants a block");
    mrb_yield(mrb, block, mrb_iv_get(mrb, self, MRB_IVSYM(routes)));
    return self;
}

// The hook that runs after the bind and before the first accept.
//: () { (Webmachine::Application) -> void } -> Webmachine::Application
mrb_value app_ready(mrb_state *mrb, mrb_value self)
{
    mrb_value block = mrb_nil_value();
    mrb_get_args(mrb, "&", &block);
    if (mrb_nil_p(block))
        mrb_raise(mrb, E_WM_ERROR(mrb), "app.ready wants a block");
    AppSpec *spec = static_cast<AppSpec *>(mrb_data_get_ptr(mrb, self, &app_type));
    if (spec->have_ready)
        mrb_gc_unregister(mrb, spec->ready);
    spec->ready = block;
    spec->have_ready = true;
    mrb_gc_register(mrb, block);
    return self;
}
} // namespace

// Webmachine::Application and its two hidden facade classes.
void application_init(mrb_state *mrb, struct RClass *webmachine_module)
{
    // The ceilings, named once, and never written down in Ruby.
    //
    // mrblib's Config refuses a value against these as it is assigned, so
    // a refusal is catchable where it was caused. read_config checks them
    // again on the way out, because Struct#[]= reaches a member without a
    // writer.
    mrb_define_const_id(mrb, webmachine_module, MRB_SYM(PORT_MAX), mrb_fixnum_value(65535));
    mrb_define_const_id(mrb, webmachine_module, MRB_SYM(FILE_MAP_MAX),
                        mrb_fixnum_value(static_cast<mrb_int>(kFileMapMax)));
    mrb_define_const_id(mrb, webmachine_module, MRB_SYM(MAX_BODY_MAX),
                        mrb_fixnum_value(static_cast<mrb_int>(kMaxBodyMax)));
    mrb_define_const_id(mrb, webmachine_module, MRB_SYM(ZERO_COPY_MAX),
                        mrb_fixnum_value(static_cast<mrb_int>(kZeroCopyMax)));

    struct RClass *app_class =
        mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Application), mrb->object_class);
    MRB_SET_INSTANCE_TT(app_class, MRB_TT_CDATA);
    mrb_define_method_id(mrb, app_class, MRB_SYM(initialize), app_initialize,
                         MRB_ARGS_NONE() | MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, app_class, MRB_SYM(configure), app_configure, MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, app_class, MRB_SYM(config), app_configure, MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, app_class, MRB_SYM(routes), app_routes, MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, app_class, MRB_SYM(ready), app_ready, MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, app_class, MRB_SYM(add_route), route_add, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, app_class, MRB_SYM(add_websocket), route_websocket, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, app_class, MRB_SYM(add_sse), route_sse, MRB_ARGS_REQ(2));

    struct RClass *const routes =
        mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Routes), mrb->object_class);
    MRB_SET_INSTANCE_TT(routes, MRB_TT_CDATA);
    mrb_define_method_id(mrb, routes, MRB_SYM(add), route_add, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, routes, MRB_SYM(sse), route_sse, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, routes, MRB_SYM(websocket), route_websocket, MRB_ARGS_ANY());
    mrb_define_method_id(mrb, routes, MRB_SYM(assets), route_assets, MRB_ARGS_ANY());
}

// Load the app's bytecode and call its `main`. A .rb is refused by name.
void app_load(mrb_state *mrb, const char *path)
{
    const size_t path_len = std::strlen(path);
    if (path_len >= 3 && std::memcmp(path + path_len - 3, ".rb", 3) == 0) {
        const std::string mrb_path(path, path_len - 3);
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "%s is Ruby source, not bytecode - this server loads bytecode only. Compile "
                   "it first: mrbc -g -o %s.mrb %s",
                   path, mrb_path.c_str(), path);
    }
    FILE *file = std::fopen(path, "rb");
    if (file == nullptr) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "cannot open %s: %s", path, std::strerror(errno));
    }
    // Read before loading, so the bytes can be hashed: app_build_hash is
    // what every error fingerprint is taken over first, and it is these
    // bytes - a rake that changed anything changes it, and with it every
    // hash this build can produce.
    std::string image;
    char chunk[65536];
    size_t read_bytes = 0;
    while ((read_bytes = std::fread(chunk, 1, sizeof chunk, file)) != 0)
        image.append(chunk, read_bytes);
    std::fclose(file);
    if (image.empty()) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s is empty - that is no bytecode", path);
    }
    app_build_hash() = fnv1a(kFnvBasis, image.data(), image.size());
    const ArenaGuard arena(mrb);
    mrb_load_irep_buf(mrb, image.data(), image.size());
    // The app's own exception, with its class and its line: it says more
    // than any sentence this frame could add.
    if (mrb->exc != nullptr)
        rethrow(mrb);
    struct RClass *owner = mrb->object_class;
    const mrb_method_t main_m = mrb_method_search_vm(mrb, &owner, MRB_SYM(main));
    if (MRB_METHOD_UNDEF_P(main_m)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "%s defines no `main` - since #116 an app file defines exactly that, and "
                   "Webmachine::Application.new inside it registers the app",
                   path);
    }
    // Without debug info a raise in this app has no file and no line, in
    // the error log and on the page. mrbc keeps it with -g, and the
    // server says so once at boot rather than once per record.
    if (!MRB_METHOD_CFUNC_P(main_m)) {
        const struct RProc *const main_p = MRB_METHOD_PROC(main_m);
        if (main_p != nullptr && !MRB_PROC_CFUNC_P(main_p) &&
            main_p->body.irep->debug_info == nullptr) {
            std::fprintf(stderr,
                         "webmachine: %s carries no line numbers - a raise in it names no file and "
                         "no line. Compile it with mrbc -g\n",
                         path);
        }
    }
    mrb_funcall_argv(mrb, mrb_top_self(mrb), MRB_SYM(main), 0, nullptr);
    if (mrb->exc != nullptr)
        rethrow(mrb);
}

// Every application `main` registered - registration order is listener order.
void app_registered_all(mrb_state *mrb, Registered out_)
{
    std::vector<AppSpec *> &out_registered = out_.specs;
    const size_t max_listeners = out_.max_listeners;
    if (registered_.empty()) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
                  "main registered no application - Webmachine::Application.new takes a block, "
                  "and returning from it is what registers the app");
    }
    if (registered_.size() > max_listeners) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "main registered %i applications and the ring holds %i listeners",
                   static_cast<mrb_int>(registered_.size()), static_cast<mrb_int>(max_listeners));
    }
    out_registered.assign(registered_.begin(), registered_.end());
}

// A pack and no app: the asset tier answers before routing, so this app
// exists only to be a listener's app - no routes, no resources, and every
// path the pack does not name is a 404. There is deliberately no resource
// here: an unfolded one answers out of nowhere, with no media type and no
// callback behind any of it (#201).
AppSpec *app_assets_only()
{
    specs_.push_back(std::unique_ptr<AppSpec>(new AppSpec()));
    AppSpec *spec = specs_.back().get();
    // No open()/commit() here: that pair is a route - the one with an empty
    // token list, which is the root path. An empty table matches nothing, and
    // that is the point.
    spec->registered = true;
    registered_.push_back(spec);
    return spec;
}

// What the listener really became; this is what conf.url reads back.
void app_mark_bound(mrb_state *mrb, AppSpec &spec, const char *unix_path, int port)
{
    if (unix_path != nullptr) {
        spec.bound_url = std::string("unix://") + unix_path;
    } else if (!spec.url_host.empty()) {
        spec.bound_url = "http://" + spec.url_host + ":" + std::to_string(port);
    } else {
        spec.bound_url = "http://0.0.0.0:" + std::to_string(port);
    }
    spec.bound = true;
    if (!mrb_nil_p(spec.conf)) {
        mrb_ary_set(mrb, spec.conf, kConfUrl,
                    mrb_str_new(mrb, spec.bound_url.data(), spec.bound_url.size()));
    }
}

// Run the ready hook from the tool, outside any VM frame - so, funcall.
void app_ready_run(mrb_state *mrb, AppSpec &spec)
{
    if (!spec.have_ready)
        return;
    const ArenaGuard arena(mrb);
    mrb_funcall_argv(mrb, spec.ready, MRB_SYM(call), 0, nullptr);
    if (mrb->exc != nullptr)
        rethrow(mrb);
}
} // namespace webmachine
