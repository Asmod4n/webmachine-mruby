#include "ruby_value.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace webmachine
{
namespace
{

// RFC 9110 15 and the registries around it. reason() already spells the
// name for the status line; this table exists for the second half - a
// page that says "RFC 9110" under a 404 and "Cloudflare, not registered"
// under a 521 tells the reader which of the two they are looking at.
struct Face {
    uint16_t status;
    const char *title;
    const char *source;
};
constexpr Face kFaces[] = {
    {400, "Bad Request", "RFC 9110"},
    {401, "Unauthorized", "RFC 9110"},
    {402, "Payment Required", "RFC 9110"},
    {403, "Forbidden", "RFC 9110"},
    {404, "Not Found", "RFC 9110"},
    {405, "Method Not Allowed", "RFC 9110"},
    {406, "Not Acceptable", "RFC 9110"},
    {407, "Proxy Authentication Required", "RFC 9110"},
    {408, "Request Timeout", "RFC 9110"},
    {409, "Conflict", "RFC 9110"},
    {410, "Gone", "RFC 9110"},
    {411, "Length Required", "RFC 9110"},
    {412, "Precondition Failed", "RFC 9110"},
    {413, "Content Too Large", "RFC 9110"},
    {414, "URI Too Long", "RFC 9110"},
    {415, "Unsupported Media Type", "RFC 9110"},
    {416, "Range Not Satisfiable", "RFC 9110"},
    {417, "Expectation Failed", "RFC 9110"},
    {419, "Page Expired", "Laravel, not registered"},
    {420, "Enhance Your Calm", "Twitter, not registered"},
    {421, "Misdirected Request", "RFC 9110"},
    {422, "Unprocessable Content", "RFC 9110"},
    {423, "Locked", "RFC 4918"},
    {424, "Failed Dependency", "RFC 4918"},
    {425, "Too Early", "RFC 8470"},
    {426, "Upgrade Required", "RFC 9110"},
    {428, "Precondition Required", "RFC 6585"},
    {429, "Too Many Requests", "RFC 6585"},
    {431, "Request Header Fields Too Large", "RFC 6585"},
    {444, "No Response", "nginx, not registered"},
    {450, "Blocked by Windows Parental Controls", "Microsoft, not registered"},
    {451, "Unavailable For Legal Reasons", "RFC 7725"},
    {495, "SSL Certificate Error", "nginx, not registered"},
    {496, "SSL Certificate Required", "nginx, not registered"},
    {497, "HTTP Request Sent to HTTPS Port", "nginx, not registered"},
    {498, "Invalid Token", "Esri, not registered"},
    {499, "Client Closed Request", "nginx, not registered"},
    {500, "Internal Server Error", "RFC 9110"},
    {501, "Not Implemented", "RFC 9110"},
    {502, "Bad Gateway", "RFC 9110"},
    {503, "Service Unavailable", "RFC 9110"},
    {504, "Gateway Timeout", "RFC 9110"},
    {506, "Variant Also Negotiates", "RFC 2295"},
    {507, "Insufficient Storage", "RFC 4918"},
    {508, "Loop Detected", "RFC 5842"},
    {509, "Bandwidth Limit Exceeded", "Apache/cPanel, not registered"},
    {510, "Not Extended", "RFC 2774"},
    {511, "Network Authentication Required", "RFC 6585"},
    {521, "Web Server Is Down", "Cloudflare, not registered"},
    {522, "Connection Timed Out", "Cloudflare, not registered"},
    {523, "Origin Is Unreachable", "Cloudflare, not registered"},
    {525, "SSL Handshake Failed", "Cloudflare, not registered"},
    {530, "Site Frozen", "Cloudflare, not registered"},
    {599, "Network Connect Timeout Error", "not registered"},
};

// The face of a status, by index: one table over 400..599, built at
// compile time, so a lookup is one load.
constexpr uint16_t kFaceFirst = 400;
constexpr uint16_t kFacePast = 600;
struct FaceIndex {
    const Face *status[kFacePast - kFaceFirst] = {};
    constexpr FaceIndex()
    {
        for (const Face &f : kFaces)
            status[f.status - kFaceFirst] = &f;
    }
};
constexpr FaceIndex kFaceIndex;

const Face *face_of_status(uint16_t status)
{
    if (status < kFaceFirst || status >= kFacePast)
        return nullptr;
    return kFaceIndex.status[status - kFaceFirst];
}

// mruby: the handler call, under mrb_protect_error - it is app code from
// the moment somebody reopens the class, and app code raises.
struct HandlerCall {
    mrb_value self;
    mrb_sym method_name;
    mrb_value argument;
};
// The same call with no arguments at all - a class body, a declaration.
mrb_value handler_call_with_no_args(mrb_state *mrb, void *user_data)
{
    const HandlerCall *call = static_cast<const HandlerCall *>(user_data);
    return mrb_funcall_argv(mrb, call->self, call->method_name, 0, nullptr);
}

// One instance of the handler class, under the same protection.
mrb_value handler_build(mrb_state *mrb, void *user_data)
{
    return mrb_obj_new(mrb, static_cast<struct RClass *>(user_data), 0, nullptr);
}

mrb_value handler_call_in_protected_call(mrb_state *mrb, void *user_data)
{
    const HandlerCall *call = static_cast<const HandlerCall *>(user_data);
    return mrb_funcall_argv(mrb, call->self, call->method_name, 1, &call->argument);
}

} // namespace

// Filesystem Hierarchy Standard 4.11: read-only data of a package lives
// in <datadir>/<package>, and the two datadirs are /usr/local/share for
// software installed locally and /usr/share for the distribution's. An
// explicit path wins. Nothing is read from the environment, and nothing
// under a user's home is looked at: whoever can write there would
// write every error page.
namespace
{
bool path_is_regular_file(const std::string &path)
{
    struct stat st {
    };
    return !path.empty() && ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}
} // namespace

std::string error_assets_path(const char *configured)
{
    if (configured != nullptr && configured[0] != '\0')
        return std::string(configured);
    static constexpr const char *const kInstalled[] = {
        "/usr/local/share/webmachine-mruby/error-assets.zip",
        "/usr/share/webmachine-mruby/error-assets.zip",
    };
    for (const char *p : kInstalled) {
        if (path_is_regular_file(p))
            return std::string(p);
    }
    return std::string();
}

// RFC 9110 15: what this status is called, from the same list the error assets is
// built from - reason() covers what the status line needs, which is not
// the same set.
const char *status_title(uint16_t status)
{
    const Face *face = face_of_status(status);
    return face != nullptr ? face->title : http::reason(status);
}

// Who registered it. "not registered" is a fact about the code, not a
// hedge: 15 of the 54 are vendor inventions and the page says so.
const char *status_source(uint16_t status)
{
    const Face *face = face_of_status(status);
    return face != nullptr ? face->source : "not registered";
}

ErrorPages::~ErrorPages()
{
    if (mrb_ != nullptr && !mrb_nil_p(res_))
        mrb_gc_unregister(mrb_, res_);
}

// #210: one instance of Webmachine::ErrorResource, and the handlers it
// answers to. Rooted with mrb_gc_register, not the arena: it outlives
// every arena mark the setup path takes and every one a request takes.
void ErrorPages::open(mrb_state *mrb, Assets *assets, Logger *elog)
{
    elog_ = elog;
    mrb_ = mrb;
    struct RClass *webmachine_module = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
    if (webmachine_module == nullptr) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "error pages: Webmachine is not defined");
    }
    if (!mrb_const_defined_at(mrb, mrb_obj_value(webmachine_module), MRB_SYM(ErrorResource))) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "error pages: Webmachine::ErrorResource is not defined");
    }
    struct RClass *klass = mrb_class_get_under_id(mrb, webmachine_module, MRB_SYM(ErrorResource));
    const ArenaGuard arena(mrb);
    mrb_bool raised = FALSE;
    {
        // A class body that raises (a template of its own that does not
        // parse) is a startup refusal with a name, not a crash on the first
        // 404.
        const mrb_value instance = mrb_protect_error(mrb, handler_build, klass, &raised);
        if (raised)
            reraise(mrb, instance);
        res_ = instance;
        mrb_gc_register(mrb, res_);
    }

    // cb.rb content_types_provided: the same word an ordinary resource
    // uses, and the whole negotiation. What it lists is what an error may
    // be spelled as; the order breaks ties, so the first entry is what a
    // client with no opinion gets.
    {
        HandlerCall c{mrb_obj_value(klass), MRB_SYM(content_types_provided), mrb_nil_value()};
        const mrb_value value = mrb_protect_error(mrb, handler_call_with_no_args, &c, &raised);
        if (raised)
            reraise(mrb, value);
        if (!mrb_array_p(value)) {
            mrb_raisef(mrb, E_WM_ERROR(mrb),
                       "error pages: ErrorResource.content_types_provided must answer "
                       "[[type, handler]] pairs, not %v",
                       value);
        }
        const size_t count = ruby_array_length(value);
        for (size_t i = 0; i < count; i++) {
            const mrb_value pair = mrb_ary_ref(mrb, value, static_cast<mrb_int>(i));
            if (!mrb_array_p(pair) || ruby_array_length(pair) < 2)
                continue;
            const mrb_value type = mrb_ary_ref(mrb, pair, 0);
            const mrb_value handler_name = mrb_ary_ref(mrb, pair, 1);
            if (!mrb_string_p(type) || !mrb_symbol_p(handler_name)) {
                mrb_raisef(
                    mrb, E_WM_ERROR(mrb),
                    "error pages: content_types_provided pairs are [String, Symbol], and %v is "
                    "not one",
                    pair);
            }
            Handler handler;
            handler.sym = mrb_symbol(handler_name);
            handler.type.assign(ruby_string_bytes(type));
            // An image form is the error assets's picture, whole. Nothing renders it,
            // so it names no method that has to exist - and it is worth
            // offering only while there is an asset file to take it from.
            handler.from_pack = handler.type.compare(0, 6, "image/") == 0;
            if (handler.from_pack) {
                if (assets == nullptr)
                    continue;
            } else if (!mrb_respond_to(mrb, res_, handler.sym)) {
                mrb_raisef(mrb, E_WM_ERROR(mrb), "error pages: %s names %n, which is not defined",
                           handler.type.c_str(), handler.sym);
            }
            have_.push_back(std::move(handler));
        }
    }
    if (have_.empty()) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "error pages: ErrorResource offers no content type");
    }
    types_.reserve(have_.size());
    for (const Handler &h : have_)
        types_.push_back(h.type);
    // The way out, by name: whatever a client asked for, text/plain is
    // something every one of them can read. Only when the list does not
    // offer it at all does the last entry stand in.
    plain_ = static_cast<int>(have_.size()) - 1;
    for (size_t i = 0; i < have_.size(); i++) {
        if (have_[i].type.compare(0, 10, "text/plain") == 0) {
            plain_ = static_cast<int>(i);
            break;
        }
    }
    // What a client with no Accept at all gets. The first form the list
    // names, unless that one is a picture - a client that said nothing
    // did not ask for one.
    html_ = 0;
    for (size_t i = 0; i < have_.size(); i++) {
        if (!have_[i].from_pack) {
            html_ = static_cast<int>(i);
            break;
        }
    }
    exc_sym_ = MRB_SYM(handle_exception);
    if (assets != nullptr)
        cats_read(*assets);
    ready_ = true;
    // After the cats: their URL is part of the page, so a page prepared
    // before them would be a page without one.
    prepared_pages_read();
}

// RFC 9110 12.5.1: which form this client can read. An error is not a
// representation of the resource, so content_types_provided has no say -
// only Accept does, weighed against what the error resource offers.
//
// First match in table order, which is html, then json, then the rest.
// With three forms that is honest; the day this list is ten long, Accept
// has to be weighed with its q-values instead.
int ErrorPages::media_pick_for_status(uint16_t status, const char *accept,
                                      size_t accept_length) const
{
    if (have_.empty())
        return -1;
    // A form the error assets cannot answer for this status is not on offer for
    // it: the picture exists per status, not per server.
    const bool have_cat =
        status >= kFirstError && status < kPastLastError && cat_index_[status - kFirstError] > 0;
    // The same weighing c4 does for a resource - q-values, both wildcard
    // forms, provided order breaking ties. An Accept nothing matches still
    // gets an answer: an error is not a representation of the resource, so
    // there is nothing here to 406 about. text/plain is the way out,
    // because every client can read it.
    if (accept == nullptr || accept_length == 0)
        return html_;
    // choose_media_type weighs the whole list, so a missing picture is
    // taken out of the list rather than out of its answer.
    std::vector<std::string> offer;
    std::vector<int> slot;
    offer.reserve(types_.size());
    slot.reserve(types_.size());
    for (size_t i = 0; i < have_.size(); i++) {
        if (have_[i].from_pack && !have_cat)
            continue;
        offer.push_back(types_[i]);
        slot.push_back(static_cast<int>(i));
    }
    if (offer.empty())
        return plain_;
    const int cursor = http::choose_media_type({offer, {accept, accept_length}});
    if (cursor < 0)
        return plain_;
    const int pick = slot[static_cast<size_t>(cursor)];
    // RFC 9110 12.5.1 leaves the tie to the server, and a tie is what a
    // wildcard makes of every form we have. A client that named types and
    // named none of ours has an opinion, and the honest reading of "*/*;
    // q=0.5" behind it is "anything, at half preference" - not "your
    // styled page". A browser fetching an image sends exactly that, and a
    // 1.6 KB page it cannot render is bytes it throws away.
    //
    // So: named nothing of ours, but named something - the cheapest form.
    // Named one of ours, or named nothing at all (curl's bare */*), the
    // negotiation above stands.
    if (accept_names_one_of_ours(accept, accept_length) ||
        !accept_names_anything(accept, accept_length))
        return pick;
    return plain_;
}

// The picture is the answer: the error assets's bytes, lent where they lie.
const char *ErrorPages::pack_body_of_status(uint16_t status, int slot, size_t *out_length) const
{
    if (slot < 0 || static_cast<size_t>(slot) >= have_.size())
        return nullptr;
    if (!have_[static_cast<size_t>(slot)].from_pack)
        return nullptr;
    if (status < kFirstError || status >= kPastLastError)
        return nullptr;
    const int16_t cursor = cat_index_[status - kFirstError];
    if (cursor <= 0)
        return nullptr;
    const Cat &cat_row = cats_[static_cast<size_t>(cursor)];
    if (cat_row.entry == nullptr)
        return nullptr;
    *out_length = cat_row.entry->uncompressed_size;
    return cat_row.entry->file_data;
}

// The bytes `t` anywhere in the first `len` of `accept`.
// RFC 9110 12.5.1: Accept is a list, and one member of it ends at a comma
// or a semicolon. A type has to fill a whole member: `text/html` inside
// `application/text/htmlx` names nothing of ours.
bool accept_member_edge(char character)
{
    return character == ',' || character == ';' || character == ' ' || character == '\t';
}

bool accept_holds_media_type(std::string_view accept, std::string_view media_type)
{
    const size_t media_type_length = accept.size();
    const size_t tlen = media_type.size();
    if (tlen == 0)
        return false;
    for (size_t i = 0; i + tlen <= media_type_length; i++) {
        if (std::memcmp(accept.data() + i, media_type.data(), tlen) != 0)
            continue;
        if (i != 0 && !accept_member_edge(accept[i - 1]))
            continue;
        const size_t after = i + tlen;
        if (after != media_type_length && !accept_member_edge(accept[after]))
            continue;
        return true;
    }
    return false;
}

// One key of the mustache context and the bytes behind it.
struct CtxEntry {
    const char *key_name;
    std::string_view value;
};

// Both halves as Strings.
void hash_put_string(mrb_state *mrb, mrb_value context, CtxEntry entry)
{
    mrb_hash_set(mrb, context, mrb_str_new_cstr(mrb, entry.key_name),
                 mrb_str_new(mrb, entry.value.data(), static_cast<mrb_int>(entry.value.size())));
}

// RFC 9110 12.5.1: does this Accept name one of the forms we offer, as a
// type and subtype rather than through a range?
bool ErrorPages::accept_names_one_of_ours(const char *accept, size_t accept_length) const
{
    for (const Handler &h : have_) {
        const char *our_type = h.type.c_str();
        const char *semi = std::strchr(our_type, ';');
        const size_t tlen = semi != nullptr ? static_cast<size_t>(semi - our_type) : h.type.size();
        if (accept_holds_media_type({accept, accept_length}, {our_type, tlen}))
            return true;
        // RFC 9110 12.5.1: "image/*" is a preference for every image type,
        // and it carries its own q - a browser fetching a picture writes
        // image/*;q=0.8 above */*;q=0.5 precisely to say which it would
        // rather have. That is naming us, and it is not the same as the
        // */* that means "if you must".
        const char *slash = std::strchr(our_type, '/');
        if (slash == nullptr)
            continue;
        std::string range(our_type, static_cast<size_t>(slash - our_type) + 1);
        range += '*';
        if (accept_holds_media_type({accept, accept_length}, range))
            return true;
    }
    return false;
}

// Does it name any concrete type at all, or is it wildcards only? A
// client with no opinion is not a client to be given the cheap answer.
bool ErrorPages::accept_names_anything(const char *accept, size_t accept_length)
{
    size_t cursor = 0;
    while (cursor < accept_length) {
        while (cursor < accept_length &&
               (accept[cursor] == ' ' || accept[cursor] == '\t' || accept[cursor] == ','))
            cursor++;
        size_t accept_end = cursor;
        while (accept_end < accept_length && accept[accept_end] != ',' && accept[accept_end] != ';')
            accept_end++;
        if (accept_end > cursor &&
            !(accept_end - cursor == 3 && std::memcmp(accept + cursor, "*/*", 3) == 0))
            return true;
        while (cursor < accept_length && accept[cursor] != ',')
            cursor++;
    }
    return false;
}

const char *ErrorPages::media_type_of_slot(int slot) const
{
    if (slot < 0 || static_cast<size_t>(slot) >= have_.size())
        return "text/plain; charset=utf-8";
    return have_[static_cast<size_t>(slot)].type.c_str();
}

// mruby: what a resource that raised has to say. fsm.rb's handle_exception,
// on the error resource and nowhere else - how an exception becomes text
// is one decision for the server, not a per-route one.
bool ErrorPages::exception_text(mrb_value exception, std::string &out_text)
{
    if (!ready_)
        return false;
    const int arena = mrb_gc_arena_save(mrb_);
    HandlerCall c{res_, exc_sym_, exception};
    mrb_bool raised = FALSE;
    const mrb_value answer = mrb_protect_error(mrb_, handler_call_in_protected_call, &c, &raised);
    if (raised) {
        mrb_->exc = nullptr;
        mrb_gc_arena_restore(mrb_, arena);
        return false;
    }
    // The one thing this server fixes about handle_exception is the shape
    // of its answer: a String, or an Array joined with CRLF. What goes in
    // it - a backtrace included - is the app's call, not this layer's.
    if (mrb_string_p(answer)) {
        out_text.assign(ruby_string_bytes(answer));
    } else if (mrb_array_p(answer)) {
        const size_t count = ruby_array_length(answer);
        for (size_t i = 0; i < count; i++) {
            const mrb_value entry = mrb_ary_ref(mrb_, answer, static_cast<mrb_int>(i));
            if (!out_text.empty())
                out_text.append("\r\n");
            if (mrb_string_p(entry)) {
                out_text.append(ruby_string_bytes(entry));
            } else {
                const mrb_value as_string = mrb_obj_as_string(mrb_, entry);
                if (mrb_string_p(as_string))
                    out_text.append(ruby_string_bytes(as_string));
            }
        }
    } else {
        // nil is an answer: "this 500 says nothing but 500".
        mrb_gc_arena_restore(mrb_, arena);
        return false;
    }
    mrb_gc_arena_restore(mrb_, arena);
    return true;
}

// A picture per status, named by it: 404.jpg is the one a 404 gets. The
// archive holds nothing else, so its own entry list is the index.
void ErrorPages::cats_read(Assets &assets)
{
    // Slot 0 is "no picture", the way index_ reserves its own zero.
    cats_.emplace_back();
    for (const AssetEntry &e : assets.entries()) {
        // PKWARE APPNOTE: a deflated entry would need inflating per answer,
        // which is not what an error path is for.
        if (e.deflated)
            continue;
        unsigned status = 0;
        char tail[8] = {};
        if (std::sscanf(e.file_name.c_str(), "%u.%3s", &status, tail) != 2)
            continue;
        if (std::strcmp(tail, "jpg") != 0)
            continue;
        // An answer below 400 is not a failure and gets no page, so a picture
        // for one is a file the pack was not built to hold.
        if (status < kFirstError || status >= kPastLastError)
            continue;
        if (cat_index_[status - kFirstError] != 0)
            continue;
        // Nothing but the entry: the <img> it carries is the whole answer.
        if (e.img_tag == nullptr)
            continue;
        Cat cat_row;
        cat_row.entry = &e;
        cat_index_[status - kFirstError] = static_cast<int16_t>(cats_.size());
        cats_.push_back(std::move(cat_row));
    }
}

// #210: one error body. The Hash built here is what every handler is
// handed, and it is also the template context: status, title, source,
// and for a 500 the fingerprint, the message and the backtrace.
// read_prepared runs this once per status at boot; body_for runs it
// again only for a page that carries one of those three.
bool ErrorPages::render(const Page &page, std::string &out_page)
{
    const uint16_t status = page.status;
    const int slot = page.slot;
    const Fields &face = page.fields;
    if (!ready_ || slot < 0 || static_cast<size_t>(slot) >= have_.size())
        return false;
    mrb_state *mrb = mrb_;
    const int arena = mrb_gc_arena_save(mrb);
    mrb_value context = mrb_hash_new(mrb);
    mrb_hash_set(mrb, context, mrb_str_new_lit(mrb, "status"), mrb_fixnum_value(status));
    hash_put_string(mrb, context, {"title", status_title(status)});
    hash_put_string(mrb, context, {"source", status_source(status)});
    if (face.fingerprint != nullptr) {
        hash_put_string(mrb, context, {"id", {face.fingerprint, kFingerprintLen}});
    }
    if (face.message != nullptr && face.message_len != 0) {
        hash_put_string(mrb, context, {"message", {face.message, face.message_len}});
    }
    if (face.backtrace != nullptr && face.backtrace_len != 0) {
        hash_put_string(mrb, context, {"backtrace", {face.backtrace, face.backtrace_len}});
    }
    const int16_t cslot =
        status >= kFirstError && status < kPastLastError ? cat_index_[status - kFirstError] : 0;
    if (cslot > 0) {
        const Cat &cat_row = cats_[static_cast<size_t>(cslot)];
        mrb_value cat_entry = mrb_hash_new(mrb);
        // The pack carries the <img> finished - src, size and alt - so the
        // page lends it out and joins nothing.
        hash_put_string(mrb, cat_entry,
                        {"cat_tag", {cat_row.entry->img_tag, cat_row.entry->img_tag_len}});
        mrb_hash_set(mrb, context, mrb_str_new_lit(mrb, "cat"), cat_entry);
    }

    HandlerCall c{res_, have_[static_cast<size_t>(slot)].sym, context};
    mrb_bool raised = FALSE;
    const mrb_value body = mrb_protect_error(mrb, handler_call_in_protected_call, &c, &raised);
    if (raised || !mrb_string_p(body)) {
        // A handler that raises has no page to offer, and the caller still
        // owes the client an answer - it falls back to the bodyless status.
        // The raise is reported, so the handler can be fixed.
        if (raised && mrb_exception_p(body)) {
            mrb->exc = mrb_obj_ptr(body);
            report_raise(elog_, mrb, 500);
        }
        mrb->exc = nullptr;
        mrb_gc_arena_restore(mrb, arena);
        return false;
    }
    out_page.assign(ruby_string_bytes(body));
    mrb_gc_arena_restore(mrb, arena);
    return true;
}

// #210: every status this build can spell, rendered once. An answer that
// names no failure carries nothing a request could have changed, so the
// bytes it sends are decided here and lent from here - the template runs
// at boot, and a 404 costs a memcpy.
void ErrorPages::prepared_pages_read()
{
    const size_t width = have_.size();
    const Fields nothing;
    std::string page;
    size_t slot = 0;
    size_t prepared_row = 0;

    // Row 0 is the one prep_index_ names when a status has none.
    prepared_.assign(width, std::string());
    for (const Face &face : kFaces) {
        prepared_row = prepared_.size() / width;
        prepared_.resize(prepared_.size() + width);
        prep_index_[face.status - kFirstError] = static_cast<int16_t>(prepared_row);
        for (slot = 0; slot < width; slot++) {
            if (have_[slot].from_pack)
                continue;
            if (render({face.status, static_cast<int>(slot), nothing}, page)) {
                prepared_[prepared_row * width + slot] = page;
            }
        }
    }
}

const char *ErrorPages::body_of_page(const Page &page, std::string &held, size_t *out_length)
{
    const uint16_t status = page.status;
    const int slot = page.slot;
    const Fields &face = page.fields;
    const char *lent = pack_body_of_status(status, slot, out_length);
    if (lent != nullptr)
        return lent;
    // An answer with nothing of its own to say is the page this status
    // always sends.
    if (face.message_len == 0 && face.backtrace_len == 0 && face.fingerprint == nullptr) {
        lent = prepared_body(status, slot, out_length);
        if (lent != nullptr)
            return lent;
    }
    if (!render({status, slot, face}, held))
        return nullptr;
    *out_length = held.size();
    return held.data();
}

const char *ErrorPages::prepared_body(uint16_t status, int slot, size_t *out_length) const
{
    if (!ready_ || status < kFirstError || status >= kPastLastError || slot < 0)
        return nullptr;
    const int16_t prepared_row = prep_index_[status - kFirstError];
    if (prepared_row <= 0)
        return nullptr;
    const std::string &page =
        prepared_[static_cast<size_t>(prepared_row) * have_.size() + static_cast<size_t>(slot)];
    if (page.empty())
        return nullptr;
    *out_length = page.size();
    return page.data();
}

} // namespace webmachine
