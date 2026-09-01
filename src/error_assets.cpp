// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace webmachine {
namespace {

// RFC 9110 15 and the registries around it. reason() already spells the
// name for the status line; this table exists for the second half - a
// page that says "RFC 9110" under a 404 and "Cloudflare, not registered"
// under a 521 tells the reader which of the two they are looking at.
struct Face {
  uint16_t status;
  const char* title;
  const char* source;
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

const Face* face_for(uint16_t status) {
  for (const Face& f : kFaces) {
    if (f.status == status) return &f;
  }
  return nullptr;
}

// mruby: the handler call, under mrb_protect_error - it is app code from
// the moment somebody reopens the class, and app code raises.
struct HandlerCall {
  mrb_value self;
  mrb_sym sym;
  mrb_value arg;
};
// The same call with no arguments at all - a class body, a declaration.
mrb_value handler_no_args(mrb_state* mrb, void* ud) {
  const HandlerCall* c = static_cast<const HandlerCall*>(ud);
  return mrb_funcall_argv(mrb, c->self, c->sym, 0, nullptr);
}

mrb_value handler_body(mrb_state* mrb, void* ud) {
  const HandlerCall* c = static_cast<const HandlerCall*>(ud);
  return mrb_funcall_argv(mrb, c->self, c->sym, 1, &c->arg);
}

}  // namespace

// XDG Base Directory Specification, and the FHS underneath it: shipped
// read-only data lives in <datadir>/<package>, and XDG's own defaults
// for XDG_DATA_DIRS are "/usr/local/share:/usr/share" - the FHS pair.
// True only for a path that names a plain file that is there.
bool is_regular_file(const std::string& p) {
  struct stat st {};
  return !p.empty() && ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

// So one search order covers a distro package, a local build and a
// container image, without any of them being special-cased and without
// walking from argv[0], which is a trick rather than a convention.
//
// An explicit path always wins; it is the only one that may fail loudly.
std::string error_assets_path(const char* configured) {
  if (configured != nullptr && configured[0] != '\0') return std::string(configured);
  if (const char* env = ::getenv("WM_ERROR_ASSETS"); env != nullptr && env[0] != '\0') {
    return std::string(env);
  }
  static constexpr const char* kLeaf = "/webmachine-mruby/error-assets.zip";
  if (const char* home = ::getenv("XDG_DATA_HOME"); home != nullptr && home[0] == '/') {
    const std::string p = std::string(home) + kLeaf;
    if (is_regular_file(p)) return p;
  } else if (const char* h = ::getenv("HOME"); h != nullptr && h[0] == '/') {
    const std::string p = std::string(h) + "/.local/share" + kLeaf;
    if (is_regular_file(p)) return p;
  }
  const char* dirs = ::getenv("XDG_DATA_DIRS");
  const std::string list =
      (dirs != nullptr && dirs[0] != '\0') ? std::string(dirs) : "/usr/local/share:/usr/share";
  size_t at = 0;
  while (at <= list.size()) {
    const size_t end = list.find(':', at);
    const std::string dir = list.substr(at, end == std::string::npos ? std::string::npos
                                                                    : end - at);
    if (!dir.empty() && dir[0] == '/') {
      const std::string p = dir + kLeaf;
      if (is_regular_file(p)) return p;
    }
    if (end == std::string::npos) break;
    at = end + 1;
  }
  // Nothing installed. A server started out of its own build tree is the
  // ordinary case while a thing is being written, and it should find the
  // file lying right there rather than answer every error in plain text
  // because nobody ran `make install` yet. So: walk UP from the binary
  // and take the first ancestor that carries the shipped layout. That is
  // one stat per level at startup, and it covers both shapes with the
  // same walk - /usr/bin -> /usr/share/webmachine-mruby/, and a build
  // directory somewhere under the checkout -> the checkout's share/.
  char exe[4096];
  const ssize_t n = ::readlink("/proc/self/exe", exe, sizeof exe - 1);
  if (n <= 0) return std::string();
  exe[n] = '\0';
  std::string dir(exe, static_cast<size_t>(n));
  for (int up = 0; up < 12; up++) {
    const size_t slash = dir.rfind('/');
    if (slash == std::string::npos || slash == 0) break;
    dir.resize(slash);
    // The installed spelling first: it is the one an operator can also
    // reach through XDG, so a tree that has both stays consistent.
    const std::string shared = dir + "/share" + kLeaf;
    if (is_regular_file(shared)) return shared;
    const std::string flat = dir + "/share/error-assets.zip";
    if (is_regular_file(flat)) return flat;
  }
  return std::string();
}

// RFC 9110 15: what this status is called, from the same list the error assets is
// built from - reason() covers what the status LINE needs, which is not
// the same set.
const char* status_title(uint16_t status) {
  const Face* f = face_for(status);
  return f != nullptr ? f->title : http::reason(status);
}

// Who registered it. "not registered" is a fact about the code, not a
// hedge: 15 of the 54 are vendor inventions and the page says so.
const char* status_source(uint16_t status) {
  const Face* f = face_for(status);
  return f != nullptr ? f->source : "not registered";
}


ErrorPages::~ErrorPages() {
  if (mrb_ != nullptr && !mrb_nil_p(res_)) mrb_gc_unregister(mrb_, res_);
}

// #210: one instance of Webmachine::ErrorResource, and the handlers it
// answers to. Rooted with mrb_gc_register, not the arena: it outlives
// every arena mark the setup path takes and every one a request takes.
bool ErrorPages::open(mrb_state* mrb, Assets* assets, char* err, size_t errlen) {
  mrb_ = mrb;
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  if (wm == nullptr) {
    std::snprintf(err, errlen, "error pages: Webmachine is not defined");
    return false;
  }
  if (!mrb_const_defined_at(mrb, mrb_obj_value(wm), MRB_SYM(ErrorResource))) {
    std::snprintf(err, errlen, "error pages: Webmachine::ErrorResource is not defined");
    return false;
  }
  struct RClass* klass = mrb_class_get_under_id(mrb, wm, MRB_SYM(ErrorResource));
  const int ai = mrb_gc_arena_save(mrb);
  mrb_bool raised = FALSE;
  {
    // A class body that raises (a template of its own that does not
    // parse) is a startup refusal with a name, not a crash on the first
    // 404.
    HandlerCall c{mrb_obj_value(klass), MRB_SYM(new), mrb_nil_value()};
    const mrb_value obj = mrb_protect_error(
        mrb,
        handler_no_args,
        &c, &raised);
    if (raised) {
      std::snprintf(err, errlen, "error pages: Webmachine::ErrorResource.new raised");
      mrb->exc = nullptr;
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    res_ = obj;
    mrb_gc_register(mrb, res_);
  }
  mrb_gc_arena_restore(mrb, ai);

  // cb.rb content_types_provided: the same word an ordinary resource
  // uses, and the whole negotiation. What it lists is what an error may
  // be spelled as; the order breaks ties, so the first entry is what a
  // client with no opinion gets.
  {
    HandlerCall c{mrb_obj_value(klass), MRB_SYM(content_types_provided), mrb_nil_value()};
    const mrb_value v = mrb_protect_error(
        mrb,
        handler_no_args,
        &c, &raised);
    if (raised || !mrb_array_p(v)) {
      std::snprintf(err, errlen,
                    "error pages: ErrorResource.content_types_provided must answer "
                    "[[type, handler]] pairs");
      mrb->exc = nullptr;
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    const mrb_int n = RARRAY_LEN(v);
    for (mrb_int i = 0; i < n; i++) {
      const mrb_value pair = mrb_ary_ref(mrb, v, i);
      if (!mrb_array_p(pair) || RARRAY_LEN(pair) < 2) continue;
      const mrb_value type = mrb_ary_ref(mrb, pair, 0);
      const mrb_value hnd = mrb_ary_ref(mrb, pair, 1);
      if (!mrb_string_p(type) || !mrb_symbol_p(hnd)) {
        std::snprintf(err, errlen,
                      "error pages: content_types_provided pairs are [String, Symbol]");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      Handler h;
      h.sym = mrb_symbol(hnd);
      h.type.assign(RSTRING_PTR(type), static_cast<size_t>(RSTRING_LEN(type)));
      // An image form is the error assets's picture, whole. Nothing renders it,
      // so it names no method that has to exist - and it is worth
      // offering only while there is an asset file to take it from.
      h.from_pack = h.type.compare(0, 6, "image/") == 0;
      if (h.from_pack) {
        if (assets == nullptr) continue;
      } else if (!mrb_respond_to(mrb, res_, h.sym)) {
        std::snprintf(err, errlen, "error pages: %s names %s, which is not defined",
                      h.type.c_str(), mrb_sym_name(mrb, h.sym));
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      have_.push_back(std::move(h));
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  if (have_.empty()) {
    std::snprintf(err, errlen, "error pages: ErrorResource offers no content type");
    return false;
  }
  types_.reserve(have_.size());
  for (const Handler& h : have_) types_.push_back(h.type);
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
  if (assets != nullptr) read_cats(*assets);
  ready_ = true;
  // After the cats: their URL is part of the page, so a page prepared
  // before them would be a page without one.
  read_prepared();
  return true;
}

// RFC 9110 12.5.1: which form this client can read. An error is not a
// representation of the resource, so content_types_provided has no say -
// only Accept does, weighed against what the error resource offers.
//
// First match in table order, which is html, then json, then the rest.
// With three forms that is honest; the day this list is ten long, Accept
// has to be weighed with its q-values instead.
int ErrorPages::media_for(uint16_t status, const char* accept, size_t len) const {
  if (have_.empty()) return -1;
  // A form the error assets cannot answer for THIS status is not on offer for
  // it: the picture exists per status, not per server.
  const bool have_cat = status >= kFirstError && status < kPastLastError &&
                        cat_index_[status - kFirstError] > 0;
  // The same weighing c4 does for a resource - q-values, both wildcard
  // forms, provided order breaking ties. An Accept nothing matches still
  // gets an answer: an error is not a representation of the resource, so
  // there is nothing here to 406 about. text/plain is the way out,
  // because every client can read it.
  if (accept == nullptr || len == 0) return html_;
  // choose_media_type weighs the whole list, so a missing picture is
  // taken out of the list rather than out of its answer.
  std::vector<std::string> offer;
  std::vector<int> slot;
  offer.reserve(types_.size());
  slot.reserve(types_.size());
  for (size_t i = 0; i < have_.size(); i++) {
    if (have_[i].from_pack && !have_cat) continue;
    offer.push_back(types_[i]);
    slot.push_back(static_cast<int>(i));
  }
  if (offer.empty()) return plain_;
  const int at = http::choose_media_type({offer, {accept, len}});
  if (at < 0) return plain_;
  const int pick = slot[static_cast<size_t>(at)];
  // RFC 9110 12.5.1 leaves the tie to the server, and a tie is what a
  // wildcard makes of every form we have. A client that NAMED types and
  // named none of ours has an opinion, and the honest reading of "*/*;
  // q=0.5" behind it is "anything, at half preference" - not "your
  // styled page". A browser fetching an image sends exactly that, and a
  // 1.6 KB page it cannot render is bytes it throws away.
  //
  // So: named nothing of ours, but named SOMETHING - the cheapest form.
  // Named one of ours, or named nothing at all (curl's bare */*), the
  // negotiation above stands.
  if (named_ours(accept, len) || !names_anything(accept, len)) return pick;
  return plain_;
}

// The picture IS the answer: the error assets's bytes, lent where they lie.
const char* ErrorPages::pack_body(uint16_t status, int slot, size_t* len) const {
  if (slot < 0 || static_cast<size_t>(slot) >= have_.size()) return nullptr;
  if (!have_[static_cast<size_t>(slot)].from_pack) return nullptr;
  if (status < kFirstError || status >= kPastLastError) return nullptr;
  const int16_t at = cat_index_[status - kFirstError];
  if (at <= 0) return nullptr;
  const Cat& c = cats_[static_cast<size_t>(at)];
  if (c.entry == nullptr) return nullptr;
  *len = c.entry->uncompressed_size;
  return c.entry->file_data;
}

// The bytes `t` anywhere in the first `len` of `accept`.
bool contains(const char* accept, size_t len, const char* t, size_t tlen) {
  for (size_t i = 0; i + tlen <= len; i++) {
    if (std::memcmp(accept + i, t, tlen) == 0) return true;
  }
  return false;
}

// One key of the mustache context, both halves as Strings.
void hash_put_str(mrb_state* mrb, mrb_value ctx, const char* key, const char* val, size_t len) {
  mrb_hash_set(mrb, ctx, mrb_str_new_cstr(mrb, key),
               mrb_str_new(mrb, val, static_cast<mrb_int>(len)));
}

// RFC 9110 12.5.1: does this Accept name one of the forms we offer, as a
// type and subtype rather than through a range?
bool ErrorPages::named_ours(const char* accept, size_t len) const {
  for (const Handler& h : have_) {
    const char* t = h.type.c_str();
    const char* semi = std::strchr(t, ';');
    const size_t tlen = semi != nullptr ? static_cast<size_t>(semi - t) : h.type.size();
    if (contains(accept, len, t, tlen)) return true;
    // RFC 9110 12.5.1: "image/*" is a preference for every image type,
    // and it carries its own q - a browser fetching a picture writes
    // image/*;q=0.8 above */*;q=0.5 precisely to say which it would
    // rather have. That is naming us, and it is not the same as the
    // */* that means "if you must".
    const char* slash = std::strchr(t, '/');
    if (slash == nullptr) continue;
    std::string range(t, static_cast<size_t>(slash - t) + 1);
    range += '*';
    if (contains(accept, len, range.data(), range.size())) return true;
  }
  return false;
}

// Does it name any concrete type at all, or is it wildcards only? A
// client with no opinion is not a client to be given the cheap answer.
bool ErrorPages::names_anything(const char* accept, size_t len) {
  size_t at = 0;
  while (at < len) {
    while (at < len && (accept[at] == ' ' || accept[at] == '\t' || accept[at] == ',')) at++;
    size_t end = at;
    while (end < len && accept[end] != ',' && accept[end] != ';') end++;
    if (end > at && !(end - at == 3 && std::memcmp(accept + at, "*/*", 3) == 0)) return true;
    while (at < len && accept[at] != ',') at++;
  }
  return false;
}

const char* ErrorPages::media_type(int slot) const {
  if (slot < 0 || static_cast<size_t>(slot) >= have_.size()) return "text/plain; charset=utf-8";
  return have_[static_cast<size_t>(slot)].type.c_str();
}

// mruby: what a resource that raised has to say. fsm.rb's handle_exception,
// on the error resource and nowhere else - how an exception becomes text
// is one decision for the server, not a per-route one.
bool ErrorPages::exception_text(mrb_value exc, std::string& out) {
  if (!ready_) return false;
  const int ai = mrb_gc_arena_save(mrb_);
  HandlerCall c{res_, exc_sym_, exc};
  mrb_bool raised = FALSE;
  const mrb_value v = mrb_protect_error(mrb_, handler_body, &c, &raised);
  if (raised) {
    mrb_->exc = nullptr;
    mrb_gc_arena_restore(mrb_, ai);
    return false;
  }
  // The one thing this server fixes about handle_exception is the shape
  // of its answer: a String, or an Array joined with CRLF. What goes in
  // it - a backtrace included - is the app's call, not this layer's.
  if (mrb_string_p(v)) {
    out.assign(RSTRING_PTR(v), RSTRING_LEN(v));
  } else if (mrb_array_p(v)) {
    const mrb_int n = RARRAY_LEN(v);
    for (mrb_int i = 0; i < n; i++) {
      const mrb_value e = mrb_ary_ref(mrb_, v, i);
      if (!out.empty()) out.append("\r\n");
      if (mrb_string_p(e)) {
        out.append(RSTRING_PTR(e), static_cast<size_t>(RSTRING_LEN(e)));
      } else {
        const mrb_value st = mrb_obj_as_string(mrb_, e);
        if (mrb_string_p(st)) out.append(RSTRING_PTR(st), static_cast<size_t>(RSTRING_LEN(st)));
      }
    }
  } else {
    // nil is an answer: "this 500 says nothing but 500".
    mrb_gc_arena_restore(mrb_, ai);
    return false;
  }
  mrb_gc_arena_restore(mrb_, ai);
  return true;
}

// A picture per status, named by it: 404.jpg is the one a 404 gets. The
// archive holds nothing else, so its own entry list is the index.
void ErrorPages::read_cats(Assets& assets) {
  // Slot 0 is "no picture", the way index_ reserves its own zero.
  cats_.emplace_back();
  for (const AssetEntry& e : assets.entries()) {
    // PKWARE APPNOTE: a deflated entry would need inflating per answer,
    // which is not what an error path is for.
    if (e.deflated) continue;
    unsigned status = 0;
    char tail[8] = {};
    if (std::sscanf(e.file_name.c_str(), "%u.%3s", &status, tail) != 2) continue;
    if (std::strcmp(tail, "jpg") != 0) continue;
    // An answer below 400 is not a failure and gets no page, so a picture
    // for one is a file the pack was not built to hold.
    if (status < kFirstError || status >= kPastLastError) continue;
    if (cat_index_[status - kFirstError] != 0) continue;
    // Nothing but the entry: the <img> it carries is the whole answer.
    if (e.img_tag == nullptr) continue;
    Cat c;
    c.entry = &e;
    cat_index_[status - kFirstError] = static_cast<int16_t>(cats_.size());
    cats_.push_back(std::move(c));
  }
}

// #210: one error body. The Hash built here is what every handler is
// handed, and it is also the template context - status, title, source,
// target, and for a 500 the message. Rendered per response: a 404 names
// what was not found, so there is nothing a boot could have prepared.
bool ErrorPages::render(uint16_t status, int slot, const Fields& f, std::string& out) {
  if (!ready_ || slot < 0 || static_cast<size_t>(slot) >= have_.size()) return false;
  mrb_state* mrb = mrb_;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value ctx = mrb_hash_new(mrb);
  mrb_hash_set(mrb, ctx, mrb_str_new_lit(mrb, "status"), mrb_fixnum_value(status));
  hash_put_str(mrb, ctx, "title", status_title(status), std::strlen(status_title(status)));
  hash_put_str(mrb, ctx, "source", status_source(status), std::strlen(status_source(status)));
  if (f.fingerprint != nullptr) hash_put_str(mrb, ctx, "id", f.fingerprint, kFingerprintLen);
  if (f.message != nullptr && f.message_len != 0) hash_put_str(mrb, ctx, "message", f.message, f.message_len);
  if (f.backtrace != nullptr && f.backtrace_len != 0) {
    hash_put_str(mrb, ctx, "backtrace", f.backtrace, f.backtrace_len);
  }
  const int16_t cslot = status >= kFirstError && status < kPastLastError
                            ? cat_index_[status - kFirstError]
                            : 0;
  if (cslot > 0) {
    const Cat& c = cats_[static_cast<size_t>(cslot)];
    mrb_value cat = mrb_hash_new(mrb);
    // The pack carries the <img> finished - src, size and alt - so the
    // page lends it out and joins nothing.
    hash_put_str(mrb, cat, "cat_tag", c.entry->img_tag, c.entry->img_tag_len);
    mrb_hash_set(mrb, ctx, mrb_str_new_lit(mrb, "cat"), cat);
  }

  HandlerCall c{res_, have_[static_cast<size_t>(slot)].sym, ctx};
  mrb_bool raised = FALSE;
  const mrb_value body = mrb_protect_error(mrb, handler_body, &c, &raised);
  if (raised || !mrb_string_p(body)) {
    // A handler that raises has no page to offer, and the caller still
    // owes the client an answer - it falls back to the bodyless status.
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  out.assign(RSTRING_PTR(body), RSTRING_LEN(body));
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

// #210: every status this build can spell, rendered once. An answer that
// names no failure carries nothing a request could have changed, so the
// bytes it sends are decided here and lent from here - the template runs
// at boot, and a 404 costs a memcpy.
void ErrorPages::read_prepared() {
  const size_t width = have_.size();
  const Fields nothing;
  std::string page;
  size_t slot = 0;
  size_t row = 0;

  // Row 0 is the one prep_index_ names when a status has none.
  prepared_.assign(width, std::string());
  for (const Face& face : kFaces) {
    row = prepared_.size() / width;
    prepared_.resize(prepared_.size() + width);
    prep_index_[face.status - kFirstError] = static_cast<int16_t>(row);
    for (slot = 0; slot < width; slot++) {
      if (have_[slot].from_pack) continue;
      if (render(face.status, static_cast<int>(slot), nothing, page)) {
        prepared_[row * width + slot] = page;
      }
    }
  }
}

const char* ErrorPages::body_for(const Page& p, std::string& held, size_t* len) {
  const uint16_t status = p.status;
  const int slot = p.slot;
  const Fields& f = p.fields;
  const char* lent = pack_body(status, slot, len);
  if (lent != nullptr) return lent;
  // An answer with nothing of its own to say is the page this status
  // always sends.
  if (f.message_len == 0 && f.backtrace_len == 0 && f.fingerprint == nullptr) {
    lent = prepared_body(status, slot, len);
    if (lent != nullptr) return lent;
  }
  if (!render(status, slot, f, held)) return nullptr;
  *len = held.size();
  return held.data();
}

const char* ErrorPages::prepared_body(uint16_t status, int slot, size_t* len) const {
  if (!ready_ || status < kFirstError || status >= kPastLastError || slot < 0) return nullptr;
  const int16_t row = prep_index_[status - kFirstError];
  if (row <= 0) return nullptr;
  const std::string& page =
      prepared_[static_cast<size_t>(row) * have_.size() +
                static_cast<size_t>(slot)];
  if (page.empty()) return nullptr;
  *len = page.size();
  return page.data();
}

}  // namespace webmachine
