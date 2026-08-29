// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>

namespace webmachine {
namespace {

// PKWARE APPNOTE: an entry this tier may read straight out of the mapping.
// The pack builder stores the index (rake error_pages), so a deflated one
// is a pack built by something else - refused by name rather than
// inflated here, because setup is not the place to grow a second
// decompressor.
bool pack_text(Assets& assets, const char* path, size_t len, std::string& out, char* err,
               size_t errlen) {
  const AssetEntry* e = assets.find(path, len);
  if (e == nullptr) return false;
  if (e->deflated) {
    std::snprintf(err, errlen, "asset pack: %s is deflated - the error pack stores its text",
                  path);
    return false;
  }
  out.assign(e->file_data, e->uncompressed_size);
  return true;
}

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
mrb_value handler_body(mrb_state* mrb, void* ud) {
  const HandlerCall* c = static_cast<const HandlerCall*>(ud);
  return mrb_funcall_argv(mrb, c->self, c->sym, 1, &c->arg);
}

}  // namespace

// RFC 9110 15: what this status is called, from the same list the pack is
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
        [](mrb_state* m, void* ud) -> mrb_value {
          const HandlerCall* cc = static_cast<const HandlerCall*>(ud);
          return mrb_funcall_argv(m, cc->self, cc->sym, 0, nullptr);
        },
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
        [](mrb_state* m, void* ud) -> mrb_value {
          const HandlerCall* cc = static_cast<const HandlerCall*>(ud);
          return mrb_funcall_argv(m, cc->self, cc->sym, 0, nullptr);
        },
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
      if (!mrb_respond_to(mrb, res_, h.sym)) {
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
  exc_sym_ = MRB_SYM(handle_exception);
  if (assets != nullptr) read_cats(*assets);
  ready_ = true;
  return true;
}

// RFC 9110 12.5.1: which form this client can read. An error is not a
// representation of the resource, so content_types_provided has no say -
// only Accept does, weighed against what the error resource offers.
//
// First match in table order, which is html, then json, then the rest.
// With three forms that is honest; the day this list is ten long, Accept
// has to be weighed with its q-values instead.
int ErrorPages::media_for(const char* accept, size_t len) const {
  if (have_.empty()) return -1;
  // The same weighing c4 does for a resource - q-values, both wildcard
  // forms, provided order breaking ties. An Accept nothing matches still
  // gets an answer: an error is not a representation of the resource, so
  // there is nothing here to 406 about. text/plain is the way out,
  // because every client can read it.
  if (accept == nullptr || len == 0) return 0;
  const int pick = http::choose_media_type(types_.data(), types_.size(), accept, len);
  return pick >= 0 ? pick : plain_;
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

// The pack's cats/index.txt: status, width, height, and the rest this
// tier does not need. A status with no line and no picture renders
// without {{#cat}}, which is what a pack that carries none does.
void ErrorPages::read_cats(Assets& assets) {
  // Slot 0 is "no picture", the way index_ reserves its own zero, so the
  // dense list opens with one entry nothing points at.
  cats_.emplace_back();
  char err[256] = {};
  std::string index;
  if (!pack_text(assets, "/cats/index.txt", 15, index, err, sizeof err)) return;
  size_t at = 0;
  while (at < index.size()) {
    size_t eol = index.find('\n', at);
    if (eol == std::string::npos) eol = index.size();
    const std::string line = index.substr(at, eol - at);
    at = eol + 1;
    if (line.empty() || line[0] == '#') continue;
    unsigned status = 0, w = 0, h = 0;
    if (std::sscanf(line.c_str(), "%u\t%u\t%u", &status, &w, &h) != 3) continue;
    if (status < 100 || status > 599 || w == 0 || h == 0) continue;
    char path[32];
    const int n = std::snprintf(path, sizeof path, "/cats/%u.jpg", status);
    if (n <= 0 || assets.find(path, static_cast<size_t>(n)) == nullptr) continue;
    Cat c;
    c.url.assign(path);
    c.width = w;
    c.height = h;
    cat_index_[status] = static_cast<int16_t>(cats_.size());
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
  const auto put = [&](const char* key, const char* val, size_t len) {
    mrb_hash_set(mrb, ctx, mrb_str_new_cstr(mrb, key),
                 mrb_str_new(mrb, val, static_cast<mrb_int>(len)));
  };
  mrb_hash_set(mrb, ctx, mrb_str_new_lit(mrb, "status"), mrb_fixnum_value(status));
  put("title", status_title(status), std::strlen(status_title(status)));
  put("source", status_source(status), std::strlen(status_source(status)));
  if (f.target != nullptr && f.target_len != 0) put("target", f.target, f.target_len);
  if (f.method != nullptr && f.method_len != 0) put("method", f.method, f.method_len);
  if (f.allow != nullptr && f.allow_len != 0) put("allow", f.allow, f.allow_len);
  if (f.message != nullptr && f.message_len != 0) put("message", f.message, f.message_len);
  if (f.backtrace != nullptr && f.backtrace_len != 0) {
    put("backtrace", f.backtrace, f.backtrace_len);
  }
  const int16_t cslot = status < 600 ? cat_index_[status] : 0;
  if (cslot > 0) {
    const Cat& c = cats_[static_cast<size_t>(cslot)];
    mrb_value cat = mrb_hash_new(mrb);
    mrb_hash_set(mrb, cat, mrb_str_new_lit(mrb, "cat_url"),
                 mrb_str_new(mrb, c.url.data(), static_cast<mrb_int>(c.url.size())));
    mrb_hash_set(mrb, cat, mrb_str_new_lit(mrb, "cat_width"),
                 mrb_fixnum_value(static_cast<mrb_int>(c.width)));
    mrb_hash_set(mrb, cat, mrb_str_new_lit(mrb, "cat_height"),
                 mrb_fixnum_value(static_cast<mrb_int>(c.height)));
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

}  // namespace webmachine
