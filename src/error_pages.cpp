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

// #210: THE page. It lives here, in the code, because a server with no
// asset pack still has to be able to say what went wrong - and an
// operator who wants a different one puts errors/error.html in the pack,
// which wins. `rake error_pages` reads these two literals into the pack,
// so the copy an operator edits and the copy every binary carries cannot
// drift.
constexpr const char kHtmlTemplate[] = R"WM_HTML(<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{{status}} {{title}}</title>
<style>
:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1a1a1a;--dim:#6b6b6b;--rule:#e2e2df}
@media (prefers-color-scheme:dark){
  :root{--bg:#15161a;--fg:#e8e8e6;--dim:#8a8a92;--rule:#2a2c33}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:var(--bg);color:var(--fg);padding:2rem 1rem;
  font:16px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:40rem;text-align:center}
.n{font-size:clamp(3.5rem,14vw,6rem);font-weight:700;letter-spacing:-.04em;
  line-height:1;margin:0;font-variant-numeric:tabular-nums}
h1{font-size:clamp(1.1rem,4vw,1.5rem);font-weight:600;margin:.4rem 0 1.6rem}
img{max-width:100%;height:auto;border-radius:.6rem;display:block;margin:0 auto}
.s{margin:1.6rem 0 0;color:var(--dim);font-size:.85rem}
.t{margin:0 0 1.6rem;color:var(--dim);font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,
  Consolas,monospace;overflow-wrap:anywhere}
.m{margin:1.2rem 0 0;padding:.8rem 1rem;border-radius:.4rem;background:rgba(127,127,127,.12);
  text-align:left;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  white-space:pre-wrap;overflow-wrap:anywhere}
.c{margin:1.2rem 0 0;padding-top:1.2rem;border-top:1px solid var(--rule);
  color:var(--dim);font-size:.75rem}
a{color:inherit}
</style>
<main>
  <p class=n>{{status}}</p>
  <h1>{{title}}</h1>
{{#target}}  <p class=t>{{target}}</p>
{{/target}}{{#cat}}  <img src="{{cat_url}}" width="{{cat_width}}" height="{{cat_height}}"
       alt="A cat, illustrating HTTP {{status}} {{title}}">
{{/cat}}  <p class=s>{{source}}</p>
{{#message}}  <p class=m>{{message}}</p>
{{/message}}{{#cat}}  <p class=c>Cat by <a href="https://girliemac.com/blog/2011/12/18/the-day-i-seized-the-interweb-http-status-cats/">Tomomi Imura</a>, <a href="https://creativecommons.org/licenses/by/2.0/">CC BY 2.0</a>, unchanged
{{/cat}}</main>
)WM_HTML";

constexpr const char kJsonTemplate[] = R"WM_JSON({"type":"about:blank","title":"{{{title}}}","status":{{status}}{{#instance}},"instance":"{{{instance}}}"{{/instance}}{{#message}},"detail":"{{{message}}}"{{/message}}{{#backtrace}},"backtrace":"{{{backtrace}}}"{{/backtrace}}}
)WM_JSON";

// RFC 2046 4.1: when a client will take neither the page nor the problem
// document, it still gets an answer it can read. No escaping here on
// purpose - text/plain interprets no markup, so {{{ }}} is the correct
// spelling and an escape would only put &amp; in front of a human.
constexpr const char kTextTemplate[] = R"WM_TEXT({{status}} {{{title}}}
{{#target}}{{{target}}}
{{/target}}{{#message}}
{{{message}}}
{{/message}}
{{{source}}}
)WM_TEXT";

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

}  // namespace webmachine

namespace webmachine {
namespace {

// PKWARE APPNOTE: an entry this tier may read straight out of the mapping.
// The pack builder stores the templates and the index (rake error_pages),
// so a deflated one is a pack built by something else - refused by name
// rather than inflated here, because setup is not the place to grow a
// second decompressor.
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

// mruby: Mustache::Template.compile(src), under mrb_protect_error - an
// operator's own template may not parse, and that is a startup refusal
// with a name, not a crash.
struct CompileCall {
  const std::string* src;
};
mrb_value compile_body(mrb_state* mrb, void* ud) {
  const CompileCall* c = static_cast<const CompileCall*>(ud);
  struct RClass* m = mrb_module_get_id(mrb, MRB_SYM(Mustache));
  struct RClass* t = mrb_class_get_under_id(mrb, m, MRB_SYM(Template));
  mrb_value s = mrb_str_new(mrb, c->src->data(), static_cast<mrb_int>(c->src->size()));
  return mrb_funcall_id(mrb, mrb_obj_value(t), MRB_SYM(compile), 1, s);
}

// mruby: template.render(context), under the same guard.
struct RenderCall {
  mrb_value tmpl;
  mrb_value ctx;
};
mrb_value render_body(mrb_state* mrb, void* ud) {
  const RenderCall* c = static_cast<const RenderCall*>(ud);
  return mrb_funcall_id(mrb, c->tmpl, MRB_SYM(render), 1, c->ctx);
}

// RFC 8259 7: the six characters a JSON string may not carry raw. The
// json template takes {{{ }}} for the message because mustache escapes
// for HTML, and &amp; inside a JSON string would be a lie - so the
// encoding job is done here, where the encoding is known.
void json_escape(const char* p, size_t n, std::string& out) {
  for (size_t i = 0; i < n; i++) {
    const unsigned char c = static_cast<unsigned char>(p[i]);
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char u[7];
          std::snprintf(u, sizeof u, "\\u%04x", c);
          out += u;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
}

}  // namespace

// RFC 9110 12.5.1: which of the three this client can read. An error is
// not a representation of the resource, so content_types_provided has no
// say - only Accept does, and a client that will take neither the page
// nor the problem document still gets something it can read.
ErrorPages::Media ErrorPages::media_for(const char* accept, size_t len) {
  if (accept == nullptr || len == 0) return Media::kHtml;
  const auto has = [&](const char* needle, size_t nlen) {
    if (nlen > len) return false;
    for (size_t i = 0; i + nlen <= len; i++) {
      if (std::memcmp(accept + i, needle, nlen) == 0) return true;
    }
    return false;
  };
  // Named first, in the order a page is the more useful answer.
  if (has("text/html", 9)) return Media::kHtml;
  // RFC 6839 3.1: the +json structured syntax suffix counts, so
  // application/problem+json and every other +json land here too.
  if (has("/json", 5) || has("+json", 5)) return Media::kJson;
  // A wildcard is a client with no opinion, and a client with no opinion
  // is nearly always a browser.
  if (has("*/*", 3) || has("text/*", 6)) return Media::kHtml;
  return Media::kText;
}

// RFC 9457 3: the problem document has its own media type, and it is not
// application/json.
const char* ErrorPages::media_type(Media m) {
  switch (m) {
    case Media::kJson: return "Content-Type: application/problem+json\r\n";
    case Media::kText: return "Content-Type: text/plain; charset=utf-8\r\n";
    case Media::kHtml: break;
  }
  return "Content-Type: text/html; charset=utf-8\r\n";
}

// The same three, as the value h2's field encoder wants.
const char* ErrorPages::media_value(Media m) {
  switch (m) {
    case Media::kJson: return "application/problem+json";
    case Media::kText: return "text/plain; charset=utf-8";
    case Media::kHtml: break;
  }
  return "text/html; charset=utf-8";
}

ErrorPages::~ErrorPages() {
  if (mrb_ == nullptr) return;
  if (!mrb_nil_p(html_)) mrb_gc_unregister(mrb_, html_);
  if (!mrb_nil_p(json_)) mrb_gc_unregister(mrb_, json_);
  if (!mrb_nil_p(text_)) mrb_gc_unregister(mrb_, text_);
}

// #210: both templates compiled once. Rooted with mrb_gc_register, not
// the arena: these outlive every arena mark the setup path takes.
bool ErrorPages::open(mrb_state* mrb, Assets* assets, char* err, size_t errlen) {
  mrb_ = mrb;
  std::string html(kHtmlTemplate);
  std::string json(kJsonTemplate);
  std::string text(kTextTemplate);
  if (assets != nullptr) {
    // The pack's copy wins - that is the whole edit path for an operator
    // who does not rebuild the server.
    std::string t;
    if (pack_text(*assets, "/errors/error.html", 18, t, err, errlen)) html.swap(t);
    else if (err[0] != '\0') return false;
    t.clear();
    if (pack_text(*assets, "/errors/error.json", 18, t, err, errlen)) json.swap(t);
    else if (err[0] != '\0') return false;
    t.clear();
    if (pack_text(*assets, "/errors/error.txt", 17, t, err, errlen)) text.swap(t);
    else if (err[0] != '\0') return false;
    read_cats(*assets);
  }
  const int ai = mrb_gc_arena_save(mrb);
  const std::string* sources[3] = {&html, &json, &text};
  static constexpr const char* kNames[3] = {"errors/error.html", "errors/error.json",
                                            "errors/error.txt"};
  for (int pass = 0; pass < 3; pass++) {
    CompileCall c{sources[pass]};
    mrb_bool raised = FALSE;
    const mrb_value t = mrb_protect_error(mrb, compile_body, &c, &raised);
    if (raised) {
      const char* which = kNames[pass];
      std::string why = "does not compile";
      if (mrb_exception_p(t)) {
        const mrb_value m = mrb_funcall_id(mrb, t, MRB_SYM(message), 0);
        if (mrb_string_p(m)) why.assign(RSTRING_PTR(m), RSTRING_LEN(m));
      }
      std::snprintf(err, errlen, "error pages: %s: %s", which, why.c_str());
      mrb->exc = nullptr;
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (pass == 0) html_ = t;
    else if (pass == 1) json_ = t;
    else text_ = t;
    mrb_gc_register(mrb, t);
  }
  mrb_gc_arena_restore(mrb, ai);
  ready_ = true;
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

// #210: one error body. Rendered per response - a 404 names what was not
// found, so there is nothing here a boot could have prepared.
bool ErrorPages::render(uint16_t status, Media m, const Fields& f, std::string& out) {
  if (!ready_) return false;
  const bool want_json = m == Media::kJson;
  mrb_state* mrb = mrb_;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value ctx = mrb_hash_new(mrb);
  const auto put = [&](const char* key, const char* val, size_t len) {
    mrb_hash_set(mrb, ctx, mrb_str_new_cstr(mrb, key),
                 mrb_str_new(mrb, val, static_cast<mrb_int>(len)));
  };
  const auto put_cstr = [&](const char* key, const char* val) {
    put(key, val, std::strlen(val));
  };
  mrb_hash_set(mrb, ctx, mrb_str_new_lit(mrb, "status"), mrb_fixnum_value(status));
  put_cstr("title", status_title(status));
  put_cstr("source", status_source(status));

  std::string scratch;
  if (f.target != nullptr && f.target_len != 0) {
    if (want_json) {
      scratch.clear();
      json_escape(f.target, f.target_len, scratch);
      put("instance", scratch.data(), scratch.size());
    } else {
      put("target", f.target, f.target_len);
    }
  }
  if (f.message != nullptr && f.message_len != 0) {
    if (want_json) {
      scratch.clear();
      json_escape(f.message, f.message_len, scratch);
      put("message", scratch.data(), scratch.size());
    } else {
      put("message", f.message, f.message_len);
    }
  }
  if (want_json && f.backtrace != nullptr && f.backtrace_len != 0) {
    scratch.clear();
    json_escape(f.backtrace, f.backtrace_len, scratch);
    put("backtrace", scratch.data(), scratch.size());
  }
  if (m == Media::kHtml) {
    const int16_t slot = status < 600 ? cat_index_[status] : 0;
    if (slot > 0) {
      const Cat& c = cats_[static_cast<size_t>(slot)];
      mrb_value cat = mrb_hash_new(mrb);
      mrb_hash_set(mrb, cat, mrb_str_new_lit(mrb, "cat_url"),
                   mrb_str_new(mrb, c.url.data(), static_cast<mrb_int>(c.url.size())));
      mrb_hash_set(mrb, cat, mrb_str_new_lit(mrb, "cat_width"),
                   mrb_fixnum_value(static_cast<mrb_int>(c.width)));
      mrb_hash_set(mrb, cat, mrb_str_new_lit(mrb, "cat_height"),
                   mrb_fixnum_value(static_cast<mrb_int>(c.height)));
      mrb_hash_set(mrb, ctx, mrb_str_new_lit(mrb, "cat"), cat);
    }
  }

  RenderCall rc{m == Media::kJson ? json_ : (m == Media::kText ? text_ : html_), ctx};
  mrb_bool raised = FALSE;
  const mrb_value body = mrb_protect_error(mrb, render_body, &rc, &raised);
  if (raised || !mrb_string_p(body)) {
    // A template that raises has no page to offer, and the caller still
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
