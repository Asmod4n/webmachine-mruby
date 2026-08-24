/*
 * Test-only surface, compiled into mrbtest and nothing else (mruby
 * builds test/ * of a gem only for its test binary). src/ never carries
 * test code; this drives the real machinery from outside, the way
 * test/flow_vectors.cpp drives the flow walker.
 *
 * WHAT IT IS FOR: webmachine-ruby's own resource specs are the oracle
 * for this tree (spec/webmachine/decision/flow_spec.rb and
 * helpers_spec.rb). Those specs drive
 *
 *     Webmachine::Decision::FSM.new(resource, request, response).run
 *
 * and then read response.code, response.headers and response.body.
 * This tree has no FSM object and no request/response the CALLER
 * builds - the flow is C++, the resource is folded once at add_route,
 * and the per-request objects are handles the run frame binds. So the
 * three objects the specs need are provided HERE, in test/, and they
 * drive the REAL resource_fold and resource_run. What the specs then
 * exercise is src/, not this file: this file only builds the arguments
 * and reads the answer back out.
 *
 * Webmachine::Headers, ::SpecRequest and ::SpecResponse are plain Ruby
 * and live in test/wm_ruby.rb (they are NOT Webmachine::Request /
 * ::Response - those names are the product's, defined in C by
 * src/request.cpp and src/response.cpp). Only the FSM needs C, because
 * only it touches the flow.
 *
 * Also here: Webmachine::TestDigest, the two library calls the specs
 * lean on that this VM has no gem for - Digest::MD5.hexdigest and
 * Base64.encode64, for the Content-MD5 cases of b9a (RFC 1864).
 */
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "../src/webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <openssl/md5.h>
#include <picohttpparser.h>
#include <simdutf.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

// One folded resource, alive as long as the FSM object that owns it.
// resource_fold's contract: `out` must live at its final address, the
// run frame's env borrows it - so it is heap-allocated and freed with
// the FSM.
struct Fsm {
  webmachine::Resource res;
};

void fsm_free(mrb_state*, void* p) { delete static_cast<Fsm*>(p); }

const mrb_data_type fsm_type = {"Webmachine::Decision::FSM", fsm_free};

// RFC 9110 5.1: one request's fields, from the spec's Headers hash into
// the two shapes the run frame reads - the 9110 facts/values through the
// SAME http::header_switch h1 and h2 use, and the raw name/value pairs
// request.headers / request.content_type lend back to Ruby. Both point
// into `store`, which is filled COMPLETELY before either is built: a
// reallocation after that would dangle every pointer handed out.
void fields_from(mrb_state* mrb, mrb_value headers, webmachine::flow::ReqFacts& facts,
                 webmachine::http::ReqValues& vals, std::string& store,
                 std::vector<struct phr_header>& hdrs) {
  const mrb_value keys = mrb_hash_keys(mrb, headers);
  const mrb_int n = RARRAY_LEN(keys);
  size_t need = 0;
  for (mrb_int i = 0; i < n; i++) {
    const mrb_value k = RARRAY_PTR(keys)[i];
    const mrb_value v = mrb_hash_get(mrb, headers, k);
    if (mrb_string_p(k)) need += static_cast<size_t>(RSTRING_LEN(k));
    if (mrb_string_p(v)) need += static_cast<size_t>(RSTRING_LEN(v));
  }
  store.reserve(need + 1);
  // Pass one: the bytes. A field whose value is not a String is one the
  // spec set to nil, i.e. one that never reached the wire - skipped.
  std::vector<size_t> klen, vlen;
  for (mrb_int i = 0; i < n; i++) {
    const mrb_value k = RARRAY_PTR(keys)[i];
    const mrb_value v = mrb_hash_get(mrb, headers, k);
    if (!mrb_string_p(k) || !mrb_string_p(v)) continue;
    const size_t koff = store.size();
    store.append(RSTRING_PTR(k), static_cast<size_t>(RSTRING_LEN(k)));
    const size_t voff = store.size();
    store.append(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
    // Lowercased in place: h1 arrives case-insensitive and h2 demands
    // lowercase (RFC 9113 8.2), and header_switch matches against
    // lowercase literals. The VALUE is left alone - Content-MD5 is
    // base64, where case is meaning.
    for (size_t j = koff; j < voff; j++) {
      char& c = store[j];
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    klen.push_back(voff - koff);
    vlen.push_back(store.size() - voff);
  }
  // Pass two: the pointers, now that `store` will not move again.
  // reserve(+1) so data() is a real address even with no fields at all -
  // request.headers refuses a null head by name, and "no fields" is not
  // that case.
  hdrs.reserve(klen.size() + 1);
  size_t at = 0;
  for (size_t i = 0; i < klen.size(); i++) {
    struct phr_header h;
    h.name = store.data() + at;
    h.name_len = klen[i];
    h.value = store.data() + at + klen[i];
    h.value_len = vlen[i];
    hdrs.push_back(h);
    webmachine::http::header_switch(h.name, h.name_len, h.value, h.value_len, facts, vals,
                                    [](const char*, size_t, const char*, size_t) {});
    at += klen[i] + vlen[i];
  }
}

// RFC 9110 8.3/15: does a response with THIS status carry a
// representation whose media type the head must spell? f6 sets
// Content-Type for everything that reaches it; 204/205 carry no
// representation and 304 must not restate one.
bool entity_status(uint16_t s) {
  if (s == 204 || s == 205 || s == 304) return false;
  return (s >= 200 && s < 300) || s == 300;
}

// RFC 9110 6.3: the field lines one run produced, as "Name: Value\r\n",
// into the Headers hash the spec reads.
void headers_into(mrb_state* mrb, mrb_value hash, const std::string& block) {
  size_t i = 0;
  while (i < block.size()) {
    const size_t eol = block.find("\r\n", i);
    if (eol == std::string::npos) break;
    const size_t colon = block.find(':', i);
    if (colon == std::string::npos || colon > eol) {
      i = eol + 2;
      continue;
    }
    size_t vs = colon + 1;
    while (vs < eol && (block[vs] == ' ' || block[vs] == '\t')) vs++;
    mrb_value kv[2] = {mrb_str_new(mrb, block.data() + i, colon - i),
                       mrb_str_new(mrb, block.data() + vs, eol - vs)};
    mrb_funcall_argv(mrb, hash, MRB_OPSYM(aset), 2, kv);
    i = eol + 2;
  }
}

// Webmachine::Decision::FSM.new(resource_class, request, response) - the
// class is folded HERE, once, exactly as add_route folds it.
mrb_value fsm_init(mrb_state* mrb, mrb_value self) {
  mrb_value klass, req, resp;
  mrb_get_args(mrb, "ooo", &klass, &req, &resp);
  Fsm* f = new Fsm();
  mrb_data_init(self, f, &fsm_type);
  char err[512] = {0};
  if (!webmachine::resource_fold(mrb, klass, f->res, err, sizeof err)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s", err);
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@request"), req);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@response"), resp);
  return self;
}

// RFC 9110: run the graph for this request and write what it answered
// into the SpecResponse the spec reads.
mrb_value fsm_run(mrb_state* mrb, mrb_value self) {
  Fsm* f = static_cast<Fsm*>(mrb_data_get_ptr(mrb, self, &fsm_type));
  const mrb_value req = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@request"));
  const mrb_value resp = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@response"));

  const mrb_value m = mrb_funcall_argv(mrb, req, mrb_intern_lit(mrb, "method"), 0, nullptr);
  const mrb_value path = mrb_funcall_argv(mrb, req, mrb_intern_lit(mrb, "path"), 0, nullptr);
  const mrb_value headers = mrb_funcall_argv(mrb, req, mrb_intern_lit(mrb, "headers"), 0, nullptr);
  const mrb_value rbody = mrb_funcall_argv(mrb, req, mrb_intern_lit(mrb, "body"), 0, nullptr);

  webmachine::flow::ReqFacts facts;
  webmachine::http::ReqValues vals;
  std::string store;
  std::vector<struct phr_header> hdrs;
  facts.method = webmachine::http::parse_method(RSTRING_PTR(m), RSTRING_LEN(m));
  fields_from(mrb, headers, facts, vals, store, hdrs);

  webmachine::ReqView rv;
  rv.target = RSTRING_PTR(path);
  rv.target_len = static_cast<size_t>(RSTRING_LEN(path));
  rv.path_len = webmachine::http::path_only(rv.target, rv.target_len);
  rv.method = facts.method;
  rv.method_p = RSTRING_PTR(m);
  rv.method_n = static_cast<size_t>(RSTRING_LEN(m));
  rv.hdrs = hdrs.data();
  rv.nhdr = hdrs.size();
  if (mrb_string_p(rbody)) {
    rv.body = RSTRING_PTR(rbody);
    rv.body_len = static_cast<size_t>(RSTRING_LEN(rbody));
  }

  std::string body;
  std::string field_lines;
  bool have_body = false;
  // resource_run binds the request itself - the caller builds the
  // structs and nothing else.
  // The wire calls resource_run from outside the VM, where mrb->jmp is
  // NULL and every raise lands in mrb->exc for the engine's raise path.
  // The shim runs INSIDE the VM, so it lends the engine that same
  // top-level frame for the duration of the run.
  struct mrb_jmpbuf* const saved_jmp = mrb->jmp;
  mrb->jmp = nullptr;
  const uint16_t status =
      webmachine::resource_run(f->res, facts, &vals, &rv, &body, &have_body, &field_lines);
  mrb->jmp = saved_jmp;

  // The no-handler 500 leaves the raise pending for the wire writer
  // (resource_exception_begin); the shim plays that writer here, so
  // the exception becomes the body and mrb is clean again.
  if (mrb->exc != nullptr) {
    const char* ep = nullptr;
    size_t en = 0;
    if (webmachine::resource_exception_begin(f->res, &ep, &en)) {
      body.assign(ep, en);
      have_body = true;
    }
    mrb->exc = nullptr;
  }

  mrb_value arg = mrb_fixnum_value(status);
  mrb_funcall_argv(mrb, resp, mrb_intern_lit(mrb, "code="), 1, &arg);
  if (have_body) {
    arg = mrb_str_new(mrb, body.data(), body.size());
    mrb_funcall_argv(mrb, resp, mrb_intern_lit(mrb, "body="), 1, &arg);
  }
  const mrb_value hash = mrb_funcall_argv(mrb, resp, mrb_intern_lit(mrb, "headers"), 0, nullptr);
  headers_into(mrb, hash, field_lines);

  // RFC 9110 8.3: the writer spells Content-Type from one of two
  // places - the conneg choice when the head could not stay prebuilt,
  // the resource's default type otherwise - and text/* carries
  // charset=utf-8 (#146). The spec reads it off response.headers, so it
  // is reconstructed here rather than left to the wire.
  std::string ct;
  if (entity_status(status)) {
    if (!f->res.run_ctype.empty()) {
      ct = webmachine::http::with_charset(f->res.run_ctype);
    } else if (!f->res.ct_provided.empty()) {
      ct = webmachine::http::with_charset(f->res.ct_provided[0].type);
    }
  }
  if (!ct.empty()) {
    mrb_value kv[2] = {mrb_str_new_lit(mrb, "Content-Type"), mrb_str_new(mrb, ct.data(), ct.size())};
    mrb_funcall_argv(mrb, hash, MRB_OPSYM(aset), 2, kv);
  }
  return mrb_nil_value();
}

// RFC 1864: Digest::MD5.hexdigest, which b9a's oracle cases need to
// build a Content-MD5 with.
mrb_value digest_md5_hex(mrb_state* mrb, mrb_value) {
  const char* p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  unsigned char d[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const unsigned char*>(p), static_cast<size_t>(n), d);
  static const char kHex[] = "0123456789abcdef";
  char hex[MD5_DIGEST_LENGTH * 2];
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    hex[2 * i] = kHex[(d[i] >> 4) & 0xf];
    hex[2 * i + 1] = kHex[d[i] & 0xf];
  }
  return mrb_str_new(mrb, hex, sizeof hex);
}

// RFC 4648: Base64.encode64 without its trailing newline - decode64
// ignores that byte, so the two spell the same Content-MD5.
mrb_value digest_b64(mrb_state* mrb, mrb_value) {
  const char* p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  std::string out(simdutf::base64_length_from_binary(static_cast<size_t>(n)), '\0');
  const size_t w = simdutf::binary_to_base64(p, static_cast<size_t>(n), out.data());
  return mrb_str_new(mrb, out.data(), w);
}

}  // namespace

// The gem gets ONE gem_test entry point (test/hpack_vectors.c owns it);
// this is what it calls for the oracle's C half.
extern "C" void mrb_webmachine_wm_ruby_init(mrb_state* mrb) {
  struct RClass* wm = mrb_module_get_id(mrb, mrb_intern_lit(mrb, "Webmachine"));
  struct RClass* dec = mrb_define_module_under_id(mrb, wm, mrb_intern_lit(mrb, "Decision"));
  struct RClass* fsm = mrb_define_class_under_id(mrb, dec, mrb_intern_lit(mrb, "FSM"), mrb->object_class);
  MRB_SET_INSTANCE_TT(fsm, MRB_TT_CDATA);
  mrb_define_method_id(mrb, fsm, mrb_intern_lit(mrb, "initialize"), fsm_init, MRB_ARGS_REQ(3));
  mrb_define_method_id(mrb, fsm, mrb_intern_lit(mrb, "run"), fsm_run, MRB_ARGS_NONE());

  struct RClass* dig = mrb_define_module_under_id(mrb, wm, mrb_intern_lit(mrb, "TestDigest"));
  mrb_define_module_function_id(mrb, dig, mrb_intern_lit(mrb, "md5_hex"), digest_md5_hex, MRB_ARGS_REQ(1));
  mrb_define_module_function_id(mrb, dig, mrb_intern_lit(mrb, "b64"), digest_b64, MRB_ARGS_REQ(1));
}
