// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <simdutf.h>

#include <cstdio>
#include <cstring>

extern "C" mrb_int mrb_proc_arity(const struct RProc* p);

namespace webmachine {
struct WsResource {
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  bool have_close = false;
  int data_argc = 1;
  int close_argc = 0;
  size_t max_message = kMaxWsMessageDefault;
  bool validate_text = true;
  bool want_deflate = false;
};

struct WsConn {
  const WsResource* res = nullptr;
  Logger* elog = nullptr;
  mrb_value self = mrb_nil_value();

  unsigned char hbuf[14] = {};
  uint8_t hlen = 0;
  uint8_t hneed = 2;

  bool in_payload = false;
  uint8_t opcode = 0;
  bool fin = false;
  bool control = false;
  uint64_t remaining = 0;
  unsigned char mask[4] = {};
  uint8_t mask_off = 0;

  char ctl[125] = {};
  uint8_t ctl_len = 0;

  mrb_value msg = mrb_nil_value();
  bool msg_live = false;
  uint8_t msg_op = 0;
  size_t validated = 0;

  wsdeflate::Codec* codec = nullptr;
  bool msg_deflated = false;

  bool sent_close = false;
  bool got_close = false;
  bool closed_reported = false;
};

namespace {
// RFC 6455 7.4.1: a Symbol answer by name. This IS the vocabulary.
bool symbol_code(mrb_sym s, uint16_t& code) {
  if (s == MRB_SYM(close) || s == MRB_SYM(normal)) code = ws::kCloseNormal;
  else if (s == MRB_SYM(going_away)) code = ws::kCloseGoingAway;
  else if (s == MRB_SYM(protocol_error)) code = ws::kCloseProtocolError;
  else if (s == MRB_SYM(unsupported)) code = ws::kCloseUnsupportedData;
  else if (s == MRB_SYM(invalid)) code = ws::kCloseInvalidPayload;
  else if (s == MRB_SYM(policy)) code = ws::kClosePolicyViolation;
  else if (s == MRB_SYM(too_big)) code = ws::kCloseTooBig;
  else if (s == MRB_SYM(internal_error)) code = ws::kCloseInternalError;
  else return false;
  return true;
}

// RFC 6455 5.1: one frame into the sink - header here, payload where it lies.
void emit(std::string& sink, uint8_t opcode, const char* p, size_t n, bool rsv1 = false) {
  char head[10];
  const size_t hn = ws::build_header(opcode, true, rsv1, n, head);
  sink.append(head, hn);
  if (n != 0) sink.append(p, n);
}

// RFC 6455 5.6 / RFC 7692 6: a DATA message, compressed where negotiated.
void emit_data(WsConn* c, std::string& sink, uint8_t opcode, const char* p, size_t n) {
  if (c->codec != nullptr) {
    static std::string scratch;
    if (c->codec->compress(p, n, scratch)) {
      emit(sink, opcode, scratch.data(), scratch.size(), true);
      return;
    }
  }
  emit(sink, opcode, p, n);
}

// RFC 6455 5.5.1: the close handshake's own half, sent at most once.
void emit_close(WsConn* c, std::string& sink, uint16_t code, const char* reason,
                size_t reason_len) {
  if (c->sent_close) return;
  c->sent_close = true;
  char payload[125];
  const size_t n = ws::build_close_payload(code, reason, reason_len, payload);
  emit(sink, ws::kClose, payload, n);
}

// RFC 3629: can these 1-3 bytes still BECOME a valid sequence?
bool valid_prefix(const unsigned char* p, size_t n) {
  if (n == 0) return true;
  const unsigned char b0 = p[0];
  size_t need = 0;
  unsigned char lo = 0x80, hi = 0xbf;
  if (b0 >= 0xc2 && b0 <= 0xdf) need = 1;
  else if (b0 == 0xe0) { need = 2; lo = 0xa0; }
  else if (b0 >= 0xe1 && b0 <= 0xec) need = 2;
  else if (b0 == 0xed) { need = 2; hi = 0x9f; }
  else if (b0 >= 0xee && b0 <= 0xef) need = 2;
  else if (b0 == 0xf0) { need = 3; lo = 0x90; }
  else if (b0 >= 0xf1 && b0 <= 0xf3) need = 3;
  else if (b0 == 0xf4) { need = 3; hi = 0x8f; }
  else return false;
  if (n - 1 > need) return false;
  for (size_t i = 1; i < n; i++) {
    const unsigned char lim_lo = i == 1 ? lo : 0x80;
    const unsigned char lim_hi = i == 1 ? hi : 0xbf;
    if (p[i] < lim_lo || p[i] > lim_hi) return false;
  }
  return true;
}

// RFC 6455 8.1: UTF-8 over a message that is still arriving.
bool utf8_ok(WsConn* c, bool final) {
  if (!c->res->validate_text) return true;
  const char* p = RSTRING_PTR(c->msg);
  const size_t n = static_cast<size_t>(RSTRING_LEN(c->msg));
  if (n <= c->validated) return true;
  const simdutf::result r =
      simdutf::validate_utf8_with_errors(p + c->validated, n - c->validated);
  if (r.error == simdutf::error_code::SUCCESS) {
    c->validated = n;
    return true;
  }
  if (!final && r.error == simdutf::error_code::TOO_SHORT &&
      c->validated + r.count + 4 > n) {
    const size_t at = c->validated + r.count;
    if (!valid_prefix(reinterpret_cast<const unsigned char*>(p) + at, n - at)) return false;
    c->validated = at;
    return true;
  }
  return false;
}

// RFC 6455 5.4: the message under construction is released.
void drop_msg(WsConn* c) {
  if (!c->msg_live) return;
  mrb_gc_unregister(c->res->mrb, c->msg);
  c->msg = mrb_nil_value();
  c->msg_live = false;
  c->msg_op = 0;
  c->msg_deflated = false;
  c->validated = 0;
}

// RFC 6455 7.1.5: on_close, once, however the connection ended.
void report_close(WsConn* c, uint16_t code, const char* reason, size_t reason_len) {
  if (c->closed_reported || !c->res->have_close) return;
  c->closed_reported = true;
  mrb_state* mrb = c->res->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value argv[2];
  argv[0] = mrb_fixnum_value(code);
  argv[1] = mrb_str_new(mrb, reason == nullptr ? "" : reason, reason_len);
  mrb_funcall_argv(mrb, c->self, MRB_SYM(on_close), c->res->close_argc, argv);
  if (mrb->exc != nullptr) {
    if (c->elog != nullptr) log_exception(*c->elog, mrb, nullptr, 0, nullptr, 0, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
  }
  mrb_gc_arena_restore(mrb, ai);
}

// RFC 6455 5.5.1: this side found something wrong - close with the code.
bool fail(WsConn* c, std::string& sink, uint16_t code) {
  emit_close(c, sink, code, nullptr, 0);
  report_close(c, code, nullptr, 0);
  drop_msg(c);
  return false;
}

// RFC 6455 5.6: a complete message to the resource, and act on the answer.
bool deliver(WsConn* c, std::string& sink) {
  const WsResource* r = c->res;
  mrb_state* mrb = r->mrb;
  const bool binary = c->msg_op == ws::kBinary;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value argv[2];
  argv[0] = c->msg;
  argv[1] = mrb_bool_value(binary);
  const mrb_value out = mrb_funcall_argv(mrb, c->self, MRB_SYM(on_data), r->data_argc, argv);
  drop_msg(c);
  if (mrb->exc != nullptr) {
    if (c->elog != nullptr) log_exception(*c->elog, mrb, nullptr, 0, nullptr, 0, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return fail(c, sink, ws::kCloseInternalError);
  }
  if (mrb_string_p(out)) {
    emit_data(c, sink, binary ? ws::kBinary : ws::kText, RSTRING_PTR(out),
              static_cast<size_t>(RSTRING_LEN(out)));
  } else if (mrb_symbol_p(out)) {
    uint16_t code = 0;
    if (symbol_code(mrb_symbol(out), code)) {
      emit_close(c, sink, code, nullptr, 0);
      report_close(c, code, nullptr, 0);
    } else {
      std::fprintf(stderr,
                   "webmachine: on_data returned :%s, which is not a close this endpoint "
                   "can speak (RFC 6455 7.4.1). Say a String, nil, or one of :close "
                   ":going_away :protocol_error :unsupported :invalid :policy :too_big "
                   ":internal_error\n",
                   mrb_sym_name(mrb, mrb_symbol(out)));
      mrb_gc_arena_restore(mrb, ai);
      return fail(c, sink, ws::kCloseInternalError);
    }
  } else if (!mrb_nil_p(out)) {
    std::fprintf(stderr,
                 "webmachine: on_data returned a %s - a websocket answer is a String (a "
                 "message), a Symbol (a close by name) or nil (nothing said)\n",
                 mrb_obj_classname(mrb, out));
    mrb_gc_arena_restore(mrb, ai);
    return fail(c, sink, ws::kCloseInternalError);
  }
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

// RFC 6455 5.5/5.6: a frame whose payload is now complete.
bool finish_frame(WsConn* c, std::string& sink) {
  switch (c->opcode) {
    case ws::kPing:
      if (!c->sent_close) emit(sink, ws::kPong, c->ctl, c->ctl_len);
      return true;
    case ws::kPong:
      return true;
    case ws::kClose: {
      uint16_t code = 0;
      const char* reason = nullptr;
      size_t rlen = 0;
      if (!ws::read_close(c->ctl, c->ctl_len, code, &reason, &rlen)) {
        return fail(c, sink, ws::kCloseProtocolError);
      }
      if (rlen != 0 && !simdutf::validate_utf8(reason, rlen)) {
        return fail(c, sink, ws::kCloseInvalidPayload);
      }
      c->got_close = true;
      emit_close(c, sink, code == 1005 ? ws::kCloseNormal : code, reason, rlen);
      report_close(c, code, reason, rlen);
      drop_msg(c);
      return false;
    }
    default: break;
  }
  if (!c->fin) return true;
  if (c->msg_deflated) {
    mrb_state* mrb = c->res->mrb;
    const size_t max = c->res->max_message;
    const int rc = c->codec->inflate_finish([&](const char* q, size_t qn) {
      if (static_cast<uint64_t>(RSTRING_LEN(c->msg)) + qn > max) return false;
      mrb_str_cat(mrb, c->msg, q, qn);
      return true;
    });
    if (rc != 0) {
      return fail(c, sink, rc == -2 ? ws::kCloseTooBig : ws::kCloseProtocolError);
    }
  }
  if (c->msg_op == ws::kText && !utf8_ok(c, true)) {
    return fail(c, sink, ws::kCloseInvalidPayload);
  }
  if (c->sent_close) {
    drop_msg(c);
    return true;
  }
  return deliver(c, sink);
}

// RFC 6455 5.2/5.5, RFC 7692 6: everything the header must satisfy.
bool begin_frame(WsConn* c, std::string& sink) {
  const unsigned char b0 = c->hbuf[0];
  const unsigned char b1 = c->hbuf[1];
  const bool fin = (b0 & 0x80) != 0;
  const bool rsv1 = (b0 & 0x40) != 0;
  const uint8_t opcode = static_cast<uint8_t>(b0 & 0x0f);
  if ((b0 & 0x30) != 0) return fail(c, sink, ws::kCloseProtocolError);
  if (rsv1 && c->codec == nullptr) return fail(c, sink, ws::kCloseProtocolError);
  const bool control = (opcode & 0x08) != 0;
  switch (opcode) {
    case ws::kContinuation:
    case ws::kText:
    case ws::kBinary:
    case ws::kClose:
    case ws::kPing:
    case ws::kPong: break;
    default: return fail(c, sink, ws::kCloseProtocolError);
  }
  if (rsv1 && (control || opcode == ws::kContinuation)) {
    return fail(c, sink, ws::kCloseProtocolError);
  }
  if ((b1 & 0x80) == 0) return fail(c, sink, ws::kCloseProtocolError);

  uint64_t plen = static_cast<uint64_t>(b1 & 0x7f);
  size_t at = 2;
  if (plen == 126) {
    plen = (static_cast<uint64_t>(c->hbuf[2]) << 8) | c->hbuf[3];
    at = 4;
    if (plen < 126) return fail(c, sink, ws::kCloseProtocolError);
  } else if (plen == 127) {
    plen = 0;
    for (int i = 0; i < 8; i++) plen = (plen << 8) | c->hbuf[2 + i];
    at = 10;
    if (plen <= 0xffff || (plen >> 63) != 0) return fail(c, sink, ws::kCloseProtocolError);
  }
  if (control && (plen > ws::kMaxControlPayload || !fin)) {
    return fail(c, sink, ws::kCloseProtocolError);
  }
  std::memcpy(c->mask, c->hbuf + at, 4);
  c->mask_off = 0;
  c->opcode = opcode;
  c->fin = fin;
  c->control = control;
  c->remaining = plen;
  c->ctl_len = 0;

  if (!control) {
    mrb_state* mrb = c->res->mrb;
    const size_t max = c->res->max_message;
    if (opcode == ws::kContinuation) {
      if (c->msg_op == 0) return fail(c, sink, ws::kCloseProtocolError);
      if (!c->msg_deflated && static_cast<uint64_t>(RSTRING_LEN(c->msg)) + plen > max) {
        return fail(c, sink, ws::kCloseTooBig);
      }
    } else {
      if (c->msg_op != 0) return fail(c, sink, ws::kCloseProtocolError);
      if (!rsv1 && plen > max) return fail(c, sink, ws::kCloseTooBig);
      const uint64_t capa = plen > max ? max : plen;
      c->msg = mrb_str_new_capa(mrb, static_cast<mrb_int>(capa));
      mrb_gc_register(mrb, c->msg);
      c->msg_live = true;
      c->msg_op = opcode;
      c->msg_deflated = rsv1;
    }
  }
  c->in_payload = plen != 0;
  return true;
}

// RFC 6455 5.2: how many header bytes the next decision needs.
uint8_t header_need(const WsConn* c) {
  if (c->hlen < 2) return 2;
  const uint8_t len7 = static_cast<uint8_t>(c->hbuf[1] & 0x7f);
  const uint8_t ext = len7 == 126 ? 2 : (len7 == 127 ? 8 : 0);
  return static_cast<uint8_t>(2 + ext + ((c->hbuf[1] & 0x80) != 0 ? 4 : 0));
}

struct FeedCall {
  WsConn* c;
  const char* data;
  size_t len;
  std::string* sink;
};

// RFC 6455 5.3: the reader - unmasked straight into the mruby String.
mrb_value feed_body(mrb_state* mrb, void* ud) {
  FeedCall* f = static_cast<FeedCall*>(ud);
  WsConn* c = f->c;
  std::string& sink = *f->sink;
  const char* p = f->data;
  size_t len = f->len;
  bool alive = true;

  while (len != 0) {
    if (!c->in_payload) {
      c->hneed = header_need(c);
      while (c->hlen < c->hneed && len != 0) {
        c->hbuf[c->hlen++] = static_cast<unsigned char>(*p++);
        len--;
        c->hneed = header_need(c);
      }
      if (c->hlen < c->hneed) break;
      c->hlen = 0;
      if (!begin_frame(c, sink)) {
        alive = false;
        break;
      }
      if (!c->in_payload) {
        if (!finish_frame(c, sink)) {
          alive = false;
          break;
        }
      }
      continue;
    }

    size_t take = len < c->remaining ? len : static_cast<size_t>(c->remaining);
    if (c->control) {
      for (size_t i = 0; i < take; i++) {
        c->ctl[c->ctl_len++] = static_cast<char>(p[i] ^ c->mask[(c->mask_off + i) & 3]);
      }
    } else {
      char tmp[512];
      size_t done = 0;
      bool broke = false;
      while (done < take) {
        const size_t chunk = take - done < sizeof(tmp) ? take - done : sizeof(tmp);
        for (size_t i = 0; i < chunk; i++) {
          tmp[i] = static_cast<char>(p[done + i] ^ c->mask[(c->mask_off + done + i) & 3]);
        }
        if (c->msg_deflated) {
          const size_t max = c->res->max_message;
          const int rc = c->codec->inflate_some(tmp, chunk, [&](const char* q, size_t qn) {
            if (static_cast<uint64_t>(RSTRING_LEN(c->msg)) + qn > max) return false;
            mrb_str_cat(mrb, c->msg, q, qn);
            return true;
          });
          if (rc != 0) {
            alive = fail(c, sink, rc == -2 ? ws::kCloseTooBig : ws::kCloseProtocolError);
            broke = true;
            break;
          }
        } else {
          mrb_str_cat(mrb, c->msg, tmp, chunk);
        }
        done += chunk;
      }
      if (broke) break;
      if (c->msg_op == ws::kText && !utf8_ok(c, false)) {
        alive = fail(c, sink, ws::kCloseInvalidPayload);
        break;
      }
    }
    c->mask_off = static_cast<uint8_t>((c->mask_off + take) & 3);
    c->remaining -= take;
    p += take;
    len -= take;
    if (c->remaining == 0) {
      c->in_payload = false;
      if (!finish_frame(c, sink)) {
        alive = false;
        break;
      }
      if (c->got_close) break;
    }
  }
  return mrb_bool_value(alive);
}
}

// RFC 6455: Webmachine::WebsocketResource, the class a route may name.
void ws_init(mrb_state* mrb, struct RClass* wm) {
  mrb_define_class_under_id(mrb, wm, MRB_SYM(WebsocketResource), mrb->object_class);
}

// RFC 6455: one route's folded resource.
WsResource* ws_resource_new() { return new WsResource(); }

// RFC 6455: unique_ptr's deleter across the TU boundary.
void ws_resource_free(WsResource* r) {
  if (r == nullptr) return;
  delete r;
}

// RFC 6455: fold a resource class for a websocket route, once, at
// route.websocket - arities read, konst answers asked, the class frozen.
bool ws_fold(mrb_state* mrb, mrb_value klass, WsResource& out, char* err, size_t errlen) {
  if (!mrb_class_p(klass)) {
    std::snprintf(err, errlen,
                  "route.websocket wants a class inheriting Webmachine::WebsocketResource");
    return false;
  }
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  struct RClass* base = mrb_class_get_under_id(mrb, wm, MRB_SYM(WebsocketResource));
  bool ok = false;
  for (struct RClass* k = mrb_class_ptr(klass)->super; k != nullptr; k = k->super) {
    if (k == base) {
      ok = true;
      break;
    }
  }
  if (!ok) {
    std::snprintf(err, errlen,
                  "route.websocket: the class does not inherit "
                  "Webmachine::WebsocketResource - a websocket resource is NOT a "
                  "Webmachine::Resource: no response, no status, no flow survives the "
                  "upgrade, only the handshake's head");
    return false;
  }
  out.mrb = mrb;
  out.klass = mrb_class_ptr(klass);

  const auto argc_of = [&](mrb_sym sym, int most, int* out_argc) -> bool {
    struct RClass* owner = out.klass;
    mrb_method_t m = mrb_method_search_vm(mrb, &owner, sym);
    if (MRB_METHOD_UNDEF_P(m)) return false;
    int a = most;
    if (!MRB_METHOD_FUNC_P(m)) {
      const struct RProc* pr = MRB_METHOD_PROC(m);
      if (pr != nullptr) {
        const mrb_int ar = mrb_proc_arity(pr);
        if (ar >= 0) a = static_cast<int>(ar) < most ? static_cast<int>(ar) : most;
      }
    }
    *out_argc = a;
    return true;
  };

  if (!argc_of(MRB_SYM(on_data), 2, &out.data_argc)) {
    std::snprintf(err, errlen,
                  "route.websocket: the resource defines no on_data - that is the one "
                  "method a websocket resource IS (on_data(data) or on_data(data, binary))");
    return false;
  }
  out.have_close = argc_of(MRB_SYM(on_close), 2, &out.close_argc);

  {
    struct RClass* meta = mrb_class(mrb, klass);
    mrb_method_t m = mrb_method_search_vm(mrb, &meta, MRB_SYM_Q(validate_text));
    if (!MRB_METHOD_UNDEF_P(m)) {
      const mrb_value v = mrb_funcall_argv(mrb, klass, MRB_SYM_Q(validate_text), 0, nullptr);
      if (mrb->exc != nullptr) {
        std::snprintf(err, errlen,
                      "route.websocket: validate_text? raised (exception below)");
        mrb_print_error(mrb);
        mrb->exc = nullptr;
        return false;
      }
      out.validate_text = mrb_test(v);
    }
  }

  {
    struct RClass* meta = mrb_class(mrb, klass);
    mrb_method_t m = mrb_method_search_vm(mrb, &meta, MRB_SYM_Q(permessage_deflate));
    if (!MRB_METHOD_UNDEF_P(m)) {
      const mrb_value v =
          mrb_funcall_argv(mrb, klass, MRB_SYM_Q(permessage_deflate), 0, nullptr);
      if (mrb->exc != nullptr) {
        std::snprintf(err, errlen,
                      "route.websocket: permessage_deflate? raised (exception below)");
        mrb_print_error(mrb);
        mrb->exc = nullptr;
        return false;
      }
      out.want_deflate = mrb_test(v);
    }
  }

  {
    struct RClass* meta = mrb_class(mrb, klass);
    mrb_method_t m = mrb_method_search_vm(mrb, &meta, MRB_SYM(max_message));
    if (!MRB_METHOD_UNDEF_P(m)) {
      const mrb_value v = mrb_funcall_argv(mrb, klass, MRB_SYM(max_message), 0, nullptr);
      if (mrb->exc != nullptr) {
        std::snprintf(err, errlen, "route.websocket: max_message raised (exception below)");
        mrb_print_error(mrb);
        mrb->exc = nullptr;
        return false;
      }
      if (!mrb_fixnum_p(v) || mrb_fixnum(v) <= 0) {
        std::snprintf(err, errlen,
                      "route.websocket: max_message answers with a positive Integer of "
                      "bytes, or it is not defined at all (the default is %zu)",
                      kMaxWsMessageDefault);
        return false;
      }
      out.max_message = static_cast<size_t>(mrb_fixnum(v));
    }
  }

  mrb_obj_freeze(mrb, klass);

  return true;
}

// RFC 6455 4.2.2: build THIS peer's resource; its initialize is the
// connect hook and its return value is the answer.
WsConn* ws_admit(const WsResource* r, Logger* elog, std::string& proto, uint16_t& status) {
  proto.clear();
  status = 0;
  mrb_state* mrb = r->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value obj =
      mrb_obj_value(mrb_obj_alloc(mrb, MRB_INSTANCE_TT(r->klass), r->klass));
  mrb_gc_register(mrb, obj);
  const mrb_value out = mrb_funcall_argv(mrb, obj, MRB_SYM(initialize), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (elog != nullptr) log_exception(*elog, mrb, nullptr, 0, nullptr, 0, 500);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_unregister(mrb, obj);
    mrb_gc_arena_restore(mrb, ai);
    status = 500;
    return nullptr;
  }
  bool admit = true;
  if (mrb_string_p(out)) {
    proto.assign(RSTRING_PTR(out), static_cast<size_t>(RSTRING_LEN(out)));
  } else if (mrb_symbol_p(out)) {
    const mrb_sym s = mrb_symbol(out);
    if (s == MRB_SYM(forbidden)) status = 403;
    else if (s == MRB_SYM(not_found)) status = 404;
    else if (s == MRB_SYM(bad_request)) status = 400;
    else status = 403;
    admit = false;
  }
  if (!admit) {
    mrb_gc_unregister(mrb, obj);
    mrb_gc_arena_restore(mrb, ai);
    return nullptr;
  }
  mrb_gc_arena_restore(mrb, ai);
  WsConn* c = new WsConn();
  c->res = r;
  c->elog = elog;
  c->self = obj;
  return c;
}

// RFC 7692: does this route accept the extension at all?
bool ws_wants_deflate(const WsResource* r) { return r->want_deflate; }

// RFC 7692: settle what the handshake negotiated; the codec is lazy.
void ws_open(WsConn* c, const wsdeflate::Params& deflate) {
  if (deflate.on) {
    c->codec = new wsdeflate::Codec();
    c->codec->configure(deflate);
  }
}

// RFC 6455 7.4.1: 1006 where no close frame was ever seen.
void ws_free(WsConn* c) {
  if (c == nullptr) return;
  report_close(c, 1006, nullptr, 0);
  drop_msg(c);
  if (c->res != nullptr && c->res->mrb != nullptr && !mrb_nil_p(c->self)) {
    mrb_gc_unregister(c->res->mrb, c->self);
    c->self = mrb_nil_value();
  }
  delete c->codec;
  delete c;
}

// RFC 6455 5.3: wire bytes for an upgraded connection, under protection.
bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink) {
  if (len == 0) return true;
  mrb_state* mrb = c->res->mrb;
  FeedCall call{c, data, len, &sink};
  mrb_bool raised = FALSE;
  const mrb_value r = mrb_protect_error(mrb, feed_body, &call, &raised);
  if (raised) {
    mrb->exc = mrb_obj_ptr(r);
    if (c->elog != nullptr) log_exception(*c->elog, mrb, nullptr, 0, nullptr, 0, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    return fail(c, sink, ws::kCloseInternalError);
  }
  return mrb_test(r);
}
}
