#include "wsconn.hpp"

#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <simdutf.h>

#include <cstdio>
#include <cstring>

#include "websocket.hpp"

// mruby computes a method's arity itself (src/proc.c); the declaration
// lives in mruby/internal.h, which is a C header with no extern "C"
// wrapper - including it from C++ yields a mangled symbol nothing
// defines. Declared here instead, next to the one place that uses it.
extern "C" mrb_int mrb_proc_arity(const struct RProc* p);

namespace webmachine {

// The route's resource: one class, one instance, the callbacks
// resolved. Nothing here is looked up again once a socket is open.
struct WsResource {
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  mrb_value self = {};  // THE instance - built once, gc_registered
  bool have_open = false;
  bool have_close = false;
  // How many arguments each callback ASKED for, read once from its own
  // signature. `def on_data(data)` and `def on_data(data, binary)` are
  // both right, and neither is handed something it did not want.
  int data_argc = 1;
  int close_argc = 0;
  size_t max_message = kMaxWsMessageDefault;
  // Does a TEXT message get checked for valid UTF-8 (RFC 6455 8.1)?
  // TRUE by default, because the RFC says MUST and Autobahn's whole
  // section 6 checks it. A route may answer false - the one reason to
  // is throughput on a link whose payloads are known good (a private
  // binary protocol that spells itself text), and the price is stated
  // where it is paid: this endpoint then forwards whatever arrives,
  // and a peer sending broken text gets an answer instead of 1007.
  bool validate_text = true;
};

// One peer, as a STREAMING frame reader.
//
// THE COPY BUDGET IS THE WHOLE DESIGN HERE (Nutzer-Entscheid
// 2026-08-22). The Ring lends fixed 4 KiB buffers, so a message bigger
// than one buffer arrives in pieces no matter what - the bytes must be
// copied somewhere. The obvious shape (gather into a std::string, then
// build an mruby String out of it) copies every one of those bytes
// TWICE. So this reader keeps no payload buffer at all: once a frame
// header is complete, every payload byte is unmasked and appended
// STRAIGHT into the mruby String that will be handed to on_data. One
// copy, from the pool buffer into the VM heap, and the pool buffer is
// never written to.
//
// What is buffered is at most 14 bytes of frame header (2 + 8 length +
// 4 mask) that a receive happened to cut in half, and a control
// frame's payload, which RFC 6455 5.5 caps at 125 bytes.
struct WsConn {
  const WsResource* res = nullptr;

  // --- the header being read
  unsigned char hbuf[14] = {};
  uint8_t hlen = 0;   // bytes of hbuf filled
  uint8_t hneed = 2;  // bytes needed before the next decision

  // --- the frame being read
  bool in_payload = false;
  uint8_t opcode = 0;
  bool fin = false;
  bool control = false;
  uint64_t remaining = 0;  // payload bytes still to come
  unsigned char mask[4] = {};
  uint8_t mask_off = 0;

  // A control frame's payload (5.5: 125 bytes, never fragmented).
  char ctl[125] = {};
  uint8_t ctl_len = 0;

  // The message under construction, held in the VM heap and rooted for
  // as long as it takes - fragments may arrive over many ticks. One
  // registration per MESSAGE, not per connection: a connection between
  // messages holds no Ruby object at all.
  mrb_value msg = mrb_nil_value();
  bool msg_live = false;
  uint8_t msg_op = 0;  // the opcode the message started with, 0 = none
  // How much of a TEXT message has been validated as UTF-8 already.
  // RFC 6455 8.1 lets a text message be rejected the moment it CANNOT
  // become valid, and Autobahn 6.4.x tests exactly that: waiting for
  // the last fragment is correct but late (measured NON-STRICT). So
  // every chunk is validated as it lands, and only a sequence the
  // chunk boundary cut in half is carried to the next one.
  size_t validated = 0;

  bool sent_close = false;
  bool got_close = false;
  bool closed_reported = false;
};

namespace {

// A Symbol answer, RFC 6455 7.4.1 by name. This IS the vocabulary - a
// resource that returns a Symbol outside it is told so.
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

// One frame into the sink: the header where it belongs, the payload
// from where it already lies (websocket.hpp builds a HEADER, never a
// buffer - the delivery discipline #168 gave h1).
void emit(std::string& sink, uint8_t opcode, const char* p, size_t n) {
  char head[10];
  const size_t hn = ws::build_header(opcode, true, n, head);
  sink.append(head, hn);
  if (n != 0) sink.append(p, n);
}

// The close handshake's own half (RFC 6455 5.5.1): sent at most once,
// whoever started it.
void emit_close(WsConn* c, std::string& sink, uint16_t code, const char* reason,
                size_t reason_len) {
  if (c->sent_close) return;
  c->sent_close = true;
  char payload[125];
  const size_t n = ws::build_close_payload(code, reason, reason_len, payload);
  emit(sink, ws::kClose, payload, n);
}

// Can these 1-3 bytes still BECOME a valid UTF-8 sequence? simdutf
// answers TOO_SHORT both for a sequence the chunk boundary cut and for
// a lead byte followed by a byte that can never continue it - and the
// difference is the whole of Autobahn 6.4.x: F4 90 is already
// unrecoverable (F4 admits only 80-8F), so a server that waits for the
// rest of the message is late. Table from RFC 3629, spelled here
// because this is the ONE thing the library cannot tell us.
bool valid_prefix(const unsigned char* p, size_t n) {
  if (n == 0) return true;
  const unsigned char b0 = p[0];
  size_t need = 0;
  unsigned char lo = 0x80, hi = 0xbf;  // the range the SECOND byte may take
  if (b0 >= 0xc2 && b0 <= 0xdf) need = 1;
  else if (b0 == 0xe0) { need = 2; lo = 0xa0; }
  else if (b0 >= 0xe1 && b0 <= 0xec) need = 2;
  else if (b0 == 0xed) { need = 2; hi = 0x9f; }
  else if (b0 >= 0xee && b0 <= 0xef) need = 2;
  else if (b0 == 0xf0) { need = 3; lo = 0x90; }
  else if (b0 >= 0xf1 && b0 <= 0xf3) need = 3;
  else if (b0 == 0xf4) { need = 3; hi = 0x8f; }
  else return false;  // ASCII would not be pending, and 80-C1/F5+ never start one
  if (n - 1 > need) return false;
  for (size_t i = 1; i < n; i++) {
    const unsigned char lim_lo = i == 1 ? lo : 0x80;
    const unsigned char lim_hi = i == 1 ? hi : 0xbf;
    if (p[i] < lim_lo || p[i] > lim_hi) return false;
  }
  return true;
}

// UTF-8 over a message that is still arriving (RFC 6455 8.1). `final`
// is the last word: a sequence still incomplete then is invalid, while
// before then it is simply a sequence the chunk boundary cut.
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
  // TOO_SHORT within the last three bytes is the boundary case: a
  // multi-byte sequence whose tail has not arrived yet. Anything else -
  // and anything at all once the message is complete - is the message
  // failing 8.1.
  if (!final && r.error == simdutf::error_code::TOO_SHORT &&
      c->validated + r.count + 4 > n) {
    const size_t at = c->validated + r.count;
    if (!valid_prefix(reinterpret_cast<const unsigned char*>(p) + at, n - at)) return false;
    c->validated = at;
    return true;
  }
  return false;
}

void drop_msg(WsConn* c) {
  if (!c->msg_live) return;
  mrb_gc_unregister(c->res->mrb, c->msg);
  c->msg = mrb_nil_value();
  c->msg_live = false;
  c->msg_op = 0;
  c->validated = 0;
}

// on_close, once, however the connection ended. A raise here is
// printed and swallowed: the connection is already over, and taking
// the process with it would be the opposite of a close handler.
void report_close(WsConn* c, uint16_t code, const char* reason, size_t reason_len) {
  if (c->closed_reported || !c->res->have_close) return;
  c->closed_reported = true;
  mrb_state* mrb = c->res->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value argv[2];
  argv[0] = mrb_fixnum_value(code);
  argv[1] = mrb_str_new(mrb, reason == nullptr ? "" : reason, reason_len);
  mrb_funcall_argv(mrb, c->res->self, MRB_SYM(on_close), c->res->close_argc, argv);
  if (mrb->exc != nullptr) {
    mrb_print_error(mrb);
    mrb->exc = nullptr;
  }
  mrb_gc_arena_restore(mrb, ai);
}

// The connection ends because THIS side found something wrong: the
// close frame goes out with the code that names it, and feed's false
// closes once the sink has drained.
bool fail(WsConn* c, std::string& sink, uint16_t code) {
  emit_close(c, sink, code, nullptr, 0);
  report_close(c, code, nullptr, 0);
  drop_msg(c);
  return false;
}

// A complete message: hand it to the resource, act on what it says.
// The String is the one this reader has been filling all along - it is
// handed over, not copied. False = the connection ends.
bool deliver(WsConn* c, std::string& sink) {
  const WsResource* r = c->res;
  mrb_state* mrb = r->mrb;
  const bool binary = c->msg_op == ws::kBinary;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value argv[2];
  argv[0] = c->msg;
  argv[1] = mrb_bool_value(binary);
  const mrb_value out = mrb_funcall_argv(mrb, r->self, MRB_SYM(on_data), r->data_argc, argv);
  drop_msg(c);
  if (mrb->exc != nullptr) {
    // A raising callback is a 1011, said once, with the reason on
    // stderr - the connection dies, the server does not.
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return fail(c, sink, ws::kCloseInternalError);
  }
  bool alive = true;
  if (mrb_string_p(out)) {
    // A String is a message, in the SAME kind the message arrived in -
    // which is what makes an echo resource `data` and nothing else.
    emit(sink, binary ? ws::kBinary : ws::kText, RSTRING_PTR(out),
         static_cast<size_t>(RSTRING_LEN(out)));
  } else if (mrb_symbol_p(out)) {
    uint16_t code = 0;
    if (symbol_code(mrb_symbol(out), code)) {
      emit_close(c, sink, code, nullptr, 0);
      report_close(c, code, nullptr, 0);
      alive = false;
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
  return alive;
}

// A frame whose payload is now complete. False = the connection ends.
bool finish_frame(WsConn* c, std::string& sink) {
  switch (c->opcode) {
    case ws::kPing:
      // 5.5.2: an endpoint MUST answer a ping with a pong carrying the
      // same payload. Not an application decision, so the resource
      // never hears about it (Nutzer-Entscheid).
      if (!c->sent_close) emit(sink, ws::kPong, c->ctl, c->ctl_len);
      return true;
    case ws::kPong:
      // 5.5.3: unsolicited pongs are legal and need no answer.
      return true;
    case ws::kClose: {
      uint16_t code = 0;
      const char* reason = nullptr;
      size_t rlen = 0;
      if (!ws::read_close(c->ctl, c->ctl_len, code, &reason, &rlen)) {
        return fail(c, sink, ws::kCloseProtocolError);
      }
      // 7.1.6: the reason is UTF-8 like any text payload.
      if (rlen != 0 && !simdutf::validate_utf8(reason, rlen)) {
        return fail(c, sink, ws::kCloseInvalidPayload);
      }
      c->got_close = true;
      // 5.5.1: echo the close, then the connection ends. 1005 is a
      // local-only code and must not go back on the wire.
      emit_close(c, sink, code == 1005 ? ws::kCloseNormal : code, reason, rlen);
      report_close(c, code, reason, rlen);
      drop_msg(c);
      return false;
    }
    default: break;
  }
  // A data frame. Nothing is assembled here - the payload has been in
  // the message String since the moment its header was read.
  if (!c->fin) return true;  // more fragments follow
  // 8.1: a text message that is not valid UTF-8 fails the connection
  // with 1007, and the resource never sees it. Most of it was checked
  // as it arrived; this is the last word on whatever the final chunk
  // boundary left open.
  if (c->msg_op == ws::kText && !utf8_ok(c, true)) {
    return fail(c, sink, ws::kCloseInvalidPayload);
  }
  return deliver(c, sink);
}

// The header is complete: check everything RFC 6455 5.2/5.5 demands of
// it, and set the payload state up. False = the connection ends.
bool begin_frame(WsConn* c, std::string& sink) {
  const unsigned char b0 = c->hbuf[0];
  const unsigned char b1 = c->hbuf[1];
  const bool fin = (b0 & 0x80) != 0;
  const uint8_t opcode = static_cast<uint8_t>(b0 & 0x0f);
  if ((b0 & 0x70) != 0) return fail(c, sink, ws::kCloseProtocolError);  // RSV, unnegotiated
  const bool control = (opcode & 0x08) != 0;
  switch (opcode) {
    case ws::kContinuation:
    case ws::kText:
    case ws::kBinary:
    case ws::kClose:
    case ws::kPing:
    case ws::kPong: break;
    default: return fail(c, sink, ws::kCloseProtocolError);  // 5.2: reserved
  }
  if ((b1 & 0x80) == 0) return fail(c, sink, ws::kCloseProtocolError);  // 5.1: masked

  uint64_t plen = static_cast<uint64_t>(b1 & 0x7f);
  size_t at = 2;
  if (plen == 126) {
    plen = (static_cast<uint64_t>(c->hbuf[2]) << 8) | c->hbuf[3];
    at = 4;
    if (plen < 126) return fail(c, sink, ws::kCloseProtocolError);  // 5.2: minimal
  } else if (plen == 127) {
    plen = 0;
    for (int i = 0; i < 8; i++) plen = (plen << 8) | c->hbuf[2 + i];
    at = 10;
    if (plen <= 0xffff || (plen >> 63) != 0) return fail(c, sink, ws::kCloseProtocolError);
  }
  // 5.5: a control frame carries at most 125 bytes and is never
  // fragmented.
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
      // 5.4: a continuation with nothing to continue.
      if (c->msg_op == 0) return fail(c, sink, ws::kCloseProtocolError);
      if (static_cast<uint64_t>(RSTRING_LEN(c->msg)) + plen > max) {
        return fail(c, sink, ws::kCloseTooBig);
      }
    } else {
      // 5.4: a new message may not begin inside another one.
      if (c->msg_op != 0) return fail(c, sink, ws::kCloseProtocolError);
      if (plen > max) return fail(c, sink, ws::kCloseTooBig);
      // Room for THIS frame, not for the limit: a 10-byte message must
      // not allocate what a route allowed at most.
      c->msg = mrb_str_new_capa(mrb, static_cast<mrb_int>(plen));
      mrb_gc_register(mrb, c->msg);
      c->msg_live = true;
      c->msg_op = opcode;
    }
  }
  c->in_payload = plen != 0;
  return true;
}

// How many header bytes are needed before the next decision can be
// made: 2, then the extended length, then the mask.
uint8_t header_need(const WsConn* c) {
  if (c->hlen < 2) return 2;
  const uint8_t len7 = static_cast<uint8_t>(c->hbuf[1] & 0x7f);
  const uint8_t ext = len7 == 126 ? 2 : (len7 == 127 ? 8 : 0);
  // The mask is always there: an unmasked client frame is refused in
  // begin_frame, and refusing it needs the two bytes that say so.
  return static_cast<uint8_t>(2 + ext + ((c->hbuf[1] & 0x80) != 0 ? 4 : 0));
}

struct FeedCall {
  WsConn* c;
  const char* data;
  size_t len;
  std::string* sink;
};

// The reader itself. Runs under mrb_protect_error (see ws_feed): every
// byte it moves goes through mruby's allocator, which raises rather
// than returning null.
mrb_value feed_body(mrb_state* mrb, void* ud) {
  FeedCall* f = static_cast<FeedCall*>(ud);
  WsConn* c = f->c;
  std::string& sink = *f->sink;
  const char* p = f->data;
  size_t len = f->len;
  bool alive = true;

  while (len != 0) {
    if (!c->in_payload) {
      // Header bytes, at most 14 of them, and only when a receive cut
      // one in half.
      c->hneed = header_need(c);
      while (c->hlen < c->hneed && len != 0) {
        c->hbuf[c->hlen++] = static_cast<unsigned char>(*p++);
        len--;
        c->hneed = header_need(c);
      }
      if (c->hlen < c->hneed) break;  // the rest of the header will come
      c->hlen = 0;
      if (!begin_frame(c, sink)) {
        alive = false;
        break;
      }
      if (!c->in_payload) {  // a zero-length frame is complete already
        if (!finish_frame(c, sink)) {
          alive = false;
          break;
        }
      }
      continue;
    }

    // PAYLOAD: unmasked straight into its destination. No intermediate
    // buffer exists, which is the whole point of this reader.
    size_t take = len < c->remaining ? len : static_cast<size_t>(c->remaining);
    if (c->control) {
      // Bounded by 125, so the small fixed buffer IS the destination.
      for (size_t i = 0; i < take; i++) {
        c->ctl[c->ctl_len++] = static_cast<char>(p[i] ^ c->mask[(c->mask_off + i) & 3]);
      }
    } else {
      // Straight into the VM heap. mrb_str_cat grows only where a
      // fragment made the message longer than its first frame said.
      char tmp[512];
      size_t done = 0;
      while (done < take) {
        const size_t chunk = take - done < sizeof(tmp) ? take - done : sizeof(tmp);
        for (size_t i = 0; i < chunk; i++) {
          tmp[i] = static_cast<char>(p[done + i] ^ c->mask[(c->mask_off + done + i) & 3]);
        }
        mrb_str_cat(mrb, c->msg, tmp, chunk);
        done += chunk;
      }
      // As it lands, not when it ends (Autobahn 6.4.x): a text message
      // that can no longer become valid is refused right here.
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
      // 5.5.1: after a close, nothing more is read from this peer.
      if (c->got_close) break;
    }
  }
  return mrb_bool_value(alive);
}

}  // namespace

void ws_init(mrb_state* mrb, struct RClass* wm) {
  // Object, not Resource: a websocket has no response and no flow (see
  // the header). The class exists so route.websocket can name what it
  // wants and refuse everything else.
  mrb_define_class_under_id(mrb, wm, MRB_SYM(WebsocketResource), mrb->object_class);
}

WsResource* ws_resource_new() { return new WsResource(); }

void ws_resource_free(WsResource* r) {
  if (r == nullptr) return;
  if (r->mrb != nullptr && !mrb_nil_p(r->self)) mrb_gc_unregister(r->mrb, r->self);
  delete r;
}

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

  // The arity each callback asked for, read ONCE. Optional or splat
  // arguments mean "hand me everything there is".
  const auto argc_of = [&](mrb_sym sym, int most, int* out_argc) -> bool {
    struct RClass* owner = out.klass;
    mrb_method_t m = mrb_method_search_vm(mrb, &owner, sym);
    if (MRB_METHOD_UNDEF_P(m)) return false;
    // mruby's own arity: n >= 0 means exactly n required; n < 0 means
    // -(n+1) required plus optionals or a splat, which is a method
    // saying "hand me what there is".
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
  int open_argc = 0;
  out.have_open = argc_of(MRB_SYM(on_open), 0, &open_argc);
  out.have_close = argc_of(MRB_SYM(on_close), 2, &out.close_argc);

  // RFC 6455 8.1's check, on or off per route - asked ONCE, like every
  // other konst answer. A `?` predicate, per the house rule.
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

  // How big a message this route lets an mruby String become. Asked
  // ONCE on the class (its metaclass owns class methods), exactly like
  // the flow's konst callbacks.
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

  // Frozen like every routed class: nothing may be redefined behind an
  // open socket.
  mrb_obj_freeze(mrb, klass);

  // THE instance, built once (Nutzer-Entscheid: "einmal instanziert").
  out.self = mrb_obj_new(mrb, out.klass, 0, nullptr);
  if (mrb->exc != nullptr) {
    std::snprintf(err, errlen,
                  "route.websocket: the resource raised while being built (exception below)");
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    return false;
  }
  mrb_gc_register(mrb, out.self);
  return true;
}

bool ws_admit(const WsResource* r, std::string& proto, uint16_t& status) {
  proto.clear();
  status = 0;
  if (!r->have_open) return true;
  mrb_state* mrb = r->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value out = mrb_funcall_argv(mrb, r->self, MRB_SYM(on_open), 0, nullptr);
  if (mrb->exc != nullptr) {
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    status = 500;
    return false;
  }
  bool admit = true;
  if (mrb_string_p(out)) {
    // The subprotocol this side picked, out of what the head offered -
    // the resource read Sec-WebSocket-Protocol through request.headers
    // and answered with one of its tokens (RFC 6455 4.2.2 step 5.5).
    proto.assign(RSTRING_PTR(out), static_cast<size_t>(RSTRING_LEN(out)));
  } else if (mrb_symbol_p(out)) {
    const mrb_sym s = mrb_symbol(out);
    if (s == MRB_SYM(forbidden)) status = 403;
    else if (s == MRB_SYM(not_found)) status = 404;
    else if (s == MRB_SYM(bad_request)) status = 400;
    else status = 403;
    admit = false;
  }
  mrb_gc_arena_restore(mrb, ai);
  return admit;
}

WsConn* ws_open(const WsResource* r) {
  WsConn* c = new WsConn();
  c->res = r;
  return c;
}

void ws_free(WsConn* c) {
  if (c == nullptr) return;
  // However this connection ended - a peer that vanished, a reset, the
  // server stopping - the resource hears about it exactly once. 1006 is
  // what RFC 6455 7.4.1 reserves for "closed abnormally, no close frame
  // was seen", which is precisely this path.
  report_close(c, 1006, nullptr, 0);
  drop_msg(c);
  delete c;
}

bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink) {
  if (len == 0) return true;
  mrb_state* mrb = c->res->mrb;
  FeedCall call{c, data, len, &sink};
  mrb_bool raised = FALSE;
  // ONE protected frame per receive, not per byte: the reader builds
  // mruby Strings, and mruby answers an exhausted heap by RAISING.
  // Outside a VM frame nothing would catch that (resource.cpp makes the
  // same distinction at setup), and a websocket's peer must not be able
  // to take the process down by asking for memory.
  const mrb_value r = mrb_protect_error(mrb, feed_body, &call, &raised);
  if (raised) {
    mrb->exc = mrb_obj_ptr(r);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    return fail(c, sink, ws::kCloseInternalError);
  }
  return mrb_test(r);
}

}  // namespace webmachine
