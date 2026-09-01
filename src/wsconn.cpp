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

// mruby's internal header, not a copy of one line out of it - see the
// note in resource.cpp. A copied signature keeps compiling after mruby
// changes it; an included one does not.
extern "C" {
#include <mruby/internal.h>
}

namespace webmachine {
namespace wsdeflate {
// RFC 7692 7.2.2: where inflated bytes go. False stops the pump, which is
// how the message cap is enforced against a decompression bomb.
using InflateSink = bool (*)(void* ud, const char* q, size_t qn);

class Codec {
 public:
  Codec() = default;
  Codec(const Codec&) = delete;
  Codec& operator=(const Codec&) = delete;
  // RFC 7692: both zlib streams die with the connection.
  ~Codec() {
    if (inf_on_) inflateEnd(&inf_);
    if (def_on_) deflateEnd(&def_);
  }

  // RFC 7692 7.1.2: what the negotiation settled on.
  void configure(const Params& p) { p_ = p; }
  // RFC 7692: what this connection agreed to.
  const Params& params() const { return p_; }

  // RFC 7692 7.2.2: payload bytes as they arrive; the SINK is the only
  // bound, which is the whole decompression-bomb answer.
  int inflate_some(const char* in, size_t n, InflateSink sink, void* ud) {
    if (!inflate_ready()) return -1;
    inf_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    inf_.avail_in = static_cast<uInt>(n);
    return pump(sink, ud);
  }

  // RFC 7692 7.2.2 step 1: the four bytes the sender stripped go back on.
  int inflate_finish(InflateSink sink, void* ud) {
    if (!inflate_ready()) return -1;
    inf_.next_in = const_cast<Bytef*>(kSyncTail);
    inf_.avail_in = sizeof(kSyncTail);
    const int rc = pump(sink, ud);
    if (rc != 0) return rc;
    if (p_.client_no_context_takeover || inf_ended_) {
      inflateReset(&inf_);
      inf_ended_ = false;
    }
    return 0;
  }

  // RFC 7692 7.2.1: one whole message; false means send it uncompressed,
  // and then never compress on this connection again.
  bool compress(const char* in, size_t n, std::string& out) {
    if (n > std::numeric_limits<uInt>::max()) return false;
    if (def_broken_ || !deflate_ready()) return false;
    out.clear();
    def_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    def_.avail_in = static_cast<uInt>(n);
    unsigned char buf[8192];
    for (;;) {
      def_.next_out = buf;
      def_.avail_out = sizeof(buf);
      const int rc = deflate(&def_, Z_SYNC_FLUSH);
      if (rc != Z_OK && rc != Z_BUF_ERROR) {
        def_broken_ = true;
        return false;
      }
      out.append(reinterpret_cast<const char*>(buf), sizeof(buf) - def_.avail_out);
      if (def_.avail_out != 0) break;
    }
    if (out.size() < sizeof(kSyncTail) ||
        std::memcmp(out.data() + out.size() - sizeof(kSyncTail), kSyncTail,
                    sizeof(kSyncTail)) != 0) {
      def_broken_ = true;
      return false;
    }
    out.resize(out.size() - sizeof(kSyncTail));
    if (p_.server_no_context_takeover) deflateReset(&def_);
    return true;
  }

 private:
  // RFC 7692 7.1.2.1: never below 9 bits - no zlib can produce an 8-bit
  // window, and larger than promised is always safe.
  bool inflate_ready() {
    if (inf_on_) return true;
    const int bits = p_.client_max_window_bits < kMinRawWindowBits
                         ? kMinRawWindowBits
                         : p_.client_max_window_bits;
    if (inflateInit2(&inf_, -bits) != Z_OK) return false;
    inf_on_ = true;
    return true;
  }

  // RFC 7692 7.1.2.1: raw deflate, the negotiated window, Z_BEST_SPEED.
  bool deflate_ready() {
    if (def_on_) return true;
    if (deflateInit2(&def_, Z_BEST_SPEED, Z_DEFLATED,
                     -static_cast<int>(p_.server_max_window_bits), 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
      def_broken_ = true;
      return false;
    }
    def_on_ = true;
    return true;
  }

  // RFC 7692 7.2.2: inflate until zlib stops producing.
  int pump(InflateSink sink, void* ud) {
    unsigned char buf[8192];
    for (;;) {
      inf_.next_out = buf;
      inf_.avail_out = sizeof(buf);
      const int rc = inflate(&inf_, Z_NO_FLUSH);
      if (rc == Z_STREAM_END) inf_ended_ = true;
      else if (rc != Z_OK && rc != Z_BUF_ERROR) return -1;
      const size_t got = sizeof(buf) - inf_.avail_out;
      if (got != 0 && !sink(ud, reinterpret_cast<const char*>(buf), got)) return -2;
      if (inf_.avail_out != 0) return 0;
    }
  }

  Params p_;
  z_stream inf_{};
  z_stream def_{};
  bool inf_on_ = false;
  bool def_on_ = false;
  bool def_broken_ = false;
  bool inf_ended_ = false;
};
}  // namespace wsdeflate

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
// One frame to send: what it is, the octets it carries, and whether those
// octets are deflated (RFC 7692 6).
struct Outgoing {
  uint8_t opcode;
  std::string_view payload;
  bool deflated = false;
};

void emit(std::string& sink, Outgoing frame) {
  const size_t n = frame.payload.size();
  char head[10];
  const size_t hn = ws::build_header({frame.opcode, true, frame.deflated, n}, head);
  sink.append(head, hn);
  if (n != 0) sink.append(frame.payload);
}

// RFC 6455 5.6 / RFC 7692 6: a DATA message, compressed where negotiated.
// How many of `most` arguments the method takes, or false if it is not
// defined. A cfunc is handed all of them; a Ruby method only its arity.
// One method to look for: the class it would be on, and its name.
struct Method {
  struct RClass* klass;
  mrb_sym sym;
};

bool method_argc(mrb_state* mrb, Method want, int most, int* out_argc) {
  struct RClass* owner = want.klass;
  mrb_method_t m = mrb_method_search_vm(mrb, &owner, want.sym);
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
}

// RFC 7692 7.2.2: inflated bytes onto the message being assembled, up to
// the resource's cap. False is what stops a decompression bomb.
bool msg_cat(void* ud, const char* q, size_t qn) {
  WsConn* c = static_cast<WsConn*>(ud);
  if (static_cast<uint64_t>(RSTRING_LEN(c->msg)) + qn > c->res->max_message) return false;
  mrb_str_cat(c->res->mrb, c->msg, q, qn);
  return true;
}

void emit_data(WsConn* c, std::string& sink, Outgoing frame) {
  const uint8_t opcode = frame.opcode;
  const char* const p = frame.payload.data();
  const size_t n = frame.payload.size();
  if (c->codec != nullptr) {
    static std::string scratch;
    if (c->codec->compress(p, n, scratch)) {
      emit(sink, {opcode, scratch, true});
      return;
    }
  }
  emit(sink, {opcode, {p, n}});
}

// RFC 6455 5.5.1: the close handshake's own half, sent at most once.
void emit_close(WsConn* c, std::string& sink, ws::Close close) {
  if (c->sent_close) return;
  c->sent_close = true;
  char payload[125];
  const size_t n = ws::build_close_payload(close, payload);
  emit(sink, {ws::kClose, {payload, n}});
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
void report_close(WsConn* c, ws::Close close) {
  const uint16_t code = close.code;
  const char* const reason = close.reason.data();
  const size_t reason_len = close.reason.size();
  if (c->closed_reported || !c->res->have_close) return;
  c->closed_reported = true;
  mrb_state* mrb = c->res->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_value argv[2];
  argv[0] = mrb_fixnum_value(code);
  argv[1] = mrb_str_new(mrb, reason == nullptr ? "" : reason, reason_len);
  mrb_funcall_argv(mrb, c->self, MRB_SYM(on_close), c->res->close_argc, argv);
  if (mrb->exc != nullptr) {
    if (c->elog != nullptr) log_raise(*c->elog, mrb, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
  }
  mrb_gc_arena_restore(mrb, ai);
}

// RFC 6455 5.5.1: this side found something wrong - close with the code.
bool fail(WsConn* c, std::string& sink, uint16_t code) {
  emit_close(c, sink, {code, {}});
  report_close(c, {code, {}});
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
    if (c->elog != nullptr) log_raise(*c->elog, mrb, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return fail(c, sink, ws::kCloseInternalError);
  }
  if (mrb_string_p(out)) {
    emit_data(c, sink,
              {binary ? ws::kBinary : ws::kText,
               {RSTRING_PTR(out), static_cast<size_t>(RSTRING_LEN(out))}});
  } else if (mrb_symbol_p(out)) {
    uint16_t code = 0;
    if (symbol_code(mrb_symbol(out), code)) {
      emit_close(c, sink, {code, {}});
      report_close(c, {code, {}});
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
      if (!c->sent_close) emit(sink, {ws::kPong, {c->ctl, c->ctl_len}});
      return true;
    case ws::kPong:
      return true;
    case ws::kClose: {
      ws::Close close;
      if (!ws::read_close({c->ctl, c->ctl_len}, close)) {
        return fail(c, sink, ws::kCloseProtocolError);
      }
      const char* const reason = close.reason.data();
      const size_t rlen = close.reason.size();
      const uint16_t code = close.code;
      if (rlen != 0 && !simdutf::validate_utf8(reason, rlen)) {
        return fail(c, sink, ws::kCloseInvalidPayload);
      }
      c->got_close = true;
      const uint16_t say = code == 1005 ? ws::kCloseNormal : code;
      emit_close(c, sink, {say, close.reason});
      report_close(c, {code, close.reason});
      drop_msg(c);
      return false;
    }
    default: break;
  }
  if (!c->fin) return true;
  if (c->msg_deflated) {
    const int rc = c->codec->inflate_finish(msg_cat, c);
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
  // RFC 6455 5.2 / 5.4: the header is READ and judged first, whole. It used
  // to be judged one rule at a time with the refusal written from inside
  // the check that failed.
  const ws::Head h = ws::read_head(c->hbuf, c->codec != nullptr);
  if (h.err != ws::Head::Err::kNone) return fail(c, sink, ws::kCloseProtocolError);
  const uint64_t msg_len =
      c->msg_op != 0 ? static_cast<uint64_t>(RSTRING_LEN(c->msg)) : 0;
  const ws::Head::Err a =
      ws::admit(h, {c->msg_op, c->msg_deflated, msg_len, c->res->max_message});
  if (a != ws::Head::Err::kNone) {
    return fail(c, sink,
                a == ws::Head::Err::kTooBig ? ws::kCloseTooBig : ws::kCloseProtocolError);
  }

  std::memcpy(c->mask, c->hbuf + h.masking_key_at, 4);
  c->mask_off = 0;
  c->opcode = h.opcode;
  c->fin = h.fin;
  c->control = h.control;
  c->remaining = h.payload_length;
  c->ctl_len = 0;

  // A data frame that starts a message opens the buffer it collects into -
  // the one thing here the VM has to be asked for.
  if (!h.control && h.opcode != ws::kContinuation) {
    mrb_state* mrb = c->res->mrb;
    const uint64_t max = c->res->max_message;
    const uint64_t capa = h.payload_length > max ? max : h.payload_length;
    c->msg = mrb_str_new_capa(mrb, static_cast<mrb_int>(capa));
    mrb_gc_register(mrb, c->msg);
    c->msg_live = true;
    c->msg_op = h.opcode;
    c->msg_deflated = h.rsv1;
  }
  c->in_payload = h.payload_length != 0;
  return true;
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
      c->hneed = ws::header_need(c->hbuf, c->hlen);
      while (c->hlen < c->hneed && len != 0) {
        c->hbuf[c->hlen++] = static_cast<unsigned char>(*p++);
        len--;
        c->hneed = ws::header_need(c->hbuf, c->hlen);
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
      ws::unmask_copy(c->ctl + c->ctl_len, {p, take}, {c->mask, c->mask_off});
      c->ctl_len += take;
    } else {
      char tmp[512];
      size_t done = 0;
      bool broke = false;
      while (done < take) {
        const size_t chunk = take - done < sizeof(tmp) ? take - done : sizeof(tmp);
        ws::unmask_copy(tmp, {p + done, chunk}, {c->mask, c->mask_off + done});
        if (c->msg_deflated) {
          const int rc = c->codec->inflate_some(tmp, chunk, msg_cat, c);
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
bool ws_fold(Setup s, mrb_value klass, WsResource& out) {
  mrb_state* const mrb = s.mrb;
  char* const err = s.why.buf;
  const size_t errlen = s.why.len;
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

  if (!method_argc(mrb, {out.klass, MRB_SYM(on_data)}, 2, &out.data_argc)) {
    std::snprintf(err, errlen,
                  "route.websocket: the resource defines no on_data - that is the one "
                  "method a websocket resource IS (on_data(data) or on_data(data, binary))");
    return false;
  }
  out.have_close =
      method_argc(mrb, {out.klass, MRB_SYM(on_close)}, 2, &out.close_argc);

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
WsConn* ws_admit(const WsResource* r, Logger* elog, WsAdmit answered) {
  std::string& proto = answered.proto;
  uint16_t& status = answered.status;
  proto.clear();
  status = 0;
  mrb_state* mrb = r->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value obj =
      mrb_obj_value(mrb_obj_alloc(mrb, MRB_INSTANCE_TT(r->klass), r->klass));
  mrb_gc_register(mrb, obj);
  const mrb_value out = mrb_funcall_argv(mrb, obj, MRB_SYM(initialize), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (elog != nullptr) log_raise(*elog, mrb, 500);
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
  report_close(c, {1006, {}});
  drop_msg(c);
  if (c->res != nullptr && c->res->mrb != nullptr && !mrb_nil_p(c->self)) {
    mrb_gc_unregister(c->res->mrb, c->self);
    c->self = mrb_nil_value();
  }
  delete c->codec;
  delete c;
}

// RFC 6455 5.3: wire bytes for an upgraded connection, under protection.
bool ws_feed(WsConn* c, std::string_view in, std::string& sink) {
  const char* const data = in.data();
  const size_t len = in.size();
  if (len == 0) return true;
  mrb_state* mrb = c->res->mrb;
  FeedCall call{c, data, len, &sink};
  mrb_bool raised = FALSE;
  const mrb_value r = mrb_protect_error(mrb, feed_body, &call, &raised);
  if (raised) {
    // Only an exception object may be stored in mrb->exc; mrb_obj_ptr on
    // an immediate (Integer, Symbol, nil) would read its bits as a
    // pointer. Same check as resource.cpp's take_pending.
    if (mrb_exception_p(r)) mrb->exc = mrb_obj_ptr(r);
    else mrb->exc = mrb_obj_ptr(mrb_exc_new_lit(mrb, E_WM_ERROR(mrb),
                                                "the websocket handler ended without an "
                                                "exception object"));
    if (c->elog != nullptr) log_raise(*c->elog, mrb, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    return fail(c, sink, ws::kCloseInternalError);
  }
  return mrb_test(r);
}
}
