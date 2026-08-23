/*
 * Test-only surface over src/websocket.hpp (#175 round one), compiled
 * into mrbtest and nothing else - src/ never carries test code, and
 * the product has no Ruby-visible framing on purpose. This drives the
 * protocol half from outside, the way test/flow_vectors.cpp drives the
 * walker, so RFC 6455's own examples can be checked byte for byte long
 * before a socket exists.
 *
 *   WsVectors.accept_key(key)               -> String or nil
 *   WsVectors.parse(bytes, max = 1<<20, rsv1 = false)
 *                                           -> [:ok, opcode, fin, payload, consumed, rsv1]
 *                                            | [:need_more]
 *                                            | [:error, close_code]
 *   WsVectors.header(opcode, fin, len, rsv1 = false) -> String (the header bytes)
 *   WsVectors.close_payload(code, reason)   -> String
 *   WsVectors.read_close(payload)           -> [code, reason] or nil
 *
 * Round two adds src/wsdeflate.hpp's negotiation, which is protocol
 * truth in exactly the same sense - a header value in, a header value
 * out, no socket and no zlib stream in sight:
 *
 *   WsVectors.negotiate(offer) -> nil (declined)
 *                               | [answer, snct, cnct, server_bits, client_bits]
 */
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/string.h>

#include <string>
#include <vector>

#include "../src/webmachine.hpp"


namespace {

mrb_value ws_negotiate(mrb_state* mrb, mrb_value) {
  const char* v;
  mrb_int n;
  mrb_get_args(mrb, "s", &v, &n);
  webmachine::wsdeflate::Params p;
  std::string answer;
  if (!webmachine::wsdeflate::negotiate(v, static_cast<size_t>(n), p, answer)) {
    return mrb_nil_value();
  }
  mrb_value a = mrb_ary_new(mrb);
  mrb_ary_push(mrb, a, mrb_str_new(mrb, answer.data(), answer.size()));
  mrb_ary_push(mrb, a, mrb_bool_value(p.server_no_context_takeover));
  mrb_ary_push(mrb, a, mrb_bool_value(p.client_no_context_takeover));
  mrb_ary_push(mrb, a, mrb_fixnum_value(p.server_max_window_bits));
  mrb_ary_push(mrb, a, mrb_fixnum_value(p.client_max_window_bits));
  return a;
}

mrb_value ws_accept_key(mrb_state* mrb, mrb_value) {
  const char* k;
  mrb_int n;
  mrb_get_args(mrb, "s", &k, &n);
  char out[28];
  if (!webmachine::ws::accept_key(k, static_cast<size_t>(n), out)) return mrb_nil_value();
  return mrb_str_new(mrb, out, sizeof(out));
}

mrb_value ws_parse(mrb_state* mrb, mrb_value) {
  const char* d;
  mrb_int n;
  mrb_int max = 1 << 20;
  mrb_bool rsv1 = FALSE;
  mrb_get_args(mrb, "s|ib", &d, &n, &max, &rsv1);
  // The parser unmasks IN PLACE, so it gets a copy of the Ruby bytes -
  // a String's buffer is not ours to rewrite.
  std::vector<char> buf(d, d + n);
  webmachine::ws::Frame f;
  uint16_t code = 0;
  const webmachine::ws::Parse r = webmachine::ws::parse(
      buf.empty() ? nullptr : buf.data(), static_cast<size_t>(n), static_cast<size_t>(max),
      rsv1 != 0, f, code);
  mrb_value a = mrb_ary_new(mrb);
  switch (r) {
    case webmachine::ws::Parse::kNeedMore:
      mrb_ary_push(mrb, a, mrb_symbol_value(mrb_intern_lit(mrb, "need_more")));
      break;
    case webmachine::ws::Parse::kError:
      mrb_ary_push(mrb, a, mrb_symbol_value(mrb_intern_lit(mrb, "error")));
      mrb_ary_push(mrb, a, mrb_fixnum_value(code));
      break;
    case webmachine::ws::Parse::kOk:
      mrb_ary_push(mrb, a, mrb_symbol_value(mrb_intern_lit(mrb, "ok")));
      mrb_ary_push(mrb, a, mrb_fixnum_value(f.opcode));
      mrb_ary_push(mrb, a, mrb_bool_value(f.fin));
      mrb_ary_push(mrb, a, mrb_str_new(mrb, f.payload, f.len));
      mrb_ary_push(mrb, a, mrb_fixnum_value(static_cast<mrb_int>(f.consumed)));
      // Appended, not inserted: round one's tests destructure this
      // array positionally and RSV1 is round two's news, not theirs.
      mrb_ary_push(mrb, a, mrb_bool_value(f.rsv1));
      break;
  }
  return a;
}

mrb_value ws_header(mrb_state* mrb, mrb_value) {
  mrb_int op, len;
  mrb_bool fin;
  mrb_bool rsv1 = FALSE;
  mrb_get_args(mrb, "ibi|b", &op, &fin, &len, &rsv1);
  char head[10];
  const size_t n = webmachine::ws::build_header(static_cast<uint8_t>(op), fin != 0, rsv1 != 0,
                                                static_cast<size_t>(len), head);
  return mrb_str_new(mrb, head, n);
}

mrb_value ws_close_payload(mrb_state* mrb, mrb_value) {
  mrb_int code;
  const char* r;
  mrb_int rn;
  mrb_get_args(mrb, "is", &code, &r, &rn);
  char out[125];
  const size_t n = webmachine::ws::build_close_payload(static_cast<uint16_t>(code), r,
                                                       static_cast<size_t>(rn), out);
  return mrb_str_new(mrb, out, n);
}

mrb_value ws_read_close(mrb_state* mrb, mrb_value) {
  const char* p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  uint16_t code = 0;
  const char* reason = nullptr;
  size_t rlen = 0;
  if (!webmachine::ws::read_close(p, static_cast<size_t>(n), code, &reason, &rlen)) {
    return mrb_nil_value();
  }
  mrb_value a = mrb_ary_new(mrb);
  mrb_ary_push(mrb, a, mrb_fixnum_value(code));
  mrb_ary_push(mrb, a, mrb_str_new(mrb, reason == nullptr ? "" : reason, rlen));
  return a;
}

}  // namespace

extern "C" void mrb_webmachine_ws_vectors_init(mrb_state* mrb);

void mrb_webmachine_ws_vectors_init(mrb_state* mrb) {
  struct RClass* m = mrb_define_module(mrb, "WsVectors");
  mrb_define_module_function(mrb, m, "accept_key", ws_accept_key, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, m, "parse", ws_parse, MRB_ARGS_ARG(1, 2));
  mrb_define_module_function(mrb, m, "header", ws_header, MRB_ARGS_ARG(3, 1));
  mrb_define_module_function(mrb, m, "negotiate", ws_negotiate, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, m, "close_payload", ws_close_payload, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, m, "read_close", ws_read_close, MRB_ARGS_REQ(1));
}
