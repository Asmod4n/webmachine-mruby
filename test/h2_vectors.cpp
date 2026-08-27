/*
 * Test-only surface over Http1::h2_send_step - RFC 9113 6.9.1, the two
 * windows that decide how much of one stream's body may go out this
 * round. Same shape as the other *_vectors files; src/ carries no test
 * code.
 *
 * This was the same twenty lines three times over, once per source, each
 * computing the budget again in the middle of writing frames. The
 * arithmetic is now one function, and these are the cases that used to
 * need a real h2 peer with a real flow-control window:
 *
 *   - a shut window sends nothing, and does NOT fall through to another
 *     source;
 *   - whichever window is smaller is the one that binds;
 *   - END_STREAM rides the round that reaches the last byte, and only it;
 *   - a copied buffer is bounded per round, a lend and a mapping are not.
 *
 *   H2Vectors.step(kind, start, total, stream_window, conn_window, chunk)
 *     -> [src, start, give, total, ends]
 */
#include <mruby.h>
#include <mruby/array.h>

#include "../src/webmachine.hpp"

namespace {

using webmachine::AssetEntry;
using webmachine::H2Stream;
using webmachine::Http1;

mrb_value step(mrb_state* mrb, mrb_value)
{
  mrb_int kind = 0, start = 0, total = 0, swin = 0, cwin = 0, chunk = 0;
  mrb_get_args(mrb, "iiiiii", &kind, &start, &total, &swin, &cwin, &chunk);
  if (start < 0 || total < 0 || chunk < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "no negatives");

  static AssetEntry fake;  // only its ADDRESS is read; h2_send_step never
                           // dereferences the source it names.
  static std::string body;
  H2Stream s;
  s.id = 1;
  s.send_window = static_cast<int64_t>(swin);
  switch (kind) {
    case 1:
      s.src = &fake;
      s.src_off = static_cast<size_t>(start);
      s.src_len = static_cast<size_t>(total);
      break;
    case 2:
      s.zc_have = true;
      s.zc_off = static_cast<size_t>(start);
      s.zc_len = static_cast<size_t>(total);
      break;
    case 3:
      body.assign(static_cast<size_t>(total), 'x');
      s.pending = body;
      break;
    default:
      break;
  }

  const Http1::H2SendStep o =
      Http1::h2_send_step(s, static_cast<int64_t>(cwin), static_cast<size_t>(chunk));
  mrb_value out = mrb_ary_new_capa(mrb, 5);
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(o.src)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(o.start)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(o.give)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(o.total)));
  mrb_ary_push(mrb, out, mrb_bool_value(o.ends));
  return out;
}

}  // namespace

extern "C" void
mrb_webmachine_h2_vectors_init(mrb_state* mrb)
{
  struct RClass* m = mrb_define_module(mrb, "H2Vectors");
  mrb_define_module_function(mrb, m, "step", step, MRB_ARGS_REQ(6));
  mrb_define_const(mrb, m, "NONE", mrb_int_value(mrb, 0));
  mrb_define_const(mrb, m, "ASSET", mrb_int_value(mrb, 1));
  mrb_define_const(mrb, m, "LENT", mrb_int_value(mrb, 2));
  mrb_define_const(mrb, m, "PENDING", mrb_int_value(mrb, 3));
  mrb_define_const(mrb, m, "CHUNK",
                   mrb_int_value(mrb, static_cast<mrb_int>(webmachine::kDeliverChunk)));
}
