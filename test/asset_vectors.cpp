/*
 * Test-only surface over Http1::asset_step - the asset tier's decision for
 * ONE request: which head, which byte range, copy or stream. Same shape as
 * test/flow_vectors.cpp and test/file_vectors.cpp; src/ carries no test
 * code.
 *
 * The range rules (RFC 9110 14.1/14.2) are exactly the kind of thing that
 * used to be checkable only by holding a socket open: a Range on a HEAD, a
 * Range on a 304, an If-Range that no longer matches, a first-byte past
 * the end. Here each is one line.
 *
 *   AssetVectors.step(wire_len, verdict, head_only, method, range,
 *                     if_range, etag, warm_budget)
 *     -> [head, status, off, len, body, copy]
 */
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/string.h>

#include "../src/webmachine.hpp"

namespace {

using webmachine::AssetEntry;
using webmachine::Http1;
using webmachine::flow::Method;

mrb_value step(mrb_state* mrb, mrb_value)
{
  mrb_int wire = 0, verdict = 0, head_only = 0, method = 0, budget = 0;
  const char* range = nullptr;
  mrb_int range_len = 0;
  const char* ifr = nullptr;
  mrb_int ifr_len = 0;
  const char* etag = nullptr;
  mrb_int etag_len = 0;
  mrb_get_args(mrb, "iiiiss!si", &wire, &verdict, &head_only, &method, &range, &range_len,
               &ifr, &ifr_len, &etag, &etag_len, &budget);
  if (wire < 0 || budget < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "wire and budget >= 0");

  AssetEntry e;
  e.deflated = false;
  e.comp_size = static_cast<size_t>(wire);
  e.uncomp_size = static_cast<size_t>(wire);
  for (mrb_int i = 0; i < etag_len && i < static_cast<mrb_int>(sizeof(e.etag)); i++) {
    e.etag[i] = etag[i];
  }

  webmachine::http::ReqValues vals;
  if (range_len > 0) {
    vals.range = range;
    vals.range_len = static_cast<size_t>(range_len);
  }
  if (ifr != nullptr && ifr_len > 0) {
    vals.if_range = ifr;
    vals.if_range_len = static_cast<size_t>(ifr_len);
  }

  const Http1::AssetStep s =
      Http1::asset_step(e, static_cast<uint16_t>(verdict), head_only != 0,
                        static_cast<Method>(method), vals, static_cast<size_t>(budget));

  mrb_value out = mrb_ary_new_capa(mrb, 6);
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(s.head)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, s.status));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(s.off)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(s.len)));
  mrb_ary_push(mrb, out, mrb_bool_value(s.body));
  mrb_ary_push(mrb, out, mrb_bool_value(s.copy));
  return out;
}

}  // namespace

extern "C" void
mrb_webmachine_asset_vectors_init(mrb_state* mrb)
{
  struct RClass* m = mrb_define_module(mrb, "AssetVectors");
  mrb_define_module_function(mrb, m, "step", step, MRB_ARGS_REQ(8));
  mrb_define_const(mrb, m, "REFUSAL", mrb_int_value(mrb, 0));
  mrb_define_const(mrb, m, "NORMAL", mrb_int_value(mrb, 1));
  mrb_define_const(mrb, m, "RANGE", mrb_int_value(mrb, 2));
  mrb_define_const(mrb, m, "UNSAT", mrb_int_value(mrb, 3));
  mrb_define_const(mrb, m, "GET", mrb_int_value(mrb, static_cast<mrb_int>(Method::kGet)));
  mrb_define_const(mrb, m, "HEAD", mrb_int_value(mrb, static_cast<mrb_int>(Method::kHead)));
  mrb_define_const(mrb, m, "POST", mrb_int_value(mrb, static_cast<mrb_int>(Method::kPost)));
}
