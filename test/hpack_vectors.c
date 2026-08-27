/*
 * Test-only Ruby surface over ls-hpack, compiled into mrbtest and
 * nothing else (mruby builds test/*.c of a gem only for its test
 * binary). The product has no Ruby-visible HPACK on purpose; this
 * exists so test/hpack.rb can drive the vendored codec against the
 * RFC 7541 vectors byte for byte.
 *
 * Two entry points, both taking blocks so the DYNAMIC table is what is
 * actually under test - one codec instance across all blocks, the way
 * one h2 connection uses it:
 *
 *   HPackVectors.decode_blocks([bin, ...], max_capacity = 0)
 *     -> [[[name, value], ...], ...]
 *   HPackVectors.roundtrip_blocks([[[name, value], ...], ...], cap = 0)
 *     -> same shape back, having gone through encode THEN decode
 */
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/string.h>

#include <string.h>

#include "lshpack.h"

/* Fits every RFC vector and every synthetic case in test/hpack.rb; a
 * header that does not fit is a failed decode, reported, not overrun -
 * lshpack_dec_decode is handed exactly this capacity. */
enum { kHdrBuf = 4096, kEncBuf = 8192 };

static mrb_value
decode_blocks(mrb_state *mrb, mrb_value self)
{
  mrb_value blocks;
  mrb_int cap = 0;
  mrb_get_args(mrb, "A|i", &blocks, &cap);

  struct lshpack_dec dec;
  lshpack_dec_init(&dec);
  if (cap > 0) lshpack_dec_set_max_capacity(&dec, (unsigned)cap);

  mrb_value out = mrb_ary_new_capa(mrb, RARRAY_LEN(blocks));
  for (mrb_int i = 0; i < RARRAY_LEN(blocks); i++) {
    mrb_value blk = mrb_ary_ref(mrb, blocks, i);
    if (!mrb_string_p(blk)) {
      lshpack_dec_cleanup(&dec);
      mrb_raise(mrb, E_TYPE_ERROR, "block must be a String");
    }
    const unsigned char *p = (const unsigned char *)RSTRING_PTR(blk);
    const unsigned char *end = p + RSTRING_LEN(blk);
    mrb_value hdrs = mrb_ary_new(mrb);
    while (p < end) {
      char buf[kHdrBuf];
      lsxpack_header_t xh;
      lsxpack_header_prepare_decode(&xh, buf, 0, sizeof(buf));
      if (lshpack_dec_decode(&dec, &p, end, &xh) != 0) {
        lshpack_dec_cleanup(&dec);
        mrb_raise(mrb, E_RUNTIME_ERROR, "hpack decode failed");
      }
      mrb_value pair = mrb_ary_new_capa(mrb, 2);
      mrb_ary_push(mrb, pair,
                   mrb_str_new(mrb, lsxpack_header_get_name(&xh), xh.name_len));
      mrb_ary_push(mrb, pair,
                   mrb_str_new(mrb, lsxpack_header_get_value(&xh), xh.val_len));
      mrb_ary_push(mrb, hdrs, pair);
    }
    mrb_ary_push(mrb, out, hdrs);
  }
  lshpack_dec_cleanup(&dec);
  return out;
}

static mrb_value
roundtrip_blocks(mrb_state *mrb, mrb_value self)
{
  mrb_value blocks;
  mrb_int cap = 0;
  mrb_get_args(mrb, "A|i", &blocks, &cap);

  struct lshpack_enc enc;
  struct lshpack_dec dec;
  lshpack_enc_init(&enc);
  lshpack_dec_init(&dec);
  if (cap > 0) {
    lshpack_enc_set_max_capacity(&enc, (unsigned)cap);
    lshpack_dec_set_max_capacity(&dec, (unsigned)cap);
  }

  mrb_value out = mrb_ary_new_capa(mrb, RARRAY_LEN(blocks));
  for (mrb_int i = 0; i < RARRAY_LEN(blocks); i++) {
    mrb_value pairs = mrb_ary_ref(mrb, blocks, i);

    unsigned char ebuf[kEncBuf];
    unsigned char *ep = ebuf;
    for (mrb_int j = 0; j < RARRAY_LEN(pairs); j++) {
      mrb_value pair = mrb_ary_ref(mrb, pairs, j);
      mrb_value n = mrb_ary_ref(mrb, pair, 0);
      mrb_value v = mrb_ary_ref(mrb, pair, 1);
      const size_t nl = (size_t)RSTRING_LEN(n);
      const size_t vl = (size_t)RSTRING_LEN(v);
      /* lsxpack's canonical layout: name ": " value in one buffer. The
       * ": " is what LSHPACK_DEC_HTTP1X_OUTPUT builds expect between the
       * offsets, so it is kept even though this build does not set it. */
      char hbuf[kHdrBuf];
      if (nl + 2 + vl > sizeof(hbuf)) {
        lshpack_enc_cleanup(&enc);
        lshpack_dec_cleanup(&dec);
        mrb_raise(mrb, E_ARGUMENT_ERROR, "header too large for test buffer");
      }
      memcpy(hbuf, RSTRING_PTR(n), nl);
      hbuf[nl] = ':';
      hbuf[nl + 1] = ' ';
      memcpy(hbuf + nl + 2, RSTRING_PTR(v), vl);
      lsxpack_header_t xh;
      lsxpack_header_set_offset2(&xh, hbuf, 0, nl, nl + 2, vl);
      unsigned char *np = lshpack_enc_encode(&enc, ep, ebuf + sizeof(ebuf), &xh);
      if (np == ep) {
        lshpack_enc_cleanup(&enc);
        lshpack_dec_cleanup(&dec);
        mrb_raise(mrb, E_RUNTIME_ERROR, "hpack encode failed");
      }
      ep = np;
    }

    const unsigned char *p = ebuf;
    const unsigned char *end = ep;
    mrb_value hdrs = mrb_ary_new(mrb);
    while (p < end) {
      char buf[kHdrBuf];
      lsxpack_header_t xh;
      lsxpack_header_prepare_decode(&xh, buf, 0, sizeof(buf));
      if (lshpack_dec_decode(&dec, &p, end, &xh) != 0) {
        lshpack_enc_cleanup(&enc);
        lshpack_dec_cleanup(&dec);
        mrb_raise(mrb, E_RUNTIME_ERROR, "hpack roundtrip decode failed");
      }
      mrb_value pair = mrb_ary_new_capa(mrb, 2);
      mrb_ary_push(mrb, pair,
                   mrb_str_new(mrb, lsxpack_header_get_name(&xh), xh.name_len));
      mrb_ary_push(mrb, pair,
                   mrb_str_new(mrb, lsxpack_header_get_value(&xh), xh.val_len));
      mrb_ary_push(mrb, hdrs, pair);
    }
    mrb_ary_push(mrb, out, hdrs);
  }
  lshpack_enc_cleanup(&enc);
  lshpack_dec_cleanup(&dec);
  return out;
}

/* test/flow_vectors.cpp and friends - the gem gets ONE
 * gem_test entry point, so the other test surfaces are registered from
 * here rather than each growing one. */
void mrb_webmachine_flow_vectors_init(mrb_state *mrb);
void mrb_webmachine_ws_vectors_init(mrb_state *mrb);
void mrb_webmachine_wm_ruby_init(mrb_state *mrb);
void mrb_webmachine_file_vectors_init(mrb_state *mrb);
void mrb_webmachine_asset_vectors_init(mrb_state *mrb);
void mrb_webmachine_h2_vectors_init(mrb_state *mrb);

void
mrb_webmachine_mruby_gem_test(mrb_state *mrb)
{
  mrb_webmachine_flow_vectors_init(mrb);
  mrb_webmachine_ws_vectors_init(mrb);
  mrb_webmachine_wm_ruby_init(mrb);
  mrb_webmachine_file_vectors_init(mrb);
  mrb_webmachine_asset_vectors_init(mrb);
  mrb_webmachine_h2_vectors_init(mrb);

  struct RClass *m = mrb_define_module(mrb, "HPackVectors");
  mrb_define_module_function(mrb, m, "decode_blocks", decode_blocks,
                             MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_module_function(mrb, m, "roundtrip_blocks", roundtrip_blocks,
                             MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
}
