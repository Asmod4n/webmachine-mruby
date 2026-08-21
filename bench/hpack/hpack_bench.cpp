// ls-hpack vs. nghttp2's HPACK codec (nghttp2_hd.c, vendored standalone
// by bench/hpack.sh - the framework it ships in was ruled out for the
// product; the codec is fetched here ONLY as a comparison point, never
// linked into webmachine-mruby itself).
//
// Measures exactly the two calls this server actually makes per h2
// request/response (src/http2.cpp), not a generic "encode everything"
// scenario - the two-lane redesign (3729394) already moved everything
// except the date field to precomputed blocks:
//
//   decode: h2_dispatch decodes the CLIENT's request headers every
//           request - RFC 7541 C.3.1's four pseudo-headers, the shape
//           h2load -m1 actually sends (same request, every time).
//   encode: h2_enc_field encodes ONE field per response - the date,
//           through the SAME connection's dynamic table every time
//           (h2.hpp's own comment: 37 bytes first hit, 14 bytes
//           steady-state 1-byte reference after).
//
// One encoder/decoder instance reused across all iterations in each
// benchmark, like hpack_vectors.c's own convention: "one codec
// instance across all blocks, the way one h2 connection uses it."
#include <benchmark/benchmark.h>

#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <vector>

extern "C" {
#include "lshpack.h"
#include "nghttp2_hd.h"
#include "hpack.h"  // cashpack (git.sr.ht/~dridi/cashpack) - stateless,
                     // event-driven, aimed at memory-constrained systems;
                     // the third comparison codec, hosted off GitHub.
}

namespace {

struct Header {
  const char* name;
  const char* value;
};

// RFC 7541 C.3.1's first request, the h2load -m1 shape: identical
// headers on every request of a connection.
const Header kRequest[] = {
    {":method", "GET"},
    {":scheme", "http"},
    {":path", "/"},
    {":authority", "www.example.com"},
};
constexpr size_t kRequestLen = sizeof(kRequest) / sizeof(kRequest[0]);

// h2_enc_field's actual shape: name="date", a 29-byte IMF-fixdate.
const char kDateName[] = "date";
const char kDateValue[] = "Mon, 20 Aug 2026 18:27:00 GMT";

// One valid HPACK encoding of kRequest, built once via ls-hpack, fed
// to both decoders under test - decode correctness needs valid HPACK
// bytes, not bytes from the library being measured.
std::vector<unsigned char> EncodeRequestOnce() {
  struct lshpack_enc enc;
  lshpack_enc_init(&enc);
  unsigned char buf[512];
  unsigned char* ep = buf;
  for (size_t i = 0; i < kRequestLen; i++) {
    char hbuf[256];
    size_t nl = std::strlen(kRequest[i].name), vl = std::strlen(kRequest[i].value);
    std::memcpy(hbuf, kRequest[i].name, nl);
    hbuf[nl] = ':';
    hbuf[nl + 1] = ' ';
    std::memcpy(hbuf + nl + 2, kRequest[i].value, vl);
    lsxpack_header_t xh;
    lsxpack_header_set_offset2(&xh, hbuf, 0, nl, nl + 2, vl);
    ep = lshpack_enc_encode(&enc, ep, buf + sizeof(buf), &xh);
  }
  std::vector<unsigned char> out(buf, ep);
  lshpack_enc_cleanup(&enc);
  return out;
}

void BM_ls_hpack_decode_request(benchmark::State& state) {
  const std::vector<unsigned char> block = EncodeRequestOnce();
  struct lshpack_dec dec;
  lshpack_dec_init(&dec);
  for (auto _ : state) {
    const unsigned char* p = block.data();
    const unsigned char* end = p + block.size();
    while (p < end) {
      char buf[4096];
      lsxpack_header_t xh;
      lsxpack_header_prepare_decode(&xh, buf, 0, sizeof(buf));
      if (lshpack_dec_decode(&dec, &p, end, &xh) != 0) state.SkipWithError("decode failed");
      benchmark::DoNotOptimize(xh.name_len);
    }
  }
  lshpack_dec_cleanup(&dec);
}
BENCHMARK(BM_ls_hpack_decode_request);

void BM_nghttp2_decode_request(benchmark::State& state) {
  const std::vector<unsigned char> block = EncodeRequestOnce();
  nghttp2_hd_inflater infl;
  nghttp2_hd_inflate_init(&infl, nghttp2_mem_default());
  for (auto _ : state) {
    const uint8_t* p = block.data();
    size_t left = block.size();
    for (;;) {
      nghttp2_hd_nv nv_out;
      int flags = 0;
      nghttp2_ssize n = nghttp2_hd_inflate_hd_nv(&infl, &nv_out, &flags, p, left, 1);
      if (n < 0) { state.SkipWithError("decode failed"); break; }
      p += n;
      left -= static_cast<size_t>(n);
      benchmark::DoNotOptimize(nv_out.name);
      if (flags & NGHTTP2_HD_INFLATE_FINAL) break;
    }
  }
  nghttp2_hd_inflate_free(&infl);
}
BENCHMARK(BM_nghttp2_decode_request);

void BM_ls_hpack_encode_date(benchmark::State& state) {
  struct lshpack_enc enc;
  lshpack_enc_init(&enc);
  const size_t nl = std::strlen(kDateName), vl = std::strlen(kDateValue);
  for (auto _ : state) {
    char hbuf[64];
    std::memcpy(hbuf, kDateName, nl);
    hbuf[nl] = ':';
    hbuf[nl + 1] = ' ';
    std::memcpy(hbuf + nl + 2, kDateValue, vl);
    unsigned char out[128];
    lsxpack_header_t xh;
    lsxpack_header_set_offset2(&xh, hbuf, 0, nl, nl + 2, vl);
    unsigned char* np = lshpack_enc_encode(&enc, out, out + sizeof(out), &xh);
    if (np == out) state.SkipWithError("encode failed");
    benchmark::DoNotOptimize(np);
  }
  lshpack_enc_cleanup(&enc);
}
BENCHMARK(BM_ls_hpack_encode_date);

void BM_nghttp2_encode_date(benchmark::State& state) {
  nghttp2_hd_deflater defl;
  nghttp2_hd_deflate_init(&defl, nghttp2_mem_default());
  nghttp2_nv nv;
  nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(kDateName));
  nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(kDateValue));
  nv.namelen = std::strlen(kDateName);
  nv.valuelen = std::strlen(kDateValue);
  nv.flags = 0;
  for (auto _ : state) {
    nghttp2_bufs bufs;
    nghttp2_bufs_init(&bufs, 128, 1, nghttp2_mem_default());
    int rv = nghttp2_hd_deflate_hd_bufs(&defl, &bufs, &nv, 1);
    if (rv != 0) state.SkipWithError("encode failed");
    benchmark::DoNotOptimize(nghttp2_bufs_len(&bufs));
    nghttp2_bufs_free(&bufs);
  }
  nghttp2_hd_deflate_free(&defl);
}
BENCHMARK(BM_nghttp2_encode_date);

// cashpack's decode is event-driven too, but request headers ARE the
// static table here (fully HPACK_FLG_TYP_IDX except :authority) - no
// encode call is on this server's critical path for requests, so
// re-derive the block with cashpack's own encoder once, outside the
// timed loop, exactly like EncodeRequestOnce() does for ls-hpack.
void cashpack_noop_cb(enum hpack_event_e, const char*, size_t, void*) {}

std::vector<unsigned char> CashpackEncodeRequestOnce() {
  struct hpack* enc = hpack_encoder(4096, -1, hpack_default_alloc);
  struct hpack_field fld[4] = {};
  fld[0] = {.flg = HPACK_FLG_TYP_IDX, .idx = 2};   // :method GET
  fld[1] = {.flg = HPACK_FLG_TYP_IDX, .idx = 6};   // :scheme http
  fld[2] = {.flg = HPACK_FLG_TYP_IDX, .idx = 4};   // :path /
  fld[3] = {.flg = HPACK_FLG_TYP_LIT | HPACK_FLG_NAM_IDX, .nam_idx = 1,
            .val = "www.example.com"};             // :authority (name-idx 1)

  static unsigned char out[512];
  size_t outlen = 0;
  auto collect = +[](enum hpack_event_e evt, const char* buf, size_t len, void* priv) {
    if (evt == HPACK_EVT_DATA && buf != nullptr) {
      auto* n = static_cast<size_t*>(priv);
      std::memcpy(out + *n, buf, len);
      *n += len;
    }
  };
  unsigned char work[512];
  struct hpack_encoding henc = {.fld = fld, .fld_cnt = 4, .buf = work,
                                .buf_len = sizeof(work), .cb = collect, .priv = &outlen};
  hpack_encode(enc, &henc);
  hpack_free(&enc);
  return std::vector<unsigned char>(out, out + outlen);
}

void BM_cashpack_decode_request(benchmark::State& state) {
  const std::vector<unsigned char> block = CashpackEncodeRequestOnce();
  struct hpack* dec = hpack_decoder(4096, -1, hpack_default_alloc);
  for (auto _ : state) {
    char dbuf[4096];
    struct hpack_decoding hdec = {.blk = block.data(), .blk_len = block.size(),
                                  .buf = dbuf, .buf_len = sizeof(dbuf), .cb = cashpack_noop_cb};
    enum hpack_result_e rv = hpack_decode(dec, &hdec);
    if (rv != HPACK_RES_OK) state.SkipWithError("decode failed");
    benchmark::DoNotOptimize(rv);
  }
  hpack_free(&dec);
}
BENCHMARK(BM_cashpack_decode_request);

void BM_cashpack_encode_date(benchmark::State& state) {
  struct hpack* enc = hpack_encoder(4096, -1, hpack_default_alloc);
  for (auto _ : state) {
    // TYP_DYN (RFC 7541 "incremental indexing") + AUT_IDX: first call
    // inserts into the dynamic table, later calls with the same value
    // get promoted to a cheap TYP_IDX reference by hpack_auto_index -
    // the same steady-state shape ls-hpack/nghttp2 default to.
    struct hpack_field fld = {.flg = HPACK_FLG_TYP_DYN | HPACK_FLG_AUT_IDX,
                              .nam = kDateName, .val = kDateValue};
    unsigned char work[128];
    struct hpack_encoding henc = {.fld = &fld, .fld_cnt = 1, .buf = work,
                                  .buf_len = sizeof(work), .cb = cashpack_noop_cb};
    enum hpack_result_e rv = hpack_encode(enc, &henc);
    if (rv != HPACK_RES_OK) state.SkipWithError("encode failed");
    benchmark::DoNotOptimize(rv);
  }
  hpack_free(&enc);
}
BENCHMARK(BM_cashpack_encode_date);

}  // namespace

BENCHMARK_MAIN();
