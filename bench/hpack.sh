#!/bin/bash
# ls-hpack (the product's HPACK codec) against nghttp2's, head to head,
# on exactly the two calls src/http2.cpp actually makes per request -
# see bench/hpack/hpack_bench.cpp's header comment for why those two
# and not a generic "encode everything" scenario.
#
# nghttp2 is fetched here ONLY as a comparison codec (lib/nghttp2_hd.c
# and its small dependency closure - no session/stream/frame code, no
# public API surface used beyond nghttp2_nv). The framework around it
# was already ruled out for the product (own frame/stream layer, own
# HPACK vendoring via ls-hpack) - this script does not change that,
# it only answers "is ls-hpack actually the fast choice."
#
#   bench/hpack.sh            # run, append results to bench/results/<host>.log
set -eu
cd "$(dirname "$0")/.."

NGHTTP2_TAG=v1.66.0
NGHTTP2_DIR=bench/hpack/nghttp2
CASHPACK_TAG=cashpack-0.5
CASHPACK_DIR=bench/hpack/cashpack
LSHPACK=deps/ls-hpack
XXHASH=$LSHPACK/deps/xxhash

if [ ! -d "$NGHTTP2_DIR" ]; then
  git clone --depth 1 --branch "$NGHTTP2_TAG" \
    https://github.com/nghttp2/nghttp2.git "$NGHTTP2_DIR"
fi
# git.sr.ht (SourceHut) - not GitHub, the third comparison codec. C,
# no external deps for the codec itself (autotools/go/xxd are its OWN
# test-suite tooling, not needed for lib/ - skipped below on purpose).
if [ ! -d "$CASHPACK_DIR" ]; then
  git clone --depth 1 --branch "$CASHPACK_TAG" \
    https://git.sr.ht/~dridi/cashpack "$CASHPACK_DIR"
fi
# inc/hpack.h.in's only @substitution@ is a copyright-year comment;
# the enum bodies are '#define HPR(...) ... \n #include "tbl/hpack_tbl.h"'
# - valid, portable C preprocessor as they stand, no config.status
# text-mangling needed EXCEPT one thing config.status does do: strip
# the two "REMOVE_ME" guard-comment lines around HPACK_STATIC/
# HPACK_OVERHEAD, uncommenting those two #defines (lib/hpack.c needs
# them; verified against config.status's real output before landing
# on this sed). gen/*.c are small generator PROGRAMS (not headers) -
# compiled and RUN once to produce the three headers Makefile.am
# lists as BUILT_SOURCES.
CP_INC="$CASHPACK_DIR/inc"
CP_GEN="$CASHPACK_DIR/gen"
[ -f "$CP_INC/hpack.h" ] || sed '/REMOVE_ME/d' "$CP_INC/hpack.h.in" > "$CP_INC/hpack.h"
for g in hpack_huf_dec hpack_huf_enc hpack_static_hdr; do
  [ -f "$CP_GEN/$g.h" ] && continue
  gcc -O2 -I"$CP_INC" -o "$CP_GEN/$g.gen" "$CP_GEN/$g.c"
  "$CP_GEN/$g.gen" > "$CP_GEN/$g.h"
done
# nghttp2ver.h is normally cmake-generated from nghttp2ver.h.in; hand-write
# it rather than run cmake for a header this codec barely uses (version
# string/number, no build-time feature detection needed by nghttp2_hd.c).
VERH="$NGHTTP2_DIR/lib/includes/nghttp2/nghttp2ver.h"
[ -f "$VERH" ] || cat > "$VERH" <<EOF
#ifndef NGHTTP2VER_H
#define NGHTTP2VER_H
#define NGHTTP2_VERSION "$NGHTTP2_TAG"
#define NGHTTP2_VERSION_NUM 0x014200
#endif
EOF

# Reuse vm.sh's google/benchmark checkout rather than cloning a second
# copy of the same ~100MB repo for a second bench script.
GB_TAG=v1.9.5
GB_DIR=bench/vm/benchmark
if [ ! -d "$GB_DIR" ]; then
  git clone --depth 1 --branch "$GB_TAG" https://github.com/google/benchmark.git "$GB_DIR"
fi
if [ ! -f "$GB_DIR/build/src/libbenchmark.a" ]; then
  cmake -S "$GB_DIR" -B "$GB_DIR/build" -DCMAKE_BUILD_TYPE=Release \
    -DBENCHMARK_ENABLE_TESTING=OFF -DBENCHMARK_ENABLE_GTEST_TESTS=OFF \
    -DBENCHMARK_INSTALL_DOCS=OFF >/dev/null
  cmake --build "$GB_DIR/build" -j"$(nproc)" >/dev/null
fi

BIN=bench/hpack/hpack_bench
NG_LIB=$NGHTTP2_DIR/lib
CP_LIB=$CASHPACK_DIR/lib
OBJDIR=bench/hpack/obj
if [ ! -x "$BIN" ] || [ bench/hpack/hpack_bench.cpp -nt "$BIN" ]; then
  mkdir -p "$OBJDIR"
  # The vendored codecs are C, not C++ - g++ on a .c file compiles it as
  # C++ and rejects the void*-to-T* conversions their own headers rely
  # on (legal C, not C++). One C compile stage, one C++ link stage -
  # same split the product's own mrbgem.rake makes for lshpack.c.
  cflags=(-O3 -march=native -DXXH_HEADER_NAME='"xxhash.h"' -I"$LSHPACK" -I"$XXHASH" \
    -I"$NG_LIB/includes" -I"$NG_LIB" -include arpa/inet.h \
    -I"$CP_INC" -I"$CP_GEN")
  cobjs=()
  for f in "$LSHPACK/lshpack.c" "$XXHASH/xxhash.c" \
           "$NG_LIB/nghttp2_hd.c" "$NG_LIB/nghttp2_hd_huffman.c" \
           "$NG_LIB/nghttp2_hd_huffman_data.c" "$NG_LIB/nghttp2_helper.c" \
           "$NG_LIB/nghttp2_buf.c" "$NG_LIB/nghttp2_mem.c" "$NG_LIB/nghttp2_rcbuf.c" \
           "$NG_LIB/nghttp2_debug.c" \
           "$CP_LIB/hpack.c" "$CP_LIB/hpack_dec.c" "$CP_LIB/hpack_huf.c" \
           "$CP_LIB/hpack_tbl.c" "$CP_LIB/hpack_val.c" "$CP_LIB/hpack_ctx.c" \
           "$CP_LIB/hpack_enc.c" "$CP_LIB/hpack_int.c"; do
    o="$OBJDIR/$(basename "$f").o"
    gcc -c -std=c11 "${cflags[@]}" "$f" -o "$o"
    cobjs+=("$o")
  done
  g++ -O3 -march=native -std=c++20 \
    -I"$LSHPACK" -I"$NG_LIB/includes" -I"$NG_LIB" -I"$CP_INC" -I"$GB_DIR/include" \
    bench/hpack/hpack_bench.cpp "${cobjs[@]}" \
    "$GB_DIR/build/src/libbenchmark.a" \
    -lpthread -o "$BIN"
fi

RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV ===="
  echo "harness: hpack_bench google-benchmark $GB_TAG ls-hpack vs nghttp2 $NGHTTP2_TAG vs cashpack $CASHPACK_TAG $(uname -mr)"
  "$BIN" --benchmark_min_time=2s 2>/dev/null | grep -E "^BM_"
} | tee -a "$RESULTS"
