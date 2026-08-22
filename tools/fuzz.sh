#!/bin/bash
# The framers under libFuzzer + ASan + UBSan (#88).
#
#   tools/fuzz.sh ws [seconds]      the websocket framing alone
#   tools/fuzz.sh feed [seconds]    h1 heads and h2 frames through Http1::feed
#
# clang, not the tree's gcc: libFuzzer is clang's. The targets INCLUDE
# the sources they test (see their heads) so ASan instruments them,
# and link libmruby.a for everything else - its members are not pulled
# for symbols the target already defines.
set -eu
cd "$(dirname "$0")/.."

TARGET="${1:-ws}"
SECONDS_TO_RUN="${2:-60}"
LIBMRUBY=mruby/build/host/lib/libmruby.a
[ -f "$LIBMRUBY" ] || { echo "$LIBMRUBY missing - run: rake compile" >&2; exit 1; }
command -v clang++ >/dev/null || { echo 'clang++ not found (libFuzzer is clang only)' >&2; exit 1; }

OUT=build/fuzz
mkdir -p "$OUT/corpus-$TARGET"

# -fno-sanitize=alignment: ls-hpack and phr read unaligned on purpose,
# and they are not what this run is about.
clang++ -g -O1 -std=c++20 \
  -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
  -fno-sanitize=alignment \
  -Imruby/include -Imruby/build/host/include \
  -Imruby/build/repos/host/mruby-phr/deps/picohttpparser \
  -Ideps/ls-hpack -Imruby/build/repos/host/mruby-string-is-utf8/include \
  "test/fuzz/${TARGET}_fuzz.cpp" "$LIBMRUBY" \
  mruby/build/host/mrbgems/mruby-io-uring/build/lib/liburing.a \
  -lz -lcrypto -lpthread -lm -o "$OUT/$TARGET"

"$OUT/$TARGET" "$OUT/corpus-$TARGET" \
  -max_total_time="$SECONDS_TO_RUN" -print_final_stats=1 -rss_limit_mb=4096
