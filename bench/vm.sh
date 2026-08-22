#!/bin/bash
# The VM copy floor, measured with Google Benchmark (Gebot 9: consistent
# numbers, one tool). Builds everything it needs on first run: clones
# google/benchmark at a pinned tag, cmakes it once, compiles vm_floor
# against the libmruby.a the normal build produced.
#
#   bench/vm.sh              # run, append results to bench/results/<host>.log
set -eu
cd "$(dirname "$0")/.."

GB_TAG=v1.9.5
GB_DIR=bench/vm/benchmark
LIBMRUBY=mruby/build/host/lib/libmruby.a
[ -f "$LIBMRUBY" ] || { echo "$LIBMRUBY missing - run: rake compile" >&2; exit 1; }

if [ ! -d "$GB_DIR" ]; then
  git clone --depth 1 --branch "$GB_TAG" https://github.com/google/benchmark.git "$GB_DIR"
fi
if [ ! -f "$GB_DIR/build/src/libbenchmark.a" ]; then
  cmake -S "$GB_DIR" -B "$GB_DIR/build" -DCMAKE_BUILD_TYPE=Release \
    -DBENCHMARK_ENABLE_TESTING=OFF -DBENCHMARK_ENABLE_GTEST_TESTS=OFF \
    -DBENCHMARK_INSTALL_DOCS=OFF >/dev/null
  cmake --build "$GB_DIR/build" -j"$(nproc)" >/dev/null
fi

# The Ruby half is BYTECODE (#100), compiled with the mrbc this build
# produced - the same rule the server follows for its apps.
MRBC="${MRBC:-mruby/bin/mrbc}"
[ -x "$MRBC" ] || { echo "$MRBC missing - run: rake compile" >&2; exit 1; }
for rb in bench/vm/handlers.rb bench/vm/bench_counter.rb bench/vm/bench_multi.rb; do
  [ "${rb%.rb}.mrb" -nt "$rb" ] || "$MRBC" -o "${rb%.rb}.mrb" "$rb"
done

BIN=bench/vm/vm_floor
if [ ! -x "$BIN" ] || [ bench/vm/vm_floor.cpp -nt "$BIN" ]; then
  # liburing.a: libmruby.a carries mruby-io-uring's objects but not the
  # vendored liburing they call into.
  g++ -O2 -g -std=c++20 \
    -Imruby/include -Imruby/build/host/include -I"$GB_DIR/include" \
    bench/vm/vm_floor.cpp "$LIBMRUBY" \
    mruby/build/host/mrbgems/mruby-io-uring/build/lib/liburing.a \
    "$GB_DIR/build/src/libbenchmark.a" \
    -lpthread -lm -lz -lcrypto -o "$BIN"
fi

# Results outlive the terminal, written by the machine that measured.
RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
MRUBY_REV=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?')
{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV mruby=$MRUBY_REV ===="
  echo "harness: vm_floor google-benchmark $GB_TAG $(uname -mr)"
  "$BIN" --benchmark_min_time=2s 2>/dev/null | grep -E "^BM_"
} | tee -a "$RESULTS"
