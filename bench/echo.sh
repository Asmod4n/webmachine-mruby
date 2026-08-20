#!/bin/bash
# The ring against plain recv/send, nothing else in the picture: one
# unix socket, one connection, ping-pong echo (bench/echo/echo.cpp).
# Three pairings per size - sys/sys is the syscall floor, uring/uring
# prices the ring on both ends, sys-client/uring-server isolates the
# server side, which is the seat our reactor sits in.
#
# Knobs: DURATION (seconds per cell, default 5), SIZES (default
# "16 16384"). Appends to bench/results/$(hostname).log; failed runs
# write nothing.
set -eu
cd "$(dirname "$0")/.."

DURATION="${DURATION:-5}"
SIZES="${SIZES:-16 16384}"
BIN=bench/echo/echo_bench
LIBURING=mruby/build/host/mrbgems/mruby-io-uring/build/lib/liburing.a
URING_INC=mruby/build/repos/host/mruby-io_uring/include
[ -f "$LIBURING" ] || { echo "$LIBURING missing - run: rake compile" >&2; exit 1; }

if [ ! -x "$BIN" ] || [ bench/echo/echo.cpp -nt "$BIN" ]; then
  g++ -O3 -march=native -std=c++20 -I"$URING_INC" \
    bench/echo/echo.cpp "$LIBURING" -o "$BIN"
fi

SOCK=/tmp/wm-echo-bench.sock
CFLAGS_LINE='-O3 -march=native'

cell() {  # cell <server-mode> <client-mode> <size>
  rm -f "$SOCK"
  "$BIN" --server "$1" --sock "$SOCK" &
  local srv=$!
  for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
  printf '%s-server / %s-client:  ' "$1" "$2"
  "$BIN" --client "$2" --sock "$SOCK" --size "$3" --seconds "$DURATION"
  wait "$srv" 2>/dev/null || true
}

LOG="bench/results/$(hostname).log"
mkdir -p bench/results
{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: echo unix ping-pong d=${DURATION}s flags=SINGLE_ISSUER|DEFER_TASKRUN|COOP_TASKRUN cflags=$CFLAGS_LINE $(uname -mr)"
  for size in $SIZES; do
    echo "-- size $size --"
    cell sys sys "$size"
    cell uring uring "$size"
    cell uring sys "$size"
    cell uring-ms sys "$size"
  done
} | tee -a "$LOG"
