#!/bin/bash
# What a value costs when it crosses a thread, and what a completion
# costs when it does not (bench/switch/switch.cpp).
#
# Three arms in one run:
#   futex   a handover that blocks - a real context switch each way
#   spin    the same handover without blocking - one cache line moving
#   ring    io_uring_for_each_cqe while multishot accept and multishot
#           recv are both delivering - shared memory, no syscall
#
# Knobs: RUNS (default 5), DURATION (seconds per arm, default 2),
# PEERS (default 24), LOADERS (load threads, default 3).
#
# This probe links the distribution's liburing, not the one the server
# carries: slipstreamIO's copy calls its own mmap and close wrappers and
# does not link on its own. The ring's setup flags are the reactor's
# (src/ring.hpp), so the submission model is the server's even where the
# library build is not.
#
# The run needs one cpu for the harvester and LOADERS for the load, so a
# four-cpu host is full at LOADERS=3. The rows say what the host was.
set -eu
cd "$(dirname "$0")/.."

RUNS="${RUNS:-5}"
DURATION="${DURATION:-2}"
PEERS="${PEERS:-24}"
LOADERS="${LOADERS:-3}"
BIN=bench/switch/switch_bench

# aarch64 GCC takes -mcpu=native, not -march=native.
case "$(uname -m)" in
  aarch64 | arm64) TUNE=-mcpu=native ;;
  *) TUNE=-march=native ;;
esac

if [ ! -x "$BIN" ] || [ bench/switch/switch.cpp -nt "$BIN" ]; then
  g++ -O2 "$TUNE" -std=c++20 bench/switch/switch.cpp -luring -o "$BIN"
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

LOG="bench/results/$(hostname).log"
mkdir -p bench/results
# shellcheck source=bench/buildline.sh
. bench/buildline.sh
{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) ===="
  echo "harness: switch_bench runs=$RUNS d=${DURATION}s peers=$PEERS loaders=$LOADERS liburing=$(pkg-config --modversion liburing 2>/dev/null || echo '?') cflags=-O2 $TUNE $(uname -mr)"
  wm_build_line "$BIN"
  for i in $(seq "$RUNS"); do
    echo "-- run $i --"
    "$BIN" --seconds "$DURATION" --peers "$PEERS" --loaders "$LOADERS" \
      --sock "$WORK/switch.sock"
  done
} | tee -a "$LOG"
