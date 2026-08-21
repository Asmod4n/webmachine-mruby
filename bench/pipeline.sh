#!/bin/bash
# The pipelined h1 floor: what the framer costs when the per-round-trip
# price is amortized away. This is TechEmpower's "Plaintext" shape -
# DEPTH requests in one write, one batch of answers back - and it is
# explicitly NOT a shape any real user agent sends (RFC 9112 9.3 allows
# pipelining; browsers abandoned it over head-of-line blocking). It
# exists here for ONE reason: the -m1 numbers are round-trip bound
# (perf showed 25-34% of the profile in kernel scheduling/TCP), so this
# is the counter-measurement that shows what the SERVER costs per
# request once syscall and scheduling overhead are divided across
# DEPTH requests instead of paid per request.
#
# Read the number as "the framer's amortized cost", never as "our
# req/s" - the comparison it belongs to is TechEmpower's Plaintext
# column (Round 23: the top of that chart sits near 28M on their
# 40GbE multi-machine rig, h2o itself at 9.5M), not to bench/h2.sh's
# round-trip figures.
#
#   THREADS=4 CONNS=400 bench/pipeline.sh          # AF_UNIX (default)
#   THREADS=4 CONNS=400 DEPTH=32 bench/pipeline.sh
#   THREADS=4 CONNS=400 TRANSPORT=tcp bench/pipeline.sh
set -u
[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
DEPTH="${DEPTH:-16}"
TRANSPORT="${TRANSPORT:-unix}"
PORT="${PORT:-8123}"
PIN_SRV="${PIN_SRV:-}"
APP="${APP-examples/hello.rb}"
cd "$(dirname "$0")/.." || exit 1

BIN=mruby/build/host/bin/webmachine-server
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

WRK="${WRK:-$HOME/wrk/wrk}"
[ -x "$WRK" ] || WRK=$(command -v wrk) || { echo "wrk not found" >&2; exit 1; }
if [ "$TRANSPORT" = unix ] && ! grep -aq WRK_UNIX "$WRK"; then
  echo "$WRK is not the WRK_UNIX-patched build - apply bench/wrk-af-unix.patch (see its header)" >&2
  exit 1
fi

APP_ARGS=()
[ -n "$APP" ] && APP_ARGS=(--app "$APP")
SRV_WRAP=()
[ -n "$PIN_SRV" ] && SRV_WRAP=(taskset -c "$PIN_SRV")

SOCK=/tmp/wm-pipeline-bench.sock
DUMMY=""
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  "${SRV_WRAP[@]}" "$BIN" --unix "$SOCK" "${APP_ARGS[@]}" 2>/tmp/wm-pipeline-srv.log & SRV=$!
  # The patched wrk still probe-connects the TCP port to validate its
  # URL even when every byte rides WRK_UNIX (see floor.sh).
  python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$PORT)); s.listen(16)
while True:
    c,_=s.accept(); c.close()" >/dev/null 2>&1 & DUMMY=$!
else
  "${SRV_WRAP[@]}" "$BIN" --port "$PORT" "${APP_ARGS[@]}" 2>/tmp/wm-pipeline-srv.log & SRV=$!
fi
trap 'kill $SRV $DUMMY 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:"; cat /tmp/wm-pipeline-srv.log; exit 1; }

RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
MRUBY_REV=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?')
OUT=$(mktemp)
{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV mruby=$MRUBY_REV ===="
  echo "harness: wrk -t$THREADS -c$CONNS -d${DURATION}s PIPELINED depth=$DEPTH transport=$TRANSPORT app=${APP:-none} pin_srv=${PIN_SRV:-no} $(uname -mr)"
  if [ "$TRANSPORT" = unix ]; then
    WRK_UNIX="$SOCK" PIPELINE_DEPTH="$DEPTH" "$WRK" -t"$THREADS" -c"$CONNS" \
      -d"${DURATION}"s -s bench/pipeline.lua --latency \
      "http://127.0.0.1:$PORT/" | grep -E "Requests/sec|50%|99%"
  else
    PIPELINE_DEPTH="$DEPTH" "$WRK" -t"$THREADS" -c"$CONNS" \
      -d"${DURATION}"s -s bench/pipeline.lua --latency \
      "http://127.0.0.1:$PORT/" | grep -E "Requests/sec|50%|99%"
  fi
} | tee "$OUT"
if grep -q "Requests/sec" "$OUT" && ! grep -q "Requests/sec: *0\.00" "$OUT"; then
  cat "$OUT" >> "$RESULTS"
fi
rm -f "$OUT"
