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
# NO PINNING - measured twice, lost twice. The previous tree removed
# every taskset it had ("handing the scheduler one core was slower than
# letting it choose"; widening the CLIENT mask 2 -> 15 -> 30 cpus raised
# throughput monotonically in the MEDIAN). And io-wq workers inherit the
# issuing thread's affinity, so pinning the server pins the pool that
# carries splice: a 32 KiB asset measured 0.07x its unspliced twin under
# `taskset -c 0`. The knobs are gone rather than defaulted off - they
# are not something anyone should turn on.
#
set -u
[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
DEPTH="${DEPTH:-16}"
TRANSPORT="${TRANSPORT:-unix}"
PORT="${PORT:-8123}"
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

# The server loads bytecode only (#100). A .rb APP is compiled here
# with the tree's own mrbc into a scratch .mrb; the harness line keeps
# naming the .rb source. An .mrb APP (or none) passes through as-is.
APP_ARGS=()
if [ -n "${APP:-}" ]; then
  case "$APP" in
    *.rb)
      MRBC="${MRBC:-mruby/bin/mrbc}"
      [ -x "$MRBC" ] || { echo "mrbc not found at $MRBC - rake compile builds it, or set MRBC=" >&2; exit 1; }
      APP_MRB=/tmp/wm-pipeline-app.mrb
      "$MRBC" -o "$APP_MRB" "$APP" || exit 1
      APP_ARGS=(--app "$APP_MRB")
      ;;
    *) APP_ARGS=(--app "$APP") ;;
  esac
fi

SOCK=/tmp/wm-pipeline-bench.sock
DUMMY=""
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  "$BIN" --unix "$SOCK" "${APP_ARGS[@]}" 2>/tmp/wm-pipeline-srv.log & SRV=$!
  # The patched wrk still probe-connects the TCP port to validate its
  # URL even when every byte rides WRK_UNIX (see floor.sh).
  python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$PORT)); s.listen(16)
while True:
    c,_=s.accept(); c.close()" >/dev/null 2>&1 & DUMMY=$!
else
  "$BIN" --port "$PORT" "${APP_ARGS[@]}" 2>/tmp/wm-pipeline-srv.log & SRV=$!
fi
trap 'kill $SRV $DUMMY 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:"; cat /tmp/wm-pipeline-srv.log; exit 1; }
grep -q "select(2) SHIM" /tmp/wm-pipeline-srv.log 2>/dev/null && {
  echo "REFUSED: the server runs the select shim - a lazy-path number must never enter bench/results/" >&2
  exit 1
}


RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
MRUBY_REV=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?')
RAW=$(mktemp)
if [ "$TRANSPORT" = unix ]; then
  WRK_UNIX="$SOCK" PIPELINE_DEPTH="$DEPTH" "$WRK" -t"$THREADS" -c"$CONNS" \
    -d"${DURATION}"s -s bench/pipeline.lua "http://127.0.0.1:$PORT/" > "$RAW" 2>&1
else
  PIPELINE_DEPTH="$DEPTH" "$WRK" -t"$THREADS" -c"$CONNS" \
    -d"${DURATION}"s -s bench/pipeline.lua "http://127.0.0.1:$PORT/" > "$RAW" 2>&1
fi

# wrk prints "Socket errors:"/"Non-2xx or 3xx responses:" ONLY when the
# count is nonzero (wrk.c:181-189), so their absence is the proof that
# there were none. Never grep for the throughput line alone: an earlier
# version of this script did, and it would have hidden exactly the
# failures a benchmark must never hide.
ERRS=$(grep -E "Socket errors|Non-2xx or 3xx" "$RAW" || true)
# --latency is deliberately NOT passed: wrk's percentiles are WRONG for
# pipelined runs and would be read as failures. Latency is recorded once
# per BATCH (wrk.c:365), but the coordinated-omission correction derives
# its interval from the per-RESPONSE count (wrk.c:170), so stats_correct
# inflates stats->count while filling buckets below stats->min - which
# it never updates (stats.c:33-42). stats_percentile then sums only
# [min,max], never reaches its rank, and falls through to `return 0`
# (stats.c:78-86). That is where the "0.00us" comes from: an accounting
# artifact, not a timeout. Batch turnaround has no per-request meaning
# here anyway - this bench measures throughput, floor.sh measures
# latency.
OUT=$(mktemp)
{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV mruby=$MRUBY_REV ===="
  echo "harness: wrk -t$THREADS -c$CONNS -d${DURATION}s PIPELINED depth=$DEPTH transport=$TRANSPORT app=${APP:-none} $(uname -mr)"
  grep -E "requests in .*read" "$RAW"
  [ -n "$ERRS" ] && echo "$ERRS"
  grep -E "Requests/sec|Transfer/sec" "$RAW"
} | tee "$OUT"

if [ -n "$ERRS" ]; then
  echo "ERRORS above - this run is not a number, nothing logged" >&2
  rm -f "$OUT" "$RAW"
  exit 1
fi
# The bytes must account for every request: complete * response size.
# A batch that silently lost answers would still report a throughput.
awk '/requests in/ {
  n = $1
  bs = $(NF-1)                 # "1.29GB" - $NF is the word "read"
  mult = 1
  if (bs ~ /GB/) mult = 1024*1024*1024
  else if (bs ~ /MB/) mult = 1024*1024
  else if (bs ~ /KB/) mult = 1024
  gsub(/[^0-9.]/, "", bs)
  printf "  bytes/response: %.1f (must equal the response size - a batch that lost answers still reports throughput)\n", (bs * mult) / n
}' "$RAW" | tee -a "$OUT"

if grep -q "Requests/sec" "$OUT" && ! grep -q "Requests/sec: *0\.00" "$OUT"; then
  cat "$OUT" >> "$RESULTS"
fi
rm -f "$OUT" "$RAW"
