#!/bin/bash
# h1 against h2: same server, same route, same client budget, and the
# SAME CLIENT - h2load speaks both (--h1 forces cleartext HTTP/1.1),
# so the client machinery cancels out of the comparison entirely.
#
# Four legs against / (TCP - h2load does not speak unix sockets):
#
#   h2load --h1 -m1     the h1 anchor: 1 outstanding request per
#                       connection, which is what real h1 clients do
#   h2load -m1          h2 under the identical load shape - what the
#                       protocol costs per response. EXPECTATION:
#                       within noise of the anchor; a real gap is a
#                       finding.
#   h2load -m32 / -m64  multiplexing, the thing h1 cannot have
#
# Methodology, learned on the shared-vCPU container (2026-08-20):
# oversubscribed shapes (c100, t2 client + server on 4 vCPUs) swing
# +-40% with the host's neighbor bursts and resolve nothing. What DOES
# resolve: small shapes (THREADS=1 CONNS=1 = the echo-probe form),
# REPS>=5 with the median, and a STEAL guard per leg - host steal is
# visible in
# /proc/stat and a contaminated leg says so instead of lying.
#
# WITHDRAWN from this note (2026-08-22): it used to prescribe pinning
# both processes to separate cpus, on an interleaved A/B that measured
# +3% and tighter. That reading did not survive. It was taken on a
# path that never touched a FILE - and touching a file is what makes
# io_uring spawn the io-wq pool whose workers inherit the pinned
# affinity. On the asset path the same taskset measured 0.07x. A
# tighter distribution around a lower number is what pinning actually
# buys, which is also what the older tree concluded when it deleted
# every taskset it had.
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# DURATION (default 10), REPS (default 1), PORT (default 8123), APP (default
# examples/hello.rb; empty = the bare floor). Appends to
# bench/results/$(hostname).log; failed runs write nothing.
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
cd "$(dirname "$0")/.." || exit 1

[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
REPS="${REPS:-1}"
PORT="${PORT:-8123}"
APP="${APP-examples/hello.rb}"
BIN=mruby/build/host/bin/webmachine-server
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
h2load --help 2>&1 | grep -q -- --h1 || { echo "this h2load lacks --h1" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

# The server loads bytecode only (#100). A .rb APP is compiled here
# with the tree's own mrbc into a scratch .mrb; the harness line keeps
# naming the .rb source. An .mrb APP (or none) passes through as-is.
APP_ARGS=()
if [ -n "${APP:-}" ]; then
  case "$APP" in
    *.rb)
      MRBC="${MRBC:-mruby/bin/mrbc}"
      [ -x "$MRBC" ] || { echo "mrbc not found at $MRBC - rake compile builds it, or set MRBC=" >&2; exit 1; }
      APP_MRB=/tmp/wm-h2-app.mrb
      "$MRBC" -o "$APP_MRB" "$APP" || exit 1
      APP_ARGS=(--app "$APP_MRB")
      ;;
    *) APP_ARGS=(--app "$APP") ;;
  esac
fi

"$BIN" --port "$PORT" "${APP_ARGS[@]}" >/dev/null 2>/tmp/wm-h2bench-srv.log &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:" >&2; cat /tmp/wm-h2bench-srv.log >&2; exit 1; }
grep -q "select(2) SHIM" /tmp/wm-h2bench-srv.log 2>/dev/null && {
  echo "REFUSED: the server runs the select shim - a lazy-path number must never enter bench/results/" >&2
  exit 1
}


URL="http://127.0.0.1:$PORT/"
LOG="bench/results/$(hostname).log"
mkdir -p bench/results

steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }

run() {  # run <label> <h2load flags...>
  local label=$1
  shift
  echo "== $label =="
  local vals=()
  for _ in $(seq "$REPS"); do
    local s0 s1 line rps
    s0=$(steal_ticks)
    line=$(h2load -D"$DURATION" -t"$THREADS" -c"$CONNS" "$@" "$URL" 2>&1 |
      grep '^finished')
    s1=$(steal_ticks)
    rps=$(echo "$line" | grep -o '[0-9.]* req/s' | grep -o '^[0-9.]*')
    echo "  $line (steal +$((s1 - s0)) ticks)"
    vals+=("$rps")
  done
  if [ "$REPS" -gt 1 ]; then
    printf '%s\n' "${vals[@]}" | sort -n | awk -v n="$REPS" \
      'NR==int((n+1)/2){m=$1} NR==1{lo=$1} END{printf "  median %.0f req/s (min %.0f, max %.0f)\n", m, lo, $1}'
  fi
}

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: h2load -t$THREADS -c$CONNS -D${DURATION} reps=$REPS app=${APP:-none} port=$PORT $(uname -mr)"
  run "h1 anchor: h2load --h1 -m1" --h1 -m1
  run "h2 -m1 (expect: within noise of the anchor)" -m1
  run "h2 -m32" -m32
  run "h2 -m64" -m64
} | tee -a "$LOG"
