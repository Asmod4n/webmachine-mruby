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
# REPS>=5 with the median, both processes PINNED to separate CPUs
# (interleaved A/B measured pinning +3% and tighter - migration cost
# is real), and a STEAL guard per leg - host steal is visible in
# /proc/stat and a contaminated leg says so instead of lying.
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# DURATION (default 10), REPS (default 1), PIN_SRV/PIN_CLI (cpu lists
# for taskset; empty = unpinned), PORT (default 8123), APP (default
# examples/hello.rb; empty = the bare floor). Appends to
# bench/results/$(hostname).log; failed runs write nothing.
set -u
cd "$(dirname "$0")/.." || exit 1

[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
REPS="${REPS:-1}"
PIN_SRV="${PIN_SRV:-}"
PIN_CLI="${PIN_CLI:-}"
PORT="${PORT:-8123}"
APP="${APP-examples/hello.rb}"
BIN=mruby/build/host/bin/webmachine-server
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
h2load --help 2>&1 | grep -q -- --h1 || { echo "this h2load lacks --h1" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

APP_ARGS=()
[ -n "$APP" ] && APP_ARGS=(--app "$APP")
SRV_WRAP=()
[ -n "$PIN_SRV" ] && SRV_WRAP=(taskset -c "$PIN_SRV")
CLI_WRAP=()
[ -n "$PIN_CLI" ] && CLI_WRAP=(taskset -c "$PIN_CLI")

"${SRV_WRAP[@]}" "$BIN" --port "$PORT" "${APP_ARGS[@]}" >/dev/null 2>/tmp/wm-h2bench-srv.log &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:" >&2; cat /tmp/wm-h2bench-srv.log >&2; exit 1; }

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
    line=$("${CLI_WRAP[@]}" h2load -D"$DURATION" -t"$THREADS" -c"$CONNS" "$@" "$URL" 2>&1 |
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
  echo "harness: h2load -t$THREADS -c$CONNS -D${DURATION} reps=$REPS pin_srv=${PIN_SRV:-no} pin_cli=${PIN_CLI:-no} app=${APP:-none} port=$PORT $(uname -mr)"
  run "h1 anchor: h2load --h1 -m1" --h1 -m1
  run "h2 -m1 (expect: within noise of the anchor)" -m1
  run "h2 -m32" -m32
  run "h2 -m64" -m64
} | tee -a "$LOG"
