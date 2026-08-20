#!/bin/bash
# h1 against h2: same server, same route, same client budget, and the
# SAME CLIENT - h2load speaks both (--h1 forces cleartext HTTP/1.1),
# so the client machinery cancels out of the comparison entirely.
#
# Four runs against / (TCP - h2load does not speak unix sockets):
#
#   h2load --h1 -m1     the h1 anchor: 1 outstanding request per
#                       connection, which is what real h1 clients do
#   h2load -m1          h2 under the identical load shape - what the
#                       protocol costs per response (HPACK encode
#                       against a prebuilt h1 head). EXPECTATION: within
#                       noise of the anchor; a real gap is a finding.
#   h2load -m32         multiplexing, the thing h1 cannot have
#   h2load -m64         more of it
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# DURATION (default 10), PORT (default 8123), APP (default
# examples/hello.rb; empty = the bare floor). Appends to
# bench/results/$(hostname).log like floor.sh - failed runs write
# nothing.
set -u
cd "$(dirname "$0")/.." || exit 1

[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
PORT="${PORT:-8123}"
APP="${APP-examples/hello.rb}"
BIN=mruby/build/host/bin/webmachine-server
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
h2load --help 2>&1 | grep -q -- --h1 || { echo "this h2load lacks --h1" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

APP_ARGS=()
[ -n "$APP" ] && APP_ARGS=(--app "$APP")
"$BIN" --port "$PORT" "${APP_ARGS[@]}" >/dev/null 2>/tmp/wm-h2bench-srv.log &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:" >&2; cat /tmp/wm-h2bench-srv.log >&2; exit 1; }

URL="http://127.0.0.1:$PORT/"
LOG="bench/results/$(hostname).log"
mkdir -p bench/results

run() {  # run <label> <h2load flags...>
  local label=$1
  shift
  echo "== $label =="
  h2load -D"$DURATION" -t"$THREADS" -c"$CONNS" "$@" "$URL" 2>&1 |
    grep -E "finished|requests:|succeeded|time to 1st byte"
}

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: h2load -t$THREADS -c$CONNS -D${DURATION} app=${APP:-none} port=$PORT $(uname -mr)"
  run "h1 anchor: h2load --h1 -m1" --h1 -m1
  run "h2 -m1 (expect: within noise of the anchor)" -m1
  run "h2 -m32" -m32
  run "h2 -m64" -m64
} | tee -a "$LOG"
