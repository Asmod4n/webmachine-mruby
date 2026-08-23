#!/bin/sh
# The external oracles, run the same way twice (#88 companion to
# tools/fuzz.sh - that one fuzzes our framers, this one asks somebody
# else's suite whether we speak the protocol).
#
#   tools/conformance.sh h2         h2spec, RFC 9113 + 7541 (146 cases)
#   tools/conformance.sh ws         Autobahn fuzzingserver, RFC 6455
#
# Both suites are containers (podman), both talk TCP to a server this
# script starts and stops. The server is found and killed through its
# --pidfile and NOTHING else: `pkill -f webmachine-server` also matches
# the shell that typed the command, which cost an afternoon of measuring
# a binary that was never restarted.
#
# Known result, and it is a REFUSAL, not a gap: h2spec 3.5/2 ("Sends
# invalid connection preface") fails, 145/146. h2spec measures an
# h2-only endpoint; this listener also speaks HTTP/1.1, so a preface
# that is wrong at byte 0 - the peer never said "PRI" - gets HTTP/1.1's
# 400 rather than a frame, which is RFC 9113 3.4's own reading ("an
# invalid preface indicates that the peer is not using HTTP/2"). The
# connection dies either way, as 3.4 requires. src/http1.cpp says the
# same at the branch that decides it, and bintest/h2.rb pins both halves.
set -eu
cd "$(dirname "$0")/.."

SUITE="${1:-}"
PORT="${PORT:-9977}"
CASES="${CASES:-\"*\"}"
BIN=mruby/build/host/bin/webmachine-server
MRBC=mruby/build/host/mrbc/bin/mrbc
OUT=build/conformance
PIDFILE="$OUT/server.pid"

[ -x "$BIN" ] || { echo "$BIN missing - run: rake" >&2; exit 1; }
[ -x "$MRBC" ] || { echo "$MRBC missing - run: rake" >&2; exit 1; }
command -v podman >/dev/null || { echo 'podman not found - both suites ship as containers' >&2; exit 1; }

mkdir -p "$OUT"

stop_server() {
  [ -f "$PIDFILE" ] || return 0
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  i=0
  while [ -f "$PIDFILE" ] && [ "$i" -lt 50 ]; do i=$((i + 1)); sleep 0.1; done
  rm -f "$PIDFILE"
}

# app.rb -> app.mrb -> a running server whose pid is on disk before the
# suite gets to send a byte.
start_server() {
  "$MRBC" -o "$OUT/app.mrb" "$1"
  rm -f "$PIDFILE"
  setsid "$BIN" --app "$OUT/app.mrb" --port "$PORT" --pidfile "$PIDFILE" \
    > "$OUT/server.log" 2>&1 &
  i=0
  while [ ! -f "$PIDFILE" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
  [ -f "$PIDFILE" ] || { echo "server never wrote $PIDFILE:" >&2; cat "$OUT/server.log" >&2; exit 1; }
  echo "server pid $(cat "$PIDFILE") on port $PORT"
}

case "$SUITE" in
h2)
  start_server examples/hello.rb
  trap stop_server EXIT INT TERM
  podman run --rm --network host summerwind/h2spec \
    -h 127.0.0.1 -p "$PORT" --timeout 5 2>&1 | tee "$OUT/h2spec.log"
  ;;
ws)
  start_server test/conformance/ws_echo.rb
  trap stop_server EXIT INT TERM
  # CASES narrows the run: CASES='"12.*"' tools/conformance.sh ws
  # answers in seconds where the full suite answers in minutes, which is
  # the difference between finding a stall and waiting one out.
  cat > "$OUT/fuzzingclient.json" <<JSON
{ "servers": [{ "url": "ws://127.0.0.1:$PORT/echo" }],
  "outdir": "/reports",
  "cases": [$CASES],
  "exclude-cases": [],
  "exclude-agent-cases": {} }
JSON
  # Everything, 12.x and 13.x included: those are permessage-deflate
  # (RFC 7692), which round two of #175 negotiates and speaks. The
  # fixture (test/conformance/ws_echo.rb) is what turns it on - the
  # tree's default is off, and wsconn.hpp says why in bytes.
  mkdir -p "$OUT/reports"
  # PYTHONUNBUFFERED, and it is not cosmetic: wstest is Python, Python
  # block-buffers stdout when it is a pipe, and a suite whose progress
  # only appears at the END is indistinguishable from a suite that
  # hung. That mistake cost half an hour of waiting on a run that was
  # working the whole time. With this, the case it is on is on screen.
  podman run --rm --network host -e PYTHONUNBUFFERED=1 \
    -v "$PWD/$OUT/fuzzingclient.json:/fuzzingclient.json:z" \
    -v "$PWD/$OUT/reports:/reports:z" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /fuzzingclient.json 2>&1 | tee "$OUT/autobahn.log"
  echo "report: $OUT/reports/index.html"
  ;;
*)
  echo "usage: $0 h2|ws   (PORT=$PORT)" >&2
  exit 2
  ;;
esac
