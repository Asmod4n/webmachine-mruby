#!/bin/sh
# The external oracles, run the same way twice (#88 companion to
# tools/fuzz.sh - that one fuzzes our framers, this one asks somebody
# else's suite whether we speak the protocol).
#
#   tools/conformance.sh h2         h2spec, RFC 9113 + 7541 (146 cases)
#   tools/conformance.sh ws         Autobahn fuzzingserver, RFC 6455
#   tools/conformance.sh ws-h2      the same suite through the h2 bridge
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
# Both suites ship as containers, and which runtime a machine has is not
# something either suite cares about: podman where there is one, docker
# where there is not. Named in ONE variable so the two call sites cannot
# drift apart.
#
# H2SPEC=path is the way out where there is no runtime at all: h2spec is
# a single static Go binary and its release tarball runs anywhere. The
# Autobahn suite has no such form - it is Python with its own tree - so
# `ws` still needs a container.
if command -v podman >/dev/null; then
  OCI=podman
elif command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  OCI=docker
else
  OCI=""
fi
if [ -z "$OCI" ] && [ -z "${H2SPEC:-}" ]; then
  echo 'no container runtime, and no H2SPEC=path to a h2spec binary' >&2
  echo '  https://github.com/summerwind/h2spec/releases (h2spec_linux_amd64.tar.gz)' >&2
  exit 1
fi

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
  setsid "$BIN" --app="$OUT/app.mrb" --port="$PORT" --pidfile="$PIDFILE" \
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
  if [ -n "${H2SPEC:-}" ]; then
    "$H2SPEC" -h 127.0.0.1 -p "$PORT" --timeout 5 2>&1 | tee "$OUT/h2spec.log"
  else
    "$OCI" run --rm --network host summerwind/h2spec \
      -h 127.0.0.1 -p "$PORT" --timeout 5 2>&1 | tee "$OUT/h2spec.log"
  fi
  ;;
ws)
  [ -n "$OCI" ] || { echo 'the Autobahn suite is a container only - podman or docker' >&2; exit 1; }
  start_server test/conformance/ws_echo.rb
  trap stop_server EXIT INT TERM
  # HOW LONG IT TAKES, measured, because it looks like a stall twice
  # otherwise: 517 cases in 735 s, of which 12.x and 13.x are 713 s.
  # Every other case together is 13 s. wstest writes its report at the
  # END, and a deflate case takes up to 14 s, so a screen that shows
  # 13.3.9 for a quarter of a minute is a suite that is working. The
  # cost is the suite's, not this server's: during the run wstest holds
  # 66% of a core and the server 33%, and a 1 MiB deflate echo measures
  # 96 MiB/s here against 112 MiB/s without the extension.
  #
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
  "$OCI" run --rm --network host -e PYTHONUNBUFFERED=1 \
    -v "$PWD/$OUT/fuzzingclient.json:/fuzzingclient.json:z" \
    -v "$PWD/$OUT/reports:/reports:z" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /fuzzingclient.json 2>&1 | tee "$OUT/autobahn.log"
  echo "report: $OUT/reports/index.html"
  ;;
ws-h2)
  # RFC 8441: the same WebSocket, reached through an h2 extended
  # CONNECT. Autobahn has no h2 client and neither has nghttpx, so
  # tools/ws_h2_bridge.rb sits between them: wstest speaks HTTP/1.1 to
  # the bridge, the bridge speaks h2 to the server, and a WebSocket
  # frame crosses both without being read.
  [ -n "$OCI" ] || { echo 'the Autobahn suite is a container only - podman or docker' >&2; exit 1; }
  command -v ruby >/dev/null || { echo 'the bridge needs a ruby on PATH' >&2; exit 1; }
  BRIDGE_PORT="${BRIDGE_PORT:-$((PORT + 1))}"
  start_server test/conformance/ws_echo.rb
  ruby tools/ws_h2_bridge.rb --listen "$BRIDGE_PORT" --server "127.0.0.1:$PORT" \
    --path /echo > "$OUT/bridge.log" 2>&1 &
  BRIDGE_PID=$!
  stop_all() { kill "$BRIDGE_PID" 2>/dev/null || true; stop_server; }
  trap stop_all EXIT INT TERM
  i=0
  while [ "$i" -lt 50 ]; do i=$((i + 1)); sleep 0.1
    grep -q 'ws-h2 bridge' "$OUT/bridge.log" && break
  done
  echo "bridge pid $BRIDGE_PID on port $BRIDGE_PORT"
  # 12.x and 13.x are permessage-deflate, and the bridge cannot carry
  # them: it would have to name the extension the server took, and that
  # answer is HPACK with Huffman-coded values. bintest/h2.rb proves
  # deflate over h2 instead. The head of tools/ws_h2_bridge.rb says the
  # same, longer.
  cat > "$OUT/fuzzingclient-h2.json" <<JSON
{ "servers": [{ "url": "ws://127.0.0.1:$BRIDGE_PORT/echo" }],
  "outdir": "/reports",
  "cases": [$CASES],
  "exclude-cases": ["12.*", "13.*"],
  "exclude-agent-cases": {} }
JSON
  mkdir -p "$OUT/reports-h2"
  "$OCI" run --rm --network host -e PYTHONUNBUFFERED=1 \
    -v "$PWD/$OUT/fuzzingclient-h2.json:/fuzzingclient.json:z" \
    -v "$PWD/$OUT/reports-h2:/reports:z" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /fuzzingclient.json 2>&1 | tee "$OUT/autobahn-h2.log"
  echo "report: $OUT/reports-h2/index.html"
  ;;
*)
  echo "usage: $0 h2|ws|ws-h2   (PORT=$PORT)" >&2
  exit 2
  ;;
esac
