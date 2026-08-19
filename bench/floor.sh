#!/bin/bash
# The floor: raw reactor, no HTTP. Its number is the ceiling every later
# layer is measured against, so the harness line is part of the result -
# THREADS and CONNS are mandatory, never silent defaults (three separate
# debugging days in the old tree came from silently differing harnesses).
#
#   THREADS=4 CONNS=400 bench/floor.sh            # AF_UNIX (default)
#   THREADS=4 CONNS=400 TRANSPORT=tcp bench/floor.sh
#   WM_BUNDLE=0 ... for the A/B on a kernel under suspicion
set -u
[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
TRANSPORT="${TRANSPORT:-unix}"
PORT="${PORT:-8123}"
BIN=mruby/build/host/bin/webmachine-server
cd "$(dirname "$0")/.." || exit 1
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

WRK="${WRK:-$HOME/wrk/wrk}"
[ -x "$WRK" ] || WRK=$(command -v wrk) || { echo "wrk not found" >&2; exit 1; }

SOCK=/tmp/wm-floor-bench.sock
DUMMY=""
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  "$BIN" --unix "$SOCK" 2>/tmp/wm-floor-srv.log & SRV=$!
  # The patched wrk routes every byte over WRK_UNIX but still validates
  # its URL with one probe connect() to the TCP port - something must
  # answer that handshake or wrk refuses to start.
  python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$PORT)); s.listen(16)
while True:
    c,_=s.accept(); c.close()" >/dev/null 2>&1 & DUMMY=$!
else
  "$BIN" --port "$PORT" 2>/tmp/wm-floor-srv.log & SRV=$!
fi
trap 'kill $SRV $DUMMY 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:"; cat /tmp/wm-floor-srv.log; exit 1; }

echo "harness: wrk -t$THREADS -c$CONNS -d${DURATION}s transport=$TRANSPORT WM_BUNDLE=${WM_BUNDLE:-default} $(uname -mr)"
if [ "$TRANSPORT" = unix ]; then
  WRK_UNIX="$SOCK" "$WRK" -t"$THREADS" -c"$CONNS" -d"${DURATION}"s --latency \
    "http://127.0.0.1:$PORT/" | grep -E "Requests/sec|50%|99%"
else
  "$WRK" -t"$THREADS" -c"$CONNS" -d"${DURATION}"s --latency \
    "http://127.0.0.1:$PORT/" | grep -E "Requests/sec|50%|99%"
fi
