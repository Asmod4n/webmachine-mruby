#!/bin/bash
# The floor: raw reactor, no HTTP. Its number is the ceiling every later
# layer is measured against, so the harness line is part of the result -
# THREADS and CONNS are mandatory, never silent defaults (three separate
# debugging days in the old tree came from silently differing harnesses).
#
#   THREADS=4 CONNS=400 bench/floor.sh            # AF_UNIX (default)
#   THREADS=4 CONNS=400 TRANSPORT=tcp bench/floor.sh
#   IMPL=epoll ...     the classic-reactor measuring stick, same protocol
#   APP=examples/hello.rb ...  bind a resource (konst or runtime tier)
#   WM_BUNDLE=0 ...    for the A/B on a kernel under suspicion
set -u
[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
TRANSPORT="${TRANSPORT:-unix}"
PORT="${PORT:-8123}"
IMPL="${IMPL:-uring}"
case "$IMPL" in
  uring) BIN=mruby/build/host/bin/webmachine-server ;;
  epoll) BIN=mruby/build/host/bin/webmachine-floor-epoll ;;
  *) echo "IMPL must be uring or epoll" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.." || exit 1
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

WRK="${WRK:-$HOME/wrk/wrk}"
[ -x "$WRK" ] || WRK=$(command -v wrk) || { echo "wrk not found" >&2; exit 1; }
if [ "${TRANSPORT:-unix}" = unix ] && ! grep -aq WRK_UNIX "$WRK"; then
  # An unpatched wrk silently ignores WRK_UNIX, talks TCP to the probe
  # dummy instead, and measures a perfect 0.00 - seen on the Pi's first
  # run. Refused here, with the fix named. grep -a, not strings(1):
  # strings is binutils, absent on a stock Pi, and a missing checker
  # once rejected a correctly patched wrk.
  echo "$WRK is not the WRK_UNIX-patched build - apply bench/wrk-af-unix.patch (see its header)" >&2
  exit 1
fi

APP_ARGS=()
[ -n "${APP:-}" ] && APP_ARGS=(--app "$APP")

SOCK=/tmp/wm-floor-bench.sock
DUMMY=""
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  "$BIN" --unix "$SOCK" "${APP_ARGS[@]}" 2>/tmp/wm-floor-srv.log & SRV=$!
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
  "$BIN" --port "$PORT" "${APP_ARGS[@]}" 2>/tmp/wm-floor-srv.log & SRV=$!
fi
# wait: back-to-back runs must not race the dying listener for the port.
trap 'kill $SRV $DUMMY 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:"; cat /tmp/wm-floor-srv.log; exit 1; }
grep -q "select(2) SHIM" /tmp/wm-floor-srv.log 2>/dev/null && {
  echo "REFUSED: the server runs the select shim - a lazy-path number must never enter bench/results/" >&2
  exit 1
}


# Results outlive the terminal: every run appends to a per-host log in
# the repo (committable, never gitignored - the numbers are the
# archive). 16+ forgecore runs once died in scrollback; never again.
RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
MRUBY_REV=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?')
OUT=$(mktemp)
{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV mruby=$MRUBY_REV ===="
  # The compiler flags are part of every number since they became a
  # variable (O2 -> O3+native landed mid-archive).
  CFLAGS_LINE=$(grep -o "'-O[^']*'.*" build_config.rb | head -1 | tr -d "'" | tr '<' ' ' | tr -s ' ')
  echo "harness: wrk -t$THREADS -c$CONNS -d${DURATION}s impl=$IMPL transport=$TRANSPORT app=${APP:-none} WM_BUNDLE=${WM_BUNDLE:-default} cflags=${CFLAGS_LINE:-?} $(uname -mr)"
  if [ "$TRANSPORT" = unix ]; then
    WRK_UNIX="$SOCK" "$WRK" -t"$THREADS" -c"$CONNS" -d"${DURATION}"s --latency \
      "http://127.0.0.1:$PORT/" | grep -E "Requests/sec|50%|99%"
  else
    "$WRK" -t"$THREADS" -c"$CONNS" -d"${DURATION}"s --latency \
      "http://127.0.0.1:$PORT/" | grep -E "Requests/sec|50%|99%"
  fi
} | tee "$OUT"
# A failed run writes nothing: the log holds only numbers that existed.
if grep -q "Requests/sec" "$OUT" && ! grep -q "Requests/sec: *0\.00" "$OUT"; then
  cat "$OUT" >> "$RESULTS"
else
  echo "run measured nothing - NOT recorded in $RESULTS" >&2
fi
rm -f "$OUT"
