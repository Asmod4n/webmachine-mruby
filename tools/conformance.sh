#!/bin/sh
# The external oracles, run the same way twice (#88 companion to
# tools/fuzz.sh - that one fuzzes our framers, this one asks somebody
# else's suite whether we speak the protocol).
#
#   tools/conformance.sh h2         h2spec, RFC 9113 + 7541 (146 cases)
#   tools/conformance.sh ws         Autobahn fuzzingserver, RFC 6455
#   tools/conformance.sh ws-h2      the same suite through the h2 bridge
#   tools/conformance.sh ws-serve   the echo server alone, and it stays up
#   tools/conformance.sh ws-client  the suite alone, against WS_HOST
#
# The last two are one run on two machines. The Autobahn image is built
# for amd64 and for nothing else, so a machine of another architecture
# cannot run the suite at all. Such a machine serves, and an amd64
# machine asks:
#
#   on the arm64 box:  tools/conformance.sh ws-serve
#   on an amd64 box:   WS_HOST=<the other box> tools/conformance.sh ws-client
#
# The server binds every address, so the second machine reaches it by
# name or by number.
#
# Both suites are containers (podman), both talk TCP to a server this
# script starts and stops. The server is found and killed through its
# --pidfile and nothing else: `pkill -f webmachine-server` also matches
# the shell that typed the command, which cost an afternoon of measuring
# a binary that was never restarted.
#
# Known result, and it is a refusal, not a gap: h2spec 3.5/2 ("Sends
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
# Which server the suite asks. It is this machine, unless a caller on
# another machine names the one that serves.
WS_HOST="${WS_HOST:-127.0.0.1}"
CASES="${CASES:-\"*\"}"
# The ship build's binary, unless the caller names another: CI runs the
# suites against the debug build it already made.
BIN="${BIN:-mruby/build/host/bin/webmachine-server}"
MRBC="${MRBC:-mruby/build/host/mrbc/bin/mrbc}"
OUT=build/conformance
PIDFILE="$OUT/server.pid"

# ws-client starts no server, so it needs neither binary.
if [ "$SUITE" != "ws-client" ]; then
  [ -x "$BIN" ] || { echo "$BIN missing - run: rake" >&2; exit 1; }
  [ -x "$MRBC" ] || { echo "$MRBC missing - run: rake" >&2; exit 1; }
fi
# Both suites ship as containers, and which runtime a machine has is not
# something either suite cares about: podman where there is one, docker
# where there is not. Named in one variable so the two call sites cannot
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
  # -g, as everywhere an app is compiled: an error record names the
  # app's source line, and only a debug section carries it.
  # The app names its listener; the fixture's port becomes this run's.
  sed "s/app.conf.port = [0-9]*/app.conf.port = $PORT/" "$1" > "$OUT/app.rb"
  "$MRBC" -g -o "$OUT/app.mrb" "$OUT/app.rb"
  rm -f "$PIDFILE"
  # Both logs, so a handshake the suite never saw answered is in the
  # access log, and a raise is in the error log.
  setsid "$BIN" --app="$OUT/app.mrb" --pidfile="$PIDFILE" \
    --log="$OUT/access.log" --log-privacy=none --error-log="$OUT/error.log" \
    > "$OUT/server.log" 2>&1 &
  i=0
  while [ ! -f "$PIDFILE" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
  [ -f "$PIDFILE" ] || { echo "server never wrote $PIDFILE:" >&2; cat "$OUT/server.log" >&2; exit 1; }
  echo "server pid $(cat "$PIDFILE") on port $PORT"
}

# The chunks answer one report each. This joins them into the single
# index.json every caller reads, and gathers the per-case files beside
# it so the artifact holds the whole run.
merge_reports() {
  for d in "$OUT"/reports-*; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      case "$f" in *"/index.json"|*"/index.html") continue ;; esac
      [ -f "$f" ] && cp "$f" "$OUT/reports/" 2>/dev/null || true
    done
  done
  ruby -rjson -e '
    out = {}
    Dir[File.join(ARGV[0], "reports-*", "index.json")].sort.each do |path|
      JSON.parse(File.read(path)).each do |agent, cases|
        (out[agent] ||= {}).merge!(cases)
      end
    end
    abort "no chunk wrote a report" if out.empty?
    File.write(File.join(ARGV[0], "reports", "index.json"), JSON.pretty_generate(out))
    n = out.values.map(&:size).sum
    puts "merged #{n} cases from #{Dir[File.join(ARGV[0], "reports-*")].size} chunks"
  ' "$OUT"
}

# The suite itself: the chunks, their reports, and the merge. Two
# commands call it - `ws`, which starts a server first, and
# `ws-client`, which asks a server on another machine.
run_suite() {
  if [ "$CASES" = '"*"' ]; then
    CHUNKS='"1.*","2.*","3.*","4.*","5.*"
"6.*","7.*","9.*","10.*"
"12.*"
"13.1.*","13.2.*","13.3.*"
"13.4.*","13.5.*","13.6.*","13.7.*"'
  else
    CHUNKS="$CASES"
  fi
  # Everything, 12.x and 13.x included: those are permessage-deflate
  # (RFC 7692), which round two of #175 negotiates and speaks. The
  # fixture (test/conformance/ws_echo.rb) is what turns it on - the
  # tree's default is off, and wsconn.hpp says why in bytes.
  mkdir -p "$OUT/reports"
  : > "$OUT/autobahn.log"
  chunk_no=0
  CHUNK_TIMEOUT=""
  command -v timeout >/dev/null && CHUNK_TIMEOUT="timeout ${WS_CHUNK_TIMEOUT:-600}"
  # PYTHONUNBUFFERED is not cosmetic: wstest is Python, Python
  # block-buffers stdout when it is a pipe, and a suite whose progress
  # only appears at the end is indistinguishable from a suite that
  # hung. That mistake cost half an hour of waiting on a run that was
  # working the whole time. With this, the case it is on is on screen.
  # One chunk at a time. Each writes its own report directory, and they
  # are merged at the end into the single index.json the caller reads.
  echo "$CHUNKS" | while IFS= read -r chunk; do
    [ -n "$chunk" ] || continue
    chunk_no=$((chunk_no + 1))
    rdir="reports-$chunk_no"
    mkdir -p "$OUT/$rdir"
    cat > "$OUT/fuzzingclient.json" <<JSON
{ "servers": [{ "url": "ws://$WS_HOST:$PORT/echo" }],
  "outdir": "/reports",
  "cases": [$chunk],
  "exclude-cases": [],
  "exclude-agent-cases": {} }
JSON
    echo "--- chunk $chunk_no: $chunk"
    # The status has to be wstest's, not tee's. A POSIX pipeline answers
    # with its last command, so `wstest | tee` reported success for a
    # wstest the runner had killed, and the failure surfaced later and
    # somewhere else - as a report file that was not there. `set -o
    # pipefail` is not POSIX, so the code travels through a file, and -e
    # goes off around it or the shell would leave before it is written.
    # A chunk gets a deadline of its own. wstest waits for ever when its
    # case list matches nothing - "will run 0 test cases" and then
    # silence - so a glob that names no case would otherwise hang the
    # whole job. Measured: the slowest chunk here is the deflate group at
    # about 4 minutes, so 15 is room and not a wait.
    set +e
    { $CHUNK_TIMEOUT "$OCI" run --rm --network host -e PYTHONUNBUFFERED=1 \
        -v "$PWD/$OUT/fuzzingclient.json:/fuzzingclient.json:z" \
        -v "$PWD/$OUT/$rdir:/reports:z" \
        crossbario/autobahn-testsuite \
        wstest -m fuzzingclient -s /fuzzingclient.json 2>&1
      echo $? > "$OUT/wstest.rc"
    } | tee -a "$OUT/autobahn.log"
    set -e
    ws_rc=$(cat "$OUT/wstest.rc" 2>/dev/null || echo 1)
    # wstest writes its report after the last case, so a chunk that ends
    # without one died in between - which the log alone cannot say.
    if [ "$ws_rc" -ne 0 ] || [ ! -f "$OUT/$rdir/index.json" ]; then
      echo "wstest ended with status $ws_rc and $([ -f "$OUT/$rdir/index.json" ] \
        && echo 'a report' || echo 'no report') on chunk $chunk_no ($chunk)" >&2
      echo "the last case it named: $(grep 'Running test case' "$OUT/autobahn.log" \
        | tail -1)" >&2
      exit 1
    fi
  done || exit 1
  merge_reports
  echo "report: $OUT/reports/index.html"
}

case "$SUITE" in
h2)
  start_server examples/hello.rb
  trap stop_server EXIT INT TERM
  if [ -n "${H2SPEC:-}" ]; then
    "$H2SPEC" -h 127.0.0.1 -p "$PORT" --timeout 5 2>&1 | tee "$OUT/h2spec.log"
  else
    "$OCI" run --rm --network host docker.io/summerwind/h2spec \
      -h 127.0.0.1 -p "$PORT" --timeout 5 2>&1 | tee "$OUT/h2spec.log"
  fi
  ;;
ws)
  [ -n "$OCI" ] || { echo 'the Autobahn suite is a container only - podman or docker' >&2; exit 1; }
  start_server test/conformance/ws_echo.rb
  trap stop_server EXIT INT TERM
  # How long it takes, measured, because it looks like a stall twice
  # otherwise: 517 cases in 735 s, of which 12.x and 13.x are 713 s.
  # Every other case together is 13 s. wstest writes its report at the
  # end, and a deflate case takes up to 14 s, so a screen that shows
  # 13.3.9 for a quarter of a minute is a suite that is working. The
  # cost is the suite's, not this server's: during the run wstest holds
  # 66% of a core and the server 33%, and a 1 MiB deflate echo measures
  # 96 MiB/s here against 112 MiB/s without the extension.
  #
  # CASES narrows the run: CASES='"12.*"' tools/conformance.sh ws
  # answers in seconds where the full suite answers in minutes, which is
  # the difference between finding a stall and waiting one out.
  #
  # One wstest per chunk, not one for all 517 cases. The runner killed a
  # whole-suite wstest twice with SIGKILL, both times about 450 cases in
  # and inside the deflate group, and a killed client writes no report.
  # A chunk is a fresh Python process, so what the client holds goes back
  # between chunks, and a failure names a group of cases rather than the
  # suite. What is covered does not change: the chunks are every case.
  #
  # CASES overrides the split, so one group can still be asked for on its
  # own. The suite has no section 8 and no section 11, so neither is
  # named here - a glob that matches nothing is what makes wstest wait
  # for ever, and the deadline below is what catches one.
  run_suite
  ;;
ws-serve)
  # The server alone, so a machine that cannot run the suite can still
  # be the one under test. It stays up until this command is stopped.
  start_server test/conformance/ws_echo.rb
  trap stop_server EXIT INT TERM
  echo "serving ws://0.0.0.0:$PORT/echo - stop with ctrl-c"
  while [ -f "$PIDFILE" ]; do sleep 1; done
  ;;
ws-client)
  # The suite alone, against the server WS_HOST names. Nothing is
  # started here and nothing is stopped.
  [ -n "$OCI" ] || { echo 'the Autobahn suite is a container only - podman or docker' >&2; exit 1; }
  [ "$WS_HOST" != "127.0.0.1" ] || echo 'WS_HOST is this machine - name the one that serves' >&2
  run_suite
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
