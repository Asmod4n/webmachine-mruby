#!/bin/bash
# Where does the h2-vs-h1 -m1 gap go? Records ONE matched pair of perf
# profiles - the h1 anchor and h2 -m1, same duration, same pinning,
# same run - and diffs them with `perf diff`, so the delta is read off
# relative sample share per symbol instead of guessed at from req/s.
#
# Needs a WM_PROFILE=1 build (debug symbols + retained frame pointers -
# see build_config.rb): rake clean && WM_PROFILE=1 rake compile.
# Rebuild WITHOUT it (rake clean && rake compile) before trusting any
# req/s number again - this binary is not the one throughput is
# measured on.
#
# Default shape is THREADS=1 CONNS=1 -m1 on purpose: it's the exact
# pair that already showed the ~7% gap (bench/h2.sh, pinned, real
# hardware) - overriding it profiles a different question, not this
# finding.
#
# Knobs: DURATION (default 20 - profiling wants more samples than a
# throughput run), FREQ (perf -F, default 999), CALLGRAPH (fp|dwarf,
# default fp - matches the frame pointers WM_PROFILE retains), PIN_SRV/
# PIN_CLI (cpu lists for taskset; empty = unpinned, not recommended
# here - a migrated process smears the profile across cores), PORT,
# APP (default examples/hello.rb).
set -u
cd "$(dirname "$0")/.." || exit 1

# Debian/Ubuntu's /usr/bin/perf is a wrapper that refuses to run
# unless a linux-tools package matching the EXACT running kernel
# string is installed - a version-string check, not a real
# incompatibility (perf's recording ABI tolerates a build/run skew).
# PERF= overrides; otherwise probe the wrapper for real, then fall
# back to any versioned perf under /usr/lib/linux-tools-*/.
PERF="${PERF:-}"
if [ -z "$PERF" ]; then
  if perf --version >/dev/null 2>&1; then
    PERF=perf
  else
    PERF=$(ls /usr/lib/linux-tools-*/perf 2>/dev/null | head -1)
  fi
fi
[ -n "$PERF" ] && [ -x "$(command -v "$PERF")" ] || {
  echo "no working perf (the wrapper refused and no /usr/lib/linux-tools-*/perf " \
       "fallback exists - install linux-tools-\$(uname -r), or set PERF=/path/to/perf)" >&2
  exit 1
}
echo "perf: $PERF ($("$PERF" --version))"
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
h2load --help 2>&1 | grep -q -- --h1 || { echo "this h2load lacks --h1" >&2; exit 1; }

BIN=mruby/build/host/bin/webmachine-server
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }
file "$BIN" 2>/dev/null | grep -q "not stripped" || echo \
  "warning: $BIN looks stripped - was it built with WM_PROFILE=1? symbols will be useless" >&2

paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "?")
if [ "$paranoid" != "?" ] && [ "$paranoid" -gt 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "kernel.perf_event_paranoid=$paranoid blocks unprivileged perf record - " \
       "sudo sysctl kernel.perf_event_paranoid=1 (or run this under sudo)" >&2
  exit 1
fi

DURATION="${DURATION:-20}"
FREQ="${FREQ:-999}"
CALLGRAPH="${CALLGRAPH:-fp}"
PIN_SRV="${PIN_SRV:-}"
PIN_CLI="${PIN_CLI:-}"
PORT="${PORT:-8123}"
APP="${APP-examples/hello.rb}"

APP_ARGS=()
[ -n "$APP" ] && APP_ARGS=(--app "$APP")
SRV_WRAP=()
[ -n "$PIN_SRV" ] && SRV_WRAP=(taskset -c "$PIN_SRV")
CLI_WRAP=()
[ -n "$PIN_CLI" ] && CLI_WRAP=(taskset -c "$PIN_CLI")

OUT=bench/profile
mkdir -p "$OUT"
URL="http://127.0.0.1:$PORT/"

# An io_uring ring is locked memory, so a LEAKED server costs more than
# a pid: enough orphans and the next ring init fails with ENOMEM
# ("io_uring_queue_init: Cannot allocate memory"), which reads like a
# code fault and is not one. Every other bench script traps EXIT; this
# one did not, and a ^C mid-run left both perf and the server behind.
SRVPID=""
PERFPID=""
cleanup() {
  [ -n "$SRVPID" ] && kill -TERM "$SRVPID" 2>/dev/null
  [ -n "$PERFPID" ] && kill "$PERFPID" 2>/dev/null
  wait 2>/dev/null
  return 0
}
trap cleanup EXIT INT TERM

if pgrep -f "$BIN" >/dev/null 2>&1; then
  echo "a webmachine-server is already running - it holds an io_uring ring:" >&2
  pgrep -af "$BIN" >&2
  echo "kill it first (pkill -f webmachine-server), or this run competes with it" >&2
  exit 1
fi

# leg <name> <perf.data path> <h2load flags...>
leg() {
  local name=$1 data=$2
  shift 2
  echo "== recording $name -> $data =="
  "$PERF" record -F "$FREQ" -g --call-graph "$CALLGRAPH" -o "$data" -- \
    "${SRV_WRAP[@]}" "$BIN" --port "$PORT" "${APP_ARGS[@]}" \
    >/tmp/wm-profile-srv.log 2>&1 &
  local perfpid=$!
  PERFPID=$perfpid
  # $! is perf's own pid (it execs the server as ITS child, taskset if
  # pinned execs again in place, same pid throughout) - pgrep -P finds
  # that direct child unambiguously, no full-line matching to race.
  local srvpid=""
  for _ in $(seq 20); do
    srvpid=$(pgrep -P "$perfpid" | head -1)
    [ -n "$srvpid" ] && bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null && break
    srvpid=""
    sleep 0.1
  done
  if [ -z "$srvpid" ]; then
    echo "server did not start (or never became reachable on :$PORT):" >&2
    cat /tmp/wm-profile-srv.log >&2
    # perf's own mmap buffers and io_uring's ring draw on the SAME
    # locked-memory budget, and the server only ever fails this way
    # UNDER perf - so say so instead of leaving it to be rediscovered.
    if grep -q "Cannot allocate memory" /tmp/wm-profile-srv.log 2>/dev/null; then
      echo "ENOMEM at ring init: perf's buffers and io_uring both take locked memory." >&2
      echo "ulimit -l says $(ulimit -l); perf_event_mlock_kb says" \
           "$(cat /proc/sys/kernel/perf_event_mlock_kb 2>/dev/null || echo '?')." >&2
      echo "Try: ulimit -l unlimited (same shell), or run this under sudo." >&2
    fi
    exit 1
  fi
  SRVPID=$srvpid
  "${CLI_WRAP[@]}" h2load -D"$DURATION" -t1 -c1 "$@" "$URL" 2>&1 | grep '^finished'
  kill -TERM "$srvpid"
  wait "$perfpid" 2>/dev/null
  SRVPID=""
  PERFPID=""
}

leg "h1 anchor" "$OUT/perf.data.h1" --h1 -m1
leg "h2 -m1"    "$OUT/perf.data.h2" -m1

echo
echo "== perf diff: relative sample share, h1 -> h2 (positive = h2 spends more here) =="
"$PERF" diff "$OUT/perf.data.h1" "$OUT/perf.data.h2" 2>/dev/null | head -60

if command -v stackcollapse-perf.pl >/dev/null && command -v flamegraph.pl >/dev/null; then
  "$PERF" script -i "$OUT/perf.data.h2" 2>/dev/null | stackcollapse-perf.pl | flamegraph.pl \
    > "$OUT/flamegraph.h2.svg"
  echo "flamegraph: $OUT/flamegraph.h2.svg"
else
  echo "FlameGraph scripts (stackcollapse-perf.pl/flamegraph.pl) not on PATH - " \
       "skipped, perf diff above is the finding" >&2
fi
