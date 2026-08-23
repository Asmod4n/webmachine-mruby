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

# --- requests per syscall -------------------------------------------
# The point of a ring server is syscall AMORTIZATION - one enter
# carries a whole batch of rounds - and this makes it a NUMBER: the
# server's syscalls over the run (raw_syscalls:sys_enter, a counting
# tracepoint: no sampling, negligible overhead), divided into the
# requests the client completed. The window is the client's run plus
# edges; an idle server sits BLOCKED in one enter, so edges add
# ~nothing. Needs a perf that may attach (root, or CAP_PERFMON /
# perf_event_paranoid low enough for tracepoints); without one the
# column prints '-' rather than a guess.
SYSC_PERF="${PERF:-}"
if [ -z "$SYSC_PERF" ]; then
  if perf --version >/dev/null 2>&1; then SYSC_PERF=perf
  else SYSC_PERF=$(ls /usr/lib/linux-tools-*/perf 2>/dev/null | head -1); fi
fi
if [ -n "$SYSC_PERF" ]; then
  # Preflight, once: tracepoints are gated separately from cpu events
  # (unprivileged needs perf_event_paranoid = -1 or CAP_PERFMON; 0/1
  # open only the cpu side, which is why perf record works while this
  # counter stays empty). A column of silent '-' hides that; say it.
  # perf stat's -x CSV goes to STDERR; the probe must read that side.
  # On failure, RELAY perf's own words - there are two separate locks
  # (perf_event_paranoid gates the syscall, tracefs permissions gate
  # resolving the event name) and guessing which one bit cost a round
  # of head-scratching already.
  SYSC_PROBE=$("$SYSC_PERF" stat -e raw_syscalls:sys_enter -x, -- /bin/true 2>&1 >/dev/null)
  if ! echo "$SYSC_PROBE" | grep -q '^[0-9]'; then
    echo "req/syscall: '-' - $SYSC_PERF cannot count raw_syscalls:sys_enter. Its own words:" >&2
    echo "$SYSC_PROBE" | head -4 | sed 's/^/    /' >&2
    echo "  Usual causes: kernel.perf_event_paranoid > -1 without CAP_PERFMON, or" >&2
    echo "  /sys/kernel/tracing unreadable (sudo chmod -R o+rX /sys/kernel/tracing helps; 700 root-only is the distro default)." >&2
    SYSC_PERF=""
  fi
fi
SYSC_PID=
SYSC_OUT="${WORK:-/tmp}/wm-sysc.$$"
sysc_begin() {  # <pid[,pid...]> <seconds>
  [ -n "$SYSC_PERF" ] || return 0
  "$SYSC_PERF" stat -e raw_syscalls:sys_enter -x, -p "$1" -o "$SYSC_OUT" \
    -- sleep "$2" >/dev/null 2>&1 &
  SYSC_PID=$!
}
# Split like snap_times, for the same reason: the WAIT must run in the
# shell that backgrounded perf (a $() subshell is not its parent, its
# wait returns at once while the output file is still being written);
# only the read may fork.
sysc_wait() {
  [ -n "$SYSC_PID" ] && wait "$SYSC_PID" 2>/dev/null
  SYSC_PID=
}
sysc_read() {
  awk -F, '$3 == "raw_syscalls:sys_enter" && $1 ~ /^[0-9]/ { print $1 }' "$SYSC_OUT" 2>/dev/null
}

run() {  # run <label> <h2load flags...>
  local label=$1
  shift
  echo "== $label =="
  local vals=()
  for _ in $(seq "$REPS"); do
    local s0 s1 out line rps nsysc ndone rsc="-"
    s0=$(steal_ticks)
    sysc_begin "$SRV" "$DURATION"
    out=$(h2load -D"$DURATION" -t"$THREADS" -c"$CONNS" "$@" "$URL" 2>&1)
    s1=$(steal_ticks)
    sysc_wait
    nsysc=$(sysc_read)
    line=$(echo "$out" | grep '^finished')
    ndone=$(echo "$out" | grep '^requests:' | awk '{print $6}')
    if [ -n "$nsysc" ] && [ "$nsysc" -gt 0 ] && [ -n "$ndone" ]; then
      rsc=$(awk -v d="$ndone" -v n="$nsysc" 'BEGIN { printf "%.1f", d / n }')
    fi
    rps=$(echo "$line" | grep -o '[0-9.]* req/s' | grep -o '^[0-9.]*')
    echo "  $line (steal +$((s1 - s0)) ticks, req/syscall $rsc)"
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
