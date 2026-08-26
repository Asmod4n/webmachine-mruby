#!/bin/bash
# The floor: raw reactor, no HTTP. Its number is the ceiling every later
# layer is measured against, so the harness line is part of the result -
# THREADS and CONNS are mandatory, never silent defaults (three separate
# debugging days in the old tree came from silently differing harnesses).
#
#   THREADS=4 CONNS=400 bench/floor.sh            # AF_UNIX (default)
#   THREADS=4 CONNS=400 TRANSPORT=tcp bench/floor.sh
#   IMPL=epoll ...     the classic-reactor measuring stick, same protocol
#   IMPL=portable ...  the emergency exit (slipstreamIO, select(2)) -
#                      what the way out costs, on the same wire
#   IMPL=pgo ...       the same flags as host plus -fprofile-use, so the
#                      A/B against IMPL=uring is PGO and nothing else
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
  portable) BIN=mruby/build/portable/bin/webmachine-server ;;
  pgo) BIN=mruby/build/pgo/bin/webmachine-server ;;
  *) echo "IMPL must be uring, epoll, portable or pgo" >&2; exit 2 ;;
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

# THE CLIENT MUST NOT BE THE BOTTLENECK - the same refusal bench/assets.sh
# already has, ported here: a number where wrk burned as much CPU as the
# server describes wrk, not webmachine. cpu_ticks reads the SERVER's own
# /proc/pid/stat (utime+stime), never system-wide - see snap_times below
# for the client's side.
cpu_ticks() {
  awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[12] + f[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo 0
}
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
WORK=$(mktemp -d)
# Split like sysc_wait: the WAIT must run in the shell that backgrounded
# wrk (a $() subshell is not its parent), only the read below may fork.
snap_times() { times > "$WORK/.times"; }
parse_child_cpu() {
  awk 'NR==2 { split($1, u, "m"); split($2, sy, "m");
               printf "%.2f", u[1]*60 + u[2] + sy[1]*60 + sy[2] }' "$WORK/.times"
}

# The server loads bytecode only (#100). A .rb APP is compiled here
# with the tree's own mrbc into a scratch .mrb; the harness line keeps
# naming the .rb source. An .mrb APP (or none) passes through as-is.
LOG="${LOG:-0}"
LOG_ARGS=()
[ "$LOG" = 1 ] && LOG_ARGS=(--log "/tmp/wm-floor-access.$$.log")
APP_ARGS=()
if [ -n "${APP:-}" ]; then
  case "$APP" in
    *.rb)
      MRBC="${MRBC:-mruby/bin/mrbc}"
      [ -x "$MRBC" ] || { echo "mrbc not found at $MRBC - rake compile builds it, or set MRBC=" >&2; exit 1; }
      APP_MRB=/tmp/wm-floor-app.mrb
      "$MRBC" -o "$APP_MRB" "$APP" || exit 1
      APP_ARGS=(--app "$APP_MRB")
      ;;
    *) APP_ARGS=(--app "$APP") ;;
  esac
fi

# BROWSER=1 sends what a browser sends. It is not decoration: Accept,
# Accept-Encoding and Accept-Language are three of the eight headers
# that clear ReqFacts::plain, and a plain request never walks the flow
# tree at all - flow::answer returns the konst status on its first
# branch. wrk's own request carries none of them, so every number this
# script has ever produced measured the path a browser never takes.
BROWSER="${BROWSER:-0}"
WRK_HDRS=()
if [ "$BROWSER" = 1 ]; then
  WRK_HDRS=(-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            -H 'Accept-Encoding: gzip, deflate'
            -H 'Accept-Language: en-US,en;q=0.9')
fi

SOCK=/tmp/wm-floor-bench.sock
DUMMY=""
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  "$BIN" --unix "$SOCK" "${APP_ARGS[@]}" "${LOG_ARGS[@]}" 2>/tmp/wm-floor-srv.log & SRV=$!
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
  "$BIN" --port "$PORT" "${APP_ARGS[@]}" "${LOG_ARGS[@]}" 2>/tmp/wm-floor-srv.log & SRV=$!
fi
# wait: back-to-back runs must not race the dying listener for the port.
trap 'kill $SRV $DUMMY 2>/dev/null; wait $SRV 2>/dev/null; rm -rf "$WORK"' EXIT

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
# OPT-IN via SYSCALLS=1: counting needs perf, tracefs access and a
# paranoid setting most machines don't have lying around - a default
# that probes and warns on every run is noise for anyone not asking
# the question. Off, the column prints '-' and nothing is touched.
SYSC_PERF=""
if [ "${SYSCALLS:-0}" = 1 ]; then
  SYSC_PERF="${PERF:-}"
  if [ -z "$SYSC_PERF" ]; then
    if perf --version >/dev/null 2>&1; then SYSC_PERF=perf
    else SYSC_PERF=$(ls /usr/lib/linux-tools-*/perf 2>/dev/null | head -1); fi
  fi
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
  # Read from the config that built THIS binary - since the split there
  # are four, and portable's flags are not host's.
  case "$IMPL" in
    portable) CFLAGS_SRC=build_config_portable.rb ;;
    *)        CFLAGS_SRC=build_config_host.rb ;;
  esac
  CFLAGS_LINE=$(grep -o "'-O[^']*'.*" "$CFLAGS_SRC" 2>/dev/null | head -1 | tr -d "'\"" | tr '<' ' ' | tr -s ' ')
  echo "harness: wrk -t$THREADS -c$CONNS -d${DURATION}s impl=$IMPL transport=$TRANSPORT app=${APP:-none} browser=$BROWSER WM_BUNDLE=${WM_BUNDLE:-default} cflags=${CFLAGS_LINE:-?} $(uname -mr)"
  # The measuring condition, sampled NOW - loadavg would smear a whole
  # minute of history over it (a browser closed 40s ago still shows).
  # runnable/total is /proc/loadavg field 4: the scheduler's own
  # instantaneous count, no averaging. busy% is a 200ms /proc/stat
  # delta - wide enough to catch a compositor's frame cadence (~24
  # frames at 120Hz), short enough to be "now". ENV_NOTE names what no
  # sampler can (ENV_NOTE="plasma 4k120" ...); the desktop the numbers
  # are measured beside is part of every number.
  RUNQ=$(cut -d' ' -f4 /proc/loadavg)
  read -r _ U1 N1 S1 I1 IO1 IRQ1 SIRQ1 ST1 _REST < /proc/stat
  sleep 0.2
  read -r _ U2 N2 S2 I2 IO2 IRQ2 SIRQ2 ST2 _REST < /proc/stat
  BUSY=$(( (U2-U1)+(N2-N1)+(S2-S1)+(IRQ2-IRQ1)+(SIRQ2-SIRQ1)+(ST2-ST1) ))
  TOTAL=$(( BUSY + (I2-I1)+(IO2-IO1) ))
  [ "$TOTAL" -gt 0 ] && BUSYPCT=$((100*BUSY/TOTAL)) || BUSYPCT=0
  echo "env: runnable=$RUNQ busy=${BUSYPCT}% (200ms sample)${ENV_NOTE:+ note=$ENV_NOTE}"
  sysc_begin "$SRV" "$DURATION"
  S0=$(cpu_ticks "$SRV")
  snap_times
  C0=$(parse_child_cpu)
  if [ "$TRANSPORT" = unix ]; then
    WRK_UNIX="$SOCK" "$WRK" -t"$THREADS" -c"$CONNS" -d"${DURATION}"s --latency \
      "${WRK_HDRS[@]}" "http://127.0.0.1:$PORT/" >"$WORK/cli.out" 2>&1 &
  else
    "$WRK" -t"$THREADS" -c"$CONNS" -d"${DURATION}"s --latency \
      "${WRK_HDRS[@]}" "http://127.0.0.1:$PORT/" >"$WORK/cli.out" 2>&1 &
  fi
  CLI=$!
  wait "$CLI" 2>/dev/null
  snap_times
  C1=$(parse_child_cpu)
  S1=$(cpu_ticks "$SRV")
  WRKOUT=$(cat "$WORK/cli.out")
  echo "$WRKOUT" | grep -E "Requests/sec|50%|99%"
  sysc_wait
  NSYSC=$(sysc_read)
  NDONE=$(echo "$WRKOUT" | grep -o '[0-9]* requests in' | awk '{print $1}')
  if [ -n "$NSYSC" ] && [ "$NSYSC" -gt 0 ] && [ -n "$NDONE" ]; then
    awk -v d="$NDONE" -v n="$NSYSC" 'BEGIN { printf "req/syscall: %.1f (%d requests / %d server syscalls)\n", d / n, d, n }'
  fi
  # THE CLIENT MUST NOT BE THE BOTTLENECK - a conjunction, not a
  # comparison (bench/assets.sh already learned this the hard way): the
  # server had headroom AND the client was pegged. wrk lawfully spends
  # more total CPU than we do across THREADS threads; that alone is not
  # client-bound.
  SU=$((S1 - S0))
  SCPU=$((SU * 100 / HZ / DURATION))
  CCPU=$(awk -v a="$C1" -v b="$C0" -v d="$DURATION" 'BEGIN { printf "%.0f", (a - b) * 100 / d }')
  if [ "$SU" -gt 0 ] && [ "$SCPU" -lt 90 ] && [ "$CCPU" -ge $((THREADS * 90)) ]; then
    echo "REFUSED: the server had headroom (${SCPU}% of its core) while the client was pegged (${CCPU}% across $THREADS threads). This measures wrk, not webmachine. Raise THREADS, or drive the load from a second machine." >&2
    echo 1 > "$WORK/client_bound"
  else
    echo "server: ${SCPU}% of one core   client: ${CCPU}% across $THREADS threads"
    echo 0 > "$WORK/client_bound"
  fi
} | tee "$OUT"
# A failed or client-bound run writes nothing: the log holds only numbers
# that describe webmachine, never wrk. CLIENT_BOUND is read back from a
# file - the block above runs in tee's subshell, its own variables die
# with it.
CLIENT_BOUND=$(cat "$WORK/client_bound" 2>/dev/null || echo 0)
if [ "$CLIENT_BOUND" = 1 ]; then
  echo "run was client-bound - NOT recorded in $RESULTS" >&2
elif grep -q "Requests/sec" "$OUT" && ! grep -q "Requests/sec: *0\.00" "$OUT"; then
  cat "$OUT" >> "$RESULTS"
else
  echo "run measured nothing - NOT recorded in $RESULTS" >&2
fi
rm -f "$OUT"
