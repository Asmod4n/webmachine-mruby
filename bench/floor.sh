#!/bin/bash
# The floor: the reactor with the smallest answer there is. Its number
# is the ceiling every later layer is measured against, so the harness
# line is part of the result - CONNS is mandatory, never a silent
# default (three separate debugging days in the old tree came from
# silently differing harnesses).
#
# It said "raw reactor, no HTTP" until this line was written, and that
# had been false since 0fdc90a: a server with nothing to serve refuses
# to start, so this script could not run without an app at all and said
# only "server died". bintest/floor.rb learned that and carries its own
# smallest resource; this did not, and was left behind for 132 commits.
# The number that is genuinely free of HTTP is bench/echo.sh.
#
# One thread each end by default. THREADS=N gives the server N answering
# threads; CLIENT_WORKERS=M drives it with M htgen processes. The harness
# line carries both, so a number always says which shape it came from.
#
# One generator, htgen. wrk and h2load are gone from this tree - the
# machine that measures does not have them installed any more, and a
# script that names a tool nobody can run is a script that lies about
# how its numbers were made.
#
#   CONNS=400 bench/floor.sh                      # AF_UNIX (default)
#   CONNS=400 TRANSPORT=tcp bench/floor.sh
#   IMPL=pgo ...       the same flags as host plus -fprofile-use, so the
#                      A/B against IMPL=uring is PGO and nothing else
#   IMPL=portable ...  REFUSED. 0b0b11d removed build_config_portable.rb,
#                      so this named a binary nobody can produce - the
#                      exact failure this file's header forbids.
#   APP=bench/apps/hello.rb ...  bind a resource (konst or runtime tier)
#   REQPATH=/cpp ...   which route to ask for, when the app has several
#   PIPELINE=8 ...     h1 requests in flight per connection (RFC 9112 9.3.2)
#   WM_BUNDLE=0 ...    for the A/B on a kernel under suspicion
set -u
# htgen registers its buffer ring as locked memory, 8 MiB per process,
# and the server's rings are charged to the same user. The server raises
# its own soft limit to the hard one; the clients run under the shell's.
# So the shell's goes up as well, and the line says what stands.
memlock_hard=$(ulimit -H -l)
ulimit -l "$memlock_hard" 2>/dev/null || true
MEMLOCK_LINE="memlock=$(ulimit -l)"
[ -n "${CONNS:-}" ] || {
  echo "CONNS= is mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
TRANSPORT="${TRANSPORT:-unix}"
PORT="${PORT:-8123}"
IMPL="${IMPL:-uring}"
# WORKERS= is gone. Nothing in this tree forks but logd, and the server
# is one process with THREADS answering threads. Refused rather
# than ignored, as THREADS= above: a silently dropped harness knob is
# how a number ends up describing a run nobody performed.
[ -z "${WORKERS:-}" ] || {
  echo "WORKERS= is gone: the server is one process. Use THREADS=N for N answering threads." >&2
  exit 2
}
# CLIENT_WORKERS=N: N htgen processes, each with CONNS connections of its
# own. Processes and not threads, and the server decides that: over
# AF_UNIX a peer has no address, so SO_PEERCRED's pid is its name and the
# acceptor derives the answering thread from it (ring.hpp worker_of_pid).
# Threads inside one htgen would share one pid and meet one answering
# thread, however many of them there were.
# htgen is one ring and one thread, so one of them cannot fill more than
# one server worker. The counts and the cpu of all N are added up, and
# the responses= line reports the sum.
CLIENT_WORKERS="${CLIENT_WORKERS:-1}"
# THREADS=N: one server with --threads=N. One thread accepts and
# hands every peer to one of N answering threads through
# IORING_OP_MSG_RING, which carries a registered descriptor between two
# rings of one process. This is the only shape: nothing in this tree
# forks but logd.
#
# Which thread is not a turn. The acceptor reads the peer's name first -
# SO_PEERCRED for AF_UNIX, SOCKET_URING_OP_GETSOCKNAME for TCP - and
# derives the thread from it (ring.hpp on_peer_name), so one client meets
# one answering thread and one VM for every connection it makes. Peers go
# to the threads in turn only where that name cannot be read, and the
# error log says so once when it happens.
#
# An application runs here. Each answering thread holds its own ring, its
# own app and its own VM (server.cpp answer_threads_start). This comment
# said "files only, a thread that answers from an application has no VM"
# until 2026-09-17; a server started with --threads=2 and an app answers
# 200 with the app's own body, so the line was wrong.
THREADS="${THREADS:-1}"
# DOCROOT=DIR: serve files from this directory and load no application.
# The file path is the only one --threads answers on, so a comparison
# that includes the thread shape is a comparison on this path.
DOCROOT="${DOCROOT:-}"
# The smallest resource in the tree: one route, one baked body. h2.sh,
# pipeline.sh and profile.sh all default to it; this one was the odd
# script out. APP= with nothing after it still means no app, and the
# check below says what that costs rather than letting the server die
# with a message about a flag the caller never saw.
[ -n "$DOCROOT" ] || APP="${APP-bench/apps/hello.rb}"
[ -n "${APP:-}" ] || [ -n "$DOCROOT" ] || {
  echo "APP= and no DOCROOT= leaves the server nothing to serve, and it refuses to start." >&2
  echo "Name one, or drop APP= to take bench/apps/hello.rb." >&2
  echo "For a number with no HTTP in it at all, bench/echo.sh is that bench." >&2
  exit 2
}
# BIN=path names the binary directly, for an A/B between two builds of the
# same impl: keep both, alternate them, and the harness line records which
# one ran. Without it the only way to compare two builds was to copy one
# over the other between runs, which leaves no trace in the log.
BIN="${BIN:-}"
if [ -z "$BIN" ]; then
  case "$IMPL" in
    uring) BIN=mruby/build/host/bin/webmachine-server ;;
    pgo) BIN=mruby/build/pgo/bin/webmachine-server ;;
    portable)
      echo "IMPL=portable is gone with build_config_portable.rb (0b0b11d)." >&2
      echo "It would have run mruby/build/portable/bin/webmachine-server, which" >&2
      echo "no config in this tree builds. Use IMPL=uring or IMPL=pgo." >&2
      exit 2
      ;;
    *) echo "IMPL must be uring or pgo" >&2; exit 2 ;;
  esac
  cd "$(dirname "$0")/.." || exit 1
else
  cd "$(dirname "$0")/.." || exit 1
  IMPL="bin:$(basename "$BIN")"
fi
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

# PROTO=h1 (default) | h2, both spoken by the same client.
PROTO="${PROTO:-h1}"
# REQPATH names the route to ask for. The default is the only path a
# splat app has; an app with several resources (examples/cpp_resource.rb)
# is A/B'd by pointing this at one of them and then the other.
REQPATH="${REQPATH:-/}"
MULTI="${MULTI:-1}"
# PIPELINE=D: h1 requests in flight per connection (RFC 9112 9.3.2).
# bench/pipeline.sh is the script that sweeps it; here it is one knob so
# a floor number can be taken at depth without a second harness.
PIPELINE="${PIPELINE:-1}"
# htgen used to live here as bench/load. It is its own tool now
# (github.com/Asmod4n/htgen) - a load generator is not part of an HTTP
# state model, and it was building against this tree's build directory,
# which tied a measuring instrument to the thing it measures.
# $HOME is not where the trees are on every machine: this container's is
# /root while both this repo and htgen sit under /home/user, so the
# generator was "not found" with the binary right beside the checkout.
# Look there too - a clone next to this one is the ordinary layout - and
# then on PATH.
# The bench owns the machine while it runs; see bench/priority.sh.
. "$(dirname "$0")/priority.sh"
bench_priority
. "$(dirname "$0")/htgen.sh"
. "$(dirname "$0")/_app.sh"
HTGEN=$(bench_htgen) || exit 1
[ -z "${CLIENT:-}" ] || {
  echo "CLIENT= is gone: htgen is the only generator this tree measures with." >&2
  echo "A path goes in HTGEN=." >&2
  exit 2
}
case "$PROTO" in
  h1) ;;
  h2) ;;
  *) echo "PROTO must be h1 or h2" >&2; exit 2 ;;
esac
if [ "$PROTO" = h1 ] && [ "$MULTI" != 1 ]; then
  echo "MULTI needs PROTO=h2 - h1 multiplexes with PIPELINE, not streams" >&2
  exit 2
fi
if [ "$PROTO" = h2 ] && [ "$PIPELINE" != 1 ]; then
  echo "PIPELINE is h1's (RFC 9112 9.3.2) - h2 has MULTI" >&2
  exit 2
fi

# The client must not be the bottleneck - the same refusal bench/assets.sh
# already has, ported here: a number where the client burned as much CPU
# as the server describes the client, not webmachine. cpu_ticks reads the server's own
# /proc/pid/stat (utime+stime), never system-wide - see snap_times below
# for the client's side.
# utime and stime separately, because their ratio is the question this
# harness could not answer: on AF_UNIX the kernel bills a copy to the
# process that called send, so a client that "does almost nothing" still
# pays for moving every response byte. A client that is mostly sys is
# the socket; a client that is mostly user is its own loop.
cpu_ticks_of() {
  awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[12] + f[13] }' \
    "$1" 2>/dev/null || echo 0
}
cpu_ticks() {
  awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[12], f[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo "0 0"
}
srv_ticks() {
  cpu_ticks "$SRV"
}
# The same ticks, one line per thread: tid, name, utime+stime. The sum
# over the threads is what srv_ticks reads, and the sum is what hides
# the question this answers. Two answering threads that read 91 percent
# together did not do 45 percent each: one worked and one waited, and
# only the split says so. The server spreads an AF_UNIX peer by the
# client's pid, so which thread gets the load is decided per run.
#
# Read at the start and at the end. A thread that lived for both is
# matched by its tid; one that came or went in between is left out and
# the line says how many that was.
srv_thread_ticks() {
  for st_task in /proc/"$SRV"/task/*; do
    [ -d "$st_task" ] || continue
    st_tid=${st_task##*/}
    st_who=$(tr -d '\n' < "$st_task/comm" 2>/dev/null) || continue
    st_t=$(cpu_ticks_of "$st_task/stat") || continue
    printf '%s %s %s\n' "$st_tid" "${st_who:-?}" "$st_t"
  done
}
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
# The whole machine's busy ticks, all cores, from /proc/stat's first line.
# The env: line above samples 200ms before the run; this one is read
# across the run itself, because what a ten-second run competed with is
# not what the 200ms before it looked like.
machine_busy() {
  awk 'NR==1 { print $2+$3+$4+$7+$8+$9 }' /proc/stat
}
WORK=$(mktemp -d)
bench_config "$WORK"
# Split like sysc_wait: the wait must run in the shell that backgrounded
# the client (a $() subshell is not its parent), only the read below may fork.
snap_times() { times > "$WORK/.times"; }

# Which cpu each server thread last ran on, and what kind of cpu that
# is. A part whose cores differ - an efficiency cluster beside two
# performance cores, or two chiplets with an L3 each - answers a
# different number depending on where the scheduler put the threads,
# and nothing else in the row says where that was. Field 39 of
# /proc/<tid>/stat is the cpu the thread last ran on.
#
# Read at the end of the run, so it names where the threads finished,
# not where they started. Nothing is pinned, so a thread may have moved.
#
# Each entry carries two clocks, now over max: scaling_cur_freq at the
# instant of the sample, and cpuinfo_max_freq. Max alone says what the
# core can do, and a core held back by heat looks in the line exactly
# like a core that was never fast. On a machine with one fan that
# difference is larger than anything this tree has changed in the code,
# so the row states it. cpu= in the build line does not answer it: that
# reads cpu0 out of /proc/cpuinfo, once, before the run, from a core the
# run need not have used.
#
# Each entry names the thread as well, from /proc/<tid>/comm. Which
# thread sat where is the whole question on a part with two kinds of
# core: an answering thread on a slow core decides the rate, an idle
# io-wq worker beside it decides nothing. The kernel's own io-wq
# workers are called iou-wrk-<pid> and nobody in this tree starts them.
#
# Linux only. Field 39 of /proc/<tid>/stat, cpufreq/cpuinfo_max_freq and
# topology/thread_siblings_list are Linux's, and a kernel may be built
# without the last two. Where a part cannot be read the field says so
# rather than printing nothing: an empty field reads as "the threads ran
# nowhere", which is a lie about the machine.
PLACEMENT_NONE="unreadable (needs Linux /proc/<tid>/stat)"
# Where the clients ran. On a machine with fast and slow cores this
# matters as much as the server's placement: a client on a P core
# finishes early and reports headroom the server does not have, and the
# row then looks server-bound when it is only slow-core-bound. It has to
# be read while the clients live, so both samples are taken mid-run.
cli_placement() {
  cp_out=""
  for cp_pid in "${CLIS[@]}"; do
    for cp_task in /proc/"$cp_pid"/task/*; do
      [ -d "$cp_task" ] || continue
      cp_cpu=$(awk '{ print $39 }' "$cp_task/stat" 2>/dev/null) || continue
      [ -n "$cp_cpu" ] || continue
      cp_max=$(cat "/sys/devices/system/cpu/cpu$cp_cpu/cpufreq/cpuinfo_max_freq" 2>/dev/null || echo "")
      cp_smt=$(cat "/sys/devices/system/cpu/cpu$cp_cpu/topology/thread_siblings_list" 2>/dev/null || echo "?")
      cp_now=$(cat "/sys/devices/system/cpu/cpu$cp_cpu/cpufreq/scaling_cur_freq" 2>/dev/null || echo "")
      cp_who=$(tr -d '\n' < "$cp_task/comm" 2>/dev/null || echo "?")
      cp_out="$cp_out ${cp_who:-?}:cpu$cp_cpu[${cp_now:-?}/${cp_max:-?}kHz,smt$cp_smt]"
    done
  done
  [ -n "$cp_out" ] || cp_out=" $PLACEMENT_NONE"
  printf '%s' "${cp_out# }"
}

srv_placement() {
  sp_out=""
  for sp_task in /proc/"$SRV"/task/*; do
    [ -d "$sp_task" ] || continue
    sp_cpu=$(awk '{ print $39 }' "$sp_task/stat" 2>/dev/null) || continue
    [ -n "$sp_cpu" ] || continue
    sp_max=$(cat "/sys/devices/system/cpu/cpu$sp_cpu/cpufreq/cpuinfo_max_freq" 2>/dev/null || echo "")
    sp_smt=$(cat "/sys/devices/system/cpu/cpu$sp_cpu/topology/thread_siblings_list" 2>/dev/null || echo "?")
    sp_now=$(cat "/sys/devices/system/cpu/cpu$sp_cpu/cpufreq/scaling_cur_freq" 2>/dev/null || echo "")
    sp_who=$(tr -d '\n' < "$sp_task/comm" 2>/dev/null || echo "?")
    sp_out="$sp_out ${sp_who:-?}:cpu$sp_cpu[${sp_now:-?}/${sp_max:-?}kHz,smt$sp_smt]"
  done
  [ -n "$sp_out" ] || sp_out=" $PLACEMENT_NONE"
  printf '%s' "${sp_out# }"
}
# times(1) line 2 is the children's user and sys - the same split as
# above, from the other side.
parse_child_cpu() {
  awk 'NR==2 { split($1, u, "m"); split($2, sy, "m");
               printf "%.2f %.2f", u[1]*60 + u[2], sy[1]*60 + sy[2] }' "$WORK/.times"
}

LOG="${LOG:-0}"
LOG_ARGS=()
[ "$LOG" = 1 ] && LOG_ARGS=(--log="$WORK/access.log")

# BROWSER=1 sends what a browser sends. It is not decoration: Accept,
# Accept-Encoding and Accept-Language are three of the eight headers
# that clear ReqFacts::plain, and a plain request never walks the flow
# tree at all - flow::answer returns the konst status on its first
# branch. A bare generator request carries none of them, so a number
# taken without BROWSER=1 measures the path a browser never takes.
# PIN="0 2": the server on the first cpu, the client on the second. The
# priority is not this knob's - bench/priority.sh takes -10 for the whole
# run, and the children inherit it. Not a default - pinning the server's
# ring was refused on measurement, and this is not that: it pins the two
# processes apart so they
# stop trading one core, which is what a machine with few cores does to a
# number. Whether it helps is a property of the machine, so the harness
# line records it and bench/ratchet.sh decides from the spread.

PIN="${PIN:-}"
SRV_PIN=()
CLI_PIN=()
if [ -n "$PIN" ]; then
  read -r SRV_CPU CLI_CPU <<<"$PIN"
  [ -n "${CLI_CPU:-}" ] || { echo "PIN wants two cpus, like PIN='0 2'" >&2; exit 2; }
  command -v taskset >/dev/null || { echo "PIN needs taskset (util-linux)" >&2; exit 2; }
  SRV_PIN=(taskset -c "$SRV_CPU")
  CLI_PIN=(taskset -c "$CLI_CPU")
else
  # The bench takes the cpus its caller does not hold. An agent that
  # works in this tree puts its own processes on one cpu, so its builds
  # and greps stay out of a measurement. A child of that shell inherits
  # the one cpu, and the bench is such a child: a server on the agent's
  # cpu measures the agent as well.
  #
  # So the run asks which cpus this shell holds, and takes the rest. It
  # is not the PIN knob: the two processes still share every cpu they
  # get, and the scheduler still places them.
  ALL_CPUS=$(getconf _NPROCESSORS_CONF 2>/dev/null || echo 1)
  if [ "$ALL_CPUS" -gt 1 ] && command -v taskset >/dev/null; then
    MINE=",$(taskset -pc $$ 2>/dev/null | sed 's/.*list: //' |
             awk -F, '{for (i = 1; i <= NF; i++) {
                         n = index($i, "-")
                         if (n) { for (c = substr($i, 1, n - 1) + 0; c <= substr($i, n + 1) + 0; c++) printf "%d,", c }
                         else printf "%d,", $i + 0 } }')"
    FREE=""
    c=0
    while [ "$c" -lt "$ALL_CPUS" ]; do
      case "$MINE" in *",$c,"*) ;; *) FREE="$FREE,$c" ;; esac
      c=$((c + 1))
    done
    FREE="${FREE#,}"
    if [ -n "$FREE" ]; then
      SRV_PIN=(taskset -c "$FREE")
      CLI_PIN=(taskset -c "$FREE")
      FREE_LINE="$FREE"
    fi
  fi
fi

BROWSER="${BROWSER:-0}"
CLI_HDRS=()
if [ "$BROWSER" = 1 ]; then
  CLI_HDRS=(--header 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            --header 'Accept-Encoding: gzip, deflate'
            --header 'Accept-Language: en-US,en;q=0.9')
fi

SOCK="$WORK/bench.sock"
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  bench_app "$WORK" "{ unix_path: \"$SOCK\" }"
  BIND_ARGS=(--unix="$SOCK")
  BIND_ARGS_KEEP=(--unix="$SOCK")
else
  bench_app "$WORK" "{ port: $PORT }"
  BIND_ARGS=(--port="$PORT")
  BIND_ARGS_KEEP=(--port="$PORT")
fi
# An app names its own listener, and the server refuses a second one on
# the command line. bench_app wrote the one above into the app source.
[ -z "$DOCROOT" ] || APP_ARGS=(--docroot="$DOCROOT")
[ ${#APP_ARGS[@]} -eq 0 ] || BIND_ARGS=()
[ -z "$DOCROOT" ] || BIND_ARGS=("${BIND_ARGS_KEEP[@]}")
# One is the default and the flag then changes nothing, so it is not
# passed. BIN= exists to run an older build beside this one, and an
# older build refuses a flag it never had.
SHAPE_ARGS=()
[ "$THREADS" = 1 ] || SHAPE_ARGS+=(--threads="$THREADS")
"${SRV_PIN[@]}" "$BIN" "${CONF_ARGS[@]}" "${BIND_ARGS[@]}" "${APP_ARGS[@]}" "${LOG_ARGS[@]}" \
  "${SHAPE_ARGS[@]}" >>"$WORK/srv.log" 2>&1 &
SRV=$!
# wait: back-to-back runs must not race the dying listener for the port.
trap 'kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; rm -rf "$WORK"' EXIT

# --- requests per syscall -------------------------------------------
# The point of a ring server is syscall amortization - one enter
# carries a whole batch of rounds - and this makes it a number: the
# server's syscalls over the run (raw_syscalls:sys_enter, a counting
# tracepoint: no sampling, negligible overhead), divided into the
# requests the client completed. The window is the client's run plus
# edges; an idle server sits blocked in one enter, so edges add
# ~nothing. Needs a perf that may attach (root, or CAP_PERFMON /
# perf_event_paranoid low enough for tracepoints); without one the
# column prints '-' rather than a guess.
# Opt-in via SYSCALLS=1: counting needs perf, tracefs access and a
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
  # On failure, relay perf's own words - there are two separate locks
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
# Split like snap_times, for the same reason: the wait must run in the
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
kill -0 "$SRV" 2>/dev/null || { echo "server died:"; cat "$WORK/srv.log"; exit 1; }
grep -q "select(2) shim" "$WORK/srv.log" 2>/dev/null && {
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
  # Read from the config that built this binary. pgo's -O and -march are
  # host's; what it adds is -fprofile-use, which the IMPL field already
  # says.
  CFLAGS_SRC=build_config_host.rb
  CFLAGS_LINE=$(grep -o "'-O[^']*'.*" "$CFLAGS_SRC" 2>/dev/null | head -1 | tr -d "'\"" | tr '<' ' ' | tr -s ' ')
  # The config spells -march through a variable so a host that migrates
  # can pin it (WM_MARCH); the LOG has to say which ISA, not which shell
  # expression, or every line after this reads the same for two builds
  # that are not the same.
  # native is not an ISA. This tree is built in containers that are
  # scheduled onto hosts that differ, so native resolved to
  # sapphirerapids with avx512 in one session and to something else in
  # the next - and both rows said "native", which is the failure the
  # paragraph above exists to stop. Ask the compiler what it picked.
  if [ "${WM_MARCH:-native}" = native ]; then
    MARCH_REAL=$("${CC:-cc}" -march=native -Q --help=target 2>/dev/null |
                 awk '$1 == "-march=" { print $2; exit }')
    MARCH_LINE="native:${MARCH_REAL:-unreadable}"
  else
    MARCH_LINE="$WM_MARCH"
  fi
  CFLAGS_LINE=${CFLAGS_LINE//\$\{march\}/$MARCH_LINE}
  CFLAGS_LINE=${CFLAGS_LINE//#\{march\}/$MARCH_LINE}
  # Which htgen - not just "htgen". A stale binary earlier in PATH than
  # the one just built is invisible otherwise, and the number it produces
  # looks exactly like the number the new one would have produced.
  CLI_LINE="$HTGEN($(bench_htgen_version "$HTGEN")) -c$CONNS -d${DURATION}s $PROTO"
  # Said only when it is true: bench/priority.sh is a no-op on a machine
  # whose user may not take -10, and a row must not claim a priority it
  # did not have.
  NICE_LINE=""
  [ "${BENCH_NICE:-0}" = 1 ] && NICE_LINE=" nice=-15"
  [ "$PROTO" = h2 ] && CLI_LINE="$CLI_LINE -m$MULTI"
  [ "$PIPELINE" != 1 ] && CLI_LINE="$CLI_LINE -p$PIPELINE"
  CLI_LINE="$CLI_LINE (one ring, one thread)"
  echo "harness: $CLI_LINE impl=$IMPL threads=$THREADS clients=$CLIENT_WORKERS $MEMLOCK_LINE${PIN:+ pin="$PIN"}${FREE_LINE:+ cpus="$FREE_LINE"}$NICE_LINE transport=$TRANSPORT app=${APP:-none} docroot=${DOCROOT:-none} path=$REQPATH browser=$BROWSER WM_BUNDLE=${WM_BUNDLE:-default} cflags=${CFLAGS_LINE:-?} $(uname -mr)"
  # cflags above is what the config asks for; this is what the binary was
  # actually built with and what it will load. A host that updated its
  # packages between two runs changes the second and not the first.
  . bench/buildline.sh
  wm_build_line "$BIN"
  # The measuring condition, sampled now - loadavg would smear a whole
  # minute of history over it (a browser closed 40s ago still shows).
  # runnable/total is /proc/loadavg field 4: the scheduler's own
  # instantaneous count, no averaging. busy% is a 200ms /proc/stat
  # delta - wide enough to catch a compositor's frame cadence (~24
  # frames at 120Hz), short enough to be "now". ENV_NOTE names what no
  # sampler can (ENV_NOTE="plasma 4k120" ...); the desktop the numbers
  # are measured beside is part of every number.
  #
  # Read runnable=N/M against this machine's own quiet floor, never
  # against zero. M is every thread that exists, and a desktop keeps
  # far more of them than the desktop shows: forgecore idles at ~865
  # with nothing running but a Plasma session, part of which is a
  # display manager holding a second VT (an Xorg greeter on tty2, as
  # root, which `ps x` does not list for you). That number is not load,
  # it is the floor to subtract. N is the part that competes.
  # The browser is the one thing worth closing by hand: a Firefox with
  # its content processes took a fifth of the server's core here, and a
  # fifth off the answer is not noise that averages out over runs - it
  # is a different number. Runs made with it open and closed sit in
  # bench/results/ next to each other and do not agree.
  RUNQ=$(cut -d' ' -f4 /proc/loadavg)
  read -r _ U1 N1 S1 I1 IO1 IRQ1 SIRQ1 ST1 _REST < /proc/stat
  sleep 0.2
  read -r _ U2 N2 S2 I2 IO2 IRQ2 SIRQ2 ST2 _REST < /proc/stat
  BUSY=$(( (U2-U1)+(N2-N1)+(S2-S1)+(IRQ2-IRQ1)+(SIRQ2-SIRQ1)+(ST2-ST1) ))
  TOTAL=$(( BUSY + (I2-I1)+(IO2-IO1) ))
  [ "$TOTAL" -gt 0 ] && BUSYPCT=$((100*BUSY/TOTAL)) || BUSYPCT=0
  echo "env: runnable=$RUNQ busy=${BUSYPCT}% (200ms sample)${ENV_NOTE:+ note=$ENV_NOTE}"
  sysc_begin "$SRV" "$DURATION"
  read -r SU0 SS0 <<<"$(srv_ticks)"
  srv_thread_ticks > "$WORK/thr0"
  M0=$(machine_busy)
  snap_times
  read -r CU0 CS0 <<<"$(parse_child_cpu)"
  # One ring, one thread - the same shape as the reactor it drives.
  HTGEN_SHAPE=()
  [ "$PROTO" = h2 ] && HTGEN_SHAPE=(--h2 --streams "$MULTI")
  [ "$PIPELINE" != 1 ] && HTGEN_SHAPE=(--pipeline "$PIPELINE")
  # LATENCY=1: the client times every answer and prints one line of
  # percentiles beside the counts. It costs two clock reads per answer,
  # so a rate taken with it is not a rate taken without it - read the
  # two from separate runs. htgen refuses it with --pipeline above 1,
  # because a batch carries one timestamp for all of its answers.
  # METHOD=POST BODY_FILE=path: an upload instead of a GET. It is the
  # only shape that walks the body path - the spill file, its writes
  # through the ring, and the reader that fills it - and no other knob
  # here reaches that code at all.
  [ -n "${METHOD:-}" ] && HTGEN_SHAPE+=(--method "$METHOD")
  [ -n "${BODY_FILE:-}" ] && HTGEN_SHAPE+=(--body-file "$BODY_FILE")
  if [ "${LATENCY:-0}" = 1 ]; then
    if [ "$PIPELINE" != 1 ]; then
      echo "LATENCY=1 needs PIPELINE=1: a batch has one timestamp for every answer in it" >&2
      exit 2
    fi
    HTGEN_SHAPE+=(--latency)
  fi
  CLIS=()
  n=0
  while [ "$n" -lt "$CLIENT_WORKERS" ]; do
    if [ "$TRANSPORT" = unix ]; then
      "${CLI_PIN[@]}" "$HTGEN" --sock "$SOCK" --conns "$CONNS" --seconds "$DURATION" \
        --path "$REQPATH" "${HTGEN_SHAPE[@]}" "${CLI_HDRS[@]}" >"$WORK/cli.$n" 2>&1 &
    else
      "${CLI_PIN[@]}" "$HTGEN" --host 127.0.0.1 --port "$PORT" --conns "$CONNS" \
        --seconds "$DURATION" --path "$REQPATH" "${HTGEN_SHAPE[@]}" "${CLI_HDRS[@]}" \
        >"$WORK/cli.$n" 2>&1 &
    fi
    CLIS+=($!)
    n=$((n + 1))
  done
  CLI=${CLIS[0]}
  # One sample of both ends, halfway through. It names where each
  # thread ran at that instant and not where it spent the run: the
  # scheduler moves them, and a row that shows one placement while the
  # rate came from another is why this is a hint and not a gate.
  (
    sleep $(( (DURATION + 1) / 2 ))
    { cli_placement; printf '\n'; srv_placement; } > "$WORK/place" 2>/dev/null
  ) &
  for p in "${CLIS[@]}"; do wait "$p" 2>/dev/null; done
  # A client that ended without its responses= line measured nothing, and
  # a sum over the others would say the machine did what those few did.
  # Every such client is shown and the run ends.
  n=0
  failed=0
  while [ "$n" -lt "$CLIENT_WORKERS" ]; do
    if ! grep -q '^responses=' "$WORK/cli.$n"; then
      echo "client $n ended without a result:" >&2
      cat "$WORK/cli.$n" >&2
      failed=1
    fi
    n=$((n + 1))
  done
  [ "$failed" = 0 ] || exit 1
  # One responses= line out of N, with the counts and the rates added.
  # bad= is summed as well: a client that failed must not hide behind
  # one that did not.
  cat "$WORK"/cli.* > "$WORK/cli.all"
  if [ "$CLIENT_WORKERS" != 1 ]; then
    awk '/^responses=/ {
           for (i = 1; i <= NF; i++) {
             split($i, kv, "=")
             k = kv[1]; v = kv[2]
             if (k == "responses" || k == "bad" || k == "rps" || k == "bytes" ||
                 k == "MB/s" || k == "conns" || k == "tx_bytes" || k == "tx_MB/s") sum[k] += v
             else keep[k] = v
             if (!(k in seen)) { seen[k] = 1; ord[++m] = k }
           }
         }
         END { line = ""
               for (i = 1; i <= m; i++) { k = ord[i]
                 v = (k in sum) ? sum[k] : keep[k]
                 line = line (i > 1 ? " " : "") k "=" v }
               print line }' "$WORK/cli.all" > "$WORK/cli.out"
  else
    cp "$WORK/cli.all" "$WORK/cli.out"
  fi
  snap_times
  M1=$(machine_busy)
  read -r CU1 CS1 <<<"$(parse_child_cpu)"
  read -r SU1 SS1 <<<"$(srv_ticks)"
  srv_thread_ticks > "$WORK/thr1"
  CLI_PLACEMENT=$(sed -n '1p' "$WORK/place" 2>/dev/null)
  PLACEMENT=$(sed -n '2p' "$WORK/place" 2>/dev/null)
  [ -n "$PLACEMENT" ] || PLACEMENT=$(srv_placement)
  CLIOUT=$(cat "$WORK/cli.out")
  echo "$CLIOUT" | grep -E "^responses="
  echo "$CLIOUT" | grep -E "^latency_us" || true
  sysc_wait
  NSYSC=$(sysc_read)
  NDONE=$(echo "$CLIOUT" | grep -o 'responses=[0-9]*' | cut -d= -f2)
  if [ -n "$NSYSC" ] && [ "$NSYSC" -gt 0 ] && [ -n "$NDONE" ]; then
    awk -v d="$NDONE" -v n="$NSYSC" 'BEGIN { printf "req/syscall: %.1f (%d requests / %d server syscalls)\n", d / n, d, n }'
  fi
  # The client must not be the bottleneck - a conjunction, not a
  # comparison (bench/assets.sh already learned this the hard way): the
  # server had headroom and the client was pegged. Each end may run
  # several threads, so "pegged" is one core per thread: the two
  # numbers are divided by the thread count of their own side before
  # they are compared. THREADS=3 CLIENT_WORKERS=3 with the client at
  # 230 percent is 77 percent per worker, which has room, and the same
  # 230 against one worker is over its limit.
  #
  # The server's divisor is THREADS, the threads this bench started.
  # The io-wq workers the kernel adds are not counted, so a server that
  # reads files looks busier per thread than it is. That error refuses
  # fewer runs, never more.
  # Headroom is a gap, not "below 90". The rule refused a run where the
  # server sat at 89 and the client at 90 - one point apart, inside the
  # noise of a percentage derived from /proc over the run, and with no
  # headroom to speak of. What it must catch is the case the number
  # lies about: the client at its limit while the server has real room
  # left. So the client must be pegged and the server at least
  # kHeadroom points below it.
  SU=$(( (SU1 - SU0) + (SS1 - SS0) ))
  SCPU=$((SU * 100 / HZ / DURATION))
  SUPCT=$(( (SU1 - SU0) * 100 / HZ / DURATION ))
  SSPCT=$(( (SS1 - SS0) * 100 / HZ / DURATION ))
  CCPU=$(awk -v a="$CU1" -v b="$CU0" -v c="$CS1" -v e="$CS0" -v d="$DURATION" \
    'BEGIN { printf "%.0f", (a - b + c - e) * 100 / d }')
  CUPCT=$(awk -v a="$CU1" -v b="$CU0" -v d="$DURATION" 'BEGIN { printf "%.0f", (a - b) * 100 / d }')
  CSPCT=$(awk -v a="$CS1" -v b="$CS0" -v d="$DURATION" 'BEGIN { printf "%.0f", (a - b) * 100 / d }')
  HEADROOM=15
  SPER=$((SCPU / THREADS))
  CPER=$((${CCPU%.*} / CLIENT_WORKERS))
  if [ "$SU" -gt 0 ] && [ "$CPER" -ge 90 ] && [ "$SPER" -le $((CPER - HEADROOM)) ]; then
    echo "REFUSED: the server had headroom (${SPER}% of a core per thread, ${SCPU}% over ${THREADS} (${SUPCT}u/${SSPCT}s), ${HEADROOM}+ points under the client's ${CPER}% per worker, ${CCPU}% over ${CLIENT_WORKERS} (${CUPCT}u/${CSPCT}s)) while the client was pegged. This measures the client, not webmachine. Drive the load from a second machine." >&2
    echo 1 > "$WORK/client_bound"
  else
    # What else ran. Same unit as the two numbers beside it, so a run
    # that came out low can be read at a glance: the machine was busy
    # with something, or it was not and the answer is elsewhere.
    #
    # A hint, and deliberately not a gate. Most of what lands here on a
    # loaded run is the bench's own doing: ~9M AF_UNIX messages a
    # second is softirq that neither process pays for out of its utime,
    # so a perfectly healthy -c16 run reports other: 12-14%. A
    # threshold on this number would refuse exactly those runs and wave
    # through a quiet -m1 run with a browser open beside it. The two
    # are not separable here - separating them is the reader's job,
    # with runnable= above and the knowledge of what was closed.
    OTHER=$(awk -v m0="$M0" -v m1="$M1" -v hz="$HZ" -v d="$DURATION" -v sc="$SCPU" -v cc="$CCPU" \
      'BEGIN { o = (m1 - m0) * 100 / hz / d - sc - cc; printf "%.0f", o < 0 ? 0 : o }')
    echo "server: ${SCPU}% of one core (${SUPCT}u/${SSPCT}s)   client: ${CCPU}% of one core (${CUPCT}u/${CSPCT}s)   other: ${OTHER}% of one core"
    echo "threads: server ${PLACEMENT:-$PLACEMENT_NONE}   client ${CLI_PLACEMENT:-$PLACEMENT_NONE}"
    # What each server thread itself burned, so a run that left a thread
    # waiting is read and not derived from the sum above.
    awk -v hz="$HZ" -v d="$DURATION" '
      NR == FNR { was[$1] = $3; name[$1] = $2; next }
      { if ($1 in was) { pct[$1] = ($3 - was[$1]) * 100 / hz / d; name[$1] = $2 }
        else { came++ } }
      END { line = ""
            for (t in pct) line = line sprintf(" %s/%s %.0f%%", name[t], t, pct[t])
            if (line == "") { print "per thread: unreadable"; exit }
            printf "per thread:%s%s\n", line, (came ? sprintf("  (%d thread(s) started during the run)", came) : "") }' \
      "$WORK/thr0" "$WORK/thr1"
    echo 0 > "$WORK/client_bound"
  fi
} | tee "$OUT"
# A failed or client-bound run writes nothing: the log holds only numbers
# that describe webmachine, never the client. CLIENT_BOUND is read back from a
# file - the block above runs in tee's subshell, its own variables die
# with it.
CLIENT_BOUND=$(cat "$WORK/client_bound" 2>/dev/null || echo 0)
if [ "$CLIENT_BOUND" = 1 ]; then
  echo "run was client-bound - not recorded in $RESULTS" >&2
elif grep -q "^responses=" "$OUT" && grep -q "bad=[1-9]" "$OUT"; then
  # bad counts refused streams, non-2xx answers and HPACK desync. A run
  # that hit any of those measured a server in trouble, not its floor.
  echo "run had errors (bad != 0) - not recorded in $RESULTS" >&2
elif { grep -q "Requests/sec" "$OUT" && ! grep -q "Requests/sec: *0\.00" "$OUT"; } ||
     { grep -q "^responses=" "$OUT" && ! grep -q "rps=0 " "$OUT"; }; then
  cat "$OUT" >> "$RESULTS"
else
  echo "run measured nothing - not recorded in $RESULTS" >&2
fi
rm -f "$OUT"
