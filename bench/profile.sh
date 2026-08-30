#!/bin/bash
# Two questions, two modes - and they are not interchangeable.
#
# DIFF (default): where does the h2-vs-h1 gap go? Records ONE matched
# pair - the h1 anchor and h2 -m1, same duration, same pinning, same
# run - and diffs them, so the delta is read off relative sample share
# per symbol instead of guessed at from req/s.
#
# LOAD (MULTI=32): where does h2 spend its time under load? Records
# the h2 leg alone at that multiplexing depth and reports it. There is
# no h1 anchor here - h1 has no multiplexing to answer with.
#
# Which one to reach for, learned the hard way on forgecore: at -m1 a
# connection sits idle for a whole round trip between requests, and
# the kernel's own path (netfilter alone ~5%) evicts its working set
# meanwhile. So a -m1 profile shows COLD-CACHE cost as much as work -
# a 296-byte H2State, whose hot fields already share three cache
# lines, still took a visible miss per request there. Use DIFF to
# compare the protocols, LOAD to find work worth removing.
#
# Profiles BUILD_DIR=build/debug by default - see the BUILD_DIR knob
# below for why that binary's samples are trustworthy despite being a
# test build. Its req/s numbers are still not the ones bench/results/
# archives (enable_test/enable_bintest add test-only gems the ship
# build never links, per #176) - trust floor.sh/h2.sh's build/host
# numbers for throughput, this script's own numbers only for WHERE
# time goes.
#
# Knobs: MULTI (1 = diff mode, >1 = load mode at that depth), DURATION
# (default 20 - profiling wants more samples than a throughput run),
# FREQ (perf -F, default 999), CALLGRAPH (fp|dwarf, default dwarf -
# works on any binary with debug info; fp needs -fno-omit-frame-pointer,
# which only WM_PROFILE=1 adds and BUILD_DIR's default, build/debug,
# does not carry unless that was ALSO set for it),
# PROTO (h2 default, or h1 - both drive htgen over a UNIX socket, see
# below), (load mode's -cN connections
# split across them; the server is one thread regardless, so this is
# entirely about whether ONE client thread can generate enough load to
# saturate it - it silently could not at deep multiplexing on forgecore,
# reading as a server-side cost that was actually client starvation),
# CONNS (load mode, default 32), PORT, APP (default examples/hello.rb),
# ASSETS + ASSET_CODING + REQPATH (see below).
#
# EVENT= is the perf event the recording samples. Unset, perf takes its
# own default (cycles, or the software clock it falls back to where no
# PMU is exposed - any VM); set, `perf record -e $EVENT` runs with the
# same -F, call graph, -m and -o. branch-misses, L1-dcache-load-misses,
# LLC-load-misses are MISS maps: the same load re-recorded, attributing
# that event per symbol instead of time - the layer under "why is this
# function hot" that cycles alone does not carry. The report headers and
# the flamegraph file name the event, so an event map is neither read as
# a cycle map nor written over one. In DIFF mode both legs record the
# same event and the diff still subtracts like for like, but what it
# then reads off is share of that EVENT, not share of time: a symbol can
# take more of the branch misses and less of the cycles, and both are
# true at once. An event this host cannot open is refused by perf record
# before the server is up, and the refusal is printed as perf's own.
#
# ANNOTATE="sym1 sym2 ..." disassembles those symbols out of the same
# recording the reports above read - `perf annotate --stdio --symbol=`
# per name, cut to 60 lines around the symbol's hottest instruction and
# saying how many it dropped either side (a whole symbol runs to
# hundreds: lshpack_dec_decode is 617). The list is space-separated,
# which is the set of names perf prints without spaces - a C++ symbol
# carries its whole signature and cannot be spelled here. A name this
# recording holds no samples for is reported as absent, not skipped in
# silence. The instructions are the profiled binary's: on the default
# BUILD_DIR=build/debug they are -Og's, and the ship build's are what
# BUILD_DIR=build/host plus WM_PROFILE=1 gives (see the BUILD_DIR knob
# below).
#
# STAT=1 answers a DIFFERENT question than everything above: not WHERE
# time goes on one binary, but HOW MUCH work one binary does per request
# against another - the number that tells "real extra work" apart from
# "cache/layout noise" between two commits, without touching perf report's
# per-symbol percentages (which are exactly the quantity layout shifts
# corrupt). Runs `perf stat -p <server-pid>` for the same DURATION htgen
# hits it, alongside the existing recording, and prints
# instructions/request, branch-misses/request and L1d-misses/request.
# A counter the host does not carry comes back `<not supported>` where
# the count would be and prints as ?, with no per-request line derived
# from it. Six counters can outnumber a PMU's slots, and perf then
# multiplexes and scales what it prints - counts that stay comparable
# between runs of the same shape, not exact ones. To compare two
# commits: check one out, `rake compile`, run this with STAT=1; check
# out the other, rebuild, run again; diff the per-request lines by
# hand - this script measures one binary per invocation, on purpose,
# so a build never straddles the numbers it produces.
#
# ASSETS profiles the ASSET TIER instead of an app. Give it a byte
# count and a one-entry pack of that size is built here and hammered;
# give it a path to a .zip and it is served as-is, with REQPATH naming
# the entry. ASSET_CODING (stored|gzip, default stored) picks which
# shape the built pack has, and they are different code: stored is one
# span straight out of the mapping, gzip is three segments around it
# (constant header, the deflate bytes where they lie, the trailer).
# With ASSETS set and no APP given, NO app is loaded - so the profile
# is the tier and the reactor and nothing else. Both modes work: DIFF
# answers "what does h2 pay for the same asset", LOAD answers "where
# does the tier spend its time".
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

# STREAMS is floor.sh's name for h2 multiplexing depth; here it is MULTI,
# which also picks the mode (1 = diff, >1 = load). Passing the other name
# used to be accepted and dropped, so a run asked for at c16 --streams 128
# quietly measured ONE connection and ONE stream - the number then
# described a latency probe while its caller believed it was load.
[ -z "${STREAMS:-}" ] || {
  echo "STREAMS= is floor.sh's knob. Here it is MULTI= - and MULTI also picks" >&2
  echo "the mode: 1 is diff (-c1), anything above is load at that depth." >&2
  echo "You probably want: MULTI=$STREAMS CONNS=${CONNS:-16}" >&2
  exit 2
}
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

# BUILD_DIR (bintest's own convention, see bintest/responsefile.rb),
# default build/debug: it carries -g3 unconditionally, which is what
# perf needs to name a symbol. It is -Og, NOT the ship build's -O3 -
# build_config_debug.rb since the four-file split - so its per-symbol
# shares describe this binary, and instructions/request runs about 15%
# above what build/host does for the same work (measured). Read it for
# WHERE time goes, never as the ship build's cost.
#
# MRB_DEBUG (enable_debug) only turns mrb_assert into a real assert()
# and adds one trivial local in mrb_vm_run - no structural change to
# the VM/GC. BUILD_DIR=build/host profiles the literal shipped binary,
# but #184 strips -g from it, so its symbols are gone and nothing in
# the tree adds them back - WM_PROFILE is named in this file only.
# build/debug does NOT get -fno-omit-frame-pointer unless WM_PROFILE=1
# was ALSO set for it - CALLGRAPH=dwarf sidesteps that, since its DWARF
# is unconditional either way.
BUILD_DIR="${BUILD_DIR:-build/debug}"
BIN="mruby/$BUILD_DIR/bin/webmachine-server"
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile (or rake test, for build/debug)" >&2; exit 1; }
if [ "$BUILD_DIR" = "build/host" ]; then
  file "$BIN" 2>/dev/null | grep -q "not stripped" || echo \
    "warning: $BIN looks stripped - was it built with WM_PROFILE=1? symbols will be useless" >&2
fi

paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "?")
if [ "$paranoid" != "?" ] && [ "$paranoid" -gt 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "kernel.perf_event_paranoid=$paranoid blocks unprivileged perf record - " \
       "sudo sysctl kernel.perf_event_paranoid=1 (or run this under sudo)" >&2
  exit 1
fi

DURATION="${DURATION:-20}"
FREQ="${FREQ:-999}"
CALLGRAPH="${CALLGRAPH:-dwarf}"
# perf maps one ring buffer PER CPU - 129 pages each by default, which
# on a 32-thread host is 16 MB. Those pages land in the kernel's
# per-USER locked_vm, and io_uring's accounting compares that same
# user-wide counter against RLIMIT_MEMLOCK: once perf has pushed it
# over, io_uring_setup returns ENOMEM for ANY ring - measured here, a
# 2-entry probe ring failed too. (ENOMEM, not the EPERM/EAGAIN mlock(2)
# gives, which is why it does not look like a limit at first.)
# The server is ONE thread, so those 32 buffers were never needed:
# 8 pages each is 0.5 MB total and still ample at -F 999 for a
# single-threaded target. --per-thread would sidestep the per-CPU
# multiplication entirely; -m stays the smaller, less surprising knob.
PERF_MMAP="${PERF_MMAP:-8}"
PORT="${PORT:-8123}"
ASSETS="${ASSETS:-}"
ASSET_CODING="${ASSET_CODING:-stored}"
# REQPATH is the path to ask for. It was TARGET here while bench/floor.sh
# called the same thing REQPATH, so no line could be carried from one
# script to the other (#34).
[ -z "${TARGET:-}" ] || {
  echo "TARGET= is REQPATH= in this script now - the name bench/floor.sh already used." >&2
  echo "Same meaning: the path to ask for." >&2
  exit 2
}
REQPATH="${REQPATH:-/}"
# An asset run has nothing to ask an app for; loading one anyway would
# put mruby in the profile for no reason. An explicit APP= still wins.
if [ -n "$ASSETS" ]; then APP="${APP-}"; else APP="${APP-examples/hello.rb}"; fi
MULTI="${MULTI:-1}"
CONNS="${CONNS:-32}"
STAT="${STAT:-0}"
EVENT="${EVENT:-}"
ANNOTATE="${ANNOTATE:-}"
# EVENT_ARGS is perf record's -e, empty when EVENT is unset (perf's own
# default event). EVENT_LABEL is the name the report headers print,
# EVENT_TAG the one the flamegraph file carries - perf event syntax
# holds : / , = (cycles:u, cpu/event=0x3c,umask=0x0/), none of which
# belong in a file name.
EVENT_ARGS=()
EVENT_LABEL=cycles
EVENT_TAG=""
if [ -n "$EVENT" ]; then
  EVENT_ARGS=(-e "$EVENT")
  EVENT_LABEL="$EVENT"
  EVENT_TAG=".$(printf '%s' "$EVENT" | tr -c 'A-Za-z0-9_.-' '_')"
fi
# perf annotate prints a whole symbol - hundreds of lines - so what
# lands in the report is this many around its hottest instruction.
ANNOTATE_WINDOW=60
# PROTO=h1 profiles the h1 path under load. Until it existed the h1 leg
# ran only in diff mode (-c1, against h2 -m1), so the question "where
# does h1 spend its time at CONNS connections" had no way to be asked -
# h1 has no -m to vary, which is why the load branch below is h2-only.
#
# It drives the load the way bench/floor.sh does - htgen over a UNIX
# socket - and NOT over TCP, which was the first attempt and measured
# the wrong machine: the profile that came back was nftables, conntrack
# and the TCP stack with no webmachine symbol above 0.8%, because the
# client could not feed the server fast enough over the port. A UNIX
# socket has no IP layer for a firewall to hook, which is the whole
# point: what is left in the profile is this tree. Both protocols now
# ride the socket, because htgen speaks h2 over it too - h2load never
# did, which is why the h2 legs used to be the TCP ones.
PROTO="${PROTO:-h2}"
case "$PROTO" in
  h1|h2) ;;
  *) echo "PROTO=$PROTO is neither h1 nor h2" >&2; exit 1 ;;
esac
HTGEN="${HTGEN:-$HOME/htgen/htgen}"
[ -x "$HTGEN" ] || HTGEN=$(command -v htgen) || {
  echo "htgen not found. Build it once:" >&2
  echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen && make -C ~/htgen" >&2
  echo "or point HTGEN= at the binary." >&2
  exit 1
}
[ -z "${THREADS:-}" ] || {
  echo "THREADS= is gone: both ends are one thread (#120, #196)." >&2
  exit 2
}

# The server loads bytecode only (#100). A .rb APP is compiled here
# with the tree's own mrbc into a scratch .mrb; the harness line keeps
# naming the .rb source. An .mrb APP (or none) passes through as-is.
APP_ARGS=()
if [ -n "${APP:-}" ]; then
  case "$APP" in
    *.rb)
      MRBC="${MRBC:-mruby/bin/mrbc}"
      [ -x "$MRBC" ] || { echo "mrbc not found at $MRBC - rake compile builds it, or set MRBC=" >&2; exit 1; }
      APP_MRB=/tmp/wm-profile-app.mrb
      "$MRBC" -o "$APP_MRB" "$APP" || exit 1
      APP_ARGS=(--app "$APP_MRB")
      ;;
    *) APP_ARGS=(--app "$APP") ;;
  esac
fi

WORK=$(mktemp -d)
ASSET_ARGS=()
# The same field, spelled for two tools: curl proves the target, htgen
# drives the load.
HDRS=()
CLI_HDRS=()
if [ -n "$ASSETS" ]; then
  command -v curl >/dev/null || { echo "curl not found (needed to prove the asset before profiling it)" >&2; exit 1; }
  case "$ASSETS" in
    *[!0-9]*)
      [ -f "$ASSETS" ] || { echo "ASSETS=$ASSETS is neither a byte count nor a file" >&2; exit 1; }
      [ "$REQPATH" != / ] || { echo "REQPATH= must name an entry when ASSETS is a pack" >&2; exit 1; }
      ZIP="$ASSETS"
      ;;
    *)
      command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
      # The built pack holds exactly one entry and names it itself.
      [ "$REQPATH" = / ] || { echo "REQPATH= only applies when ASSETS names a pack - the built one has one entry" >&2; exit 1; }
      case "$ASSET_CODING" in
        stored)
          # urandom, forced stored: the body IS the file-backed span.
          head -c "$ASSETS" /dev/urandom > "$WORK/a.bin"
          (cd "$WORK" && zip -q -0 -X pack.zip a.bin) || exit 1
          REQPATH=/a.bin
          ;;
        gzip)
          # This tree's own sources, repeated to length: real text, so
          # the ratio is one an asset pack actually gets.
          cat src/*.cpp src/*.hpp > "$WORK/corpus" 2>/dev/null
          [ -s "$WORK/corpus" ] || { echo "no src/ corpus to build a compressible fixture from" >&2; exit 1; }
          cl=$(wc -c < "$WORK/corpus")
          for _ in $(seq $(( (ASSETS + cl - 1) / cl ))); do cat "$WORK/corpus"; done |
            head -c "$ASSETS" > "$WORK/t.txt"
          (cd "$WORK" && zip -q -9 -X pack.zip t.txt) || exit 1
          REQPATH=/t.txt
          HDRS=(-H 'accept-encoding: gzip')
          CLI_HDRS=(--header 'accept-encoding: gzip')
          ;;
        *) echo "ASSET_CODING must be stored or gzip" >&2; exit 1 ;;
      esac
      ZIP="$WORK/pack.zip"
      ;;
  esac
  ASSET_ARGS=(--assets "$ZIP")
fi

OUT=bench/profile
mkdir -p "$OUT"
WM_SOCK=/tmp/wm-profile-bench.sock
echo "profiling: ${APP:-no app}${ASSETS:+ + assets $ZIP} path $REQPATH coding ${ASSETS:+$ASSET_CODING}"
# Which binary, built with what, running on what. A profile without this
# is a share of a machine nobody wrote down.
. bench/buildline.sh
wm_build_line "$BIN"
if [ "$PROTO" = h1 ]; then
  echo "harness: htgen --sock -c$CONNS -d${DURATION}s h1 (unix socket, no TCP/nftables)"
else
  echo "harness: htgen --sock $([ "$MULTI" = 1 ] && echo "-c1 (diff mode)" || echo "-c$CONNS") --streams $MULTI -d${DURATION}s"
fi
[ -z "$EVENT" ] || echo "event: $EVENT (every share below is a share of it, not of time)"

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
  rm -rf "$WORK"
  rm -f "$WM_SOCK"
  return 0
}
trap cleanup EXIT INT TERM

if pgrep -f "$BIN" >/dev/null 2>&1; then
  echo "a webmachine-server is already running - it holds an io_uring ring:" >&2
  pgrep -af "$BIN" >&2
  echo "kill it first (pkill -f webmachine-server), or this run competes with it" >&2
  exit 1
fi

# leg <name> <perf.data path> <htgen flags...>
leg() {
  local name=$1 data=$2
  shift 2
  echo "== recording $name -> $data =="
  # ONE bind for both protocols: the client speaks h2 over AF_UNIX, so
  # there is no reason left to put the TCP stack in the profile.
  rm -f "$WM_SOCK"
  local bindargs=(--unix "$WM_SOCK")
  "$PERF" record "${EVENT_ARGS[@]}" -F "$FREQ" -g --call-graph "$CALLGRAPH" -m "$PERF_MMAP" -o "$data" -- \
    "$BIN" "${bindargs[@]}" "${APP_ARGS[@]}" "${ASSET_ARGS[@]}" \
    >/tmp/wm-profile-srv.log 2>&1 &
  local perfpid=$!
  PERFPID=$perfpid
  # $! is perf's own pid (it execs the server as ITS child, so
  # pinned execs again in place, same pid throughout) - pgrep -P finds
  # that direct child unambiguously, no full-line matching to race.
  local srvpid="" perfstate=""
  for _ in $(seq 20); do
    srvpid=$(pgrep -P "$perfpid" | head -1)
    if [ -n "$srvpid" ] && [ -S "$WM_SOCK" ]; then break; fi
    srvpid=""
    # perf record parses -e and opens the event BEFORE it execs the
    # server, so an event it cannot spell or cannot open leaves no
    # child to wait for. An exited perf is a zombie until it is waited
    # for and kill -0 answers yes to one; the state field of
    # /proc/PID/stat - the character after the comm parens - is what
    # tells Z from a live recording.
    perfstate=$(sed -n 's/.*) \(.\) .*/\1/p' "/proc/$perfpid/stat" 2>/dev/null)
    [ "${perfstate:-Z}" != Z ] || break
    sleep 0.1
  done
  # An exited perf that recorded nothing at all never got as far as the
  # server: -o is written when the recording ends, and a refused event
  # leaves it zero bytes, where a server that ran and then died leaves
  # its samples in it (measured: 5 samples, 63 KB, from a server that
  # died on a bad app). So the log here is perf's own words, not the
  # server's, and the ENOMEM reading below would be the wrong one.
  if [ -z "$srvpid" ] && [ "${perfstate:-Z}" = Z ] && [ ! -s "$data" ]; then
    echo "perf record exited before the server was up${EVENT:+ - EVENT=$EVENT}. perf's own words:" >&2
    cat /tmp/wm-profile-srv.log >&2
    exit 1
  fi
  if [ -z "$srvpid" ]; then
    echo "server did not start (or never became reachable on $WM_SOCK):" >&2
    cat /tmp/wm-profile-srv.log >&2
    # perf's own mmap buffers and io_uring's ring draw on the SAME
    # locked-memory budget, and the server only ever fails this way
    # UNDER perf - so say so instead of leaving it to be rediscovered.
    if grep -q "Cannot allocate memory" /tmp/wm-profile-srv.log 2>/dev/null; then
      # Traced on forgecore: perf's 32 per-CPU buffers pushed the
      # per-user locked_vm over RLIMIT_MEMLOCK, and io_uring_setup then
      # refused even a 2-entry ring with ENOMEM. -m is already lowered
      # above; if it still happens, the limit itself is too small for
      # this host's CPU count.
      echo "ENOMEM at ring init: perf's per-CPU buffers and io_uring share the" >&2
      echo "per-USER locked_vm budget, checked against RLIMIT_MEMLOCK." >&2
      echo "ulimit -l says $(ulimit -l) KB; perf mapped $(nproc) buffers of" \
           "$PERF_MMAP pages. Lower PERF_MMAP further, or raise ulimit -l." >&2
    fi
    exit 1
  fi
  SRVPID=$srvpid
  # PROVE THE PATH, and not with the status code: a server started
  # with --assets and no app answers 200 with a two-byte body for any
  # name the pack does not hold, so a typo profiles the default
  # resource and looks exactly like a hit. The ETag is the tell - only
  # the asset tier sends one.
  if [ -n "$ASSETS" ]; then
    curl -s --max-time 10 --unix-socket "$WM_SOCK" -D "$WORK/hdr" -o /dev/null \
         "${HDRS[@]}" "http://localhost$REQPATH"
    grep -qi '^etag:' "$WORK/hdr" || {
      echo "$REQPATH did not come back from the asset tier (no ETag) - the pack does not hold that name" >&2
      kill -TERM "$srvpid"; exit 1
    }
    if [ "$ASSET_CODING" = gzip ] && [ -z "${ASSETS%%[0-9]*}" ]; then
      grep -qi '^content-encoding: *gzip' "$WORK/hdr" || {
        echo "the entry did not come back gzip-coded - it was not stored as method 8" >&2
        kill -TERM "$srvpid"; exit 1
      }
    fi
  fi
  # STAT: a second, independent perf session on the SAME pid, alongside
  # the recording above - `perf stat -p PID -- sleep N` is the same
  # attach-for-N-seconds idiom bench/floor.sh's sysc_begin already uses,
  # here measuring cycles/instructions/cache instead of syscall count.
  local statpid=""
  if [ "$STAT" = 1 ]; then
    "$PERF" stat -e cycles,instructions,L1-icache-load-misses,iTLB-load-misses,branch-misses,L1-dcache-load-misses \
      -p "$srvpid" -x, -o "$WORK/stat.out" -- sleep "$DURATION" >/dev/null 2>&1 &
    statpid=$!
  fi
  local cliout
  cliout=$("$HTGEN" --sock "$WM_SOCK" --conns "$LEGCONNS" --seconds "$DURATION" \
             --path "$REQPATH" "$@" "${CLI_HDRS[@]}" 2>&1)
  echo "$cliout" | grep '^responses='
  [ -n "$statpid" ] && wait "$statpid" 2>/dev/null
  if [ "$STAT" = 1 ] && [ -s "$WORK/stat.out" ]; then
    local ndone cyc instr icm itlb bmiss dcm
    ndone=$(echo "$cliout" | grep -o 'responses=[0-9]*' | cut -d= -f2)
    # A counter this host does not carry is `<not supported>` sitting
    # in the field a count would be in - a string awk's arithmetic
    # reads as 0. Only a count is taken here; anything else leaves the
    # value empty, which prints as ? and derives no per-request line.
    cyc=$(awk -F, '$3=="cycles" && $1 ~ /^[0-9]+$/ {print $1}' "$WORK/stat.out")
    instr=$(awk -F, '$3=="instructions" && $1 ~ /^[0-9]+$/ {print $1}' "$WORK/stat.out")
    icm=$(awk -F, '$3=="L1-icache-load-misses" && $1 ~ /^[0-9]+$/ {print $1}' "$WORK/stat.out")
    itlb=$(awk -F, '$3=="iTLB-load-misses" && $1 ~ /^[0-9]+$/ {print $1}' "$WORK/stat.out")
    bmiss=$(awk -F, '$3=="branch-misses" && $1 ~ /^[0-9]+$/ {print $1}' "$WORK/stat.out")
    dcm=$(awk -F, '$3=="L1-dcache-load-misses" && $1 ~ /^[0-9]+$/ {print $1}' "$WORK/stat.out")
    echo "  perf stat ($name): cycles=${cyc:-?} instructions=${instr:-?}" \
         "L1-icache-misses=${icm:-?} iTLB-misses=${itlb:-?}" \
         "branch-misses=${bmiss:-?} L1d-misses=${dcm:-?}"
    # The companion counter can be missing on its own - a partial PMU
    # counts instructions but not cache events - and prints as ?, never
    # as a 0.0 that reads like a measurement.
    if [ -n "$instr" ] && [ -n "$ndone" ] && [ "$ndone" -gt 0 ]; then
      awk -v i="$instr" -v c="$cyc" -v d="$ndone" \
        'BEGIN { printf "  instructions/request: %.1f   cycles/request: %s\n", i / d, c == "" ? "?" : sprintf("%.1f", c / d) }'
    fi
    if [ -n "$bmiss" ] && [ -n "$ndone" ] && [ "$ndone" -gt 0 ]; then
      awk -v b="$bmiss" -v l="$dcm" -v d="$ndone" \
        'BEGIN { printf "  branch-misses/request: %.1f   L1d-misses/request: %s\n", b / d, l == "" ? "?" : sprintf("%.1f", l / d) }'
    fi
    mv "$WORK/stat.out" "$OUT/stat.$(echo "$name" | tr ' /' '__').out"
  fi
  kill -TERM "$srvpid"
  wait "$perfpid" 2>/dev/null
  SRVPID=""
  PERFPID=""
}

# WHOSE cycles - or whose EVENT, when one is set: one line per object,
# nothing hidden, under a header that names which of the two it is. A
# top-30 symbol list with a 0.5% floor showed 63% of the samples and
# made this tree look like 3% of its own profile - our code is spread
# thin over many small symbols, exactly the shape a floor erases. This
# is the number that says how much of the run is webmachine at all;
# the symbol list after it says where inside that.
report_full() {
  local data=$1 what=$2
  echo
  echo "== whose $EVENT_LABEL ($what): per object, all samples =="
  "$PERF" report -i "$data" --stdio --no-children -g none --sort dso \
    --percent-limit=0 2>/dev/null | grep -vE '^#|^$'
  echo
  echo "== where in it ($what): every symbol at or above 0.10% =="
  "$PERF" report -i "$data" --stdio --no-children -g none \
    --percent-limit=0.10 2>/dev/null | grep -vE '^#|^$'
}

if [ "$PROTO" = h1 ]; then
  # h1 has no multiplexing, so CONNS alone carries the load and MULTI
  # says nothing here.
  LEGCONNS="$CONNS"
  GRAPH="$OUT/perf.data.h1"
  leg "h1 (c$CONNS)" "$GRAPH"
  report_full "$GRAPH" "h1 c$CONNS"
elif [ "$MULTI" = 1 ]; then
  LEGCONNS=1
  GRAPH="$OUT/perf.data.h2"
  leg "h1 anchor" "$OUT/perf.data.h1"
  leg "h2 --streams 1" "$OUT/perf.data.h2" --h2 --streams 1
  echo
  echo "== perf diff: relative sample share${EVENT:+ of $EVENT}, h1 -> h2 (positive = h2 spends more here) =="
  "$PERF" diff "$OUT/perf.data.h1" "$OUT/perf.data.h2" 2>/dev/null | grep -vE '^#|^$'
  report_full "$OUT/perf.data.h2" "h2 --streams 1"
else
  # No h1 anchor: h1 has no multiplexing to answer -m$MULTI with, so
  # there is nothing to diff against. This is the shape that keeps the
  # connection's working set warm, which is the whole point - what
  # shows up here is work, not the cold-cache cost -m1 also measures.
  LEGCONNS="$CONNS"
  GRAPH="$OUT/perf.data.h2"
  leg "h2 --streams $MULTI (c$CONNS)" "$OUT/perf.data.h2" --h2 --streams "$MULTI"

  report_full "$OUT/perf.data.h2" "h2 --streams $MULTI c$CONNS"
fi

# The instructions behind a symbol from the list above, read out of
# $GRAPH - the same recording report_full just described. perf annotate
# writes a symbol it has no samples for as nothing at all on stdout,
# with "data has no samples" on stderr, which is why the percent lines
# are counted rather than the exit status.
for sym in $ANNOTATE; do
  echo
  echo "== annotate ($sym): $EVENT_LABEL per instruction =="
  "$PERF" annotate -i "$GRAPH" --stdio --symbol="$sym" \
    >"$WORK/annotate.out" 2>"$WORK/annotate.err"
  if ! grep -qE '^ *[0-9]+\.[0-9]+ :' "$WORK/annotate.out"; then
    echo "  $sym: no annotated instruction in $GRAPH - this recording holds no samples for that symbol"
    sed 's/^/  perf: /' "$WORK/annotate.err" | head -4
    continue
  fi
  awk -v win="$ANNOTATE_WINDOW" -v perf="$PERF" -v data="$GRAPH" -v sym="$sym" '
    { line[NR] = $0 }
    $1 ~ /^[0-9]+\.[0-9]+$/ && $1 + 0 > hot { hot = $1 + 0; at = NR }
    END {
      head = (NR > 2 ? 2 : NR)
      for (i = 1; i <= head; i++) print line[i]
      lo = head + 1; hi = NR
      if (NR - head > win) {
        lo = at - int(win / 2)
        if (lo < head + 1) lo = head + 1
        hi = lo + win - 1
        if (hi > NR) { hi = NR; lo = hi - win + 1 }
      }
      if (lo > head + 1) printf "  ... %d lines before this window ...\n", lo - head - 1
      for (i = lo; i <= hi; i++) print line[i]
      if (hi < NR) printf "  ... %d lines after it - all of it: %s annotate -i %s --stdio --symbol=%s\n", \
                          NR - hi, perf, data, sym
    }
  ' "$WORK/annotate.out"
done

if command -v stackcollapse-perf.pl >/dev/null && command -v flamegraph.pl >/dev/null; then
  "$PERF" script -i "$GRAPH" 2>/dev/null | stackcollapse-perf.pl | flamegraph.pl \
    > "$OUT/flamegraph.$PROTO$EVENT_TAG.svg"
  echo "flamegraph: $OUT/flamegraph.$PROTO$EVENT_TAG.svg"
else
  echo "FlameGraph scripts (stackcollapse-perf.pl/flamegraph.pl) not on PATH - " \
       "skipped, perf diff above is the finding" >&2
fi
