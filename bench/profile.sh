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
# THREADS (h2load client threads, default 1 - load mode's -cN connections
# split across them; the server is one thread regardless, so this is
# entirely about whether ONE client thread can generate enough load to
# saturate it - it silently could not at deep multiplexing on forgecore,
# reading as a server-side cost that was actually client starvation),
# CONNS (load mode, default 32), PORT, APP (default examples/hello.rb),
# ASSETS + ASSET_CODING + TARGET (see below).
#
# STAT=1 answers a DIFFERENT question than everything above: not WHERE
# time goes on one binary, but HOW MUCH work one binary does per request
# against another - the number that tells "real extra work" apart from
# "cache/layout noise" between two commits, without touching perf report's
# per-symbol percentages (which are exactly the quantity layout shifts
# corrupt). Runs `perf stat -p <server-pid>` for the same DURATION h2load
# hits it, alongside the existing recording, and prints
# instructions/request. To compare two commits: check one out, `rake
# compile`, run this with STAT=1; check out the other, rebuild, run
# again; diff the instructions/request lines by hand - this script
# measures one binary per invocation, on purpose, so a build never
# straddles the numbers it produces.
#
# ASSETS profiles the ASSET TIER instead of an app. Give it a byte
# count and a one-entry pack of that size is built here and hammered;
# give it a path to a .zip and it is served as-is, with TARGET naming
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

# BUILD_DIR (bintest's own convention, see bintest/responsefile.rb),
# default build/debug: it carries -g3 unconditionally AND shares
# WM_FLAGS' -O3, so it profiles the same codegen shape the ship build
# runs - not a de-optimized stand-in - at zero extra build cost beyond
# a plain `rake test`. MRB_DEBUG (enable_debug) only turns mrb_assert
# into a real assert() and adds one trivial local in mrb_vm_run - no
# structural change to the VM/GC. The ship build (build/host) never
# needs WM_PROFILE=1 for this reason: BUILD_DIR=build/host still works
# for the rare case of profiling the literal shipped binary, but then
# needs that env var for symbols at all (#184 strips -g by default).
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
TARGET="${TARGET:-/}"
# An asset run has nothing to ask an app for; loading one anyway would
# put mruby in the profile for no reason. An explicit APP= still wins.
if [ -n "$ASSETS" ]; then APP="${APP-}"; else APP="${APP-examples/hello.rb}"; fi
MULTI="${MULTI:-1}"
CONNS="${CONNS:-32}"
THREADS="${THREADS:-1}"
STAT="${STAT:-0}"

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
HDRS=()
if [ -n "$ASSETS" ]; then
  command -v curl >/dev/null || { echo "curl not found (needed to prove the asset before profiling it)" >&2; exit 1; }
  case "$ASSETS" in
    *[!0-9]*)
      [ -f "$ASSETS" ] || { echo "ASSETS=$ASSETS is neither a byte count nor a file" >&2; exit 1; }
      [ "$TARGET" != / ] || { echo "TARGET= must name an entry when ASSETS is a pack" >&2; exit 1; }
      ZIP="$ASSETS"
      ;;
    *)
      command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
      # The built pack holds exactly one entry and names it itself.
      [ "$TARGET" = / ] || { echo "TARGET= only applies when ASSETS names a pack - the built one has one entry" >&2; exit 1; }
      case "$ASSET_CODING" in
        stored)
          # urandom, forced stored: the body IS the file-backed span.
          head -c "$ASSETS" /dev/urandom > "$WORK/a.bin"
          (cd "$WORK" && zip -q -0 -X pack.zip a.bin) || exit 1
          TARGET=/a.bin
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
          TARGET=/t.txt
          HDRS=(-H 'accept-encoding: gzip')
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
URL="http://127.0.0.1:$PORT$TARGET"
echo "profiling: ${APP:-no app}${ASSETS:+ + assets $ZIP} target $TARGET coding ${ASSETS:+$ASSET_CODING}"
echo "harness: h2load -t$THREADS $([ "$MULTI" = 1 ] && echo "-c1 (diff mode)" || echo "-c$CONNS -m$MULTI") -D${DURATION}"

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
  "$PERF" record -F "$FREQ" -g --call-graph "$CALLGRAPH" -m "$PERF_MMAP" -o "$data" -- \
    "$BIN" --port "$PORT" "${APP_ARGS[@]}" "${ASSET_ARGS[@]}" \
    >/tmp/wm-profile-srv.log 2>&1 &
  local perfpid=$!
  PERFPID=$perfpid
  # $! is perf's own pid (it execs the server as ITS child, so
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
  # PROVE THE TARGET, and not with the status code: a server started
  # with --assets and no app answers 200 with a two-byte body for any
  # name the pack does not hold, so a typo profiles the default
  # resource and looks exactly like a hit. The ETag is the tell - only
  # the asset tier sends one.
  if [ -n "$ASSETS" ]; then
    curl -s --max-time 10 -D "$WORK/hdr" -o /dev/null "${HDRS[@]}" "$URL"
    grep -qi '^etag:' "$WORK/hdr" || {
      echo "$URL did not come back from the asset tier (no ETag) - the pack does not hold that name" >&2
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
    "$PERF" stat -e cycles,instructions,L1-icache-load-misses,iTLB-load-misses \
      -p "$srvpid" -x, -o "$WORK/stat.out" -- sleep "$DURATION" >/dev/null 2>&1 &
    statpid=$!
  fi
  local h2out
  h2out=$(h2load -D"$DURATION" -t"$THREADS" -c"$LEGCONNS" "$@" "${HDRS[@]}" "$URL" 2>&1)
  echo "$h2out" | grep '^finished'
  [ -n "$statpid" ] && wait "$statpid" 2>/dev/null
  if [ "$STAT" = 1 ] && [ -s "$WORK/stat.out" ]; then
    local ndone cyc instr icm itlb
    ndone=$(echo "$h2out" | grep '^requests:' | awk '{print $6}')
    cyc=$(awk -F, '$3=="cycles"{print $1}' "$WORK/stat.out")
    instr=$(awk -F, '$3=="instructions"{print $1}' "$WORK/stat.out")
    icm=$(awk -F, '$3=="L1-icache-load-misses"{print $1}' "$WORK/stat.out")
    itlb=$(awk -F, '$3=="iTLB-load-misses"{print $1}' "$WORK/stat.out")
    echo "  perf stat ($name): cycles=${cyc:-?} instructions=${instr:-?} L1-icache-misses=${icm:-?} iTLB-misses=${itlb:-?}"
    if [ -n "$instr" ] && [ -n "$ndone" ] && [ "$ndone" -gt 0 ]; then
      awk -v i="$instr" -v c="${cyc:-0}" -v d="$ndone" \
        'BEGIN { printf "  instructions/request: %.1f   cycles/request: %.1f\n", i / d, c / d }'
    fi
    mv "$WORK/stat.out" "$OUT/stat.$(echo "$name" | tr ' /' '__').out"
  fi
  kill -TERM "$srvpid"
  wait "$perfpid" 2>/dev/null
  SRVPID=""
  PERFPID=""
}

if [ "$MULTI" = 1 ]; then
  LEGCONNS=1
  leg "h1 anchor" "$OUT/perf.data.h1" --h1 -m1
  leg "h2 -m1"    "$OUT/perf.data.h2" -m1
  echo
  echo "== perf diff: relative sample share, h1 -> h2 (positive = h2 spends more here) =="
  "$PERF" diff "$OUT/perf.data.h1" "$OUT/perf.data.h2" 2>/dev/null | head -60
else
  # No h1 anchor: h1 has no multiplexing to answer -m$MULTI with, so
  # there is nothing to diff against. This is the shape that keeps the
  # connection's working set warm, which is the whole point - what
  # shows up here is work, not the cold-cache cost -m1 also measures.
  LEGCONNS="$CONNS"
  leg "h2 -m$MULTI (c$CONNS)" "$OUT/perf.data.h2" -m"$MULTI"
  echo
  echo "== perf report: where h2 spends its time under load =="
  # -g none: a flat list. The call graph was recorded (it is what
  # annotate and the flamegraph want) but here the question is only
  # which symbol burns the cycles.
  "$PERF" report -i "$OUT/perf.data.h2" --stdio --no-children -g none \
    --percent-limit=0.5 2>/dev/null | grep -vE '^#|^$' | head -30
fi

if command -v stackcollapse-perf.pl >/dev/null && command -v flamegraph.pl >/dev/null; then
  "$PERF" script -i "$OUT/perf.data.h2" 2>/dev/null | stackcollapse-perf.pl | flamegraph.pl \
    > "$OUT/flamegraph.h2.svg"
  echo "flamegraph: $OUT/flamegraph.h2.svg"
else
  echo "FlameGraph scripts (stackcollapse-perf.pl/flamegraph.pl) not on PATH - " \
       "skipped, perf diff above is the finding" >&2
fi
