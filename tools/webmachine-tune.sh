#!/bin/sh
# webmachine-tune: read the machine, print how to run THIS server on it.
#
# Operator tool, not a benchmark (bench/ owns measuring). It reads
# /proc, /sys, uname and ulimit - and WRITES NOTHING: no sysctl -w, no
# governor file, no bench/results/. Where a change would help, it
# prints the command for the operator to copy; it never runs it.
#
# Every number it checks against is one this server actually hardcodes
# or derives (src/ring.hpp) - no generic sysctl folklore. Values it
# cannot read are named unreadable, never guessed (same doctrine as the
# named refusals in bench/floor.sh).
set -u
cd "$(dirname "$0")/.." || exit 1

BIN=mruby/build/host/bin/webmachine-server

# The constants come out of the one source of truth so this tool can
# never drift from the code it advises about. A failed parse is a
# named refusal for that section, not a silent default.
FD_RESERVE=$(sed -n 's/.*kFdReserve = \([0-9][0-9]*\);.*/\1/p' src/ring.hpp)
MAX_LISTENERS=$(sed -n 's/.*kMaxListeners = \([0-9][0-9]*\);.*/\1/p' src/ring.hpp)
BACKLOG=$(sed -n 's/.*io_uring_prep_listen(s, slot, \([0-9][0-9]*\));.*/\1/p' src/ring.hpp)

read_or() {  # read_or <file> <fallback-text>
  if [ -r "$1" ]; then cat "$1"; else echo "$2"; fi
}

echo "==== webmachine-tune $(date -u +%FT%RZ) $(hostname) $(uname -srm) ===="

# ---- CPU placement ---------------------------------------------------
# NO PINNING. This is a measured verdict, not a preference, and it has
# been reached twice:
#
#   1. The previous tree removed every --cpu/--fast-core/taskset it had
#      ("it was measured and it lost - handing the scheduler one core
#      was slower than letting it choose"). Widening the CLIENT's mask
#      from 2 to 15 to 30 cpus raised throughput monotonically,
#      332k -> 341k -> 352k req/s, and moved the MEDIAN, not the tail.
#
#   2. Splice makes it worse than merely useless. io-wq workers INHERIT
#      the issuing thread's affinity, so pinning the server pins the
#      pool that exists to move bytes on ANOTHER core. Measured here on
#      4 cpus: a 32 KiB asset served at 0.07x its unspliced twin under
#      `taskset -c 0` (2,903 vs 42,688 req/s).
#
# So this section reports what the machine looks like and does NOT
# hand out a taskset line.
echo ""
echo "-- cpu placement"
NPROC=$(nproc)
ISOLATED=$(read_or /sys/devices/system/cpu/isolated "")
echo "cores: $NPROC   isolated: ${ISOLATED:-none}"

if [ -r /sys/fs/cgroup/cpu.max ]; then
  echo "cgroup v2 cpu.max: $(cat /sys/fs/cgroup/cpu.max) (quota period; max = unrestricted)"
elif [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
  Q=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
  P=$(read_or /sys/fs/cgroup/cpu/cpu.cfs_period_us "?")
  if [ "$Q" = "-1" ]; then
    echo "cgroup v1 cpu quota: unrestricted (period $P)"
  else
    echo "cgroup v1 cpu quota: $Q / $P us (~$((Q / P)) cores effective)"
  fi
else
  echo "cgroup cpu quota: unreadable here"
fi

# Live steal over one second - contention is a property of NOW.
steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }
S0=$(steal_ticks); sleep 1; S1=$(steal_ticks)
echo "steal: +$((S1 - S0)) ticks over 1s (0 = quiet; sustained >0 = a neighbor is eating this host)"

echo "recommend: do NOT pin - no taskset, no cpu mask, no isolated core."
echo "  the scheduler beat every placement this project measured, and the"
echo "  io-wq pool that carries splice inherits whatever affinity it is given."
if [ "$NPROC" -lt 4 ]; then
  echo "note: $NPROC cores is few for splice - its workers need cores of their"
  echo "  own to be worth the hop; the delivery path falls back to plain copies"
  echo "  wherever they are not there (that fallback is the design, not a bug)."
fi

# ---- io_uring / WM_BUNDLE --------------------------------------------
echo ""
echo "-- io_uring"
KREL=$(uname -r)
KMAJ=$(echo "$KREL" | cut -d. -f1)
KMIN=$(echo "$KREL" | cut -d. -f2 | sed 's/[^0-9].*//')
if [ "$KMAJ" -gt 6 ] 2>/dev/null || { [ "$KMAJ" -eq 6 ] && [ "${KMIN:-0}" -ge 11 ]; } 2>/dev/null; then
  echo "kernel $KREL: >= 6.11, has IORING_OP_BIND/LISTEN (the server probes this itself at init)"
else
  echo "kernel $KREL: BELOW 6.11 - the server will refuse to start, by name (needs IORING_OP_BIND/LISTEN)"
fi

# The one KNOWN-broken build (src/ring.hpp: recv-bundle dense-fill
# contract violated). Anything else is not asserted safe - bundles are
# verified on real hardware with a byte comparison, or not at all.
WM_BUNDLE_REC=""
case "$KREL" in
  6.18.5-fc*)
    WM_BUNDLE_REC="WM_BUNDLE=0 "
    echo "recommend: WM_BUNDLE=0 - this exact kernel build violates the recv-bundle dense-fill contract (documented in src/ring.hpp)"
    ;;
  *)
    echo "recv bundles: kernel default stands, but is NOT verified against this kernel - before trusting it under load, byte-compare responses once with WM_BUNDLE=0 vs default"
    ;;
esac

# ---- resource limits -------------------------------------------------
# Since #169 the server derives its capacity itself: at init it raises
# soft to hard (ceiling fs.nr_open) and takes everything the final
# limit allows minus the reserve. This section PRINTS that arithmetic -
# the server does not need help, but the operator deserves the number.
echo ""
echo "-- capacity (the server derives this itself at init)"
HARD=$(ulimit -Hn)
NR_OPEN=$(read_or /proc/sys/fs/nr_open "")
if [ -z "$FD_RESERVE" ] || [ -z "$MAX_LISTENERS" ]; then
  echo "cannot parse kFdReserve/kMaxListeners out of src/ring.hpp - capacity arithmetic not printed (fix the parse, do not guess)"
else
  if [ "$HARD" = "unlimited" ]; then
    LIMIT=${NR_OPEN:-1048576}
  else
    LIMIT=$HARD
    [ -n "$NR_OPEN" ] && [ "$NR_OPEN" -lt "$LIMIT" ] && LIMIT=$NR_OPEN
  fi
  # Kernel cap on a fixed-file table: 2^20 (io_uring/rsrc.c).
  TABLE_CAP=1048576
  MAXC=$((LIMIT - FD_RESERVE - MAX_LISTENERS))
  [ $((MAXC + MAX_LISTENERS)) -gt "$TABLE_CAP" ] && MAXC=$((TABLE_CAP - MAX_LISTENERS))
  echo "RLIMIT_NOFILE hard: $HARD   fs.nr_open: ${NR_OPEN:-unreadable}"
  echo "max connections: $LIMIT - $FD_RESERVE (fd reserve) - $MAX_LISTENERS (listeners) = $MAXC"
  if [ "$MAXC" -le 0 ]; then
    echo "the limit leaves NO room - the server will refuse to start; raise it: systemd LimitNOFILE=$((FD_RESERVE + MAX_LISTENERS + 1024)) or higher"
  elif [ "$HARD" != "unlimited" ] && [ "$HARD" -lt 65536 ]; then
    echo "hard limit is low; more connections need a raised hard limit, e.g. systemd LimitNOFILE=524288"
  fi
fi

SOMAXCONN=$(read_or /proc/sys/net/core/somaxconn "")
if [ -z "$BACKLOG" ]; then
  echo "cannot parse the listen backlog out of src/ring.hpp - backlog check not printed"
elif [ -z "$SOMAXCONN" ]; then
  echo "net.core.somaxconn: unreadable here (server backlog is $BACKLOG)"
elif [ "$SOMAXCONN" -lt "$BACKLOG" ]; then
  echo "net.core.somaxconn=$SOMAXCONN < server backlog $BACKLOG - linux silently clamps; to honor the full backlog:"
  echo "  sysctl -w net.core.somaxconn=$BACKLOG   # run as root, not run by this tool"
else
  echo "net.core.somaxconn=$SOMAXCONN >= server backlog $BACKLOG - fine"
fi

# ---- governor (best effort) ------------------------------------------
echo ""
echo "-- cpu governor"
GOV=$(read_or /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor "")
if [ -z "$GOV" ]; then
  echo "scaling_governor: unreadable/not present here (containers and some VMs have no cpufreq)"
else
  echo "scaling_governor: $GOV"
  [ "$GOV" != "performance" ] && {
    echo "for latency-stable serving:"
    echo "  echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor   # as root, not run by this tool"
  }
fi

# ---- summary ---------------------------------------------------------
echo ""
echo "-- run it like this"
ENVP=""
[ -n "$WM_BUNDLE_REC" ] && ENVP="env $WM_BUNDLE_REC"
echo "  $ENVP$BIN --port 8080 --app your_app.mrb"
echo "  (no taskset on purpose - see the cpu placement section)"
