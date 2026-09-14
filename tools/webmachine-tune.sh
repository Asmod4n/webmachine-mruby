#!/bin/sh
# webmachine-tune: read the machine, print how to run this server on it.
#
# Operator tool, not a benchmark (bench/ owns measuring). It reads
# /proc, /sys, uname and ulimit - and writes nothing: no sysctl -w, no
# governor file, no bench/results/. Where a change would help, it
# prints the command for the operator to copy; it never runs it.
#
# Every number it checks against is one this server actually hardcodes
# or derives (src/ring_setup.hpp) - no generic sysctl folklore. Values it
# cannot read are named unreadable, never guessed (same doctrine as the
# named refusals in bench/floor.sh).
set -u
cd "$(dirname "$0")/.." || exit 1

BIN=mruby/build/host/bin/webmachine-server

# The constants come out of the one source of truth so this tool can
# never drift from the code it advises about. A failed parse is a
# named refusal for that section, not a silent default.
FD_RESERVE=$(sed -n 's/.*kFdReserve = \([0-9][0-9]*\);.*/\1/p' src/ring_setup.hpp)
BODY_FILES=$(sed -n 's/.*kBodyFilesMax = \([0-9][0-9]*\);.*/\1/p' src/ring_setup.hpp)
MAX_LISTENERS=$(sed -n 's/.*kMaxListeners = \([0-9][0-9]*\);.*/\1/p' src/ring_setup.hpp)
# The backlog is not a literal in the source: the server takes [tune]
# backlog, and SOMAXCONN where the operator named none. So the number
# this tool checks against is the fallback, and the line below says that
# a configured backlog replaces it. The old parse looked for a literal
# that has not been there, and printed its refusal on every run.
BACKLOG=$(sed -n 's/.*backlog_ = ring_config.backlog != 0 ? ring_config.backlog : \([A-Z_]*\);.*/\1/p' \
          src/ring.hpp)
[ "$BACKLOG" = SOMAXCONN ] && BACKLOG=$(getconf SOMAXCONN 2>/dev/null || echo 4096)

read_or() {  # read_or <file> <fallback-text>
  if [ -r "$1" ]; then cat "$1"; else echo "$2"; fi
}

echo "==== webmachine-tune $(date -u +%FT%RZ) $(hostname) $(uname -srm) ===="

# ---- CPU placement ---------------------------------------------------
# "Do not pin" is inherited here, and this tree has not proven it.
#
# The two measurements that used to stand in this comment are both from
# a tree that is gone. One was the previous tree's client mask sweep
# (332k -> 341k -> 352k req/s from 2 to 15 to 30 cpus). The other read
# a 32 KiB asset at 0.07 of its rate under `taskset -c 0`, and its
# mechanism was io-wq workers inheriting the pinned thread's affinity -
# workers that carried splice.
#
# This tree has no splice. `grep -rn splice src/` finds four lines and
# every one of them is the word used about header fields; there is no
# IORING_OP_SPLICE. So that measurement describes a path this binary
# does not walk.
#
# io-wq did not go with it. A serving process shows `iou-wrk-<pid>`
# beside its own threads, and those workers carry the file work a ring
# cannot do inline - the open, the statx and the read behind every
# docroot answer. Measured here: a single-ring server on the docroot
# path holds 112 percent of a cpu, and the 12 is that pool. An io-wq
# worker inherits the affinity of the thread that issued its work, so
# pinning the reactor pins the pool as well.
#
# The plainer reason needs no ring at all: a pinned process cannot be
# moved, so the scheduler can no longer put it on a core with less to
# do. Measured on the author's machine, a pin showed no advantage.
#
# Two current reasons, then, and a stale number. This file states no
# number it cannot stand behind, so the line below names the reasons
# and not a rate, until the sweep is run here.
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

# Live steal over one second - contention is a property of now.
steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }
S0=$(steal_ticks); sleep 1; S1=$(steal_ticks)
echo "steal: +$((S1 - S0)) ticks over 1s (0 = quiet; sustained >0 = a neighbor is eating this host)"

echo "recommend: do not pin - no taskset, no cpu mask, no isolated core."
echo "  a pinned reactor pins its io-wq workers too - they inherit the"
echo "  affinity of the thread that issued their work, and they carry the"
echo "  open, statx and read behind every file this server answers."
echo "  and a pinned process cannot be moved, so the scheduler can no longer"
echo "  put it on a core with less to do. A pin showed no advantage where"
echo "  it was tried."
echo "  no rate is quoted: the old one measured splice, which this tree"
echo "  does not have. The reasons are current, the number is not."
# And most operators cannot do it even where they want to. A process may
# set its own mask, and a mask is inherited through exec, so `taskset -c
# 0 webmachine-server ...` works for anybody. Pinning a server that is
# already running is another matter: it needs CAP_SYS_NICE unless the
# caller owns the process. Measured: as uid 65534 against a root-owned
# pid, `taskset -pc 1` answers "failed to set affinity: Operation not
# permitted". A server under systemd User=nobody, or a container's
# non-root user, is therefore out of reach of `taskset -p` anyway.
WHOAMI=$(id -u)
if [ "$WHOAMI" -ne 0 ]; then
  echo "  you are uid $WHOAMI: pinning a server already running as another user"
  echo "  needs CAP_SYS_NICE and answers EPERM without it. A mask given at"
  echo "  exec is inherited and needs nothing - which is the form to avoid."
fi
if [ "$NPROC" -lt 4 ]; then
  echo "note: $NPROC cores leaves little to split. See the shape section: the"
  echo "  count it recommends is the cpu budget less one, and on a small"
  echo "  machine that is one ring."
fi

# ---- io_uring ---------------------------------------------------------
echo ""
echo "-- io_uring"
KREL=$(uname -r)
KMAJ=$(echo "$KREL" | cut -d. -f1)
KMIN=$(echo "$KREL" | cut -d. -f2 | sed 's/[^0-9].*//')
if [ "$KMAJ" -gt 6 ] 2>/dev/null || { [ "$KMAJ" -eq 6 ] && [ "${KMIN:-0}" -ge 11 ]; } 2>/dev/null; then
  echo "kernel $KREL: >= 6.11, has IORING_OP_BIND/LISTEN (the server probes this itself at init)"
else
  echo "kernel $KREL: below 6.11 - the server will refuse to start, by name (needs IORING_OP_BIND/LISTEN)"
fi

echo "recv bundles: as the kernel offers them (IORING_FEAT_RECVSEND_BUNDLE); the server reads the feature bit at init"

# ---- how many, and in what shape --------------------------------------
# Three shapes answer on one address, and they are not equal. Measured
# on the docroot path, this host, one session, both ends read:
#
#   A shared listener does not spread. Several processes that inherit
#   one listening socket do not share the peers: the kernel wakes the
#   same one every time. Four processes on one TCP listener, over five
#   seconds: one spent 549 clock ticks and the other three spent 5, 5
#   and 6. The rate is not merely flat, it falls - 0.37 of the single
#   process rate on h1.
#
#   A SO_REUSEPORT group spreads. Each process binds its own socket and
#   the kernel picks at the SYN. Two processes answered 1.86 times one
#   process on h1 and 1.93 times on h2. TCP only: AF_UNIX has no
#   SO_REUSEPORT.
#
#   An acceptor with answering threads spreads, and is the only shape
#   that spreads on AF_UNIX. One thread accepts and hands each peer to
#   the next ring by IORING_OP_MSG_RING. Three answering threads spent
#   356, 345 and 350 ticks while the acceptor spent 3.
#
# The whole matrix, on 4 cpus, req/s, median of three runs. Read the
# count across, the shape down:
#
#   h1 AF_UNIX   threads    102.8k  231.2k  318.5k  296.3k
#                shared              75.6k   67.5k   67.9k
#   h1 TCP       threads     58.6k  138.3k  220.8k  207.1k
#                reuseport          129.1k  236.9k  191.8k
#                shared              43.9k   46.5k   43.8k
#   h2 AF_UNIX   threads    871.6k   4.88M   6.23M   6.78M
#                shared             759.2k  788.5k  760.5k
#   h2 TCP       threads      1.01M   4.92M   6.14M   6.15M
#                reuseport           1.84M   1.72M   1.79M
#                shared             817.5k  781.9k  769.8k
#
# What the rows say, and what they do not:
#
#   The shared listener is flat at every count and on every transport,
#   and below one ring on h2. More children change nothing there.
#   h1 peaks at three of four cpus and falls at four. h2 is flat from
#   three to four - the 6.23M and 6.78M of the AF_UNIX row differ by 9
#   percent, which these cells cannot resolve.
#   The h2 reuseport row is not read as a server property. Its client
#   held 161 to 188 percent of a cpu against the thread row's 114 to
#   154, so part of that gap is a client that could not keep up, on a
#   machine that also ran the server.
#
# So the advice below is by transport, and it never names --workers for
# throughput: that flag forks children onto one inherited listener,
# which is the shape that loses.
echo ""
echo "-- how many, and in what shape"
# What this process may actually use, not what the machine has. A quota
# is the number the shape has to fit inside.
BUDGET=$NPROC
if [ -r /sys/fs/cgroup/cpu.max ]; then
  set -- $(cat /sys/fs/cgroup/cpu.max)
  if [ "${1:-max}" != max ] && [ "${2:-0}" -gt 0 ] 2>/dev/null; then
    BUDGET=$(( $1 / $2 ))
    [ "$BUDGET" -lt 1 ] && BUDGET=1
  fi
fi
echo "cpu this process may use: $BUDGET (cores $NPROC)"
# One core is left over on purpose: the kernel does the socket work of
# every answer, and on a machine that also runs the client there is
# nothing left to do it with. The count is answering threads, or
# servers in a reuseport group - not counting the acceptor, which does
# almost nothing (3 ticks against 350 in the run above).
SHAPE_N=$(( BUDGET - 1 ))
[ "$SHAPE_N" -lt 1 ] && SHAPE_N=1
echo "recommend: $SHAPE_N answering ring(s)"
echo "  h1 peaked here at the cpu budget less one and fell above it. h2 was"
echo "  flat from there to the whole budget, so $SHAPE_N is the count for both."
if [ "$BUDGET" -le 2 ]; then
  echo "  $BUDGET cpu is too few to split. One ring, and every core left for the"
  echo "  kernel side of the answers."
fi
echo ""
echo "  files only, any transport (--docroot / --assets, no --app):"
echo "    $BIN --unix=/run/webmachine.sock --docroot=DIR --threads=$SHAPE_N"
echo "    one acceptor, $SHAPE_N answering threads, one ring each. The only shape"
echo "    that spreads on AF_UNIX."
echo ""
echo "  an application, TCP:"
echo "    $SHAPE_N separate servers on one port. Each binds its own socket and"
echo "    the kernel spreads at the SYN (SO_REUSEPORT, set by the server):"
I=1
while [ "$I" -le "$SHAPE_N" ]; do
  echo "      $BIN --port=8080 --app=your_app.mrb &"
  I=$((I + 1))
done
echo ""
echo "  an application, AF_UNIX:"
echo "    one server. A unix path has no SO_REUSEPORT, and --threads answers"
echo "    files only - a thread that answers from an application needs a VM"
echo "    of its own, and this build gives it none."
echo "      $BIN --unix=/run/webmachine.sock --app=your_app.mrb"
echo ""
echo "  not for throughput: --workers=N. Its children inherit one listening"
echo "  socket, and a shared listener gives every peer to the same child."

# ---- resource limits -------------------------------------------------
# Since #169 the server derives its capacity itself: at init it raises
# soft to hard (ceiling fs.nr_open) and takes everything the final
# limit allows minus the reserve, the body files and the listeners
# (src/ring_setup.hpp). This section prints that arithmetic -
# the server does not need help, but the operator deserves the number.
echo ""
echo "-- capacity (the server derives this itself at init)"
HARD=$(ulimit -Hn)
NR_OPEN=$(read_or /proc/sys/fs/nr_open "")
if [ -z "$FD_RESERVE" ] || [ -z "$BODY_FILES" ] || [ -z "$MAX_LISTENERS" ]; then
  echo "cannot parse kFdReserve/kBodyFilesMax/kMaxListeners out of src/ring_setup.hpp - capacity arithmetic not printed (fix the parse, do not guess)"
else
  if [ "$HARD" = "unlimited" ]; then
    LIMIT=${NR_OPEN:-1048576}
  else
    LIMIT=$HARD
    [ -n "$NR_OPEN" ] && [ "$NR_OPEN" -lt "$LIMIT" ] && LIMIT=$NR_OPEN
  fi
  # Kernel cap on a fixed-file table: 2^20 (io_uring/rsrc.c).
  TABLE_CAP=1048576
  MAXC=$((LIMIT - FD_RESERVE - BODY_FILES - MAX_LISTENERS))
  [ $((MAXC + MAX_LISTENERS)) -gt "$TABLE_CAP" ] && MAXC=$((TABLE_CAP - MAX_LISTENERS))
  echo "RLIMIT_NOFILE hard: $HARD   fs.nr_open: ${NR_OPEN:-unreadable}"
  echo "max connections: $LIMIT - $FD_RESERVE (fd reserve) - $BODY_FILES (body files) - $MAX_LISTENERS (listeners) = $MAXC"
  if [ "$MAXC" -le 0 ]; then
    echo "the limit leaves no room - the server will refuse to start; raise it: systemd LimitNOFILE=$((FD_RESERVE + BODY_FILES + MAX_LISTENERS + 1024)) or higher"
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
if [ "$SHAPE_N" -gt 1 ]; then
  echo "  $BIN --port=8080 --app=your_app.mrb      # this line $SHAPE_N times, one port, one group"
else
  echo "  $BIN --port=8080 --app=your_app.mrb"
fi
echo "  (no taskset on purpose - see the cpu placement section)"
echo "  (the shape section above says how many, and why)"
