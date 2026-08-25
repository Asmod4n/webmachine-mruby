#!/bin/bash
# What [tune] zero_copy_threshold should be ON THIS MACHINE.
#
# The crossover between copying a dynamic body into the send buffer and
# LENDING the handler's own String to the kernel is a property of the box:
# its memory bandwidth, its allocator, how busy its neighbours are. The
# default baked into src/webmachine.hpp (kZeroCopyDefault, 128 KiB) was
# measured on one shared 4-vCPU container and errs high on purpose. This
# measures the same A/B here and prints the line to paste.
#
#   bench/vm/zero_copy_advise.sh
#   REPS=13 bench/vm/zero_copy_advise.sh        # slower, steadier
#   MARGIN=15 bench/vm/zero_copy_advise.sh      # demand a bigger win
#
# It REUSES bench/vm/ring_body.sh - the same driver, the same real
# Ring<App>, the same pinned/paired/interleaved discipline, the same
# median-of-per-rep-ratios. Nothing about the measurement is respelled
# here; this file only READS its verdict and turns it into a number.
#
# This is bench/, not tools/: it measures, it costs a minute of CPU, and
# it appends to bench/results/. tools/webmachine-tune.sh stays read-only
# by charter and gets no benchmark bolted onto it.
#
# THE RULE it applies, and why it is not just "smallest winning size":
# a size qualifies when zero-copy beat copy by at least MARGIN percent AND
# won at least three quarters of its reps. The recommendation is the
# smallest qualifying size whose LARGER sizes all qualify too. That tail
# test is not decoration - an earlier run of this very harness showed a
# 40-47% "win" at 4-16KB that a control experiment traced to glibc
# allocator behaviour tied to object lifetime, with nothing to do with
# copy-avoidance, and 32KB in the middle did not win. A monotone tail is
# what tells a real crossover from a hole in the allocator.
set -eu
cd "$(dirname "$0")/../.."

SIZES="${SIZES:-16384 32768 65536 131072 262144}"
REPS="${REPS:-7}"
MARGIN="${MARGIN:-10}"

echo "webmachine: measuring the copy/lend crossover on $(hostname) ($(uname -m))"
echo "webmachine: sizes: $SIZES  reps: $REPS  margin: ${MARGIN}%"
echo "webmachine: this runs the real reactor once per size per rep per"
echo "webmachine: variant - several minutes, and the box should be"
echo "webmachine: otherwise idle for every one of them."
echo

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

# The measurement itself, unchanged and unwrapped. copy:0 is today's shape
# and zero:1 the lend; copyhold is left out because this tool decides a
# threshold, not an attribution.
SIZES="$SIZES" REPS="$REPS" VARIANTS="copy:0 zero:1" \
  bench/vm/ring_body.sh | tee "$OUT"

echo
awk -v margin="$MARGIN" '
  # "<size>   paired zero     /copy median 0.746  (+25.4% vs copy)  won 7/7 reps"
  /paired zero/ && /vs copy/ {
    size = $1 + 0
    pct = $0; sub(/.*\(/, "", pct); sub(/%.*/, "", pct); pct = pct + 0
    w = $0; sub(/.*won /, "", w); sub(/ reps.*/, "", w)
    split(w, ab, "/")
    n[++k] = size; P[size] = pct; WON[size] = ab[1] + 0; OF[size] = ab[2] + 0
  }
  function qualifies(s) {
    return (P[s] >= margin && OF[s] > 0 && WON[s] * 4 >= OF[s] * 3)
  }
  END {
    if (k == 0) {
      print "webmachine: no paired result came back - the runs failed, and"
      print "webmachine: a threshold guessed from nothing is worse than the default."
      exit 1
    }
    for (i = 1; i <= k; i++)
      for (j = i + 1; j <= k; j++)
        if (n[j] < n[i]) { t = n[i]; n[i] = n[j]; n[j] = t }

    printf "%-10s %10s %10s   %s\n", "size", "zero vs copy", "reps won", "verdict"
    for (i = 1; i <= k; i++) {
      s = n[i]
      printf "%-10d %+9.1f%% %10s   %s\n", s, P[s], WON[s] "/" OF[s],
             qualifies(s) ? "lend wins" : "copy stands"
    }

    # The smallest qualifying size with a fully qualifying tail above it.
    pick = 0
    for (i = k; i >= 1; i--) {
      if (!qualifies(n[i])) break
      pick = n[i]
    }

    print ""
    if (pick == 0) {
      print "webmachine: lending never cleared the margin here. Copy every body:"
      print ""
      print "  [tune]"
      print "  zero_copy_threshold = 0"
      print ""
      print "webmachine: 0 is a real answer, not a fallback - it turns lending off."
      exit 0
    }
    printf "webmachine: crossover at %d bytes. Paste into webmachine.toml:\n", pick
    print ""
    print "  [tune]"
    printf "  zero_copy_threshold = %d\n", pick
    print ""
    printf "webmachine: or --zero-copy-threshold %d, or conf.zero_copy_threshold = %d\n",
           pick, pick
    if (pick != n[1]) {
      printf "webmachine: (%d and below did not clear the margin - see the table.)\n", n[1]
    }
    if (pick == n[k]) {
      print "webmachine: the largest size measured is the answer, so the real"
      print "webmachine: crossover may be above it - rerun with a wider SIZES."
    }
  }
' "$OUT"
