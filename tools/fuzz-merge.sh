#!/bin/bash
# Shrink every corpus to the smallest set with the SAME coverage (#88).
#
#   tools/fuzz-merge.sh
#
# A campaign keeps every input that reached one new edge, so a corpus
# grows for hours and most of what it holds is a longer way of saying
# what a shorter entry already says. libFuzzer's -merge=1 answers
# exactly that: it replays a corpus into an empty directory and keeps
# only the inputs that ADD coverage, in order of increasing size.
#
# WHY IT IS WORTH RUNNING and not just tidiness: every fuzz run starts
# by replaying the whole corpus before it mutates anything, so a
# corpus with ten thousand redundant entries costs that replay on
# every restart and on every one of a -fork campaign's children. The
# minimal set has the same reach and starts in a fraction of the time.
#
# SAFE BY CONSTRUCTION: the merge writes into a NEW directory and the
# old one is only replaced once libFuzzer has exited successfully. A
# merge that dies halfway leaves the corpus it was called on
# untouched - which matters, because that corpus may be the only copy
# of hours of work.
set -eu
cd "$(dirname "$0")/.."

TARGETS="${TARGETS:-ws wsdeflate http feed assets}"
OUT=build/fuzz
RSS_LIMIT="${RSS_LIMIT:-4096}"

for t in $TARGETS; do
  bin="$OUT/$t"
  corpus="$OUT/corpus-$t"
  if [ ! -x "$bin" ]; then
    echo "$t: no binary - run tools/fuzz.sh first (it builds them)" >&2
    continue
  fi
  if [ ! -d "$corpus" ]; then
    echo "$t: no corpus yet"
    continue
  fi
  before=$(ls "$corpus" | wc -l)
  bytes_before=$(du -sk "$corpus" | cut -f1)
  fresh="$OUT/corpus-$t.merged"
  rm -rf "$fresh"
  mkdir -p "$fresh"
  # -merge=1 <destination> <source>: replay source, keep what adds
  # coverage. The dictionary is not passed - a merge mutates nothing,
  # so it has nothing to mutate WITH.
  if "$bin" -merge=1 -rss_limit_mb="$RSS_LIMIT" "$fresh" "$corpus" > "$OUT/$t.merge.log" 2>&1; then
    after=$(ls "$fresh" | wc -l)
    bytes_after=$(du -sk "$fresh" | cut -f1)
    rm -rf "$corpus"
    mv "$fresh" "$corpus"
    printf '%-11s %6s -> %-6s files   %6s -> %-6s KiB\n' \
      "$t" "$before" "$after" "$bytes_before" "$bytes_after"
  else
    rm -rf "$fresh"
    echo "$t: merge FAILED, corpus left as it was (see $OUT/$t.merge.log)" >&2
  fi
done
