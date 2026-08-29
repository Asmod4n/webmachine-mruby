#!/bin/bash
# A comment carries an anchor - an RFC clause, an issue, a file:line, a
# measurement, a proper name - or it does not exist (.DESIGN.md,
# commandment 2). This counts the ones that do not.
cd "$(dirname "$0")/.."
out=$(mktemp)
for f in src/*.cpp src/*.hpp; do
  tot=$(grep -cE "^\s*//" "$f")
  ok=$(grep -E "^\s*//" "$f" | grep -cE "RFC [0-9]|#[0-9]{2,}|\.(cpp|hpp|rb|c|h):|WHATWG|POSIX|§|[0-9]+ ?(ns|us|ms|MB|KB|bytes)|\b(ada|hiredis|lmdb|liburing|slipstream|miniz|ls-hpack|picohttpparser|Dean|Sheehy)\b")
  printf "%s %s\n" "$((tot-ok))" "$(basename "$f")"
done | sort -rn > "$out"

base=tools/comment-anchors.baseline
[ -f "$base" ] || { cat "$out"; rm -f "$out"; exit 0; }

# A ratchet, not a gate: 1772 unanchored lines cannot be fixed in one
# commit, but no file may get worse while they are being fixed.
rc=0
while read -r n f; do
  was=$(awk -v f="$f" '$2 == f { print $1 }' "$base")
  [ -n "$was" ] || was=0
  if [ "$n" -gt "$was" ]; then
    echo "$f: $n unanchored comments, was $was"
    rc=1
  fi
done < "$out"
if [ "$rc" = 0 ]; then
  echo "comment anchors: no file got worse ($(awk '{s+=$1} END {print s}' "$out") unanchored)"
fi
rm -f "$out"
exit $rc
