#!/bin/bash
# Which htgen a bench runs, and the refusal when that is not one answer.
#
# The scripts used to try $HOME/htgen/htgen, then a clone beside this
# tree, then PATH, and take the first that existed. A machine with two
# clones then measured with whichever came first, and a row taken with
# one is not comparable with a row taken with the other: on 2026-09-06
# the h2 rows dropped 13% between two runs whose only visible difference
# was `htgen(2026-09-02)` against `htgen(2026-08-29)`.
#
# So: one candidate runs, several REFUSE, and HTGEN= settles it. The
# same rule bench/priority.sh follows - a number taken under conditions
# nobody chose is not a number.
#
# Sourced by every bench script; prints the path on stdout.
bench_htgen() {
  if [ -n "${HTGEN:-}" ]; then
    [ -x "$HTGEN" ] || { echo "HTGEN=$HTGEN is not executable" >&2; return 1; }
    echo "$HTGEN"
    return 0
  fi

  # Where to look, in order. The last two matter under sudo, which the
  # bench needs for renice: sudo sets HOME to /root, so $HOME/htgen is
  # not the operator's, and it replaces PATH with secure_path, which on
  # openSUSE has no /usr/local/bin - so an installed htgen is invisible
  # to `command -v`. SUDO_USER names who asked.
  local home_of_caller=""
  if [ -n "${SUDO_USER:-}" ]; then
    home_of_caller=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
  fi

  local found=() seen=() c real dup
  for c in "$HOME/htgen/htgen" "${home_of_caller:+$home_of_caller/htgen/htgen}" \
           "$PWD/../htgen/htgen" "$(command -v htgen 2>/dev/null)" /usr/local/bin/htgen; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    real=$(readlink -f "$c")
    case " ${seen[*]} " in *" $real "*) continue ;; esac
    # The same bytes under two names is one candidate, not two: an
    # installed copy beside the build it came from must not refuse.
    dup=0
    for other in "${found[@]}"; do
      cmp -s "$c" "$other" && { dup=1; break; }
    done
    [ "$dup" = 1 ] && continue
    seen+=("$real")
    found+=("$c")
  done

  if [ ${#found[@]} -eq 0 ]; then
    echo "htgen not found. Build it once:" >&2
    echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen && make -C ~/htgen" >&2
    echo "or point HTGEN= at the binary." >&2
    return 1
  fi

  if [ ${#found[@]} -gt 1 ]; then
    echo "more than one htgen, and they measure differently:" >&2
    for c in "${found[@]}"; do
      echo "  $c  ($(date -u -r "$c" +%Y-%m-%dT%H:%MZ))" >&2
    done
    echo "name one: HTGEN=<path>" >&2
    return 1
  fi

  echo "${found[0]}"
}
