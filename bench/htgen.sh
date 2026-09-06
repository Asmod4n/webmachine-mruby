#!/bin/bash
# Which htgen a bench runs: the one on PATH, and nothing else.
#
# Not $HOME, not a clone beside this tree, not a fixed /usr path. The
# reason is a measurement that went wrong: a machine had two builds of
# the SAME commit in two places, the scripts took whichever they found
# first, the h2 rows dropped 13%, and the server was blamed for a
# client. One name on PATH is one answer.
#
# `make install` is how a client gets there. HTGEN= overrides it for a
# one-off run.
#
# Sourced by every bench script; prints the path on stdout.

# Which commit a binary was built from. htgen bakes it in and answers
# --version. A date is not a version: two builds of one commit carry two
# dates and nothing that says they are the same code.
bench_htgen_version() {
  local v
  v=$("$1" --version 2>/dev/null | head -1)
  case "$v" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) echo "$v" ;;
    *) echo "no --version, built $(date -u -r "$1" +%Y-%m-%dT%H:%MZ)" ;;
  esac
}

bench_htgen() {
  if [ -n "${HTGEN:-}" ]; then
    [ -x "$HTGEN" ] || { echo "HTGEN=$HTGEN is not executable" >&2; return 1; }
    echo "$HTGEN"
    return 0
  fi

  local c
  c=$(command -v htgen 2>/dev/null) && [ -x "$c" ] && { echo "$c"; return 0; }

  echo "no htgen on PATH. Install it:" >&2
  echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen" >&2
  echo "  make -C ~/htgen && make -C ~/htgen install PREFIX=~/.local" >&2
  echo "or point HTGEN= at the binary." >&2
  return 1
}
