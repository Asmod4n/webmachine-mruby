#!/bin/bash
# SessionStart: make this checkout buildable, then hand over anything the
# last session left behind.
#
# Everything here is what a fresh remote container does NOT have and the
# build refuses without - learned the hard way, once each.
set -euo pipefail

ROOT="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

# The handoff goes first: it is the part a human wrote for the next
# session, and it is read exactly once. Deleted whether or not the setup
# below succeeds, so a failed build never replays a stale note.
if [ -f "$ROOT/HANDOFF.md" ]; then
  # Read and DELETE before printing. Printing can die on a closed pipe,
  # and with set -e that would leave the note behind to be replayed - a
  # handoff read twice is worse than one read late.
  handoff="$(cat "$ROOT/HANDOFF.md")"
  rm -f "$ROOT/HANDOFF.md"
  printf '%s\n%s\n%s\n' \
    "=== HANDOFF.md (left by the previous session; deleted after this read) ===" \
    "$handoff" \
    "=== end of handoff ===" || true
fi

# Only the web/remote container needs any of the rest; a laptop has it.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# rake is not on PATH in this image: ruby is /usr/local/bin/ruby but the
# gem executables live under the rbenv version that owns it.
GEMBIN="$(ruby -e 'require "rubygems"; print Gem.bindir' 2>/dev/null)"
if [ -n "$GEMBIN" ] && [ -d "$GEMBIN" ]; then
  export PATH="$GEMBIN:$PATH"
  command -v rake >/dev/null 2>&1 || gem install rake --no-document >/dev/null 2>&1 || true
  if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    echo "export PATH=\"$GEMBIN:\$PATH\"" >> "$CLAUDE_ENV_FILE"
  fi
fi

# mrbgem.rake aborts by name when <liburing.h> is missing, on every
# non-portable target. The kernel headers are already in the image; the
# library's are not.
if [ ! -f /usr/include/liburing.h ]; then
  (apt-get install -y liburing-dev >/dev/null 2>&1 ||
   sudo apt-get install -y liburing-dev >/dev/null 2>&1) || true
fi

# deps/ls-hpack and deps/miniz are submodules, and the build refuses with
# "deps/miniz is empty" without them.
if [ ! -f "$ROOT/deps/miniz/miniz.c" ] || [ ! -f "$ROOT/deps/ls-hpack/lshpack.c" ]; then
  git -C "$ROOT" submodule update --init --depth 1 >/dev/null 2>&1 || true
fi

echo "session-start: rake $(command -v rake >/dev/null 2>&1 && rake --version 2>/dev/null || echo 'MISSING')," \
     "liburing $([ -f /usr/include/liburing.h ] && echo ok || echo MISSING)," \
     "submodules $([ -f "$ROOT/deps/miniz/miniz.c" ] && echo ok || echo MISSING)"

# The debug target needs mruby/bin/mrbc, which only the HOST build makes.
# Build order for a cold checkout, both several minutes:
#   rake compile                                   # host, makes mruby/bin/mrbc
#   MRUBY_CONFIG=build_config_debug.rb rake compile
