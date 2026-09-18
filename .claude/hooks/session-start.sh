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
  printf '%s\n%s\n%s\n%s\n' \
    "=== HANDOFF.md (left by the previous session; deleted after this read) ===" \
    "$handoff" \
    "=== end of handoff ===" \
    "COMMIT THAT DELETION. A handoff has to be committed to reach the next \
container at all - a remote session is a fresh clone - so deleting it only \
here leaves it in HEAD, and every later clone reads a note that was answered \
weeks ago. \`git rm HANDOFF.md\` belongs in this session's first commit." || true
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
  # Once, not once per session. This appended blindly until 2026-09-18,
  # and the file had grown to 350 identical lines - every session adds
  # one, the file outlives the session, and nothing ever reads it twice.
  # The container's own provisioning already writes the same path into
  # /etc/environment and /etc/profile.d, so this is the third place; it
  # stays because CLAUDE_ENV_FILE is the one the harness reads for a
  # tool's environment.
  if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    line="export PATH=\"$GEMBIN:\$PATH\""
    if ! grep -qxF "$line" "$CLAUDE_ENV_FILE" 2>/dev/null; then
      echo "$line" >> "$CLAUDE_ENV_FILE"
    fi
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

echo "session-start: $(command -v rake >/dev/null 2>&1 && rake --version 2>/dev/null || echo 'rake MISSING')," \
     "liburing $([ -f /usr/include/liburing.h ] && echo ok || echo MISSING)," \
     "submodules $([ -f "$ROOT/deps/miniz/miniz.c" ] && echo ok || echo MISSING)"

# The mruby-lsp index, reported and never rebuilt here. Rebuilding it is
# `mruby-lsp-setup`, and that builds the whole mruby tree with every gem
# this project pulls - minutes, during which the harness is still
# starting its MCP servers into a 30 second window. A session start is
# the worst moment for it. So this says how old the index is and leaves
# the decision to whoever reads the line.
INDEX="$HOME/.cache/mruby-lsp/$(echo "$ROOT" | sed 's|^/||; s|/|_|g')"
if [ -f "$INDEX/native.sha256" ]; then
  age_days=$(( ( $(date +%s) - $(stat -c %Y "$INDEX/native.sha256") ) / 86400 ))
  newest_cxx=$(find "$ROOT/src" -name '*.cpp' -o -name '*.hpp' -newer "$INDEX/native.sha256" 2>/dev/null | head -1)
  if [ -n "$newest_cxx" ]; then
    echo "session-start: the mruby-lsp index is ${age_days} day(s) old and src/ has changed since." \
         "Its hover and diagnostics describe the older tree. \`mruby-lsp-setup $ROOT\` rebuilds it," \
         "and that builds the whole mruby tree - run it when nothing else needs the machine."
  else
    echo "session-start: the mruby-lsp index is ${age_days} day(s) old and matches src/"
  fi
else
  echo "session-start: no mruby-lsp index for this tree; hover and diagnostics have nothing to read"
fi

# The debug target needs mruby/bin/mrbc, which only the HOST build makes.
# Build order for a cold checkout, both several minutes:
#   rake compile                                   # host, makes mruby/bin/mrbc
#   MRUBY_CONFIG=build_config_debug.rb rake compile
