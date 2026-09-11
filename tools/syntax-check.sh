#!/bin/bash
# A syntax check of one source file, with no object written.
#
# Why it exists: a full `rake compile` of this tree is minutes, and most
# of an edit's life is spelling. This answers "does it still compile" in
# seconds, and it answers nothing else - a change is not done until
#
#   MRUBY_CONFIG=build_config_debug.rb rake test
#
# has run. The include list is read from the debug build's own
# dependency files, so it cannot drift from what the build uses. Run
# rake compile once before the first check, so that tree exists.
#
#   tools/syntax-check.sh src/http1.cpp src/http2.cpp
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
build="$root/mruby/build/debug"
[ -d "$build" ] || { echo "no debug build yet: run MRUBY_CONFIG=build_config_debug.rb rake compile" >&2; exit 2; }
inc=(-I"$root/src"
     -I"$root/mruby/include"
     -I"$build/include"
     -I"$build/mrbgems/mruby-slipstreamio/build/include"
     -I"$build/mrbgems/webmachine-mruby/src"
     -I"$root/mruby/build/repos/debug/mruby-ktls/include"
     -I"$root/mruby/build/repos/debug/mruby-phr/include"
     -I"$root/mruby/build/repos/debug/slipstreamIO/src")
for d in "$root"/mruby/build/repos/debug/*/include "$root"/mruby/build/repos/debug/*/src \
         "$root"/deps/*/ "$root"/deps/*/deps/*/; do
  [ -d "$d" ] && inc+=(-I"$d")
done
fail=0
for f in "$@"; do
  g++ -fsyntax-only -std=c++20 -Wall -Wextra -DMRB_DEBUG=1 -DMRB_UTF8_STRING \
      -DMRB_USE_CXX_EXCEPTION -DWM_EXAMPLES "${inc[@]}" "$f" || fail=1
done
exit $fail
