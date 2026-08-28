#!/bin/bash
# RETIRED. The per-target harness that lived here fuzzed METHODS -
# five libFuzzer targets, each calling an internal function directly.
# That is not the attack surface: what a peer cannot reach through the
# socket is not an attack point (#206). It also rotted, because a
# target bound to an internal API breaks on every refactor and reports
# it as "does not build", which nobody reads as an alarm.
#
# What replaced it, both driving the SERVER through a real socket:
#   tools/webmachine-fuzz  (build_config_libfuzzer.rb) - libFuzzer in
#     a second binary, a client connected to the real listener, the
#     reactor stepped with Ring::tick. Coverage-guided.
#   tools/fuzz-socket.py   (build_config_fuzz.rb) - the shipped server
#     as its OWN process, so a death, a restart and a wedge are
#     visible from outside. Blind, and complementary.
echo "tools/fuzz.sh is retired - see the header, and #206" >&2
exit 2
