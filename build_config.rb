# THREE builds:
#
#   host   - no name, the SHIP build. No enable_test, no bintest, so
#            no test-only gem ever rides into its libmruby (the
#            enable_test door below) - mruby-fast-json/simdjson and
#            the MRB_UTF8_STRING it demands simply do not exist here.
#            This is the binary bench/ measures and operators run.
#   debug  - where the tests run, WITH debug: enable_debug sets
#            MRB_DEBUG, which the coming error log needs for mruby
#            backtraces, and the tracer after it builds on the same
#            ground. Test gems (and their demands) live only here.
#   portable - the same ship binary WITHOUT liburing: <liburing.h>
#            resolves to slipstreamIO's select(2) implementation, on
#            any host. It exists because io_uring can be forbidden to
#            a PROCESS on a machine that has it - Debian/Ubuntu ship
#            kernel.io_uring_disabled=2 hardening, Docker's default
#            seccomp profile blocks the syscalls, SELinux/AppArmor
#            can too - and a binary linked against liburing has
#            nothing else to fall back on. CORRECT, NOT FAST: it is
#            the way out, not the way.
#
# Shared shape lives in the lambdas; a difference between the two
# builds should be a DECISION visible in the block below, never an
# accident of copy drift.

# march=native: every machine compiles its own binary, so every
# recorded number is bound to the host that measured it.
#
# WM_MARCH overrides it, and exists for ONE caller: a container image,
# which is built on one machine and run on another. `native` there
# bakes the BUILDER's CPU into the binary, and the first host with an
# older one dies on an illegal instruction. An image build names a
# baseline instead (x86-64-v3 is the sane fleet floor: AVX2, ~2015 and
# later), and pays whatever that costs against a native build - which
# is a measurement, and belongs in bench/results/ like every other.
WM_FLAGS = lambda do |conf|
  # WM_MARCH also buys the way OUT of a broken toolchain, found the
  # hard way in this tree's own container (gcc 13.3, -march=native
  # resolving to cascadelake): gcc emitted `vmovw` - an AVX512-FP16
  # instruction, EVEX MAP5 - into three objects (ours, mruby-io's,
  # mruby's fp_uscale) although its own `-Q --help=target` reports
  # -mavx512fp16 as disabled, and the CPU traps it with SIGILL at
  # startup. A compiler bug, not a tree bug; `WM_MARCH=x86-64-v3 rake`
  # sidesteps it, and `rake clean` first, because the build system
  # does not rebuild on a flags-only change.
  march = ENV['WM_MARCH'] || 'native'
  conf.cc.flags << '-O3' << "-march=#{march}"
  conf.cxx.flags << '-O3' << "-march=#{march}" << '-std=c++20'

  # WM_PROFILE=1: symbols (-g) and retained frame pointers, for perf -
  # never the shape a req/s number is taken through. -g only adds a
  # debug section (zero runtime cost); -fno-omit-frame-pointer costs a
  # register and a fraction of a percent, which is why it stays opt-in
  # and out of every reference build. `rake clean` between the two -
  # the build system does not reliably rebuild on a flags-only change.
  if ENV['WM_PROFILE'] == '1'
    conf.cc.flags << '-g' << '-fno-omit-frame-pointer'
    conf.cxx.flags << '-g' << '-fno-omit-frame-pointer'
  end
end

# Not 'default': that box also adds mirb/mruby/mrdb/mruby-strip (each
# pulling mruby-compiler in for its own REPL/eval needs) and the
# metaprog box (which adds mruby-compiler directly, "to build other
# mrbgems" - a build-time job the toolchain does for itself either
# way, not a reason for the shipped binary to carry a parser). This
# server loads precompiled .mrb only (#100) and touches none of
# eval/binding/Method/UnboundMethod, so metaprog's whole box is
# skipped too - stdlib/stdlib-ext/stdlib-io/math cover everything the
# product and its tests use.
#
# mrbc itself is NOT listed here. Every build named "host" gets one
# for free: the toolchain bootstraps an isolated host/mrbc build
# (mruby-compiler and all) to compile the tree's own mrblib, and
# exposes it as this build's `mrbcfile` - a separate artifact,
# nothing here links against it. Adding the mruby-bin-mrbc gem HERE
# too, as 'default' did, would build a second mrbc redundantly and,
# worse, pull mruby-compiler into THIS build's own gem list, i.e.
# into webmachine-server's libmruby.
WM_GEMS = lambda do |conf|
  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  # slipstreamIO decides what <liburing.h> resolves to on THIS host: it
  # stands aside when mruby-io-uring built a real liburing, and takes
  # over the name when it could not. That is the only reason it is
  # here - no source in this tree names it (see src/ring.hpp, which
  # includes <liburing.h> and nothing else).
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end

MRuby::Build.new do |conf|
  conf.toolchain
  WM_FLAGS.call(conf)
  WM_GEMS.call(conf)
end

# The way out. One define is the whole declaration: webmachine's own
# mrbgem.rake and slipstreamIO's both read it and drop mruby-io-uring
# from THIS target's gem list - which is the only granularity mruby
# has (a build's gems belong to its libmruby.a, and every spec.bins
# entry links that same archive; there is no per-binary gem list).
# src/server.cpp then takes the SLIPSTREAM_IO branch and says at
# startup, in as many words, which implementation is serving.
MRuby::Build.new('portable') do |conf|
  conf.toolchain
  conf.cc.defines  << 'SLIPSTREAM_IO_ONLY'
  conf.cxx.defines << 'SLIPSTREAM_IO_ONLY'
  WM_FLAGS.call(conf)
  WM_GEMS.call(conf)
end

MRuby::Build.new('debug') do |conf|
  conf.toolchain
  # MRB_DEBUG (and -g): mruby keeps the debug hooks the error log's
  # backtraces and the tracer need. Only this build carries them.
  conf.enable_debug

  # enable_test here turns every add_test_dependency in the whole gem
  # graph into a real dependency of THIS build: mruby's
  # add_test_dependency is add_dependency guarded only by
  # test_enabled? (lib/mruby/gem.rb) - there is no separate mrbtest
  # gem set, so a test-only gem's objects land in this build's
  # libmruby. That is exactly why the SHIP build above enables
  # nothing: what rides in here (mruby-fast-json via mruby-toml's
  # tests, and the MRB_UTF8_STRING it requires below) never reaches
  # the shipped binary (#176, first half; the compiler half is the
  # remaining task).
  conf.enable_bintest
  conf.enable_test

  WM_FLAGS.call(conf)

  # mruby-toml's test suite rides in mruby-fast-json, which requires
  # UTF-8 strings in core. Test build only - the ship build has
  # neither the gem nor the define.
  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

  WM_GEMS.call(conf)
end
