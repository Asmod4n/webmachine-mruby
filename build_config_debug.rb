# The TEST build, alone and self-contained - no shared file, no other
# build_config.rb requires this one or is required by it. Three
# builds, three files: this one (debug), build_config_host.rb,
# build_config_portable.rb - MRUBY_CONFIG=build_config_debug.rb rake
# (or rake test) builds/tests ONLY this target.
#
# Where the tests run, WITH debug: enable_debug sets MRB_DEBUG, which
# the error log needs for mruby backtraces, and the tracer builds on
# the same ground. Test gems (and their demands) live only here.
#
# -Og -g3 -ggdb, not -O3: this build is for DEBUGGING - stepping in
# gdb, locals that have not been optimized away, breakpoints that land
# where the source says. What -O3 does to the ship build is a separate
# question this binary does not answer; profiling reads the ship
# build's own codegen, not a debug build standing in for it.
MRuby::Build.new('debug') do |conf|
  conf.toolchain

  # mrbc only bootstraps for free on a build literally named "host"
  # (MRuby::Build#host? == @name == "host"; see mruby/lib/mruby/
  # build.rb's create_mrbc_build). This file builds only "debug"
  # standalone, so it borrows build_config_host.rb's own isolated mrbc
  # bootstrap instead of growing one of its own - built once by `rake`
  # against build_config_host.rb, then read here every time after.
  # That is the one ordering dependency independence has: host first,
  # once; debug after, as many times as iteration needs, without
  # rebuilding host again.
  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  # MRB_DEBUG (and -g3): mruby keeps the debug hooks the error log's
  # backtraces and the tracer need. Only this build carries them.
  conf.enable_debug

  # enable_test here turns every add_test_dependency in the whole gem
  # graph into a real dependency of THIS build: mruby's
  # add_test_dependency is add_dependency guarded only by
  # test_enabled? (lib/mruby/gem.rb) - there is no separate mrbtest
  # gem set, so a test-only gem's objects land in this build's
  # libmruby. That is exactly why the SHIP build enables nothing: what
  # rides in here (mruby-fast-json via mruby-toml's tests, and the
  # MRB_UTF8_STRING it requires below) never reaches the shipped
  # binary (#176, first half; the compiler half is the remaining
  # task).
  conf.enable_bintest
  conf.enable_test

  conf.cc.flags << '-Og' << '-g3' << '-ggdb'
  conf.cxx.flags << '-Og' << '-g3' << '-ggdb' << '-std=c++20'

  # mruby-toml's test suite rides in mruby-fast-json, which requires
  # UTF-8 strings in core. Test build only - the ship build has
  # neither the gem nor the define.
  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

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
