# The TEST build for the PORTABLE path - alone and self-contained, no
# shared file. Four builds now, four files: this one (portable_debug),
# build_config_host.rb, build_config_debug.rb, build_config_
# portable.rb - MRUBY_CONFIG=build_config_portable_debug.rb rake (or
# rake test) builds/tests ONLY this target.
#
# build_config_debug.rb tests the io_uring path; nothing exercised
# slipstreamIO's select(2) fallback beyond the Rakefile's 3-second
# portable_smoke, because "portable" (build_config_portable.rb) is a
# RELEASE build and release builds do not get tests (enable_test/
# enable_bintest live on debug builds only). This is that gap closed:
# SLIPSTREAM_IO_ONLY + enable_test/enable_bintest together, so the
# portable code path gets the same unit/bintest coverage the io_uring
# path already has, not just a smoke check.
#
# -Og -g3 -ggdb, not -O3: a debug build, for the same reason build_
# config_debug.rb is - stepping in gdb, locals intact, breakpoints
# that land where the source says.
MRuby::Build.new('portable_debug') do |conf|
  conf.toolchain

  # mrbc only bootstraps for free on a build literally named "host"
  # (MRuby::Build#host? == @name == "host"; see mruby/lib/mruby/
  # build.rb's create_mrbc_build). This file builds only
  # "portable_debug" standalone, so it borrows build_config_host.rb's
  # own isolated mrbc bootstrap instead of growing one of its own -
  # built once by `rake` against build_config_host.rb, then read here
  # every time after.
  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  # See build_config_portable.rb: the one define that drops
  # mruby-io-uring and takes <liburing.h> over as slipstreamIO's
  # select(2) shim.
  conf.cc.defines  << 'SLIPSTREAM_IO_ONLY'
  conf.cxx.defines << 'SLIPSTREAM_IO_ONLY'

  # MRB_DEBUG (and -g3): mruby keeps the debug hooks the error log's
  # backtraces and the tracer need. Only debug builds carry them.
  conf.enable_debug

  # enable_test here turns every add_test_dependency in the whole gem
  # graph into a real dependency of THIS build - see build_config_
  # debug.rb for the full reasoning. Release builds (host, portable)
  # enable neither; only the two debug builds do.
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
  # includes <liburing.h> and nothing else). SLIPSTREAM_IO_ONLY above
  # forces the takeover unconditionally, real liburing or not.
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
