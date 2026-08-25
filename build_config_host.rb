# The SHIP build, alone and self-contained - no shared file, no other
# build_config.rb requires this one or is required by it. Three
# builds, three files: this one (host), build_config_debug.rb,
# build_config_portable.rb - MRUBY_CONFIG=build_config_host.rb rake
# builds ONLY this target. No env var picks a variant of it; what you
# get is what this file says, which is the whole point of naming it
# instead of toggling it.
#
# No enable_test, no bintest, so no test-only gem ever rides into its
# libmruby - mruby-fast-json/simdjson and the MRB_UTF8_STRING they
# demand simply do not exist here. This is the binary bench/ measures
# and operators run.
MRuby::Build.new do |conf|
  conf.toolchain

  # Every machine compiles its own binary, so every recorded number is
  # bound to the host that measured it - always native, no override.
  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  # THE 23 MB WERE DWARF (#184). mruby's gcc toolchain hardcodes -g
  # into its compiler_flags (tasks/toolchains/gcc.rake:3), so every
  # object carried full debug info and the shipped binary was 23.4 MB
  # of which 20.1 MB was .debug_*: `strip` alone took it to 3.38 MB
  # without touching one instruction. Nobody asked for it, nothing
  # reads it, and it rode into every container image.
  #
  # So it is removed at the SOURCE rather than stripped off the end -
  # the ship binary never carries symbols at all. Profiling reads
  # build_config_debug.rb's binary instead, which carries -g3
  # unconditionally already - this file never needs a debug-symbols
  # variant of its own.
  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  # Not 'default': that box also adds mirb/mruby/mrdb/mruby-strip (each
  # pulling mruby-compiler in for its own REPL/eval needs) and the
  # metaprog box (which adds mruby-compiler directly, "to build other
  # mrbgems" - a build-time job the toolchain does for itself either
  # way, not a reason for the shipped binary to carry a parser). This
  # server loads precompiled .mrb only (#100) and touches none of
  # eval/binding/Method/UnboundMethod, so metaprog's whole box is
  # skipped too - stdlib/stdlib-ext/stdlib-io/math cover everything
  # the product and its tests use.
  #
  # mrbc itself is NOT listed here. This build, named "host", gets one
  # for free: the toolchain bootstraps an isolated host/mrbc build
  # (mruby-compiler and all) to compile the tree's own mrblib, and
  # exposes it as this build's `mrbcfile` - a separate artifact,
  # nothing here links against it. build_config_debug.rb and
  # build_config_portable.rb both point their own conf.mrbcfile at
  # this build's mruby/build/host/mrbc/bin/mrbc rather than growing a
  # second one - so this file must build first, once.
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
