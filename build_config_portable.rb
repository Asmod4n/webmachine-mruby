# The PORTABLE build, alone and self-contained - no shared file, no
# other build_config.rb requires this one or is required by it. Three
# builds, three files: this one (portable), build_config_host.rb,
# build_config_debug.rb - MRUBY_CONFIG=build_config_portable.rb rake
# builds ONLY this target.
#
# The same ship binary WITHOUT liburing: <liburing.h> resolves to
# slipstreamIO's select(2) implementation - the way OUT when io_uring
# is forbidden to a process (kernel.io_uring_disabled=2, a seccomp
# profile, SELinux/AppArmor), never a cross-OS build. CORRECT, NOT
# FAST: it is the way out, not the way.
MRuby::Build.new('portable') do |conf|
  conf.toolchain

  # See build_config_debug.rb's identical line: mrbc only bootstraps
  # for free on a build named "host", so this file borrows the one
  # build_config_host.rb already built instead of growing its own.
  # Host first, once; portable after, as many times as needed.
  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  # One define is the whole declaration: webmachine's own mrbgem.rake
  # and slipstreamIO's both read it and drop mruby-io-uring from THIS
  # target's gem list - which is the only granularity mruby has (a
  # build's gems belong to its libmruby.a, and every spec.bins entry
  # links that same archive; there is no per-binary gem list).
  # src/server.cpp then takes the SLIPSTREAM_IO branch and says at
  # startup, in as many words, which implementation is serving.
  conf.cc.defines  << 'SLIPSTREAM_IO_ONLY'
  conf.cxx.defines << 'SLIPSTREAM_IO_ONLY'

  # Every machine compiles its own binary, so every recorded number is
  # bound to the host that measured it - always native, no override.
  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  # THE 23 MB WERE DWARF (#184) - see build_config_host.rb's identical
  # block. Removed at the source, not stripped off the end; this ship
  # binary never carries symbols either.
  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
