MRuby::Build.new do |conf|
  conf.toolchain

  conf.enable_bintest
  conf.enable_test

  # march=native: every machine compiles its own binary, so every
  # recorded number is bound to the host that measured it.
  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

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

  conf.gembox 'default'
  conf.gem mgem: 'mruby-io-uring'
  # slipstreamIO decides what <liburing.h> resolves to on THIS host: it
  # stands aside when mruby-io-uring built a real liburing, and takes
  # over the name when it could not. That is the only reason it is
  # here - no source in this tree names it (see src/ring.hpp, which
  # includes <liburing.h> and nothing else).
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem mgem: 'mruby-phr'
  conf.gem mgem: 'mruby-chrono'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
