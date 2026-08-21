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
  conf.gem mgem: 'mruby-phr'
  conf.gem mgem: 'mruby-chrono'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
