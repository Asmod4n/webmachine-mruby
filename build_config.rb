MRuby::Build.new do |conf|
  conf.toolchain

  conf.enable_bintest
  conf.enable_test

  # march=native: every machine compiles its own binary, so every
  # recorded number is bound to the host that measured it.
  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  conf.gembox 'default'
  conf.gem mgem: 'mruby-io-uring'
  conf.gem mgem: 'mruby-phr'
  conf.gem mgem: 'mruby-chrono'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
