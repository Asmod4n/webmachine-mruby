MRuby::Build.new do |conf|
  conf.toolchain

  conf.enable_bintest
  conf.enable_test

  # -O2, not -O3: the difference has to be measured before it is paid
  # for in code size; icache pressure was a real cost in the old tree.
  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  conf.gembox 'default'
  conf.gem mgem: 'mruby-io-uring'
  conf.gem mgem: 'mruby-phr'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
