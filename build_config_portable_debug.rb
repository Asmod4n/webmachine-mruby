MRuby::Build.new('portable_debug') do |conf|
  conf.toolchain

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  conf.cc.defines  << 'SLIPSTREAM_IO_ONLY'
  conf.cxx.defines << 'SLIPSTREAM_IO_ONLY'

  conf.enable_debug

  conf.enable_bintest
  conf.enable_test

  conf.cc.flags << '-Og' << '-mavx2' << '-g3' << '-ggdb'
  conf.cxx.flags << '-Og' << '-mavx2' << '-g3' << '-ggdb' << '-std=c++20'

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
