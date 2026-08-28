MRuby::Build.new('debug') do |conf|
  conf.toolchain

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  conf.enable_debug

  conf.enable_bintest
  conf.enable_test

  conf.cc.flags << '-Og' << '-mavx2' << '-g3' << '-ggdb'
  conf.cxx.flags << '-Og' << '-mavx2' << '-g3' << '-ggdb' << '-std=c++20'

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

  # bintest/cpp_resource.rb needs the example binary to exist (#207).
  conf.cc.defines  << 'WM_EXAMPLES'
  conf.cxx.defines << 'WM_EXAMPLES'

  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
