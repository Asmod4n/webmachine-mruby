MRuby::Build.new('portable') do |conf|
  conf.toolchain

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  conf.cc.defines  << 'SLIPSTREAM_IO_ONLY'
  conf.cxx.defines << 'SLIPSTREAM_IO_ONLY'

  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

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
