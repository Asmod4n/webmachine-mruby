MRuby::Build.new('pgo') do |conf|
  conf.toolchain

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  dir = File.expand_path('pgo-profile', __dir__)
  pgo = case ENV['WM_PGO']
        when 'gen'
          ["-fprofile-generate=#{dir}"]
        when 'use'
          ["-fprofile-use=#{dir}", '-fprofile-correction',
           '-fprofile-partial-training', '-Wno-missing-profile']
        else
          abort 'build_config_pgo.rb: WM_PGO must be gen or use'
        end

  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'
  conf.cc.flags.concat(pgo)
  conf.cxx.flags.concat(pgo)
  conf.linker.flags << '-fprofile-generate' if ENV['WM_PGO'] == 'gen'

  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.gem File.expand_path(File.dirname(__FILE__))
end
