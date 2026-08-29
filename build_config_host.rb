MRuby::Build.new do |conf|
  conf.toolchain

  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.gem File.expand_path(File.dirname(__FILE__))
end
