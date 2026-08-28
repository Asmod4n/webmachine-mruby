# build_config_host.rb's flags, plus the C++ resource example (#207).
#
# It is a SEPARATE target because the example is not part of what this
# tree ships: the host build stays exactly the two binaries an operator
# installs. The flags are copied verbatim from build_config_host.rb so
# the example's number and the host build's number may be compared -
# a measurement across different flags would compare the compiler.
MRuby::Build.new('example') do |conf|
  conf.toolchain

  # A NAMED build has no mrbc of its own; the host build's is the one
  # every target here uses (build_config_debug.rb does the same).
  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.cc.defines  << 'WM_EXAMPLES'
  conf.cxx.defines << 'WM_EXAMPLES'

  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
