# NO LOCKFILE. mruby writes build_config_*.rb.lock beside this file and
# then PREFERS it: load_gems.rb takes the locked commit over the branch a
# dependency names, so a gem pinned here to a branch quietly keeps
# whatever commit the lock first saw. This tree names branches on
# purpose - the seam lives in mruby-slipstreamio and moves - and a lock
# turned that into a checkout that silently stayed months behind, with a
# liburing.a to match. Measured: the shim path failed on a fix that had
# been in the branch for hours.
MRuby::Lockfile.disable

MRuby::Build.new do |conf|
  conf.toolchain

  # -march: forgecore builds native and always has, and every number in
  # bench/results/forgecore.log was taken that way - changing that here
  # would make the next A/B measure the ISA as well as the change. A box
  # that MIGRATES between hosts cannot use native: gcc resolves it to
  # whatever the machine booted on (cascadelake, on the container this
  # was written on), and that binary meets an illegal instruction on the
  # next host - and under valgrind. WM_MARCH= is how such a box asks for
  # a fixed ISA without changing what anybody else builds.
  march = ENV['WM_MARCH'] || 'native'
  conf.cc.flags << '-O3' << "-march=#{march}"
  conf.cxx.flags << '-O3' << "-march=#{march}" << '-std=c++20'

  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.gem File.expand_path(File.dirname(__FILE__))
end
