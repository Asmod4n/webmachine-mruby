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

  # One section per function and per object, and a link that drops the
  # ones nothing reaches. Without this the linker's unit is the object
  # file, so ONE referenced symbol drags in the whole translation unit -
  # and an amalgamated dependency is one translation unit. Measured on
  # ada 3.4.4 (mruby-uri-parser vendors it that way): the object is
  # 103 KB .text and 256 KB .rodata whole, while a program that calls
  # only url_search_params keeps 13 KB of it and one that calls only
  # percent_decode keeps 6 KB. That difference is the whole question of
  # whether such a dependency is affordable on the request path at all
  # (.DESIGN.md #cold-paths: ~14 KB per big function against a 32 KiB
  # L1i), and it costs one flag pair to have.
  section_flags = %w[-ffunction-sections -fdata-sections]
  conf.cc.flags.concat(section_flags)
  conf.cxx.flags.concat(section_flags)
  conf.linker.flags << '-Wl,--gc-sections'

  # LTO is asked for, never assumed: the optimizer's unit becomes the
  # program instead of the file, and the bill is paid at link time by
  # ONE process. gcc's whole-program stage (lto1-wpa) is not what
  # -flto=auto parallelizes - that is the ltrans phase after it - and on
  # this tree it was killed by the OOM killer at 13.8 GB RSS in a 14 GB
  # cgroup. A machine with the memory can have it; a container that
  # builds the same tree must not fail because of a default.
  #
  # gcc-ar, not ar: with LTO an object's real content is GCC's IR in a
  # section plain ar does not index, so a symbol defined in an archive
  # member goes missing at link time. The wrapper loads the LTO plugin
  # and indexes it. libmruby.a is exactly such an archive, so this is
  # not optional once LTO is on. No ranlib line: the archiver writes
  # `rcs`, which builds the index in the same step.
  #
  # The optimization and -march flags are repeated on the link line
  # because that is where the code is generated under LTO; the compile
  # step only records IR.
  if ENV['WM_LTO']
    lto = "-flto=#{ENV['WM_LTO'] == '1' ? 'auto' : ENV['WM_LTO']}"
    conf.cc.flags << lto
    conf.cxx.flags << lto
    conf.archiver.command = 'gcc-ar'
    conf.linker.flags << lto << '-O3' << "-march=#{march}"
  end

  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.gem File.expand_path(File.dirname(__FILE__))
end
