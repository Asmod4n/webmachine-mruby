# NO LOCKFILE. mruby writes build_config_*.rb.lock beside this file and
# then PREFERS it: load_gems.rb takes the locked commit over the branch a
# dependency names, so a gem pinned here to a branch quietly keeps
# whatever commit the lock first saw. This tree names branches on
# purpose - the seam lives in mruby-slipstreamio and moves - and a lock
# turned that into a checkout that silently stayed months behind, with a
# liburing.a to match. Measured: the shim path failed on a fix that had
# been in the branch for hours.
MRuby::Lockfile.disable

MRuby::Build.new('pgo') do |conf|
  conf.toolchain

  # -Wundef is mruby's own default (mruby/tasks/toolchains/gcc.rake). It
  # finds nothing in this tree and hundreds of lines in the vendored
  # sources every gem here carries - simdutf, ada, lmdb, ls-hpack - which
  # belong to other people and are not ours to fix. A build whose real
  # warnings scroll off the screen has no warnings. The last flag wins.
  conf.cc.flags  << '-Wno-undef'
  conf.cxx.flags << '-Wno-undef'

  # mrbc is a TOOL of this build, not an artifact of another one: the
  # gem builds it here. Naming an external mrbc under mruby/bin
  # instead made a cold tree unbuildable - nothing in this config
  # produces that path, so rake had no rule for it.
  conf.gem core: 'mruby-bin-mrbc'

  dir = File.expand_path('pgo-profile', __dir__)
  mode = ENV['WM_PGO']
  pgo = case mode
        when 'gen'
          # -ftest-coverage writes the .gcno notes gcov reads names from;
          # -fprofile-generate alone writes .gcda only -fprofile-use can
          # decode. Compile-time notes, nothing in the running binary.
          ["-fprofile-generate=#{dir}", '-ftest-coverage']
        when 'use'
          ["-fprofile-use=#{dir}", '-fprofile-correction',
           '-fprofile-partial-training', '-Wno-missing-profile']
        else
          abort 'build_config_pgo.rb: WM_PGO must be gen or use'
        end

  # Stamp file under mruby/build/pgo: the WM_PGO mode that last built it.
  stamp = File.expand_path('mruby/build/pgo/.wm_pgo_mode', __dir__)
  if File.exist?(stamp)
    recorded = File.read(stamp)
    if recorded != mode
      abort "build_config_pgo.rb: mruby/build/pgo was built with WM_PGO=#{recorded} - " \
            "this run wants WM_PGO=#{mode}, and mruby's rake does not rebuild an object " \
            "for a flags-only mode switch, so stale #{recorded}-mode objects would reach " \
            "the link. Fix: rm -rf mruby/build/pgo"
    end
  else
    mkdir_p File.dirname(stamp)
    File.write(stamp, mode)
  end

  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'
  conf.cc.flags.concat(pgo)
  conf.cxx.flags.concat(pgo)
  conf.linker.flags << '-fprofile-generate' if mode == 'gen'

  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |c|
    c.flags.each { |f| f.delete('-g') if f.is_a?(Array) }
    c.flags.delete('-g')
  end

  conf.gem File.expand_path(File.dirname(__FILE__))
end
