MRuby::Build.new('pgo') do |conf|
  conf.toolchain

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

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
