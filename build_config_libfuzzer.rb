# The SECOND binary: the same server sources, with the fuzzer's entry
# point instead of the CLI's (#206). Nothing here changes what the
# server does - it changes who calls it, and the shipped binary never
# carries a byte of this.
#
# clang, because libFuzzer is clang's. -no-pie because libmruby.a is
# built without -fPIE and clang defaults to PIE. -fno-sanitize=alignment
# because ls-hpack and phr read unaligned on purpose.
MRuby::Build.new('libfuzzer') do |conf|
  conf.toolchain :clang

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)
  conf.enable_debug

  san = %w[-fsanitize=fuzzer-no-link,address,undefined
           -fno-sanitize-recover=undefined -fno-omit-frame-pointer
           -fno-sanitize=alignment]

  conf.cc.flags << '-O1' << '-g' << san
  conf.cxx.flags << '-O1' << '-g' << '-std=c++20' << san
  conf.linker.flags << '-fsanitize=fuzzer,address,undefined' << '-no-pie'

  conf.cc.defines  << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'
  conf.cxx.defines << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'

  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
