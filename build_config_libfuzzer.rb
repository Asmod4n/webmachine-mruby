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

  # mrbc is a TOOL of this build, not an artifact of another one: the
  # gem builds it here. Naming an external mrbc under mruby/bin
  # instead made a cold tree unbuildable - nothing in this config
  # produces that path, so rake had no rule for it.
  conf.gem core: 'mruby-bin-mrbc'

  conf.enable_debug

  # ONE FLAG PER ENTRY, as Strings: mruby-io_uring's mrbgem.rake looks
  # for a cc.flags entry that is_a?(String) and starts with -fsanitize=,
  # and only then hands liburing's configure --enable-sanitizer. Pushed
  # as an Array the check misses, and liburing ends up built WITHOUT
  # sanitizer support while everything around it has it.
  san = %w[-fsanitize=fuzzer-no-link,address,undefined
           -fno-sanitize-recover=undefined -fno-omit-frame-pointer
           -fno-sanitize=alignment]

  san.each { |f| conf.cc.flags << f }
  conf.cc.flags << '-O1' << '-g'
  san.each { |f| conf.cxx.flags << f }
  conf.cxx.flags << '-O1' << '-g' << '-std=c++20'
  conf.linker.flags << '-fsanitize=fuzzer,address,undefined' << '-no-pie'

  conf.cc.defines  << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'
  conf.cxx.defines << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
