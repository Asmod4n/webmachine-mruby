# NO LOCKFILE. mruby writes build_config_*.rb.lock beside this file and
# then PREFERS it: load_gems.rb takes the locked commit over the branch a
# dependency names, so a gem pinned here to a branch quietly keeps
# whatever commit the lock first saw. This tree names branches on
# purpose - the seam lives in mruby-slipstreamio and moves - and a lock
# turned that into a checkout that silently stayed months behind, with a
# liburing.a to match. Measured: the shim path failed on a fix that had
# been in the branch for hours.
MRuby::Lockfile.disable

# The SECOND binary: the same server sources, with the fuzzer's entry
# point instead of the CLI's (#206). Nothing here changes what the
# server does - it changes who calls it, and the shipped binary never
# carries a byte of this.
#
# clang, because libFuzzer is clang's. -no-pie because libmruby.a is
# built without -fPIE and clang defaults to PIE. -fno-sanitize=alignment
# because ls-hpack and phr read unaligned on purpose.
# mrbc is a TOOL, and a tool must not carry the fuzzer's entry point:
# -fsanitize=fuzzer goes to EVERY link in a build, and mrbc has a main of
# its own - the link dies on the collision (and on libFuzzer's missing
# LLVMFuzzerTestOneInput) long before the fuzz binary is reached. So mrbc
# is built HERE, first, by a plain toolchain, and the fuzz build is
# pointed at it. In this file, because an mrbc named under mruby/bin has
# no rule that produces it and left a cold tree unbuildable; and under
# its own name, because a build called 'host' would write into the
# directory the shipped build owns.
MRuby::Build.new('libfuzzer-tools') do |conf|
  conf.toolchain
  conf.gem core: 'mruby-bin-mrbc'
end

MRuby::Build.new('libfuzzer') do |conf|
  conf.toolchain :clang

  conf.mrbcfile = "#{MRuby.targets['libfuzzer-tools'].build_dir}/bin/mrbc"

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
