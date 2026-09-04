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
#
# -fsanitize=fuzzer is NOT here, and that is the whole point: a flag in a
# build's linker reaches every binary the build produces, and mrbc - a
# tool of this build, from a core gem - has a main of its own for
# libFuzzer's to collide with. So the fuzzer flag lives with the fuzz
# binary, in mrbgem.rake, and only the sanitizers are build-wide.
MRuby::Build.new('libfuzzer') do |conf|
  conf.toolchain :clang

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

  conf.enable_debug

  # The toolchain's own: it puts ONE -fsanitize= string into cc, cxx and
  # the linker, which is what mruby-slipstreamio's mrbgem.rake looks for
  # before it hands liburing's configure --enable-sanitizer. Hand-pushed
  # flags used to have to be one String per entry for the same reason.
  conf.enable_sanitizer 'address', 'undefined'

  # After enable_sanitizer, because a -fno-sanitize= only subtracts from
  # an -fsanitize= to its left. ls-hpack and phr read unaligned on
  # purpose; that is not what this campaign is about, and it fires on the
  # first frame otherwise.
  tuning = %w[-fno-sanitize-recover=undefined -fno-omit-frame-pointer
              -fno-sanitize=alignment]
  tuning.each { |f| conf.cc.flags << f }
  conf.cc.flags << '-O1' << '-g'
  tuning.each { |f| conf.cxx.flags << f }
  conf.cxx.flags << '-O1' << '-g' << '-std=c++20'
  conf.linker.flags << '-no-pie'

  conf.cc.defines  << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'
  conf.cxx.defines << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
