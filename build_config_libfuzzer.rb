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
  # an -fsanitize= to its left.
  #
  # -fsanitize-recover=pointer-overflow is the ONE exception to "an UB
  # report ends the run", and it is here so that a report can be
  # SUPPRESSED at all: an unrecoverable check aborts inside its handler,
  # before UBSAN_OPTIONS=suppressions is ever consulted. ls-hpack does
  # NULL + 0 on the first dynamic-table insert of every h2 connection
  # (tools/webmachine-fuzz/ubsan.supp names it), and a campaign that dies
  # at run one on a submodule's defect is a campaign that never runs. It
  # is two checks because that one line trips both: the NULL + 0 is
  # pointer-overflow, and handing the result to memcpy is
  # nonnull-attribute. The cost is real and worth writing down: those two
  # checks in OUR code are now printed with a stack and walked past
  # instead of ending the run. Every other UB check still ends it, and
  # the way to get these back is a fixed ls-hpack.
  tuning = %w[-fno-sanitize-recover=undefined
              -fsanitize-recover=pointer-overflow,nonnull-attribute
              -fno-omit-frame-pointer -fno-sanitize=alignment]
  tuning.each { |f| conf.cc.flags << f }
  conf.cc.flags << '-O1' << '-g'
  tuning.each { |f| conf.cxx.flags << f }
  conf.cxx.flags << '-O1' << '-g' << '-std=c++20'
  conf.linker.flags << '-no-pie'

  conf.cc.defines  << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'
  conf.cxx.defines << 'MRB_UTF8_STRING' << 'WM_FUZZ_BUILD'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
