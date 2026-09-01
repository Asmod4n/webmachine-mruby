# NO LOCKFILE. mruby writes build_config_*.rb.lock beside this file and
# then PREFERS it: load_gems.rb takes the locked commit over the branch a
# dependency names, so a gem pinned here to a branch quietly keeps
# whatever commit the lock first saw. This tree names branches on
# purpose - the seam lives in mruby-slipstreamio and moves - and a lock
# turned that into a checkout that silently stayed months behind, with a
# liburing.a to match. Measured: the shim path failed on a fix that had
# been in the branch for hours.
MRuby::Lockfile.disable

# The binary under the fuzzer: the SHIPPED server, unchanged in what it
# does, only compiled so that memory errors speak. Nothing here links a
# fuzzer into the process and nothing calls a function directly - the
# payload arrives the way an attacker's does, on the socket (#206).
#
# -fno-sanitize-recover=undefined: an UB report must END the run, not be
# logged and walked past, or the campaign records "no crash" for a bug.
# -fno-omit-frame-pointer: without it the ASan stack is a guess.
MRuby::Build.new('fuzz') do |conf|
  conf.toolchain

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
  san = %w[-fsanitize=address,undefined -fno-sanitize-recover=undefined
           -fno-omit-frame-pointer -fno-sanitize=alignment]
  # ls-hpack and phr read unaligned on purpose; that is not what this
  # campaign is about, and it fires on the first frame otherwise.

  san.each { |f| conf.cc.flags << f }
  conf.cc.flags << '-O1' << '-g3'
  san.each { |f| conf.cxx.flags << f }
  conf.cxx.flags << '-O1' << '-g3' << '-std=c++20'
  conf.linker.flags << '-fsanitize=address,undefined'

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
