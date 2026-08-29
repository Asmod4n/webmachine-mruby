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

  conf.mrbcfile = File.expand_path('mruby/bin/mrbc', __dir__)

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
