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

  san = %w[-fsanitize=address,undefined -fno-sanitize-recover=undefined
           -fno-omit-frame-pointer -fno-sanitize=alignment]
  # ls-hpack and phr read unaligned on purpose; that is not what this
  # campaign is about, and it fires on the first frame otherwise.

  conf.cc.flags << '-O1' << '-g3' << san
  conf.cxx.flags << '-O1' << '-g3' << '-std=c++20' << san
  conf.linker.flags << '-fsanitize=address,undefined'

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
