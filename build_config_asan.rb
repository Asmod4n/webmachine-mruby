# The debug build, plus AddressSanitizer and UndefinedBehaviorSanitizer.
#
# What it is for: a stall that only appears on a CI runner and never
# here. A use-after-free or an overflow of a buffer the reactor hands
# around does not have to crash to end a run - it can leave a connection
# waiting for an answer nobody will write. ASan says so at the moment it
# happens rather than minutes later.
#
# See build_config_tsan.rb for the other half. They cannot share a build:
# -fsanitize=address and -fsanitize=thread refuse each other.
MRuby::Lockfile.disable

MRuby::Build.new('asan') do |conf|
  # clang, as in the thread build: the ignore list below is a clang
  # feature, and one compiler for both sanitizer builds is one thing
  # to keep working.
  conf.toolchain :clang

  conf.cc.flags  << '-Wno-undef'
  conf.cxx.flags << '-Wno-undef'

  conf.gem core: 'mruby-bin-mrbc'
  conf.gem core: 'mruby-bin-mruby'

  conf.enable_debug
  conf.enable_bintest
  conf.enable_test

  # -O1 and a frame pointer: the sanitizers ask for both, and a trace
  # without frame pointers names the wrong function.
  ignore = File.expand_path('sanitizer-ignore.txt', File.dirname(__FILE__))
  san = %W[-fsanitize=address,undefined -fno-omit-frame-pointer
           -fno-sanitize-recover=all -fsanitize-ignorelist=#{ignore}
           -O1 -g3 -ggdb]
  conf.cc.flags.concat(san)
  conf.cxx.flags.concat(san + %w[-std=c++20])
  # The runtime is linked, not just compiled in.
  conf.linker.flags.concat(%w[-fsanitize=address,undefined])

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'
  conf.cc.defines  << 'WM_EXAMPLES'
  conf.cxx.defines << 'WM_EXAMPLES'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
