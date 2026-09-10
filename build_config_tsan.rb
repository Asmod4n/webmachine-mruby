# The debug build, plus ThreadSanitizer.
#
# What it is for: the compute pool is threads, and a run that stops on a
# CI runner and never here is what a race looks like from the outside.
# TSan reports the race whether or not it fired, so it does not need the
# stall to happen while it watches.
#
# One known source of noise: the reactor shares memory with the kernel -
# the completion ring and the provided buffer pool are written on one
# side and read on the other, and TSan sees only this side. Anything it
# says about those is its own blind spot, not a race. Nothing is
# suppressed here yet, so the first run says what it says and the
# suppressions come from reading it.
MRuby::Lockfile.disable

MRuby::Build.new('tsan') do |conf|
  conf.toolchain

  conf.cc.flags  << '-Wno-undef'
  conf.cxx.flags << '-Wno-undef'

  conf.gem core: 'mruby-bin-mrbc'
  conf.gem core: 'mruby-bin-mruby'

  conf.enable_debug
  conf.enable_bintest
  conf.enable_test

  san = %w[-fsanitize=thread -fno-omit-frame-pointer -O1 -g3 -ggdb]
  conf.cc.flags.concat(san)
  conf.cxx.flags.concat(san + %w[-std=c++20])
  conf.linker.flags.concat(%w[-fsanitize=thread])

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'
  conf.cc.defines  << 'WM_EXAMPLES'
  conf.cxx.defines << 'WM_EXAMPLES'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
