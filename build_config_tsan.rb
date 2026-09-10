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
# says about those is its own blind spot, not a race.
#
# Nothing is suppressed. src/compute_task.cpp tells the sanitizer where
# the io_uring handover of a compute slot begins and ends, with
# __tsan_release and __tsan_acquire, so the sanitizer knows the order
# the kernel gives and still reports every race in the pool.
MRuby::Lockfile.disable

MRuby::Build.new('tsan') do |conf|
  # clang, not the default: GCC cannot keep the 'always_inline'
  # promise in the vendored ada.cpp under -fsanitize=thread, and it
  # stops with an error. clang is the reference for TSan and compiles
  # the same file.
  conf.toolchain :clang

  conf.cc.flags  << '-Wno-undef'
  conf.cxx.flags << '-Wno-undef'

  conf.gem core: 'mruby-bin-mrbc'
  conf.gem core: 'mruby-bin-mruby'

  conf.enable_debug
  conf.enable_bintest
  conf.enable_test

  # One string, and the sanitizer flag is not at its front. The
  # slipstreamIO gem reads the flag list and configures the carried
  # liburing with --enable-sanitizer when an entry starts with
  # '-fsanitize='. That switch means address and undefined for
  # liburing, always, so a thread build would link an address runtime
  # into a thread binary and the link fails. The compiler reads the
  # string as two flags, so the build gets what it asks for.
  san = ['-fno-omit-frame-pointer -fsanitize=thread', '-O1', '-g3', '-ggdb']
  conf.cc.flags.concat(san)
  conf.cxx.flags.concat(san + %w[-std=c++20])
  conf.linker.flags.concat(%w[-fsanitize=thread])

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'
  conf.cc.defines  << 'WM_EXAMPLES'
  conf.cxx.defines << 'WM_EXAMPLES'

  conf.gem File.expand_path(File.dirname(__FILE__))
end
