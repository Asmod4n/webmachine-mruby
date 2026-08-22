MRuby::Build.new do |conf|
  conf.toolchain

  conf.enable_bintest
  conf.enable_test

  # march=native: every machine compiles its own binary, so every
  # recorded number is bound to the host that measured it.
  conf.cc.flags << '-O3' << '-march=native'
  conf.cxx.flags << '-O3' << '-march=native' << '-std=c++20'

  # WM_PROFILE=1: symbols (-g) and retained frame pointers, for perf -
  # never the shape a req/s number is taken through. -g only adds a
  # debug section (zero runtime cost); -fno-omit-frame-pointer costs a
  # register and a fraction of a percent, which is why it stays opt-in
  # and out of every reference build. `rake clean` between the two -
  # the build system does not reliably rebuild on a flags-only change.
  if ENV['WM_PROFILE'] == '1'
    conf.cc.flags << '-g' << '-fno-omit-frame-pointer'
    conf.cxx.flags << '-g' << '-fno-omit-frame-pointer'
  end

  # Not 'default': that box also adds mirb/mruby/mrdb/mruby-strip (each
  # pulling mruby-compiler in for its own REPL/eval needs) and the
  # metaprog box (which adds mruby-compiler directly, "to build other
  # mrbgems" - a build-time job the toolchain does for itself either
  # way, not a reason for the shipped binary to carry a parser). This
  # server loads precompiled .mrb only (#100) and touches none of
  # eval/binding/Method/UnboundMethod, so metaprog's whole box is
  # skipped too - stdlib/stdlib-ext/stdlib-io/math cover everything the
  # product and its tests use.
  #
  # mrbc itself is NOT listed here. Every build named "host" gets one
  # for free: the toolchain bootstraps an isolated host/mrbc build
  # (mruby-compiler and all) to compile the tree's own mrblib, and
  # exposes it as this build's `mrbcfile` - a separate artifact,
  # nothing here links against it. Adding the mruby-bin-mrbc gem HERE
  # too, as 'default' did, would build a second mrbc redundantly and,
  # worse, pull mruby-compiler into THIS build's own gem list, i.e.
  # into webmachine-server's libmruby.
  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'stdlib-io'
  conf.gembox 'math'
  conf.gem mgem: 'mruby-io-uring'
  # slipstreamIO decides what <liburing.h> resolves to on THIS host: it
  # stands aside when mruby-io-uring built a real liburing, and takes
  # over the name when it could not. That is the only reason it is
  # here - no source in this tree names it (see src/ring.hpp, which
  # includes <liburing.h> and nothing else).
  conf.gem github: 'Asmod4n/slipstreamIO', branch: 'main'
  conf.gem mgem: 'mruby-phr'
  # mruby-chrono pulls in mruby-c-ext-helpers, whose mrbgem.rake lists
  # `add_test_dependency 'mruby-compiler'` alongside its other test-only
  # gems - normally inert, but conf.enable_test/enable_bintest above
  # (needed for `rake test` to run at all, on this same build) turn
  # every add_test_dependency in the whole gem graph into a real one,
  # for every gem, not only the one under test. So mruby-compiler is
  # still an active gem of THIS build and still lands in
  # webmachine-server's libmruby via the generated gem_init.c, which
  # calls every active gem's init unconditionally - dropping 'default'
  # above (#100) does not reach this one. Confirmed by build summary
  # ("host" lists mruby-compiler) and `nm` (mrb_mruby_compiler_gem_init
  # present in the linked binary). The fix is upstream, in
  # mruby-c-ext-helpers itself, or in splitting this tree's one build
  # target into a shipping build and a test build - both bigger than
  # #100 asked for, so this is named here rather than done silently.
  conf.gem mgem: 'mruby-chrono'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
