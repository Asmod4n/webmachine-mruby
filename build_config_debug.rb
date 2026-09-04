# NO LOCKFILE. mruby writes build_config_*.rb.lock beside this file and
# then PREFERS it: load_gems.rb takes the locked commit over the branch a
# dependency names, so a gem pinned here to a branch quietly keeps
# whatever commit the lock first saw. This tree names branches on
# purpose - the seam lives in mruby-slipstreamio and moves - and a lock
# turned that into a checkout that silently stayed months behind, with a
# liburing.a to match. Measured: the shim path failed on a fix that had
# been in the branch for hours.
MRuby::Lockfile.disable

MRuby::Build.new('debug') do |conf|
  conf.toolchain

  # -Wundef is mruby's own default (mruby/tasks/toolchains/gcc.rake). It
  # finds nothing in this tree and hundreds of lines in the vendored
  # sources every gem here carries - simdutf, ada, lmdb, ls-hpack - which
  # belong to other people and are not ours to fix. A build whose real
  # warnings scroll off the screen has no warnings. The last flag wins.
  conf.cc.flags  << '-Wno-undef'
  conf.cxx.flags << '-Wno-undef'

  # mrbc is a TOOL of this build, not an artifact of another one.
  # `conf.mrbcfile = mruby/bin/mrbc` named a path only a HOST build
  # installs, and this build is named 'debug' - mruby runs its mrbc
  # bootstrap only for a build called 'host' (lib/mruby/build.rb,
  # host? and create_mrbc_build) - so a tree without a prior host
  # build had no rule for that path and died before the first compile.
  # The gem builds mrbc here instead; mruby-bin-mruby comes with it so
  # the debug build carries an interpreter to probe itself with.
  conf.gem core: 'mruby-bin-mrbc'
  conf.gem core: 'mruby-bin-mruby'

  conf.enable_debug

  conf.enable_bintest
  conf.enable_test

  conf.cc.flags << '-Og' << '-mavx2' << '-g3' << '-ggdb'
  conf.cxx.flags << '-Og' << '-mavx2' << '-g3' << '-ggdb' << '-std=c++20'

  conf.cc.defines  << 'MRB_UTF8_STRING'
  conf.cxx.defines << 'MRB_UTF8_STRING'

  # bintest/cpp_resource.rb needs the example binary to exist (#207).
  conf.cc.defines  << 'WM_EXAMPLES'
  conf.cxx.defines << 'WM_EXAMPLES'



  # #30: the watcher is a promise about FOREIGN descriptors, and the only
  # honest test of one drives a real database. libpq is the case the
  # design was written against: it says what to wait for, and it changes
  # its mind in the middle of a wait - writable while it flushes,
  # readable while it reads.
  #
  # The TEST build only, and WITHOUT the gem's own tests: they need a
  # server on the default port and they are that repository's to run, not
  # this one's - 59 of them crashed here. bintest/watcher_pq.rb asks for
  # a database itself and skips when there is none.
  if system('pkg-config --exists libpq >/dev/null 2>&1')
    conf.gem github: 'Asmod4n/mruby-postgresql', branch: 'master' do |g|
      g.test_rbfiles = []
      g.test_objs = []
      g.test_preload = nil
    end
  end

  conf.gem File.expand_path(File.dirname(__FILE__))
end
