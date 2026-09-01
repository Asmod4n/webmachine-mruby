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

  conf.gem File.expand_path(File.dirname(__FILE__))
end
