# The build system names this gem: mruby/lib/mruby/gem.rb resolves a gem
# called `hal-<short>-<conf>` as the external HAL for the gem whose name
# ends in <short>, and drops that gem's own ports/* from the build. So
# `hal-task-webmachine` replaces mruby-task/ports/posix, which this
# server cannot use - see src/task_hal.cpp for why.
MRuby::Gem::Specification.new('hal-task-webmachine') do |spec|
  spec.license = 'Apache-2.0'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby-task HAL for a threaded io_uring server'

  spec.add_dependency 'mruby-task', core: 'mruby-task'

  spec.linker.flags_before_libraries << '-pthread'
  spec.cc.flags << '-pthread'
  spec.cxx.flags << '-pthread'
end
