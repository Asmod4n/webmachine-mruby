# Builds the gem inside an mruby checkout - master HEAD, per project
# decision: the gem tracks mruby as it is developed, and the checkout's
# revision is printed by `rake compile` so every measurement can name it.
MRUBY_DIR = File.expand_path('mruby', __dir__)
CONFIG = ENV['MRUBY_CONFIG'] || File.expand_path('build_config.rb', __dir__)

file MRUBY_DIR do
  sh "git clone --depth 1 https://github.com/mruby/mruby.git #{MRUBY_DIR}"
end

desc 'build'
task compile: MRUBY_DIR do
  sh "git -C #{MRUBY_DIR} log -1 --format='mruby %h %ad' --date=short"
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake"
end

desc 'build and run every test'
task test: MRUBY_DIR do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake all test"
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
