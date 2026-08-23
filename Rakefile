# Builds the gem inside an mruby checkout - master HEAD, NEVER a tag.
# That is a security decision, not a taste one: mruby's newest release
# tag carries known holes that master has already fixed, so pinning here
# would be pinning to the vulnerable one. Anybody tidying up later and
# reaching for `--branch <latest tag>` is making it worse, not tidier.
#
# The cost, stated: --depth 1 clones once and never refreshes, so a
# checkout made months ago is months of unfixed master behind. `rake
# compile` prints the revision and its date on every build for exactly
# that reason - and it is what lets a measurement name what it ran on.
# Refresh with: git -C mruby fetch --depth 1 origin master && git -C mruby reset --hard FETCH_HEAD
MRUBY_DIR = File.expand_path('mruby', __dir__)
CONFIG = ENV['MRUBY_CONFIG'] || File.expand_path('build_config.rb', __dir__)

file MRUBY_DIR do
  sh "git clone --depth 1 https://github.com/mruby/mruby.git #{MRUBY_DIR}"
end

desc 'build'
task compile: MRUBY_DIR do
  sh "git -C #{MRUBY_DIR} --no-pager log -1 --format='mruby %h %ad' --date=short"
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
