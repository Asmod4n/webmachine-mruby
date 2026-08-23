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
  Rake::Task[:ship_smoke].invoke
end

# THE SHIPPED BINARY IS THE ONE NOBODY WAS TESTING. Since the build
# split in two (build_config.rb's head), enable_test/enable_bintest
# live on `debug` alone - so every unit test and every bintest runs
# against the debug binary, and the host binary an operator actually
# runs is covered by nothing. That gap was not theoretical: a compiler
# bug (see WM_MARCH in build_config.rb) put an instruction into the
# host build that the CPU refused, and the whole green suite had
# nothing to say about it.
#
# So: after the suite, start the ship binary and ask it one question.
# It is three seconds and it catches "does not even come up", which is
# the failure a test suite on another binary structurally cannot see.
desc 'the SHIP binary starts and answers - what the suite (debug) never checks'
task :ship_smoke do
  require 'socket'
  bin = File.expand_path('mruby/build/host/bin/webmachine-server', __dir__)
  raise "no ship binary at #{bin} - run rake compile first" unless File.executable?(bin)

  sock = "/tmp/wm-ship-smoke-#{$$}.sock"
  log = "/tmp/wm-ship-smoke-#{$$}.log"
  File.unlink(sock) if File.exist?(sock)
  pid = spawn(bin, '--unix', sock, out: File::NULL, err: log)
  begin
    200.times do
      break if File.socket?(sock)
      sleep 0.05
    end
    unless File.socket?(sock)
      raise "the SHIP binary never came up:\n#{begin File.read(log) rescue '' end}"
    end
    answer = UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: ship\r\nConnection: close\r\n\r\n")
      s.read
    end
    unless answer.start_with?('HTTP/1.1 200')
      raise "the SHIP binary answered:\n#{answer}"
    end
    puts 'ship smoke: the shipped binary starts and answers 200'
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    File.unlink(log) rescue nil
  end
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
