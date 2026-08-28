
require 'socket'
require 'tempfile'

ELOG_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(ELOG_BIN)

def elog_compile(source)
  src = Tempfile.new(['wm-elog', '.rb'])
  src.write(source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-elog', '.mrb'])
  mrb.close
  raise "mrbc failed:\n#{source}" unless system(mrbc, '-g', '-o', mrb.path, src.path)
  mrb
ensure
  src&.unlink
end

ELOG_APP = <<~APP
  class Boom < Webmachine::Resource
    def to_html
      raise ArgumentError, 'the resource said no'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.add [:*], Boom }
    end
  end
APP

def elog_server(extra_args)
  app = elog_compile(ELOG_APP)
  sock = "/tmp/wm-elog-#{$$}.sock"
  log = "/tmp/wm-elog-#{$$}.log"
  err = "/tmp/wm-elog-stderr-#{$$}.log"
  [sock, log].each { |f| File.unlink(f) rescue nil }
  pid = spawn({ 'WM_BUNDLE' => '0' }, ELOG_BIN, '--unix', sock, '--app', app.path,
              '--error-log', log, *extra_args, out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, log
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    [sock, log, err].each { |f| File.unlink(f) rescue nil }
    app.unlink
  end
end

def elog_get(sock, target)
  s = UNIXSocket.new(sock)
  s.write "GET #{target} HTTP/1.1\r\nHost: e\r\nConnection: close\r\n\r\n"
  out = +''
  loop do
    out << s.readpartial(4096)
  rescue EOFError
    break
  end
  s.close
  out
end

def elog_await(log, want)
  100.times do
    break if File.exist?(log) && File.read(log).lines.size >= want
    sleep 0.05
  end
  File.read(log) rescue ''
end

assert('error log: a raise lands with class, message and trace') do
  elog_server([]) do |sock, log|
    answer = elog_get(sock, '/boom')
    assert_include answer, '500'
    assert_include answer, 'the resource said no'
    assert_false answer.include?('to_html')

    lines = elog_await(log, 2).lines
    head = lines.first.to_s
    assert_include head, 'ArgumentError: the resource said no'
    assert_include head, '/boom'
    assert_include head, ' 500 '
    assert_true lines.size > 1
    assert_include lines[1], "\tfrom "
    assert_include lines[1], ':in to_html'
  end
end

assert('error log: a request that does NOT raise writes nothing') do
  elog_server([]) do |sock, log|
    s = UNIXSocket.new(sock)
    s.write "DELETE / HTTP/1.1\r\nHost: e\r\nConnection: close\r\n\r\n"
    out = +''
    begin
      loop { out << s.readpartial(4096) }
    rescue EOFError
    end
    s.close
    assert_include out, '405'
    sleep 0.3
    assert_true !File.exist?(log) || File.size(log) == 0
  end
end

# The error log has NO ceiling and ignores --log-max-bytes on purpose.
# It is not a window: only 500s and exceptions land here, never ordinary
# traffic, so it grows in a fault storm - and there the FIRST entry names
# the cause while everything after it is consequence. Keeping the newest
# half, which is what the access log's cap does, would drop exactly the
# line worth having. Driven with an absurd cap so the difference shows.
assert('error log: --log-max-bytes does not apply, and the OLDEST entry survives') do
  cap = 4096
  elog_server(['--log-max-bytes', cap.to_s]) do |sock, log|
    60.times { |i| elog_get(sock, "/boom#{i}") }
    text = ''
    100.times do
      text = File.read(log) rescue ''
      break if text.include?('/boom59')
      sleep 0.05
    end
    assert_true File.size(log) > cap
    assert_include text, '/boom0 '
    assert_include text, '/boom59'
    assert_true text.start_with?('[')
  end
end

# The other half of the same switch, and the only stream it still governs.
# The access log IS a window - it answers what happened recently - so the
# cap keeps the newest and drops the oldest. Until this test the ceiling
# was pinned on the error stream, which is the one place it never applied.
#
# Read AFTER the server is gone, not by polling: the access stream buffers
# a whole MiB before it writes (webmachine-logd, `out.size() >= (1u << 20)`)
# while the error stream flushes per block. A few hundred requests are ~20 KB
# and sit in the daemon's memory until it exits, so a poll here would read an
# empty file and prove nothing. The exit flush is also what runs the cap.
assert('access log: --log-max-bytes is a ceiling, and the NEWEST lines survive') do
  cap = 8192
  app = elog_compile(ELOG_APP)
  sock = "/tmp/wm-alog-#{$$}.sock"
  alog = "/tmp/wm-alog-#{$$}.log"
  err = "/tmp/wm-alog-stderr-#{$$}.log"
  [sock, alog].each { |f| File.unlink(f) rescue nil }
  pid = spawn({ 'WM_BUNDLE' => '0' }, ELOG_BIN, '--unix', sock, '--app', app.path,
              '--log', alog, '--log-max-bytes', cap.to_s, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(sock); sleep 0.05 }
    raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
    400.times { |i| elog_get(sock, "/hit#{i}") }
    Process.kill('TERM', pid)
    Process.wait(pid)
    size = nil
    100.times do
      now = File.size(alog) rescue 0
      break if now != 0 && now == size
      size = now
      sleep 0.05
    end
    text = File.read(alog) rescue ''
    assert_true File.size(alog) <= cap
    assert_include text, '/hit399'
    assert_false text.include?('/hit0 ')
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    [sock, alog, err].each { |f| File.unlink(f) rescue nil }
    app.unlink
  end
end

# The other half of the same switch, and the only stream it still governs.
# The access log IS a window - it answers what happened recently - so the
# cap keeps the newest and drops the oldest. Until this test the ceiling
# was pinned on the error stream, the one place it never applied.
assert('access log: --log-max-bytes is a ceiling, and the NEWEST lines survive') do
  cap = 8192
  app = elog_compile(ELOG_APP)
  sock = "/tmp/wm-alog-#{$$}.sock"
  alog = "/tmp/wm-alog-#{$$}.log"
  err = "/tmp/wm-alog-stderr-#{$$}.log"
  [sock, alog].each { |f| File.unlink(f) rescue nil }
  pid = spawn({ 'WM_BUNDLE' => '0' }, ELOG_BIN, '--unix', sock, '--app', app.path,
              '--log', alog, '--log-max-bytes', cap.to_s, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(sock); sleep 0.05 }
    raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
    400.times { |i| elog_get(sock, "/hit#{i}") }
    text = ''
    100.times do
      text = File.read(alog) rescue ''
      break if text.include?('/hit399')
      sleep 0.05
    end
    assert_true File.size(alog) <= cap
    assert_include text, '/hit399'
    assert_false text.include?('/hit0 ')
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    [sock, alog, err].each { |f| File.unlink(f) rescue nil }
    app.unlink
  end
end
