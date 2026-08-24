# The error log: the SECOND stream, its own file and its own writer.
# What a callback RAISED lands there - the class, the message, the
# backtrace - while the peer still gets nothing but a 500. And the hard
# ceiling: past MAXBYTES the oldest lines go and the newest stay, in
# place, because a log that only grows takes the disk with it.

require 'socket'
require 'tempfile'

ELOG_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(ELOG_BIN)

# -g, deliberately: it is what puts the LOCATIONS in the bytecode, and
# a trace without them is one "(unknown):0" line no build can recover.
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

# The daemon writes one record per raise, so the file is current after
# a request rather than after a megabyte - but the send and the write
# are two processes, so give them a moment to happen.
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
    # The peer's half of the deal is unchanged: a 500 with the reason,
    # and not one word about where in the app it happened.
    assert_include answer, '500'
    assert_include answer, 'the resource said no'
    assert_false answer.include?('to_html')

    lines = elog_await(log, 2).lines
    head = lines.first.to_s
    assert_include head, 'ArgumentError: the resource said no'
    assert_include head, '/boom'          # the target that asked
    assert_include head, ' 500 '          # what the peer was answered
    # The frames follow, indented, one per line - and with -g they name
    # a file and a line rather than mruby's "(unknown)".
    assert_true lines.size > 1
    assert_include lines[1], "\tfrom "
    assert_include lines[1], ':in to_html'
  end
end

assert('error log: a request that does NOT raise writes nothing') do
  elog_server([]) do |sock, log|
    # 405: the flow's own answer, decided without the VM. An answer is
    # not an error, and the error log must stay empty for it.
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

assert('error log: MAXBYTES is a ceiling, and the NEWEST lines survive') do
  cap = 4096
  elog_server(['--log-max-bytes', cap.to_s]) do |sock, log|
    60.times { |i| elog_get(sock, "/boom#{i}") }
    # Long enough for the last record's write, and for the cap that
    # follows it in the same flush.
    text = ''
    100.times do
      text = File.read(log) rescue ''
      break if text.include?('/boom59')
      sleep 0.05
    end
    assert_true File.size(log) <= cap
    # The newest is there, the oldest is gone, and what is left starts
    # at a line boundary rather than mid-record.
    assert_include text, '/boom59'
    assert_false text.include?('/boom0 ')
    assert_true text.start_with?('[')
  end
end
