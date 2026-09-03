require 'socket'
require 'tempfile'

SLOW_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(SLOW_BIN)

# 16 ms between every read and every write - a phone on a train, and the
# shape a reactor has to survive without noticing. The body is big enough
# that a slow reader needs many rounds of it.
SLOW_GAP = 0.016 unless defined?(SLOW_GAP)

SLOW_APP = <<~RUBY unless defined?(SLOW_APP)
  class SlowFloor < Webmachine::Resource
    def self.to_html
      'x' * 64_000
    end
  end

  class SlowEcho < Webmachine::Resource
    def self.allowed_methods
      'GET HEAD POST'
    end

    def process_post
      response.body = "got \#{request.body.length}"
      true
    end

    def to_html
      'echo'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes do |route|
        route.add ['echo'], SlowEcho
        route.add [:*], SlowFloor
      end
    end
  end
RUBY

def slow_app
  return $slow_app if $slow_app
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  rb = "/tmp/wm-slow-app-#{$$}.rb"
  mrb = "/tmp/wm-slow-app-#{$$}.mrb"
  File.write(rb, SLOW_APP)
  system(mrbc, '-o', mrb, rb) or raise 'mrbc failed to compile the slow-client app'
  File.unlink(rb) rescue nil
  $slow_app = mrb
end

def slow_server
  sock = "/tmp/wm-slow-#{$$}-#{rand(1 << 30)}.sock"
  err = Tempfile.new(['wm-slow-err', '.log'])
  pid = spawn({ 'WM_BUNDLE' => '0' }, SLOW_BIN, "--unix=#{sock}", "--app=#{slow_app}",
              out: File::NULL, err: err.path)
  200.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up: #{File.read(err.path)}" unless File.socket?(sock)
  yield sock
ensure
  Process.kill(:TERM, pid) rescue nil
  Process.waitpid(pid) rescue nil
  File.unlink(sock) rescue nil
  err.unlink rescue nil
end

# Read a whole response the slow way: one chunk per 16 ms, never asking
# for more than the socket has.
def slow_read_all(s, deadline = 30)
  buf = +''.b
  stop = Time.now + deadline
  loop do
    break if Time.now > stop
    sleep SLOW_GAP
    begin
      buf << s.read_nonblock(4096)
    rescue IO::WaitReadable
      IO.select([s], nil, nil, 1) or next
      retry
    rescue EOFError
      break
    end
    if (i = buf.index("\r\n\r\n"))
      len = buf[/^Content-Length: *(\d+)\r$/i, 1]
      break if len && buf.bytesize >= i + 4 + len.to_i
    end
  end
  buf
end

assert('slow client: a head written 16 ms at a time is answered whole') do
  slow_server do |sock|
    s = UNIXSocket.new(sock)
    # One line per gap, and the terminator on its own: the parser sees a
    # head that arrives in five separate recv completions.
    ["GET / HTTP/1.1\r\n", "Host: slow\r\n", "User-Agent: bintest\r\n",
     "Accept: text/html\r\n", "\r\n"].each do |part|
      sleep SLOW_GAP
      s.write(part)
    end
    got = slow_read_all(s)
    s.close
    assert_include got, '200 OK'
    assert_equal 64_000, got[/^Content-Length: *(\d+)\r$/i, 1].to_i
    assert_true got.end_with?('x' * 100), 'the body did not arrive whole'
  end
end

assert('slow client: a body written 16 ms at a time is read whole') do
  slow_server do |sock|
    s = UNIXSocket.new(sock)
    body = 'y' * 4000
    s.write("POST /echo HTTP/1.1\r\nHost: slow\r\nContent-Type: text/plain\r\n" \
            "Content-Length: #{body.bytesize}\r\n\r\n")
    # 8 pieces, 16 ms apart: the round owes content across several recvs.
    body.scan(/.{1,500}/m).each do |piece|
      sleep SLOW_GAP
      s.write(piece)
    end
    got = slow_read_all(s)
    s.close
    assert_include got, "got #{body.bytesize}"
  end
end

assert('slow client: a 16 ms reader gets every byte, in order') do
  slow_server do |sock|
    s = UNIXSocket.new(sock)
    s.write("GET / HTTP/1.1\r\nHost: slow\r\n\r\n")
    got = slow_read_all(s)
    s.close
    head, body = got.split("\r\n\r\n", 2)
    assert_include head, '200 OK'
    assert_equal 64_000, body.bytesize
    assert_equal 0, body.count('^x'), 'the body carried something other than its own bytes'
  end
end

assert('slow client: one does not slow the others down') do
  slow_server do |sock|
    # Sixteen clients dribbling a request head at 16 ms a line, while a
    # fast client asks the same question over and over. The reactor is one
    # thread, so if a slow client could hold it, this is where it shows.
    slow = 16.times.map do
      Thread.new do
        begin
          c = UNIXSocket.new(sock)
          ["GET / HTTP/1.1\r\n", "Host: slow\r\n", "X-Slow: 1\r\n", "\r\n"].each do |part|
            sleep SLOW_GAP
            c.write(part)
          end
          ok = slow_read_all(c).include?('200 OK')
          c.close
          ok
        rescue StandardError
          false
        end
      end
    end

    # What the fast client costs while all that dribbles.
    t0 = Time.now
    n = 0
    30.times do
      c = UNIXSocket.new(sock)
      c.write("GET / HTTP/1.1\r\nHost: fast\r\nConnection: close\r\n\r\n")
      body = +''.b
      body << c.read
      c.close
      n += 1 if body.include?('200 OK')
    end
    per = (Time.now - t0) / 30

    assert_equal 30, n, 'the fast client did not get 30 answers'
    assert_true slow.map(&:value).all?, 'a slow client was dropped'
    # A round trip on a unix socket is microseconds; 16 ms is one slow
    # client's gap. Anything near that means the reactor waited for them.
    assert_true per < 0.008, "fast client averaged #{(per * 1000).round(2)} ms per request"
  end
end
