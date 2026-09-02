
require 'socket'
require 'tempfile'

SSE_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(SSE_BIN)

def sse_compile(src)
  f = Tempfile.new(['wm-sse', '.rb'])
  f.write(src)
  f.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set'
  out = Tempfile.new(['wm-sse', '.mrb'])
  out.close
  raise "mrbc failed:\n#{src}" unless system(mrbc, '-o', out.path, f.path)
  out
ensure
  f&.unlink
end

def sse_server(app_src)
  app = sse_compile(app_src)
  sock = "/tmp/wm-sse-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-sse-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, SSE_BIN, "--unix=#{sock}", "--app=#{app.path}",
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "sse server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, err
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

def sse_head(s)
  head = ''.b
  deadline = Time.now + 10
  until head.end_with?("\r\n\r\n")
    IO.select([s], nil, nil, 10) or raise "head deadline:\n#{head}"
    head << s.readpartial(1)
    raise "head too slow:\n#{head}" if Time.now > deadline
  end
  head
end

def sse_collect(s, secs)
  raw = ''.b
  stop = Time.now + secs
  while Time.now < stop
    left = stop - Time.now
    break if left <= 0
    if IO.select([s], nil, nil, left)
      begin
        part = s.read_nonblock(4096)
      rescue IO::WaitReadable
        next
      rescue EOFError
        break
      end
      raw << part
    end
  end
  body = ''.b
  i = 0
  while i < raw.bytesize
    nl = raw.index("\r\n", i) or break
    n = raw[i...nl].to_i(16)
    break if n.zero?
    body << raw[(nl + 2), n]
    i = nl + 2 + n + 2
  end
  body
end


CLOCK = <<~RUBY unless defined?(CLOCK)
  class Clock < Webmachine::SseResource
    def initialize
      @n = 0
    end

    def on_tick
      @n += 1
      { event: 'tick', id: @n.to_s, data: "n=\#{@n}" }
    end
  end

  class Page < Webmachine::Resource
    def self.to_html
      'not a stream'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.add_sse ['events'], Clock
      app.add_route [:*], Page
    end
  end
RUBY

assert('sse: the head is text/event-stream, chunked and uncacheable') do
  sse_server(CLOCK) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
      head = sse_head(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_true head.match?(%r{^Content-Type: text/event-stream\r$}i), head
      assert_true head.match?(/^Transfer-Encoding: chunked\r$/i), head
      assert_true head.match?(/^Cache-Control: no-store\r$/i), head
      assert_false head.match?(/^Content-Length:/i), head
    end
  end
end

assert('sse: on_tick events arrive as event/id/data lines, one chunk each') do
  sse_server(CLOCK) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
      sse_head(s)
      body = sse_collect(s, 3)
      assert_true body.include?("event: tick\n"), body
      assert_true body.include?("id: 1\n"), body
      assert_true body.include?("data: n=1\n"), body
      assert_true body.include?("\n\n"), body
    end
  end
end


REFUSE = <<~RUBY unless defined?(REFUSE)
  class Gate < Webmachine::SseResource
    def initialize
      :forbidden
    end

    def on_tick
      'never reached'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.add_sse ['events'], Gate
    end
  end
RUBY

assert('sse: initialize may refuse with an HTTP status - no stream opens') do
  sse_server(REFUSE) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /events HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head = sse_head(s)
      assert_true head.start_with?('HTTP/1.1 403 '), head
    end
  end
end


BRIEF = <<~RUBY unless defined?(BRIEF)
  class Brief < Webmachine::SseResource
    def initialize
      @n = 0
    end

    def on_tick
      @n += 1
      return :close if @n >= 2
      "tick \#{@n}"
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.add_sse ['events'], Brief
    end
  end
RUBY

assert('sse: :close ends the stream, terminal chunk and socket close') do
  sse_server(BRIEF) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
      sse_head(s)
      raw = ''.b
      closed = false
      deadline = Time.now + 6
      while Time.now < deadline
        left = deadline - Time.now
        IO.select([s], nil, nil, left) or break
        part = s.read_nonblock(4096, exception: false)
        next if part == :wait_readable
        if part.nil?
          closed = true
          break
        end
        raw << part
      end
      assert_true closed, "stream did not close after :close (got #{raw.inspect})"
      assert_true raw.include?("data: tick 1\n"), raw
      assert_true raw.end_with?("0\r\n\r\n"), raw
    end
  end
end


assert('sse: a non-GET on a stream route is 405 with Allow: GET') do
  sse_server(CLOCK) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST /events HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      head = sse_head(s)
      assert_true head.start_with?('HTTP/1.1 405 '), head
      assert_true head.match?(/^Allow: GET\r$/i), head
    end
  end
end


assert('sse: event-stream routes are their own table - the flow still answers') do
  sse_server(CLOCK) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head = sse_head(s)
      assert_false head.match?(%r{Content-Type: text/event-stream}i), head
    end
  end
end
