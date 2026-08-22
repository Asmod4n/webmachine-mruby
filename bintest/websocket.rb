# WebSocket over the wire (#175): the handshake, the framing and the
# resource that is FED. Round one's protocol half is proven in
# test/ws.rb against RFC 6455's own examples; this is the other half -
# a real server, a real socket, a resource answering.
#
# The surface under test (Nutzer-Entscheid 2026-08-22): a
# Webmachine::WebsocketResource - NOT a Webmachine::Resource, since no
# response, status or flow survives the upgrade - instantiated once and
# fed through on_data(data, binary). A String goes back as a message in
# the same kind; a Symbol is a close by name; nil says nothing.

require 'socket'
require 'tempfile'

WS_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WS_BIN)

def ws_compile(src)
  f = Tempfile.new(['wm-ws', '.rb'])
  f.write(src)
  f.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set'
  out = Tempfile.new(['wm-ws', '.mrb'])
  out.close
  raise "mrbc failed:\n#{src}" unless system(mrbc, '-o', out.path, f.path)
  out
ensure
  f&.unlink
end

def ws_server(app_src)
  app = ws_compile(app_src)
  sock = "/tmp/wm-ws-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-ws-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WS_BIN, '--unix', sock, '--app', app.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "ws server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, err
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

def ws_recv(s, n, deadline = 10)
  out = ''.b
  while out.bytesize < n
    IO.select([s], nil, nil, deadline) or raise "read deadline (#{out.bytesize}/#{n} bytes)"
    part = s.readpartial(n - out.bytesize)
    raise 'peer closed' if part.nil? || part.empty?
    out << part
  end
  out
end

def ws_head(s)
  head = ''.b
  head << ws_recv(s, 1) until head.end_with?("\r\n\r\n")
  head
end

# The client half of RFC 6455 4.1, with the spec's own key so the
# accept value is the one 4.2.2 works out by hand.
def ws_handshake(s, path = '/ws', extra = '')
  s.write("GET #{path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n" \
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n#{extra}\r\n")
  head = ws_head(s)
  raise "no 101:\n#{head}" unless head.start_with?('HTTP/1.1 101 ')
  head
end

def ws_be16(n)
  (((n >> 8) & 0xff).chr + (n & 0xff).chr).b
end

# A client frame is always masked (5.1).
def ws_frame(opcode, payload, fin: true, mask: "\x21\x09\x8f\x3c".b)
  masked = ''.b
  payload.bytes.each_with_index { |b, i| masked << (b ^ mask.getbyte(i % 4)).chr }
  out = ''.b
  out << ((fin ? 0x80 : 0x00) | opcode).chr
  n = payload.bytesize
  if n < 126
    out << (0x80 | n).chr
  elsif n <= 0xffff
    out << (0x80 | 126).chr << ws_be16(n)
  else
    out << (0x80 | 127).chr
    7.downto(0) { |i| out << ((n >> (i * 8)) & 0xff).chr }
  end
  out + mask + masked
end

# One server frame off the wire: [opcode, fin, payload].
def ws_read_frame(s)
  b = ws_recv(s, 2)
  b0 = b.getbyte(0)
  b1 = b.getbyte(1)
  raise 'a server frame must not be masked (5.1)' if (b1 & 0x80) != 0
  len = b1 & 0x7f
  if len == 126
    two = ws_recv(s, 2)
    len = (two.getbyte(0) << 8) | two.getbyte(1)
  elsif len == 127
    eight = ws_recv(s, 8)
    len = 0
    8.times { |i| len = (len << 8) | eight.getbyte(i) }
  end
  [b0 & 0x0f, (b0 & 0x80) != 0, len.zero? ? ''.b : ws_recv(s, len)]
end

WS_ECHO = <<~RUBY unless defined?(WS_ECHO)
  class Echo < Webmachine::WebsocketResource
    def on_data(data, binary)
      data
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes do |route|
        route.websocket ['ws'], Echo
      end
    end
  end
RUBY

assert('ws: the handshake answers 101 with RFC 6455 4.2.2 accept value') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    head = ws_handshake(s)
    assert_true head.include?('Upgrade: websocket'), head
    assert_true head.include?('Connection: Upgrade'), head
    # The spec's own worked example, on the wire this time.
    assert_true head.include?('Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo='), head
    s.close
  end
end

assert('ws: a text message comes back as text, a binary one as binary') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x1, 'hello'))
    op, fin, payload = ws_read_frame(s)
    assert_equal [0x1, true, 'hello'], [op, fin, payload]

    # The SAME String answer, in the kind the message arrived in - that
    # is what makes an echo resource `data` and nothing else.
    s.write(ws_frame(0x2, "\x00\x01\xfe\xff".b))
    op2, _, payload2 = ws_read_frame(s)
    assert_equal 0x2, op2
    assert_equal "\x00\x01\xfe\xff".b, payload2
    s.close
  end
end

assert('ws: a message split over fragments arrives whole, once') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x1, 'one ', fin: false))
    s.write(ws_frame(0x0, 'two ', fin: false))
    s.write(ws_frame(0x0, 'three', fin: true))
    op, fin, payload = ws_read_frame(s)
    assert_equal [0x1, true, 'one two three'], [op, fin, payload]
    s.close
  end
end

assert('ws: a message bigger than one 4 KiB receive buffer survives whole') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    # 20 KiB: five recv buffers, one frame - the streaming reader's
    # own case (the payload is copied ONCE, straight into the String).
    big = 'x' * 20_000
    s.write(ws_frame(0x1, big))
    op, _, payload = ws_read_frame(s)
    assert_equal 0x1, op
    assert_equal big.bytesize, payload.bytesize
    assert_equal big, payload
    s.close
  end
end

assert('ws: ping is answered with a pong, by the server, with no resource in sight') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x9, 'beat'))
    op, fin, payload = ws_read_frame(s)
    assert_equal [0xa, true, 'beat'], [op, fin, payload]
    # An unsolicited pong is legal and answered with nothing (5.5.3);
    # the echo behind it proves the connection kept its place.
    s.write(ws_frame(0xa, 'ignored'))
    s.write(ws_frame(0x1, 'still here'))
    _, _, after = ws_read_frame(s)
    assert_equal 'still here', after
    s.close
  end
end

assert('ws: the close handshake is echoed and the connection ends') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x8, ws_be16(1000) + 'bye'))
    op, _, payload = ws_read_frame(s)
    assert_equal 0x8, op
    assert_equal ws_be16(1000) + 'bye', payload
    assert_equal '', s.read.to_s   # FIN follows; nothing more is said
    s.close
  end
end

assert('ws: invalid UTF-8 in a text message closes 1007, on_data never sees it') do
  src = <<~RUBY
    class Seen < Webmachine::WebsocketResource
      def on_data(data, binary)
        'SEEN'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws'], Seen }
      end
    end
  RUBY
  ws_server(src) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x1, "\xc3\x28".b))  # a truncated two-byte sequence
    op, _, payload = ws_read_frame(s)
    assert_equal 0x8, op
    assert_equal 1007, (payload.getbyte(0) << 8) | payload.getbyte(1)
    s.close
  end
end

assert('ws: a Symbol answer is a close by name; a String is a message') do
  src = <<~RUBY
    class Says < Webmachine::WebsocketResource
      def on_data(data, binary)
        case data
        when 'go' then :going_away
        when 'quiet' then nil
        else data.upcase
        end
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws'], Says }
      end
    end
  RUBY
  ws_server(src) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x1, 'loud'))
    _, _, up = ws_read_frame(s)
    assert_equal 'LOUD', up
    # nil says nothing at all - the ping behind it is what comes back.
    s.write(ws_frame(0x1, 'quiet'))
    s.write(ws_frame(0x9, 'p'))
    op, _, payload = ws_read_frame(s)
    assert_equal [0xa, 'p'], [op, payload]
    s.write(ws_frame(0x1, 'go'))
    op2, _, payload2 = ws_read_frame(s)
    assert_equal 0x8, op2
    assert_equal 1001, (payload2.getbyte(0) << 8) | payload2.getbyte(1)
    s.close
  end
end

assert('ws: on_open reads the handshake head and picks the subprotocol') do
  src = <<~RUBY
    class Picky < Webmachine::WebsocketResource
      def on_open
        offered = request.headers['sec-websocket-protocol'].to_s
        return :forbidden unless request.path_info[:room] == 'lobby'
        'chat.v1' if offered.split(',').map(&:strip).include?('chat.v1')
      end

      def on_data(data, binary)
        data
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws', :room], Picky }
      end
    end
  RUBY
  ws_server(src) do |sock|
    s = UNIXSocket.new(sock)
    head = ws_handshake(s, '/ws/lobby', "Sec-WebSocket-Protocol: chat.v1, chat.v0\r\n")
    assert_true head.include?('Sec-WebSocket-Protocol: chat.v1'), head
    s.write(ws_frame(0x1, 'hi'))
    _, _, back = ws_read_frame(s)
    assert_equal 'hi', back
    s.close

    # A room the resource does not admit: no upgrade, an HTTP refusal.
    t = UNIXSocket.new(sock)
    t.write("GET /ws/attic HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" \
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" \
            "Sec-WebSocket-Version: 13\r\n\r\n")
    refused = ws_head(t)
    assert_true refused.start_with?('HTTP/1.1 403'), refused
    t.close
  end
end

assert('ws: max_message is the route own say, and 1009 past it') do
  src = <<~RUBY
    class Small < Webmachine::WebsocketResource
      def self.max_message
        64
      end

      def on_data(data, binary)
        data
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws'], Small }
      end
    end
  RUBY
  ws_server(src) do |sock|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x1, 'a' * 64))
    _, _, ok = ws_read_frame(s)
    assert_equal 'a' * 64, ok
    s.write(ws_frame(0x1, 'b' * 65))
    op, _, payload = ws_read_frame(s)
    assert_equal 0x8, op
    assert_equal 1009, (payload.getbyte(0) << 8) | payload.getbyte(1)
    s.close
  end
end

assert('ws: a wrong version is told which one to speak (4.4)') do
  ws_server(WS_ECHO) do |sock|
    s = UNIXSocket.new(sock)
    s.write("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" \
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n")
    head = ws_head(s)
    assert_true head.start_with?('HTTP/1.1 426'), head
    assert_true head.include?('Sec-WebSocket-Version: 13'), head
    s.close
  end
end

assert('ws: an upgrade on a path no websocket route claims stays HTTP') do
  src = <<~RUBY
    class Page < Webmachine::Resource
      def self.to_html
        'plain http'
      end
    end

    class Echo < Webmachine::WebsocketResource
      def on_data(data, binary)
        data
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['page'], Page
          route.websocket ['ws'], Echo
        end
      end
    end
  RUBY
  ws_server(src) do |sock|
    s = UNIXSocket.new(sock)
    # RFC 9110 7.8: a server may ignore an upgrade it does not offer -
    # and here that means the ordinary resource answers.
    s.write("GET /page HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" \
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    head = ws_head(s)
    assert_true head.start_with?('HTTP/1.1 200'), head
    s.close
  end
end

assert('ws: route.websocket refuses a class that is not a WebsocketResource') do
  src = <<~RUBY
    class NotOne < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws'], NotOne }
      end
    end
  RUBY
  app = ws_compile(src)
  err = "/tmp/wm-ws-refuse-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WS_BIN, '--unix', "/tmp/wm-ws-refuse-#{$$}.sock",
              '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  assert_true $?.exitstatus != 0
  out = File.read(err)
  assert_true out.include?('WebsocketResource'), out
  app.unlink
end

assert('ws: a resource without on_data is refused at route.websocket') do
  src = <<~RUBY
    class Mute < Webmachine::WebsocketResource
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws'], Mute }
      end
    end
  RUBY
  app = ws_compile(src)
  err = "/tmp/wm-ws-mute-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WS_BIN, '--unix', "/tmp/wm-ws-mute-#{$$}.sock",
              '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  assert_true $?.exitstatus != 0
  out = File.read(err)
  assert_true out.include?('on_data'), out
  app.unlink
end

assert('ws: on_close hears the client going away, with its code and reason') do
  src = <<~RUBY
    class Bookkeeper < Webmachine::WebsocketResource
      def on_data(data, binary)
        data
      end

      def on_close(code, reason)
        STDERR.puts "CLOSED \#{code} \#{reason}"
        STDERR.flush
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.websocket ['ws'], Bookkeeper }
      end
    end
  RUBY
  ws_server(src) do |sock, errlog|
    s = UNIXSocket.new(sock)
    ws_handshake(s)
    s.write(ws_frame(0x8, ws_be16(1001) + 'leaving'))
    ws_read_frame(s)   # the echoed close
    s.close
    seen = false
    100.times do
      seen = File.read(errlog).include?('CLOSED 1001 leaving') rescue false
      break if seen
      sleep 0.05
    end
    assert_true seen, (File.read(errlog) rescue '')
  end
end
