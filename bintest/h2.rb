# h2c on the wire, frames built by hand: the preface upgrades, streams
# answer through the SAME konst vectors and run frame h1 uses, flow
# control and control frames behave per RFC 9113. The request header
# blocks are RFC 7541's own vector bytes where possible, so the decode
# side is pinned to the spec, not to our encoder.

require 'socket'
require 'tempfile'

H2_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(H2_BIN)
H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b unless defined?(H2_PREFACE)

# Every suite read has a deadline: a wedged server must FAIL the test,
# never hang it.
def wm_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def h2_server(app_source = nil)
  args = []
  app = nil
  if app_source
    app = Tempfile.new(['wm-h2app', '.rb'])
    app.write(app_source)
    app.close
    args = ['--app', app.path]
  end
  sock = "/tmp/wm-h2-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-h2-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, H2_BIN, '--unix', sock, *args, out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "h2 server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app&.unlink
  end
end

def h2_read_exact(s, n)
  buf = +''.b
  buf << wm_recv(s, n - buf.bytesize) while buf.bytesize < n
  buf
end

def h2_frame(type, flags, stream, payload = ''.b)
  len = payload.bytesize
  [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
    [stream].pack('N') + payload
end

# -> [type, flags, stream, payload]
def h2_next(s)
  h = h2_read_exact(s, 9)
  len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
  payload = len > 0 ? h2_read_exact(s, len) : ''.b
  [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fffffff, payload]
end

# RFC 7541 C.3.1's block: :method GET, :scheme http, :path /,
# :authority www.example.com - fully indexed plus one literal.
def h2_get_block
  "\x82\x86\x84\x41\x0fwww.example.com".b
end

# Literal :method (name index 2, no indexing) + indexed scheme/path.
def h2_method_block(method)
  "\x02#{method.bytesize.chr}#{method}\x86\x84\x41\x0bexample.com".b
end

# Preface + empty client SETTINGS; consumes the server SETTINGS and the
# SETTINGS ACK so the caller reads request frames only.
def h2_handshake(s)
  s.write(H2_PREFACE + h2_frame(4, 0, 0))
  t, f, st, = h2_next(s)
  raise "expected server SETTINGS, got type #{t}" unless t == 4 && f == 0 && st == 0
  t, f, = h2_next(s)
  raise "expected SETTINGS ACK, got type #{t}/#{f}" unless t == 4 && f == 1
end

assert('h2: the preface upgrades, a GET answers 200 in frames, streams multiplex') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))  # END_HEADERS|END_STREAM
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_true (flags & 0x04) != 0, 'END_HEADERS missing'
      # :status 200 is static-table entry 8: one indexed byte leads.
      assert_equal 0x88, block.getbyte(0)
      type, flags, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 1, stream
      assert_true (flags & 0x01) != 0, 'END_STREAM missing on DATA'
      assert_equal 'OK', data
      # A second stream on the same connection: the tables carry over.
      s.write(h2_frame(1, 0x05, 3, "\x82\x86\x84\xbe".b))  # authority now indexed (dyn table)
      type, _, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 3, stream
      assert_equal 0x88, block.getbyte(0)
      type, _, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 3, stream
      assert_equal 'OK', data
    end
    # h1 on the very same listener still answers: the probe costs the
    # h1 path its first bytes only.
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head = +''
      head << wm_recv(s) until head.end_with?("\r\n\r\n")
      assert_true head.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h2: PING echoes, unknown frame types are ignored, oversize dies with GOAWAY') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(0xdd, 0, 0, 'x' * 8))  # unknown type: ignored per spec
      s.write(h2_frame(6, 0, 0, '12345678'))  # PING
      type, flags, _, payload = h2_next(s)
      assert_equal 6, type
      assert_equal 1, flags & 1
      assert_equal '12345678', payload
    end
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      # A frame length past SETTINGS_MAX_FRAME_SIZE is a connection
      # error (RFC 9113 4.2): GOAWAY, then the connection ends.
      s.write([0x00, 0x40, 0x01, 0x00, 0x00].pack('C5') + [1].pack('N'))
      type, _, stream, payload = h2_next(s)
      assert_equal 7, type
      assert_equal 0, stream
      assert_equal 6, payload[4, 4].unpack1('N')  # FRAME_SIZE_ERROR
      assert_raise(EOFError) { h2_read_exact(s, 1) }
    end
  end
end

assert('h2: a resource answers typed bodies, HEAD sends no DATA, POST is 405') do
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0)
      _, flags, _, data = h2_next(s)
      assert_equal '<html><body>Hello, World!</body></html>', data
      assert_equal 1, flags & 1
      # HEAD: the head, END_STREAM on HEADERS, no DATA follows.
      s.write(h2_frame(1, 0x05, 3, h2_method_block('HEAD')))
      type, flags, stream, = h2_next(s)
      assert_equal 1, type
      assert_equal 3, stream
      assert_true (flags & 0x01) != 0, 'HEAD must END_STREAM on HEADERS'
      # POST is outside allowed_methods: 405 (B10), headers only here
      # (h1 spells Content-Length: 0; h2 frames delimit).
      s.write(h2_frame(1, 0x05, 5, h2_method_block('POST')))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 5, stream
      assert_true (flags & 0x01) != 0
      assert_not_equal 0x88, block.getbyte(0)  # anything but :status 200
    end
  end
end

assert('h2: the run frame answers per request, exceptions speak 500 with their reason') do
  counter = File.read(File.expand_path('../examples/counter.rb', __dir__))
  h2_server(counter) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      _, _, _, block = h2_next(s)
      assert_equal 0x88, block.getbyte(0)
      _, _, _, data = h2_next(s)
      assert_equal '<html><body>hit 1</body></html>', data
      s.write(h2_frame(1, 0x05, 3, "\x82\x86\x84\xbe".b))
      h2_next(s)
      _, _, _, data = h2_next(s)
      assert_equal '<html><body>hit 2</body></html>', data
    end
  end
  boom = <<~RUBY
    class Boom < Webmachine::Resource
      def to_html
        raise 'boom'
      end
    end
  RUBY
  h2_server(boom) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_not_equal 0x88, block.getbyte(0)
      _, flags, _, data = h2_next(s)
      assert_true data.include?('boom'), data
      assert_equal 1, flags & 1
      # The connection survives the exception, like h1.
      s.write(h2_frame(6, 0, 0, 'still-up!'[0, 8]))
      type, flags, = h2_next(s)
      assert_equal 6, type
      assert_equal 1, flags & 1
    end
  end
end

assert('h2: a request body is counted, credited and discarded; END_STREAM dispatches') do
  src = <<~RUBY
    class WideResource < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST'
      end
    end
  RUBY
  h2_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      # POST with a body over two DATA frames; headers first, no
      # END_STREAM until the body ends.
      s.write(h2_frame(1, 0x04, 1, h2_method_block('POST')))
      s.write(h2_frame(0, 0x00, 1, 'a' * 100))
      s.write(h2_frame(0, 0x01, 1, 'b' * 50))
      # Receive credits come back for both frames (connection + stream),
      # then the answer.
      frames = []
      6.times { frames << h2_next(s) }
      updates = frames.select { |t, _, _, _| t == 8 }
      assert_equal 4, updates.size
      headers = frames.find { |t, _, _, _| t == 1 }
      assert_true headers != nil, 'no HEADERS answer after END_STREAM'
      assert_equal 0x88, headers[3].getbyte(0)  # 200: post accepted at this tier
    end
  end
end

assert('h2: an exhausted window parks DATA, WINDOW_UPDATE drains it (9113 6.9)') do
  # Found live: a credit-less client stalled at exchange 1681 - exactly
  # 65535/39 bytes - because the server correctly refused to send past
  # the window. This pins that behavior deterministically: a 20-byte
  # initial stream window splits hello's 39-byte body into a sent part
  # and a parked part, and the credit releases the rest.
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      # SETTINGS_INITIAL_WINDOW_SIZE = 20 (6.9.2): stream windows start
      # at 20; the connection window keeps its default and does not
      # bind here.
      s.write(H2_PREFACE + h2_frame(4, 0, 0, [4, 20].pack('nN')))
      t, f, = h2_next(s)
      raise 'expected server SETTINGS' unless t == 4 && f == 0
      t, f, = h2_next(s)
      raise 'expected SETTINGS ACK' unless t == 4 && f == 1
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, flags, = h2_next(s)
      assert_equal 1, type
      assert_equal 0, flags & 1  # END_STREAM must wait for the parked DATA
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 20, data.bytesize  # the window, to the byte
      assert_equal 0, flags & 1
      s.write(h2_frame(8, 0, 1, [64].pack('N')))  # stream credit
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 19, data.bytesize  # the parked remainder
      assert_equal 1, flags & 1       # and only now END_STREAM
    end
  end
end

assert('h2: a drained stream is debited for what it already sent (9113 6.9.1)') do
  # The park test above cannot see a wrong window: it hands over more
  # credit than the remainder needs, so an undebited stream and a
  # correctly debited one both deliver the same 19 bytes. This one
  # credits LESS than the remainder, which only the correct accounting
  # can answer partially.
  #
  # Correct: 20-byte window, 20 sent, stream window now 0. +10 credit
  # releases exactly 10, END_STREAM still withheld.
  # Undebited (the bug this pins): the stream would still read 20, +10
  # would make 30, and all 19 remaining bytes would leave at once WITH
  # END_STREAM - overshooting the peer's window by the 20 already sent.
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write(H2_PREFACE + h2_frame(4, 0, 0, [4, 20].pack('nN')))
      t, f, = h2_next(s)
      raise 'expected server SETTINGS' unless t == 4 && f == 0
      t, f, = h2_next(s)
      raise 'expected SETTINGS ACK' unless t == 4 && f == 1
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      h2_next(s)  # HEADERS
      type, _, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 20, data.bytesize
      # Ten bytes of credit against a nineteen-byte remainder.
      s.write(h2_frame(8, 0, 1, [10].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 10, data.bytesize, 'stream window was not debited for the first 20 bytes'
      assert_equal 0, flags & 1, 'nine bytes still owed - END_STREAM must wait'
      # The rest, once it is actually paid for.
      s.write(h2_frame(8, 0, 1, [64].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 9, data.bytesize
      assert_equal 1, flags & 1
    end
  end
end

assert('h2: a merged answer pays the connection window too (9113 6.9.1)') do
  # A konst body under the merge cap leaves as ONE append - head and
  # DATA in the same buffer - and that path owes the connection window
  # exactly what the chunked one owes. Nothing else here can see it:
  # the other tests use 2-byte bodies, where an unpaid window takes
  # thousands of exchanges to show.
  #
  # 1000-byte body: 65 answers fit the 65535 default, the 66th does
  # not and must be cut to the 535 that remain. Unpaid, the window
  # would still read 65535 at the 66th and all 1000 bytes would leave
  # with END_STREAM, past a window the peer never opened.
  app = <<~RUBY
    class Big < Webmachine::Resource
      def self.to_html
        'x' * 1000
      end
    end
  RUBY
  h2_server(app) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      sid = 1
      65.times do
        s.write(h2_frame(1, 0x05, sid, h2_get_block))
        t, = h2_next(s)
        raise "expected HEADERS, got #{t}" unless t == 1
        t, _, _, data = h2_next(s)
        raise "expected DATA, got #{t}" unless t == 0
        raise "short DATA: #{data.bytesize}" unless data.bytesize == 1000
        sid += 2
      end
      # 65535 - 65 * 1000 = 535 left on the connection.
      s.write(h2_frame(1, 0x05, sid, h2_get_block))
      type, flags, = h2_next(s)
      assert_equal 1, type
      assert_equal 0, flags & 1, 'body is owed - END_STREAM must wait'
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 535, data.bytesize, 'merged answers did not pay the connection window'
      assert_equal 0, flags & 1
      # Credit the CONNECTION (stream 0); the parked remainder follows.
      s.write(h2_frame(8, 0, 0, [4096].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 465, data.bytesize
      assert_equal 1, flags & 1
    end
  end
end

if `curl --version 2>/dev/null`.include?('HTTP2')
  assert('h2: curl --http2-prior-knowledge round-trips against the same listener') do
    h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
      body = `curl -sS --max-time 10 --http2-prior-knowledge --unix-socket #{sock} http://localhost/`
      assert_equal '<html><body>Hello, World!</body></html>', body
    end
  end
end
