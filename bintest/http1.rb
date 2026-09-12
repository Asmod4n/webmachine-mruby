
require 'socket'

# The floor these tests speak to: one splat route, one baked body, nothing
# else. It used to be the server's own built-in default - a Resource nobody
# folded, which is why it had no media type and answered out of nowhere.
# That is gone; a server with nothing to serve refuses to start.
H1_APP = <<~RUBY unless defined?(H1_APP)
  class Floor < Webmachine::Resource
    def self.to_html
      'OK'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.add [:*], Floor }
    end
  end
RUBY

def h1_expect_eof(s)
  deadline = Time.now + 5
  begin
    loop do
      raise 'no EOF' if Time.now > deadline
      s.read_nonblock(4096)
    end
  rescue IO::WaitReadable
    IO.select([s], nil, nil, 5)
    retry
  rescue EOFError, Errno::ECONNRESET
    true
  end
end

assert('h1: 200 with Date, keep-alive carries no Connection header') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Date: \w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT\r$/)
      assert_false head.match?(/^Connection:/i)
      assert_equal 'OK', body
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = wm_read(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h1: three pipelined requests get three responses in order') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\nGET /c HTTP/1.1\r\nHost: x\r\n\r\n")
      3.times do
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200 OK')
        assert_equal 'OK', body
      end
    end
  end
end

assert('h1: a head trickled byte by byte still parses (carry across receives)') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      "GET / HTTP/1.1\r\nHost: x\r\n\r\n".each_char do |ch|
        s.write(ch)
        sleep 0.002
      end
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_equal 'OK', body
    end
  end
end

# RFC 9112 6.6: this resource reads no body - it declares none of
# content_types_accepted, create_path or process_post - so the flow
# answers on the head and the connection ends. The octets of the body are
# never read, whether they all arrived or not.
assert('h1: a body no node reads is answered, then the connection closes') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Allow: GET, HEAD\r$/i)
      assert_true head.match?(/^Connection: close\r$/i), head
      assert_equal '', s.read.to_s
    end
    # And the same when the body is still arriving: the answer does not
    # wait for the rest, because nothing was ever going to read it.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhell")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Connection: close\r$/i), head
    end
    # A request with no body keeps the connection, as it always did.
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Connection: close\r$/i), head
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = wm_read(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h1: the flow speaks on the wire - 405/304/HEAD from the graph') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Allow: GET, HEAD\r$/i)
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n")
      head304 = +''
      head304 << wm_recv(s) until head304.end_with?("\r\n\r\n")
      assert_true head304.start_with?('HTTP/1.1 304')
      assert_false head304.match?(/^Content-Length:/i)
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
      hh = +''
      hh << wm_recv(s) until hh.end_with?("\r\n\r\n")
      assert_true hh.start_with?('HTTP/1.1 200 OK')
      assert_true hh.match?(/^Content-Length: 2\r$/i)
      nxt = +''
      nxt << wm_recv(s) until nxt.end_with?("\r\n\r\n")
      assert_true nxt.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nxt.inspect}"
      body = +''
      body << wm_recv(s, 2 - body.bytesize) while body.bytesize < 2
      assert_equal 'OK', body
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nAccept-Language: de\r\n" \
              "Accept-Encoding: gzip\r\nAccept-Charset: utf-8\r\n\r\n")
      headn, bodyn = wm_read(s)
      assert_true headn.start_with?('HTTP/1.1 200 OK')
      assert_equal 'OK', bodyn
    end
  end
end

assert('h1: Connection: close is honored, spelled, and followed by EOF') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Connection: close\r$/i)
      assert_equal 'OK', body
      assert_true h1_expect_eof(s)
    end
  end
end

assert('h1: HTTP/1.0 closes by default, persists only when asked (RFC 9112 C.2.2)') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.0\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Connection: close\r$/i)
      assert_true h1_expect_eof(s)
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
      head, = wm_read(s)
      assert_true head.match?(/^Connection: keep-alive\r$/i)
      s.write("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
      head2, = wm_read(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
  end
end

# RFC 9110 6.4: a body of 256 KiB or more does not stay in the
# connection's buffer - it goes to a file, and request.body reads that
# file. A resource cannot tell which half it got: both answer read,
# size, seek and the rest.
assert('h1: a large body is a File, a small one is a StringIO') do
  src = <<~RUBY
    class Upload < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end

      def process_post
        b = request.body
        bytes = b.read
        response.body = [
          b.class.to_s, b.size.to_s, bytes.bytesize.to_s,
          bytes[0, 4], bytes[-4, 4], b.eof?.to_s,
        ].join('|')
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.add_route [:*], Upload
      end
    end
  RUBY
  wm_server(src, tag: 'wm-spill') do |sock|
    # One byte under the threshold stays in memory.
    small = 'ab' + ('s' * ((256 * 1024) - 5)) + 'yz'
    # And one megabyte goes to a file.
    big = 'AB' + ('L' * ((1024 * 1024) - 4)) + 'YZ'
    [[small, 'StringIO'], [big, 'File']].each do |(payload, want)|
      UNIXSocket.open(sock) do |s|
        s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: #{payload.bytesize}\r\n\r\n")
        # In pieces, so the body arrives over several reads and the
        # spill has to take them one at a time.
        payload.scan(/.{1,65536}/m).each { |chunk| s.write(chunk) }
        _, body = wm_read(s)
        got = body.split('|')
        assert_equal want, got[0]
        assert_equal payload.bytesize.to_s, got[1]
        assert_equal payload.bytesize.to_s, got[2]
        assert_equal payload[0, 4], got[3]
        assert_equal payload[-4, 4], got[4]
        assert_equal 'true', got[5]
      end
    end

    # Three large bodies on one connection. Each round gives its file
    # back before the next head is parsed, so the descriptors do not
    # pile up and no round reads the one before it.
    UNIXSocket.open(sock) do |s|
      3.times do |i|
        payload = i.to_s + ('R' * ((512 * 1024) - 2)) + i.to_s
        s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: #{payload.bytesize}\r\n\r\n")
        s.write(payload)
        _, body = wm_read(s)
        got = body.split('|')
        assert_equal 'File', got[0]
        assert_equal payload.bytesize.to_s, got[1]
        assert_equal payload[0, 4], got[3], "round #{i} read the wrong body"
        assert_equal payload[-4, 4], got[4], "round #{i} read the wrong body"
      end
    end
  end
end

# RFC 9110 15.5.14: conf.max_body is what this application accepts, and
# the refusal reads the declared Content-Length - no body is read for it.
# The default is 1 MiB, which the refusals test above stands on.
assert('h1: conf.max_body is what an application accepts, and 413 is per app') do
  app = H1_APP.sub("Webmachine::Application.new do |app|\n",
                   "Webmachine::Application.new do |app|\n      app.conf.max_body = 8\n")
  wm_server(app, tag: 'wm-maxbody') do |sock, _|
    checks = [
      # 405, not 413: the body fits, so the flow runs and refuses the
      # method instead. Floor names no process_post.
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\n12345678", '405'],
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\n123456789", '413'],
      # Declared but never sent: the refusal comes from the field alone.
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1048576\r\n\r\n", '413'],
    ]
    checks.each do |(wire, code)|
      UNIXSocket.open(sock) do |s|
        s.write(wire)
        head, = wm_read(s)
        assert_true head.start_with?("HTTP/1.1 #{code}"), "expected #{code}, got: #{head.lines.first}"
      end
    end
  end
end

# RFC 9110 15.5.14: a chunked body declares no length, so the count is
# the only thing the limit can hold. The refusal is 413, the same answer a
# declared length over the limit earns.
assert('h1: a chunked body over conf.max_body answers 413') do
  src = <<~RUBY
    class Taker < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end

      def process_post
        response.body = request.body.read.bytesize.to_s
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 8
        app.add_route [:*], Taker
      end
    end
  RUBY
  wm_server(src, tag: 'wm-chunk413') do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
      s.write("10\r\n0123456789abcdef\r\n0\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 413'), "expected 413, got: #{head.lines.first}"
    end
    # The same body inside the limit is read, and the resource answers it.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
      s.write("4\r\nabcd\r\n0\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 2'), "expected 2xx, got: #{head.lines.first}"
      assert_equal '4', body
    end
  end
end

assert('h1: refusals - 400 no Host, 400 malformed, 431 huge head, 413 huge body, 501 gzip framing') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    checks = [
      ["GET / HTTP/1.1\r\n\r\n", '400'],
      ["GARBAGE\r\n\r\n", '400'],
      ["GET / HTTP/1.1\r\nHost: x\r\nX-Big: #{'a' * 9000}\r\n\r\n", '431'],
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2097152\r\n\r\n", '413'],
      # RFC 9112 6.1: chunked is read, and every other coding is 501.
      ["POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n", '501'],
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nab", '400'],
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab", '400'],
      ["GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", '400'],
      ["GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 2x\r\n\r\n", '400'],
    ]
    checks.each do |(wire, code)|
      UNIXSocket.open(sock) do |s|
        s.write(wire)
        head, = wm_read(s)
        assert_true head.start_with?("HTTP/1.1 #{code}"), "expected #{code}, got: #{head.lines.first}"
        assert_true head.match?(/^Connection: close\r$/i)
        assert_true h1_expect_eof(s)
      end
    end
  end
end

assert('h1: random garbage kills connections, never the process') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, pid|
    30.times do
      UNIXSocket.open(sock) do |s|
        begin
          s.write(Random.bytes(64 + rand(512)))
        rescue Errno::EPIPE
        end
        IO.select([s], nil, nil, 0.05)
      end
    end
    assert_true Process.kill(0, pid) == 1
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
    end
  end
end

# RFC 9110 6.4: only three callbacks read the request body -
# content_types_accepted, create_path and process_post. A resource that
# defines none of them has no node that can ask for one, so the server
# steps over the octets instead of keeping them. No file opens, and
# request.body answers nothing rather than a part of the body.
#
# A GET that carries a body is what shows it: the flow answers it, and
# before this the connection held the whole megabyte to hand over.
assert('h1: a resource that reads no body keeps none of it') do
  src = <<~RUBY
    class Peek < Webmachine::Resource
      def to_html
        b = request.body
        b.nil? ? 'none' : "held:\#{b.size}"
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.add_route [:*], Peek
      end
    end
  RUBY
  wm_server(src, tag: 'wm-nobody') do |sock|
    # A megabyte announced to a resource that reads no body. The answer
    # comes back without the server waiting for the octets, and the
    # connection ends - so the upload is never read and never held.
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: #{1024 * 1024}\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_true head.match?(/^Connection: close\r$/i), head
      assert_equal 'none', body, 'the resource was handed a body'
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal 'none', body
    end
  end
end

# #36: the flow walks the head, and only kN11, kO14 and kP3 read the
# body. So a request the flow refuses above those nodes is answered
# while the client is still sending, and its octets are never read.
assert('h1: a refused upload is answered before its body arrives') do
  src = <<~RUBY
    class Guarded < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end

      def is_authorized?(header)
        header.to_s == 'letmein'
      end

      def process_post
        response.body = "took \#{request.body.size}"
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 8 * 1024 * 1024
        app.add_route [:*], Guarded
      end
    end
  RUBY
  wm_server(src, tag: 'wm-early') do |sock|
    # No credentials. is_authorized? is asked at kB8, far above the
    # nodes that read content, so the 401 comes back before the body
    # has been sent - the server never reads those octets.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: #{4 * 1024 * 1024}\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 401'), head.lines.first.to_s
    end

    # With credentials the walk reaches kN11, stops there, and goes on
    # when the last octet lands. The handler sees the whole body.
    UNIXSocket.open(sock) do |s|
      payload = 'p' * (512 * 1024)
      s.write("POST / HTTP/1.1\r\nHost: x\r\nAuthorization: letmein\r\n" \
              "Content-Length: #{payload.bytesize}\r\n\r\n")
      payload.scan(/.{1,65536}/m).each { |chunk| s.write(chunk) }
      _, body = wm_read(s)
      assert_equal "took #{payload.bytesize}", body
    end

    # And a small body, which never reaches a file.
    UNIXSocket.open(sock) do |s|
      payload = 'q' * 1000
      s.write("POST / HTTP/1.1\r\nHost: x\r\nAuthorization: letmein\r\n" \
              "Content-Length: #{payload.bytesize}\r\n\r\n")
      s.write(payload)
      _, body = wm_read(s)
      assert_equal "took #{payload.bytesize}", body
    end
  end
end

# RFC 9112 9.3.2: a request pipelined behind an upload waits its turn.
# Its head can land in the same receive as the upload's last octet, and
# it must not be parsed while the run that reads the body is stopped.
assert('h1: a request pipelined behind an upload is answered after it') do
  src = <<~RUBY
    class Sink < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end

      def process_post
        response.body = "took \#{request.body.size}"
        true
      end

      def to_html
        'plain'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 8 * 1024 * 1024
        app.add_route [:*], Sink
      end
    end
  RUBY
  wm_server(src, tag: 'wm-pipe') do |sock|
    UNIXSocket.open(sock) do |s|
      payload = 'z' * (400 * 1024)
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: #{payload.bytesize}\r\n\r\n")
      s.write(payload[0, payload.bytesize - 16])
      # The last octets and the next request's head, in one write.
      s.write(payload[-16, 16] + "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, first = wm_read(s)
      assert_equal "took #{payload.bytesize}", first
      _, second = wm_read(s)
      assert_equal 'plain', second
    end
  end
end

assert('h1: valid_entity_length? is asked the declared length, before the body') do
  src = <<~RUBY
    class Sized < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end

      # RFC 9110 15.5.14: the declared number decides, and it decides at
      # the head. The body has not arrived when this is asked.
      def valid_entity_length?(length)
        @asked = length
        length <= 64
      end

      def process_post
        response.body = "took \#{request.body.size} after \#{@asked}"
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 8 * 1024 * 1024
        app.add_route [:*], Sized
      end
    end
  RUBY
  wm_server(src, tag: 'wm-b4') do |sock|
    # The head names a million octets and not one of them is sent. The
    # answer is 413 all the same, so the number B4 saw was the declared
    # one and not the nothing that had arrived.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 413'), head.lines.first.to_s
    end

    # And a body the resource allows is read whole, after the same node
    # let it through on the same number.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\n")
      s.write('abcdefgh')
      _, body = wm_read(s)
      assert_equal 'took 8 after 8', body
    end
  end
end

# RFC 9110 15.5.14: three levels hold a body limit and the nearest one
# answers - the resource, then conf.max_body, then the default of 1 MiB.
assert('h1: max_body - the resource answers before the application does') do
  app = <<~RUBY_APP
    class Uploads < Webmachine::Resource
      reads_body :process_post
      def self.max_body
        64
      end
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        response.body = 'took'
        true
      end
      def self.to_html
        'uploads'
      end
    end

    class Small < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        response.body = 'took'
        true
      end
      def self.to_html
        'small'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 16
        app.routes do |route|
          route.add ['uploads'], Uploads
          route.add [:*], Small
        end
      end
    end
  RUBY_APP
  wm_server(app, tag: 'wm-maxbody-levels') do |sock, _|
    checks = [
      # The resource says 64, so 32 octets pass where the application's
      # 16 would have refused them.
      ['/uploads', 32, '200'],
      ['/uploads', 65, '413'],
      # This route says nothing, so the application's 16 answers.
      ['/small', 16, '200'],
      ['/small', 17, '413'],
    ]
    checks.each do |(path, len, code)|
      UNIXSocket.open(sock) do |s|
        s.write("POST #{path} HTTP/1.1\r\nHost: x\r\nContent-Length: #{len}\r\n\r\n#{'a' * len}")
        head, = wm_read(s)
        assert_true head.start_with?("HTTP/1.1 #{code}"),
                    "#{path} with #{len} octets: expected #{code}, got #{head.lines.first}"
      end
    end
  end
end

assert('h1: max_body on the instance is refused by name') do
  src = <<~RUBY_APP
    class Wrong < Webmachine::Resource
      def max_body
        64
      end
      def self.to_html
        'no'
      end
    end

    class Right < Webmachine::Resource
      def self.to_html
        'yes'
      end
    end

    def main
      Webmachine::Application.new do |app|
        begin
          app.add_route [:*], Wrong
        rescue Webmachine::RouteError => e
          puts "refused=\#{e.message}"
        end
        app.add_route [:*], Right
      end
    end
  RUBY_APP
  wm_server(src, tag: 'wm-maxbody-instance') do |_sock, _pid, _err, out|
    text = File.read(out)
    assert_true text.include?('refused='), text
    assert_true text.include?('max_body'), text
  end
end

# RFC 9112 7.1: a chunked request body is read. It declares no length,
# so the count of octets that arrive is what conf.max_body holds, and
# what moves the body from memory into a file.
assert('h1: a chunked body is read, counted, and grows into a file') do
  app = <<~RUBY_APP
    class Chunks < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        b = request.body
        bytes = b.read
        response.body = [b.class.to_s, bytes.bytesize.to_s, bytes[0, 2], bytes[-2, 2]].join('|')
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.routes { |route| route.add [:*], Chunks }
      end
    end
  RUBY_APP
  wm_server(app, tag: 'wm-chunked') do |sock, _|
    # One chunk, then the last chunk and an empty trailer section.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" \
              "4\r\nabcd\r\n0\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal 'StringIO|4|ab|cd', body
    end
    # Several chunks, a chunk extension, and a trailer field. The
    # extension and the trailer are read and dropped.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" \
              "3;name=value\r\nabc\r\n3\r\ndef\r\n0\r\nX-Checksum: 1\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal 'StringIO|6|ab|ef', body
    end
    # The octets arrive in pieces, so the reader stops inside a size
    # line, inside a chunk and between the CR and the LF.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
      # 10 in hexadecimal is sixteen octets, and the writes stop inside
      # the size, inside the data, and between the CR and the LF.
      ["1", "0\r\n0123456789", "abcdef", "\r\n", "0\r", "\n\r\n"].each do |piece|
        s.write(piece)
        sleep 0.02
      end
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal 'StringIO|16|01|ef', body
    end
    # Past the spill mark: what memory holds moves into the file, and
    # the body reads back whole and in order.
    UNIXSocket.open(sock) do |s|
      payload = 'ab' + ('L' * ((512 * 1024) - 4)) + 'yz'
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
      off = 0
      while off < payload.bytesize
        piece = payload.byteslice(off, 64 * 1024)
        off += piece.bytesize
        s.write(format("%x\r\n", piece.bytesize) + piece + "\r\n")
      end
      s.write("0\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      got = body.split('|')
      assert_equal 'File', got[0], 'a chunked body that outgrows memory moves to a file'
      assert_equal payload.bytesize.to_s, got[1]
      assert_equal 'ab', got[2], 'the octets written before the move must be first'
      assert_equal 'yz', got[3]
    end
    # A size that is not hexadecimal is a client fault.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
      assert_true h1_expect_eof(s)
    end
  end
end

assert('h1: a chunked body is held to max_body by its count alone') do
  app = <<~RUBY_APP
    class SmallChunks < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        response.body = 'took'
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 32
        app.routes { |route| route.add [:*], SmallChunks }
      end
    end
  RUBY_APP
  wm_server(app, tag: 'wm-chunked-limit') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" \
              "10\r\n0123456789abcdef\r\n0\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal 'took', body
    end
    # 64 octets against a limit of 32: the connection ends at the octet
    # that passes the limit.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" \
              "40\r\n#{'a' * 64}\r\n0\r\n\r\n")
      assert_true h1_expect_eof(s)
    end
  end
end

# RFC 9112 7.1: a chunk of one octet is legal, so a client that chunks
# small is legal. The framing budget is a floor of 64 KiB plus five
# octets for every content octet, and phr_decode_chunked drops every
# framing octet it reads. A body in 8-octet chunks spends five framing
# octets per chunk and passes. Framing that carries no content stops at
# the floor. The budget is per body, so a kept-alive connection carries
# any number of small-chunked bodies.
assert('h1: small chunks pass the framing budget, framing alone does not') do
  app = <<~RUBY_APP
    class TinyChunks < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        b = request.body
        bytes = b.read
        response.body = [b.class.to_s, bytes.bytesize.to_s, bytes[0, 2], bytes[-2, 2]].join('|')
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.routes { |route| route.add [:*], TinyChunks }
      end
    end
  RUBY_APP
  # The body as chunks of eight octets, then the last chunk and an
  # empty trailer section.
  chunk_wire = lambda do |payload|
    wire = +''.b
    off = 0
    while off < payload.bytesize
      piece = payload.byteslice(off, 8)
      off += piece.bytesize
      wire << format("%x\r\n", piece.bytesize) << piece << "\r\n"
    end
    wire << "0\r\n\r\n"
  end
  wm_server(app, tag: 'wm-chunked-small') do |sock, _|
    # 320 KiB in 40960 chunks of eight octets. Every chunk spends five
    # framing octets, 200 KiB in all. The body crosses kBodySpill
    # inside the small chunks, so the move from memory to the file is
    # under test too. The old budget of one framing octet per eight
    # content octets refused this body near 128 KiB of content.
    UNIXSocket.open(sock) do |s|
      payload = 'ab' + ('m' * ((320 * 1024) - 4)) + 'yz'
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
      chunk_wire.call(payload).scan(/.{1,65536}/m).each { |slice| s.write(slice) }
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal "File|#{payload.bytesize}|ab|yz", body
    end
    # Framing that carries no content: one chunk of one octet with a
    # chunk extension of 80 KiB. The decoder drops the extension. The
    # framing crosses the floor, and one content octet allows only five
    # octets of it. The refusal comes inside the body, where the
    # reader ends the connection and answers no page. 80 KiB is under
    # the decoder's own rule of 100 KiB, so the refusal is this
    # server's. The server closes with most of the extension unread,
    # so the peer may see a reset in place of EOF.
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
      begin
        s.write("1;" + ('x' * (80 * 1024)) + "\r\na\r\n0\r\n\r\n")
      rescue Errno::EPIPE, Errno::ECONNRESET
        # The server ended the connection before the write was done.
      end
      out = begin
        wm_read_until_eof(s)
      rescue Errno::ECONNRESET
        +''.b
      end
      assert_false out.start_with?('HTTP/1.1 2'), out[0, 64]
    end
    # The budget is per body. Eighty bodies of 2 KiB in 8-octet chunks
    # on one connection spend 1280 framing octets each, 100 KiB in all,
    # and every one of them passes. A budget that carried over from body
    # to body refused the 52nd against the old floor, and the 60th
    # against the new one.
    UNIXSocket.open(sock) do |s|
      payload = 'ab' + ('k' * 2044) + 'yz'
      wire = chunk_wire.call(payload)
      80.times do |i|
        s.write("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + wire)
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), "body #{i}: #{head.lines.first}"
        assert_equal 'StringIO|2048|ab|yz', body
      end
    end
  end
end


# RFC 9110 8.3: `sniff: true` on a content_types_accepted row asks the
# server to check the octets against the type the head declared, and to
# refuse at the first buffer rather than after the whole upload.
assert('h1: sniff refuses a body that is not what its head declared') do
  app = <<~RUBY_APP
    class Sniffed < Webmachine::Resource
      reads_body :from_png
      reads_body :from_text
      reads_body :from_json
      def self.allowed_methods
        %w[GET PUT]
      end

      def self.content_types_accepted
        [['image/png', :from_png, { sniff: true }],
         ['text/plain', :from_text, { sniff: true }],
         ['application/json', :from_json]]
      end

      def from_png
        response.body = "png \#{request.body.read.bytesize}"
        true
      end

      def from_text
        response.body = "text \#{request.body.read.bytesize}"
        true
      end

      def from_json
        response.body = "json \#{request.body.read.bytesize}"
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.routes { |route| route.add [:*], Sniffed }
      end
    end
  RUBY_APP
  png = "\x89PNG\r\n\x1a\n".b + ("\x00" * 64)
  mp4 = ("\x00\x00\x00\x18" + 'ftypisom').b + ("\x00" * 64)
  wm_server(app, tag: 'wm-sniff') do |sock, _|
    checks = [
      # The octets are what the head said: served.
      ['image/png', png, '200', 'png'],
      # A PNG declared as text: the table cannot confirm text/plain, so
      # it asks what the octets are, and they name another family.
      ['text/plain', png, '415', nil],
      # Your case: an mp4 that says it is a text file.
      ['text/plain', mp4, '415', nil],
      # An mp4 that says it is a PNG: a type the table knows, with the
      # wrong octets.
      ['image/png', mp4, '415', nil],
      # Text that says it is text: nothing to contradict.
      ['text/plain', 'the quick brown fox', '200', 'text'],
      # A row without sniff: true is not checked at all.
      ['application/json', mp4, '200', 'json'],
    ]
    checks.each do |(type, body, code, want)|
      UNIXSocket.open(sock) do |s|
        s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Type: #{type}\r\n" \
                "Content-Length: #{body.bytesize}\r\n\r\n#{body}")
        head, got = wm_read(s)
        assert_true head.start_with?("HTTP/1.1 #{code}"),
                    "#{type} with those octets: expected #{code}, got #{head.lines.first}"
        assert_true got.start_with?(want), got if want
      end
    end
  end
end

# RFC 9110 6.4: request.body.save puts an upload in the filesystem under
# a directory named for its own octets, and tells the block where it
# landed or what stopped it.
assert('h1: request.body.save is content addressed, and the second upload of the same octets is free') do
  root = "/tmp/wm-save-#{$$}"
  Dir.mkdir(root) unless Dir.exist?(root)
  app = <<~RUBY_APP
    class Saved < Webmachine::Resource
      reads_body :take, save: true
      def self.allowed_methods
        %w[GET PUT]
      end

      def self.content_types_accepted
        [['application/octet-stream', :take]]
      end

      def take
        request.body.save('#{root}', request.headers['x-name'] || 'blob.bin') do |dir, err|
          dir
        end
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.routes { |route| route.add [:*], Saved }
      end
    end
  RUBY_APP
  put = lambda do |sock, body, name|
    UNIXSocket.open(sock) do |s|
      extra = name ? "X-Name: #{name}\r\n" : ''
      s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n" \
              "#{extra}Content-Length: #{body.bytesize}\r\n\r\n#{body}")
      head, got = wm_read(s)
      [head, got]
    end
  end
  begin
    wm_server(app, tag: 'wm-save') do |sock, _|
      small = 'a body that stays in memory'
      big = 'AB' + ('L' * ((512 * 1024) - 4)) + 'YZ'
      # A body in memory: written out, under the digest of itself.
      head, dir = put.call(sock, small, nil)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_true dir.start_with?(root), dir
      assert_true File.exist?(File.join(dir, 'blob.bin')), dir
      assert_equal small, File.read(File.join(dir, 'blob.bin'))
      # Two octets of the digest are the first level, the whole digest
      # the second.
      rest = dir[(root.size + 1)..]
      assert_equal 2, rest.split('/')[0].size
      assert_equal 64, rest.split('/')[1].size
      assert_true rest.split('/')[1].start_with?(rest.split('/')[0])
      # The same octets again: the same directory, and nothing written.
      head2, dir2 = put.call(sock, small, nil)
      assert_true head2.start_with?('HTTP/1.1 200'), head2
      assert_equal dir, dir2
      # The same octets under another name: one more link in the same
      # directory.
      _, dir3 = put.call(sock, small, 'copy.bin')
      assert_equal dir, dir3
      assert_true File.exist?(File.join(dir, 'copy.bin'))
      assert_equal File.size(File.join(dir, 'blob.bin')), File.size(File.join(dir, 'copy.bin'))
      # A body that went to a file is linked into place, whole and in
      # order.
      head4, dir4 = put.call(sock, big, 'big.bin')
      assert_true head4.start_with?('HTTP/1.1 200'), head4
      assert_true dir4 != dir
      landed = File.join(dir4, 'big.bin')
      assert_equal big.bytesize, File.size(landed)
      assert_equal big, File.read(landed)
      # A name with a directory in it never reaches the filesystem, and
      # the server spells the status for it - the resource does not.
      head5, = put.call(sock, small, '../escaped.bin')
      assert_true head5.start_with?('HTTP/1.1 500'), head5
      assert_false File.exist?('/tmp/escaped.bin')
    end
  ensure
    Dir.glob(File.join(root, '*', '*', '*')).each { |f| File.unlink(f) rescue nil }
    Dir.glob(File.join(root, '*', '*')).each { |d| Dir.rmdir(d) rescue nil }
    Dir.glob(File.join(root, '*')).each { |d| Dir.rmdir(d) rescue nil }
    Dir.rmdir(root) rescue nil
  end
end

# #54: a save is a stop's worth of promise too. Without `save: true` the
# body of a small request is in memory, and saving it there would be a
# second write of every octet - so it is refused by name.
assert('h1: request.body.save is refused when the callback did not declare it') do
  root = "/tmp/wm-nosave-#{$$}"
  Dir.mkdir(root) unless Dir.exist?(root)
  app = <<~RUBY_APP
    class Undeclared < Webmachine::Resource
      reads_body :take
      def self.allowed_methods
        %w[GET PUT]
      end
      def self.content_types_accepted
        [['application/octet-stream', :take]]
      end
      def take
        request.body.save('#{root}', 'blob.bin') { |dir, _err| dir }
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [:*], Undeclared }
      end
    end
  RUBY_APP
  begin
    wm_server(app, tag: 'wm-nosave') do |sock, _|
      UNIXSocket.open(sock) do |s|
        body = 'a body nobody promised to save'
        s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n" \
                "Content-Length: #{body.bytesize}\r\n\r\n#{body}")
        head, page = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 500'), head
        assert_true page.include?('save: true'), page
      end
      assert_true Dir.glob(File.join(root, '*')).empty?
    end
  ensure
    Dir.rmdir(root) rescue nil
  end
end

# #54: and with the declaration the head puts even a small body in a
# file, so the save is a link and not a second write.
assert('h1: a declared saver gets a file, whatever the size') do
  app = <<~RUBY_APP
    class Declared < Webmachine::Resource
      reads_body :take, save: true
      def self.allowed_methods
        %w[GET PUT]
      end
      def self.content_types_accepted
        [['application/octet-stream', :take]]
      end
      def take
        response.body = request.body.class.to_s
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [:*], Declared }
      end
    end
  RUBY_APP
  wm_server(app, tag: 'wm-declared-save') do |sock, _|
    UNIXSocket.open(sock) do |s|
      body = 'small enough to have stayed in memory'
      s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n" \
              "Content-Length: #{body.bytesize}\r\n\r\n#{body}")
      head, got = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal 'File', got
    end
  end
end

# A body a run asked for and never read is that request's, and it ends
# with it. Before this the file and the flag stayed on the connection:
# the next request was handed the old octets as its body, and its own
# octets were stepped over as though a run had taken them.
assert('h1: a body no run read ends with its request, not with the next one') do
  app = <<~RUBY_APP
    class Gate < Webmachine::Resource
      reads_body :process_post, save: true

      def self.allowed_methods
        %w[GET POST]
      end

      # Above the three nodes that read content, so a refusal here
      # answers while the body is still nobody's.
      def forbidden?
        request.headers['x-open'].nil?
      end

      def process_post
        response.body = request.body.read
        true
      end

      def to_html
        'get'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [:*], Gate }
      end
    end
  RUBY_APP
  wm_server(app, tag: 'wm-stale-body') do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n" \
              "Content-Length: 5\r\n\r\nfirst")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 403'), head
      s.write("POST / HTTP/1.1\r\nHost: x\r\nX-Open: 1\r\n" \
              "Content-Type: application/octet-stream\r\nContent-Length: 6\r\n\r\nsecond")
      head2, body2 = wm_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), head2
      assert_equal 'second', body2
    end
  end
end
