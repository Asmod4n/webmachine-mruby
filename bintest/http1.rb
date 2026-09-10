
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

assert('h1: refusals - 400 no Host, 400 malformed, 431 huge head, 413 huge body, 411 chunked') do
  wm_server(H1_APP, tag: 'wm-h1') do |sock, _|
    checks = [
      ["GET / HTTP/1.1\r\n\r\n", '400'],
      ["GARBAGE\r\n\r\n", '400'],
      ["GET / HTTP/1.1\r\nHost: x\r\nX-Big: #{'a' * 9000}\r\n\r\n", '431'],
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2097152\r\n\r\n", '413'],
      ["POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", '411'],
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
