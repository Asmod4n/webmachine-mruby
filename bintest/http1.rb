# HTTP/1.1 framing, proven on real sockets: keep-alive, pipelining,
# split heads, body skipping, the Connection-header trim lesson, and
# every refusal path with its RFC clause. Malformed input must kill the
# connection, never the process.

require 'socket'

H1_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(H1_BIN)

def h1_server
  sock = "/tmp/wm-h1-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-h1-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, H1_BIN, '--unix', sock, out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  unless File.socket?(sock)
    Process.kill('TERM', pid) rescue nil
    raise "h1 server never came up\n#{File.read(err) rescue '(no stderr)'}"
  end
  begin
    yield sock, pid
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
  end
end

# Every suite read has a deadline: a wedged server must FAIL the test,
# never hang it. Seen live (2026-08-20): the pre-fix accept bug held a
# readpartial forever and the whole run died in the scrollback.
def wm_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def h1_read_response(s)
  head = +''
  head << wm_recv(s) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''
  body << wm_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

def h1_expect_eof(s)
  # A closing response must be followed by EOF, not silence.
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

assert('h1: 200 with Date, keep-alive carries NO Connection header') do
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Date: \w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT\r$/)
      # The trim lesson: persistence is 1.1's default (RFC 9112 9.3),
      # saying so costs 24 bytes a response for nothing.
      assert_false head.match?(/^Connection:/i)
      assert_equal 'OK', body
      # Keep-alive holds: same socket answers again.
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = h1_read_response(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h1: three pipelined requests get three responses in order') do
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\nGET /c HTTP/1.1\r\nHost: x\r\n\r\n")
      3.times do
        head, body = h1_read_response(s)
        assert_true head.start_with?('HTTP/1.1 200 OK')
        assert_equal 'OK', body
      end
    end
  end
end

assert('h1: a head trickled byte by byte still parses (carry across receives)') do
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      "GET / HTTP/1.1\r\nHost: x\r\n\r\n".each_char do |ch|
        s.write(ch)
        sleep 0.002
      end
      head, body = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_equal 'OK', body
    end
  end
end

assert('h1: a Content-Length body is skipped and framing holds') do
  # The flow answers POST with 405 (default allowed_methods is GET/HEAD,
  # B10) - but the body must STILL be consumed or keep-alive would parse
  # body bytes as the next head.
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")
      head, = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Allow: GET, HEAD\r$/i)
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = h1_read_response(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
    UNIXSocket.open(sock) do |s|
      # Body split across receives: head+partial body, pause, the rest.
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhell")
      sleep 0.02
      s.write('o worl')
      head, = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 405')
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = h1_read_response(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h1: the flow speaks on the wire - 405/304/HEAD from the graph') do
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      # OPTIONS is not in the default allowed_methods: B10 says 405
      # before B3 is ever reached - keep-alive holds, it is no error.
      s.write("OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Allow: GET, HEAD\r$/i)
      # If-None-Match: * on an existing resource: I13 -> J18 -> 304,
      # bodyless by definition (RFC 9110 15.4.5).
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n")
      head304 = +''
      head304 << wm_recv(s) until head304.end_with?("\r\n\r\n")
      assert_true head304.start_with?('HTTP/1.1 304')
      assert_false head304.match?(/^Content-Length:/i)
      # HEAD: 200's head, Content-Length announced, NO body bytes - the
      # pipelined GET's response must begin immediately after.
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
      # A browser-shaped GET negotiates through C4/D5/E6/F7 to 200.
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nAccept-Language: de\r\n" \
              "Accept-Encoding: gzip\r\nAccept-Charset: utf-8\r\n\r\n")
      headn, bodyn = h1_read_response(s)
      assert_true headn.start_with?('HTTP/1.1 200 OK')
      assert_equal 'OK', bodyn
    end
  end
end

assert('h1: Connection: close is honored, spelled, and followed by EOF') do
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head, body = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Connection: close\r$/i)
      assert_equal 'OK', body
      assert_true h1_expect_eof(s)
    end
  end
end

assert('h1: HTTP/1.0 closes by default, persists only when asked (RFC 9112 C.2.2)') do
  h1_server do |sock, _|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.0\r\n\r\n")
      head, = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Connection: close\r$/i)
      assert_true h1_expect_eof(s)
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
      head, = h1_read_response(s)
      assert_true head.match?(/^Connection: keep-alive\r$/i)
      s.write("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
      head2, = h1_read_response(s)
      assert_true head2.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h1: refusals - 400 no Host, 400 malformed, 431 huge head, 413 huge body, 411 chunked') do
  h1_server do |sock, _|
    checks = [
      ["GET / HTTP/1.1\r\n\r\n", '400'],                                        # RFC 9112 3.2
      ["GARBAGE\r\n\r\n", '400'],                                               # RFC 9112 2.2
      ["GET / HTTP/1.1\r\nHost: x\r\nX-Big: #{'a' * 9000}\r\n\r\n", '431'],     # RFC 6585 5
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2097152\r\n\r\n", '413'], # bound
      ["POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", '411'], # RFC 9112 6.1
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nab", '400'], # 6.3.3
      ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab", '400'], # 6.3
      ["GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", '400'],                  # RFC 9112 3.2
      ["GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 2x\r\n\r\n", '400'],       # 1*DIGIT
    ]
    checks.each do |(wire, code)|
      UNIXSocket.open(sock) do |s|
        s.write(wire)
        head, = h1_read_response(s)
        assert_true head.start_with?("HTTP/1.1 #{code}"), "expected #{code}, got: #{head.lines.first}"
        assert_true head.match?(/^Connection: close\r$/i)
        assert_true h1_expect_eof(s)
      end
    end
  end
end

assert('h1: random garbage kills connections, never the process') do
  h1_server do |sock, pid|
    30.times do
      UNIXSocket.open(sock) do |s|
        begin
          s.write(Random.bytes(64 + rand(512)))
        rescue Errno::EPIPE
        end
        # 400+close or (rarely) a parser still waiting for more - either
        # way the server must survive; the socket ends with the block.
        IO.select([s], nil, nil, 0.05)
      end
    end
    assert_true Process.kill(0, pid) == 1
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = h1_read_response(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
    end
  end
end
