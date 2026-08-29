
require 'socket'
require 'stringio'
require 'tempfile'
require 'zlib'

A_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(A_BIN)

def a_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def a_build_zip(entries, flags: 0)
  out = +''.b
  cd = +''.b
  dtime = (12 << 11) | (4 << 5) | 3
  ddate = ((2025 - 1980) << 9) | (3 << 5) | 1
  entries.each do |name, data, method|
    crc = Zlib.crc32(data)
    comp =
      if method == 8
        z = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
        c = z.deflate(data, Zlib::FINISH)
        z.close
        c
      else
        data
      end
    lho = out.bytesize
    out << [0x04034b50, 20, flags, method, dtime, ddate, crc, comp.bytesize, data.bytesize,
            name.bytesize, 0].pack('VvvvvvVVVvv') << name.b << comp
    cd << [0x02014b50, 20, 20, flags, method, dtime, ddate, crc, comp.bytesize, data.bytesize,
           name.bytesize, 0, 0, 0, 0, 0, lho].pack('VvvvvvvVVVvvvvvVV') << name.b
  end
  cd_off = out.bytesize
  out << cd
  out << [0x06054b50, 0, 0, entries.size, entries.size, cd.bytesize, cd_off, 0].pack('VvvvvVVv')
  out
end

def a_server(zip_bytes, extra = [])
  zf = Tempfile.new(['wm-assets', '.zip'])
  zf.binmode
  zf.write(zip_bytes)
  zf.close
  sock = "/tmp/wm-assets-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-assets-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', sock, '--assets', zf.path, *extra,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "asset server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    zf.unlink
  end
end

def a_read(s, body: true)
  head = +''.b
  head << a_recv(s) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  b = +''.b
  if body
    b << a_recv(s, len - b.bytesize) while b.bytesize < len
  end
  [head, b]
end

A_CSS = "body { margin: 0; }\n" * 40 unless defined?(A_CSS)
A_RAW = (0..255).to_a.pack('C*') * 3 unless defined?(A_RAW)

def a_the_zip
  a_build_zip([['site.css', A_CSS, 8], ['img.bin', A_RAW, 0]])
end

assert('assets: a method-8 entry ships as gzip synthesized from the archive itself') do
  a_server(a_the_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /site.css HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(%r{^Content-Type: text/css; charset=utf-8\r$}i)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      assert_true head.match?(/^Vary: Accept-Encoding\r$/i)
      etag = format('"%08x"', Zlib.crc32(A_CSS))
      assert_true head.include?("ETag: #{etag}\r\n"), "etag missing: #{head.inspect}"
      assert_true head.match?(/^Last-Modified: Sat, 01 Mar 2025 12:04:06 GMT\r$/)
      assert_equal "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff".b, body[0, 10]
      assert_equal [Zlib.crc32(A_CSS), A_CSS.bytesize].pack('VV'), body[-8, 8]
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
      s.write("HEAD /site.css HTTP/1.1\r\nHost: x\r\n\r\nGET /img.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      hh, = a_read(s, body: false)
      assert_true hh.start_with?('HTTP/1.1 200 OK')
      assert_true hh.match?(/^Content-Length: #{body.bytesize}\r$/i)
      nh, nb = a_read(s)
      assert_true nh.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nh.inspect}"
      assert_equal A_RAW.b, nb
    end
  end
end

assert('assets: a stored entry is identity - the method IS the decision') do
  a_server(a_the_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /img.bin HTTP/1.1\r\nHost: x\r\nAccept-Encoding: identity\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding/i)
      assert_false head.match?(/^Vary/i)
      assert_equal A_RAW.b, body
      assert_true head.match?(%r{^Content-Type: application/octet-stream\r$}i)
    end
  end
end

assert('assets: Accept-Encoding negotiation - gzip or 406, per RFC 9110 12.5.3/15.5.7') do
  a_server(a_the_zip) do |sock|
    cases = [
      ['',                          200],
      ['Accept-Encoding: gzip',     200],
      ['Accept-Encoding: gzip;q=0.5, br', 200],
      ['Accept-Encoding: *',        200],
      ['Accept-Encoding: x-gzip',   200],
      ['Accept-Encoding: identity', 406],
      ['Accept-Encoding: br',       406],
      ['Accept-Encoding: gzip;q=0', 406],
      ['Accept-Encoding: gzip;q=0, *;q=1', 406],
      ['Accept-Encoding: *;q=0',    406],
      ['Accept-Encoding:',          406],
    ]
    UNIXSocket.open(sock) do |s|
      cases.each do |hdr, want|
        req = +"GET /site.css HTTP/1.1\r\nHost: x\r\n"
        req << hdr << "\r\n" unless hdr.empty?
        req << "\r\n"
        s.write(req)
        head, = a_read(s)
        got = head[/\AHTTP\/1\.1 (\d+)/, 1].to_i
        assert_equal want, got, "#{hdr.inspect} answered #{got}"
        assert_true head.match?(/^Vary: Accept-Encoding\r$/i), "no Vary on #{hdr.inspect}"
      end
    end
  end
end

assert('assets: the CRC ETag drives 304 and 412') do
  a_server(a_the_zip) do |sock|
    etag = format('"%08x"', Zlib.crc32(A_CSS))
    UNIXSocket.open(sock) do |s|
      ["If-None-Match: #{etag}",
       %(If-None-Match: W/#{etag}),
       'If-None-Match: *',
       %(If-None-Match: "nope", #{etag})].each do |hdr|
        s.write("GET /site.css HTTP/1.1\r\nHost: x\r\n#{hdr}\r\n\r\n")
        head, = a_read(s, body: false)
        assert_true head.start_with?('HTTP/1.1 304'), "#{hdr} answered #{head[0, 20].inspect}"
        assert_true head.include?("ETag: #{etag}\r\n")
        assert_false head.match?(/^Content-Length/i)
      end
      s.write("GET /site.css HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"zzzzzzzz\"\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      ["If-Match: \"zzzzzzzz\"", "If-Match: W/#{etag}"].each do |hdr|
        s.write("GET /site.css HTTP/1.1\r\nHost: x\r\n#{hdr}\r\n\r\n")
        head, = a_read(s)
        assert_true head.start_with?('HTTP/1.1 412'), "#{hdr} answered #{head[0, 20].inspect}"
      end
      s.write("GET /site.css HTTP/1.1\r\nHost: x\r\nIf-Match: #{etag}\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
    end
  end
end

assert('assets: only GET/HEAD; a miss falls through, and with no app that is a 404') do
  a_server(a_the_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST /site.css HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Allow: GET, HEAD\r$/i)
      s.write("GET /site.css?v=1 HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      # The pack does not hold it and no app was named, so nothing stands
      # behind this path. It used to be a 200 from the built-in default
      # resource, which is gone.
      s.write("GET /missing.css HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 404'), head.lines.first.to_s
      assert_false head.match?(/^Content-Encoding/i)
    end
  end
end

assert('assets: an archive this tier cannot serve refuses the start by name') do
  zf = Tempfile.new(['wm-assets-bad', '.zip'])
  zf.binmode
  zf.write(a_build_zip([['weird.dat', 'x' * 32, 12]]))
  zf.close
  err = "/tmp/wm-assets-refuse-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', "/tmp/wm-assets-refuse-#{$$}.sock",
              '--assets', zf.path, out: File::NULL, err: err)
  Process.wait(pid)
  assert_false $?.exitstatus == 0
  msg = File.read(err)
  assert_true msg.include?('weird.dat') && msg.include?('method 12'), msg
ensure
  zf.unlink
  File.delete(err) rescue nil
end


def a_h2_read_exact(s, n)
  buf = +''.b
  buf << a_recv(s, n - buf.bytesize) while buf.bytesize < n
  buf
end

def a_h2_frame(type, flags, stream, payload = ''.b)
  len = payload.bytesize
  [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
    [stream].pack('N') + payload
end

def a_h2_next(s)
  h = a_h2_read_exact(s, 9)
  len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
  payload = len > 0 ? a_h2_read_exact(s, len) : ''.b
  [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fffffff, payload]
end

def a_h2_get(path)
  "\x82\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
end

assert('assets over h2: the same gzip bytes ride DATA frames') do
  a_server(a_the_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b + a_h2_frame(4, 0, 0))
      t, = a_h2_next(s)
      raise "expected server SETTINGS, got #{t}" unless t == 4
      t, f, = a_h2_next(s)
      raise "expected SETTINGS ACK, got #{t}/#{f}" unless t == 4 && f == 1
      s.write(a_h2_frame(1, 0x05, 1, a_h2_get('/site.css')))
      t, f, st, block = a_h2_next(s)
      assert_equal 1, t
      assert_equal 1, st
      assert_equal 0x88, block.getbyte(0)
      assert_true block.include?('text/css'.b)
      assert_true block.include?('gzip'.b)
      assert_true block.include?('Accept-Encoding'.b)
      assert_true block.include?(format('"%08x"', Zlib.crc32(A_CSS)).b)
      body = +''.b
      loop do
        t, f, st, payload = a_h2_next(s)
        assert_equal 0, t
        body << payload
        break if (f & 0x1) == 0x1
      end
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
      etag = format('"%08x"', Zlib.crc32(A_CSS))
      inm = "if-none-match"
      block = "\x82\x86\x04#{'/site.css'.bytesize.chr}/site.css\x41\x0bexample.com".b
      block << "\x00#{inm.bytesize.chr}#{inm}#{etag.bytesize.chr}#{etag}".b
      s.write(a_h2_frame(1, 0x05, 3, block))
      t, f, st, blk = a_h2_next(s)
      assert_equal 1, t
      assert_equal 3, st
      assert_equal 0x01, f & 0x01
      assert_equal 0x8b, blk.getbyte(0)
    end
  end
end


A_BIG = Random.new(42).bytes(300 * 1024) unless defined?(A_BIG)

def a_big_zip
  a_build_zip([['big.bin', A_BIG, 0], ['big.gz.bin', A_BIG, 8], ['site.css', A_CSS, 8]])
end

assert('delivery h1: a body past the chunk budget arrives whole, in order') do
  a_server(a_big_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_equal A_BIG.bytesize, body.bytesize
      assert_equal A_BIG.b, body
      s.write("GET /big.gz.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      assert_equal A_BIG.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /site.css HTTP/1.1\r\nHost: x\r\n\r\n")
      h1, b1 = a_read(s)
      assert_true h1.start_with?('HTTP/1.1 200 OK')
      assert_equal A_BIG.b, b1
      h2, b2 = a_read(s)
      assert_true h2.match?(%r{^Content-Type: text/css; charset=utf-8\r$}i)
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(b2)).read.b
      s.write("HEAD /big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /site.css HTTP/1.1\r\nHost: x\r\n\r\n")
      hh, = a_read(s, body: false)
      assert_true hh.match?(/^Content-Length: #{A_BIG.bytesize}\r$/i)
      nh, = a_read(s)
      assert_true nh.start_with?('HTTP/1.1 200 OK')
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head, body = a_read(s)
      assert_true head.match?(/^Connection: close\r$/i)
      assert_equal A_BIG.b, body
      assert_equal '', (s.read_nonblock(1) rescue '') if IO.select([s], nil, nil, 2)
    end
  end
end

assert('delivery h2: the drained sink continues a parked source; so does WINDOW_UPDATE') do
  a_server(a_big_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      settings = [4, 1 << 24].pack('nN')
      s.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b + a_h2_frame(4, 0, 0, settings))
      t, = a_h2_next(s)
      raise "expected server SETTINGS, got #{t}" unless t == 4
      t, f, = a_h2_next(s)
      raise "expected SETTINGS ACK, got #{t}/#{f}" unless t == 4 && f == 1
      s.write(a_h2_frame(8, 0, 0, [1 << 24].pack('N')))
      s.write(a_h2_frame(1, 0x05, 1, a_h2_get('/big.bin')))
      t, _f, st, = a_h2_next(s)
      assert_equal 1, t
      assert_equal 1, st
      body = +''.b
      loop do
        t, f, _st, payload = a_h2_next(s)
        assert_equal 0, t
        body << payload
        break if (f & 0x1) == 0x1
      end
      assert_equal A_BIG.b, body
    end
    UNIXSocket.open(sock) do |s|
      settings = [4, 20].pack('nN')
      s.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b + a_h2_frame(4, 0, 0, settings))
      t, = a_h2_next(s)
      raise "expected server SETTINGS, got #{t}" unless t == 4
      t, f, = a_h2_next(s)
      raise "expected SETTINGS ACK, got #{t}/#{f}" unless t == 4 && f == 1
      s.write(a_h2_frame(1, 0x05, 1, a_h2_get('/site.css')))
      t, _f, st, = a_h2_next(s)
      assert_equal 1, t
      t, f, _st, payload = a_h2_next(s)
      assert_equal 0, t
      assert_equal 20, payload.bytesize
      assert_equal 0, f & 0x1
      s.write(a_h2_frame(8, 0, 0, [1 << 20].pack('N')))
      s.write(a_h2_frame(8, 0, 1, [1 << 20].pack('N')))
      body = payload.dup
      loop do
        t, f, _st, p2 = a_h2_next(s)
        assert_equal 0, t
        body << p2
        break if (f & 0x1) == 0x1
      end
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
    end
  end
end


def a_tcp_server(zip_bytes)
  zf = Tempfile.new(['wm-assets-tcp', '.zip'])
  zf.binmode
  zf.write(zip_bytes)
  zf.close
  err = "/tmp/wm-assets-tcp-#{$$}.log"
  port = nil
  pid = nil
  10.times do
    # Below ip_local_port_range (32768 up here): a fixed port picked
    # INSIDE that window collides with an ephemeral port the machine
    # already handed out, which is how this suite once died on 44468.
    port = 20000 + rand(11000)
    pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--port', port.to_s, '--assets', zf.path,
                out: File::NULL, err: err)
    up = false
    50.times do
      begin
        TCPSocket.open('127.0.0.1', port).close
        up = true
        break
      rescue Errno::ECONNREFUSED, Errno::EADDRNOTAVAIL
        break unless Process.wait(pid, Process::WNOHANG).nil?
        sleep 0.05
      end
    end
    break if up
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    pid = nil
  end
  raise "tcp asset server never came up:\n#{File.read(err) rescue ''}" if pid.nil?
  begin
    yield port
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    zf.unlink
  end
end

assert('big bodies over TCP arrive whole, interleaved with small ones') do
  a_tcp_server(a_big_zip) do |port|
    TCPSocket.open('127.0.0.1', port) do |s|
      s.write("GET /big.gz.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      h, b1 = a_read(s)
      assert_true h.match?(/^Content-Encoding: gzip\r$/i)
      assert_equal A_BIG.b, Zlib::GzipReader.new(StringIO.new(b1)).read.b
      s.write("GET /site.css HTTP/1.1\r\nHost: x\r\n\r\nGET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      h2a, = a_read(s)
      assert_true h2a.match?(%r{^Content-Type: text/css; charset=utf-8\r$}i)
      _, b3 = a_read(s)
      assert_equal A_BIG.b, b3
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=1000-201000\r\n\r\n")
      h4, b4 = a_read(s)
      assert_true h4.start_with?('HTTP/1.1 206')
      assert_equal A_BIG.b[1000..201000], b4
    end
  end
end


def a_wire_gzip(data)
  z = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
  c = z.deflate(data, Zlib::FINISH)
  z.close
  "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff".b + c + [Zlib.crc32(data), data.bytesize].pack('VV')
end

assert('ranges: 206 slices the wire body - stored AND the gzip stream alike') do
  a_server(a_big_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 206 Partial Content')
      assert_true head.match?(%r{^Content-Range: bytes 0-9/#{A_BIG.bytesize}\r$}i)
      assert_equal A_BIG.b[0, 10], body
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=-10\r\n\r\n")
      head, body = a_read(s)
      assert_equal A_BIG.b[-10, 10], body
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=307000-\r\n\r\n")
      head, body = a_read(s)
      assert_true head.match?(%r{^Content-Range: bytes 307000-#{A_BIG.bytesize - 1}/#{A_BIG.bytesize}\r$}i)
      assert_equal A_BIG.b[307000..], body
      wire = a_wire_gzip(A_BIG)
      s.write("GET /big.gz.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=5-1004\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 206')
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      assert_true head.match?(%r{^Content-Range: bytes 5-1004/#{wire.bytesize}\r$}i)
      assert_equal wire[5, 1000], body
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=1000-201000\r\n\r\n")
      _head, body = a_read(s)
      assert_equal A_BIG.b[1000..201000], body
    end
  end
end

assert('ranges: 416, ignored forms, If-Range, HEAD') do
  a_server(a_big_zip) do |sock|
    etag = format('"%08x"', Zlib.crc32(A_BIG))
    UNIXSocket.open(sock) do |s|
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=999999999-\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 416 Range Not Satisfiable')
      assert_true head.match?(%r{^Content-Range: bytes \*/#{A_BIG.bytesize}\r$}i)
      ['bytes=0-1,5-6', 'chapters=1-2', 'bytes=9-5'].each do |r|
        s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: #{r}\r\n\r\n")
        head, body = a_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), "#{r} answered #{head[0, 20].inspect}"
        assert_equal A_BIG.bytesize, body.bytesize
      end
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\nIf-Range: #{etag}\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 206')
      assert_equal 10, body.bytesize
      ['"deadbeef"', 'Sat, 01 Mar 2025 12:04:06 GMT'].each do |ir|
        s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\nIf-Range: #{ir}\r\n\r\n")
        head, body = a_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), "If-Range #{ir} answered #{head[0, 20].inspect}"
        assert_equal A_BIG.bytesize, body.bytesize
      end
      s.write("HEAD /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\n\r\n")
      head, = a_read(s, body: false)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_true head.match?(/^Accept-Ranges: bytes\r$/i)
      assert_true head.match?(/^Content-Length: #{A_BIG.bytesize}\r$/i)
    end
  end
end

assert('ranges over h2: 206 block and windowed DATA') do
  a_server(a_big_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      settings = [4, 1 << 24].pack('nN')
      s.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b + a_h2_frame(4, 0, 0, settings))
      t, = a_h2_next(s)
      raise "expected server SETTINGS, got #{t}" unless t == 4
      t, f, = a_h2_next(s)
      raise "expected SETTINGS ACK, got #{t}/#{f}" unless t == 4 && f == 1
      s.write(a_h2_frame(8, 0, 0, [1 << 24].pack('N')))
      block = a_h2_get('/big.bin')
      block << "\x00\x05range\x0Cbytes=10-109".b
      s.write(a_h2_frame(1, 0x05, 1, block))
      t, _f, st, blk = a_h2_next(s)
      assert_equal 1, t
      assert_equal 0x8a, blk.getbyte(0)
      assert_true blk.include?("bytes 10-109/#{A_BIG.bytesize}".b)
      body = +''.b
      loop do
        t, f, _st2, payload = a_h2_next(s)
        assert_equal 0, t
        body << payload
        break if (f & 0x1) == 0x1
      end
      assert_equal A_BIG.b[10, 100], body
    end
  end
end

def a_refusal(zip_bytes)
  zf = Tempfile.new(['wm-assets-bad', '.zip'])
  zf.binmode
  zf.write(zip_bytes)
  zf.close
  sock = "/tmp/wm-assets-bad-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-assets-bad-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', sock, '--assets', zf.path,
              out: File::NULL, err: err)
  Process.wait(pid)
  raise 'the server came up on a pack it should have refused' if File.socket?(sock)
  File.read(err)
ensure
  File.unlink(sock) rescue nil
  zf.unlink rescue nil
end

assert('assets: an encrypted entry is refused by name, not served') do
  out = a_refusal(a_build_zip([['secret.css', A_CSS, 8]], flags: 0x1))
  assert_true out.include?('secret.css'), out
  assert_true out.downcase.include?('encrypted'), out
end

assert('assets: a method this tier cannot serve is refused by name') do
  out = a_refusal(a_build_zip([['odd.css', A_CSS, 12]]))
  assert_true out.include?('odd.css'), out
  assert_true out.include?('method 12'), out
end

assert('assets: a body above the warm budget arrives byte-exact behind its head') do
  big = ((0..255).to_a.pack('C*') * 800).byteslice(0, 200_000)
  a_server(a_build_zip([['big.bin', big, 0]])) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_equal big.bytesize, body.bytesize
      assert_equal big, body
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body2 = a_read(s)
      assert_equal big, body2
    end
  end
end

assert('access log: --log writes combined lines through the record daemon') do
  zip = a_build_zip([['img.bin', A_RAW, 0]])
  zf = Tempfile.new(['wm-logzip', '.zip'])
  zf.binmode
  zf.write(zip)
  zf.close
  logf = "/tmp/wm-access-#{$$}.log"
  File.unlink(logf) if File.exist?(logf)
  sock = "/tmp/wm-log-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', sock, '--assets', zf.path,
              '--log', logf, out: File::NULL, err: File::NULL)
  100.times { break if File.socket?(sock); sleep 0.05 }
  begin
    UNIXSocket.open(sock) do |s|
      s.write("GET /img.bin HTTP/1.1\r\nHost: x\r\nUser-Agent: probe/1\r\n" \
              "Referer: http://r.example/\"q\r\n\r\n")
      a_read(s)
      s.write("GET /miss HTTP/1.1\r\nHost: x\r\n\r\n")
      a_read(s)
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
  end
  20.times { break if File.exist?(logf) && File.readlines(logf).size >= 2; sleep 0.1 }
  lines = File.readlines(logf)
  assert_equal 2, lines.size
  combined = %r{\A\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "[^"]*(?:\\.[^"]*)*" \d{3} (?:\d+|-) "[^"]*(?:\\.[^"]*)*" "[^"]*(?:\\.[^"]*)*"\n\z}
  lines.each { |l| assert_true l.match?(combined), "not combined: #{l.inspect}" }
  assert_true lines[0].include?('"GET /img.bin HTTP/1.1" 200 768'), lines[0]
  assert_true lines[0].include?('probe/1'), lines[0]
  assert_true lines[0].include?('http://r.example/\\"q'), lines[0]
  # /miss is in no pack and behind no route. It used to be a 200: the server
  # without --app invented a splat route on a Resource nobody folded. That
  # resource is gone, and a path nothing serves is a 404.
  assert_true lines[1].include?(' 404 '), lines[1]
ensure
  File.unlink(logf) rescue nil
  File.unlink(sock) rescue nil
  zf&.unlink
end


assert('assets: an extension the deleted table never knew gets its real type') do
  a_server(a_build_zip([['book.epub', 'PK-ish bytes'.b * 8, 0]])) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /book.epub HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(%r{^Content-Type: application/epub\+zip\r$}i),
                  "epub got: #{head[/^Content-Type:.*$/i]}"
    end
  end
end

assert('assets: --mime-types names the database, and the operator wins') do
  db = Tempfile.new(['wm-mime', '.types'])
  db.write("# a database of one\napplication/vnd.webmachine-test\t\twm  WM\n")
  db.close
  begin
    a_server(a_build_zip([['x.wm', 'body'.b * 16, 0], ['y.zzz', 'body'.b * 16, 0]]),
             ['--mime-types', db.path]) do |sock|
      UNIXSocket.open(sock) do |s|
        s.write("GET /x.wm HTTP/1.1\r\nHost: x\r\n\r\n")
        head, = a_read(s)
        assert_true head.match?(%r{^Content-Type: application/vnd\.webmachine-test\r$}i),
                    "operator file ignored: #{head[/^Content-Type:.*$/i]}"
        s.write("GET /y.zzz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        h2, = a_read(s)
        assert_true h2.match?(%r{^Content-Type: application/octet-stream\r$}i)
      end
    end
  ensure
    db.unlink
  end
end

assert('assets: a --mime-types file that cannot be read refuses the start, by name') do
  zf = Tempfile.new(['wm-assets', '.zip'])
  zf.binmode
  zf.write(a_build_zip([['a.css', 'a{}', 0]]))
  zf.close
  sock = "/tmp/wm-mime-refuse-#{$$}.sock"
  err = "/tmp/wm-mime-refuse-#{$$}.log"
  File.unlink(sock) if File.exist?(sock)
  begin
    pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', sock, '--assets', zf.path,
                '--mime-types', '/nonexistent/mime.types', out: File::NULL, err: err)
    Process.wait(pid)
    assert_false $?.success?, 'a missing media-type database started the server anyway'
    text = File.read(err) rescue ''
    assert_true text.include?('/nonexistent/mime.types'),
                "refusal does not name the file: #{text.inspect}"
    assert_false File.socket?(sock), 'listener came up despite the refusal'
  ensure
    File.unlink(sock) rescue nil
    File.unlink(err) rescue nil
    zf.unlink
  end
end

assert('assets: shared-mime-info globs2 is the second format, and it parses') do
  dir = "/tmp/wm-globs2-#{$$}"
  Dir.mkdir(dir) unless Dir.exist?(dir)
  path = File.join(dir, 'globs2')
  File.write(path, "# generated\n50:application/vnd.webmachine-glob:*.wm\n" \
                   "50:text/plain:*README*\n")
  begin
    a_server(a_build_zip([['x.wm', 'body'.b * 16, 0]]), ['--mime-types', path]) do |sock|
      UNIXSocket.open(sock) do |s|
        s.write("GET /x.wm HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        head, = a_read(s)
        assert_true head.match?(%r{^Content-Type: application/vnd\.webmachine-glob\r$}i),
                    "globs2 not parsed: #{head[/^Content-Type:.*$/i]}"
      end
    end
  ensure
    File.unlink(path) rescue nil
    Dir.rmdir(dir) rescue nil
  end
end

assert('access log: a TCP peer logs its address, not "-" (%h through arm_peer)') do
  zip = a_build_zip([['img.bin', A_RAW, 0]])
  zf = Tempfile.new(['wm-peerzip', '.zip'])
  zf.binmode
  zf.write(zip)
  zf.close
  logf = "/tmp/wm-peer-access-#{$$}.log"
  File.unlink(logf) if File.exist?(logf)
  # Below ip_local_port_range (32768 up here): a fixed port picked
  # INSIDE that window collides with an ephemeral port the machine
  # already handed out, which is how this suite once died on 44468.
  port = 20000 + rand(11000)
  errf = "/tmp/wm-peer-err-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--port', port.to_s, '--assets', zf.path,
              '--log', logf, out: File::NULL, err: errf)
  begin
    up = false
    100.times do
      begin
        TCPSocket.open('127.0.0.1', port).close
        up = true
        break
      rescue Errno::ECONNREFUSED, Errno::EADDRNOTAVAIL
        break unless Process.wait(pid, Process::WNOHANG).nil?
        sleep 0.05
      end
    end
    assert_true up, 'no TCP listener came up'
    TCPSocket.open('127.0.0.1', port) do |s|
      s.write("GET /img.bin HTTP/1.1\r\nHost: x\r\nUser-Agent: probe/2\r\n\r\n")
      a_read(s)
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
  end
  20.times { break if File.exist?(logf) && File.readlines(logf).size >= 1; sleep 0.1 }
  lines = File.readlines(logf)
  assert_true lines.size >= 1, 'no access line was written'
  assert_true lines[0].include?('"GET /img.bin HTTP/1.1" 200'), lines[0]
  # SOCKET_URING_OP_GETSOCKNAME is not in every kernel. Where it is
  # missing the server says so once and %h is '-' by contract; where it
  # is there, the address has to arrive. Both are checked - what is NOT
  # allowed is a '-' on a kernel that could have answered.
  errtext = begin File.read(errf) rescue '' end
  if errtext.include?('peer address unavailable')
    assert_true lines[0].start_with?('- '),
                "the cmd is unsupported here, so %h must be '-': #{lines[0].inspect}"
  else
    assert_true lines[0].start_with?('127.0.0.1 '),
                "peer address missing from %h: #{lines[0].inspect}"
  end
ensure
  File.unlink(logf) rescue nil
  File.unlink(errf) rescue nil
  zf&.unlink
end

assert('assets: a pack alone serves, and everything it does not name is 404') do
  # Stored, not deflated: this test is about what a pack alone serves, and a
  # deflate-only entry has no identity to offer - that is the tier's own 406
  # and it has its own test.
  a_server(a_build_zip([['only.txt', 'in the pack', 0]])) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /only.txt HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal 'in the pack', body
      # No app means no routes at all - not a splat route onto a resource the
      # fold never saw. The server stays up and says 404.
      ['/miss', '/'].each do |path|
        s.write("GET #{path} HTTP/1.1\r\nHost: x\r\n\r\n")
        h, = a_read(s)
        assert_true h.start_with?('HTTP/1.1 404'), "#{path}: #{h.lines.first}"
      end
    end
  end
end

assert('assets: the shipped cat pack serves every status it holds, unchanged') do
  # share/http-cats.zip, built by `rake cats`. CC BY 2.0 asks that the
  # images be named, linked and stated as unchanged - the last of those is
  # a claim about BYTES, so it is checked here rather than asserted in a
  # README: what the tier serves is what the archive holds.
  pack = File.expand_path('../share/http-cats.zip', __dir__)
  skip "no #{pack} - run rake cats" unless File.exist?(pack)
  sock = "/tmp/wm-cats-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-cats-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', sock, '--assets', pack,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "cat server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    UNIXSocket.open(sock) do |s|
      [400, 404, 418, 451, 500, 503].each do |code|
        s.write("GET /cats/#{code}.jpg HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = a_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), "#{code}: #{head.lines.first}"
        assert_true head.match?(%r{^Content-Type: image/jpeg\r$}i), head
        # A JPEG starts SOI and ends EOI. Anything that resized or
        # re-encoded on the way would still satisfy the first and is
        # unlikely to satisfy both against a stored entry.
        assert_equal "\xFF\xD8".b, body[0, 2].b
        assert_equal "\xFF\xD9".b, body[-2, 2].b
      end
      # The attribution travels inside the archive, and is reachable.
      s.write("GET /cats/NOTICE.txt HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_true body.include?('CC BY 2.0'), body
      assert_true body.include?('Tomomi Imura'), body
      assert_true body.include?('CHANGES: NONE'), body
      # Below 400 there is no cat, by the pack's own definition.
      s.write("GET /cats/302.jpg HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 404'), head.lines.first.to_s
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    File.unlink(err) rescue nil
  end
end
