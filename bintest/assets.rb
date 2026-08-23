# The asset tier on the wire (#170): a ZIP built by hand right here,
# served back as gzip synthesized from the archive's own bytes - the
# deflate stream untouched, header and trailer from the Central
# Directory. Every claim the task makes is asserted at byte level:
# method encodes the coding, 406 for refused codings, 304/412 from the
# CRC ETag, Explorer-shaped archives (deflate only) just work.

require 'socket'
require 'stringio'
require 'tempfile'
require 'zlib'

A_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(A_BIN)

def a_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

# One ZIP, spelled by hand so the test owns every byte: entries are
# [name, data, method]; method 8 deflates via zlib (raw stream, the
# same bytes any zip tool would store), 0 stores. DOS stamp fixed:
# 2025-03-01 12:04:06.
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

def a_server(zip_bytes)
  zf = Tempfile.new(['wm-assets', '.zip'])
  zf.binmode
  zf.write(zip_bytes)
  zf.close
  sock = "/tmp/wm-assets-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-assets-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, A_BIN, '--unix', sock, '--assets', zf.path,
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

# Reads one response; body only where one is owed (a HEAD caller and
# the bodyless statuses say so).
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
      # RFC 1952 framing, byte for byte: MTIME=0 and OS=0xff are what
      # keep the header constant; the trailer is CRC-32 + ISIZE out of
      # the Central Directory. Content-Length = deflate + 18.
      assert_equal "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff".b, body[0, 10]
      assert_equal [Zlib.crc32(A_CSS), A_CSS.bytesize].pack('VV'), body[-8, 8]
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
      # HEAD: the same head (Content-Length announced), no body bytes -
      # a pipelined GET's answer must begin immediately.
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
      # identity asked, identity served: stored entries have no 406 case.
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
      ['',                          200],  # no field: any coding acceptable
      ['Accept-Encoding: gzip',     200],
      ['Accept-Encoding: gzip;q=0.5, br', 200],
      ['Accept-Encoding: *',        200],
      ['Accept-Encoding: x-gzip',   200],  # the alias the RFC folds into gzip
      ['Accept-Encoding: identity', 406],  # we cannot inflate - refusal by name
      ['Accept-Encoding: br',       406],
      ['Accept-Encoding: gzip;q=0', 406],
      ['Accept-Encoding: gzip;q=0, *;q=1', 406],  # specific beats star
      ['Accept-Encoding: *;q=0',    406],
      ['Accept-Encoding:',          406],  # empty value: no codings acceptable
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
      # If-None-Match matches (strong, weak-prefixed, starred, listed):
      # 304 with the validators a cache updates by.
      ["If-None-Match: #{etag}",
       %(If-None-Match: W/#{etag}),
       'If-None-Match: *',
       %(If-None-Match: "nope", #{etag})].each do |hdr|
        s.write("GET /site.css HTTP/1.1\r\nHost: x\r\n#{hdr}\r\n\r\n")
        head, = a_read(s, body: false)
        assert_true head.start_with?('HTTP/1.1 304'), "#{hdr} answered #{head[0, 20].inspect}"
        assert_true head.include?("ETag: #{etag}\r\n")
        assert_false head.match?(/^Content-Length/i)  # 304 is bodyless
      end
      # A non-matching If-None-Match serves the representation.
      s.write("GET /site.css HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"zzzzzzzz\"\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      # If-Match compares STRONGLY: a wrong tag is 412, a weak spelling
      # of the right tag can never match (13.1.1).
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

assert('assets: only GET/HEAD; misses fall through to the app tier') do
  a_server(a_the_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST /site.css HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 405')
      assert_true head.match?(/^Allow: GET, HEAD\r$/i)
      # The query never names an entry; the path alone does.
      s.write("GET /site.css?v=1 HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      # A path the table does not hold is NOT an asset: it answers from
      # the app resource (the default konst 200 here), untouched.
      s.write("GET /missing.css HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_false head.match?(/^Content-Encoding/i)
    end
  end
end

assert('assets: an archive this tier cannot serve refuses the start by name') do
  zf = Tempfile.new(['wm-assets-bad', '.zip'])
  zf.binmode
  # method 12 (bzip2): neither stored nor deflate.
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

# --- the h2 side: same table, same verdicts, frames instead of heads ---

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

# :method GET (indexed), :scheme http (indexed), :path literal (name
# index 4, no indexing), :authority literal.
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
      s.write(a_h2_frame(1, 0x05, 1, a_h2_get('/site.css')))  # END_HEADERS|END_STREAM
      t, f, st, block = a_h2_next(s)
      assert_equal 1, t
      assert_equal 1, st
      assert_equal 0x88, block.getbyte(0)  # :status 200, indexed
      # Never-indexed literals arrive as raw bytes: the type, the
      # coding, the Vary and the ETag are all visible in the block.
      assert_true block.include?('text/css'.b)
      assert_true block.include?('gzip'.b)
      assert_true block.include?('Accept-Encoding'.b)
      assert_true block.include?(format('"%08x"', Zlib.crc32(A_CSS)).b)
      body = +''.b
      loop do
        t, f, st, payload = a_h2_next(s)
        assert_equal 0, t  # DATA
        body << payload
        break if (f & 0x1) == 0x1  # END_STREAM
      end
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
      # A conditional over h2 hits the same verdict: 304, no DATA.
      etag = format('"%08x"', Zlib.crc32(A_CSS))
      inm = "if-none-match"
      block = "\x82\x86\x04#{'/site.css'.bytesize.chr}/site.css\x41\x0bexample.com".b
      block << "\x00#{inm.bytesize.chr}#{inm}#{etag.bytesize.chr}#{etag}".b
      s.write(a_h2_frame(1, 0x05, 3, block))
      t, f, st, blk = a_h2_next(s)
      assert_equal 1, t
      assert_equal 3, st
      assert_equal 0x01, f & 0x01  # END_STREAM on HEADERS: bodyless
      assert_equal 0x8b, blk.getbyte(0)  # :status 304, indexed
    end
  end
end

# --- the delivery model (#168): bodies past one chunk arrive whole ---

# Incompressible bytes, deterministic: deflate stays >1 chunk, so the
# gzip framing crosses chunk boundaries and the h1 transfer needs
# several more() rounds.
A_BIG = Random.new(42).bytes(300 * 1024) unless defined?(A_BIG)

def a_big_zip
  a_build_zip([['big.bin', A_BIG, 0], ['big.gz.bin', A_BIG, 8], ['site.css', A_CSS, 8]])
end

assert('delivery h1: a body past the chunk budget arrives whole, in order') do
  a_server(a_big_zip) do |sock|
    UNIXSocket.open(sock) do |s|
      # Stored: the body is the mapping's bytes, several chunks long.
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_equal A_BIG.bytesize, body.bytesize
      assert_equal A_BIG.b, body
      # Deflated: gzip header/deflate/trailer cross chunk boundaries.
      s.write("GET /big.gz.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = a_read(s)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      assert_equal A_BIG.b, Zlib::GzipReader.new(StringIO.new(body)).read.b
      # Pipelined BEHIND a transfer: the small answer must wait its
      # turn and still be byte-perfect.
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /site.css HTTP/1.1\r\nHost: x\r\n\r\n")
      h1, b1 = a_read(s)
      assert_true h1.start_with?('HTTP/1.1 200 OK')
      assert_equal A_BIG.b, b1
      h2, b2 = a_read(s)
      assert_true h2.match?(%r{^Content-Type: text/css; charset=utf-8\r$}i)
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(b2)).read.b
      # HEAD on a big entry: the head announces the full length, no
      # transfer starts, the connection stays immediately usable.
      s.write("HEAD /big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /site.css HTTP/1.1\r\nHost: x\r\n\r\n")
      hh, = a_read(s, body: false)
      assert_true hh.match?(/^Content-Length: #{A_BIG.bytesize}\r$/i)
      nh, = a_read(s)
      assert_true nh.start_with?('HTTP/1.1 200 OK')
    end
    # Connection: close still delivers the whole source first, then FIN.
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
      # Big client windows: the ONLY thing that can continue past the
      # chunk cap is the drained-sink signal (more()) - no further
      # client frame arrives.
      settings = [4, 1 << 24].pack('nN')  # INITIAL_WINDOW_SIZE
      s.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b + a_h2_frame(4, 0, 0, settings))
      t, = a_h2_next(s)
      raise "expected server SETTINGS, got #{t}" unless t == 4
      t, f, = a_h2_next(s)
      raise "expected SETTINGS ACK, got #{t}/#{f}" unless t == 4 && f == 1
      s.write(a_h2_frame(8, 0, 0, [1 << 24].pack('N')))  # connection window
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
      # A 20-byte stream window parks the source at offset 20; the
      # WINDOW_UPDATE pair drains the rest - the offset park behaves
      # exactly like the byte park the window test has always pinned.
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
      assert_equal 0, f & 0x1  # not END_STREAM: the rest is parked
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

# --- plan delivery over TCP (#168): many rounds, one connection ---
#
# The unix-socket cases elsewhere cover the same code; TCP is here
# because it is the transport that actually segments - a big body
# leaves as a plan spread over several sends, and the rounds must not
# reorder against the small responses queued behind them.

def a_tcp_server(zip_bytes)
  zf = Tempfile.new(['wm-assets-tcp', '.zip'])
  zf.binmode
  zf.write(zip_bytes)
  zf.close
  err = "/tmp/wm-assets-tcp-#{$$}.log"
  port = nil
  pid = nil
  # The port is a guess; a taken one shows as a dead server - try on.
  10.times do
    port = 20000 + rand(40000)
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
      # deflated (gzip framing around the mapping's deflate bytes), a
      # small entry behind it, then stored - all on ONE connection.
      # Order must hold across continuation rounds: a plan is unsent
      # bytes, and the next response may not overtake them.
      s.write("GET /big.gz.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      h, b1 = a_read(s)
      assert_true h.match?(/^Content-Encoding: gzip\r$/i)
      assert_equal A_BIG.b, Zlib::GzipReader.new(StringIO.new(b1)).read.b
      s.write("GET /site.css HTTP/1.1\r\nHost: x\r\n\r\nGET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
      h2a, = a_read(s)
      assert_true h2a.match?(%r{^Content-Type: text/css; charset=utf-8\r$}i)
      _, b3 = a_read(s)
      assert_equal A_BIG.b, b3
      # a ranged window wider than one chunk spans rounds too, clipped
      # to the window's edges (#148 through #168's machinery)
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=1000-201000\r\n\r\n")
      h4, b4 = a_read(s)
      assert_true h4.start_with?('HTTP/1.1 206')
      assert_equal A_BIG.b[1000..201000], b4
    end
  end
end

# --- ranges (#148): one range, wire-body octets, 206/416/If-Range ---

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
      # suffix form: the final 10 octets
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=-10\r\n\r\n")
      head, body = a_read(s)
      assert_equal A_BIG.b[-10, 10], body
      # open end from an offset
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=307000-\r\n\r\n")
      head, body = a_read(s)
      assert_true head.match?(%r{^Content-Range: bytes 307000-#{A_BIG.bytesize - 1}/#{A_BIG.bytesize}\r$}i)
      assert_equal A_BIG.b[307000..], body
      # A range over a Content-Encoding: gzip response ranges the
      # ENCODED stream (RFC 9110 14.1.2) - anything else is silent
      # corruption. The wire body is reconstructable bit for bit.
      wire = a_wire_gzip(A_BIG)
      s.write("GET /big.gz.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=5-1004\r\n\r\n")
      head, body = a_read(s)
      assert_true head.start_with?('HTTP/1.1 206')
      assert_true head.match?(/^Content-Encoding: gzip\r$/i)
      assert_true head.match?(%r{^Content-Range: bytes 5-1004/#{wire.bytesize}\r$}i)
      assert_equal wire[5, 1000], body
      # a range wider than one delivery chunk walks the window through
      # the transfer machinery
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
      # past the end: unsatisfiable, names the complete length
      s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=999999999-\r\n\r\n")
      head, = a_read(s)
      assert_true head.start_with?('HTTP/1.1 416 Range Not Satisfiable')
      assert_true head.match?(%r{^Content-Range: bytes \*/#{A_BIG.bytesize}\r$}i)
      # multi-range and foreign units degrade to the full 200 (14.2:
      # a server MAY ignore Range) - stated, tested, never a surprise
      ['bytes=0-1,5-6', 'chapters=1-2', 'bytes=9-5'].each do |r|
        s.write("GET /big.bin HTTP/1.1\r\nHost: x\r\nRange: #{r}\r\n\r\n")
        head, body = a_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), "#{r} answered #{head[0, 20].inspect}"
        assert_equal A_BIG.bytesize, body.bytesize
      end
      # If-Range: the matching validator keeps the range; a stale one
      # (and the unparsed date form) serves the whole representation
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
      # Range handling is defined for GET alone: HEAD answers its
      # plain 200 head, which now advertises the ability
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
      block << "\x00\x05range\x0Cbytes=10-109".b  # literal new-name range
      s.write(a_h2_frame(1, 0x05, 1, block))
      t, _f, st, blk = a_h2_next(s)
      assert_equal 1, t
      assert_equal 0x8a, blk.getbyte(0)  # :status 206, indexed
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

# The refusals, checked as refusals: the server must NOT come up, and it
# must say which entry and why. Since #177 the finding is miniz's, the
# sentence is this tier's - so both halves are pinned.
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
  # General purpose bit 0. miniz reports m_is_encrypted; nothing is
  # served from a pack this tree cannot read whole.
  out = a_refusal(a_build_zip([['secret.css', A_CSS, 8]], flags: 0x1))
  assert_true out.include?('secret.css'), out
  assert_true out.downcase.include?('encrypted'), out
end

assert('assets: a method this tier cannot serve is refused by name') do
  # 12 is bzip2: a legal ZIP method, and one whose bytes are not a
  # deflate stream - so it can never become a gzip body (#170).
  out = a_refusal(a_build_zip([['odd.css', A_CSS, 12]]))
  assert_true out.include?('odd.css'), out
  assert_true out.include?('method 12'), out
end
