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
def a_build_zip(entries)
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
    out << [0x04034b50, 20, 0, method, dtime, ddate, crc, comp.bytesize, data.bytesize,
            name.bytesize, 0].pack('VvvvvvVVVvv') << name.b << comp
    cd << [0x02014b50, 20, 20, 0, method, dtime, ddate, crc, comp.bytesize, data.bytesize,
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
      assert_true head.match?(%r{^Content-Type: text/css\r$}i)
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
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read
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
      assert_equal A_CSS.b, Zlib::GzipReader.new(StringIO.new(body)).read
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
