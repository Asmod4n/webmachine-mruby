# Dynamic-body gzip on the wire (#147): encodings_provided compressing
# what a resource RENDERS, never what #170's asset tier ships (that
# tier bakes its coding into the ZIP at build time and is covered in
# bintest/assets.rb - nothing here touches it).
#
# TOR 1 (size) used to be MSS asked at accept over the ring, and every
# TCP case here forced the loopback MSS down with TCP_MAXSEG on the
# CLIENT socket before connect() to get a response across that line
# with a bintest-sized body. That query is gone (Nutzer-Entscheid
# 2026-08-22, #147 Tor 1 revision): src/http1.hpp's kCompressFloor is
# now a fixed 1280 bytes of head+body (the IPv6 minimum MTU), so the
# cases below steer entirely through response SIZE - a body comfortably
# over the floor (GZ_BODY, 11400 bytes), comfortably under it
# (GZ_SMALL_RESOURCE, 2 bytes), or, for the boundary case, sized to
# land exactly on 1280 and 1279 total bytes. No socket option involved
# anywhere in this file any more.

require 'socket'
require 'stringio'
require 'tempfile'
require 'zlib'

GZ_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(GZ_BIN)

def gz_recv(s, maxlen = 65536, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def gz_compile(app_source)
  src = Tempfile.new(['wm-gzapp', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-gzapp', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile:\n#{app_source}" unless ok
  mrb
ensure
  src&.unlink
end

# head + up-to-len body, read to a deadline like every other bintest
# reader here - a wedged server fails the test, never hangs the suite.
def gz_read(s)
  head = +''.b
  head << gz_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''.b
  body << gz_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

def gz_unix_server(app_source)
  app = gz_compile(app_source)
  sock = "/tmp/wm-gz-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-gz-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, GZ_BIN, '--unix', sock, '--app', app.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    UNIXSocket.open(sock) { |s| yield s }
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

def gz_tcp_server(app_source)
  app = gz_compile(app_source)
  err = "/tmp/wm-gz-tcp-stderr-#{$$}.log"
  port = nil
  pid = nil
  # The port is a guess; a taken one shows as a dead server - try on
  # (same shape as bintest/assets.rb's a_tcp_server).
  10.times do
    port = 20000 + rand(40000)
    pid = spawn({ 'WM_BUNDLE' => '0' }, GZ_BIN, '--port', port.to_s, '--app', app.path,
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
  raise "tcp server never came up:\n#{File.read(err) rescue ''}" if pid.nil?
  begin
    yield port
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    app.unlink
  end
end

def gz_tcp_connect(port)
  TCPSocket.open('127.0.0.1', port)
end

GZ_ENC_RESOURCE = <<~RUBY unless defined?(GZ_ENC_RESOURCE)
  class GzEncResource < Webmachine::Resource
    def self.encodings_provided
      {"identity" => :encode_identity, "gzip" => :encode_gzip}
    end
    def to_html
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200
    end
  end
RUBY

GZ_NOENC_RESOURCE = <<~RUBY unless defined?(GZ_NOENC_RESOURCE)
  class GzNoEncResource < Webmachine::Resource
    def to_html
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200
    end
  end
RUBY

GZ_SMALL_RESOURCE = <<~RUBY unless defined?(GZ_SMALL_RESOURCE)
  class GzSmallResource < Webmachine::Resource
    def self.encodings_provided
      {"identity" => :encode_identity, "gzip" => :encode_gzip}
    end
    def to_html
      "hi"
    end
  end
RUBY

GZ_BODY = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200).b unless defined?(GZ_BODY)

# A resource whose body is an exact byte count, sliced off GZ_BODY (the
# same repetitive, gzip-friendly text every other case here uses) so
# the boundary test below can steer head+body across kCompressFloor by
# construction rather than by guessing a request size that happens to
# land there.
def gz_sized_resource(n)
  body = GZ_BODY[0, n]
  raise "GZ_BODY too short for #{n} bytes" if body.bytesize != n
  <<~RUBY
    class GzBoundaryResource < Webmachine::Resource
      def self.encodings_provided
        {"identity" => :encode_identity, "gzip" => :encode_gzip}
      end
      def to_html
        #{body.inspect}
      end
    end
  RUBY
end

# (a) encodings_provided + a gzip-accepting client + a body comfortably
# over kCompressFloor (GZ_BODY, 11400 bytes): the answer is gzip, and
# `gzip -dc` (Zlib::GzipReader here - the same decoder, no reason to
# shell out) reproduces the body byte for byte. Vary: Accept-Encoding
# is present.
#
# NOT asserted here, by name (#147's own report explains why): a
# DISTINCT ETag per coding and a coding-aware 304. Dynamic resources
# carry no ETag machinery at all yet - generate_etag stays refused at
# setup (resource.cpp's kUnhonored) until a later tier lands it, so
# there is no ETag for this test to compare, distinct or otherwise.
assert('gzip: encodings_provided + Accept-Encoding: gzip + a body over the floor compresses, byte-identical') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      assert_true head.match?(/^Vary: Accept-Encoding\r$/i), head
      decompressed = Zlib::GzipReader.new(StringIO.new(body)).read
      assert_equal GZ_BODY, decompressed
      assert_true body.bytesize < GZ_BODY.bytesize, 'gzip should shrink repetitive text'
    ensure
      s.close
    end
  end
end

# (b) the SAME resource, over a unix socket: unix is never packetized
# on this hop (a proxy sits behind it, #147), so this tier never
# compresses there, regardless of body size or Accept-Encoding.
assert('gzip: the same resource over a unix socket never compresses') do
  gz_unix_server(GZ_ENC_RESOURCE) do |s|
    s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
    head, body = gz_read(s)
    assert_true head.start_with?('HTTP/1.1 200 OK')
    assert_false head.match?(/^Content-Encoding:/i), head
    # Still varies by coding in principle (a TCP client of the same
    # resource could get gzip) - Vary stays present.
    assert_true head.match?(/^Vary: Accept-Encoding\r$/i), head
    assert_equal GZ_BODY, body
  end
end

# (c) a response well under kCompressFloor (GZ_SMALL_RESOURCE, "hi" -
# 2 bytes): TOR 1 says identity even though the resource offers gzip
# and the client accepts it - compression cannot help a response this
# small on any path.
assert('gzip: a response under the compress floor stays identity') do
  gz_tcp_server(GZ_SMALL_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_true head.match?(/^Vary: Accept-Encoding\r$/i), head
      assert_equal 'hi', body
    ensure
      s.close
    end
  end
end

# (d) a resource that never declared encodings_provided: always
# identity, no matter how large the body - and no Vary either (this
# resource never varies by coding at all).
assert('gzip: a resource without encodings_provided is always identity') do
  gz_tcp_server(GZ_NOENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_false head.match?(/^Vary:/i), head
      assert_equal GZ_BODY, body
    ensure
      s.close
    end
  end
end

# Negotiation is shared code (http::gzip_acceptable, pulled out of the
# asset tier rather than duplicated - #147's own requirement): a
# client that explicitly refuses gzip (q=0) gets identity even though
# the response is well over the compress floor.
assert('gzip: Accept-Encoding: gzip;q=0 refuses the coding, identity answers') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip;q=0\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_equal GZ_BODY, body
    ensure
      s.close
    end
  end
end

# A missing Accept-Encoding accepts anything (RFC 9110 12.5.3): the
# default negotiation still lets gzip through once the size gate says
# yes.
assert('gzip: a missing Accept-Encoding still compresses past the size gate') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      assert_equal GZ_BODY, Zlib::GzipReader.new(StringIO.new(body)).read
    ensure
      s.close
    end
  end
end

# HEAD renders too (the same invariant dynamic bodies already carry):
# its Content-Length must be the GET's - here, the GZIPPED length,
# since this exact request would compress as a GET - and it sends no
# body bytes.
assert('gzip: HEAD reports the gzipped Content-Length and no body') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n")
      data = +''.b
      begin
        loop { data << gz_recv(s) }
      rescue EOFError
        # readpartial's ordinary way of reporting the peer's close -
        # Connection: close ends the response with no further framing
        # to read, so this is success, not a failure.
      end
      idx = data.index("\r\n\r\n")
      # +4: keep the terminating blank line IN head, the same shape
      # gz_read hands its callers - the last header's line needs its
      # trailing \r for the "\r$" regexes below to anchor on.
      head = data[0, idx + 4]
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      gz_len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
      assert_true gz_len > 0 && gz_len < GZ_BODY.bytesize
      assert_equal idx + 4, data.bytesize, 'HEAD must not leak body bytes'
    ensure
      s.close
    end
  end
end

# The exact edge of kCompressFloor (src/http1.hpp): head+body >= 1280
# compresses, one byte short does not. The head's own byte count is
# not hardcoded here - a calibration request measures it against a
# known body length first, so this test tracks the real wire format
# instead of a guess at it (and fails loudly, via the digit-count
# check below, if that format ever changes shape).
assert('gzip: exactly at the compress floor (1280B) compresses; 1279B does not') do
  cal_n = 2000  # 4 digits, same band the two computed sizes land in
  head_bytesize = nil
  gz_tcp_server(gz_sized_resource(cal_n)) do |port|
    s = gz_tcp_connect(port)
    begin
      # q=0 forces identity so the calibration body is exactly cal_n
      # bytes on the wire - but the HEAD BYTES themselves are the same
      # ok_prefix_vary_ head a real gzip-eligible request would also
      # get (assemble_dynamic always sizes against that prefix,
      # win or lose), so this measurement is valid for the gating
      # decision too, not just for a forced-identity response.
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip;q=0\r\n\r\n")
      head, body = gz_read(s)
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_equal cal_n, body.bytesize
      head_bytesize = head.bytesize
    ensure
      s.close
    end
  end

  # total = head_bytesize + n holds for any n whose Content-Length
  # digit count matches cal_n's - true here since both computed sizes
  # land in the low thousands, same 4 digits as cal_n.
  n_compress = 1280 - head_bytesize
  n_identity = 1279 - head_bytesize
  assert_equal cal_n.to_s.size, n_compress.to_s.size, 'digit count drifted - recheck cal_n'
  assert_equal cal_n.to_s.size, n_identity.to_s.size, 'digit count drifted - recheck cal_n'

  gz_tcp_server(gz_sized_resource(n_compress)) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      assert_equal GZ_BODY[0, n_compress], Zlib::GzipReader.new(StringIO.new(body)).read
    ensure
      s.close
    end
  end

  gz_tcp_server(gz_sized_resource(n_identity)) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_equal GZ_BODY[0, n_identity], body
    ensure
      s.close
    end
  end
  true
end
