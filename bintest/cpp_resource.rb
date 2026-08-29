# #207 acceptance 1: a C++ resource and a Ruby resource that declare the
# same things answer the SAME BYTES, over both protocols, on every
# method the resource allows.
#
# The pairs come from examples/cpp_resource.rb: /cppk against /rbk is
# the static tier (`def self.to_html`, baked at fold), /cpp against /rb
# is the dynamic one (`def to_html`, run per request). CppKonst and
# CppRun are defined in C++ - tools/webmachine-example/main.cpp - which
# is why this test drives that binary and not webmachine-server.
require 'socket'
require 'tempfile'

CPPR_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-example')
CPPR_APP = File.expand_path('../examples/cpp_resource.rb', __dir__)
CPPR_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b

def cppr_server
  raise "no #{CPPR_BIN} - the example binary needs WM_EXAMPLES (build_config_debug.rb)" \
    unless File.executable?(CPPR_BIN)

  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  app = Tempfile.new(['wm-cppr', '.mrb'])
  app.close
  raise "mrbc failed on #{CPPR_APP}" unless system(mrbc, '-o', app.path, CPPR_APP)

  sock = "/tmp/wm-cppr-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-cppr-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, CPPR_BIN, '--unix', sock, '--app', app.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "example server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

def cppr_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s"
  s.readpartial(maxlen)
end

# One request, one connection, the whole answer - Connection: close makes
# the socket itself the framing, so nothing here has to agree with the
# writer about lengths.
def cppr_ask(sock, method, path, fields = {})
  UNIXSocket.open(sock) do |s|
    head = +"#{method} #{path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
    fields.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "\r\n"
    s.write(head)
    out = +''.b
    loop do
      out << cppr_recv(s, 65_536)
    rescue EOFError
      break
    end
    out
  end
end

# RFC 9110 6.6.1: Date is generated per answer, so it is the one field
# two resources may legitimately differ on. Everything else must match.
def cppr_undate(answer)
  answer.sub(/^Date: [^\r\n]*\r\n/, '')
end

# #210: an error page names the request target, so two answers ABOUT TWO
# DIFFERENT PATHS differ in that one string - and in the Content-Length
# it moves. Both are normalized the way Date is: replaced, not dropped,
# so everything else still has to match byte for byte.
def cppr_untarget(answer, path)
  answer.sub(/^Content-Length: \d+\r\n/, "Content-Length: N\r\n").gsub(path, '/TARGET')
end

def cppr_h2_frame(type, flags, stream, payload = ''.b)
  len = payload.bytesize
  [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
    [stream].pack('N') + payload
end

def cppr_h2_read(s, n)
  buf = +''.b
  buf << cppr_recv(s, n - buf.bytesize) while buf.bytesize < n
  buf
end

def cppr_h2_next(s)
  h = cppr_h2_read(s, 9)
  len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
  [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fffffff,
   len > 0 ? cppr_h2_read(s, len) : ''.b]
end

# One h2 request as the FIRST on its connection: the HPACK encoder is in
# its initial state both times, so two answers that mean the same are
# also spelled the same - which is what makes a byte comparison possible
# at all on a stateful encoding.
def cppr_h2_ask(sock, method, path)
  UNIXSocket.open(sock) do |s|
    s.write(CPPR_PREFACE + cppr_h2_frame(4, 0, 0))
    t, = cppr_h2_next(s)
    raise "expected server SETTINGS, got #{t}" unless t == 4
    cppr_h2_next(s)
    block = "\x02#{method.bytesize.chr}#{method}\x86\x04#{path.bytesize.chr}#{path}" \
            "\x41\x0bexample.com".b
    s.write(cppr_h2_frame(1, 0x05, 1, block))
    frames = []
    loop do
      type, flags, _, payload = cppr_h2_next(s)
      frames << [type, payload]
      break if (flags & 0x01) != 0
    end
    frames
  end
end

assert('#207 h1: the C++ resource and the Ruby one answer the same bytes') do
  cppr_server do |sock|
    %w[/cppk /cpp].each_with_index do |cpp, i|
      rb = %w[/rbk /rb][i]
      %w[GET HEAD].each do |m|
        a = cppr_undate(cppr_ask(sock, m, cpp))
        b = cppr_undate(cppr_ask(sock, m, rb))
        assert_equal b, a, "#{m} #{cpp} differs from #{m} #{rb}"
        assert_true a.start_with?('HTTP/1.1 200 OK'), "#{m} #{cpp}: #{a[0, 40]}"
      end
      # The methods the resource does NOT allow - OPTIONS on the static
      # pair, which declares no allowed_methods, and POST on both. The
      # refusal has to match too, Allow header included; what it must
      # NOT do is differ between C++ and Ruby.
      %w[OPTIONS POST].each do |m|
        a = cppr_untarget(cppr_undate(cppr_ask(sock, m, cpp)), cpp)
        b = cppr_untarget(cppr_undate(cppr_ask(sock, m, rb)), rb)
        assert_equal b, a, "#{m} #{cpp} differs from #{m} #{rb}"
      end
    end
  end
end

assert('#207 h1: the dynamic pair agrees on ETag and on the 304 it earns') do
  cppr_server do |sock|
    a = cppr_ask(sock, 'GET', '/cpp')
    assert_true a.include?("ETag: \"v1\"\r\n"), "no ETag from the C++ resource: #{a[0, 120]}"
    a = cppr_undate(cppr_ask(sock, 'GET', '/cpp', 'If-None-Match' => '"v1"'))
    b = cppr_undate(cppr_ask(sock, 'GET', '/rb', 'If-None-Match' => '"v1"'))
    assert_true a.start_with?('HTTP/1.1 304 Not Modified'), a[0, 40]
    assert_equal b, a
  end
end

assert('#207 h2: the same pairs, frame for frame') do
  cppr_server do |sock|
    [%w[/cppk /rbk], %w[/cpp /rb]].each do |cpp, rb|
      %w[GET HEAD].each do |m|
        # The Date field rides INSIDE the HPACK block, so a second
        # boundary between the two connections is a false negative, not
        # a difference in the resources. Retried, never slackened.
        ok = false
        3.times do
          ok = cppr_h2_ask(sock, m, cpp) == cppr_h2_ask(sock, m, rb)
          break if ok
        end
        assert_true ok, "h2 #{m} #{cpp} differs from h2 #{m} #{rb}"
      end
    end
  end
end
