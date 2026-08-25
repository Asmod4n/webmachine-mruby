
require 'socket'
require 'tempfile'
require 'fileutils'

RF_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(RF_BIN)

RF_TEXT = 'hello from the docroot'.freeze
RF_BIG = ('rf' + ('0123456789abcdefghij' * 12_499) + 'END').freeze
RF_SECRET = 'THIS FILE IS OUTSIDE THE DOCROOT'.freeze

def rf_recv(s, maxlen = 65_536, deadline = 10)
  IO.select([s], nil, nil, deadline) or
    raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def rf_read(s)
  head = +''.b
  head << rf_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''.b
  body << rf_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

def rf_app
  <<~RUBY
    # The name comes off the query string on purpose: a path a REQUEST chose
    # is the only interesting case, and the one every traversal test needs.
    class RfFile < Webmachine::Resource
      def to_html
        response.file = request.query['n'] || 'a.txt'
        ''
      end
    end
    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['f'], RfFile
        end
      end
    end
  RUBY
end

def rf_compile(source)
  src = Tempfile.new(['wm-rfapp', '.rb'])
  src.write(source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-rfapp', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise 'mrbc failed to compile the response.file fixture' unless ok
  mrb
ensure
  src&.unlink
end

def rf_tree
  base = "/tmp/wm-rf-#{$$}-#{rand(1 << 30)}"
  root = File.join(base, 'root')
  outside = File.join(base, 'outside')
  FileUtils.mkdir_p(File.join(root, 'sub'))
  FileUtils.mkdir_p(outside)
  File.binwrite(File.join(root, 'a.txt'), RF_TEXT)
  File.binwrite(File.join(root, 'big.txt'), RF_BIG)
  File.binwrite(File.join(root, 'sub', 'deep.txt'), 'deep')
  File.binwrite(File.join(outside, 'secret.txt'), RF_SECRET)
  File.symlink(File.join(outside, 'secret.txt'), File.join(root, 'escape.txt'))
  File.symlink(outside, File.join(root, 'escapedir'))
  [base, root]
end

def rf_serve(docroot: true)
  base, root = rf_tree
  sock = "/tmp/wm-rf-#{$$}-#{rand(1 << 30)}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-rf-stderr-#{$$}.log"
  app = rf_compile(rf_app)
  args = [RF_BIN, '--unix', sock, '--app', app.path]
  args += ['--docroot', root] if docroot
  pid = spawn({ 'WM_BUNDLE' => '0' }, *args, out: File::NULL, err: err)
  200.times do
    break if File.socket?(sock)
    sleep 0.05
  end
  unless File.socket?(sock)
    raise "server never came up:\n#{begin File.read(err) rescue '' end}"
  end
  yield sock, root
ensure
  Process.kill(:TERM, pid) rescue nil
  Process.waitpid(pid) rescue nil
  app&.unlink
  File.unlink(sock) rescue nil
  FileUtils.rm_rf(base) if base
end

def rf_get(sock, name, extra = '', method = 'GET')
  s = UNIXSocket.new(sock)
  s.write "#{method} /f?n=#{name} HTTP/1.1\r\nHost: rf\r\n#{extra}Connection: close\r\n\r\n"
  head, body = rf_read(s)
  s.close
  [head, body]
end

def rf_undated(head)
  head.sub(/^Date: .*\r\n/i, '')
end

assert('response.file serves a file under the docroot') do
  rf_serve do |sock, _root|
    head, body = rf_get(sock, 'a.txt')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_include head, "Content-Length: #{RF_TEXT.bytesize}\r\n"
    assert_include head, 'Last-Modified: '
    assert_equal RF_TEXT, body
  end
end

assert('response.file serves a file in a subdirectory') do
  rf_serve do |sock, _root|
    head, body = rf_get(sock, 'sub%2Fdeep.txt')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal 'deep', body
  end
end

assert('response.file delivers a body larger than one delivery round') do
  rf_serve do |sock, _root|
    head, body = rf_get(sock, 'big.txt')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_include head, "Content-Length: #{RF_BIG.bytesize}\r\n"
    assert_equal RF_BIG, body
  end
end

assert('response.file answers HEAD with the length and no body') do
  rf_serve do |sock, _root|
    s = UNIXSocket.new(sock)
    s.write "HEAD /f?n=a.txt HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n"
    buf = +''.b
    loop do
      chunk = (rf_recv(s) rescue nil)
      break if chunk.nil? || chunk.empty?
      buf << chunk
    end
    s.close
    assert_include buf, 'HTTP/1.1 200 OK'
    assert_include buf, "Content-Length: #{RF_TEXT.bytesize}\r\n"
    assert_true buf.end_with?("\r\n\r\n")
  end
end

assert('response.file answers If-Modified-Since with 304') do
  rf_serve do |sock, _root|
    head, = rf_get(sock, 'a.txt')
    lm = head[/^Last-Modified: *(.+)\r$/i, 1]
    assert_true !lm.nil?
    again, body = rf_get(sock, 'a.txt', "If-Modified-Since: #{lm}\r\n")
    assert_include again, 'HTTP/1.1 304 Not Modified'
    assert_include again, "Last-Modified: #{lm}\r\n"
    assert_equal '', body
  end
end

assert('response.file refuses every escape as the same 404') do
  rf_serve do |sock, _root|
    miss, missb = rf_get(sock, 'nothing-here.txt')
    assert_include miss, 'HTTP/1.1 404 Not Found'
    assert_equal '', missb
    baseline = rf_undated(miss)

    {
      'a "../" traversal' => '..%2Foutside%2Fsecret.txt',
      'a deeper traversal' => 'sub%2F..%2F..%2Foutside%2Fsecret.txt',
      'a symlink pointing outside' => 'escape.txt',
      'a symlinked directory' => 'escapedir%2Fsecret.txt',
      'an absolute path' => '%2Fetc%2Fpasswd',
      'an absolute path into the tree' => '%2Fetc%2Fhostname',
      'a directory' => 'sub',
      'the docroot itself' => '.',
      'an empty name' => ''
    }.each do |what, name|
      head, body = rf_get(sock, name)
      assert_include head, 'HTTP/1.1 404 Not Found'
      assert_false head.include?(RF_SECRET)
      assert_equal '', body
      assert_equal baseline, rf_undated(head), "#{what} answered differently"
    end
  end
end

assert('response.file without a docroot is a named refusal, not a wrong answer') do
  rf_serve(docroot: false) do |sock, _root|
    head, body = rf_get(sock, 'a.txt')
    assert_include head, 'HTTP/1.1 500 Internal Server Error'
    assert_include body, 'response.file='
    assert_include body, 'docroot'
    again, = rf_get(sock, 'a.txt')
    assert_include again, 'HTTP/1.1 500 Internal Server Error'
  end
end

assert('response.file keeps a keep-alive connection in order') do
  rf_serve do |sock, _root|
    s = UNIXSocket.new(sock)
    3.times do
      s.write "GET /f?n=a.txt HTTP/1.1\r\nHost: rf\r\n\r\n"
      head, body = rf_read(s)
      assert_include head, 'HTTP/1.1 200 OK'
      assert_equal RF_TEXT, body
    end
    s.close
  end
end

assert('response.file answers pipelined requests in order') do
  rf_serve do |sock, _root|
    s = UNIXSocket.new(sock)
    s.write("GET /f?n=a.txt HTTP/1.1\r\nHost: rf\r\n\r\n" \
            "GET /f?n=big.txt HTTP/1.1\r\nHost: rf\r\n\r\n" \
            "GET /f?n=nothing-here.txt HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n")
    head, body = rf_read(s)
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal RF_TEXT, body
    head, body = rf_read(s)
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal RF_BIG, body
    head, body = rf_read(s)
    assert_include head, 'HTTP/1.1 404 Not Found'
    assert_equal '', body
    s.close
  end
end

RF_H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b unless defined?(RF_H2_PREFACE)

def rf_h2_frame(type, flags, stream, payload = ''.b)
  len = payload.bytesize
  [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
    [stream].pack('N') + payload
end

def rf_h2_exact(s, n)
  buf = +''.b
  buf << rf_recv(s, n - buf.bytesize) while buf.bytesize < n
  buf
end

def rf_h2_next(s)
  h = rf_h2_exact(s, 9)
  len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
  payload = len > 0 ? rf_h2_exact(s, len) : ''.b
  [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fffffff, payload]
end

assert('response.file over h2 refuses rather than sending an empty body') do
  rf_serve do |sock, _root|
    UNIXSocket.open(sock) do |s|
      s.write(RF_H2_PREFACE + rf_h2_frame(4, 0, 0, ''.b))
      t, = rf_h2_next(s)
      assert_equal 4, t
      t, = rf_h2_next(s)
      assert_equal 4, t
      path = '/f?n=a.txt'
      block = "\x82\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
      s.write(rf_h2_frame(1, 0x05, 1, block))
      type, _flags, stream, hblock = rf_h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_equal 0x8e, hblock.getbyte(0)
      assert_false hblock.getbyte(0) == 0x88
    end
  end
end

assert('a docroot that is missing or is not a directory refuses startup') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  begin
    [[File.join(base, 'no-such-dir'), 'No such file'],
     [File.join(root, 'a.txt'), 'is not a directory']].each do |path, want|
      out = IO.popen([RF_BIN, '--unix', "/tmp/wm-rf-never-#{$$}.sock", '--app', app.path,
                      '--docroot', path, { err: [:child, :out] }], &:read)
      assert_include out, '--docroot'
      assert_include out, want
    end
  ensure
    app&.unlink
    FileUtils.rm_rf(base)
  end
end
