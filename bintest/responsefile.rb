
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

# The window is what bounds memory, so the sizes that matter are the ones
# around it: one short of a window, exactly one, and several - plus a file
# far past the 16 MiB ceiling this path used to refuse outright.
assert('response.file streams a file of any size, window by window') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  sock = "/tmp/wm-rf-big-#{$$}-#{rand(1 << 30)}.sock"
  pid = nil
  begin
    pid = spawn({ 'WM_BUNDLE' => '0' }, RF_BIN, '--unix', sock, '--app', app.path,
                '--docroot', root, out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    [262_143, 262_144, 262_145, 700_000, 20 << 20].each do |n|
      # A repeating pattern, not zeros: a window delivered twice or a window
      # skipped both survive a length check, neither survives this.
      blob = (0...n).map { |i| ((i * 31 + i / 977) & 0xff).chr }.join
      File.binwrite(File.join(root, 'sized.bin'), blob)
      head, body = rf_get(sock, 'sized.bin')
      assert_include head, 'HTTP/1.1 200 OK'
      assert_include head, "Content-Length: #{n}\r\n"
      assert_equal n, body.bytesize
      assert_equal blob, body
    end
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app&.unlink
    File.unlink(sock) rescue nil
    FileUtils.rm_rf(base)
  end
end

# The head named a Content-Length before the last window was read. If the
# file shrinks under it the promise cannot be kept, and a 500 spelled after
# those bytes would sit BEHIND them - the client would wait for a remainder
# that never comes. RFC 9112 6.3: close instead. The property asserted here
# is the deterministic one - the request ENDS - because whether the truncate
# wins the race against the send does not change what must not happen.
assert('response.file that shrinks mid-flight ends the request, never hangs') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  sock = "/tmp/wm-rf-shrink-#{$$}-#{rand(1 << 30)}.sock"
  path = File.join(root, 'shrink.bin')
  File.binwrite(path, 'S' * (48 << 20))
  pid = nil
  begin
    pid = spawn({ 'WM_BUNDLE' => '0' }, RF_BIN, '--unix', sock, '--app', app.path,
                '--docroot', root, out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    cutter = Thread.new { sleep 0.05; File.truncate(path, 1 << 20) rescue nil }
    done = false
    reader = Thread.new do
      s = UNIXSocket.new(sock)
      s.write "GET /f?n=shrink.bin HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n"
      begin
        loop { break if s.readpartial(1 << 16).nil? }
      rescue EOFError, Errno::ECONNRESET, IOError
      end
      s.close rescue nil
      done = true
    end
    assert_true reader.join(20) ? true : false, 'the request never ended'
    assert_true done
    cutter.join
    # And the server is still there afterwards, serving the next request.
    head, body = rf_get(sock, 'a.txt')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal RF_TEXT, body
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app&.unlink
    File.unlink(sock) rescue nil
    FileUtils.rm_rf(base)
  end
end

# A sparse file: the last byte is the only one on disk, so a multi-gigabyte
# case costs no space and no time to create.
def rf_sparse(path, size)
  File.open(path, 'wb') do |f|
    f.seek(size - 1)
    f.write("\xff")
  end
  size
end

# Streams the body instead of collecting it - these cases are gigabytes.
def rf_stream(sock, name)
  s = UNIXSocket.new(sock)
  s.write "GET /f?n=#{name} HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n"
  head = +''.b
  head << rf_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  got = 0
  last = nil
  begin
    while got < len
      part = rf_recv(s, 1 << 16, 30)
      got += part.bytesize
      last = part.getbyte(-1)
    end
  rescue EOFError, Errno::ECONNRESET
  end
  s.close rescue nil
  [head, len, got, last]
end

# ONE sendmsg moves at most MAX_RW_COUNT (INT_MAX rounded down to a page,
# 2,147,479,552 here). A body offered past that comes back short, which is
# indistinguishable from a dead peer - the connection used to be dropped
# with the client holding a prefix and a Content-Length it would never
# reach. The mapping is lent in bounded chunks now, so the size stops
# mattering.
assert('response.file serves a file larger than one send can move') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  sock = "/tmp/wm-rf-huge-#{$$}-#{rand(1 << 30)}.sock"
  size = rf_sparse(File.join(root, 'huge.bin'), 2_200_000_000)
  pid = nil
  begin
    pid = spawn({ 'WM_BUNDLE' => '0' }, RF_BIN, '--unix', sock, '--app', app.path,
                '--docroot', root, out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    head, len, got, last = rf_stream(sock, 'huge.bin')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal size, len
    assert_equal size, got
    assert_equal 0xff, last
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app&.unlink
    File.unlink(sock) rescue nil
    FileUtils.rm_rf(base)
  end
end

# A mapping that cannot be made is not an error: the read path serves the
# same bytes, a window at a time. What must NOT happen is the fallback
# asking for the whole file - that allocation threw std::bad_alloc and took
# the process down, every connection on it with one request.
assert('response.file survives an mmap it cannot make, and still serves') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  sock = "/tmp/wm-rf-nomap-#{$$}-#{rand(1 << 30)}.sock"
  size = rf_sparse(File.join(root, 'huge.bin'), 2_200_000_000)
  pid = nil
  begin
    # An address space too small for the mapping, large enough for the server.
    cmd = "ulimit -v 2000000; exec #{RF_BIN} --unix #{sock} --app #{app.path} " \
          "--docroot #{root}"
    pid = spawn({ 'WM_BUNDLE' => '0' }, 'sh', '-c', cmd, out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock), 'the server never came up under the limit'
    _, len, got, last = rf_stream(sock, 'huge.bin')
    assert_equal size, len
    assert_equal size, got
    assert_equal 0xff, last
    # And it is still there afterwards - the point of the case.
    head, body = rf_get(sock, 'a.txt')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal RF_TEXT, body
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app&.unlink
    File.unlink(sock) rescue nil
    FileUtils.rm_rf(base)
  end
end

# RFC 9110: one access line per REQUEST. A 4 MB file over the window path
# takes sixteen rounds, and the line used to be written from inside the
# round - sixteen lines for one request, each with a window's byte count.
assert('response.file writes one access line per request, not one per window') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  sock = "/tmp/wm-rf-log-#{$$}-#{rand(1 << 30)}.sock"
  logf = "/tmp/wm-rf-access-#{$$}-#{rand(1 << 30)}.log"
  File.unlink(logf) if File.exist?(logf)
  n = 4_000_000
  File.binwrite(File.join(root, 'big.bin'), 'B' * n)
  pid = nil
  begin
    pid = spawn({ 'WM_BUNDLE' => '0' }, RF_BIN, '--unix', sock, '--app', app.path,
                '--docroot', root, '--log', logf, '--file-map-threshold', '0',
                out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    head, body = rf_get(sock, 'big.bin')
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal n, body.bytesize
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
  end
  20.times { break if File.exist?(logf) && !File.readlines(logf).empty?; sleep 0.1 }
  lines = File.readlines(logf)
  assert_equal 1, lines.size, "one request, #{lines.size} lines"
  assert_true lines[0].include?("\" 200 #{n} "), lines[0]
ensure
  File.unlink(logf) rescue nil
  File.unlink(sock) rescue nil
  app&.unlink
  FileUtils.rm_rf(base) if base
end

# A client that hangs up mid-transfer is exactly the event an operator wants
# in the log, so the line is still owed - with the bytes that really left,
# not the ones the head promised.
assert('response.file logs an abandoned transfer once, with what really left') do
  base, root = rf_tree
  app = rf_compile(rf_app)
  sock = "/tmp/wm-rf-abort-#{$$}-#{rand(1 << 30)}.sock"
  logf = "/tmp/wm-rf-abort-access-#{$$}-#{rand(1 << 30)}.log"
  File.unlink(logf) if File.exist?(logf)
  n = 4_000_000
  File.binwrite(File.join(root, 'big.bin'), 'B' * n)
  pid = nil
  begin
    pid = spawn({ 'WM_BUNDLE' => '0' }, RF_BIN, '--unix', sock, '--app', app.path,
                '--docroot', root, '--log', logf, '--file-map-threshold', '0',
                out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    s = UNIXSocket.new(sock)
    s.write "GET /f?n=big.bin HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n"
    head = +''.b
    head << rf_recv(s, 1) until head.end_with?("\r\n\r\n")
    rf_recv(s, 4096)
    s.close                       # hang up with the body still owed
  ensure
    sleep 0.3
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
  end
  20.times { break if File.exist?(logf) && !File.readlines(logf).empty?; sleep 0.1 }
  lines = File.readlines(logf)
  assert_equal 1, lines.size, "one aborted request, #{lines.size} lines"
  bytes = lines[0][/" 200 (\d+) /, 1].to_i
  assert_true bytes > 0, "logged #{bytes} bytes"
  assert_true bytes < n, "logged #{bytes}, which is the whole file"
ensure
  File.unlink(logf) rescue nil
  File.unlink(sock) rescue nil
  app&.unlink
  FileUtils.rm_rf(base) if base
end
