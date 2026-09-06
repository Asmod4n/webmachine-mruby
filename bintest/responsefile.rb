
require 'socket'
require 'tempfile'
require 'fileutils'

RF_TEXT = 'hello from the docroot'.freeze
RF_BIG = ('rf' + ('0123456789abcdefghij' * 12_499) + 'END').freeze
RF_SECRET = 'THIS FILE IS OUTSIDE THE DOCROOT'.freeze

def rf_app
  <<~RUBY
    # The name comes off the query string on purpose: a path a request chose
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
  args = docroot ? ["--docroot=#{root}"] : []
  wm_server(rf_app, *args, sock: sock, tag: 'wm-rf') do |s|
    yield s, root
  end
ensure
  FileUtils.rm_rf(base) if base
end

def rf_get(sock, name, extra = '', method = 'GET')
  wm_conn(sock) do |s|
    s.write "#{method} /f?n=#{name} HTTP/1.1\r\nHost: rf\r\n#{extra}\r\n"
    wm_read(s)
  end
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
      chunk = (wm_recv(s, 65_536) rescue nil)
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
    # Every refusal wears the page its status has - the graph has one 404,
    # and a file that is not there is that 404.
    assert_include missb, '<p class=n>404</p>'
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
      # The same bytes as a plain miss, so an attacker cannot tell a
      # caught escape from a name that was never there.
      assert_equal missb, body, "#{what} answered a different body"
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
      head, body = wm_read(s)
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
    head, body = wm_read(s)
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal RF_TEXT, body
    head, body = wm_read(s)
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal RF_BIG, body
    head, body = wm_read(s)
    assert_include head, 'HTTP/1.1 404 Not Found'
    assert_include body, '<p class=n>404</p>'
    s.close
  end
end

assert('response.file over h2 refuses rather than sending an empty body') do
  rf_serve do |sock, _root|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      path = '/f?n=a.txt'
      block = "\x82\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
      s.write(h2_frame(1, 0x05, 1, block))
      type, _flags, stream, hblock = h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_equal 0x8e, hblock.getbyte(0)
      assert_false hblock.getbyte(0) == 0x88
    end
  end
end

assert('a docroot that is missing or is not a directory refuses startup') do
  base, root = rf_tree
  app = wm_compile(rf_app, 'wm-rfapp')
  begin
    [[File.join(base, 'no-such-dir'), 'No such file'],
     [File.join(root, 'a.txt'), 'is not a directory']].each do |path, want|
      out = IO.popen([WM_BIN, "--unix=/tmp/wm-rf-never-#{$$}.sock", "--app=#{app.path}",
                      "--docroot=#{path}", { err: [:child, :out] }], &:read)
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
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-big-#{$$}-#{rand(1 << 30)}.sock"
  pid = nil
  begin
    pid = spawn(WM_BIN, "--unix=#{sock}", "--app=#{app.path}",
                "--docroot=#{root}", out: File::NULL, err: File::NULL)
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
# those bytes would sit behind them - the client would wait for a remainder
# that never comes. RFC 9112 6.3: close instead. The property asserted here
# is the deterministic one - the request ends - because whether the truncate
# wins the race against the send does not change what must not happen.
assert('response.file that shrinks mid-flight ends the request, never hangs') do
  base, root = rf_tree
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-shrink-#{$$}-#{rand(1 << 30)}.sock"
  path = File.join(root, 'shrink.bin')
  File.binwrite(path, 'S' * (48 << 20))
  pid = nil
  begin
    pid = spawn(WM_BIN, "--unix=#{sock}", "--app=#{app.path}",
                "--docroot=#{root}", out: File::NULL, err: File::NULL)
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
  head << wm_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  got = 0
  last = nil
  begin
    while got < len
      part = wm_recv(s, 1 << 16, 30)
      got += part.bytesize
      last = part.getbyte(-1)
    end
  rescue EOFError, Errno::ECONNRESET
  end
  s.close rescue nil
  [head, len, got, last]
end

# One sendmsg moves at most MAX_RW_COUNT (INT_MAX rounded down to a page,
# 2,147,479,552 here). A body offered past that comes back short, which is
# indistinguishable from a dead peer - the connection used to be dropped
# with the client holding a prefix and a Content-Length it would never
# reach. The mapping is lent in bounded chunks now, so the size stops
# mattering.
assert('response.file serves a file larger than one send can move') do
  base, root = rf_tree
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-huge-#{$$}-#{rand(1 << 30)}.sock"
  size = rf_sparse(File.join(root, 'huge.bin'), 2_200_000_000)
  pid = nil
  begin
    pid = spawn(WM_BIN, "--unix=#{sock}", "--app=#{app.path}",
                "--docroot=#{root}", out: File::NULL, err: File::NULL)
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
# same bytes, a window at a time. What must not happen is the fallback
# asking for the whole file - that allocation threw std::bad_alloc and took
# the process down, every connection on it with one request.
assert('response.file survives an mmap it cannot make, and still serves') do
  base, root = rf_tree
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-nomap-#{$$}-#{rand(1 << 30)}.sock"
  size = rf_sparse(File.join(root, 'huge.bin'), 2_200_000_000)
  pid = nil
  begin
    # An address space too small for the mapping, large enough for the server.
    cmd = "ulimit -v 2000000; exec #{WM_BIN} --unix=#{sock} --app=#{app.path} " \
          "--docroot=#{root}"
    pid = spawn('sh', '-c', cmd, out: File::NULL, err: File::NULL)
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

# RFC 9110: one access line per request. A 4 MB file over the window path
# takes sixteen rounds, and the line used to be written from inside the
# round - sixteen lines for one request, each with a window's byte count.
assert('response.file writes one access line per request, not one per window') do
  base, root = rf_tree
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-log-#{$$}-#{rand(1 << 30)}.sock"
  logf = "/tmp/wm-rf-access-#{$$}-#{rand(1 << 30)}.log"
  File.unlink(logf) if File.exist?(logf)
  n = 4_000_000
  File.binwrite(File.join(root, 'big.bin'), 'B' * n)
  pid = nil
  begin
    pid = spawn(WM_BIN, "--unix=#{sock}", "--app=#{app.path}",
                "--docroot=#{root}", "--log=#{logf}", '--file-map-threshold=0',
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
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-abort-#{$$}-#{rand(1 << 30)}.sock"
  logf = "/tmp/wm-rf-abort-access-#{$$}-#{rand(1 << 30)}.log"
  File.unlink(logf) if File.exist?(logf)
  n = 4_000_000
  File.binwrite(File.join(root, 'big.bin'), 'B' * n)
  pid = nil
  begin
    pid = spawn(WM_BIN, "--unix=#{sock}", "--app=#{app.path}",
                "--docroot=#{root}", "--log=#{logf}", '--file-map-threshold=0',
                out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    s = UNIXSocket.new(sock)
    s.write "GET /f?n=big.bin HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n"
    head = +''.b
    head << wm_recv(s, 1) until head.end_with?("\r\n\r\n")
    wm_recv(s, 4096)
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

# Read a body at a fixed byte rate, the way a throttled mobile link does.
# Returns what the head promised and what actually arrived - a client that
# gets dropped mid-body comes back with the second smaller than the first.
def rf_throttled(sock, name, rate)
  s = UNIXSocket.new(sock)
  s.write "GET /f?n=#{name} HTTP/1.1\r\nHost: rf\r\nConnection: close\r\n\r\n"
  head = +''.b
  head << wm_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  t0 = Time.now
  got = 0
  begin
    while got < len
      wait = t0 + got.to_f / rate - Time.now
      sleep wait if wait > 0
      got += wm_recv(s, 1 << 14, 20).bytesize
    end
  rescue EOFError, Errno::ECONNRESET
  end
  s.close rescue nil
  [head, len, got]
end

# A deadline is refreshed per completed send, so what one send carries decides
# which clients survive: offer the whole body at once and the client must
# drain all of it before the clock that is running - the header clock, until
# the first send completes - runs out. That is why the chunk is derived from
# send_timeout and the slowest rate we serve (16 kbit/s) instead of chosen: a
# 64 MiB chunk picked for MAX_RW_COUNT's sake silently demanded 1.12 MB/s of
# every client, and a phone on a spent monthly allowance gets 32 kbit/s.
# Here both clocks are 3 s, so nothing but the chunking can carry the
# request: 3 s -> 6000 bytes a send, and the 1.5 MB body takes ten seconds
# at the rate this client reads. Offered whole, it dies around 700 KB.
assert('response.file serves a client slower than one send-timeout of body') do
  base, root = rf_tree
  app = wm_compile(rf_app, 'wm-rfapp')
  sock = "/tmp/wm-rf-slow-#{$$}-#{rand(1 << 30)}.sock"
  n = 1_500_000
  File.binwrite(File.join(root, 'slow.bin'), 'S' * n)
  cfg = Tempfile.new(['wm-rf-slow', '.toml'])
  cfg.write("[server]\nunix = \"#{sock}\"\n\n[tune]\n" \
            "header_timeout = 3\nsend_timeout = 3\n")
  cfg.close
  pid = nil
  begin
    pid = spawn(WM_BIN, "--config=#{cfg.path}",
                "--app=#{app.path}", "--docroot=#{root}",
                '--file-map-threshold=65536',
                out: File::NULL, err: File::NULL)
    200.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock)
    head, len, got = rf_throttled(sock, 'slow.bin', 150_000)
    assert_include head, 'HTTP/1.1 200 OK'
    assert_equal n, len
    assert_equal n, got
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app&.unlink
    cfg&.unlink
    File.unlink(sock) rescue nil
    FileUtils.rm_rf(base)
  end
end
