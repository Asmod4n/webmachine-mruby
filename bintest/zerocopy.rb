# The lend path on the wire: above [tune] zero_copy_threshold a dynamic
# body is NOT copied into the send buffer - the handler's own String is
# frozen, rooted and handed to the kernel as an external segment, the same
# door the mmap'd asset tier already uses.
#
# Every case here is a BYTE test, because that is the only failure mode
# worth catching: a wrong external pointer is still the right LENGTH, so a
# test that only counted bytes would pass on garbage. The bodies below are
# phase-sensitive (a repeating 10-byte unit with a distinct head and tail),
# so an off-by-one offset in the sink split shows up as a mismatch and not
# as a short read.
#
# The switch itself must be INVISIBLE: the same request answered with the
# threshold at 1 (lend everything), at its default (lend the big body only)
# and at 0 (lend nothing) has to produce identical bytes. That is what the
# cases assert against each other.

require 'socket'
require 'tempfile'

ZC_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(ZC_BIN)

# 200_000 bytes: over the 128 KiB default, so the default configuration
# lends it and no flag is needed to reach the new path.
ZC_BIG = ('START' + ('abcdefghij' * 19_999) + 'ENDEND').freeze
# 4_000 bytes: under every threshold this file sets except 1.
ZC_SMALL = ('S4K' + ('zyxwvutsrq' * 399) + 'E4K4').freeze

def zc_recv(s, maxlen = 65_536, deadline = 10)
  IO.select([s], nil, nil, deadline) or
    raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def zc_app
  <<~RUBY
    class ZcBig < Webmachine::Resource
      def to_html
        'START' + ('abcdefghij' * 19_999) + 'ENDEND'
      end
    end
    class ZcSmall < Webmachine::Resource
      def to_html
        'S4K' + ('zyxwvutsrq' * 399) + 'E4K4'
      end
    end
    # A body the app KEPT: already frozen, so it may be shared, so it is
    # copied however high the threshold says to lend.
    ZC_KEPT = ('START' + ('abcdefghij' * 19_999) + 'ENDEND').freeze
    class ZcFrozen < Webmachine::Resource
      def to_html
        ZC_KEPT
      end
    end
    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['big'], ZcBig
          route.add ['small'], ZcSmall
          route.add ['kept'], ZcFrozen
        end
      end
    end
  RUBY
end

def zc_compile(source)
  src = Tempfile.new(['wm-zcapp', '.rb'])
  src.write(source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-zcapp', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile the zero-copy fixture" unless ok
  mrb
ensure
  src&.unlink
end

# head + exactly Content-Length body, to a deadline: a wedged server fails
# the test instead of hanging the suite.
def zc_read(s)
  head = +''.b
  head << zc_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''.b
  body << zc_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

def zc_serve(threshold = nil)
  sock = "/tmp/wm-zc-#{$$}-#{threshold.inspect.gsub(/\W/, '')}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-zc-stderr-#{$$}.log"
  app = zc_compile(zc_app)
  args = [ZC_BIN, '--unix', sock, '--app', app.path]
  args += ['--zero-copy-threshold', threshold.to_s] unless threshold.nil?
  pid = spawn({ 'WM_BUNDLE' => '0' }, *args, out: File::NULL, err: err)
  200.times do
    break if File.socket?(sock)
    sleep 0.05
  end
  unless File.socket?(sock)
    raise "server never came up:\n#{begin File.read(err) rescue '' end}"
  end
  yield sock
ensure
  Process.kill(:TERM, pid) rescue nil
  Process.waitpid(pid) rescue nil
  app&.unlink
  File.unlink(sock) rescue nil
end

def zc_get(sock, target)
  s = UNIXSocket.new(sock)
  s.write "GET #{target} HTTP/1.1\r\nHost: zc\r\nConnection: close\r\n\r\n"
  head, body = zc_read(s)
  s.close
  [head, body]
end

assert('zero-copy: a lent body is byte-identical to a copied one') do
  lent = nil
  copied = nil
  zc_serve(1) { |sock| lent = zc_get(sock, '/big') }
  zc_serve(0) { |sock| copied = zc_get(sock, '/big') }
  assert_include lent[0], '200 OK'
  assert_include copied[0], '200 OK'
  assert_equal ZC_BIG.bytesize, lent[1].bytesize
  assert_equal ZC_BIG, lent[1]
  assert_equal copied[1], lent[1]
  assert_include lent[0], "Content-Length: #{ZC_BIG.bytesize}\r\n"
end

assert('zero-copy: the built-in default lends the big body and copies the small') do
  zc_serve do |sock|
    big = zc_get(sock, '/big')
    small = zc_get(sock, '/small')
    assert_equal ZC_BIG, big[1]
    assert_equal ZC_SMALL, small[1]
  end
end

assert('zero-copy: keep-alive releases between rounds') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    8.times do
      s.write "GET /big HTTP/1.1\r\nHost: zc\r\n\r\n"
      head, body = zc_read(s)
      assert_include head, '200 OK'
      assert_equal ZC_BIG, body
    end
    s.close
    true
  end
end

assert('zero-copy: a lent body splits a pipelined round correctly') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    # Three answers out of ONE plan: only the first may be lent, the two
    # behind it are copied into the sink AFTER the external segment, which
    # is exactly the ordering the sink split has to get right.
    s.write "GET /big HTTP/1.1\r\nHost: zc\r\n\r\n" \
            "GET /small HTTP/1.1\r\nHost: zc\r\n\r\n" \
            "GET /big HTTP/1.1\r\nHost: zc\r\n\r\n"
    h1, b1 = zc_read(s)
    h2, b2 = zc_read(s)
    h3, b3 = zc_read(s)
    s.close
    assert_include h1, '200 OK'
    assert_include h2, '200 OK'
    assert_include h3, '200 OK'
    assert_equal ZC_BIG, b1
    assert_equal ZC_SMALL, b2
    assert_equal ZC_BIG, b3
  end
end

assert('zero-copy: HEAD spells the length and lends nothing') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    s.write "HEAD /big HTTP/1.1\r\nHost: zc\r\nConnection: close\r\n\r\n"
    head = +''.b
    head << zc_recv(s, 1) until head.end_with?("\r\n\r\n")
    rest = begin
      s.read_nonblock(4096)
    rescue StandardError
      ''
    end
    s.close
    assert_include head, '200 OK'
    assert_include head, "Content-Length: #{ZC_BIG.bytesize}\r\n"
    assert_equal '', rest.to_s
  end
end

assert('zero-copy: a String the app froze is copied, not lent') do
  zc_serve(1) do |sock|
    # Twice, on one connection: if the freeze had been lifted on release
    # the second answer would be serving a String nothing roots any more.
    s = UNIXSocket.new(sock)
    2.times do
      s.write "GET /kept HTTP/1.1\r\nHost: zc\r\n\r\n"
      head, body = zc_read(s)
      assert_include head, '200 OK'
      assert_equal ZC_BIG, body
    end
    s.close
    true
  end
end

assert('zero-copy: [tune] zero_copy_threshold is read from the config file') do
  sock = "/tmp/wm-zc-toml-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  app = zc_compile(zc_app)
  cfg = Tempfile.new(['wm-zc', '.toml'])
  cfg.write("[server]\nunix = \"#{sock}\"\napp = \"#{app.path}\"\n\n" \
            "[tune]\nzero_copy_threshold = 1024\n")
  cfg.close
  err = "/tmp/wm-zc-toml-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, ZC_BIN, '--config', cfg.path,
              out: File::NULL, err: err)
  begin
    200.times do
      break if File.socket?(sock)
      sleep 0.05
    end
    unless File.socket?(sock)
      raise "server never came up:\n#{begin File.read(err) rescue '' end}"
    end
    head, body = zc_get(sock, '/small')
    assert_include head, '200 OK'
    assert_equal ZC_SMALL, body
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app.unlink
    cfg.unlink
    File.unlink(sock) rescue nil
  end
end

assert('zero-copy: a threshold outside the range refuses the start') do
  err = "/tmp/wm-zc-bad-#{$$}.log"
  cfg = Tempfile.new(['wm-zcbad', '.toml'])
  cfg.write("[server]\nunix = \"/tmp/wm-zc-never-#{$$}.sock\"\n\n" \
            "[tune]\nzero_copy_threshold = -1\n")
  cfg.close
  pid = spawn({ 'WM_BUNDLE' => '0' }, ZC_BIN, '--config', cfg.path,
              out: File::NULL, err: err)
  Process.waitpid(pid)
  ok = $?.exitstatus == 2
  assert_true ok
  assert_include File.read(err), 'zero_copy_threshold'
ensure
  cfg&.unlink
  File.unlink(err) rescue nil
end
