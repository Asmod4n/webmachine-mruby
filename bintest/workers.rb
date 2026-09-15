# --workers=N: one process binds and listens, forks N children, and every
# child answers on the listener it inherited. What is proven here is what
# an operator can see: the answers are right whichever child gives them,
# stdout names the server once and not once per child, and the way out
# takes every child and the socket with it.
require 'socket'
require 'fileutils'

def w_ask(sock_path, target)
  wm_conn(sock_path) do |s|
    s.write("GET #{target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    wm_read(s)
  end
end

def w_server(workers, &block)
  root = "/tmp/wm-workers-#{$$}"
  FileUtils.mkdir_p(root)
  File.binwrite(File.join(root, 'index.html'), "worker page\n")
  wm_server("--docroot=#{root}", "--workers=#{workers}", app: false,
            tag: 'wm-workers', &block)
ensure
  FileUtils.rm_rf(root)
end

assert('workers: every child answers on the listener it inherited') do
  w_server(3) do |sock|
    # More requests than children, each on its own connection, so the
    # kernel hands them out as it likes and every answer still has to be
    # a whole one.
    12.times do
      head, body = w_ask(sock, '/')
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal "worker page\n", body
    end
  end
end

assert('workers: the server says where it answers once, not once per child') do
  w_server(3) do |sock, _pid, _err, out|
    lines = File.read(out).lines.grep(%r{^http://localhost/})
    assert_equal 1, lines.size, File.read(out)
    assert_true lines[0].include?(sock), lines[0]
  end
end

assert('workers: the supervisor holds the children, and no child holds the port') do
  w_server(2) do |_sock, pid|
    children = `pgrep -P #{pid}`.split.map(&:to_i)
    assert_equal 2, children.size
    # The supervisor answers nothing: it closed the listening descriptor
    # after the fork, so only its children have one open.
    open_by_children = children.count do |kid|
      Dir.glob("/proc/#{kid}/fd/*").any? { |fd| (File.readlink(fd) rescue '') =~ /socket:/ }
    end
    assert_equal 2, open_by_children
  end
end

# --threads=N: one thread accepts and hands every peer to the next of N
# answering threads, each with its own ring. IORING_OP_MSG_RING carries
# the registered descriptor between the two rings, which is the only way
# a direct descriptor moves at all.
def t_server(threads, &block)
  root = "/tmp/wm-threads-#{$$}"
  FileUtils.mkdir_p(root)
  File.binwrite(File.join(root, 'index.html'), "thread page\n")
  wm_server("--docroot=#{root}", "--threads=#{threads}", app: false,
            tag: 'wm-threads', &block)
ensure
  FileUtils.rm_rf(root)
end

assert('threads: every answering thread answers what the acceptor sends it') do
  t_server(3) do |sock|
    12.times do
      head, body = w_ask(sock, '/')
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal "thread page\n", body
    end
  end
end

# What is not tested here: that the acceptor spreads the peers over the
# answering threads. The only instrument that was available for it was
# utime plus stime out of /proc, which counts in clock ticks of 10ms,
# and a run of small answers costs less than one tick per thread - so
# the test read zero everywhere and called that a failure to spread.
#
# Output would say it and time cannot, but no output of this server
# names the thread that made it: there is no thread number in the access
# log, none in the answer, and /proc/<tid>/io stays at zero because an
# io_uring send never goes through the path that counts wchar. Naming
# the thread is operator-visible surface, and it is not added for a
# test. The case below still proves that every answering thread answers
# what the acceptor sends it.

assert('threads: a konst application is answered by the threads') do
  src = <<~'RUBY'
    class MyResource < Webmachine::Resource
      def self.to_html
        'konst page'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['x'], MyResource
        end
      end
    end
  RUBY
  wm_server(src, '--threads=2', tag: 'wm-threads-konst') do |sock|
    6.times do
      head, body = w_ask(sock, '/x')
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal 'konst page', body
    end
  end
end

assert('threads: a route with a callback refuses the thread shape by name') do
  mrb = wm_compile(<<~'RUBY', 'wm-threads-refuse')
    class MyResource < Webmachine::Resource
      def to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure do |conf|
          conf.port = 8080
        end
        app.routes do |route|
          route.add ['x'], MyResource
        end
      end
    end
  RUBY
  out = "/tmp/wm-threads-refuse-#{$$}.log"
  pid = spawn(WM_BIN, "--app=#{mrb.path}", '--threads=2', out: File::NULL, err: out)
  Process.wait(pid)
  said = File.read(out)
  assert_false $?.success?, said
  assert_true said.include?('konst routes only'), said
ensure
  File.unlink(out) rescue nil
  mrb&.unlink
end

# A TCP peer is handed to the thread its address names, so the acceptor
# asks the kernel for the peer's address first. This case proves that the
# ask completes and every answer over TCP is a whole one.
assert('threads: a TCP peer is answered after its address was read') do
  root = "/tmp/wm-threads-tcp-#{$$}"
  FileUtils.mkdir_p(root)
  File.binwrite(File.join(root, 'index.html'), "tcp thread page\n")
  port = 20_000 + ($$ % 20_000)
  err = "/tmp/wm-threads-tcp-stderr-#{$$}.log"
  pid = spawn(WM_BIN, "--docroot=#{root}", "--port=#{port}", '--threads=3',
              out: File::NULL, err: err)
  up = false
  100.times do
    begin
      TCPSocket.new('127.0.0.1', port).close
      up = true
      break
    rescue SystemCallError
      sleep 0.05
    end
  end
  assert_true up, File.read(err)
  12.times do
    s = TCPSocket.new('127.0.0.1', port)
    s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    head, body = wm_read(s)
    s.close
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_equal "tcp thread page\n", body
  end
  said = File.read(err)
  assert_false said.include?('peer address cannot be read'), said
ensure
  Process.kill('TERM', pid) rescue nil
  Process.wait(pid) rescue nil
  FileUtils.rm_rf(root)
  File.unlink(err) rescue nil
end
