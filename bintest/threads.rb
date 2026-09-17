# --threads=N: N threads answer, each with its own ring and its own VM,
# and the thread that takes the peers is one of them. What is proven
# here is what an operator can see: the answers are right whichever
# thread gives them, a route with a callback runs in the thread's own
# VM, and a compute task and a watcher work from there.
require 'socket'
require 'fileutils'

def w_ask(sock_path, target)
  wm_conn(sock_path) do |s|
    s.write("GET #{target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    wm_read(s)
  end
end

# --threads=N: the thread that takes the peers gives each one to the
# next ring in turn and keeps every Nth for itself. IORING_OP_MSG_RING
# carries the registered descriptor between two rings, which is the
# only way a direct descriptor moves at all.
def t_server(threads, &block)
  root = "/tmp/wm-threads-#{$$}"
  FileUtils.mkdir_p(root)
  File.binwrite(File.join(root, 'index.html'), "thread page\n")
  wm_server("--docroot=#{root}", "--threads=#{threads}", app: false,
            tag: 'wm-threads', &block)
ensure
  FileUtils.rm_rf(root)
end

assert('threads: every answering thread answers what it is given') do
  t_server(3) do |sock|
    12.times do
      head, body = w_ask(sock, '/')
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal "thread page\n", body
    end
  end
end

# What is not tested here: that the peers spread over the answering
# threads. The only instrument that was available for it was
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
# what it is given.

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

assert('threads: a route with a callback is answered in the thread\'s own VM') do
  src = <<~'RUBY'
    class MyResource < Webmachine::Resource
      def to_html
        "callback page for #{request.path}"
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['x'], MyResource
          route.add ['y'], MyResource
        end
      end
    end
  RUBY
  wm_server(src, '--threads=3', tag: 'wm-threads-callback') do |sock|
    6.times do |i|
      path = i.even? ? '/x' : '/y'
      head, body = w_ask(sock, path)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal "callback page for #{path}", body
    end
  end
end

assert('threads: a compute task is answered to the thread that asked') do
  src = <<~'RUBY'
    class MyResource < Webmachine::Resource
      compute :is_authorized?
      def is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { true }
      end
      def to_html
        'answered by a worker'
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
  wm_server(src, '--threads=3', tag: 'wm-threads-compute') do |sock|
    6.times do
      head, body = w_ask(sock, '/x')
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal 'answered by a worker', body
    end
  end
end

# A TCP peer goes round the answering threads like a unix peer does.
# This case proves that every answer over TCP is a whole one.
assert('threads: a TCP peer is answered whichever thread takes it') do
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
  # A kernel without SOCKET_URING_OP_GETSOCKNAME makes the server say so
  # once and hand the peers out in turn. That is the answer the case
  # above proves, so the line is allowed here and not asserted either way.
ensure
  Process.kill('TERM', pid) rescue nil
  Process.wait(pid) rescue nil
  FileUtils.rm_rf(root)
  File.unlink(err) rescue nil
end

# A watcher polls on the ring of the thread that answers, so a run that
# waits on a descriptor waits there and resumes there.
assert('threads: a watcher waits and resumes on the thread that answers') do
  src = <<~'RUBY'
    class Quiet < Webmachine::Resource
      def self.to_html
        r, w = IO.pipe
        lines = []
        begin
          waits = 0
          patient = Webmachine::Watcher.new(r, :r, timeout: 50.ms) do |_revents, watcher|
            waits += 1
            watcher.abort if waits == 2
          end
          lines << "again:#{patient.deadline_passed}"
          lines << "over:#{patient.deadline_passed}"
          lines << "aborted:#{patient.aborted?}"
        ensure
          r.close
          w.close
        end
        lines.join("\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], Quiet }
      end
    end
  RUBY
  wm_server(src, '--threads=3', tag: 'wm-threads-watch') do |sock|
    6.times do
      head, body = w_ask(sock, '/')
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal "again:true\nover:false\naborted:true", body
    end
  end
end
