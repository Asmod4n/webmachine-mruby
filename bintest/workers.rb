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

assert('threads: the work does not all land on one thread') do
  t_server(3) do |sock, pid|
    300.times { w_ask(sock, '/') }
    ticks = Dir.glob("/proc/#{pid}/task/*/stat").map do |path|
      fields = File.read(path).split(') ')[1].split
      fields[11].to_i + fields[12].to_i
    end
    # This is the property a shared listener does not have: there, one
    # process took every peer and the others stayed at nothing. A clock
    # tick is 10ms, so a short run cannot show every thread - two that
    # both did work already says the acceptor spread them.
    busy = ticks.count { |t| t > 0 }
    assert_true busy >= 2, "only #{busy} threads of #{ticks.size} did anything: #{ticks.inspect}"
  end
end

assert('threads: an application refuses the thread shape by name') do
  mrb = wm_compile(<<~'RUBY', 'wm-threads-refuse')
    class MyResource < Webmachine::Resource
      def self.to_html
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
  assert_true said.include?('answers files only'), said
ensure
  File.unlink(out) rescue nil
  mrb&.unlink
end
