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
