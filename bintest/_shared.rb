# The helpers every bintest file shares. The runner loads bintest/**/*.rb
# in glob order, and the underscore sorts this file first. Each definition
# is guarded so a second load does not redefine it.
#
# One server, one connection, one request, one answer:
#
#   wm_server(app_source, *args) { |sock, pid, err, out| }
#   wm_conn(sock) { |s| }
#   wm_request(s, target, headers = {}, method: 'GET', body: nil, close: false)
#   wm_read(s)   -> [head, body]
#
# And for h2: h2_handshake, h2_stream and h2_collect.
require 'socket'
require 'tempfile'

WM_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WM_BIN)
WM_H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b unless defined?(WM_H2_PREFACE)

unless defined?(wm_compile)
  # Compiles an app source with mrbc -g. Returns the closed Tempfile that
  # holds the .mrb; the caller unlinks it.
  def wm_compile(app_source, tag = 'wm-app')
    src = Tempfile.new([tag, '.rb'])
    src.write(app_source)
    src.close
    mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
    mrb = Tempfile.new([tag, '.mrb'])
    mrb.close
    ok = system(mrbc, '-g', '-o', mrb.path, src.path)
    raise "mrbc failed to compile:\n#{app_source}" unless ok
    mrb
  ensure
    src&.unlink
  end
end

unless defined?(wm_await_socket)
  # Waits for a unix socket path to appear. Raises with the stderr log
  # when it does not.
  def wm_await_socket(sock, err, tries = 100)
    tries.times { break if File.socket?(sock); sleep 0.05 }
    return if File.socket?(sock)
    raise "server never came up:\n#{File.read(err) rescue ''}"
  end
end

unless defined?(wm_server)
  # Spawns one server on a unix socket and yields until the block ends.
  #
  # app_source is the Ruby source of the app. The helper compiles it and
  # passes --app. With `app: false` there is no app, and app_source is
  # the first extra flag instead:
  #
  #   wm_server(src, '--error-log=/tmp/x.log') { |sock| }
  #   wm_server('--standalone', "--assets=#{zip}", app: false) { |sock| }
  #
  # Keywords: `bin` names another binary, `env` adds environment
  # variables, `sock` names the socket path, `tag` names the log files.
  # The block gets the socket path, the pid, and the stderr and stdout
  # log paths. The helper kills the pid, waits, and unlinks the socket.
  def wm_server(app_source = nil, *args, app: true, bin: WM_BIN, env: {},
                sock: nil, tag: 'wm')
    sock ||= "/tmp/#{tag}-#{$$}.sock"
    mrb = nil
    if app
      # An application names its own listener; the command line names
      # none for it.
      mrb = wm_compile(wm_listen(app_source, sock), "#{tag}-app")
      args = ["--app=#{mrb.path}", *args]
    else
      args = [app_source, *args].compact
      args = ["--unix=#{sock}", *args]
    end
    File.unlink(sock) if File.exist?(sock)
    err = "/tmp/#{tag}-stderr-#{$$}.log"
    out = "/tmp/#{tag}-stdout-#{$$}.log"
    pid = spawn(env, bin, *args, out: out, err: err)
    begin
      wm_await_socket(sock, err)
      yield sock, pid, err, out
    ensure
      Process.kill('TERM', pid) rescue nil
      Process.wait(pid) rescue nil
      File.unlink(sock) rescue nil
      mrb&.unlink
    end
  end
end

unless defined?(wm_listen)
  # The application source with its listener named: a unix socket, or a
  # TCP port. A source that already names one keeps its shape and gets
  # the new value; one that names none gets the line after
  # `Application.new do |app|`.
  def wm_listen(app_source, sock = nil, port: nil)
    line = port ? "conf.port = #{port}" : "conf.unix_path = #{sock.inspect}"
    src = app_source.dup
    if src =~ /^\s*(app\.)?conf\.(port|unix_path) = /
      return src.sub(/^(\s*)(app\.)?conf\.(port|unix_path) = .*$/) { "#{$1}#{$2}#{line}" }
    end
    src.sub(/^(\s*)Webmachine::Application\.new do \|app\|\n/) { "#{$&}#{$1}  app.#{line}\n" }
  end
end

unless defined?(wm_conn)
  # One connection to the server, closed when the block ends.
  def wm_conn(sock, &block)
    UNIXSocket.open(sock, &block)
  end
end

unless defined?(wm_request)
  # Writes one HTTP/1.1 request. The connection stays open unless the
  # caller asks for `close: true`.
  def wm_request(s, target, headers = {}, method: 'GET', body: nil, close: false)
    req = +"#{method} #{target} HTTP/1.1\r\nHost: x\r\n"
    req << "Connection: close\r\n" if close
    headers.each { |k, v| req << "#{k}: #{v}\r\n" }
    req << "Content-Length: #{body.bytesize}\r\n" if body
    req << "\r\n"
    req << body if body
    s.write(req)
  end
end

unless defined?(wm_recv)
  # Reads up to maxlen bytes, or raises when nothing arrives in time.
  def wm_recv(s, maxlen = 1, deadline = 10)
    IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
    s.readpartial(maxlen)
  end
end

unless defined?(wm_read)
  # Reads one response: the head, then as many bytes as Content-Length
  # says. Returns [head, body]. `body: false` reads the head alone, for
  # an answer to HEAD, which spells a length and sends no body.
  def wm_read(s, body: true)
    head = +''.b
    head << wm_recv(s) until head.end_with?("\r\n\r\n")
    len = body ? head[/^Content-Length: *(\d+)\r$/i, 1].to_i : 0
    body = +''.b
    body << wm_recv(s, len - body.bytesize) while body.bytesize < len
    [head, body]
  end
end

unless defined?(wm_read_until_eof)
  # Reads everything until the server closes the connection.
  def wm_read_until_eof(s, deadline = 10)
    out = +''.b
    loop do
      out << wm_recv(s, 65_536, deadline)
    rescue EOFError
      break
    end
    out
  end
end

unless defined?(h2_read_exact)
  def h2_read_exact(s, n)
    buf = +''.b
    buf << wm_recv(s, n - buf.bytesize) while buf.bytesize < n
    buf
  end
end

unless defined?(h2_frame)
  def h2_frame(type, flags, stream, payload = ''.b)
    len = payload.bytesize
    [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
      [stream].pack('N') + payload
  end
end

unless defined?(h2_next)
  # Reads one frame. Returns [type, flags, stream, payload].
  def h2_next(s)
    h = h2_read_exact(s, 9)
    len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
    payload = len > 0 ? h2_read_exact(s, len) : ''.b
    [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fffffff, payload]
  end
end

unless defined?(h2_handshake)
  # Sends the preface and the client SETTINGS, then reads the server
  # SETTINGS and the ACK.
  def h2_handshake(s, settings = ''.b)
    s.write(WM_H2_PREFACE + h2_frame(4, 0, 0, settings))
    t, f, st, = h2_next(s)
    raise "expected server SETTINGS, got type #{t}" unless t == 4 && f == 0 && st == 0
    t, f, = h2_next(s)
    raise "expected SETTINGS ACK, got type #{t}/#{f}" unless t == 4 && f == 1
  end
end

unless defined?(h2_stream)
  # Sends one request on a stream: HEADERS with the block, then DATA when
  # there is a body. Both end the stream.
  def h2_stream(s, id, block, body: nil)
    s.write(h2_frame(1, body ? 0x04 : 0x05, id, block))
    s.write(h2_frame(0, 0x01, id, body)) if body
  end
end

unless defined?(h2_collect)
  # Reads frames until END_STREAM arrives on the stream. Returns every
  # frame read, as [type, flags, stream, payload], on any stream.
  def h2_collect(s, id)
    frames = []
    loop do
      frame = h2_next(s)
      frames << frame
      type, flags, stream, = frame
      break if stream == id && (type == 0 || type == 1) && (flags & 0x01) != 0
    end
    frames
  end
end
