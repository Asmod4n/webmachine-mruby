require 'socket'
require 'tempfile'

# #30: the watcher against a REAL foreign descriptor.
#
# libpq is the case the design was written against. It says what to wait
# for and it changes its mind in the middle of one wait: writable while
# it flushes, readable while it reads, and during the handshake it
# answers :reading or :writing per poll. A watcher that could not follow
# that would be a watcher no database could use.
#
# This needs two things the machine may not have: a libpq to link (the
# debug build adds mruby-postgresql only when pkg-config knows one) and
# a server to talk to. Both are asked for by name and the case skips
# when either is missing - a test that lies about what it ran is worse
# than one that says it did not run.
WPQ_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WPQ_BIN)
WPQ_URL = ENV['WM_PG_URL'] || 'postgresql://127.0.0.1:5432/postgres?user=postgres'

def wpq_server_there?(url)
  host = url[%r{//([^:/?]+)}, 1] || '127.0.0.1'
  port = (url[%r{//[^:/?]+:(\d+)}, 1] || '5432').to_i
  TCPSocket.new(host, port).close
  true
rescue StandardError
  false
end

def wpq_answer(app_source)
  src = Tempfile.new(['wm-wpq', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-wpq', '.mrb'])
  mrb.close
  raise "mrbc failed:\n#{app_source}" unless system(mrbc, '-o', mrb.path, src.path)
  sock = "/tmp/wm-wpq-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-wpq-err-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WPQ_BIN, "--unix=#{sock}", "--app=#{mrb.path}",
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    UNIXSocket.open(sock) do |c|
      c.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head = +''
      loop do
        IO.select([c], nil, nil, 15) or raise "no answer in 15s\n#{File.read(err) rescue ''}"
        head << c.readpartial(1)
        break if head.end_with?("\r\n\r\n")
      end
      len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
      body = +''
      while body.bytesize < len
        IO.select([c], nil, nil, 15) or raise 'body stalled'
        body << c.readpartial(len - body.bytesize)
      end
      [head, body]
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    src.unlink
    mrb.unlink
  end
end

assert('watcher: libpq drives a run, and it changes what it waits for mid-wait (#30)') do
  skip 'this build has no libpq' unless system('pkg-config --exists libpq >/dev/null 2>&1')
  skip "no PostgreSQL at #{WPQ_URL}" unless wpq_server_there?(WPQ_URL)

  _, body = wpq_answer(<<~RUBY)
    class PqAnswer < Webmachine::Resource
      def self.to_html
        conn = Pq.connect_start(#{WPQ_URL.inspect})
        stage = :connect
        rows = nil
        seen = []
        # The mask starts at :w because PQconnectStart wants to write
        # first. After that libpq says what it wants, every time.
        Webmachine::Watcher.new(conn.socket, :w, timeout: 5.s) do |ready, w|
          seen << stage
          case stage
          when :connect
            case conn.connect_poll
            when :ok
              conn.nonblocking = true
              conn.send_query('select 42')
              stage = :flush
              w.events = :w
            when :failed
              w.abort
              "failed:\#{conn.error_message}"
            when :reading then w.events = :r
            when :writing then w.events = :w
            end
          when :flush
            # 0 = everything is on the socket. Anything else means the
            # kernel took some and wants the rest later.
            if conn.flush == 0
              stage = :read
              w.events = :r
            else
              w.events = :w
            end
          else
            conn.consume_input
            unless conn.busy?
              res = conn.get_result
              if res.nil?
                # nil = every result is drained. THAT is the end, not the
                # first row - a multi-statement query answers twice.
                w.abort
                "rows:\#{rows.inspect} stages:\#{seen.uniq.join(',')}"
              else
                rows = res.to_ary
              end
            end
          end
        end
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], PqAnswer }
      end
    end
  RUBY

  # The row libpq brought back through the watcher.
  assert_true body.include?('rows:[[42]]'), body
  # And the wait really did pass through all three stages, which is what
  # says the mask changed twice while the poll was live.
  assert_true body.include?('stages:connect,flush,read'), body
end
