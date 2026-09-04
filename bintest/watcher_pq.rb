require 'socket'
require 'tempfile'

# #30: the watcher against a REAL foreign descriptor.
#
# libpq is the case the design was written against. It says what to wait
# for and it changes its mind in the middle of one wait: the handshake
# answers :reading or :writing per poll, then the query wants writable
# while it flushes and readable while it reads. A watcher that could not
# follow that would be a watcher no database could use.
#
# This needs two things a machine may not have: a libpq to link (the
# debug build adds mruby-postgresql only when pkg-config knows one) and a
# server to talk to. Both are asked for by name, and the case skips when
# either is missing - a test that lies about what it ran is worse than
# one that says it did not run.
WPQ_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WPQ_BIN)
WPQ_URL = ENV['WM_PG_URL'] || 'postgresql://127.0.0.1:5432/postgres?user=postgres' unless defined?(WPQ_URL)

def wpq_server_there?(url)
  host = url[%r{//([^:/?]+)}, 1] || '127.0.0.1'
  port = (url[%r{//[^:/?]+:(\d+)}, 1] || '5432').to_i
  TCPSocket.new(host, port).close
  true
rescue StandardError
  false
end

def wpq_head(app_source)
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
      c.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic eA==\r\n\r\n")
      head = +''
      until head.end_with?("\r\n\r\n")
        IO.select([c], nil, nil, 15) or raise "no answer in 15s\n#{File.read(err) rescue ''}"
        head << c.readpartial(1)
      end
      head
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    src.unlink
    mrb.unlink
  end
end

assert('watcher: libpq drives a stopped run, and changes what it waits for mid-wait (#30)') do
  skip 'this build has no libpq' unless system('pkg-config --exists libpq >/dev/null 2>&1')
  skip "no PostgreSQL at #{WPQ_URL}" unless wpq_server_there?(WPQ_URL)

  head = wpq_head(<<~RUBY)
    class PqWatch < Webmachine::Resource
      watch :is_authorized?

      def self.is_authorized?(_header)
        conn = Pq.connect_start(#{WPQ_URL.inspect})
        # The loop libpq documents asks FIRST and waits second. A watcher
        # waits first, so the first answer is taken here and it decides
        # what the watcher starts out waiting for.
        first = conn.connect_poll
        stage = :connect
        rows = nil
        seen = [first]
        Webmachine::Watcher.new(conn.socket, first == :reading ? :r : :w, timeout: 5.s) do |ready, w|
          if ready == :timeout
            w.abort
            "timeout stage=\#{stage} states=\#{seen.join(',')}"
          elsif stage == :connect
            st = conn.connect_poll
            seen << st
            case st
            when :ok
              conn.nonblocking = true
              conn.send_query('select 42')
              stage = :flush
              w.events = :w
            when :failed
              w.abort
              "failed=\#{conn.error_message}"
            when :reading then w.events = :r
            else w.events = :w
            end
          elsif stage == :flush
            # 0 = the query is on the socket. Anything else means the
            # kernel took some of it and wants the rest later.
            if conn.flush == 0
              stage = :read
              w.events = :r
            else
              w.events = :w
            end
          else
            conn.consume_input
            unless conn.busy?
              # PQgetResult answers until it answers nil, and the ones
              # after the first come out of libpq's own buffer - waiting
              # for the socket again would wait forever.
              while (res = conn.get_result)
                rows = res.to_ary
              end
              w.abort
              # RFC 9110 11.6.1: a String from is_authorized? IS the
              # challenge, so the row reaches the wire in a header. That
              # is what makes this test read the value the run answered.
              "rows=\#{rows.inspect} states=\#{seen.join(',')}"
            end
          end
        end
      end

      def to_html
        'answered'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], PqWatch }
      end
    end
  RUBY

  challenge = head[/^WWW-Authenticate: (.*)\r$/, 1].to_s
  # The row the database sent, carried back through the watcher into the
  # flow and out onto the wire.
  assert_true challenge.include?('rows=[[42]]'), head
  # And the handshake really did change what it waited for, twice.
  assert_true challenge.include?('states=writing,reading,writing,reading,ok'), head
end
