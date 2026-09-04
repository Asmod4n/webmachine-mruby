require 'socket'
require 'tempfile'

WA_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WA_BIN)

def wa_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s"
  s.readpartial(maxlen)
end

def wa_body(app_source)
  src = Tempfile.new(['wm-wa', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-wa', '.mrb'])
  mrb.close
  raise "mrbc failed:\n#{app_source}" unless system(mrbc, '-o', mrb.path, src.path)
  sock = "/tmp/wm-wa-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-wa-err-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WA_BIN, "--unix=#{sock}", "--app=#{mrb.path}",
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    UNIXSocket.open(sock) do |c|
      c.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head = +''
      head << wa_recv(c) until head.end_with?("\r\n\r\n")
      len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
      body = +''
      body << wa_recv(c, len - body.bytesize) while body.bytesize < len
      body
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    src.unlink
    mrb.unlink
  end
end

# #30: a Watcher is a DESCRIPTION - a source, what to wait for, and what
# to do when that happens. Building one arms nothing, so all of this can
# be asked without a reactor being involved at all.
assert('watcher: it describes, and it says no to what it cannot describe') do
  out = wa_body(<<~RUBY)
    class Probe < Webmachine::Resource
      def self.to_html
        r, w = IO.pipe
        lines = []
        begin
          watcher = Webmachine::Watcher.new(r, :r, timeout: 5.0) { |revents, self_| }
          lines << "source:\#{watcher.source.fileno == r.fileno}"
          # events is what was ORDERED. :r is the default.
          lines << "events:\#{watcher.events}"
          watcher.events = :rw
          lines << "changed:\#{watcher.events}"
          # Running on is the default; stopping is the one word.
          lines << "aborted:\#{watcher.aborted?}"
          watcher.abort
          lines << "then:\#{watcher.aborted?}"
          begin
            watcher.events = :sideways
          rescue ArgumentError => e
            lines << "order:\#{e.message}"
          end
          # A bare Integer IS a source - hiredis hands its event
          # callbacks an int and has no object to offer.
          bare = Webmachine::Watcher.new(r.fileno, :r, timeout: 50.ms) { }
          lines << "bare:\#{bare.source}"
          begin
            Webmachine::Watcher.new('not a socket', :r, timeout: 5.0) { }
          rescue TypeError => e
            lines << "source_type:\#{e.message}"
          end
          begin
            Webmachine::Watcher.new(r, :r, timeout: 5.0)
          rescue ArgumentError => e
            lines << "no_block:\#{e.message}"
          end
        ensure
          r.close
          w.close
        end
        lines.join("\\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], Probe }
      end
    end
  RUBY

  assert_true out.include?('source:true'), out
  assert_true out.include?('events:r'), out
  assert_true out.include?('changed:rw'), out
  assert_true out.include?('aborted:false'), out
  assert_true out.include?('then:true'), out
  # The order menu is :r, :w, :rw and nothing else - what ARRIVES is a
  # wider set, which is why the two do not share a name.
  assert_true out.include?('order:a watcher waits for :r, :w or :rw'), out
  # A source is something with a descriptor, refused where the mistake
  # was made rather than somewhere inside the reactor.
  # One conversion covers both shapes: an Integer passes through, anything
  # else is asked for its fileno, and something with none says so itself.
  assert_true out.match?(/^bare:\d+$/), out
  assert_true out.include?("source_type:can't convert String into Integer"), out
  assert_true out.include?('no_block:a watcher without a block'), out
end

# #30: a watcher owes a deadline, the same way a compute task owes
# max_runtime. What the two do at the deadline is where they differ.
assert('watcher: it owes a deadline, and it says so when it gets none') do
  out = wa_body(<<~RUBY)
    class Deadline < Webmachine::Resource
      def self.to_html
        r, w = IO.pipe
        lines = []
        begin
          # mruby-chrono spells a time as Float seconds.
          watcher = Webmachine::Watcher.new(r, :r, timeout: 50.ms) { }
          lines << "timeout:\#{watcher.timeout}"
          begin
            Webmachine::Watcher.new(r, :r) { }
          rescue ArgumentError => e
            lines << "none:\#{e.message}"
          end
          begin
            Webmachine::Watcher.new(r, :r, timeout: 0) { }
          rescue ArgumentError => e
            lines << "zero:\#{e.message}"
          end
          begin
            Webmachine::Watcher.new(r, :r, timeout: -1.0) { }
          rescue ArgumentError => e
            lines << "past:\#{e.message}"
          end
        ensure
          r.close
          w.close
        end
        lines.join("\\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], Deadline }
      end
    end
  RUBY

  assert_true out.include?('timeout:0.05'), out
  assert_true out.include?('none:a watcher wants timeout:'), out
  assert_true out.include?('zero:timeout: 0 is not a time a watcher could wait'), out
  assert_true out.include?('past:timeout: -1.0 is not a time a watcher could wait'), out
end

# #30: the peer said nothing. That is the world, and not a fault of the
# application - so the deadline reaches the block as an event, and the
# block says what happens next.
assert('watcher: the deadline reaches the block, and the block answers it') do
  out = wa_body(<<~RUBY)
    class Quiet < Webmachine::Resource
      def self.to_html
        r, w = IO.pipe
        lines = []
        begin
          seen = []
          waits = 0
          patient = Webmachine::Watcher.new(r, :r, timeout: 50.ms) do |revents, watcher|
            seen << revents
            waits += 1
            watcher.abort if waits == 2
          end
          # A watcher that wants to wait again says nothing, so it waits.
          lines << "again:\#{patient.deadline_passed}"
          lines << "alive:\#{patient.aborted?}"
          # The second deadline makes it give up, and it says so.
          lines << "over:\#{patient.deadline_passed}"
          lines << "aborted:\#{patient.aborted?}"
          lines << "events:\#{seen.join(',')}"
        ensure
          r.close
          w.close
        end
        lines.join("\\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], Quiet }
      end
    end
  RUBY

  # The block gets the event, and true says the run waits again.
  assert_true out.include?('again:true'), out
  assert_true out.include?('alive:false'), out
  # abort inside the block is the one way to give up, and the answer
  # carries it back to the reactor.
  assert_true out.include?('over:false'), out
  assert_true out.include?('aborted:true'), out
  # `:timeout` ARRIVES, and cannot be ordered - so revents and events do
  # not share a menu.
  assert_true out.include?('events:timeout,timeout'), out
end
