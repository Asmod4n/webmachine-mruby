require 'socket'
require 'tempfile'

def wa_body(app_source)
  wa_exchange(app_source)[1]
end

# The same, and the head as well - a value round writes ETag and
# Last-Modified, and only the head shows them.
# One server, `times` requests on it, each on its own connection. The
# answer is the last one, and a block sees every one.
def wa_exchange(app_source, times: 1)
  wm_server(app_source, tag: 'wm-wa') do |sock|
    last = nil
    times.times do
      wm_conn(sock) do |c|
        wm_request(c, '/')
        head, body = wm_read(c)
        last = [head, body]
        yield head, body if block_given?
      end
    end
    last
  end
end

# The same server, `times` requests on one connection. The block sees
# the request number, from one, with each answer.
def wa_same_connection(app_source, times: 1)
  wm_server(app_source, tag: 'wm-wa') do |sock|
    wm_conn(sock) do |c|
      1.upto(times) do |n|
        wm_request(c, '/')
        head, body = wm_read(c)
        yield n, head, body
      end
    end
  end
end

# #30: a Watcher is a description - a source, what to wait for, and what
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
          # events is what was ordered. :r is the default.
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
          # A bare Integer is a source - hiredis hands its event
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
  # The order menu is :r, :w, :rw and nothing else - what arrives is a
  # wider set, which is why the two do not share a name.
  assert_true out.include?('order:a watcher waits for :r (:in), :w (:out) or :rw (:inout)'), out
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
  # `:timeout` arrives, and cannot be ordered - so revents and events do
  # not share a menu.
  assert_true out.include?('events:timeout,timeout'), out
end

# A raise inside the block is the run's raise: a 500 that names it, and
# the server goes on. It never unwinds through the reactor.
assert('watcher: a block that raises answers 500 with its message, and the server lives') do
  src = <<~RUBY_SRC
    class BlockRaises < Webmachine::Resource
      watch :generate_etag
      def generate_etag
        r, w = IO.pipe
        w.write('x')
        Webmachine::Watcher.new(r, :r, timeout: 2.s) { |_ev, _w| raise 'inside the block' }
      end
      def to_html
        'never'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], BlockRaises }
      end
    end
  RUBY_SRC
  wa_exchange(src, times: 2) do |head, body|
    assert_true head.start_with?('HTTP/1.1 500'), head
    assert_true body.include?('inside the block'), body
  end
end

# #30: the second request on a route is asked its watched value too.
assert('watcher: a watched value is asked on every request (#30)') do
  src = <<~RUBY_SRC
    class WatchEveryTime < Webmachine::Resource
      watch :generate_etag
      def generate_etag
        r, w = IO.pipe
        w.write('e')
        Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_ev, self_|
          r.read(1)
          self_.abort
          'watched-every-time'
        end
      end
      def to_html
        'body'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], WatchEveryTime }
      end
    end
  RUBY_SRC
  wa_exchange(src, times: 3) do |head, body|
    assert_equal 'body', body
    assert_true head.include?('ETag: "watched-every-time"'), head
  end
end

# #30: a round waits on several descriptors at once. Two watchers, two
# pipes, and the run stops once for both.
assert('watcher: a round waits on two watchers at one stop (#30)') do
  head, body = wa_exchange(<<~RUBY_SRC)
    class TwoWatchers < Webmachine::Resource
      watch :generate_etag, :last_modified
      def generate_etag
        r, w = IO.pipe
        w.write('e')
        Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_ev, self_|
          r.read(1)
          self_.abort
          'two-watchers'
        end
      end
      def last_modified
        r, w = IO.pipe
        w.write('m')
        Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_ev, self_|
          r.read(1)
          self_.abort
          1_000_000_000
        end
      end
      def to_html
        'body'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], TwoWatchers }
      end
    end
  RUBY_SRC
  assert_equal 'body', body
  assert_true head.include?('ETag: "two-watchers"')
  assert_true head.include?('Last-Modified: Sun, 09 Sep 2001 01:46:40 GMT')
end

# #30: the block is written inside the resource, so `response` is in its
# scope. While the run waits, the walk's state is on the connection -
# and the block writes into the run that will resume.
assert('watcher: the block speaks for the run it belongs to (#30)') do
  head, body = wa_exchange(<<~RUBY_SRC)
    class BlockSpeaks < Webmachine::Resource
      watch :generate_etag
      def generate_etag
        r, w = IO.pipe
        w.write('x')
        Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_ev, self_|
          r.read(1)
          response.userdata = 'kept in the block'
          response.headers['X-From-Block'] = 'yes'
          self_.abort
          'etag-from-block'
        end
      end
      def to_html
        response.userdata
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], BlockSpeaks }
      end
    end
  RUBY_SRC
  assert_equal 'kept in the block', body
  assert_true head.include?('ETag: "etag-from-block"')
  assert_true head.include?('X-From-Block: yes')
end

# #80: a watcher that runs out of time leaves no poll behind. The next
# request on the same connection arms a new watcher in the same slot,
# and the old poll, had it stayed, would have fired on it.
assert('watcher: a timed-out watcher leaves no poll for its successor (#80)') do
  src = <<~RUBY_SRC
    class WatchThenWatch < Webmachine::Resource
      watch :generate_etag
      def generate_etag
        $asked = ($asked || 0) + 1
        r, w = IO.pipe
        if $asked.odd?
          Webmachine::Watcher.new(r, :r, timeout: 50.ms) do |ev, self_|
            self_.abort
            "quiet-\#{ev}"
          end
        else
          w.write('x')
          Webmachine::Watcher.new(r, :r, timeout: 2.s) do |ev, self_|
            r.read(1)
            self_.abort
            "ready-\#{ev}"
          end
        end
      end
      def to_html
        'body'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], WatchThenWatch }
      end
    end
  RUBY_SRC
  wa_same_connection(src, times: 4) do |n, head, body|
    assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
    assert_equal 'body', body
    want = n.odd? ? 'ETag: "quiet-timeout"' : 'ETag: "ready-r"'
    assert_true head.include?(want), head
  end
end

# The server ends while a watcher is armed. The connection lets its
# watchers go before the ring is gone and the VM closes after both, so
# the exit is clean: status 0, nothing freed twice, nothing freed late.
assert('watcher: the server exits clean with a watcher still armed') do
  src = <<~RUBY_SRC
    class LongWait < Webmachine::Resource
      watch :generate_etag
      def generate_etag
        r, _w = IO.pipe
        Webmachine::Watcher.new(r, :r, timeout: 30.s) do |_ev, self_|
          self_.abort
          'never'
        end
      end
      def to_html
        'body'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], LongWait }
      end
    end
  RUBY_SRC
  wm_server(src, tag: 'wm-wa-exit') do |sock, pid, err|
    c = UNIXSocket.open(sock)
    c.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    sleep 0.2
    Process.kill('TERM', pid)
    _, status = Process.wait2(pid)
    assert_true status.exited?, "the server did not exit: #{status.inspect}\n#{File.read(err) rescue ''}"
    assert_equal 0, status.exitstatus, "exit status #{status.exitstatus}:\n#{File.read(err) rescue ''}"
    c.close
  end
end

# The three directions have two names each: :r or :in, :w or :out,
# :rw or :inout. Both spell the same order, and events reads back the
# short one.
assert('watcher: :in, :out and :inout are the same orders as :r, :w and :rw') do
  out = wa_body(<<~RUBY_SRC)
    class TwoNames < Webmachine::Resource
      def self.to_html
        r, w = IO.pipe
        lines = []
        begin
          a = Webmachine::Watcher.new(r, :in, timeout: 1.s) { |_e, s| s.abort }
          b = Webmachine::Watcher.new(w, :out, timeout: 1.s) { |_e, s| s.abort }
          c = Webmachine::Watcher.new(r, :inout, timeout: 1.s) { |_e, s| s.abort }
          lines << "in:\#{a.events}" << "out:\#{b.events}" << "inout:\#{c.events}"
          c.events = :in
          lines << "changed:\#{c.events}"
        ensure
          r.close
          w.close
        end
        lines.join("\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], TwoNames }
      end
    end
  RUBY_SRC
  assert_true out.include?('in:r'), out
  assert_true out.include?('out:w'), out
  assert_true out.include?('inout:rw'), out
  assert_true out.include?('changed:r'), out
end
