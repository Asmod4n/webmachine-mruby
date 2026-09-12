require 'tempfile'
require 'fileutils'

# webmachine-passwd reads the password from /dev/tty, never from
# stdin or argv (main.cpp, ask()). A pty is what makes that testable:
# `script` allocates one and feeds it what its own stdin carries.
unless defined?(WM_PASSWD_BIN)
  WM_PASSWD_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-passwd')
end

unless defined?(wm_app)
  # bintest files load in glob order, and this one sorts before
  # resource.rb, which is where wm_app usually comes from. Declared
  # here too, guarded the same way, so load order does not matter.
  def wm_app(name, src)
    <<~RUBY
      #{src}
      def main
        Webmachine::Application.new do |app|
          app.routes do |route|
            route.add [:*], #{name}
          end
        end
      end
    RUBY
  end
end

unless defined?(resource_refused)
  # Declared here too, guarded the same way as wm_app above: this file
  # sorts before resource.rb, which is where resource_refused usually
  # comes from.
  def resource_refused(app_source)
    app = wm_compile(app_source)
    err = "/tmp/wm-res-stderr-#{$$}.log"
    pid = spawn(WM_BIN, "--app=#{app.path}", out: File::NULL, err: err)
    Process.wait(pid)
    raise 'server came up but must have refused' if $?.exitstatus == 0
    File.read(err)
  ensure
    app.unlink
  end
end

unless defined?(wm_have_script?)
  def wm_have_script?
    ENV['PATH'].to_s.split(File::PATH_SEPARATOR).any? { |d| File.executable?(File.join(d, 'script')) }
  end
end

unless defined?(wm_passwd_add)
  # Adds one user to FILE's sub-database DB, typing PASSWORD twice at
  # the prompts webmachine-passwd puts on the pty. Raises on any
  # failure, so a caller that gets past this call has a real record.
  #
  # Each line arrives after a short wait, not both at once. ask()
  # (tools/webmachine-passwd/main.cpp) flushes pending input when it
  # turns terminal echo off, once per prompt - a line sent too early
  # sits in the queue and that flush throws it away.
  def wm_passwd_add(file, db, user, password)
    feed = "sleep 0.3; printf '%s\\n'; sleep 0.3; printf '%s\\n'" % [password, password]
    cmd = "#{WM_PASSWD_BIN} add #{file} #{db} #{user}"
    ok = system("(#{feed}) | script -qfec '#{cmd}' /dev/null", out: File::NULL, err: File::NULL)
    raise "webmachine-passwd add failed for #{user} in #{db}" unless ok
  end
end

assert('passwd: the right password answers 200, everything else 401') do
  skip 'no script(1) on PATH - cannot drive the /dev/tty prompt' unless wm_have_script?

  Dir.mktmpdir('wm-passwd') do |dir|
    file = File.join(dir, 'pw.lmdb')
    system(WM_PASSWD_BIN, 'create', file, out: File::NULL) or raise 'create failed'
    wm_passwd_add(file, 'users', 'ada', 'secret')
    # A second sub-database, with the same user name and a different
    # password: PasswdRec's ad is the sub-database's name, so this row
    # verifies only in the set it was made for (webmachine.hpp).
    wm_passwd_add(file, 'others', 'ada', 'different')

    src = <<~RUBY
      Webmachine::Workers::Registry[:passwd] = proc do
        Webmachine::Passwd.open(#{file.inspect}, 'users')
      end

      class Login < Webmachine::Resource
        compute :is_authorized?

        def is_authorized?(header)
          Webmachine::ComputeTask.new(header, max_runtime: 500.ms) do |h|
            user, pass = h.to_s.split(':', 2)
            Webmachine::Workers::Registry[:passwd].valid?(user.to_s, pass.to_s)
          end
        end

        def to_html
          'welcome'
        end
      end
    RUBY

    wm_server(wm_app('Login', src)) do |sock|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: ada:secret\r\n\r\n")
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), head
        assert_equal 'welcome', body
      end
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: ada:wrong\r\n\r\n")
        head, = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 401'), head
      end
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: ghost:secret\r\n\r\n")
        head, = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 401'), head
      end
      UNIXSocket.open(sock) do |s|
        # The same record, checked against a Passwd opened on the
        # other sub-database: ada's password there is 'different', so
        # 'secret' does not verify - a row copied between sets stays
        # unverifiable (webmachine.hpp).
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: ada:secret\r\n\r\n")
        head, = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), head
      end
    end

    src_other = src.sub("'users'", "'others'")
    wm_server(wm_app('Login', src_other), tag: 'wm-other') do |sock|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: ada:secret\r\n\r\n")
        head, = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 401'), head
      end
    end
  end
end

assert('passwd: a file the worker cannot open answers 503 and names the file') do
  Dir.mktmpdir('wm-passwd') do |dir|
    file = File.join(dir, 'missing.lmdb')
    src = <<~RUBY
      Webmachine::Workers::Registry[:passwd] = proc do
        Webmachine::Passwd.open(#{file.inspect}, 'users')
      end

      class NeedsPasswd < Webmachine::Resource
        compute :is_authorized?
        def is_authorized?(header)
          Webmachine::ComputeTask.new(header, max_runtime: 500.ms) do |h|
            Webmachine::Workers::Registry[:passwd].valid?('ada', 'secret')
          end
        end
        def to_html; 'x'; end
      end
    RUBY
    # The workers boot on the first job, so the server comes up. A
    # registry proc that raises leaves that worker without a VM, and a
    # worker without a VM answers every job as a fault: the run gets
    # its 503, and the error output names the file (#25).
    wm_server(wm_app('NeedsPasswd', src), tag: 'wm-passwd-missing') do |sock, _pid, err|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: ada:secret\r\n\r\n")
        head, = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 503'), head
      end
      assert_true File.read(err).include?(file), File.read(err)
    end
  end
end
