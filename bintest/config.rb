# The config file (#166): the invocation as TOML, parsed by mruby-toml
# through the VM the process already carries. The file can do what the
# flags can do and NOTHING the app does - it names no resources. The
# precedence sentence: CLI > file > the app's conf. A file that cannot
# be honored refuses the start by name, exit 2.

require 'socket'
require 'tempfile'

CFG_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(CFG_BIN)

def cfg_write(toml)
  f = Tempfile.new(['wm-cfg', '.toml'])
  f.write(toml)
  f.close
  f
end

def cfg_spawn(args, err)
  spawn({ 'WM_BUNDLE' => '0' }, CFG_BIN, *args, out: File::NULL, err: err)
end

def cfg_await(sock, err)
  100.times do
    break if File.socket?(sock)
    sleep 0.05
  end
  raise "server never came up:\n#{begin File.read(err) rescue '' end}" unless File.socket?(sock)
end

def cfg_get(sock, target)
  s = UNIXSocket.new(sock)
  s.write "GET #{target} HTTP/1.1\r\nHost: cfg\r\nConnection: close\r\n\r\n"
  head = +''
  loop do
    head << s.readpartial(4096)
  rescue EOFError
    break
  end
  s.close
  head
end

assert('webmachine.toml: the invocation as a file') do
  sock = "/tmp/wm-cfg-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  cfg = cfg_write("[server]\nunix = \"#{sock}\"\n\n[tune]\nbacklog = 128\nsq_entries = 2048\n")
  err = "/tmp/wm-cfg-stderr-#{$$}.log"
  pid = cfg_spawn(['--config', cfg.path], err)
  begin
    cfg_await(sock, err)
    # No app: the default splat resource answers, proving the file
    # alone brings a serving process up - and the [tune] knobs were
    # accepted (a refused knob never reaches the listen).
    assert_include cfg_get(sock, '/'), '200 OK'
    assert_include File.read(err), 'config '
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    cfg.unlink
  end
end

assert('the typed flag beats the file') do
  sock_file = "/tmp/wm-cfg-file-#{$$}.sock"
  sock_cli = "/tmp/wm-cfg-cli-#{$$}.sock"
  [sock_file, sock_cli].each { |s| File.unlink(s) if File.exist?(s) }
  cfg = cfg_write("[server]\nunix = \"#{sock_file}\"\n")
  err = "/tmp/wm-cfg-stderr2-#{$$}.log"
  pid = cfg_spawn(['--config', cfg.path, '--unix', sock_cli], err)
  begin
    cfg_await(sock_cli, err)
    assert_include cfg_get(sock_cli, '/'), '200 OK'
    assert_false File.socket?(sock_file)
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    cfg.unlink
  end
end

assert('a bad config refuses the start by name') do
  err = "/tmp/wm-cfg-stderr3-#{$$}.log"
  {
    "[server]\nport = \"acht\"\n" => 'server.port',
    "[log]\nfile = \"x\"\nprivacy = \"geheim\"\n" => 'log.privacy',
    "kaputt = [\n" => 'expected',
  }.each do |toml, named|
    cfg = cfg_write(toml)
    pid = cfg_spawn(['--config', cfg.path], err)
    Process.waitpid(pid)
    assert_equal 2, $?.exitstatus
    assert_include File.read(err), named
    cfg.unlink
  end
end
