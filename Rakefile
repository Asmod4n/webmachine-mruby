MRUBY_DIR = File.expand_path('mruby', __dir__)
CONFIG = File.expand_path(ENV['MRUBY_CONFIG'] || 'build_config_host.rb', __dir__)

file MRUBY_DIR do
  sh "git clone --depth 1 https://github.com/mruby/mruby.git #{MRUBY_DIR}"
end

desc 'build'
task compile: MRUBY_DIR do
  sh "git -C #{MRUBY_DIR} --no-pager log -1 --format='mruby %h %ad' --date=short"
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake"
end

desc 'build and run every test'
task test: MRUBY_DIR do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake all test"
  Rake::Task[:ship_smoke].invoke
  Rake::Task[:portable_smoke].invoke
end

SMOKE_APP = <<~RUBY
  class Smoke < Webmachine::Resource
    def self.to_html
      'OK'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.add [:*], Smoke }
    end
  end
RUBY

# The server refuses to start with nothing to serve, so a smoke brings its
# own resource - one route, one baked body.
def wm_smoke_app
  return @wm_smoke_app if @wm_smoke_app
  mrbc = [File.expand_path('mruby/build/host/mrbc/bin/mrbc', __dir__),
          File.expand_path('mruby/bin/mrbc', __dir__)].find { |c| File.executable?(c) }
  raise 'no mrbc to compile the smoke app - run rake compile first' unless mrbc
  rb = "/tmp/wm-smoke-app-#{$$}.rb"
  mrb = "/tmp/wm-smoke-app-#{$$}.mrb"
  File.write(rb, SMOKE_APP)
  sh "#{mrbc} -o #{mrb} #{rb}"
  File.unlink(rb) rescue nil
  @wm_smoke_app = mrb
end

def wm_smoke(build_name, label)
  require 'socket'
  bin = File.expand_path("mruby/build/#{build_name}/bin/webmachine-server", __dir__)
  raise "no #{label} binary at #{bin} - run rake compile first" unless File.executable?(bin)

  sock = "/tmp/wm-#{build_name}-smoke-#{$$}.sock"
  log = "/tmp/wm-#{build_name}-smoke-#{$$}.log"
  File.unlink(sock) if File.exist?(sock)
  pid = spawn(bin, '--unix', sock, '--app', wm_smoke_app, out: File::NULL, err: log)
  begin
    200.times do
      break if File.socket?(sock)
      sleep 0.05
    end
    unless File.socket?(sock)
      text = begin File.read(log) rescue '' end
      if text.include?('io_uring is not usable here')
        warn "#{build_name} smoke: skipped - this machine cannot run io_uring " \
             "(the #{label} binary needs it, no fallback); use " \
             "build_config_portable.rb or build_config_portable_debug.rb here instead"
        return
      end
      raise "the #{label} binary never came up:\n#{text}"
    end
    answer = UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: smoke\r\nConnection: close\r\n\r\n")
      s.read
    end
    unless answer.start_with?('HTTP/1.1 200')
      raise "the #{label} binary answered:\n#{answer}"
    end
    puts "#{build_name} smoke: the #{label} binary starts and answers 200"
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    File.unlink(log) rescue nil
  end
end

desc 'the SHIP binary starts and answers - what the suite (debug) never checks'
task :ship_smoke do
  wm_smoke('host', 'shipped')
end

desc 'the PORTABLE binary (no liburing, select(2)) starts and answers'
task :portable_smoke do
  wm_smoke('portable', 'portable')
end

CATS_ZIP = File.expand_path('share/http-cats.zip', __dir__)
CATS_NOTICE = <<~TEXT
  HTTP status cats
  ================

  Images: "HTTP Status Cats" by Tomomi Imura (@girlie_mac),
          https://girliemac.com/blog/2011/12/18/the-day-i-seized-the-interweb-http-status-cats/
  Fetched from the http.cat service by @rogeriopvl, https://http.cat/

  Licence: Creative Commons Attribution 2.0 (CC BY 2.0)
           https://creativecommons.org/licenses/by/2.0/

  CHANGES: NONE. Every image in this pack is the byte-for-byte JPEG that
  https://http.cat/<status>.jpg served. Nothing was resized, recompressed,
  cropped or re-encoded, so the "angeben, ob Aenderungen vorgenommen wurden"
  half of the attribution has one honest answer: no.

  This notice travels inside the pack on purpose. A zip is what gets copied
  around, so the terms have to be in it - not only in the repository it was
  built from.
TEXT

# The pack format the asset tier reads: stored or deflate, nothing else
# (#170/#177). Everything here is STORED - a JPEG does not compress, and
# the notice is too small for it to matter. One fixed timestamp keeps the
# zip reproducible, so a rebuild shows up as a rebuild and not as noise.
def cats_zip(entries)
  out = +''.b
  cd = +''.b
  dtime = 0
  ddate = ((2026 - 1980) << 9) | (8 << 5) | 28
  entries.each do |name, data|
    data = data.b
    crc = Zlib.crc32(data)
    lho = out.bytesize
    out << [0x04034b50, 20, 0, 0, dtime, ddate, crc, data.bytesize, data.bytesize,
            name.bytesize, 0].pack('VvvvvvVVVvv') << name.b << data
    cd << [0x02014b50, 20, 20, 0, 0, dtime, ddate, crc, data.bytesize, data.bytesize,
           name.bytesize, 0, 0, 0, 0, 0, lho].pack('VvvvvvvVVVvvvvvVV') << name.b
  end
  cd_off = out.bytesize
  out << cd
  out << [0x06054b50, 0, 0, entries.size, entries.size, cd.bytesize, cd_off, 0].pack('VvvvvVVv')
  out
end

desc 'rebuild share/http-cats.zip from http.cat (every status >= 400)'
task :cats do
  require 'zlib'
  require 'open-uri'
  got = []
  (400..599).each do |code|
    body = begin
      URI.parse("https://http.cat/#{code}.jpg").open(
        'User-Agent' => 'webmachine-mruby cats packer', read_timeout: 20
      ) { |f| f.read }
    rescue StandardError
      next
    end
    next unless body.start_with?("\xFF\xD8".b)
    got << [format('cats/%d.jpg', code), body]
    print "#{code} "
  end
  puts
  raise 'http.cat answered with no images at all' if got.empty?
  entries = [['cats/NOTICE.txt', CATS_NOTICE]] + got.sort_by { |n, _| n }
  File.binwrite(CATS_ZIP, cats_zip(entries))
  puts "share/http-cats.zip: #{got.size} cats, #{File.size(CATS_ZIP)} bytes"
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
