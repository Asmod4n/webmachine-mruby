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

ERROR_PACK = File.expand_path('share/error-pages.zip', __dir__)

# The status name, and WHERE THE NAME COMES FROM. The tree's own
# flow::reason() covers what the flow can reach and answers "Response" for
# everything else; a pack that ships a page per status needs the wider
# table, and in this tree a table names its source - including the entries
# whose source is "nobody registered this, a vendor shipped it".
#
# Checked against http.cat's own alt texts (2026-08-28). They disagree on
# three, and on two of them they are simply older: "Request-URI Too Long"
# is RFC 2616's name for 414, which RFC 9110 renamed to "URI Too Long",
# and "Unprocessable Entity" is RFC 4918's 422, renamed to "Unprocessable
# Content". Their pictures are the source of the cat, not of the name.
ERROR_STATUS = {
  400 => ['Bad Request',                     'RFC 9110'],
  401 => ['Unauthorized',                    'RFC 9110'],
  402 => ['Payment Required',                'RFC 9110'],
  403 => ['Forbidden',                       'RFC 9110'],
  404 => ['Not Found',                       'RFC 9110'],
  405 => ['Method Not Allowed',              'RFC 9110'],
  406 => ['Not Acceptable',                  'RFC 9110'],
  407 => ['Proxy Authentication Required',   'RFC 9110'],
  408 => ['Request Timeout',                 'RFC 9110'],
  409 => ['Conflict',                        'RFC 9110'],
  410 => ['Gone',                            'RFC 9110'],
  411 => ['Length Required',                 'RFC 9110'],
  412 => ['Precondition Failed',             'RFC 9110'],
  413 => ['Content Too Large',               'RFC 9110'],
  414 => ['URI Too Long',                    'RFC 9110'],
  415 => ['Unsupported Media Type',          'RFC 9110'],
  416 => ['Range Not Satisfiable',           'RFC 9110'],
  417 => ['Expectation Failed',              'RFC 9110'],
  418 => ["I'm a teapot",                    'RFC 2324; RFC 9110 reserves 418 as unused'],
  419 => ['Page Expired',                    'Laravel, not registered'],
  420 => ['Enhance Your Calm',               'Twitter, not registered'],
  421 => ['Misdirected Request',             'RFC 9110'],
  422 => ['Unprocessable Content',           'RFC 9110'],
  423 => ['Locked',                          'RFC 4918'],
  424 => ['Failed Dependency',               'RFC 4918'],
  425 => ['Too Early',                       'RFC 8470'],
  426 => ['Upgrade Required',                'RFC 9110'],
  428 => ['Precondition Required',           'RFC 6585'],
  429 => ['Too Many Requests',               'RFC 6585'],
  431 => ['Request Header Fields Too Large', 'RFC 6585'],
  444 => ['No Response',                     'nginx, not registered'],
  450 => ['Blocked by Windows Parental Controls', 'Microsoft, not registered'],
  451 => ['Unavailable For Legal Reasons',   'RFC 7725'],
  495 => ['SSL Certificate Error',           'nginx, not registered'],
  496 => ['SSL Certificate Required',        'nginx, not registered'],
  497 => ['HTTP Request Sent to HTTPS Port', 'nginx, not registered'],
  498 => ['Invalid Token',                   'Esri, not registered'],
  499 => ['Client Closed Request',           'nginx, not registered'],
  500 => ['Internal Server Error',           'RFC 9110'],
  501 => ['Not Implemented',                 'RFC 9110'],
  502 => ['Bad Gateway',                     'RFC 9110'],
  503 => ['Service Unavailable',             'RFC 9110'],
  504 => ['Gateway Timeout',                 'RFC 9110'],
  506 => ['Variant Also Negotiates',         'RFC 2295'],
  507 => ['Insufficient Storage',            'RFC 4918'],
  508 => ['Loop Detected',                   'RFC 5842'],
  509 => ['Bandwidth Limit Exceeded',        'Apache/cPanel, not registered'],
  510 => ['Not Extended',                    'RFC 2774'],
  511 => ['Network Authentication Required', 'RFC 6585'],
  521 => ['Web Server Is Down',              'Cloudflare, not registered'],
  522 => ['Connection Timed Out',            'Cloudflare, not registered'],
  523 => ['Origin Is Unreachable',           'Cloudflare, not registered'],
  525 => ['SSL Handshake Failed',            'Cloudflare, not registered'],
  530 => ['Site Frozen',                     'Cloudflare, not registered'],
  599 => ['Network Connect Timeout Error',   'not registered']
}.freeze

ERROR_NOTICE = <<~TEXT
  webmachine-mruby error pages
  ============================

  cats/index.txt         status, width, height, bytes, and what the
                         upstream service said the picture's validators
                         were - tab separated, one line per status
  cats/<status>.jpg      the pictures, see below

  This pack holds PICTURES. The pages themselves live in the server, as
  Webmachine::ErrorResource - a server with no pack still has to be able
  to say what went wrong, so the templates cannot live out here. What
  this pack decides is whether a page has a picture: a status with no
  cats/<status>.jpg renders without one.

  The page is rendered when the error happens, by the route that produced
  it - nothing in here is reached by a second trip through the router.
  The picture is: the page names it by URL, the way any page names an
  image, and the asset tier serves it from this pack.

  To change a page, reopen the class rather than editing an archive:

    class Webmachine::ErrorResource
      def self.content_types_provided
        super + [['application/xml', :to_xml_error]]
      end

      def to_xml_error(e)
        "<error status=\"\#{e['status']}\">\#{e['title']}</error>"
      end
    end

  The pictures are "HTTP Status Cats" by Tomomi Imura (@girlie_mac),

      https://girliemac.com/blog/2011/12/18/the-day-i-seized-the-interweb-http-status-cats/

  licensed under Creative Commons Attribution 2.0 (CC BY 2.0),

      https://creativecommons.org/licenses/by/2.0/

  fetched through the http.cat service by @rogeriopvl (https://http.cat/).

  CHANGES: NONE. Every image is the byte-for-byte JPEG the service served,
  not resized, not recompressed, not cropped, not re-encoded - so the
  "angeben, ob Aenderungen vorgenommen wurden" half of the attribution has
  one honest answer: no. (The service itself serves 750x600, already
  smaller than the originals; "unchanged" is measured against what it
  served, and that is all it claims.)

  CC BY 2.0 covers the images only. The templates are ours and carry this
  server's Apache-2.0.

  This notice travels inside the pack on purpose. A zip is what gets
  copied around, so the terms have to be in it, not only in the
  repository it was built from.
TEXT



# The picture's real geometry, from file(1) - in the standard install of
# every distro this would be rebuilt on, and this task is a developer's
# tool, never something a server runs.
#
# It has to be read from the FILE. http.cat does deliver dimensions, on
# its /status/<code> pages, and they are wrong for nine of the 55:
# 414, 422, 495, 498, 509, 521, 523, 525 and 530 are 600x750 and every
# page claims 750x600. That is a layout constant, not a measurement, and
# using it would cause exactly the reflow the numbers exist to prevent.
# The image headers carry no geometry at all (checked 2026-08-28:
# content-type, content-length, etag, last-modified, and nothing else).
#
# file(1)'s output is human-readable and not an API - the wording has
# moved between versions - so this takes the LAST WxH it finds and
# refuses loudly rather than shipping a zero.
def jpeg_size(path)
  out = `file -b #{path.shellescape}`
  raise "file(1) said nothing about #{path}" unless $?.success?
  m = out.scan(/(\d+)x(\d+)/).last
  raise "file(1) found no geometry in #{path}: #{out.strip}" unless m
  w = m[0].to_i
  h = m[1].to_i
  raise "file(1) gave #{w}x#{h} for #{path}" unless w.positive? && h.positive?
  [w, h]
end

# Reading back what a previous run wrote. Everything in this pack is
# stored, so a local header is the whole format.
def read_pack(path)
  raw = File.binread(path)
  out = {}
  off = 0
  while off + 30 <= raw.bytesize && raw[off, 4] == "PK\x03\x04".b
    csize, _usize, nlen, elen = raw[off + 18, 12].unpack('VVvv')
    name = raw[off + 30, nlen]
    out[name] = raw[off + 30 + nlen + elen, csize]
    off += 30 + nlen + elen + csize
  end
  out
end

# The pack format the asset tier reads: stored or deflate, nothing else
# (#170/#177). Everything here is STORED - measured on the cats, a deflate
# entry always leaves as gzip, even to a client that sent no
# Accept-Encoding, and `curl -o` then saves a gzip file instead of a JPEG.
# One fixed timestamp keeps the zip reproducible.
def error_zip(entries)
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

desc 'rebuild share/error-pages.zip: the two error templates and the cats'
task :error_pages do
  require 'zlib'
  require 'open-uri'
  require 'shellwords'
  require 'tmpdir'
  # What the last build recorded, so a rebuild can ASK instead of fetch:
  # http.cat serves an etag, and an image that has not changed upstream
  # answers 304 and costs nothing.
  have = {}
  if File.exist?(ERROR_PACK)
    old_entries = read_pack(ERROR_PACK)
    (old_entries['cats/index.txt'] || '').each_line do |l|
      next if l.start_with?('#')
      code, _w, _h, _n, etag, lastmod = l.chomp.split("\t")
      next unless code
      have[code.to_i] = { etag: etag, lastmod: lastmod,
                          bytes: old_entries["cats/#{code}.jpg"] }
    end
  end

  cats = {}
  meta = {}
  fetched = 0
  ERROR_STATUS.each_key do |code|
    known = have[code]
    headers = { 'User-Agent' => 'webmachine-mruby error-pages packer', read_timeout: 20 }
    if known && known[:etag].to_s != '' && known[:bytes]
      headers['If-None-Match'] = known[:etag]
    end
    body = nil
    etag = nil
    lastmod = nil
    begin
      URI.parse("https://http.cat/#{code}.jpg").open(headers) do |f|
        body = f.read
        etag = f.meta['etag'].to_s
        lastmod = f.meta['last-modified'].to_s
      end
      fetched += 1
    rescue OpenURI::HTTPError => e
      # 304 means upstream still holds exactly what the last build did.
      raise unless e.io.status.first.to_s == '304' && known && known[:bytes]
      body = known[:bytes]
      etag = known[:etag]
      lastmod = known[:lastmod]
    rescue StandardError
      next
    end
    next unless body.b.start_with?("\xFF\xD8".b)
    tmp = File.join(Dir.tmpdir, "wm-cat-#{$$}-#{code}.jpg")
    File.binwrite(tmp, body.b)
    dims = begin
      jpeg_size(tmp)
    ensure
      File.unlink(tmp) rescue nil
    end
    cats[code] = body.b
    meta[code] = [dims[0], dims[1], cats[code].bytesize, etag, lastmod]
    print "#{code} "
  end
  puts
  raise 'http.cat answered with no images at all' if cats.empty?
  puts "  #{fetched} fetched, #{cats.size - fetched} unchanged upstream"

  # Pictures and provenance, nothing else. The templates live in
  # Webmachine::ErrorResource (mrblib/webmachine.rb), because a server
  # with no pack still has to be able to say what went wrong - and the
  # way to change a page is to reopen that class, not to edit a zip.
  entries = [['NOTICE.txt', ERROR_NOTICE]]
  # Geometry and provenance, so the server needs no JPEG reader and the
  # next rebuild can ask upstream instead of downloading.
  index = +"# status\twidth\theight\tbytes\tupstream etag\tupstream last-modified\n"
  cats.keys.sort.each { |code| index << ([code] + meta[code]).join("\t") << "\n" }
  entries << ['cats/index.txt', index]
  cats.keys.sort.each { |code| entries << ["cats/#{code}.jpg", cats[code]] }
  File.binwrite(ERROR_PACK, error_zip(entries))
  puts "share/error-pages.zip: #{cats.size} cats, " \
       "#{entries.size} entries, #{File.size(ERROR_PACK)} bytes"
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
