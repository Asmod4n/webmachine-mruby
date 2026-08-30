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

ERROR_ASSETS = File.expand_path('share/error-assets.zip', __dir__)

# The status name, and WHERE THE NAME COMES FROM. The tree's own
# flow::reason() covers what the flow can reach and answers "Response" for
# everything else; an asset file that ships a page per status needs the wider
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

  <status>.jpg           the pictures, one per status, at the root

  There is no index: the archive's own entry list is one, and each
  entry's comment carries what the upstream service said the picture's
  validators were - its ETag and Last-Modified, tab separated - so a
  rebuild can ask instead of download.

  This pack holds PICTURES. The pages themselves live in the server, as
  Webmachine::ErrorResource - a server with no pack still has to be able
  to say what went wrong, so the templates cannot live out here. What
  these error assets decides is whether a page has a picture: a status with no
  <status>.jpg renders without one.

  The page is rendered when the error happens, by the route that produced
  it - nothing in here is reached by a second trip through the router.
  The picture is: the page names it by URL, the way any page names an
  image, and the asset tier serves it from these error assets.

  To change a page, reopen the class rather than editing an archive:

    class Webmachine::ErrorResource
      def self.content_types_provided
        super + [['application/xml', :to_xml_error]]
      end

      def to_xml_error(e)
        "<error status=\\"\#{e['status']}\\">\#{e['title']}</error>"
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

  This notice travels inside the error assets on purpose. A zip is what gets
  copied around, so the terms have to be in it, not only in the
  repository it was built from.
TEXT


# Reading back what a previous run wrote. Everything in these error assets is
# stored, so a local header is the whole format.
# What a previous run wrote, per entry: the bytes, and the three things
# beside them. The ETag is the comment, because ZIP has no field for an
# opaque validator that has to go back exactly as it came. The time and
# the picture's size are NOT in the comment - ZIP has places for both,
# and they are used: the entry's own timestamp, and an extra field.
# APPNOTE 4.5.2: extra field header ids are PKWARE's to hand out. This one
# is NOT registered - "WM" as two bytes, picked to sit clear of the ids
# the format's own extensions use. It carries the picture's size, so a
# page can name width and height and not reflow when the image lands.
WM_EXTRA_ID = 0x574d

def read_pack_entries(path)
  raw = File.binread(path)
  eocd = raw.rindex("PK\x05\x06".b) or return {}
  n, _cdsize, cdoff = raw[eocd + 10, 10].unpack('vVV')
  out = {}
  off = cdoff
  n.times do
    break unless raw[off, 4] == "PK\x01\x02".b
    csize, _usize, nlen, elen, clen = raw[off + 20, 14].unpack('VVvvv')
    lho = raw[off + 42, 4].unpack1('V')
    name = raw[off + 46, nlen]
    extra = elen.zero? ? '' : raw[off + 46 + nlen, elen]
    comment = clen.zero? ? '' : raw[off + 46 + nlen + elen, clen]
    lnlen, lelen = raw[lho + 26, 4].unpack('vv')
    fields = extra_fields(extra)
    mtime = fields[0x5455] && fields[0x5455].bytesize >= 5 ?
            fields[0x5455][1, 4].unpack1('l<') : nil
    w, h = fields[WM_EXTRA_ID] && fields[WM_EXTRA_ID].bytesize >= 4 ?
           fields[WM_EXTRA_ID].unpack('vv') : [nil, nil]
    out[name] = { bytes: raw[lho + 30 + lnlen + lelen, csize], etag: comment,
                  mtime: mtime, width: w, height: h }
    off += 46 + nlen + elen + clen
  end
  out
end

# An extra field block is a run of (id, size, payload). Unknown ids are
# skipped by every reader, which is what makes it the place to put
# something only this tree knows about.
def extra_fields(blob)
  out = {}
  off = 0
  while off + 4 <= blob.bytesize
    id, size = blob[off, 4].unpack('vv')
    break if off + 4 + size > blob.bytesize
    out[id] = blob[off + 4, size]
    off += 4 + size
  end
  out
end

# The picture's size, from file(1): its JPEG line names the geometry as
# "750x600" in a field of its own, after the comma the density is not
# written with. file(1) reads a path, the bytes are in hand, so they go
# through a temp file.
def jpeg_size(bytes)
  Tempfile.create(['wm-cat', '.jpg']) do |f|
    f.binmode
    f.write(bytes)
    f.flush
    said = `file -b #{f.path.shellescape}`
    raise 'file(1) failed' unless $?.success?
    m = said.match(/,\s*(\d+)x(\d+)\b/)
    raise "file(1) found no geometry: #{said.strip}" unless m
    w = m[1].to_i
    h = m[2].to_i
    raise "file(1) gave #{w}x#{h}" unless w.positive? && h.positive?
    [w, h]
  end
end

# An HTTP-date to the second it names, or nil when a server sent none.
def http_seconds(text)
  return nil if text.to_s.empty?
  Time.httpdate(text).to_i
rescue ArgumentError
  nil
end

# MS-DOS date and time, which is what a ZIP header holds: two-second
# resolution and no zone. The upstream Last-Modified is GMT, and that is
# what goes in - a reader that treats it as local time is off by its own
# offset, which is the format's limitation and the reason the exact
# second rides in the extended timestamp beside it.
def dos_stamp(unix)
  t = Time.at(unix || 0).utc
  [((t.year - 1980) << 9) | (t.month << 5) | t.day,
   (t.hour << 11) | (t.min << 5) | (t.sec / 2)]
end

# Two fields: Info-ZIP's extended timestamp (0x5455, flag 1 = the
# modification time follows, as a signed 32-bit Unix time), and this
# tree's own with the picture's size.
def entry_extra(mtime, width, height)
  ext = +''.b
  ext << [0x5455, 5, 0x01, mtime.to_i].pack('vvCl<')
  ext << [WM_EXTRA_ID, 4, width.to_i, height.to_i].pack('vvvv')
  ext
end

# The error assets format the asset tier reads: stored or deflate, nothing else
# (#170/#177). Everything here is STORED - measured on the cats, a deflate
# entry always leaves as gzip, even to a client that sent no
# Accept-Encoding, and `curl -o` then saves a gzip file instead of a JPEG.
# PKWARE APPNOTE 4.4.18: the central directory carries a comment per
# entry, and that is where the upstream ETag goes - ZIP has no field for
# an opaque validator, and one that goes back changed is not the one the
# service handed out.
# The notice rides in the archive's own comment field, not as an entry:
# the pack is pictures and nothing else, and read_cats reads every entry
# as one. A comment travels with the file wherever it is copied, which is
# what CC BY 2.0 asks for and what a zip handed to somebody else would
# otherwise arrive without.
def error_zip(entries, archive_comment = '')
  out = +''.b
  cd = +''.b
  archive_comment = archive_comment.b
  entries.each do |name, data, etag, mtime, width, height|
    data = data.b
    etag = (etag || '').b
    ddate, dtime = dos_stamp(mtime)
    extra = entry_extra(mtime, width, height)
    crc = Zlib.crc32(data)
    lho = out.bytesize
    out << [0x04034b50, 20, 0, 0, dtime, ddate, crc, data.bytesize, data.bytesize,
            name.bytesize, extra.bytesize].pack('VvvvvvVVVvv') << name.b << extra << data
    cd << [0x02014b50, 20, 20, 0, 0, dtime, ddate, crc, data.bytesize, data.bytesize,
           name.bytesize, extra.bytesize, etag.bytesize, 0, 0, 0, lho]
          .pack('VvvvvvvVVVvvvvvVV') << name.b << extra << etag
  end
  cd_off = out.bytesize
  out << cd
  out << [0x06054b50, 0, 0, entries.size, entries.size, cd.bytesize, cd_off,
          archive_comment.bytesize].pack('VvvvvVVv') << archive_comment
  out
end

desc 'rebuild share/error-assets.zip: the cats, one per status'
task :error_assets do
  require 'zlib'
  require 'open-uri'
  require 'time'
  require 'tempfile'
  require 'shellwords'
  # What the last build recorded, so a rebuild can ASK instead of fetch:
  # http.cat serves an etag, and an image that has not changed upstream
  # answers 304 and costs nothing.
  have = {}
  if File.exist?(ERROR_ASSETS)
    read_pack_entries(ERROR_ASSETS).each do |name, e|
      code = name[/\A(\d+)\.jpg\z/, 1]
      have[code.to_i] = e if code
    end
  end

  cats = {}
  meta = {}
  fetched = 0
  ERROR_STATUS.each_key do |code|
    known = have[code]
    headers = { 'User-Agent' => 'webmachine-mruby error-assets packer', read_timeout: 20 }
    if known && known[:bytes]
      # RFC 9110 13.1.1/13.1.3: the ETag is the strong question and goes
      # back exactly as it came; the date is the weaker one, and now that
      # it is kept it is asked with too.
      headers['If-None-Match'] = known[:etag] if known[:etag].to_s != ''
      headers['If-Modified-Since'] = Time.at(known[:mtime]).utc.httpdate if known[:mtime]
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
      lastmod = known[:mtime] ? Time.at(known[:mtime]).utc.httpdate : nil
    rescue StandardError
      next
    end
    w, h = jpeg_size(body.b)
    cats[code] = body.b
    meta[code] = [etag, http_seconds(lastmod), w, h]
    print "#{code} "
  end
  puts
  raise 'http.cat answered with no images at all' if cats.empty?
  puts "  #{fetched} fetched, #{cats.size - fetched} unchanged upstream"

  # PICTURES AND NOTHING ELSE, named by the status they illustrate, at
  # the root - so the name in the archive is the name a caller writes,
  # with no directory anyone had to be told about. The templates live in
  # Webmachine::ErrorResource (mrblib/webmachine.rb); the licence lives
  # in share/README.md.
  entries = cats.keys.sort.map do |code|
    etag, mtime, w, h = meta[code]
    ["#{code}.jpg", cats[code], etag, mtime, w, h]
  end
  File.binwrite(ERROR_ASSETS, error_zip(entries, ERROR_NOTICE))
  puts "share/error-assets.zip: #{cats.size} cats, " \
       "#{entries.size} entries, #{File.size(ERROR_ASSETS)} bytes"
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
