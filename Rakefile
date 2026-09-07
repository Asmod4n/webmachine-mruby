MRUBY_DIR = File.expand_path('mruby', __dir__)
CONFIG = File.expand_path(ENV['MRUBY_CONFIG'] || 'build_config_host.rb', __dir__)
# Where each thing lives, named here rather than left to whatever
# MRUBY_CONFIG happened to say: every test in this tree is in the debug
# build - the host build carries none - and the shipped binary is the
# host build's, which is why its smoke is a host task.
TEST_CONFIG = File.expand_path('build_config_debug.rb', __dir__)
HOST_CONFIG = File.expand_path('build_config_host.rb', __dir__)

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
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{TEST_CONFIG} rake all test"
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
#
# mrbc -g, here and in every place this tree compiles an app: an error
# record names the app's source line, and only the debug section of the
# .mrb carries the line table. The cost is that section's size, once
# per file; a ship build reads it and pays nothing per request. The
# installed mrbc is the same program, and README tells users the same
# line.
def wm_smoke_app(sock)
  return @wm_smoke_app if @wm_smoke_app
  mrbc = [File.expand_path('mruby/build/host/mrbc/bin/mrbc', __dir__),
          File.expand_path('mruby/bin/mrbc', __dir__)].find { |c| File.executable?(c) }
  raise 'no mrbc to compile the smoke app - run rake compile first' unless mrbc
  rb = "/tmp/wm-smoke-app-#{$$}.rb"
  mrb = "/tmp/wm-smoke-app-#{$$}.mrb"
  File.write(rb, SMOKE_APP.sub("Webmachine::Application.new do |app|\n",
                              "Webmachine::Application.new do |app|\n      app.conf.unix_path = #{sock.inspect}\n"))
  sh "#{mrbc} -g -o #{mrb} #{rb}"
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
  pid = spawn(bin, "--app=#{wm_smoke_app(sock)}", out: File::NULL, err: log)
  begin
    200.times do
      break if File.socket?(sock)
      sleep 0.05
    end
    unless File.socket?(sock)
      text = begin File.read(log) rescue '' end
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

desc 'the ship binary starts and answers - what the suite (debug) never checks'
task ship_smoke: MRUBY_DIR do
  # The shipped binary is the host build's, so this builds that one and
  # smokes it. It is not part of `rake test`: the suite is the debug
  # build's, and a debug run cannot answer for a binary it never made.
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{HOST_CONFIG} rake"
  wm_smoke('host', 'shipped')
end


ERROR_ASSETS = File.expand_path('share/error-assets.zip', __dir__)

# Which pictures the pack carries, and only that. A page's <h1> and the
# alt text on its picture have to say the same thing, so both names come
# from the server's own table in src/error_assets.cpp.
#
# 418 is here and not in kFaces: the picture ships, the page has no name
# for the status, and both stay true of whatever this bakes.
ERROR_CODES = [
  400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
  410, 411, 412, 413, 414, 415, 416, 417, 418, 419,
  420, 421, 422, 423, 424, 425, 426, 428, 429, 431,
  444, 450, 451, 495, 496, 497, 498, 499, 500, 501,
  502, 503, 504, 506, 507, 508, 509, 510, 511, 521,
  522, 523, 525, 530, 599
].freeze
ERROR_CODES.each { |c| raise "#{c} is not an error" if c < 400 || c > 599 }

# kErrorAssetsPrefix in src/webmachine.hpp: where the server mounts this
# pack, and therefore the src of every picture in it.
def error_assets_prefix
  File.read(File.expand_path('src/webmachine.hpp', __dir__))[
    /kErrorAssetsPrefix\[\] = "([^"]*)"/, 1] or
    raise 'src/webmachine.hpp: no kErrorAssetsPrefix to build the picture URLs from'
end

# RFC 9110 15: what the server calls each error, read out of the source
# that answers with it rather than copied to a second place that can
# drift. Both tables also name statuses that are not errors; 399 and
# below never reach a page here, so they are not carried around either.
def status_titles
  out = {}
  reason = File.read(File.expand_path('src/webmachine.hpp', __dir__))[
    /constexpr const char\* reason\(uint16_t status\) \{(.*?)\n\}/m, 1] or
    raise 'src/webmachine.hpp: no reason() to read the status names from'
  faces = File.read(File.expand_path('src/error_assets.cpp', __dir__))[
    /constexpr Face kFaces\[\] = \{(.*?)\n\};/m, 1] or
    raise 'src/error_assets.cpp: no kFaces table to read the status names from'
  reason.scan(/case (\d+): return "([^"]*)";/) { |c, n| out[c.to_i] = n if c.to_i >= 400 }
  faces.scan(/\{\s*(\d+),\s*"([^"]*)"/) { |c, n| out[c.to_i] = n if c.to_i >= 400 }
  raise 'no status names found' if out.empty?
  out
end

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
# the picture's size are not in the comment - ZIP has places for both,
# and they are used: the entry's own timestamp, and an extra field.
# APPNOTE 4.5.2: extra field header ids are PKWARE's to hand out. This one
# is not registered - "WM" as two bytes, picked to sit clear of the ids
# the format's own extensions use. It carries the finished <img> for the
# picture - src, size and alt, the bytes a page emits - so the server
# appends what it read and spells nothing.
WM_EXTRA_ID = 0x574d
WM_CACHE_ID = 0x574e
WM_PLAIN_ID = 0x574f

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
    out[name] = { bytes: raw[lho + 30 + lnlen + lelen, csize], etag: comment,
                  mtime: mtime, tag: fields[WM_EXTRA_ID] }
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

# The <img> attributes for a picture, from file(1): its JPEG line names
# the geometry as "750x600" in a field of its own, after the comma the
# density is not written with. file(1) reads a path, the bytes are in
# hand, so they go through a temp file.
def size_attributes(bytes)
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
    %Q{width="#{w}" height="#{h}"}
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
# resolution and no zone. GMT goes in, so a reader that takes it as local
# time is off by its own offset. That is the format's limitation, and the
# reason the exact second rides in the extended timestamp beside it.
def dos_stamp(unix)
  t = Time.at(unix || 0).utc
  [((t.year - 1980) << 9) | (t.month << 5) | t.day,
   (t.hour << 11) | (t.min << 5) | (t.sec / 2)]
end

# The whole <img>, as the page emits it. Everything in it is known here:
# the mount point and the status name from the server's own sources, the
# geometry from file(1). The server appends this and spells nothing.
def img_tag(prefix, code, title, size_attrs)
  alt = "A cat, illustrating HTTP #{[code, title].join(' ').strip}"
  raise "#{code}: #{alt.inspect} needs escaping, and a baked tag does not escape" if
    alt.match?(/[&<>"]/)
  %Q{<img src="#{prefix}#{code}.jpg" #{size_attrs} alt="#{alt}">}
end

# Two fields: Info-ZIP's extended timestamp (0x5455, flag 1 = the
# modification time follows, as a signed 32-bit Unix time), and this
# tree's own with the finished <img> for this picture.
def entry_extra(mtime, tag)
  ext = +''.b
  ext << [0x5455, 5, 0x01, mtime.to_i].pack('vvCl<')
  ext << [WM_EXTRA_ID, tag.bytesize].pack('vv') << tag.b
  ext
end

# The error assets format the asset tier reads: stored or deflate, nothing else
# (#170/#177). Everything here is stored - measured on the cats, a deflate
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
  entries.each do |name, data, etag, mtime, tag|
    data = data.b
    etag = (etag || '').b
    ddate, dtime = dos_stamp(mtime)
    extra = entry_extra(mtime, tag)
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
  # What the last build recorded, so a rebuild can ask instead of fetch:
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
  prefix = error_assets_prefix
  titles = status_titles
  ERROR_CODES.each do |code|
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
    size_attrs = nil
    begin
      URI.parse("https://http.cat/#{code}.jpg").open(headers) do |f|
        body = f.read
        etag = f.meta['etag'].to_s
        lastmod = f.meta['last-modified'].to_s
      end
      # The one moment a picture is measured: it just arrived. From here
      # the attributes live in the zip, and no later run asks again.
      size_attrs = size_attributes(body.b)
      fetched += 1
    rescue OpenURI::HTTPError => e
      # 304 means upstream still holds exactly what the last build did.
      raise unless e.io.status.first.to_s == '304' && known && known[:bytes]
      body = known[:bytes]
      etag = known[:etag]
      lastmod = known[:mtime] ? Time.at(known[:mtime]).utc.httpdate : nil
      # The picture is the same one; the tag around it need not be. Its
      # size is the half only the bytes know, and it is read back out of
      # what the last build wrote rather than measured again.
      size_attrs = known[:tag].to_s[/width="\d+" height="\d+"/]
      raise "#{code}.jpg is unchanged upstream but the pack carries no size " \
            "for it - delete #{ERROR_ASSETS} and rebuild" unless size_attrs
    rescue StandardError
      next
    end
    cats[code] = body.b
    meta[code] = [etag, http_seconds(lastmod),
                  img_tag(prefix, code, titles[code], size_attrs)]
    print "#{code} "
  end
  puts
  raise 'http.cat answered with no images at all' if cats.empty?
  puts "  #{fetched} fetched, #{cats.size - fetched} unchanged upstream"

  # Pictures and nothing else, named by the status they illustrate, at
  # the root - so the name in the archive is the name a caller writes,
  # with no directory anyone had to be told about. The templates live in
  # Webmachine::ErrorResource (mrblib/webmachine.rb); the licence lives
  # in share/README.md.
  entries = cats.keys.sort.map do |code|
    etag, mtime, tag = meta[code]
    ["#{code}.jpg", cats[code], etag, mtime, tag]
  end
  File.binwrite(ERROR_ASSETS, error_zip(entries, ERROR_NOTICE))
  puts "share/error-assets.zip: #{cats.size} cats, " \
       "#{entries.size} entries, #{File.size(ERROR_ASSETS)} bytes"
end

# --- packing a directory for --assets ---------------------------------
#
# The server serves static files from a ZIP, and this writes one. It is
# here rather than in a shell line because the two decisions a pack makes
# are decisions, not switches: what is compressed, and what the entry is
# named.
#
# A deflate entry leaves the server as gzip - always, to every client,
# because the tier hands out the archive's own stream. That is right for
# text and wrong for a JPEG, which does not compress and would then reach
# `curl -o` as a gzip file. So a suffix that names an already compressed
# format is stored, and everything else is deflated at level 9.
#
# The name in the archive is the path a client writes, without a leading
# slash: examples/site/img/p1015.jpg goes in as img/p1015.jpg and answers
# GET /img/p1015.jpg. A directory takes its own index.html.
PACK_STORED = %w[
  .jpg .jpeg .png .gif .webp .avif .ico .bmp
  .woff .woff2 .otf .ttc
  .zip .gz .br .zst .xz .bz2
  .mp3 .mp4 .m4a .webm .ogg .ogv .opus .flac .mov .avi .mkv
  .pdf .wasm
].freeze

# 0x574E, the pack's second extra field: what Cache-Control this entry
# answers with. It is decided here, once, and the server bakes it into the
# prebuilt head when it opens the pack - no request ever reads it.
#
# Every file goes into the pack twice, under two names for the same
# bytes: the name it has, and the name plus a hash of its content -
# site.css and site.a1b2c3d4e5f6.css. Both central directory entries
# point at one local record, so the pack does not grow.
#
# The point of the pair is that the two names deserve different answers.
#
# The hashed name can never mean other bytes, so it says the maximum a
# cache may hold: a year, immutable, never asked about again. A page
# that wants that names the hashed file.
#
# The plain name means "whatever is there now". How long a browser may
# use it is a decision only the person with the site can make, so this
# task asks them once per extension and writes the answers into
# <DIR>/.cache-rules beside the files.
#
# RFC 9111 5.2.2.1: a lifetime of 0 is spelled no-cache, which means
# keep the file but ask before using it. The ETag then makes that ask
# cost a 304 with no body.
PACK_IMMUTABLE = 'public, max-age=31536000, immutable'
# What a hashed name looks like: name.<12 hex>.ext. An old one is kept in
# the directory when a build no longer makes it, because a link somebody
# wrote down still names it.
PACK_HASHED = /\.[0-9a-f]{12}\.[A-Za-z0-9]+\z/.freeze
PACK_RULES_FILE = '.cache-rules'

# What the task offers when it asks. Nothing here is applied unasked.
PACK_SUGGESTED = {
  # A page gets a few minutes, not nothing. A reader who walks a site
  # comes back to the page they just left, and 300 seconds of that costs
  # no request at all. It is short enough that a correction is visible
  # while the person who made it is still watching.
  '.html' => 300, '.htm' => 300, '.json' => 0, '.txt' => 60, '.md' => 60, '.xml' => 60,
  '.css' => 3600, '.js' => 3600, '.mjs' => 3600, '.map' => 3600, '.wasm' => 3600,
  '.jpg' => 604_800, '.jpeg' => 604_800, '.png' => 604_800, '.gif' => 604_800,
  '.webp' => 604_800, '.avif' => 604_800, '.ico' => 604_800, '.bmp' => 604_800,
  '.svg' => 604_800, '.pdf' => 604_800,
  '.woff' => 31_536_000, '.woff2' => 31_536_000, '.otf' => 31_536_000,
  '.ttf' => 31_536_000, '.ttc' => 31_536_000,
  '.mp3' => 2_592_000, '.mp4' => 2_592_000, '.m4a' => 2_592_000,
  '.webm' => 2_592_000, '.ogg' => 2_592_000, '.opus' => 2_592_000,
  '.flac' => 2_592_000, '.mov' => 2_592_000
}.freeze

def pack_cache_control(seconds)
  seconds.to_i <= 0 ? 'no-cache' : "public, max-age=#{seconds.to_i}"
end

def read_cache_rules(path)
  rules = {}
  return rules unless File.exist?(path)

  File.readlines(path).each_with_index do |line, i|
    line = line.sub(/#.*/, '').strip
    next if line.empty?

    ext, secs = line.split(/[\s=]+/, 2)
    raise "#{path}:#{i + 1}: #{line.inspect} is not 'EXTENSION SECONDS'" if secs.nil?
    raise "#{path}:#{i + 1}: #{secs.inspect} is not a number of seconds" unless
      secs.match?(/\A\d+\z/)

    rules[ext.downcase] = secs.to_i
  end
  rules
end

def write_cache_rules(path, rules)
  body = +"# How long a browser may use a file under its plain name without\n" \
          "# asking again, in seconds. 0 means ask every time (no-cache).\n" \
          "# The hashed name of the same file always says one year.\n" \
          "# rake pack asks for an extension that is not here yet.\n"
  rules.keys.sort.each { |ext| body << format("%-8s %d\n", ext, rules[ext]) }
  File.write(path, body)
end

# The one question this task asks. It asks per extension, not per file,
# and it asks once: the answer goes into .cache-rules and no later run
# asks again.
def ask_cache_seconds(ext, count)
  suggested = PACK_SUGGESTED.fetch(ext, 0)
  unless $stdin.tty?
    puts "  #{ext}: no rule, and nobody to ask - taking #{suggested} s. " \
         "Write #{PACK_RULES_FILE} to decide it."
    return suggested
  end
  print "  #{ext} (#{count} file(s)): how many seconds may a browser use it " \
        "without asking? [#{suggested}] "
  $stdout.flush
  answer = $stdin.gets.to_s.strip
  return suggested if answer.empty?
  raise "#{answer.inspect} is not a number of seconds" unless answer.match?(/\A\d+\z/)

  answer.to_i
end

# name.ext -> name.<12 hex of the content>.ext, in the same directory.
def pack_hashed_name(name, data)
  require 'digest'
  ext = File.extname(name)
  "#{name[0, name.length - ext.length]}.#{Digest::SHA256.hexdigest(data)[0, 12]}#{ext}"
end

def pack_entry_extra(mtime, plain_name, cache_control)
  extra = [0x5455, 5, 0x01, mtime.to_i].pack('vvCl<')
  extra << [WM_CACHE_ID, cache_control.bytesize].pack('vv') << cache_control.b
  # A page has no second name, so it carries no table field: the entry is
  # already named what it answers under.
  extra << [WM_PLAIN_ID, plain_name.bytesize].pack('vv') << plain_name.b if plain_name
  extra
end

# A page that wants the hashed name of a file it embeds has to be able to
# write it, and it cannot know a hash before the file is packed. So the
# page writes the path it means, in one spelling, and the pack fills it
# in:
#
#     <link rel="stylesheet" href="{{asset:/site.css}}">
#     <img src="{{asset:/img/p1015.jpg}}">
#
# {{asset:PATH}}, with the real path inside it. The pack replaces it with
# that file's hashed name and refuses, by name, a path it does not hold.
# The path stays readable in the source, and there is no second name for
# anything to learn.
#
# A link to a page is not an asset. It stays plain - href="/gallery.html".
# A page is what somebody calls, bookmarks and links to from outside, and
# a hashed page address would change with every word on the page. So only
# what a page embeds is hashed: a stylesheet, a script, a picture, a font.
#
# That is also why there is no hen and egg here. Hashed references point
# from a page to a leaf and never back, so nothing waits for a hash that
# waits for it. A leaf may name another leaf - a stylesheet that names a
# picture - and the pack does those in the order the naming gives.
PACK_ASSET_TAG = /\{\{\s*asset:\s*([^\s}]+)\s*\}\}/.freeze

# Which entries get their {{asset:...}} tags filled: the text ones. This
# is the list when <DIR>/.fill-extensions does not say otherwise. That
# file holds one extension per line, with the dot, and replaces the
# whole list.
PACK_FILL_FILE = '.fill-extensions'
PACK_TEXT_DEFAULT = %w[.html .htm .xhtml .css .js .mjs .cjs .map .svg .json .jsonld .txt
                       .md .xml .rss .atom .webmanifest .manifest .csv .tsv .yaml .yml
                       .toml .ini .vtt .srt .ics .txt .appcache].uniq.freeze

def pack_text_extensions(root)
  path = File.join(root, PACK_FILL_FILE)
  return PACK_TEXT_DEFAULT unless File.file?(path)

  list = File.readlines(path, chomp: true).map { |l| l.sub(/#.*/, '').strip.downcase }
  list = list.reject(&:empty?)
  bad = list.reject { |e| e.start_with?('.') }
  raise "#{path}: an extension starts with a dot, and these do not: #{bad.join(', ')}" unless bad.empty?

  list.uniq
end

# Set once per pack, from the directory being packed.
$pack_text = PACK_TEXT_DEFAULT

def pack_text?(name)
  $pack_text.include?(File.extname(name).downcase)
end

def pack_fill(name, body, table)
  body.gsub(PACK_ASSET_TAG) do
    path = Regexp.last_match(1)
    table[path] or
      raise "#{name} asks for #{path}, which the pack does not hold.\n" \
            "  it holds: #{table.keys.sort.join(', ')}"
  end
end

# The order the naming gives. A file that names no other file is ready at
# once; one that names files is ready when all of them are hashed. Two
# files that name each other have no order, and that is refused by name.
def pack_fill_all(files, pages)
  table = {}
  left = files.dup
  filled = {}
  until left.empty?
    ready = left.reject do |name, data|
      pack_text?(name) &&
        data.scan(PACK_ASSET_TAG).flatten.uniq.any? { |path| !table.key?(path) }
    end
    if ready.empty?
      waiting = left.map do |name, data|
        want = data.scan(PACK_ASSET_TAG).flatten.uniq.reject { |path| table.key?(path) }
        "#{name} waits for #{want.join(', ')}"
      end
      raise "these files name each other, or name what the pack does not hold:\n  " +
            waiting.join("\n  ")
    end
    ready.each do |name, data|
      out = pack_text?(name) ? pack_fill(name, data, table) : data
      filled[name] = out
      # A page answers under its own name; only a leaf gets a hashed one.
      table["/#{name}"] = pages.include?(name) ? "/#{name}" : "/#{pack_hashed_name(name, out)}"
      left.delete(name)
    end
  end
  [filled, table]
end

# What a pack already holds, read from its central directory: the name,
# the extra field, and where the local record lies. The bytes themselves
# are not read - they stay where they are.
def pack_read(path)
  return [+''.b, []] unless File.exist?(path)

  raw = File.binread(path)
  eocd = raw.rindex([0x06054b50].pack('V'))
  raise "#{path} has no end record - it is not a zip this task wrote" if eocd.nil?

  count, cd_size, cd_off = raw[eocd + 10, 12].unpack('vVV')
  old = []
  at = cd_off
  count.times do
    raise "#{path}: broken central directory" unless raw[at, 4] == [0x02014b50].pack('V')

    method, dtime, ddate, crc, csize, usize, nlen, elen, clen =
      raw[at + 10, 24].unpack("vvvVVVvvv")
    lho = raw[at + 42, 4].unpack1('V')
    name = raw[at + 46, nlen]
    extra = raw[at + 46 + nlen, elen]
    old << { name: name, extra: extra, method: method, dtime: dtime, ddate: ddate,
             crc: crc, csize: csize, usize: usize, lho: lho }
    at += 46 + nlen + elen + clen
  end
  raise "#{path}: central directory is #{at - cd_off} bytes, not #{cd_size}" if
    at - cd_off != cd_size

  # Everything up to the central directory is the part that never moves.
  [raw[0, cd_off], old]
end

# What decides that an entry already in the pack is this entry: its
# name, which is a hash of the bytes, its CRC, and what the pack says
# about it - the lifetime and the plain name. The modification time is
# none of that: touch(1) on an unchanged file must not write it again.
def pack_same(old, crc, extra)
  old[:crc] == crc && pack_extra_without_time(old[:extra]) == pack_extra_without_time(extra)
end

# The extra field with the timestamp block taken out. APPNOTE 4.5.2: a
# block is (id, size, payload), and a reader skips the ids it does not
# know - so this drops one id and keeps the rest in order.
def pack_extra_without_time(extra)
  out = +''.b
  at = 0
  while at + 4 <= extra.bytesize
    id, size = extra[at, 4].unpack('vv')
    break if at + 4 + size > extra.bytesize

    out << extra[at, 4 + size] unless id == 0x5455
    at += 4 + size
  end
  out
end

def pack_central(e)
  [0x02014b50, 20, 20, 0, e[:method], e[:dtime], e[:ddate], e[:crc], e[:csize], e[:usize],
   e[:name].bytesize, e[:extra].bytesize, 0, 0, 0, 0, e[:lho]]
    .pack('VvvvvvvVVVvvvvvVV') << e[:name].b << e[:extra].b
end

# Append only. A pack that is written a second time keeps every byte it
# already has where it already is: the local records stay at their
# offsets, and this writes the new records after them and one fresh
# central directory over both. ZIP is built for that - the directory is
# at the end and names an offset per entry.
#
# Two things follow, and both are what a running server wants:
#
#   an entry the build makes again, byte for byte, is already there. Its
#   hashed name is the same, so nothing is appended and nothing is
#   deflated a second time;
#
#   an entry the build no longer makes stays in the directory. That is
#   how a link somebody's browser wrote down two minutes ago still
#   answers: a hashed name means the same bytes forever, so the old one
#   is never wrong, only old.
#
# A page is the exception, because a page is not named by its content: a
# new one is appended and the directory names the new record. The old
# record stays in the file as dead space, which is what `compact` clears.
def pack_write(path, entries, compact: false)
  base, old = compact ? [+''.b, []] : pack_read(path)
  out = base.dup
  kept = old.to_h { |e| [e[:name], e] }
  fresh = {}
  appended = 0

  entries.each do |name, data, mtime, cache_control, plain|
    data = data.b
    ddate, dtime = dos_stamp(mtime)
    crc = Zlib.crc32(data)
    extra = pack_entry_extra(mtime, plain, cache_control)
    # An entry already in the pack under this name holds these bytes -
    # the name is a hash of them - and says the same thing about them.
    # There is nothing to write, and nothing to deflate a second time.
    if kept[name] && pack_same(kept[name], crc, extra)
      fresh[name] = kept[name]
      next
    end

    stored = PACK_STORED.include?(File.extname(name).downcase)
    body = stored ? data : Zlib::Deflate.deflate(data, 9)[2..-5]
    # A file that grows under deflate is stored instead.
    if !stored && body.bytesize >= data.bytesize
      stored = true
      body = data
    end
    lho = out.bytesize
    out << [0x04034b50, 20, 0, stored ? 0 : 8, dtime, ddate, crc, body.bytesize,
            data.bytesize, name.bytesize, extra.bytesize].pack('VvvvvvVVVvv') <<
           name.b << extra << body
    fresh[name] = { name: name, extra: extra, method: stored ? 0 : 8, dtime: dtime,
                    ddate: ddate, crc: crc, csize: body.bytesize, usize: data.bytesize,
                    lho: lho }
    appended += 1
  end

  # The old names this build did not make again. A hashed one is kept -
  # it is an old link that still answers. A plain one is dropped: it is
  # a page or a file that is not part of the site any more.
  gone = kept.reject { |name, _e| fresh.key?(name) || !name.match?(PACK_HASHED) }
  all = fresh.values + gone.values
  cd = +''.b
  all.each { |e| cd << pack_central(e) }
  cd_off = out.bytesize
  # What the file holds that no entry names any more: the records of
  # pages that were replaced, and of anything an older build wrote
  # differently. It is why the file can grow while the number of names
  # does not, so the task says it rather than leaving it to be found in
  # ls(1).
  live = all.sum { |e| 30 + e[:name].bytesize + e[:extra].bytesize + e[:csize] }
  dead = cd_off - live
  out << cd
  out << [0x06054b50, 0, 0, all.size, all.size, cd.bytesize, cd_off, 0].pack('VvvvvVVv')

  # Never in place. A running server has this file mapped, and a mapping
  # follows the inode, not the name. Writing over it would show the
  # server a half-written pack, and File.binwrite truncates first.
  #
  # What that costs depends on who reads. On h1 the mapped bytes go to
  # the kernel as iovecs (Assets::wire_iov), and a truncated mapping
  # fails the send. On h2 the server copies them itself
  # (Assets::copy_wire, src/http2.cpp) - a read past the end of a
  # mapping in this process is SIGBUS, which kills the server instead of
  # failing one request.
  #
  # So the pack is written beside the old one and renamed over it.
  # rename(2) only swaps the directory entry: the old inode stays alive
  # for as long as anybody holds it open or mapped, so the server keeps
  # a whole and correct view until it opens the path again.
  tmp = "#{path}.#{Process.pid}.new"
  File.open(tmp, 'wb') do |f|
    f.write(out)
    f.fsync
  end
  File.rename(tmp, path)
  { appended: appended, reused: fresh.size - appended, kept: gone.size, names: all.size,
    dead: dead }
end

desc 'pack a directory for --assets: rake pack[DIR,OUT.zip,compact]'
task :pack, %i[dir out compact] do |_t, args|
  require 'zlib'
  dir = args[:dir] or raise 'rake pack[DIR,OUT.zip] - which directory?'
  raise "#{dir} is not a directory" unless File.directory?(dir)

  out = args[:out] || "#{File.basename(File.expand_path(dir))}.zip"
  root = File.expand_path(dir)
  # Files only, sorted, and nothing whose name begins with a dot - an
  # editor's swap file, a .git directory and .cache-rules itself are not
  # part of a site.
  names = Dir.glob('**/*', File::FNM_DOTMATCH, base: root).sort.reject do |n|
    n.split('/').any? { |seg| seg.start_with?('.') } || File.directory?(File.join(root, n))
  end
  raise "#{dir} holds no files" if names.empty?

  # A page is an HTML document: what somebody calls, bookmarks and links
  # to. Everything else is a leaf, which is what a page embeds.
  pages = names.select { |n| %w[.html .htm].include?(File.extname(n).downcase) }

  rules_path = File.join(root, PACK_RULES_FILE)
  rules = read_cache_rules(rules_path)
  $pack_text = pack_text_extensions(root)
  wanted = names.group_by { |n| File.extname(n).downcase }
  missing = wanted.keys.sort.reject { |ext| rules.key?(ext) }
  unless missing.empty?
    puts "#{rules_path}: #{missing.size} extension(s) with no rule yet."
    missing.each { |ext| rules[ext] = ask_cache_seconds(ext, wanted[ext].size) }
    write_cache_rules(rules_path, rules)
  end

  files = names.to_h { |n| [n, File.binread(File.join(root, n))] }
  filled, table = pack_fill_all(files, pages)

  # What goes into the pack, name by name. A page is one entry under the
  # name people call. Everything else is two: the hashed name, which is
  # where the bytes lie, and the plain name, which the server answers
  # from the same bytes with the lifetime this site decided.
  entries = []
  names.each do |n|
    data = filled[n]
    mtime = File.mtime(File.join(root, n))
    cache = pack_cache_control(rules[File.extname(n).downcase])
    if pages.include?(n)
      entries << [n, data, mtime, cache, nil]
    else
      entries << [pack_hashed_name(n, data), data, mtime, cache, n]
    end
  end

  said = pack_write(out, entries, compact: args[:compact].to_s == 'compact')
  puts "#{out}: #{names.size} files, #{said[:names]} names, #{File.size(out)} bytes " \
       "(#{said[:appended]} appended, #{said[:reused]} already there, " \
       "#{said[:kept]} older name(s) still answering)"
  if said[:dead] > 0
    puts "  #{said[:dead]} bytes no name points at any more - " \
         "rake pack[#{dir},#{out},compact] writes the file without them"
  end
  names.each do |n|
    puts "  /#{n}  #{pack_cache_control(rules[File.extname(n).downcase])}"
    puts "    /#{pack_hashed_name(n, filled[n])}  #{PACK_IMMUTABLE}" unless pages.include?(n)
  end
end

desc 'build the example site: examples/site.zip and examples/site.mrb'
task :site do
  Rake::Task[:pack].invoke('examples/site', 'examples/site.zip')
  mrbc = File.expand_path('mruby/bin/mrbc', __dir__)
  raise "#{mrbc} not found - rake compile builds it" unless File.executable?(mrbc)

  sh "#{mrbc} -g -o examples/site.mrb examples/site.rb"
  puts 'now: webmachine-server --app=examples/site.mrb'
end

# Where an installed server lives, by the Filesystem Hierarchy Standard:
# the programs under PREFIX/bin, the package's data under
# PREFIX/share/webmachine-mruby, and its configuration in its own
# directory under PREFIX/etc. The config is written by the server
# itself, naming the archive it was just given, and never over one that
# is there.
desc 'install the ship build: rake install[PREFIX], PREFIX is /usr/local'
task :install, %i[prefix] do |_t, args|
  prefix = args[:prefix] || '/usr/local'
  bin = File.join(prefix, 'bin')
  share = File.join(prefix, 'share', 'webmachine-mruby')
  etc = File.join(prefix, 'etc', 'webmachine')
  host_bin = File.expand_path('mruby/build/host/bin', __dir__)
  programs = %w[webmachine-server webmachine-logd webmachine-passwd]
  mrbc = File.expand_path('mruby/build/host/mrbc/bin/mrbc', __dir__)
  missing = programs.reject { |p| File.executable?(File.join(host_bin, p)) }
  raise "no ship build at #{host_bin}: #{missing.join(', ')} - run rake ship_smoke first" unless missing.empty?
  raise "no mrbc at #{mrbc}" unless File.executable?(mrbc)

  [bin, share, etc].each { |d| mkdir_p d }
  programs.each { |p| install File.join(host_bin, p), bin, mode: 0o755 }
  install mrbc, bin, mode: 0o755
  archive = File.join(share, 'error-assets.zip')
  install ERROR_ASSETS, archive, mode: 0o644
  conf = File.join(etc, 'webmachine.toml')
  if File.exist?(conf)
    puts "#{conf} is there and is kept"
  else
    sh "#{File.join(bin, 'webmachine-server')} --error-assets=#{archive} --write-config=#{conf}"
  end
end

# The reference config in this tree is generated, and by the server
# itself: --write-config states every knob it reads, and a second copy
# written by hand is a second answer that goes stale on the first change.
desc 'regenerate webmachine.toml.example from the server itself'
task :config_example => :compile do
  out = File.expand_path('webmachine.toml.example', __dir__)
  bin = File.expand_path('mruby/bin/webmachine-server', __dir__)
  raise "#{bin} not found - rake compile builds it" unless File.executable?(bin)

  rm_f out
  sh "#{bin} --write-config=#{out}"
  puts "webmachine.toml.example: #{File.readlines(out).size} lines"
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
