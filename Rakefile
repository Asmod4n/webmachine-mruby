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
  418 => ['(Unused)',                        'RFC 9110 reserves it; RFC 2324 made the joke'],
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

  errors/error.html      the page TEMPLATE (mustache)
  errors/error.json      the problem-document TEMPLATE (mustache)
  cats/<status>.jpg      the pictures, see below

  The server renders these ONCE at startup, one page per status it can
  answer with, and emits the result as the body of the response that
  failed. Nothing in here is reached by a request: an error is delivered
  by the route that produced it, not by a second trip through the router.

  Replace either template and the server renders yours instead. The slots
  it fills:

    {{status}}     404
    {{title}}      Not Found
    {{source}}     "RFC 9110", or "nginx, not registered"
    {{#cat}}       present only when this pack holds a picture for the
                   status; inside it, {{cat_url}}, {{cat_width}} and
                   {{cat_height}}
    {{#message}}   the 500 only: what the resource's handle_exception
                   returned - webmachine-ruby's own name for the hook -
                   or, when it defines none, the exception message and
                   its backtrace. Escaped by {{ }}, which is the whole
                   reason this goes through a template
    {{#backtrace}} the json template's own slot for the frames

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

# ONE template for every status. What differs between a 404 and a 503 is
# three strings and a picture, and a template is the shape that says so.
# Rendered once at startup - nothing in here costs a request.
ERROR_HTML_TEMPLATE = <<~HTML
  <!doctype html>
  <html lang=en>
  <meta charset=utf-8>
  <meta name=viewport content="width=device-width,initial-scale=1">
  <title>{{status}} {{title}}</title>
  <style>
  :root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1a1a1a;--dim:#6b6b6b;--rule:#e2e2df}
  @media (prefers-color-scheme:dark){
    :root{--bg:#15161a;--fg:#e8e8e6;--dim:#8a8a92;--rule:#2a2c33}}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:var(--bg);color:var(--fg);padding:2rem 1rem;
    font:16px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  main{max-width:40rem;text-align:center}
  .n{font-size:clamp(3.5rem,14vw,6rem);font-weight:700;letter-spacing:-.04em;
    line-height:1;margin:0;font-variant-numeric:tabular-nums}
  h1{font-size:clamp(1.1rem,4vw,1.5rem);font-weight:600;margin:.4rem 0 1.6rem}
  img{max-width:100%;height:auto;border-radius:.6rem;display:block;margin:0 auto}
  .s{margin:1.6rem 0 0;color:var(--dim);font-size:.85rem}
  .m{margin:1.2rem 0 0;padding:.8rem 1rem;border-radius:.4rem;background:rgba(127,127,127,.12);
    text-align:left;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    white-space:pre-wrap;overflow-wrap:anywhere}
  .c{margin:1.2rem 0 0;padding-top:1.2rem;border-top:1px solid var(--rule);
    color:var(--dim);font-size:.75rem}
  a{color:inherit}
  </style>
  <main>
    <p class=n>{{status}}</p>
    <h1>{{title}}</h1>
  {{#cat}}  <img src="{{cat_url}}" width="{{cat_width}}" height="{{cat_height}}"
         alt="A cat, illustrating HTTP {{status}} {{title}}">
  {{/cat}}  <p class=s>{{source}}</p>
  {{#message}}  <p class=m>{{message}}</p>
  {{/message}}{{#cat}}  <p class=c>Cat by <a href="https://girliemac.com/blog/2011/12/18/the-day-i-seized-the-interweb-http-status-cats/">Tomomi Imura</a>, <a href="https://creativecommons.org/licenses/by/2.0/">CC BY 2.0</a>, unchanged
  {{/cat}}</main>
HTML

# RFC 9457 problem details: type, title, status, and nothing invented. No
# cat - whatever reads JSON wants the status, not a picture. "detail" is
# the member RFC 9457 reserves for exactly what the 500 has to say, and it
# appears only when there is something to say.
#
# {{{...}}} is raw ON PURPOSE: mustache escapes for HTML, and &amp; inside
# a JSON string would be wrong. The titles come from the server's own
# table; the message is JSON-escaped by the server before it gets here,
# because that is an encoding job and not a template's.
ERROR_JSON_TEMPLATE = <<~JSON
  {"type":"about:blank","title":"{{{title}}}","status":{{status}}{{#message}},"detail":"{{{message}}}"{{/message}}{{#backtrace}},"backtrace":"{{{backtrace}}}"{{/backtrace}}}
JSON

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
  cats = {}
  ERROR_STATUS.each_key do |code|
    body = begin
      URI.parse("https://http.cat/#{code}.jpg").open(
        'User-Agent' => 'webmachine-mruby error-pages packer', read_timeout: 20
      ) { |f| f.read }
    rescue StandardError
      next
    end
    next unless body.b.start_with?("\xFF\xD8".b)
    cats[code] = body.b
    print "#{code} "
  end
  puts
  raise 'http.cat answered with no images at all' if cats.empty?

  # TWO templates, not a page per status. What differs between a 404 and a
  # 503 is three strings and a picture; the server holds the table and
  # renders once at startup.
  entries = [['NOTICE.txt', ERROR_NOTICE],
             ['errors/error.html', ERROR_HTML_TEMPLATE],
             ['errors/error.json', ERROR_JSON_TEMPLATE]]
  cats.keys.sort.each { |code| entries << ["cats/#{code}.jpg", cats[code]] }
  File.binwrite(ERROR_PACK, error_zip(entries))
  puts "share/error-pages.zip: 2 templates, #{cats.size} cats, " \
       "#{entries.size} entries, #{File.size(ERROR_PACK)} bytes"
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
