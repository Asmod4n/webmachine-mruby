# The directory listing --listings switches on.
#
# It is an ordinary application: one resource, one route, and the
# decision graph answers every question about it - which media type the
# client gets, whether the list has changed since the client last saw
# it, which methods are allowed. Nothing here is a special case in the
# server, and a reader who wants to write one like it can read this.
#
# What it may see is not this file's decision. Webmachine.docroot_listing
# opens the directory with openat2 against the docroot descriptor, under
# RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS, so the
# kernel refuses a name that climbs out and this code never has to ask
# whether one did. The same descriptor and the same three flags answer
# response.file, so the list and the files it links to see one docroot.
#
# The file tier hands this application every target that ends in a
# slash, and keeps every other one: a plain file is served with no route
# and no VM entry, as it was before --listings existed.
module Webmachine
  class Listing < Resource
    # One template. {{ }} escapes, which is why a file name - a name this
    # server did not choose and cannot constrain - goes through it.
    HTML = Mustache::Template.compile(<<~'WM_LIST')
      <!doctype html>
      <html lang=en>
      <meta charset=utf-8>
      <meta name=viewport content="width=device-width,initial-scale=1">
      <title>{{path}}</title>
      <style>
      :root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1a1a1a;--dim:#6b6b6b;--rule:#e2e2df}
      @media (prefers-color-scheme:dark){
        :root{--bg:#15161a;--fg:#e8e8e6;--dim:#8a8a92;--rule:#2a2c33}}
      *{box-sizing:border-box}
      body{margin:0;background:var(--bg);color:var(--fg);padding:2.5rem 1.25rem;
        font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
      main{max-width:56rem;margin:0 auto}
      h1{font:600 1.05rem/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
        margin:0 0 1.5rem;overflow-wrap:anywhere}
      table{border-collapse:collapse;width:100%}
      th{text-align:left;font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;
        color:var(--dim);font-weight:600;padding:0 1rem .5rem 0;border-bottom:1px solid var(--rule)}
      td{padding:.45rem 1rem .45rem 0;border-bottom:1px solid var(--rule);
        font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
      td.size,th.size{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
      td.when,th.when{color:var(--dim);white-space:nowrap;padding-right:0}
      th.when{padding-right:0}
      a{color:inherit;text-decoration:none}
      a:hover{text-decoration:underline}
      .dir a{font-weight:600}
      .c{margin:1.5rem 0 0;color:var(--dim);font-size:.8rem}
      </style>
      <main>
        <h1>{{path}}</h1>
        <table>
          <thead><tr><th>Name</th><th class=size>Size</th><th class=when>Last modified</th></tr></thead>
          <tbody>
      {{#parent}}      <tr class=dir><td><a href="../">../</a></td><td class=size></td><td class=when></td></tr>
      {{/parent}}{{#entries}}      <tr{{#directory}} class=dir{{/directory}}><td><a href="{{href}}">{{label}}</a></td><td class=size>{{size}}</td><td class=when>{{when}}</td></tr>
      {{/entries}}    </tbody>
        </table>
      {{#empty}}    <p class=c>This directory is empty.</p>
      {{/empty}}{{#truncated}}    <p class=c>The list stops at {{limit}} names.</p>
      {{/truncated}}  <p class=c>{{count}}.</p>
      </main>
    WM_LIST

    MONTHS = %w[Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec].freeze

    # RFC 9110 9.1: a list is read, never written.
    def self.allowed_methods
      %w[GET HEAD]
    end

    # The same list, for a reader and for a program. The graph weighs the
    # client's Accept and calls whichever of the two it named.
    def self.content_types_provided
      [['text/html; charset=utf-8', :to_html],
       ['application/json', :to_json_list]]
    end

    # A size a reader takes in at a glance. Whole octets up to a
    # kibibyte, one decimal above it - the unit is what carries the
    # magnitude, and a third digit adds nothing to it.
    #: (Integer) -> String
    def self.human_size(n)
      return "#{n} B" if n < 1024

      # The first division is the one that makes KiB, so it happens before
      # the walk and `unit` stays at units[0]. Counting it as a step named
      # every size one unit too large: 307200 octets read "300.0 MiB".
      units = %w[KiB MiB GiB TiB PiB]
      value = n / 1024.0
      unit = 0
      while value >= 1024.0 && unit < units.length - 1
        value /= 1024.0
        unit += 1
      end
      tenths = (value * 10.0 + 0.5).to_i
      # 1023.97 KiB rounds to 1024.0, which is a unit that reads wrong.
      # Carrying it is one step, and there is never a second: the carry
      # lands on 1.0 of the next unit.
      if tenths >= 10240 && unit < units.length - 1
        tenths = 10
        unit += 1
      end
      "#{tenths / 10}.#{tenths % 10} #{units[unit]}"
    end

    # mruby's Time has no strftime, so the stamp is spelled here. UTC,
    # because a server and the person reading its list are not always in
    # one place, and a date without a zone says nothing.
    #: (Integer) -> String
    def self.stamp(epoch)
      return '' if epoch.nil? || epoch.zero?

      t = Time.at(epoch).utc
      format('%04d-%s-%02d %02d:%02d', t.year, MONTHS[t.month - 1], t.day, t.hour, t.min)
    end

    # The request path as a directory name: one leading slash, one
    # trailing slash. The file tier only ever hands over a target that
    # already ends in one, and this says so rather than trusting it.
    #: () -> String
    def directory_path
      p = request.path
      p = "/#{p}" unless p.start_with?('/')
      p = "#{p}/" unless p.end_with?('/')
      p
    end

    # RFC 9110 9.3.1: is there a directory at this target? The answer
    # decides 200 against 404, and the graph asks it before anything
    # else this resource does.
    def resource_exists?
      @listing = Webmachine.docroot_listing(directory_path)
      !@listing.nil?
    end

    # The index document of this directory, if it has one. A directory
    # with an index.html answers that document, exactly as it did before
    # --listings existed; the generated list is for a directory with
    # none.
    #: () -> String?
    def index_name
      unless @index_asked
        @index_asked = true
        found = @listing['entries'].find { |e| !e['directory'] && e['name'] == 'index.html' }
        @index_name = found.nil? ? nil : "#{directory_path[1, directory_path.length - 1]}index.html"
      end
      @index_name
    end

    # RFC 9110 8.8.2: when this list last changed. The directory's own
    # mtime moves when a name is added or removed, which is exactly when
    # the list changes, so a client that asks twice gets 304 the second
    # time. An index document answers with its own dates instead - the
    # file machine spells those - so this says nothing then.
    def last_modified
      return nil unless index_name.nil?

      mtime = @listing['mtime']
      mtime.nil? || mtime.zero? ? nil : Time.at(mtime)
    end

    def to_html
      name = index_name
      unless name.nil?
        # The file machine takes it from here: openat2 beneath the same
        # docroot descriptor, statx, and the bytes through the ring.
        response.file = name
        return ''
      end
      HTML.render(page)
    end

    # Not `to_json`: every object already answers that one - mruby-fast-json
    # defines it on Object - so a callback of that name is found on the
    # class before the instance, and a client that asks for JSON gets this
    # class dumped instead of the list. mrblib/webmachine.rb names its own
    # to_json_error for the same reason.
    def to_json_list
      here = directory_path
      {
        'path' => here,
        'truncated' => @listing['truncated'],
        'entries' => @listing['entries'].sort_by { |e| [e['directory'] ? 0 : 1, e['name']] }
                                        .map { |e|
          { 'name' => e['name'],
            'directory' => e['directory'],
            # A directory has a size of its own - the octets the filesystem
            # spends on the list of names in it - and it says nothing about
            # what is under that name. The HTML list leaves the cell empty
            # for the same reason, so the JSON says null rather than a
            # number a reader would take for the size of the contents.
            'size' => e['directory'] ? nil : e['size'],
            'mtime' => e['mtime'],
            'url' => "#{here}#{URI.encode(e['name'])}#{e['directory'] ? '/' : ''}" }
        }
      }.to_json
    end

    # Decide, then do: the whole page as one Hash, and the template puts
    # it on the wire.
    #
    # URI.encode is RFC 3986's unreserved set, which is what one name
    # segment needs: it also encodes '/', and a file name carries no
    # '/' anyway, so a name that somehow did cannot make a second path
    # segment. '#', '?' and '%' each end or redirect a URL where they
    # stand, and they go through it too.
    #: () -> Hash
    def page
      here = directory_path
      rows = @listing['entries'].sort_by { |e| [e['directory'] ? 0 : 1, e['name']] }.map { |e|
        dir = e['directory']
        { 'href' => "#{URI.encode(e['name'])}#{dir ? '/' : ''}",
          'label' => "#{e['name']}#{dir ? '/' : ''}",
          'directory' => dir,
          'size' => dir ? '' : Listing.human_size(e['size']),
          'when' => Listing.stamp(e['mtime']) }
      }
      { 'path' => here,
        'parent' => here != '/',
        'entries' => rows,
        'empty' => rows.empty?,
        'count' => rows.length == 1 ? '1 name' : "#{rows.length} names",
        'truncated' => @listing['truncated'],
        'limit' => Webmachine::LISTING_MAX }
    end
  end

  # The application --listings registers. It names no listener: the
  # operator's --port or --unix is this server's, and the standalone
  # listener is what carries it.
  def self.listing_application
    Application.new do |app|
      app.add_route [:*], Listing
    end
  end
end
