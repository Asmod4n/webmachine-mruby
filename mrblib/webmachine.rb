module Webmachine
  module Workers
    # #30: the response a compute task speaks to. It has one thing, and
    # it is the same one the run has at home: what the application
    # carries from one callback to the next. The worker fills it before
    # the block runs and reads it after.
    class Response
      attr_accessor :userdata
    end

    def self.response
      @response ||= Response.new
    end

    # The block of a compute task, and its arguments, made into a proc
    # that takes none.
    #
    # mruby-task starts a proc WITHOUT arguments: mrb_create_task takes
    # none, and mrb_execute_proc_synchronously ignores the ones it is
    # given ("reserved for future use"). So the worker closes over them
    # here, inside its own VM, where closing over is allowed - the ban
    # is on DUMPING an environment, not on making one.
    #
    # A task body must be Ruby. task_init_context reads
    # proc->body.irep, so a proc built from a C function has nothing the
    # scheduler could run.
    #
    # It lives in mrblib because mrbc translates mrblib at BUILD time. A
    # ship build carries no mruby-compiler, so a worker cannot translate
    # a string of Ruby when it opens its VM.
    def self.wrap(block, args)
      proc { block.call(*args) }
    end
  end
end

module Webmachine
  class Application
    attr_reader :conf
  end

  # The configuration, and nothing but the values in it.
  #
  # A Struct is a Ruby Array with names on its slots - MRB_TT_STRUCT is
  # struct RArray in mruby's value.h - which is exactly what is wanted for
  # handing a set of values to someone else: Ruby collects them, C++ walks
  # the array once at registration and decides what they mean. It is its
  # own type tag though, so the C side checks MRB_TT_STRUCT; mrb_array_p
  # says no to a Struct.
  #
  # There is no writer here, no validation and no parsing. Every ceiling
  # (kZeroCopyMax, kFileMapMax), every refusal and the whole grammar of
  # conf.url live in application.cpp, where they lived before - one rule
  # per knob, in one place. What this file decides is the ORDER, because
  # the array is read by index: ConfIdx in application.cpp mirrors this
  # list and the two are checked against each other at registration.
  #
  # Struct also draws the line the config URL needs. `c[:add_route] = x`
  # is a NameError - "no member 'add_route' in struct" - because []= can
  # only reach a member, never a method. Routes name classes and stay in
  # Ruby code; nothing a URL or a config file says can reach them.
  class Config < Struct.new(:port, :unix_path, :url, :docroot, :certificate,
                            :private_key, :file_map_threshold, :zero_copy_threshold,
                            :disable_http_cats)
    # A refusal belongs where it was caused. bintest calls this "catchable
    # BY CLASS, not by luck": an app may write
    #
    #   begin
    #     conf.port = 99999
    #   rescue Webmachine::ConfigError => e
    #
    # and that only works if the refusal happens on THAT line, not when
    # the block ends. So the writers refuse here, in the words they had
    # when they were C setters, and read_config checks the same bounds
    # again on the way out - Struct#[]= reaches a member without passing
    # a writer, so this is not the last word on any of it.
    #
    # The numbers are NOT written down here: PORT_MAX, FILE_MAP_MAX and
    # ZERO_COPY_MAX come from application.cpp, which is where the code
    # that honours them lives.
    def port=(v)
      Config.whole(v, PORT_MAX, 'port', '')
      self[:port] = v
    end

    def file_map_threshold=(v)
      Config.whole(v, FILE_MAP_MAX, 'file_map_threshold', ' bytes')
      self[:file_map_threshold] = v
    end

    def zero_copy_threshold=(v)
      Config.whole(v, ZERO_COPY_MAX, 'zero_copy_threshold', ' bytes')
      self[:zero_copy_threshold] = v
    end

    def unix_path=(v)
      Config.text(v, 'unix_path')
      self[:unix_path] = v
    end

    def docroot=(v)
      Config.text(v, 'docroot')
      self[:docroot] = v
    end

    def certificate=(v)
      Config.text(v, 'certificate')
      self[:certificate] = v
    end

    def private_key=(v)
      Config.text(v, 'private_key')
      self[:private_key] = v
    end

    # conf.url is not checked here: its grammar - the scheme, the IPv6
    # literal, the settings its query may name - is ada's and
    # application.cpp's, and there is no second copy of it in Ruby.
    def self.whole(v, ceiling, name, unit)
      raise ConfigError, "conf.#{name} wants an Integer" unless v.is_a?(Integer)
      return if v >= 0 && v <= ceiling

      raise ConfigError, "conf.#{name} = #{v} is outside 0..#{ceiling}#{unit}"
    end

    def self.text(v, name)
      raise ConfigError, "conf.#{name} wants a String" unless v.is_a?(String)
      raise ConfigError, "conf.#{name} is empty" if v.empty?
    end
  end

  # #210: the error resource. Always there, never routed - the route that
  # produced the error calls it, so an error is delivered by whoever made
  # it and not by a second trip through the router.
  #
  # It declares content_types_provided like any other resource, and that
  # list is the whole negotiation. Adding a format means reopening the
  # class, naming the type and writing the method:
  #
  #   class Webmachine::ErrorResource
  #     def self.content_types_provided
  #       super + [['application/xml', :to_xml_error]]
  #     end
  #
  #     def to_xml_error(e)
  #       "<error status=\"#{e['status']}\">#{e['title']}</error>"
  #     end
  #   end
  #
  # Every handler is handed the same Hash, which is also the template
  # context: status, title, source, and - for a 500 - id, message and, in
  # a debug build, backtrace. cat is present only when the asset pack
  # holds a picture for the status.
  #
  # handle_exception lives here too, and only here.
  class ErrorResource
    # The same word an ordinary resource uses, and for the same reason:
    # this is the list Accept is weighed against (RFC 9110 12.5.1, q-values
    # and all). Order breaks ties, so the first entry is what a client with
    # no opinion gets. Adding a format is one line here and one method
    # below - the server reads this list and nothing else.
    #
    # RFC 9457 3: a problem document is application/problem+json, which is
    # not what the MIME database says .json is. That is why the list is
    # written out rather than derived from a file extension.
    def self.content_types_provided
      [['text/html; charset=utf-8', :to_html_error],
       ['application/problem+json', :to_json_error],
       # A browser fetching an <img> sends image/* and nothing this list
       # otherwise has, so it would get a page it cannot render. It can
       # have the picture instead - the same cat the HTML page links to,
       # as the whole body. This form has NO method: the picture is not
       # rendered, it IS the asset, and the server lends it straight out
       # of the error assets's mapping. It is offered only while the error assets holds a
       # cat for the status.
       ['image/jpeg', :from_the_pack],
       # RFC 6839 3.1: +json is its own media type, so a client that
       # asked for application/json has NOT asked for problem+json. It
       # meant the same thing, though, so the same handler answers both -
       # and the wire gets whichever of the two it named.
       ['application/json', :to_json_error],
       ['text/plain; charset=utf-8', :to_text_error]]
    end

    # ONE template for every status. What differs between a 404 and a 503
    # is three strings and a picture, and a template is the shape that
    # says so. {{ }} escapes, which is the whole reason the target and the
    # exception message go through here at all.
    HTML = Mustache::Template.compile(<<~'WM_HTML')
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
      {{#cat}}  {{{cat_tag}}}
      {{/cat}}  <p class=s>{{source}}</p>
      {{#message}}  <p class=m>{{message}}</p>
      {{/message}}{{#backtrace}}  <p class=m>{{backtrace}}</p>
      {{/backtrace}}{{#id}}  <p class=s>Reference {{id}}</p>
      {{/id}}{{#cat}}  <p class=c>Cat by <a href="https://girliemac.com/blog/2011/12/18/the-day-i-seized-the-interweb-http-status-cats/">Tomomi Imura</a>, <a href="https://creativecommons.org/licenses/by/2.0/">CC BY 2.0</a>, unchanged
      {{/cat}}</main>

    WM_HTML

    # RFC 9457 problem details: type, title, status, and nothing invented.
    # No cat - whatever reads JSON wants the status, not a picture.
    # {{{ }}} is raw ON PURPOSE: mustache escapes for HTML, and &amp;
    # inside a JSON string would be wrong. json_escape below does the job
    # this format actually needs.
    JSON = Mustache::Template.compile(<<~'WM_JSON')
      {"type":"about:blank","title":"{{{title}}}","status":{{status}}{{#id}},"id":"{{{id}}}"{{/id}}{{#message}},"detail":"{{{message}}}"{{/message}}{{#backtrace}},"backtrace":"{{{backtrace}}}"{{/backtrace}}}

    WM_JSON

    # RFC 2046 4.1: when a client will take neither of the first two, it
    # still gets something it can read. No escaping - text/plain
    # interprets no markup, so an escape would only put &amp; in front of
    # a human.
    TEXT = Mustache::Template.compile(<<~'WM_TEXT')
      {{status}} {{{title}}}
      {{#message}}
      {{{message}}}
      {{/message}}
      {{{source}}}
      {{#backtrace}}
      {{{backtrace}}}
      {{/backtrace}}{{#id}}Reference {{{id}}}
      {{/id}}
    WM_TEXT

    # fsm.rb's own name for the hook, and the ONE place it exists. A
    # handle_exception on an ordinary resource is ignored: how an
    # exception becomes text is one decision for the whole server, not a
    # per-route one, and this is where it is made.
    #
    # An exception only reaches here when app code raised and nothing
    # handled it - a bug, not a controlled refusal, which is what
    # response.code is for.
    #
    # The ONE thing the server fixes is the shape of the answer: a String,
    # or an Array, which it joins with CRLF. Everything else is yours -
    # whether the backtrace goes into the PAGE is your call, not the
    # server's (--error-log carries it either way):
    #
    #   def handle_exception(e)
    #     ["#{e.class}: #{e.message}", *e.backtrace]
    #   end
    #
    # Answer nil and a 500 is just "500".
    def handle_exception(e)
      "#{e.class}: #{e.message}"
    end

    def to_html_error(e)
      HTML.render(e)
    end

    def to_json_error(e)
      JSON.render(json_escaped(e))
    end

    def to_text_error(e)
      TEXT.render(e)
    end

    private

    # RFC 8259 7: the characters a JSON string may not carry raw. The
    # template takes these values through {{{ }}}, so the encoding is this
    # method's job.
    JSON_ESCAPES = {
      '"' => '\\"', '\\' => '\\\\', "\b" => '\\b', "\f" => '\\f',
      "\n" => '\\n', "\r" => '\\r', "\t" => '\\t'
    }.freeze

    def json_escape(s)
      out = ''
      s.each_char do |c|
        out << (JSON_ESCAPES[c] || (c.ord < 0x20 ? format('\\u%04x', c.ord) : c))
      end
      out
    end

    # RFC 9457 names an "instance" member for the specific occurrence. It
    # would be the request target, and an error page carries nothing the
    # client sent - the access log is where a request is named.
    def json_escaped(e)
      out = { 'status' => e['status'], 'title' => json_escape(e['title'].to_s) }
      out['id'] = e['id'] if e['id']
      out['message'] = json_escape(e['message'].to_s) if e['message']
      out['backtrace'] = json_escape(e['backtrace'].to_s) if e['backtrace']
      out
    end
  end

end
