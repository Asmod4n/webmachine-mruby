module Webmachine
  class Application
    attr_reader :conf
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
  # context: status, title, source, target, and - for a 500 - message and
  # backtrace. cat is present only when the asset pack holds a picture for
  # the status.
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
      .t{margin:0 0 1.6rem;color:var(--dim);font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,
        Consolas,monospace;overflow-wrap:anywhere}
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
      {{#target}}  <p class=t>{{target}}</p>
      {{/target}}{{#cat}}  <img src="{{cat_url}}" width="{{cat_width}}" height="{{cat_height}}"
             alt="A cat, illustrating HTTP {{status}} {{title}}">
      {{/cat}}  <p class=s>{{source}}</p>
      {{#message}}  <p class=m>{{message}}</p>
      {{/message}}{{#cat}}  <p class=c>Cat by <a href="https://girliemac.com/blog/2011/12/18/the-day-i-seized-the-interweb-http-status-cats/">Tomomi Imura</a>, <a href="https://creativecommons.org/licenses/by/2.0/">CC BY 2.0</a>, unchanged
      {{/cat}}</main>

    WM_HTML

    # RFC 9457 problem details: type, title, status, and nothing invented.
    # No cat - whatever reads JSON wants the status, not a picture.
    # {{{ }}} is raw ON PURPOSE: mustache escapes for HTML, and &amp;
    # inside a JSON string would be wrong. json_escape below does the job
    # this format actually needs.
    JSON = Mustache::Template.compile(<<~'WM_JSON')
      {"type":"about:blank","title":"{{{title}}}","status":{{status}}{{#instance}},"instance":"{{{instance}}}"{{/instance}}{{#message}},"detail":"{{{message}}}"{{/message}}{{#backtrace}},"backtrace":"{{{backtrace}}}"{{/backtrace}}}

    WM_JSON

    # RFC 2046 4.1: when a client will take neither of the first two, it
    # still gets something it can read. No escaping - text/plain
    # interprets no markup, so an escape would only put &amp; in front of
    # a human.
    TEXT = Mustache::Template.compile(<<~'WM_TEXT')
      {{status}} {{{title}}}
      {{#target}}{{{target}}}
      {{/target}}{{#message}}
      {{{message}}}
      {{/message}}
      {{{source}}}

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

    # The target becomes RFC 9457's "instance": the member that names the
    # specific occurrence.
    def json_escaped(e)
      out = { 'status' => e['status'], 'title' => json_escape(e['title'].to_s) }
      out['instance'] = json_escape(e['target'].to_s) if e['target']
      out['message'] = json_escape(e['message'].to_s) if e['message']
      out['backtrace'] = json_escape(e['backtrace'].to_s) if e['backtrace']
      out
    end
  end
end
