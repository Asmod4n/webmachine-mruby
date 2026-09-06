# The example site

Four pages that use one server. The pages, the stylesheet, htmx and the
photographs are **files**, and they are in this directory. Nothing here
is written by Ruby. The parts of a page that change come from
`examples/site.rb`, one resource each.

    index.html    htmx asks for three fragments: a clock, a search, a counter
    gallery.html  a row of photographs, and the next row when you scroll
    events.html   an EventSource on /events, opened and closed by hand
    ws.html       a WebSocket on /ws, spoken to with the browser's own object

## Build it

One task builds both halves - the pack and the bytecode:

    rake site

That writes `examples/site.zip` and `examples/site.mrb`. Neither is in
git; both are build output, and the files they are built from are here.

`rake pack[DIR,OUT.zip]` does the pack half for any directory, so a site
of your own needs no new task:

    rake pack[public,public.zip]

The pack stores what does not compress (a JPEG, a font, a video) and
deflates the rest. That matters: a deflated entry leaves the server as
gzip, to every client, so a stored JPEG is what makes `curl -o` save a
JPEG.

## Run it

    mruby/bin/webmachine-server --port=8080 \
        --app=examples/site.mrb --assets=examples/site.zip

Then open <http://127.0.0.1:8080/>. The root of the pack answers `/`,
because a path that names a directory takes that directory's
`index.html`.

## What answers what

    /                     index.html, from the pack
    /site.css /htmx.min.js /img/*.jpg   from the pack
    /fragment/time        the server's clock, as one element
    /fragment/search?q=   the matching list items
    /fragment/count       GET reads it, POST raises it, DELETE clears it
    /fragment/photos?page=N   two figures, and the ask for the page after
    /events               text/event-stream, one line a second
    /ws                   a websocket that numbers what you send it

htmx is version 2.0.10, MIT licensed. The photographs and their licence
are named in `img/SOURCES.md`.
