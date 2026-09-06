# The example site

Four pages that use one server. The pages, the stylesheet, htmx and the
photographs are **files**, and they are in this directory. Nothing here
is written by Ruby. The parts of a page that change come from
`examples/site.rb`, one resource each.

    index.html    htmx asks for three fragments: a clock, a search, a counter
    gallery.html  a row of photographs, and the next row when you scroll
    events.html   an EventSource on /events, opened and closed by hand
    ws.html       a WebSocket on /ws, spoken to with the browser's own object

## Build the pack

The server serves static files from a ZIP. Store the photographs and
send the text compressed:

    cd examples/site
    zip -q -9 -r ../../site.zip . -x README.md 'img/*'
    zip -q -0 -r ../../site.zip img -x 'img/SOURCES.md'

The second line stores the photographs, because a JPEG does not
compress. A stored entry goes out as it lies; a deflated one goes out as
gzip, and a client that says it cannot take gzip gets a 406.

## Compile the app

    mruby/bin/mrbc -o site.mrb examples/site.rb

## Run the two together

    mruby/bin/webmachine-server --port=8080 --app=site.mrb --assets=site.zip

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
