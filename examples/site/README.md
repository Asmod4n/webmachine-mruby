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

## Two names for one file

Every file that a page embeds goes into the pack under two names: the
one you gave it, and the same name with a hash of its content in it -
`site.css` and `site.60b5e09bbd47.css`. Both are one copy of the bytes.

The two names get different answers, and that is the point:

    /site.60b5e09bbd47.css   public, max-age=31536000, immutable
    /site.css                public, max-age=3600

The hashed name cannot ever mean other bytes, so a browser may keep it
for a year and never ask again. The plain name means whatever is there
now, so it says how long you decided it may be used without asking.

**A page is not embedded, it is called.** So a page keeps its plain name
only. A hashed page address would change with every word on the page,
and then no bookmark and no link from outside would hold.

## Writing the hashed name

A page cannot know a hash before the file is packed, so it writes the
path it means and the pack fills it in:

    <link rel="stylesheet" href="{{asset:/site.css}}">
    <script src="{{asset:/htmx.min.js}}"></script>
    <img src="{{asset:/img/p1015.jpg}}">

`{{asset:PATH}}`, with the real path inside it. The pack refuses, by
name, a path it does not hold. A link to another **page** stays plain:

    <a href="/gallery.html">Gallery</a>

The tag works in every text file in the pack, so a stylesheet writes
`url({{asset:/img/p1015.jpg}})` the same way. The pack does the files in
the order the naming gives, and two files that name each other are
refused rather than looped over.

## Which files get their tags filled

Text files do: `.html`, `.css`, `.js`, `.svg`, `.json`, `.xml` and the
other text extensions `rake pack` knows. To decide it yourself, write
`<DIR>/.fill-extensions`, one extension per line with the dot. That
file replaces the whole list.

## How long is yours to say

`rake pack` asks, once per file extension, and writes the answers into
`<DIR>/.cache-rules` beside the files:

    .css     3600
    .html    300
    .jpg     604800

A page gets a few minutes, not nothing: a reader who walks a site comes
back to the page they just left, and those 300 seconds cost no request
at all. It is short enough that a correction is visible while the person
who made it is still watching. A lifetime of 0 means `no-cache` - keep
the file, but ask before using it, which the ETag then answers with a
304 and no body.

## Run it

    mruby/bin/webmachine-server --app=examples/site.mrb

The application names its port and its pack: `app.conf.port = 8080`
and `app.conf.assets = 'examples/site.zip'` in `examples/site.rb`.

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
