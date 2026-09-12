# Serve static files

This how-to is for an operator who has files to serve and no resource
to write for them. At the end, you serve a directory, a zip pack, or
both, with the right cache headers on every file.

## Two sources, no app at all

`--standalone` serves files and enters no VM: no `--app`, no route, no
Ruby runs per request. Point it at a pack, a directory, or both:

    webmachine-server --standalone --port=8080 --assets=site.zip --docroot=/srv/site

`--assets=FILE.zip` is answered first, from the pack's own mapping.
`--docroot=DIR` is answered next, from disk. Only `GET` and `HEAD`
answer; every other method is 405. A path that names a directory takes
that directory's `index.html`. A name the server does not hold is 404,
and so is a name that climbs out of the directory with `..`.

An application does the same with `app.conf.assets` and
`app.conf.docroot`, set in its own configure block, and the app still
answers its own routes for everything the pack and the docroot do not
hold.

## Build a pack

    rake pack[DIR,OUT.zip]

packs every file under `DIR` into `OUT.zip`. A file whose name, or any
path segment, starts with a dot is skipped. The optional third
argument, the literal word `compact`, writes the zip without entries
no name points to any more.

Point a server at the result:

    app.conf.assets = 'site.zip'

or, standalone:

    webmachine-server --standalone --port=8080 --assets=site.zip

## Two names for one file

Every file the pack holds gets two names: the one you gave it, and the
same name with a hash of its content in it - `site.css` and
`site.60b5e09bbd47.css`. Both are one copy of the bytes.

    /site.60b5e09bbd47.css   public, max-age=31536000, immutable
    /site.css                public, max-age=3600

The hashed name cannot ever mean other bytes, so a browser may keep it
for a year and never ask again. The plain name means whatever is there
now.

An HTML document is stored under its plain name only: a page is not
embedded, it is called, and a hashed page address would change with
every word on the page.

## Writing the hashed name into a page

A page cannot know a hash before the file is packed, so it writes the
path it means and the pack fills it in:

```html
<link rel="stylesheet" href="{{asset:/site.css}}">
<script src="{{asset:/htmx.min.js}}"></script>
<img src="{{asset:/img/p1015.jpg}}">
```

`{{asset:PATH}}`, with the real path inside it. The pack refuses, by
name, a path it does not hold. A link to another page stays plain:

```html
<a href="/gallery.html">Gallery</a>
```

The tag works in every text file the pack fills in, so a stylesheet
writes `url({{asset:/img/p1015.jpg}})` the same way. The pack does the
files in the order the naming gives, and two files that name each
other are refused rather than looped over.

### Which files get their tags filled

Text files do: `.html`, `.css`, `.js`, `.svg`, `.json`, `.xml`, and the
other text extensions `rake pack` knows. To decide it yourself, write
`<DIR>/.fill-extensions`, one extension per line with the dot. That
file replaces the whole list.

## How long a file is yours to keep

`rake pack` asks, once per file extension, and writes the answers into
`<DIR>/.cache-rules` beside the files:

    .css     3600
    .html    300
    .jpg     604800

A lifetime of 0 means `no-cache`: keep the file, but ask before using
it. Every file in the pack also carries an ETag, so a `no-cache` file
still answers 304 and no body when nothing changed.

## Next

- [../tutorial.md](../tutorial.md)
- [accept-uploads.md](accept-uploads.md)
- [../reference/configuration.md](../reference/configuration.md)
- [../reference/command-line.md](../reference/command-line.md)
