# share/

Data this tree ships and reads, as opposed to code it compiles.

## mime.types

Apache httpd's own `docs/conf/mime.types`, verbatim. Its header states
the licence in its own words: *"Although created for httpd, this file
is used by many software systems and has been placed in the public
domain for unlimited redistribution."* Nothing in it conflicts with
this tree's Apache-2.0.

It is the LAST resort, never the first. The server reads the machine's
own database when it has one - `/etc/mime.types`, the apache paths,
`/usr/share/mime/globs2` - because that file belongs to the machine and
says what its operator installed. This one only answers when none of
them exists, and the startup line always names which source actually
answered.

The build compiles it in (see mrbgem.rake): a server that is one
binary cannot rely on a data file being installed beside it. Only the
lines that carry an extension survive that step - the file lists
hundreds of registered types with none, to guide configuration, and
those cannot answer a lookup.

Refresh it verbatim from upstream; do not edit it here:

    curl -o share/mime.types \
      https://raw.githubusercontent.com/apache/httpd/trunk/docs/conf/mime.types

## error-pages.zip

An asset pack holding what the server renders its ERROR PAGES from - two
templates and the pictures:

    errors/error.html   the page template (mustache)
    errors/error.json   the problem-document template (mustache)
    cats/<status>.jpg   the pictures, CC BY 2.0, see below
    NOTICE.txt          the terms, inside the archive

`rake error_pages` fetches and rebuilds it. 58 entries, 1.6 MB.

### It is a source, not a route

An error is delivered by the route that produced it. A page fetched from
`/errors/404.html` would be a second trip through the same router that
just failed to find anything, so nothing in this pack is meant to be
served: the server reads the templates at STARTUP, renders one page per
status it can answer with, and appends the result as the body of the
response that failed. The wire path stays one `append` of prebuilt bytes.

The picture is the one exception, and it is the reason the pack exists at
all: the cats are far too big to compile in, and the server looks them up
in the pack directly - no router involved.

### The slots

| slot | what fills it |
|---|---|
| `{{status}}` | 404 |
| `{{title}}` | Not Found |
| `{{source}}` | `RFC 9110`, or `nginx, not registered` |
| `{{#cat}}` | present only when the pack holds a picture for that status; inside it `{{cat_url}}`, `{{cat_width}}`, `{{cat_height}}` |
| `{{#message}}` | the 500 only: what the resource's `handle_exception` returned, or - when it defines none - the exception message and its backtrace |

Replace either template and the server renders yours instead. The status,
its name and where the name comes from are the server's table, not the
template's: fifteen of the statuses it knows are vendor inventions rather
than registered, and `{{source}}` says which.

`{{message}}` is **escaped**, and that is the whole reason the 500 goes
through a template. What a callback raised routinely carries request data
(`raise "bad id: #{params[:id]}"`), and it used to be the response body
verbatim under `Content-Type: text/html`.

### The pictures

*HTTP Status Cats* are by **Tomomi Imura** (@girlie_mac), published under
the **Creative Commons Attribution 2.0** licence
(<https://creativecommons.org/licenses/by/2.0/>); they are fetched here
through the `http.cat` service by @rogeriopvl. CC BY 2.0 permits
commercial use and derivatives and asks no ShareAlike, so it sits beside
this tree's Apache-2.0 without touching it, and anyone redistributing
this server may redistribute the pack.

| the licence asks | this pack |
|---|---|
| name the creator | Tomomi Imura, in `NOTICE`, in `NOTICE.txt` inside the zip, on every rendered page that shows a picture, and here |
| link the licence | the deed URL, in all four places |
| say whether it was changed | **not changed** - every image is the byte-for-byte JPEG `http.cat` served (which is itself 750x600, already smaller than the originals; "unchanged" is measured against what the service served) |
| no further restrictions | a plain zip with a notice in it, nothing wrapped, nothing locked |

### Everything is stored, nothing is deflated

The asset tier reads stored and deflate, and this pack is stored
throughout. Measured on the cats:

| | stored | deflate |
|---|---|---|
| archive, 55 images | 1 569 342 | 1 434 434 (-8.6%) |
| wire, `404.jpg` | 38 532 identity | 37 025 gzip (-3.9%) |
| `Accept-Encoding: identity` | 200 | **406** |
| `curl -o cat.jpg`, no `--compressed` | a JPEG | **a gzip file** |

A stored entry always leaves as identity, even for a client offering
gzip - the tier hands the archive through, it does not compress on the
fly. A deflate entry always leaves as gzip, including to a client that
sent no `Accept-Encoding` at all, and `file` calls what curl saved "gzip
compressed data". Four percent on the wire does not buy a broken download
and a 406.

The pack is **not** compiled into the binary. `mime.types` is, because a
lookup must answer without a data file beside it; 1.6 MB of pictures must
not be, and #184 went the other way.
