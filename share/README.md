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

## error-assets.zip

An asset pack holding the pictures the error pages show, and nothing
else:

    <status>.jpg        one per status, at the root, CC BY 2.0, see below

There is no index and no directory: the archive's own entry list is the
index, and `404.jpg` is both the name inside it and the name a caller
writes. What a rebuild and a page need rides where ZIP puts each of
them: the upstream ETag in the entry's comment, the upstream second in
the entry's own timestamp and in Info-ZIP's extended timestamp field
(0x5455, which keeps the second the DOS stamp rounds away), and the
picture's size in an extra field of this tree's own (0x574D) - not as
numbers but as the page spells them, `width="750" height="600"`. The
archive's own comment carries the licence, so the terms travel with the
file wherever it is copied rather than only with this repository.

`rake error_assets` fetches and rebuilds it.

The templates are NOT in here. They live in `Webmachine::ErrorResource`
(mrblib/webmachine.rb), because a server with no pack still has to be
able to say what went wrong - and the way to change a page is to reopen
that class, not to edit a zip:

    class Webmachine::ErrorResource
      def self.content_types_provided
        super + [['application/xml', :to_xml_error]]
      end

      def to_xml_error(e)
        "<error status=\"#{e['status']}\">#{e['title']}</error>"
      end
    end

The pack only decides whether a page HAS a picture: a status with no
`<status>.jpg` renders without one.

### Asking instead of downloading

The ETag and the timestamp on each entry are the upstream service's
own. A rebuild sends both questions RFC 9110 13.1 has -
`If-None-Match` from the comment and `If-Modified-Since` from the
timestamp - and a picture that has not changed answers 304 and costs
nothing, so `rake error_assets` on an unchanged upstream fetches no
bytes at all and says how many it skipped.

The size is not something a response carries, so `file(1)` measures a
picture in the one moment it arrives and the entry keeps the answer. A
304 brings no bytes and needs no measuring - the field travels from the
old pack into the new one - so a rebuild against an unchanged upstream
runs `file(1)` not once.

What the entry keeps is the finished `width="750" height="600"`, because
that is what has to appear in the page. The server hands the field
through: nothing at boot turns a number back into digits, and nothing at
request time does either - the rendered page is bytes long before the
first request. It is what lets a browser reserve the space before the
picture lands.

### The page is not a route; the picture is

An error is delivered by the route that produced it. A page fetched from
`/errors/404.html` would be a second trip through the same router that
just failed to find anything, so no page is served from anywhere: the
server renders one at STARTUP for every status it can answer with and
appends those bytes to the response that failed. The wire path is one
`append`, and for every 4xx it is the same bytes every time.

The pictures are the exception, and they have to be: an `<img>` is a
second request by definition. They are mounted at `/error_assets/`, which
is where the `cat_url` in a rendered page points - `/error_assets/404.jpg`
is entry `404.jpg` of this archive, answered by the asset tier like any
other file, conditional requests and ranges included.

The picture is the one exception, and it is the reason the error assets exists at
all: the cats are far too big to compile in, and the server looks them up
in the error assets directly - no router involved.

### The slots

| slot | what fills it |
|---|---|
| `{{status}}` | 404 |
| `{{title}}` | Not Found |
| `{{source}}` | `RFC 9110`, or `nginx, not registered` |
| `{{#cat}}` | present only when the error assets holds a picture for that status; inside it `{{cat_url}}` and `{{{cat_size}}}`, the `<img>` attributes straight out of the pack - raw, because escaped quotes are not attributes |
| `{{#id}}` | the 16 hex digits the failure is named by - the same ones the error log leads its record with, and the only thing tying the two together |
| `{{#message}}` | the 500 only: what `Webmachine::ErrorResource#handle_exception` made of the exception. It lives there and nowhere else: a `handle_exception` on an ordinary resource is ignored, because how an exception becomes text is one decision for the server rather than a per-route one |
| `{{#backtrace}}` | the debug build only (#210): where it was raised |

Every handler is handed this same Hash. The status, its name and where
the name comes from are the server's table, not the template's: fifteen
of the statuses it knows are vendor inventions rather than registered,
and `{{source}}` says which.

`{{message}}` is **escaped**, and that is the whole reason it goes
through a template: what a callback raised routinely carries request
data (`raise "bad id: #{params[:id]}"`), and it used to be the response
body verbatim under `Content-Type: text/html`. Nothing else on the page
came from the client - #210 took the request out of it, and the log is
where a request belongs.

### The pictures

*HTTP Status Cats* are by **Tomomi Imura** (@girlie_mac), published under
the **Creative Commons Attribution 2.0** licence
(<https://creativecommons.org/licenses/by/2.0/>); they are fetched here
through the `http.cat` service by @rogeriopvl. CC BY 2.0 permits
commercial use and derivatives and asks no ShareAlike, so it sits beside
this tree's Apache-2.0 without touching it, and anyone redistributing
this server may redistribute the error assets.

| the licence asks | these error assets |
|---|---|
| name the creator | Tomomi Imura, in `NOTICE`, in the zip's own archive comment, on every rendered page that shows a picture, and here |
| link the licence | the deed URL, in all four places |
| say whether it was changed | **not changed** - every image is the byte-for-byte JPEG `http.cat` served (46 of the 55 are 750x600 and the other nine 600x750, already smaller than the originals; "unchanged" is measured against what the service served) |
| no further restrictions | a plain zip carrying its notice, nothing wrapped, nothing locked |

### Everything is stored, nothing is deflated

The asset tier reads stored and deflate, and these error assets is stored
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

The error assets is **not** compiled into the binary. `mime.types` is, because a
lookup must answer without a data file beside it; 1.6 MB of pictures must
not be, and #184 went the other way.
