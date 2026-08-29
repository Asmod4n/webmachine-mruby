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

An asset pack - the same format `--assets` reads - holding, for every HTTP
status from 400 upwards that a picture exists for, three entries:

    errors/<status>.html   a standalone page, ours, Apache-2.0
    errors/<status>.json   an RFC 9457 problem document, ours
    cats/<status>.jpg      the picture, CC BY 2.0, see below
    NOTICE.txt             the terms, inside the archive

55 statuses, 166 entries. `rake error_pages` fetches and rebuilds it.

The **pages** stand alone: no stylesheet, no script, no font, light and
dark from `prefers-color-scheme`, and the picture's real width and height
read out of its SOF marker so the layout does not jump. The only thing a
page asks for is the cat beside it in this same pack - an error page must
not depend on a second request to somewhere else, and a 5xx page is the
one most likely to be read while something is already broken.

The **problem documents** follow RFC 9457: `type`, `title`, `status`, and
nothing invented. No cat - whatever reads JSON wants the status, not a
picture. (Served from this pack they carry `application/json`, by
extension; the media type RFC 9457 asks for is
`application/problem+json`, which is the error path's to set when it
serves the same bytes itself.)

Each page names **where its status comes from**: an RFC where one exists,
and "nginx, not registered" or "Cloudflare, not registered" where none
does. Fifteen of the 55 are vendor inventions, and the page says so.

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
| name the creator | Tomomi Imura, in `NOTICE`, in `NOTICE.txt` inside the zip, on every page that shows a picture, and here |
| link the licence | the deed URL, in all four places |
| say whether it was changed | **not changed** - every image is the byte-for-byte JPEG `http.cat` served |
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
and a 406. The pages would deflate far better than the images do, and
they are stored for the same reason: this pack must be readable by
whatever asks for it.

The pack is **not** compiled into the binary. `mime.types` is, because a
lookup must answer without a data file beside it; 1.6 MB of pages and
cats must not be, and #184 went the other way.
