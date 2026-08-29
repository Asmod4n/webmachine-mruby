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

## http-cats.zip

An asset pack — the same format `--assets` reads — holding one JPEG per
HTTP status code from 400 upwards, 55 of them, keyed `cats/<status>.jpg`.
`rake cats` rebuilds it from source.

*HTTP Status Cats* are by **Tomomi Imura** (@girlie_mac), published under
the **Creative Commons Attribution 2.0** licence
(<https://creativecommons.org/licenses/by/2.0/>); they are fetched here
through the `http.cat` service by @rogeriopvl. CC BY 2.0 permits
commercial use and derivatives and asks no ShareAlike, so it sits beside
this tree's Apache-2.0 without touching it, and anyone redistributing
this server may redistribute the pack.

What the licence asks in return, and how it is answered:

| the licence asks | this pack |
|---|---|
| name the creator | Tomomi Imura, in `NOTICE`, in `cats/NOTICE.txt` inside the zip, and here |
| link the licence | the deed URL, in all three places |
| say whether it was changed | **not changed** — every entry is the byte-for-byte JPEG `http.cat` served |
| no further restrictions | the pack is a plain zip with a notice in it, nothing wrapped, nothing locked |

The images are **stored**, not deflated: a JPEG does not compress, and the
asset tier reads stored and deflate only. The notice sits inside the
archive on purpose — a zip is what gets copied around, so the terms have
to travel with the bytes rather than stay behind in this repository.

They are NOT compiled into the binary. `mime.types` is, because a lookup
must answer without a data file beside it; 1.5 MB of cats must not be, and
#184 went the other way. They are served like any other pack.
