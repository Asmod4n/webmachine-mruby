#!/usr/bin/env python3
"""The shapes a mutator should not have to discover (#206).

A payload here is raw wire bytes on ONE connection, exactly what
LLVMFuzzerTestOneInput sends - so a seed is a whole request, not a
fragment. What they buy is the first few thousand runs: a coverage-guided
fuzzer starting from an empty corpus spends them arriving at "GET / "
and the h2 preface, which are not discoveries.

  tools/fuzz-seeds.py [DIR]      # default tools/webmachine-fuzz/corpus

Seed files are named seed-*.raw and rewritten every run; anything else in
the directory is a campaign's own find and is left alone. That is why the
generator is committed beside the corpus and not run once by hand: a seed
that changes because the server changed has to be regenerable.
"""
import os, sys

# RFC 9113 3.4: the connection preface, and the SETTINGS frame that must
# follow it before anything else on the wire.
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def frame(kind, flags, stream, payload):
    """RFC 9113 4.1: length(3) type(1) flags(1) R+stream(4), then payload."""
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + \
        stream.to_bytes(4, 'big') + payload


# RFC 7541 appendix A, by index: 2 is ":method GET", 4 ":path /", 6
# ":scheme http". 0x41 is ":authority" indexed with a literal value, which
# is the one header of a minimal request that cannot be an index.
H2_GET = bytes([0x82, 0x86, 0x84, 0x41, 0x01, ord('x')])

SEEDS = {
    # RFC 9112 3: the request line, and the field the flow branches on.
    'h1-get': b'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
    'h1-get-close': b'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
    'h1-head': b'HEAD / HTTP/1.1\r\nHost: x\r\n\r\n',
    # RFC 9110 9.3.7: the one target that is not a path.
    'h1-options-star': b'OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n',
    # RFC 9112 3.2.2: absolute-form, which a proxy sends and a server must read.
    'h1-absolute': b'GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n',
    # RFC 9112 6: the two ways a body is framed.
    'h1-post-length': b'POST / HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n'
                      b'Content-Length: 5\r\n\r\nhello',
    'h1-post-chunked': b'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n'
                       b'5\r\nhello\r\n0\r\n\r\n',
    # RFC 9110 10.1.1: the body the server may refuse before it arrives.
    'h1-expect-100': b'PUT / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n'
                     b'Content-Length: 3\r\n\r\nabc',
    # RFC 9110 13: the conditionals, which is where the flow forks most.
    'h1-inm': b'GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: "abc"\r\n\r\n',
    'h1-inm-star': b'GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n',
    'h1-ims': b'GET / HTTP/1.1\r\nHost: x\r\n'
              b'If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n\r\n',
    'h1-if-match': b'PUT / HTTP/1.1\r\nHost: x\r\nIf-Match: "abc"\r\nContent-Length: 0\r\n\r\n',
    # RFC 9110 12: content negotiation, all four fields at once.
    'h1-negotiate': b'GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html;q=0.9, */*;q=0.1\r\n'
                    b'Accept-Encoding: gzip\r\nAccept-Language: de\r\n'
                    b'Accept-Charset: utf-8\r\n\r\n',
    # RFC 9110 14: a range, and one that cannot be satisfied.
    'h1-range': b'GET / HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\n\r\n',
    'h1-range-suffix': b'GET / HTTP/1.1\r\nHost: x\r\nRange: bytes=-5\r\n\r\n',
    # RFC 9112 9.3.2: two requests in one write.
    'h1-pipeline': b'GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n',
    # RFC 9113 3.4 and 6.5: the preface alone, and with a first frame.
    'h2-preface': H2_PREFACE + frame(0x04, 0, 0, b''),
    'h2-get': H2_PREFACE + frame(0x04, 0, 0, b'') + frame(0x01, 0x05, 1, H2_GET),
    # RFC 6455 4.1: the upgrade, with and without the extension.
    'ws-handshake': b'GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n'
                    b'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
                    b'Sec-WebSocket-Version: 13\r\n\r\n',
    'ws-deflate': b'GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n'
                  b'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
                  b'Sec-WebSocket-Version: 13\r\n'
                  b'Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n',
    # WHATWG HTML: the stream a client opens and never closes.
    'sse-open': b'GET /events HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n',
}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'tools/webmachine-fuzz/corpus'
    os.makedirs(out, exist_ok=True)
    for name, payload in sorted(SEEDS.items()):
        with open(os.path.join(out, f'seed-{name}.raw'), 'wb') as fh:
            fh.write(payload)
    print(f'{len(SEEDS)} seeds written to {out}')


if __name__ == '__main__':
    main()
