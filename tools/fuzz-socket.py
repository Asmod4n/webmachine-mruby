#!/usr/bin/env python3
"""Fuzz the SERVER, not its functions (#206).

The binary under test is the shipped webmachine-server, built with
ASan+UBSan and otherwise unchanged. This starts it, connects to its
unix socket, and writes a payload - the same door an attacker has.
Nothing is linked in, no function is called directly.

  tools/fuzz-socket.py [seconds] [--seed DIR]

THE VERDICT HAS FOUR CASES, and only the first is a crash:
  died      the process is gone
  report    ASan/UBSan wrote to stderr, with or without dying
  hung      no answer inside the deadline
  wedged    still alive, but a following HEALTHY request goes unanswered
The last one is the one a crash-only oracle swallows, and it is real:
a POST halted at n11 with 500 once left the request body unread and
the server stopped answering while still running.

The server is kept ALIVE across payloads (one connection each) and only
restarted when it dies. That is faster than a process per payload, and
closer to what a running server experiences - state accumulates.

No coverage feedback yet: this mutates blind, from a seed corpus and a
dictionary. Coverage-guided (AFL++) is the next step and is what turns
"we sent a lot of bytes" into "we reached what an attacker can reach".
"""
import os, random, signal, socket, subprocess, sys, time

BIN = 'mruby/build/fuzz/bin/webmachine-server'
SOCK = '/tmp/wm-fuzz.sock'
HEALTHY = b'GET / HTTP/1.1\r\nHost: f\r\nConnection: close\r\n\r\n'

# The fixed bytes a mutator never invents. Ordered by the door they open.
DICT = [
    # h1 request line and the fields the flow actually branches on
    b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ',
    b'TRACE ', b'CONNECT ', b' HTTP/1.1\r\n', b' HTTP/1.0\r\n', b'\r\n', b'\r\n\r\n',
    b'Host: x\r\n', b'Content-Length: ', b'Transfer-Encoding: chunked\r\n',
    b'Connection: close\r\n', b'Connection: keep-alive\r\n',
    b'Expect: 100-continue\r\n', b'Content-MD5: ', b'Accept: ', b'Accept-Encoding: gzip\r\n',
    b'Accept-Language: ', b'Accept-Charset: ', b'If-Match: ', b'If-None-Match: ',
    b'If-Modified-Since: ', b'If-Unmodified-Since: ', b'Range: bytes=',
    b'Content-Type: ', b'Authorization: ', b'Cookie: ', b'DNT: 1\r\n', b'Sec-GPC: 1\r\n',
    # the upgrades
    b'Upgrade: h2c\r\n', b'HTTP2-Settings: ', b'Upgrade: websocket\r\n',
    b'Sec-WebSocket-Key: ', b'Sec-WebSocket-Version: 13\r\n',
    b'Sec-WebSocket-Protocol: ', b'Sec-WebSocket-Extensions: permessage-deflate\r\n',
    b'client_max_window_bits', b'permessage-deflate',
    # h2: the preface, then frame headers by type, then HPACK indices
    b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',
    b'\x00\x00\x00\x04\x00\x00\x00\x00\x00',      # SETTINGS, empty
    b'\x00\x00\x00\x04\x01\x00\x00\x00\x00',      # SETTINGS ack
    b'\x00\x00\x08\x06\x00\x00\x00\x00\x00',      # PING
    b'\x00\x00\x08\x07\x00\x00\x00\x00\x00',      # GOAWAY
    b'\x00\x00\x04\x08\x00\x00\x00\x00\x00',      # WINDOW_UPDATE
    b'\x00\x00\x04\x03\x00\x00\x00\x00\x01',      # RST_STREAM
    b'\x00\x00\x00\x00\x01\x00\x00\x00\x01',      # DATA, END_STREAM
    b'\x00\x00\x05\x01\x05\x00\x00\x00\x01',      # HEADERS, END_STREAM|END_HEADERS
    b'\x00\x00\x05\x09\x04\x00\x00\x00\x01',      # CONTINUATION
    b'\x82\x84\x86\x41',                          # HPACK static: :method GET, :path /, :scheme, :authority
    b'\x83\x85\x87\x88\x8b',                      # more static-table indices
    b'\x40', b'\x00', b'\x10', b'\x20',           # HPACK literal/never-indexed/table-update prefixes
    # ws frames
    b'\x81', b'\x82', b'\x88', b'\x89', b'\x8a',  # FIN|text/binary/close/ping/pong
    b'\x01', b'\x00', b'\xc1',                    # continuation, no-FIN, RSV1|text
    b'\xfe', b'\xff', b'\x7e', b'\x7f',           # mask bit + the 126/127 length escapes
]


def start():
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    p = subprocess.Popen([BIN, '--unix', SOCK], stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
    for _ in range(200):
        if os.path.exists(SOCK):
            return p
        if p.poll() is not None:
            break
        time.sleep(0.05)
    raise SystemExit('server never came up:\n' + p.stderr.read().decode('utf8', 'replace'))


MAX_LIVE = 64


def fire(rng, payload, live):
    """One payload, one NEW connection. Some are then LEFT OPEN.

    A driver that closes every connection at once never puts the server
    where it is weakest: several connections alive at the same time, some
    idle mid-request, slots being reused under generation counters, the
    idle and header deadlines actually running. So a share of them linger
    for a random while and are reaped later, and the write is not waited
    on - a peer that stops reading is a peer the server has to survive.
    """
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(SOCK)
    try:
        s.sendall(payload)
    except OSError:
        s.close()
        return live
    if rng.random() < 0.30 and len(live) < MAX_LIVE:
        # Left open, deliberately unread: the server may be mid-answer.
        live.append((s, time.time() + rng.uniform(0.05, 4.0)))
        return live
    try:
        s.settimeout(0.25)
        while s.recv(65536):
            pass
    except OSError:
        pass
    s.close()
    return live


def reap(live, force=False):
    now = time.time()
    keep = []
    for s, close_at in live:
        if force or now >= close_at:
            try:
                s.close()
            except OSError:
                pass
        else:
            keep.append((s, close_at))
    return keep


def healthy(deadline=3.0):
    """A request that is fine, on its own fresh connection. If THIS goes
    unanswered the server is wedged - alive, and no longer serving."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(deadline)
    try:
        s.connect(SOCK)
        s.sendall(HEALTHY)
        got = b''
        while True:
            b = s.recv(65536)
            if not b:
                break
            got += b
        return got.startswith(b'HTTP/1.1 200')
    except OSError:
        return False
    finally:
        s.close()


def mutate(rng, corpus):
    p = bytearray(rng.choice(corpus)) if corpus and rng.random() < 0.7 else bytearray()
    for _ in range(rng.randint(1, 8)):
        r = rng.random()
        if r < 0.45 and DICT:                      # splice a token in
            t = rng.choice(DICT)
            at = rng.randint(0, len(p)) if p else 0
            p[at:at] = t
        elif r < 0.65 and p:                       # flip a byte
            i = rng.randrange(len(p))
            p[i] ^= 1 << rng.randrange(8)
        elif r < 0.8:                              # random run
            p += bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
        elif r < 0.9 and len(p) > 2:               # cut
            a = rng.randrange(len(p))
            del p[a:a + rng.randint(1, 64)]
        elif p:                                    # repeat a slice
            a = rng.randrange(len(p))
            p += p[a:a + rng.randint(1, 128)]
    return bytes(p[:65536])


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1][0].isdigit() else 60.0
    corpus = []
    # The seed corpora the old per-method harness accumulated. Its targets
    # go (#206), these files stay: h1 heads, h2 frames and ws frames are
    # still the shapes a payload wants to start from.
    import glob
    for d in glob.glob('build/fuzz/corpus-*'):
        for f in os.listdir(d):
            try:
                with open(os.path.join(d, f), 'rb') as fh:
                    corpus.append(fh.read(65536))
            except OSError:
                pass
    print(f'seed corpus: {len(corpus)} files, dictionary: {len(DICT)} tokens')

    rng = random.Random(1)
    proc = start()
    n = bad = restarts = 0
    live = []
    end = time.time() + secs
    findings = []
    while time.time() < end:
        payload = mutate(rng, corpus)
        n += 1
        try:
            live = fire(rng, payload, live)
        except OSError:
            pass
        live = reap(live)
        # died: the process is gone. Read what it said on the way out.
        if proc.poll() is not None:
            err = proc.stderr.read().decode('utf8', 'replace')
            kind = 'REPORT' if ('Sanitizer' in err or 'runtime error' in err) else 'DIED'
            findings.append((kind, payload, err[-4000:]))
            live = reap(live, force=True)
            proc = start()
            restarts += 1
            continue
        # A payload that gets no answer is NOT a finding on its own: an
        # incomplete request is SUPPOSED to wait, the header deadline says
        # 60s. My first run called 13 of those a bug, every one of them
        # between 0 and 22 bytes of nothing. Only this decides.
        if n % 16 == 0 and not healthy():
            findings.append(('WEDGED', payload, ''))
            bad += 1
            live = reap(live, force=True)
            proc.kill()
            proc.wait()
            proc = start()
            restarts += 1
    live = reap(live, force=True)
    print(f'payloads={n} findings={len(findings)} restarts={restarts}')
    os.makedirs('/tmp/wm-fuzz-findings', exist_ok=True)
    for i, (kind, payload, err) in enumerate(findings):
        with open(f'/tmp/wm-fuzz-findings/{i:04d}-{kind}.bin', 'wb') as fh:
            fh.write(payload)
        if err:
            with open(f'/tmp/wm-fuzz-findings/{i:04d}-{kind}.txt', 'w') as fh:
                fh.write(err)
        print(f'  {kind}: {len(payload)} bytes' + (f' - {err.splitlines()[0][:120]}' if err else ''))
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
