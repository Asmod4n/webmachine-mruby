# Serve TLS

This how-to is for an operator who needs `https` on the listener. At
the end, you have a listener that speaks TLS through the kernel, and
you know what the machine needs for that to work.

## Name a certificate and a key

An application turns TLS on by naming an `https` listener, and gives
it a certificate and a key:

```ruby
def main
  Webmachine::Application.new do |app|
    app.conf.url = 'https://0.0.0.0:8443'
    app.conf.certificate = '/etc/webmachine/cert.pem'
    app.conf.private_key = '/etc/webmachine/key.pem'
    app.add_route [:*], YourResource
  end
end
```

Both files are PEM. Both settings are required together: a listener
that names a certificate but is not `https` is refused, and an `https`
listener that names only one of the two is refused as well.

## One listener, several names

RFC 6066 3. A host that answers for several names needs one certificate
per name, and `conf.certificates` names them:

```ruby
def main
  Webmachine::Application.new do |app|
    app.conf.url = 'https://0.0.0.0:8443'
    app.conf.certificate = '/etc/webmachine/default.pem'
    app.conf.private_key = '/etc/webmachine/default.key'
    app.conf.certificates = {
      'shop.example'  => ['/etc/webmachine/shop.pem', '/etc/webmachine/shop.key'],
      '*.api.example' => ['/etc/webmachine/api.pem', '/etc/webmachine/api.key']
    }
    app.add_route [:*], YourResource
  end
end
```

The client's TLS handshake names the host it asked for, and the server
answers with that name's certificate. `conf.certificate` and
`conf.private_key` stay the default pair, so both are still required.

Three rules:

- **A name nobody named gets the default pair**, and so does a client
  that names no host at all. The other answer, refusing the handshake,
  would tell a stranger which names this server holds and would break
  every client that arrived by address.
- **The name is compared without regard to letter case.**
- **One leading `*.` matches exactly one label.** `*.api.example`
  answers for `v1.api.example`, and not for `v1.beta.api.example` and
  not for `api.example` itself. Name `api.example` as well if it needs
  a certificate.

Every pair is read and checked at start: a file that is not there, a PEM
that does not parse, and a key that does not belong to its certificate
are each refused by name before the listener opens. The same name twice
is refused too.

Both cipher suites and the ALPN list reach every pair, so a request that
arrives under any of these names can still be HTTP/2.

You might expect IPv6 to have made this unnecessary - one address per
name, and no need to share. It has not: plenty of hosting providers
still hand out no IPv6 at all, so several names share one IPv4 address
and the handshake is the only place the name appears.

## What the kernel needs

The certificate and the key are read and checked before the kernel is
asked for anything, so a wrong path or a bad PEM file is reported even
on a machine that has no TLS support at all.

Serving the listener needs the kernel's `tls` module. Without it, the
server refuses to start that listener and names the reason: this
listener serves TLS and the kernel has no `tls` ULP, with the fix
alongside it, `modprobe tls`. Loading the module is attempted once at
start; when that also fails, the refusal is what you see and the
server does not start.

## The two cipher suites

Every TLS listener offers `TLS_AES_128_GCM_SHA256` and
`TLS_CHACHA20_POLY1305_SHA256`, and picks which one to offer first by
asking the machine whether it has fast AES instructions. Both HTTP/2
and HTTP/1.1 are offered through ALPN, in that order.

## Next

- [../tutorial.md](../tutorial.md)
- [../reference/configuration.md](../reference/configuration.md)
- [run-in-a-container.md](run-in-a-container.md)
