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
