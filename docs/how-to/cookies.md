# Write a safe cookie

This how-to is for a developer who writes a cookie from a resource. At
the end you know what `response.set_cookie` writes, which rules it
refuses to break, and why each rule exists.

## One call

    response.set_cookie(name, value, attributes = nil)

It appends one `Set-Cookie` line. It never replaces one, so two calls
write two cookies. `name` is a String or a Symbol. `value` is a String.
`attributes` is a Hash.

| Key | On the wire |
|---|---|
| `:path` | `Path=` |
| `:domain` | `Domain=` |
| `:max_age` | `Max-Age=` |
| `:expires` | `Expires=` |
| `:secure` | `; Secure` |
| `:httponly` | `; HttpOnly` |
| `:same_site` | `; SameSite=` |

A simple session cookie:

    response.set_cookie('session', token, path: '/', max_age: '3600',
                                          secure: true, httponly: true,
                                          same_site: 'Lax')

## What each attribute does for you

`Secure` keeps the cookie off a plain HTTP request. Without it the
cookie travels in clear text the first time a user types the host name
without a scheme.

`HttpOnly` keeps the cookie away from `document.cookie`. A script that
an attacker got onto your page cannot read it.

`SameSite` is the browser's defence against a cross-site request. The
three values:

- `Strict` - the cookie goes out only on a request from your own site. A
  link from another site does not carry it.
- `Lax` - the cookie goes out on a top-level navigation from another
  site, and on nothing else. This is what most browsers apply when a
  cookie names no `SameSite` at all.
- `None` - the cookie goes out on every cross-site request. You need
  this for a cookie a third party reads, and for almost nothing else.

`Max-Age` and `Expires` bound the cookie's life. A cookie with neither
lives until the browser closes.

`Path` and `Domain` bound who the browser sends it to. A `Domain` widens
that: `Domain=example.com` sends the cookie to every host under
`example.com`, a subdomain an attacker controls included.

## The rules this server enforces

A browser drops a cookie that breaks one of the rules below, and it says
nothing. You see a session that never arrives and no error anywhere. So
`set_cookie` raises `Webmachine::Error` at the call instead, because the
call knows the name and every attribute at the same moment.

### SameSite=None needs Secure

RFC 6265bis 4.1.2.7. A browser refuses `SameSite=None` on a cookie with
no `Secure`.

    response.set_cookie('a', '1', same_site: 'None')
    # Webmachine::Error: response.set_cookie wants Secure beside SameSite=None

    response.set_cookie('a', '1', same_site: 'None', secure: true)  # fine

The value is read without regard to letter case, and the line carries the
spelling the RFC writes. A value that is not `Strict`, `Lax` or `None`
is refused as well.

### `__Secure-` needs Secure

RFC 6265bis 4.1.3. A name that starts with `__Secure-` promises the
browser that the cookie was set over a secure connection with `Secure`
on it.

    response.set_cookie('__Secure-a', '1', secure: true)  # fine

### `__Host-` needs Secure, no Domain, and Path=/

RFC 6265bis 4.1.3. This is the stronger promise: the cookie belongs to
exactly one host.

    response.set_cookie('__Host-a', '1', secure: true, path: '/')  # fine

`Domain` is what the prefix forbids. Without a `Domain` the browser
sends the cookie to the one host that set it, and a subdomain cannot
write over it. That is the attack the prefix stops: a host at
`sub.example.com`, which an attacker reached, setting a cookie with
`Domain=example.com` that your own host then reads as its own.

The server reads both prefixes without regard to letter case, because a
browser reads them that way.

## What the server already refused before these rules

A cookie's name, value and attributes all end up in one field value, and
the application wrote all three. So `set_cookie` refuses:

- a name that is empty, or that carries `=` or `;` - either one names a
  second cookie or an attribute,
- a `;` in the value or in any attribute, for the same reason,
- CR, LF or NUL anywhere in the line, which would end the field or the
  head.

## What it costs

Nothing per request. Every rule on this page is read in `set_cookie`,
which runs when your code calls it.

## Reading a cookie

`request.headers['cookie']` is the request's own field, with repeated
`Cookie` lines joined by `", "`. This server does not split it into
pairs for you.
