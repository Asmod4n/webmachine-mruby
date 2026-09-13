# Refuse a cross-site request

This how-to is for a developer whose resource changes state - a form post,
a delete, a password change. At the end you know how the server answers
"did this request come from my own site", what that answer covers, and
what it does not.

## The split

Cross-site request forgery needs two defences, and they belong in two
places.

The **origin check** is the server's. It reads the request's `Origin`
field, compares it against the origin this request arrived on, and needs
no state at all. It works with nothing on your side but a question.

The **token** is yours. A synchroniser token needs a session, and this
server keeps no session store yet.

Neither one replaces the other. The origin check stops a form on another
site from posting to yours. A token stops a request that carries your own
origin because the attacker got a script onto your page.

## One question

    request.same_origin?

| It answers | When |
|---|---|
| `true` | the `Origin` field names the origin this request arrived on |
| `false` | it names another origin, or it is the opaque `null` |
| `nil` | this server cannot say |

"The origin this request arrived on" is what `base_uri` names: `https://`
when the connection is TLS and `http://` when it is not, then the `Host`
field. Scheme and host compare without regard to letter case. The default
port folds: under `http` a `Host` of `x:80` is the same origin as an
`Origin` of `http://x`, and under `https` the same holds for `:443`.

`nil` has two causes, and both mean the same thing for you - no comparison
was made:

- The request carries no `Origin`. A client that is not a browser sends
  none, so absent is not cross-site.
- The request named no host this server could compare against. An HTTP/2
  request that sends `:authority` and no `host` field is this case.

## Using it

Refuse in `forbidden?`, which the graph asks before any callback writes
anything:

    class Transfer < Webmachine::Resource
      reads_body :process_post

      def self.allowed_methods
        %w[POST]
      end

      def forbidden?
        request.same_origin? == false
      end

      def process_post
        # ...
      end
    end

`== false` is the whole rule: a cross-site origin is refused, and `nil`
passes. That is the right default for an endpoint an API client also
calls.

For a browser-only endpoint, refuse the absence as well:

    def forbidden?
      request.same_origin? != true
    end

A safe method needs neither. `GET` and `HEAD` change nothing, so there is
nothing to forge.

## Sec-Fetch-Site

Every current browser sends `Sec-Fetch-Site`, and it answers a near
question more directly. It is not folded into `same_origin?`, because two
signals in one boolean hide which one spoke. Read it yourself:

    def forbidden?
      case request.headers['sec-fetch-site']
      when 'same-origin', 'same-site', 'none' then false
      when nil then request.same_origin? == false
      else true
      end
    end

`none` is a user who typed the address or used a bookmark. `same-site`
covers a sibling host under one registrable domain, which
`same_origin?` calls `false` - that is the case this field answers better.
A client that sends no `Sec-Fetch-Site` falls back to the origin check.

`Sec-Fetch-Site` is not in an RFC. It is in the Fetch Metadata Request
Headers specification, and a client is free to send nothing.

## What the origin check cannot do

It cannot see a request from your own page, so a script an attacker got
onto your site carries your origin and passes. A token is what stops
that one.

It cannot see a request from a client that sends no `Origin` and no
`Sec-Fetch-Site`. You decide whether that passes, with `== false` or
`!= true` above.

## What it costs

Nothing for a request that does not ask. `Origin` is not in the parsed
field table the framer reads on every request. `same_origin?` walks the
request's own field lines at the moment a resource asks. Measured: the h2
floor is 2610 instructions per response before this question existed and
2610 after.
