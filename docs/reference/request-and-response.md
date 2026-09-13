# Request and response reference

This page is for a developer who writes a resource class and needs the
exact method list on the request object and the response object. At the
end, you know every public method on both, what it returns, and what it
refuses.

`Webmachine::Request` and `Webmachine::Response` are C++ data classes.
An app cannot build one with `new`. A resource gets one through
`request` and `response`, called inside a resource callback. `request`
returns a fresh handle on every call; `response` returns a fresh handle
on every call. Neither handle is cached, so calling `request` twice in
one callback gives two handles over the same data.

Calling a request method outside a resource callback raises
`RuntimeError`. Calling a response method outside a run raises
`RuntimeError`. Reading or writing `response.headers` needs a bound
header buffer; without one it raises `RuntimeError`.

Three error classes carry refusals: `Webmachine::Error`,
`Webmachine::ConfigError`, and `Webmachine::RouteError`. `ConfigError`
and `RouteError` are subclasses of `Webmachine::Error`. An app can
rescue the class at the line that caused the refusal.

## Request

All methods below take no arguments, except `body.save`.

| Method | Returns | Note |
| --- | --- | --- |
| `method` | String | The request method: `"GET"`, `"HEAD"`, `"POST"`, `"PUT"`, `"DELETE"`, `"OPTIONS"`, or the method token as sent. Raises `RuntimeError` when the method's bytes are not available on this path. |
| `uri` | String | The request-target as it arrived, query included. Example: `/fizz/one/a/b?x=1&y=two%20words&z`. |
| `path` | String | The target up to `?`. Example: `/fizz/one/a/b`. |
| `disp_path` | String | The part of the path a `:*` splat matched. A route with no splat gives the whole path. When `create_path` set a new path in this run, that path wins. |
| `path_info` | Hash | Keys are the Symbols the route bound, values are Strings. An empty Hash when the route bound nothing. |
| `path_tokens` | Array of String | The splat's segments in order. Empty when the route has no splat. |
| `query_string` | String | The raw query, without the `?`. `""` when there is none. |
| `query` | Hash of String to String | Percent-decoded, `+` read as a space, split on `&` only; `;` is not a separator. A key with no `=` gets `""`. A broken escape stays as written. Keys are frozen. |
| `headers` | Hash | Every request header field, names lowercased. Repeated fields are joined with `", "`. Empty Hash when there are no fields. |
| `body` | IO or nil | `nil` when no body arrived. A body kept in memory is a `StringIO` over a copy of the bytes. A body spilled to a file is a `File`, rewound to position 0. One object per run: a second call returns the same object. Raises `RuntimeError` when the body cannot be opened or rewound. |
| `has_body?` | true or false | True when the body length is greater than 0. |
| `content_type` | String or nil | The `Content-Type` field's value, or nil. |
| `content_length` | String or nil | The `Content-Length` field's value, as a String, not an Integer. The caller converts it with `.to_i`. |
| `authorization` | String or nil | The `Authorization` field's value, or nil. |
| `accept` | String or nil | The `Accept` field's value, or nil. |
| `accept_encoding` | String or nil | The `Accept-Encoding` field's value, or nil. |
| `if_match` | String or nil | The `If-Match` field's value, or nil. |
| `if_none_match` | String or nil | The `If-None-Match` field's value, or nil. Repeats are joined with `", "`. |
| `if_modified_since` | String or nil | The `If-Modified-Since` field's value, or nil. |
| `if_unmodified_since` | String or nil | The `If-Unmodified-Since` field's value, or nil. |
| `host` | String or nil | The `Host` field's value, or nil. |
| `cookies` | Hash of String to String | The `Cookie` field's `k=v` pairs, split on `;`, with spaces trimmed. Empty Hash when there is no `Cookie` field. Several `Cookie` lines are joined with `"; "` first, so split cookie fields on HTTP/2 still arrive as one Hash. |
| `same_origin?` | true, false or nil | RFC 6454 6.1: does the `Origin` field name the origin this request arrived on? `true` it does; `false` another origin, or the opaque `null`; `nil` this server cannot say, because the request carries no `Origin`. Scheme and host compare without regard to letter case, and the default port folds (`:80` under http, `:443` under https). Reads the request's field lines when asked, so a request that never asks pays nothing. See [Refuse a cross-site request](../how-to/refuse-a-cross-site-request.md). |
| `base_uri` | String | `"https://"` when the connection is TLS, else `"http://"`, then the `Host` field's value, then `/`. Without a `Host` field it is `"http:///"` or `"https:///"`. No port or query normalization. |
| `get?` | true or false | True when `method` is `GET`. |
| `head?` | true or false | True when `method` is `HEAD`. |
| `post?` | true or false | True when `method` is `POST`. |
| `put?` | true or false | True when `method` is `PUT`. |
| `delete?` | true or false | True when `method` is `DELETE`. |
| `options?` | true or false | True when `method` is `OPTIONS`. |

### request.body as an IO

`request.body` answers to `read`, `gets`, `getc`, `each`, `pos`, `seek`,
`rewind`, `size` and `eof?`. A body under 256 KiB stays in memory as a
`StringIO`. From 256 KiB up, it spills to a file.

### request.body.save

`save(dir, name)` takes two Strings and an optional block.

Without a block, it returns the directory the content now lives in, or
raises `Webmachine::Error` on a failure.

With a block, the block gets `(dir, err)`. Exactly one of the two is
non-nil; `err` is a `Webmachine::Error`. After the block runs, a failed
save still raises `Webmachine::Error`. When the block's answer is
truthy, that answer's `to_s` becomes the response body; `nil` and
`false` leave the body alone.

The saved layout is `<dir>/<first two hex of sha256>/<full sha256 hex>/<name>`.

```ruby
def take
  # the block's String is the answer's body: /var/uploads/3f/3fa7c9...d21e
  request.body.save('/var/uploads', 'photo.png') { |dir, err| dir }
end
```

## Response

| Method | Returns | Note |
| --- | --- | --- |
| `headers` | `Webmachine::Response::Headers` | A view over the run's header buffer, built fresh on each call. |
| `headers[name]` | String or nil | Case-insensitive lookup. |
| `headers[name] = value` | - | A String replaces the line of that name, or appends one. `nil` deletes it. Refuses a value that is not a String or nil, a name that is not a valid field-name token, a value with CR, LF or NUL, or a name the server spells itself (a framing or connection field). |
| `headers.key?(name)` | true or false | Case-insensitive presence check. |
| `headers.delete(name)` | String or nil | Removes the field and returns its old value, or nil. |
| `code` | Integer or nil | nil until a callback sets it. |
| `code = n` | - | Takes an Integer. Refuses with `ArgumentError` when `n` is below 100 or above 599. |
| `body` | String or nil | The response body a callback set. |
| `body = s` | - | A String sets the body; `nil` clears it. Refuses a value that is not a String or nil. Raises `RuntimeError` when no body buffer is bound for this run. |
| `file` | String or nil | The file name a callback set with `file=`. |
| `file = "rel/path"` | - | Names a file under the docroot; the reactor opens and streams it later. A String sets it, `nil` clears it. Refuses a value that is not a String or nil. Raises `Webmachine::ConfigError` when the server has no docroot. An empty name or one with a NUL is marked bad and answers 404. The resource that sets `response.file` returns `''` from its body callback. |
| `error_asset(name)` | the name | Makes an entry of the error assets zip the body, with the media type the zip recorded. `nil` is a no-op. Refuses a name that is not a String, refuses when the server has no error assets, refuses an empty or too-long name, and refuses a name not present in the error assets. |
| `do_redirect(location = nil)` | true | Same function as `redirect_to`. With an argument, sets `Location` to `location.to_s`, replacing any earlier value, and marks the run a redirect. Refuses with `ArgumentError` a location carrying CR, LF or NUL. Raises `RuntimeError` without a bound header buffer. |
| `redirect_to(location = nil)` | true | Same function as `do_redirect`, under the other name. |
| `is_redirect?` | true or false | Whether this run was marked a redirect. |
| `error` | any | A plain instance variable. The server never reads it. |
| `error = v` | - | Sets that instance variable. |
| `set_cookie(name, value, attrs = nil)` | nil | Appends one `Set-Cookie` line; never replaces one. `name` may be a Symbol or String. `value` must be a String. `attrs` is a Hash with keys `:path`, `:domain`, `:max_age`, `:expires`, `:secure`, `:httponly`, `:same_site`, spelled on the wire as `Path=`, `Domain=`, `Max-Age=`, `Expires=`, `; Secure`, `; HttpOnly`, `; SameSite=`. Refuses a name with `=` or `;`, a value or attribute with `;`, or any of the three with CR, LF or NUL. Refuses a `:same_site` that is not `Strict`, `Lax` or `None`, read without regard to letter case; `None` without `:secure`; a `__Secure-` name without `:secure`; and a `__Host-` name without `:secure`, or with a `:domain`, or with a `:path` that is not `/`. The two prefixes are read without regard to letter case. See [Write a safe cookie](../how-to/cookies.md). |
| `userdata` | any | One slot per run. Set in one callback, read in a later callback of the same run. The server never reads it. An unset slot gives nil. |
| `userdata = v` | - | Sets that slot. |

```ruby
class WritesResponse < Webmachine::Resource
  def to_html
    response.headers['X-Every-Path'] = 'yes'
    response.set_cookie('every', 'path', path: '/', max_age: '60',
                                         secure: true, httponly: true)
    BODY
  end

  def finish_request
    response.headers['X-Finished'] = 'yes'
    nil
  end
end
```

### A compute worker sees its arguments, and nothing else

A compute block runs in a worker VM. That VM holds no request, no
response and no state of the run. It holds what the task was given and
what the worker was told to build once, at start
(`Webmachine::Workers::Registry`).

So the block is a function:

- **In** — the arguments of `ComputeTask.new(*args, max_runtime:)`, which
  cross as CBOR. A value CBOR cannot carry raises `Webmachine::Error` at
  the call, in the run's own VM.
- **Out** — the value of the block, which crosses back as CBOR and
  becomes the answer of the callback the task stands for.

Nothing else crosses in either direction. A block that names `request` or
`response` finds no such method and raises `NoMethodError` in the worker.
That raise crosses back whole - class, message and backtrace - and the
run raises it as its own, so the answer is a 500 that says what happened.

```ruby
class Verify < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(_h)
    # The token is read here, where the request exists, and handed over.
    Webmachine::ComputeTask.new(request.headers['authorization'].to_s,
                                max_runtime: 500.ms) do |presented|
      Webmachine::Workers::Registry[:db].verify(presented)
    end
  end

  def to_html
    'welcome'
  end
end
```

Everything the worker needs is read in the callback, where the request
exists, and passed as an argument.

`response.userdata` is the run's own slot between its callbacks, in the
run's VM. It survives a `compute` or `watch` stop, because the run
survives it. A worker never sees it.

## Next

- [../tutorial.md](../tutorial.md)
- [configuration.md](configuration.md)
- [command-line.md](command-line.md)
