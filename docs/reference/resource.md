# Resource reference

This page is for a developer who writes a `Webmachine::Resource`
subclass and needs the exact contract for one callback. At the end,
you know every callback the decision graph calls, its node, its
arguments, its default answer, what the server does with it, and
whether it may run once at start or must run per request.

Every request walks the same graph. The
[decision graph](../explanation/decision-graph.md) explains why the
graph exists and what it owns; this page lists what it calls. A
resource is a class that answers the questions it cares about; every
other question keeps the default the table below names.

`request` and `response` are covered in full on the
[request and response reference](request-and-response.md). `compute`,
`watch`, `reads_body`, `Webmachine::ComputeTask` and
`Webmachine::Watcher` are covered on the [waiting reference](waiting.md).

## Every callback

The node column names the letter and number the decision graph uses
for the edge that calls this callback, from Alan Dean and Justin
Sheehy's diagram, with RFC 9110's clauses beside each edge. "Once" in the "runs"
column means a `def self.` answer is asked one time, while the
application starts, and kept for the life of the process. "Per
request" means the answer is asked again on every request that reaches
the node.

### `service_available?`

Node B13. Arguments: none. Default: `true`. Returns: Boolean. `def self.`: Yes, once.

`false` halts 503.

### `known_methods`

Node B12. Arguments: none. Default: the server's own HTTP method set. Returns: Array of String, or a space/comma-separated String. `def self.`: Yes, once, or per request as `def`.

A request method outside the list halts 501.

### `uri_too_long?`

Node B11. Arguments: the URI. Default: `false`. Returns: Boolean. `def self.`: No - takes an argument.

`true` halts 414.

### `allowed_methods`

Node B10. Arguments: none. Default: the server's own HTTP method set. Returns: Array of String, or a space/comma-separated String. `def self.`: Yes, once, or per request as `def`.

Writes `Allow`; a method outside the list halts 405.

### `malformed_request?`

Node B9b. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` halts 400.

### `is_authorized?`

Node B8. Arguments: the `Authorization` field, or `nil`. Default: `true`. Returns: Boolean. `def self.`: Yes - asked per request on the class, not frozen. May be named in `compute` or `watch`.

`false` halts 401 and asks for `WWW-Authenticate`.

### `forbidden?`

Node B7. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` halts 403.

### `valid_content_headers?`

Node B6. Arguments: the request's Content-* fields. Default: `true`. Returns: Boolean. `def self.`: No - takes an argument.

`false` halts 501.

### `known_content_type?`

Node B5. Arguments: the request's `Content-Type`. Default: `true`. Returns: Boolean. `def self.`: No - takes an argument.

`false` halts 415.

### `valid_entity_length?`

Node B4. Arguments: the body's declared length. Default: `true`. Returns: Boolean. `def self.`: No - takes an argument.

`false` halts 413.

### `options`

Node B3. Arguments: none. Default: not defined: writes `Allow`. Returns: Hash of field name to value. `def self.`: Yes, once, or per request as `def`.

Answers an `OPTIONS` request with 200; a Hash writes each pair as a field instead of the default `Allow` line.

### `content_types_provided`

Node C3/C4/O18. Arguments: none. Default: see below. Returns: Array of `[type, handler_symbol]` pairs. `def self.`: Yes, once, or per request as `def`.

Negotiates `Accept`; 406 when nothing matches; the chosen handler renders the body.

### `languages_provided`

Node D4/D5. Arguments: none. Default: not implemented. Returns: -. `def self.`: Refused.

Defining this raises at fold time: this tree has no i18n conversion.

### `charsets_provided`

Node E5/E6. Arguments: none. Default: not implemented. Returns: -. `def self.`: Refused.

Same refusal as `languages_provided`.

### `encodings_provided`

Node F6/F7. Arguments: none. Default: not implemented per-request. Returns: Hash. `def self.`: Yes, class-only.

Must be `def self.`; an instance method is refused.

### `resource_exists?`

Node G7. Arguments: none. Default: `true`. Returns: Boolean. `def self.`: Yes, once.

`false` walks the "does not exist yet" branch instead of the caching branch.

### `generate_etag`

Node G11/K13. Arguments: none. Default: not present. Returns: String or `nil`. `def self.`: Yes, once, or per request as `def`. May be named in `compute` or `watch`.

Spells an `ETag`; feeds `If-Match`/`If-None-Match` checks (412/304).

### `last_modified`

Node H12/L17. Arguments: none. Default: not present. Returns: `Time`, an epoch Integer, or `nil`. `def self.`: Yes, once, or per request as `def`. May be named in `compute` or `watch`.

Spells `Last-Modified`; feeds `If-Unmodified-Since`/`If-Modified-Since` (412/304).

### `moved_permanently?`

Node I4/K5. Arguments: none. Default: `false`. Returns: `false`, or a String/URI. `def self.`: Yes, once.

A truthy answer halts 301 and writes `Location` from it.

### `previously_existed?`

Node K7. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` walks the "gone" branch (410-eligible); `false` walks the "never existed" branch (404).

### `moved_temporarily?`

Node L5. Arguments: none. Default: `false`. Returns: `false`, or a String/URI. `def self.`: Yes, once.

A truthy answer halts 307 and writes `Location` from it.

### `allow_missing_post?`

Node M7/N5. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` lets a POST proceed against a resource that does not exist (`false` halts 404 or 410).

### `delete_resource`

Node M20. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: No - runs per request. Refused as `def self.`.

`false` halts 500; `true` continues to `delete_completed?`.

### `delete_completed?`

Node M20b. Arguments: none. Default: `true`. Returns: Boolean. `def self.`: Yes, once.

`false` halts 202 (accepted, not yet done).

### `post_is_create?`

Node N11. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` calls `create_path`; `false` calls `process_post`.

### `create_path`

Node N11. Arguments: none. Default: not present. Returns: String. `def self.`: No - runs per request. Refused as `def self.`.

The new path; a missing `Location` is filled from it and `base_uri`.

### `process_post`

Node N11. Arguments: none. Default: not present. Returns: Boolean, or a value the flow treats as truthy/falsy. `def self.`: No - runs per request. Refused as `def self.`.

Handles the POST; `false` is a failure.

### `is_conflict?`

Node O14/P3. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` halts 409; `false` runs the negotiated `content_types_accepted` handler.

### `content_types_accepted`

Node O14/P3. Arguments: none. Default: none - a resource that accepts a body must define it. Returns: Array of `[type, handler_symbol]`, each optionally followed by `{sniff: true}`. `def self.`: Yes, once, or per request as `def`.

Negotiates the request's `Content-Type`; no match halts 415.

### `multiple_choices?`

Node O18b. Arguments: none. Default: `false`. Returns: Boolean. `def self.`: Yes, once.

`true` halts 300 instead of 200.

### `variances`

Node -. Arguments: none. Default: `[]`. Returns: Array of String. `def self.`: Yes, once, or per request as `def`.

Extra `Vary` field names beside the ones negotiation already added.

### `max_body`

Node -. Arguments: none. Default: `conf.max_body`, else 1 MiB. Returns: Integer, octets. `def self.`: Yes, class-only; an instance method is refused.

A larger declared `Content-Length` halts 413 before a byte is read.

### `expires`

Node -. Arguments: none. Default: not present. Returns: `Time`, an epoch Integer, or `nil`. `def self.`: Yes, once, or per request as `def`. May be named in `compute` or `watch`.

Spells an `Expires` field.

### `finish_request`

Node -. Arguments: none. Default: not present. Returns: ignored. `def self.`: No - runs per request. Refused as `def self.`. May be named in `compute`.

Runs after every request, including one that raised, if the resource defines it.

### `handle_exception`

Node -. Arguments: the exception. Default: class default: `"#{e.class}: #{e.message}"`. Returns: String, or an Array the server joins with CRLF. `def self.`: Instance only; not a `def self.` question.

Only honoured on `Webmachine::ErrorResource`; ignored on an ordinary resource.


## The `def self.` rule

A `def self.x` on a resource runs once, while the application starts.
The fold asks it, keeps the answer, and freezes the class right after - 
so the answer can never go stale, and it never sees a request.

That is the right shape for a question with one answer for the whole
process. It is the wrong shape for a callback that takes an argument:
an argument means the callback is asking about *this* request - the
URI, the fields, the type, the length - and a class method never sees
one. The fold checks this at startup:

> `def self.%n takes an argument, so it asks about a request - a class
> method runs once at start and sees none. Write def %n`

The same fold refuses the reverse mistake for a callback that does
real work - `delete_resource`, `create_path`, `process_post`, and
`finish_request` - because a class-level version of one of these would
run exactly once, at start, and answer zero requests, silently:

> `%s does work, so it runs per request - declare it on the instance
> (def %s), not on the class: def self.%s would be asked once at start
> and never again`

Two more names are refused outright, because this tree has no
implementation behind them:

> `%s is defined but i18n/charset conversion does not exist in this
> tree`

 - for `languages_provided`, `charsets_provided`, and `language_chosen`.

And two names must be the class form and only the class form, because
they shape a compiled table rather than answer a question:

> `%s shapes the compiled vectors - declare it konst (def self.%s)`

 - for `encodings_provided` and `max_body`.

For the value-semantics callbacks - `known_methods`, `allowed_methods`,
`content_types_provided`, `content_types_accepted`, `options`,
`variances`, `generate_etag`, `last_modified`, and `expires` - either
form is honoured. An instance method (`def`) wins when both are
defined, and is asked again on every request; a class method
(`def self.`) is asked once and frozen. `is_authorized?` is the one
exception among the boolean callbacks: it takes an argument, so
`def self.` is not refused for taking one, but it is asked again on
every request rather than frozen, because `compute` or `watch` may
answer it from a worker or a descriptor.

## `content_types_provided` and `content_types_accepted`

Both answer an Array of pairs. A pair is `[String, Symbol]`: a media
type, and the name of the instance method that renders it (provided)
or reads it (accepted). Both tables are the same for every request, so
they are written `def self.` and read once at start. Written `def`,
they are read per request, which is allowed and slower. `content_types_provided` must answer at least
one pair; `content_types_accepted` has no default and a resource that
allows a body-carrying method must define it, or every such request
gets 415.

```ruby
class Order < Webmachine::Resource
  reads_body :from_json

  def self.allowed_methods
    %w[GET HEAD PUT]
  end

  def self.content_types_provided
    [['text/html; charset=utf-8', :to_html],
     ['application/json', :to_json]]
  end

  def self.content_types_accepted
    [['application/json', :from_json]]
  end

  def self.resource_exists?
    true
  end

  def generate_etag
    'v1'
  end

  def to_html
    '<html><body>ok</body></html>'
  end

  def to_json
    '{"ok":true}'
  end

  def from_json
    true
  end
end
```

A row of `content_types_accepted` may carry a third member, a Hash
with `sniff: true`. When present, the server checks the first bytes of
the body against the type the request declared (the WHATWG MIME
Sniffing Standard's table) and answers 415 when they disagree - before
the handler runs, and before a large lie is read in full.

A handler `content_types_accepted` names must be declared with
`reads_body`, or the request raises:

> `content_types_accepted names %n, and that callback gets the request
> body - say reads_body :%n`

## The error path

An exception that reaches no `rescue` is answered by
`Webmachine::ErrorResource`, and only by it - a `handle_exception` on
an ordinary resource is never called. `handle_exception` turns the
exception into a String, or an Array the server joins with CRLF. A
`nil` answer is a 500 page that says only "500".

```ruby
class Webmachine::ErrorResource
  def handle_exception(e)
    ["#{e.class}: #{e.message}", *e.backtrace]
  end
end
```

`ErrorResource` negotiates like any other resource, through its own
`content_types_provided`:

- `text/html; charset=utf-8` -> `to_html_error`
- `application/problem+json` -> `to_json_error`, an RFC 9457 problem
  document (`problem_document`): `type` is always `"about:blank"`,
  plus `title`, `status`, and - when present - `id`, `detail`, and
  `backtrace`.
- `application/json` -> the same `to_json_error`, since a client asking
  for `application/json` meant the same thing as `+json`.
- `image/jpeg` -> the status cat, lent straight out of the error asset
  pack; no method is called for this row.
- `text/plain; charset=utf-8` -> `to_text_error`

A resource can add a format by reopening the class:

```ruby
class Webmachine::ErrorResource
  def self.content_types_provided
    super + [['application/xml', :to_xml_error]]
  end

  def to_xml_error(e)
    "<error status=\"#{e['status']}\">#{e['title']}</error>"
  end
end
```

Every handler is handed the same Hash, which is also the template
context: `status`, `title`, `source`, and - on a 500 - `id`, `message`,
and, in a debug build, `backtrace`. `cat` is present only when the
asset pack holds a picture for the status.

Nothing the client sent reaches the page: not the request target, not
a header, not the query. A 4xx is an answer, not a failure, so it
carries no fingerprint and nothing is written to the error log. A 5xx
does: the fingerprint is 16 lowercase hex digits, an FNV-1a hash over
the build, the method, the request target, the fields the server
steered by, the exception class, the backtrace, and the status. The
same failure at the same place hashes the same twice; a different
request target is a different fingerprint even at the same line. The
error log carries the fingerprint on the same line as the request it
belongs to - the target, the method, the message, the backtrace - so
an operator greps the fingerprint a user read off the page and finds
the request that caused it.

## Base class helpers

`Webmachine::Resource.new` is refused - a resource is the server's to
build, one per request, from the class a route named:

> `a resource is the server's to build, one per request - name the
> class in a route, never an instance`

Four class methods are defined on `Webmachine::Resource` itself:
`compute`, `watch`, and `reads_body`, which declare a callback's
relationship to the request loop (see the
[waiting reference](waiting.md)), and the refused `new` above.
`request` and `response` are the two per-callback handles onto the
current exchange; see the
[request and response reference](request-and-response.md) for their
full method lists.

## Where the body is read

A callback only receives the request body when the resource named it
with `reads_body`:

```ruby
class Upload < Webmachine::Resource
  reads_body :process_post

  def self.allowed_methods
    %w[POST]
  end

  def process_post
    request.body.read
    true
  end
end
```

Before this declaration existed, a run stopped for the body whenever
the fold found one of the three callbacks that can read one
(`process_post`, `create_path`, or a `content_types_accepted` handler)
and nothing in the resource said so. Now the names are explicit, and a
handler `content_types_accepted` names without a matching `reads_body`
raises at request time (see above).

`reads_body :name, save: true` additionally promises that `name` may
call `request.body.save`. The head reads this promise before the first
octet arrives and puts the body in a file even when it is small, so
the save is a filesystem link rather than a second write of the
octets. Calling `request.body.save` from a callback that did not make
this promise is refused:

> `%s gets the request body, so the run stops for it - say
> reads_body :%s`

## Next

- [The decision graph](../explanation/decision-graph.md)
- [Request and response](request-and-response.md)
- [Waiting](waiting.md)
- [WebSocket and server-sent events](websocket-and-sse.md)
