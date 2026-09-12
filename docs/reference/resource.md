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

The graph asks the callbacks in the order below. The node names the
letter and number the decision graph uses for the edge that calls the
callback, from Alan Dean and Justin Sheehy's diagram, with RFC 9110's
clauses beside each edge. Each entry shows the callback in use. A
callback written `def self.` is asked once, while the application
starts, and its answer is kept for the life of the process; a
callback written `def` is asked on every request that reaches the
node. The entry says which forms are allowed.

### Is the service up, and is this request acceptable

#### `service_available?`

Node B13. No arguments. Default `true`. Returns a Boolean. `def self.`
allowed. `false` answers 503.

```ruby
class Api < Webmachine::Resource
  def service_available?
    !MAINTENANCE[0]
  end
end
```

#### `known_methods`

Node B12. No arguments. Default: the server's own method set. Returns
an Array of String, or one String with spaces or commas. `def self.`
allowed. A method outside the list answers 501.

```ruby
class Api < Webmachine::Resource
  def self.known_methods
    %w[GET HEAD POST PUT DELETE OPTIONS PATCH]
  end
end
```

#### `uri_too_long?`

Node B11. Argument: the request URI. Default `false`. Returns a
Boolean. `def` only, because it takes an argument. `true` answers 414.

```ruby
class Api < Webmachine::Resource
  def uri_too_long?(uri)
    uri.length > 2048
  end
end
```

#### `allowed_methods`

Node B10. No arguments. Default: the server's own method set. Returns
an Array of String, or one String. `def self.` allowed. A method
outside the list answers 405, and the list is the `Allow` field.

```ruby
class Article < Webmachine::Resource
  def self.allowed_methods
    %w[GET HEAD PUT DELETE]
  end
end
```

#### `malformed_request?`

Node B9b. No arguments. Default `false`. Returns a Boolean. `def self.`
allowed, but a check of the request is `def`. `true` answers 400.

```ruby
class Search < Webmachine::Resource
  def malformed_request?
    request.query['q'].to_s.empty?
  end
end
```

#### `is_authorized?`

Node B8. Argument: the `Authorization` field, or `nil`. Default
`true`. Returns a Boolean. Asked per request, on the class or the
instance. May be named in `compute` or `watch`. `false` answers 401.

```ruby
class Admin < Webmachine::Resource
  def is_authorized?(header)
    header == "Bearer #{TOKEN}"
  end
end
```

#### `forbidden?`

Node B7. No arguments. Default `false`. Returns a Boolean. `def self.`
allowed. `true` answers 403: the client is known, and still may not.

```ruby
class Report < Webmachine::Resource
  def forbidden?
    request.path_info[:id] != request.cookies['owner']
  end
end
```

#### `valid_content_headers?`

Node B6. Argument: the request's `Content-*` fields. Default `true`.
Returns a Boolean. `def` only. `false` answers 501.

```ruby
class Upload < Webmachine::Resource
  def valid_content_headers?(fields)
    !fields.key?('content-encoding')
  end
end
```

#### `known_content_type?`

Node B5. Argument: the request's `Content-Type`. Default `true`.
Returns a Boolean. `def` only. `false` answers 415.

```ruby
class Upload < Webmachine::Resource
  def known_content_type?(type)
    type.to_s.start_with?('image/')
  end
end
```

#### `valid_entity_length?`

Node B4. Argument: the declared length of the body. Default `true`.
Returns a Boolean. `def` only. `false` answers 413, before a byte of
the body is read. `max_body` below is the class-level form of the same
limit.

```ruby
class Upload < Webmachine::Resource
  def valid_entity_length?(length)
    length.to_i <= 8 * 1024 * 1024
  end
end
```

#### `options`

Node B3. No arguments. Default: not defined, and then the server
writes `Allow`. Returns a Hash of field name to value, the fields of
the answer to OPTIONS. `def self.` allowed.

```ruby
class Api < Webmachine::Resource
  def self.options
    { 'Access-Control-Allow-Origin' => '*' }
  end
end
```

### Negotiation

#### `content_types_provided`

Node C3, C4 and O18. No arguments. Returns an Array of pairs, a media
type and the handler that renders it. `def self.` allowed, and the
usual form. The section below has every form the table takes.

```ruby
class Article < Webmachine::Resource
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def to_html
    "<h1>#{request.path_info[:id]}</h1>"
  end

  def to_json
    %Q({"id":"#{request.path_info[:id]}"})
  end
end
```

#### `languages_provided` and `charsets_provided`

Nodes D4, D5, E5 and E6. Not in this tree: a resource that defines
either one is refused at start with `does not exist in this tree`.

#### `encodings_provided`

Nodes F6 and F7. No arguments. Returns a Hash. Class-only. The
default is identity, and a pack answers gzip on its own.

### Existence and caching

#### `resource_exists?`

Node G7. No arguments. Default `true`. Returns a Boolean. `def self.`
allowed. `false` answers 404 on a read, and leads to `previously_existed?`
and `allow_missing_post?` for the other methods.

```ruby
class Article < Webmachine::Resource
  def resource_exists?
    ARTICLES.key?(request.path_info[:id])
  end
end
```

#### `generate_etag`

Nodes G11 and K13. No arguments. Default: none. Returns a String, or
`nil` for no ETag. `def self.` allowed for an ETag that is the same
for every request; `def` is the usual form. May be named in `compute`
or `watch`. The graph writes `ETag`, and answers `If-None-Match` with
304 and `If-Match` with 412 from it.

```ruby
class Article < Webmachine::Resource
  def generate_etag
    ARTICLES[request.path_info[:id]][:version].to_s
  end
end
```

#### `last_modified`

Nodes H12 and L17. No arguments. Default: none. Returns a `Time`, an
epoch Integer, or `nil`. `def self.` allowed; `def` is the usual form.
May be named in `compute` or `watch`. The graph writes
`Last-Modified` and answers `If-Modified-Since` and
`If-Unmodified-Since` from it.

```ruby
class Article < Webmachine::Resource
  def last_modified
    ARTICLES[request.path_info[:id]][:changed_at]
  end
end
```

#### `expires`

Not a node; read while the answer is written. No arguments. Default:
none. Returns a `Time`, an epoch Integer, or `nil`. `def self.`
allowed. May be named in `compute` or `watch`. The graph writes
`Expires`. A time in the past says a cache must ask again.

```ruby
class Clock < Webmachine::Resource
  def expires
    Time.now - 1
  end
end
```

#### `moved_permanently?`

Nodes I4 and K5. No arguments. Default `false`. Returns `false`, or the
new URI as a String. `def self.` allowed. Asked when the resource does
not exist. A URI answers 301 with `Location`.

```ruby
class OldArticle < Webmachine::Resource
  def self.resource_exists?
    false
  end

  def moved_permanently?
    "/articles/#{request.path_info[:id]}"
  end
end
```

#### `previously_existed?`

Node K7. No arguments. Default `false`. Returns a Boolean. `def self.`
allowed. Asked when the resource does not exist and has not moved.
`true` answers 410 instead of 404.

```ruby
class Article < Webmachine::Resource
  def resource_exists?
    ARTICLES.key?(request.path_info[:id])
  end

  def previously_existed?
    DELETED.include?(request.path_info[:id])
  end
end
```

#### `moved_temporarily?`

Node L5. No arguments. Default `false`. Returns `false`, or the new URI
as a String. `def self.` allowed. A URI answers 307 with `Location`.

```ruby
class Mirror < Webmachine::Resource
  def self.resource_exists?
    false
  end

  def moved_temporarily?
    "https://mirror.example/#{request.path}"
  end
end
```

### Writing

#### `allow_missing_post?`

Nodes M7 and N5. No arguments. Default `false`. Returns a Boolean.
`def self.` allowed. `true` lets a POST to a resource that does not
exist go on to `process_post` instead of answering 404.

```ruby
class Inbox < Webmachine::Resource
  def self.allow_missing_post?
    true
  end
end
```

#### `post_is_create?`

Node N11. No arguments. Default `false`. Returns a Boolean. `def self.`
allowed. `true` means a POST creates a new resource: the graph asks
`create_path` and then the handler `content_types_accepted` names.
`false` means the graph asks `process_post`.

#### `create_path`

Node N11. No arguments. Default: none. Returns the path of the new
resource as a String. `def` only. The answer is 201 with `Location`.

```ruby
class Articles < Webmachine::Resource
  reads_body :from_json

  def self.allowed_methods
    %w[GET HEAD POST]
  end

  def self.post_is_create?
    true
  end

  def self.content_types_accepted
    [['application/json', :from_json]]
  end

  def create_path
    @id = ARTICLES.size.to_s
    "/articles/#{@id}"
  end

  def from_json
    ARTICLES[@id] = request.body.read
    true
  end
end
```

#### `process_post`

Node N11. No arguments. Default: none. Returns a Boolean. `def` only,
and it must be named in `reads_body` to read the body. `true` answers
200 with the body the callback set, or 204 without one.

```ruby
class Counter < Webmachine::Resource
  reads_body :process_post
  COUNT = [0]

  def self.allowed_methods
    %w[GET HEAD POST]
  end

  def process_post
    COUNT[0] += request.body.read.to_i
    response.body = COUNT[0].to_s
    true
  end
end
```

#### `content_types_accepted`

Nodes O14 and P3. No arguments. Default: none, and a resource that
allows PUT or POST must define it. Returns an Array of pairs, a media
type and the handler that reads it, with an optional `{sniff: true}`
third member. `def self.` allowed, and the usual form. The handler
must be named in `reads_body`.

```ruby
class Photo < Webmachine::Resource
  reads_body :from_png, save: true

  def self.allowed_methods
    %w[GET HEAD PUT]
  end

  def self.content_types_accepted
    [['image/png', :from_png, { sniff: true }]]
  end

  def from_png
    request.body.save('/var/photos', 'photo.png') { |dir, _err| dir }
  end
end
```

#### `is_conflict?`

Nodes O14 and P3. No arguments. Default `false`. Returns a Boolean.
`def self.` allowed. Asked before a PUT is read. `true` answers 409.

```ruby
class Document < Webmachine::Resource
  def is_conflict?
    request.if_match.nil? && DOCS.key?(request.path_info[:id])
  end
end
```

#### `delete_resource`

Node M20. No arguments. Default `false`. Returns a Boolean. `def` only.
`true` means the delete was accepted; `false` answers 500.

#### `delete_completed?`

Node M20b. No arguments. Default `true`. Returns a Boolean. `def self.`
allowed. `true` answers 204 or 200; `false` answers 202, the delete is
still going on.

```ruby
class Document < Webmachine::Resource
  def self.allowed_methods
    %w[GET HEAD DELETE]
  end

  def delete_resource
    !DOCS.delete(request.path_info[:id]).nil?
  end

  def self.delete_completed?
    true
  end
end
```

### The answer

#### `multiple_choices?`

Node O18b. No arguments. Default `false`. Returns a Boolean. `def self.`
allowed. `true` answers 300 with the body the resource rendered.

#### `variances`

Not a node. No arguments. Default `[]`. Returns an Array of String,
field names added to `Vary` beside the ones negotiation adds.
`def self.` allowed.

```ruby
class Greeting < Webmachine::Resource
  def self.variances
    ['Cookie']
  end
end
```

#### `max_body`

Not a node. No arguments. Default: `conf.max_body`, else 1 MiB.
Returns an Integer, octets. Class-only; an instance method is refused.
A declared length above it answers 413 before the body is read.

```ruby
class Upload < Webmachine::Resource
  def self.max_body
    64 * 1024 * 1024
  end
end
```

#### `finish_request`

Not a node; the last callback, after the answer is decided. No
arguments. The return value is ignored. `def` only. May be named in
`compute`. The place for a field every answer of this resource
carries.

```ruby
class Api < Webmachine::Resource
  def finish_request
    response.headers['Cache-Control'] = 'private'
  end
end
```

#### `handle_exception`

Not a node. Argument: the exception a callback raised. Default:
`"#{e.class}: #{e.message}"`. Returns a String, or an Array the server
joins with CRLF, as the body of the 500. Instance only.

```ruby
class Api < Webmachine::Resource
  def handle_exception(e)
    "something went wrong: #{e.class}"
  end
end
```

## Combinations

Four resources, each a common shape.

### A document that is read and cached

Negotiation and conditional requests, and nothing written.

```ruby
class Article < Webmachine::Resource
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def resource_exists?
    @article = ARTICLES[request.path_info[:id]]
    !@article.nil?
  end

  def generate_etag
    @article[:version].to_s
  end

  def last_modified
    @article[:changed_at]
  end

  def to_html
    "<h1>#{@article[:title]}</h1>"
  end

  def to_json
    %Q({"title":"#{@article[:title]}"})
  end
end
```

`resource_exists?` runs first and keeps what it found, so the later
callbacks read `@article` instead of looking it up again. The graph
answers 404, 304, 412 and 406 from these six methods.

### A collection that creates on POST

```ruby
class Articles < Webmachine::Resource
  reads_body :from_json

  def self.allowed_methods
    %w[GET HEAD POST]
  end

  def self.content_types_provided
    [['application/json', :to_json]]
  end

  def self.content_types_accepted
    [['application/json', :from_json]]
  end

  def self.post_is_create?
    true
  end

  def create_path
    @id = ARTICLES.size.to_s
    "/articles/#{@id}"
  end

  def from_json
    ARTICLES[@id] = request.body.read
    true
  end

  def to_json
    "[#{ARTICLES.keys.join(',')}]"
  end
end
```

A POST with `Content-Type: application/json` answers 201 with
`Location: /articles/N`. A POST with another type answers 415 before
the body is read.

### A document that is replaced with PUT and removed with DELETE

```ruby
class Document < Webmachine::Resource
  reads_body :from_text

  def self.allowed_methods
    %w[GET HEAD PUT DELETE]
  end

  def self.content_types_provided
    [['text/plain', :to_text]]
  end

  def self.content_types_accepted
    [['text/plain', :from_text]]
  end

  def resource_exists?
    DOCS.key?(request.path_info[:id])
  end

  def is_conflict?
    request.if_match.nil? && resource_exists?
  end

  def from_text
    DOCS[request.path_info[:id]] = request.body.read
    true
  end

  def delete_resource
    !DOCS.delete(request.path_info[:id]).nil?
  end

  def to_text
    DOCS[request.path_info[:id]]
  end
end
```

A PUT to a new id creates it and answers 201. A PUT to an existing id
without `If-Match` answers 409. A DELETE answers 204.

### A protected resource with the password check on a worker

```ruby
Webmachine::Workers::Registry[:passwords] = proc do
  { 'ada' => Argon2.hash('secret')[:encoded] }
end

class Admin < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(header)
    Webmachine::ComputeTask.new(header, max_runtime: 200.ms) do |h|
      user, pass = h.to_s.split(':', 2)
      stored = Webmachine::Workers::Registry[:passwords][user]
      stored ? Argon2.verify(stored, pass.to_s) : false
    end
  end

  def forbidden?
    request.path_info[:id] == 'root'
  end

  def to_html
    '<h1>admin</h1>'
  end
end
```

The hash runs on a worker with a deadline, and the request loop keeps
taking requests while it does. `forbidden?` runs after it, on the
loop, because it is a lookup.

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
