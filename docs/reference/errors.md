# Errors

This page is for a developer who wants to know what the server
answers when something is wrong, and for an operator who has a
fingerprint from a 500 page. At the end you know the three kinds of
error, which callback each status comes from, what a failure page
holds, and how a fingerprint finds its log record.

## Three kinds

- A refusal the graph makes. A callback answered a question, and the
  RFC says what the status is. A 404 from `resource_exists?` is one.
  Nothing failed.
- A refusal the resource chooses. The callback sets `response.code`
  and a body. Nothing failed either.
- A failure. A callback raised and nothing rescued it. The server
  answers 500 through `Webmachine::ErrorResource`, writes a record to
  the error log, and puts the record's fingerprint on the page.

A 4xx of the first two kinds carries no fingerprint and writes no log
record. It is an answer, not a failure.

## Statuses the graph answers on its own

| Status | From | When |
| --- | --- | --- |
| 300 | `multiple_choices?` | `true` |
| 301 | `moved_permanently?` | a URI, when the resource does not exist |
| 304 | `generate_etag`, `last_modified` | `If-None-Match` or `If-Modified-Since` matches |
| 307 | `moved_temporarily?` | a URI, when the resource does not exist |
| 400 | `malformed_request?` | `true` |
| 401 | `is_authorized?` | `false` |
| 403 | `forbidden?` | `true` |
| 404 | `resource_exists?` | `false`, and not moved, and not previously there |
| 405 | `allowed_methods` | the method is not in the list; `Allow` carries the list |
| 406 | `content_types_provided` | nothing in the list matches `Accept` |
| 409 | `is_conflict?` | `true` |
| 410 | `previously_existed?` | `true`, when the resource does not exist |
| 412 | `generate_etag`, `last_modified` | `If-Match` or `If-Unmodified-Since` fails |
| 413 | `valid_entity_length?`, `max_body` | the declared length is over the limit, before the body is read |
| 414 | `uri_too_long?` | `true` |
| 415 | `known_content_type?`, `content_types_accepted` | the type is unknown, or nothing in the list takes it |
| 501 | `known_methods`, `valid_content_headers?` | the method is unknown, or a `Content-*` field is refused |
| 503 | `service_available?` | `false` |

A request the parser cannot read as HTTP answers 400 before any
callback runs. A client that sends more body than it declared is
refused and the connection closes.

## A refusal the resource chooses

Set the status and, when it helps, a body. `response.code` takes an
Integer from 100 to 599 and refuses anything else with
`ArgumentError`.

```ruby
class Order < Webmachine::Resource
  reads_body :process_post

  def self.allowed_methods
    %w[GET HEAD POST]
  end

  def process_post
    if request.body.read.empty?
      response.code = 422
      response.body = 'an order needs at least one line'
      return true
    end
    true
  end
end
```

`response.error_asset(name)` makes an entry of the error asset pack
the body, with the media type the pack recorded, when a resource wants
the same page the server would show.

## A failure

A raise that reaches no `rescue` is a bug, not a refusal. The route
that produced it answers it through `Webmachine::ErrorResource`. That
class is always there and never routed. Its `handle_exception` turns
the exception into text, and it is the one place that method exists: a
`handle_exception` on an ordinary resource is never called.

```ruby
class Webmachine::ErrorResource
  def handle_exception(e)
    ["#{e.class}: #{e.message}", *e.backtrace]
  end
end
```

The method answers a String, or an Array the server joins with CRLF.
Whether the backtrace goes on the page is your call; the error log
carries it either way. Answer `nil` and the 500 page says only "500".

### The formats

`ErrorResource` negotiates like any other resource, through its own
`content_types_provided`, and the order breaks ties:

| Media type | Handler | What it is |
| --- | --- | --- |
| `text/html; charset=utf-8` | `to_html_error` | the error page, with the status cat when the pack has one |
| `application/problem+json` | `to_json_error` | an RFC 9457 problem document |
| `application/json` | `to_json_error` | the same document, for a client that asked for plain JSON |
| `image/jpeg` | none | the status cat, lent straight out of the pack |
| `text/plain; charset=utf-8` | `to_text_error` | status, title, message, source, backtrace, reference |

The problem document holds `type`, always `"about:blank"`, `title`,
`status`, and, when present, `id`, `detail` and `backtrace`. It has no
`instance` member, because an error page carries nothing the client
sent.

Every handler gets the same Hash: `status`, `title`, `source`, and on a
500 `id`, `message` and, in a debug build, `backtrace`. `cat` is
present only when the pack holds a picture for the status. Add a
format by reopening the class:

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

### The pages

The error pages are files in an asset pack, one picture per status.
`rake error_assets` builds `share/error-assets.zip`, `rake install`
puts it under `PREFIX/share/webmachine-mruby`, and `--error-assets=FILE.zip`
names one by hand. Without a pack the server says so at start and
errors answer in plain text:

    webmachine: no error assets found - errors answer in plain text. Name a file with --error-assets=FILE.zip, or install one as <prefix>/share/webmachine-mruby/error-assets.zip

Nothing the client sent reaches a page: not the request target, not a
header, not the query.

### The fingerprint

A 5xx writes a record to the error log and puts the record's
fingerprint on the page as its reference. The fingerprint is 16
lowercase hex digits: an FNV-1a hash over the build, the method, the
request target, the fields the server steered by, the exception class,
the backtrace and the status. The same failure at the same place gives
the same fingerprint twice. A different request target gives a
different one, even at the same line.

The error log carries the fingerprint on the same line as the request
it belongs to: the target, the method, the message and the backtrace.
An operator greps the fingerprint a user read off the page and finds
the request that caused it. [Logs](../how-to/logs.md) says how to
turn the log on.

## Failures off the request loop

- A compute task over its `max_runtime` answers 500, with no
  `Retry-After`: the deadline was wrong, and a second attempt costs the
  same.
- A worker that raises answers 503 with `Retry-After: 60`.
- A watcher block that raises: the run raises the exception as its
  own, and the failure path above answers it.
- A compute task whose block cannot be dumped, or whose arguments CBOR
  cannot carry, raises at the crossing with the reason.

[Waiting](waiting.md) has each of these beside the declaration.

## Refusals at start

The server checks an application when it loads it, and a wrong
declaration is a message at start with the line to write, never a
surprise under load. The messages name the callback:

- a callback that asks about a request written `def self.`, or one of
  the four that do work written the same way;
- `content_types_accepted names %n, and that callback gets the request
  body - say reads_body :%n`;
- `%n answered a Webmachine::ComputeTask and never declared one - write
  compute %n`;
- a `compute` or `watch` name that is a node callback written on the
  class, or that is not one of `generate_etag`, `last_modified` and
  `expires`;
- `languages_provided` and `charsets_provided`: `does not exist in this
  tree`;
- `listener %d serves TLS and this kernel has no tls ULP (modprobe
  tls)`.

Three classes carry refusals in Ruby: `Webmachine::Error`, and its
subclasses `Webmachine::ConfigError`, for a `conf` value the server
will not take, and `Webmachine::RouteError`, for a route it will not
add. An application can rescue them at the line that raised.

## Next

- [Resource callbacks](resource.md)
- [Request and response](request-and-response.md)
- [Waiting](waiting.md)
- [Write logs](../how-to/logs.md)
