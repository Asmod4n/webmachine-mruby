# When a method runs

This page is for a reader who wants to know where the speed comes
from. At the end you know what `def self.` does to a callback, what it
costs, and when to write one.

## Two spellings, two moments

A callback written `def to_html` runs per request. This is the
ordinary form, and most callbacks are written this way. A callback
written `def self.to_html` runs once, when the server starts. The
server keeps what it answered, as bytes: the status line, the head,
the ETag when there is one, and the HTTP/2 header block.

A request against a resource whose answer is kept that way is a lookup
and a write. The Ruby VM is not entered. This is why one core answers
about one million HTTP/1.1 requests a second and ten million HTTP/2
requests a second on such a resource.

## What may be `def self.`

Any callback can be `def self.` when its answer is the same for every
request: the media types, the allowed methods, an ETag that changes
only when the server restarts, a body that is the same for everyone.

A callback that asks about a request is `def`. The four that do work,
`process_post`, `create_path`, `delete_resource` and `finish_request`,
and every callback the graph calls with an argument, such as
`is_authorized?(header)`, are always `def`. The server says so at
start when one of them is written the other way, with the line to
change.

## Not a constant, a moment

A `def self.` callback is a method that runs once. It can read files,
walk a directory, render templates and query a database while the
server comes up, and leave its answer in memory. That is a site
generator that runs at start and never writes an output directory.
`examples/site.rb` and the static half of a site in a pack are the two
ends of that idea.

## A choice per callback

Doing the work at start is a choice, never a condition of using the
server. The same resource written to run per request works. A resource
may fold its media types and run its body per request, or the other
way round. You pick per callback, and an answer can be as static or as
dynamic as HTTP allows.

## Next

- [The decision graph](decision-graph.md)
- [One thread, and the work off it](one-thread.md)
- [An honest number](../../bench/how-to-measure.md)
