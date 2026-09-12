# The decision graph

This page is for a reader who wants to know why a resource here is a
list of answers and not a handler. At the end you know what the server
decides, what a resource decides, and where the line between them is.

## Half of HTTP is the same for every resource

Take one GET. Before the body goes out, the server has to know whether
the service is up, whether the method is allowed, whether the client
can take any of the media types the resource offers, whether the
resource exists, whether the client already holds the current version,
and what `Vary` and `ETag` should say. RFC 9110 answers each of those
questions the same way for every resource on the internet.

A handler that writes the response by hand has to remember all of
that. Most handlers remember some of it.

## The graph asks, the resource answers

webmachine turns those questions into a graph. Every request walks the
same graph, from the first node to the last. Each node asks one
question and cites the clause it comes from: node B13 asks
`service_available?`, node B10 asks `allowed_methods` and writes the
`Allow` field from the answer, node C3 asks `content_types_provided`
and negotiates, node G7 asks `resource_exists?`, node O14 asks
`is_conflict?`.

A resource is a class that answers the questions it cares about. Every
other question has a default answer, and the default is the one the
RFC gives. So a resource that names two media types and an ETag
answers `Accept`, `If-None-Match` and `OPTIONS` correctly with nothing
else written.

The callback names are webmachine-ruby's. Its documentation and its
diagram of the graph apply here. The
[reference](../reference/resource.md) lists every callback with its
node.

## What the resource owns

The resource owns the facts about itself: the media types it can
produce and accept, whether it exists, its ETag and last-modified
time, what happens on POST, PUT and DELETE, and the body. That list is
short, and everything on it is something only the application can
know.

The resource does not own the status code. It answers questions, and
the status is what the graph concludes from the answers. A resource
that says it does not exist gets a 404 from the graph. A resource
whose ETag matches `If-None-Match` gets a 304 from the graph. The
application never writes those numbers.

## Where the body waits

The graph walks on the head of the request. The body, when there is
one, is read only at the three nodes that need it: `process_post`,
`create_path`, and the handler that `content_types_accepted` points
at. A request with a body it may not send, a wrong media type or a
length over the limit, is refused before the body is read. A callback
that needs the body says so with `reads_body`, and the server checks
that declaration when the route is added.

## Next

- [When a method runs](when-a-method-runs.md)
- [Resource callbacks, the reference](../reference/resource.md)
- [Your first server](../tutorial.md)
