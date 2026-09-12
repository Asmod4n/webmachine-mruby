# One thread, and the work off it

This page is for a reader who asks how one thread can be enough. At
the end you know what the one thread does, what must not run on it,
and the two ways to take work off it.

## One thread takes every request

`webmachine-server` is one process and one thread. That thread accepts
connections, parses requests, walks the decision graph, and writes the
answers. It runs on io_uring where the kernel allows it, so a socket
operation is a submission and a completion, not a call that waits. One
thread that never waits serves every connection in turn.

The cost of that design is a rule: a callback must not wait. A
callback that hashes a password for 200 milliseconds, or that waits on
a database socket, stops every other connection for as long as it
waits.

## Two declarations, and the loop keeps taking requests

A callback that waits says so on the class. The graph stops at that
node, and goes on with the answer when it arrives. Nothing else on the
server waits with it.

`compute` sends a block to a worker thread, with a deadline. Each
worker has its own Ruby VM and its own ring. The block is dumped once
and every worker keeps it, so per request only its arguments and its
answer cross. A dumped block carries no environment: a local variable
from around it and an instance variable both read as `nil` in the
worker. Pass what the block needs as an argument, or build it once per
worker through `Webmachine::Workers::Registry`. A task over its
deadline answers 500. A worker that raises answers 503 with
`Retry-After`.

`watch` waits on a descriptor in the server's own thread. The block
runs each time the descriptor is ready, until it says `abort`, and its
last value is the callback's answer. Because the block stays in the
request, `request` and `response` are in reach. A database socket
driven this way answers the request without leaving the loop.

`reads_body` is the third declaration. It names the callback that
waits for the octets of a request body.

## Which one to use

Use `compute` when the work is the CPU's: hashing, compression,
rendering. Use `watch` when the work is another process's and you hold
a descriptor to it: a database, a queue, a pipe. Use neither when the
callback is a lookup; a lookup is faster on the loop than off it.

## Next

- [Work off the request loop, the how-to](../how-to/work-off-the-loop.md)
- [Waiting, the reference](../reference/waiting.md)
- [When a method runs](when-a-method-runs.md)
