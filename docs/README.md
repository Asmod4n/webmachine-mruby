# Documentation

The docs are split by what you need from them. A tutorial teaches by
doing. A how-to guide does one job. A reference page lists everything
about one thing. An explanation page says why a thing is the way it
is.

## Tutorial

- [Your first server](tutorial.md): build, write a resource, answer a
  request, add a second media type, answer a conditional request with
  304.

## How-to guides

One job per page, for a reader who already runs a server.

- [Serve static files](how-to/serve-static-files.md): a pack, a
  directory, and the standalone server.
- [Accept uploads](how-to/accept-uploads.md): request bodies, size
  limits, `request.body.save`.
- [Work off the request loop](how-to/work-off-the-loop.md): `compute`
  on a worker thread, `watch` on a descriptor.
- [Add a WebSocket endpoint](how-to/websocket.md)
- [Send server-sent events](how-to/server-sent-events.md)
- [Serve TLS](how-to/tls.md): a certificate, a key, and kTLS.
- [Write logs](how-to/logs.md): the access log, the error log, and
  `webmachine-logd`.
- [Keep passwords](how-to/passwords.md): `webmachine-passwd` and a
  login that hashes on a worker.
- [Install on a machine](how-to/install.md): `rake install`, the
  layout, the config file.
- [Run in a container](how-to/run-in-a-container.md), and
  [the container in full](container.md).

## Reference

Complete and dry. Structured like the thing it describes.

- [Resource callbacks](reference/resource.md): every callback the
  decision graph calls, its node, its default, and whether it may be
  `def self.`.
- [Request and response](reference/request-and-response.md): every
  method on both objects.
- [Configuration](reference/configuration.md): `Application`, routes,
  every `app.conf` key, every `webmachine.toml` key.
- [Waiting](reference/waiting.md): `compute`, `watch`, `reads_body`,
  `ComputeTask`, `Watcher`, the worker registry.
- [WebSocket and server-sent events](reference/websocket-and-sse.md):
  `WebsocketResource` and `SseResource`.
- [Command line](reference/command-line.md): the four programs, the
  rake tasks, the build configs.

## Explanation

- [The decision graph](explanation/decision-graph.md): why the server
  owns half of HTTP, and what a resource owns.
- [When a method runs](explanation/when-a-method-runs.md): `def self.`
  once at start, `def` per request, and why that is where the speed
  comes from.
- [One thread, and the work off it](explanation/one-thread.md): why
  the server is one thread, and how `compute` and `watch` keep it
  answering.
- [An honest number](../bench/how-to-measure.md): how a benchmark is
  run so that a change in the code is visible.

## Elsewhere in the tree

- `examples/`: one file per kind of resource. `examples/site/` is a
  four-page htmx site served from an asset pack.
- `webmachine.toml.example`: every setting, with what it does, written
  by the server itself.
- `tools/conformance.sh`: h2spec and Autobahn, and the one known
  refusal.
- `CLAUDE.md`: the rules of the repository.
