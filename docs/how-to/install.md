# Install on a machine

This how-to is for an operator putting webmachine-mruby on a machine
outside a container. At the end, the four programs and a config file
are in place under one prefix.

## Build the ship binaries first

`rake install` refuses when the ship build is missing, so build it
first:

    rake ship_smoke

This builds the host config - the two binaries an operator installs,
and nothing else - and checks that it starts and answers 200.

## Install

    rake install[PREFIX]

`PREFIX` defaults to `/usr/local`. This lays the tree out by the
Filesystem Hierarchy Standard:

- `PREFIX/bin`: `webmachine-server`, `webmachine-logd`,
  `webmachine-passwd`, and `mrbc`.
- `PREFIX/share/webmachine-mruby`: `error-assets.zip`, the pictures
  error pages carry.
- `PREFIX/etc/webmachine`: `webmachine.toml`, written by
  `--write-config` and kept as it is if one is already there.

## The config file the install leaves you

`webmachine.toml` at `PREFIX/etc/webmachine` has every setting
commented out, each comment showing its default -
[`webmachine.toml.example`](../../webmachine.toml.example) is the same
file, generated the same way. Uncomment a line to change it.

## Where the server looks for it

Without `--config=FILE.toml`, `webmachine-server` looks in this order:
`webmachine.toml` in the directory it was started from, then
`/usr/local/etc/webmachine/webmachine.toml`, then
`/etc/webmachine/webmachine.toml`. It uses the first one it can read.

Running as root skips the first one: naming bytecode to run as root
from a directory somebody else can write is a risk the server refuses
by default. Root can still use that file with an explicit
`--config=webmachine.toml`.

## Next

- [run-in-a-container.md](run-in-a-container.md)
- [../reference/configuration.md](../reference/configuration.md)
- [../reference/command-line.md](../reference/command-line.md)
