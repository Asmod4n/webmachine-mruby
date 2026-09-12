# Write logs

This how-to is for an operator who wants an access log, an error log,
or both. At the end, you have both logs running, know their privacy
setting, and know what the fingerprint in the error log is for.

## Turn them on

Both logs are opt-in, separate files, separate writers, with no field
in common. Without a flag, nothing is written.

    webmachine-server --app=app.mrb --log=/var/log/webmachine/access.log \
      --error-log=/var/log/webmachine/error.log

`--log=FILE` is the access log, one Combined Log Format line per
response. `--error-log=FILE` is what a callback raised: its class,
message, backtrace, the request that led there, and up to 4 KB of the
body the app was sent. Both are written by their own process,
`webmachine-logd`, not by the server itself.

Compile the app with `mrbc -g` so a raise in the error log names a
file and a line; without `-g` the server still runs, but warns once at
start that a raise there will name neither.

## Privacy

`--log-privacy=MODE` controls what the access log's address field
holds: `full` keeps the address, `anon` (the default) drops the host
part, `none` writes no address at all. A client that sends `DNT` or
`Sec-GPC` can only ever raise its own privacy level, never lower it.

## The ceiling

`--log-max-bytes=N` caps the access log at `N` bytes; `0` is no
ceiling, and 500 MB is the default. The access log is a window on
recent traffic: the cap keeps the newest lines and drops the oldest.

The error log has no ceiling and ignores this flag on purpose. It is
not a window: only 500s and exceptions land there, so it only grows
during a fault storm, and in a storm the first entry names the cause
while every line after it is consequence. Keeping the newest half,
which is what the access log's cap does, would drop exactly the line
worth having.

## The fingerprint

Every error log line carries a fingerprint next to the status code: a
hash of the method, the request target, the fields that steered the
answer, the exception class, the backtrace and the status code, over
the running app's own bytecode. The message is left out on purpose:
the same fault at the same place, under the same kind of request, is
one failure whatever the exception happened to say. Grepping for the
fingerprint finds every occurrence of that one fault, for as long as
the app's bytecode does not change; a rebuild gives every fault a new
fingerprint, so an old one can never point at a line that has moved.

## Next

- [../tutorial.md](../tutorial.md)
- [../reference/configuration.md](../reference/configuration.md)
- [../reference/command-line.md](../reference/command-line.md)
