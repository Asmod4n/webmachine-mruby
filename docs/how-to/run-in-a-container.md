# Run in a container

This how-to is for an operator who wants webmachine-mruby in a
container and needs the short version. The full page,
[`../container.md`](../container.md), builds it, runs it, and covers
every knob; this page states the two facts that most often surprise a
first run.

## seccomp

The fast path needs three syscalls a default seccomp profile usually
blocks: `io_uring_setup`, `io_uring_enter`, `io_uring_register`. Without
them the server still serves - it answers the rings a different way,
and prints which reason applied - but slower, since every socket
operation becomes readiness plus a classic syscall. Allowing the three
syscalls, and the ulimit below, is a performance choice, not a
requirement for the server to start.

## ulimit

Pass `--ulimit nofile=65536:65536` (or another number) at run time.
This sets the file descriptor capacity and the ring's startup memory;
without it, the server runs at whatever ceiling the container's
default gives it.

## Next

- [../container.md](../container.md): build, run, packages, and every
  knob.
- [install.md](install.md): install outside a container.
