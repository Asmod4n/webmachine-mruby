# Shared by floor.sh, h2.sh, pipeline.sh and profile.sh.
#
# The server refuses --unix and --port beside --app. An application
# names its own listener, pack and docroot in its conf, and one process
# serves any number of applications. The harness knows the socket path
# only when it runs, so it writes the listener into the app source
# before it compiles it. A bench app reads BENCH_LISTEN.
#
# The server also loads bytecode only (#100). The tree's own mrbc
# compiles the source into a scratch .mrb, and the harness line keeps
# naming the .rb.
#
# bench_app WORK LISTEN
#   WORK    scratch directory
#   LISTEN  a Ruby hash: { unix_path: "..." } or { port: 8080 }
#   reads   APP, MRBC
#   writes  APP_ARGS
bench_app() {
  local work="$1" listen="$2" mrbc src
  APP_ARGS=()
  [ -n "${APP:-}" ] || return 0

  case "$APP" in
    *.rb) ;;
    *)
      echo "APP=$APP: the harness writes the listener into the app source, so it needs the .rb" >&2
      exit 1
      ;;
  esac

  mrbc="${MRBC:-mruby/bin/mrbc}"
  [ -x "$mrbc" ] || { echo "mrbc not found at $mrbc - rake compile builds it, or set MRBC=" >&2; exit 1; }

  src="$work/app.rb"
  { printf 'BENCH_LISTEN = %s\n' "$listen"; cat "$APP"; } > "$src" || exit 1
  "$mrbc" -o "$work/app.mrb" "$src" || exit 1
  APP_ARGS=(--app="$work/app.mrb")
}
