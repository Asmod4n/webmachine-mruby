# What a number was made ON and WITH, for the log line beside it.
#
# The harness line already names the client, the transport and the flags a
# config ASKED for. This names what the binary actually carries and what
# it will load, because a host that updated its packages between two runs
# is otherwise invisible: same kernel string, same cflags, a different
# compiler and a different libstdc++, and two numbers that cannot be
# compared look identically labelled.
#
# Read off the BINARY, never off PATH. BIN= points a run at another build
# on purpose, and `gcc --version` would then describe a compiler that
# never touched it. GCC and clang both write themselves into .comment,
# the loader names the shared objects the run will actually use, and
# glibc's own libc.so.6 answers --version, which a symlink cannot.
wm_build_line() {
  wm_bl_bin=$1
  wm_bl_cc=$(readelf -p .comment "$wm_bl_bin" 2>/dev/null |
             grep -oE '(GCC:|clang version).*' | head -1 | sed 's/^GCC: /gcc /' | tr -s ' ')
  wm_bl_cxx=$(ldd "$wm_bl_bin" 2>/dev/null | grep -oE '/[^ ]*libstdc\+\+\.so[^ ]*' | head -1)
  [ -n "$wm_bl_cxx" ] && wm_bl_cxx=$(basename "$(readlink -f "$wm_bl_cxx")")
  # WHICH libc, and whether there is one at all. The path answers the
  # second question and the library itself answers the first.
  #
  # It used to look for the word GLIBC in `libc.so --version`. Ubuntu
  # writes it - "(Ubuntu GLIBC 2.39-0ubuntu8.7)" - and openSUSE writes
  # "(GNU libc)", so the search found nothing there and the line fell
  # back to the word "static". Every run on that machine said the binary
  # was statically linked. It was not. A build line that guesses is worse
  # than one that says it does not know.
  wm_bl_libc_so=$(ldd "$wm_bl_bin" 2>/dev/null | grep -oE '/[^ ]*/libc\.so[^ ]*' | head -1)
  if [ -n "$wm_bl_libc_so" ]; then
    wm_bl_libc_v=$("$wm_bl_libc_so" --version 2>/dev/null | head -1)
    case "$wm_bl_libc_v" in
      *musl*) wm_bl_libc="musl $(printf '%s' "$wm_bl_libc_v" |
                                 grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)" ;;
      *)      wm_bl_libc="glibc $(printf '%s' "$wm_bl_libc_v" |
                                  grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | tail -1)" ;;
    esac
    # A library that answers nothing still counts as present.
    [ "$wm_bl_libc" = "glibc " ] && wm_bl_libc="glibc ?"
  else
    wm_bl_libc=static
  fi
  echo "build: $wm_bl_bin cc=${wm_bl_cc:-?} libstdc++=${wm_bl_cxx:-static}" \
       "libc=${wm_bl_libc:-?} kernel=$(uname -r) host=$(uname -n)"
}
