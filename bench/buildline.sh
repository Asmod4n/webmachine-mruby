# What a number was made on and with, for the log line beside it.
#
# The harness line already names the client, the transport and the flags a
# config asked for. This names what the binary actually carries and what
# it will load, because a host that updated its packages between two runs
# is otherwise invisible: same kernel string, same cflags, a different
# compiler and a different libstdc++, and two numbers that cannot be
# compared look identically labelled.
#
# Read off the binary, never off PATH. BIN= points a run at another build
# on purpose, and `gcc --version` would then describe a compiler that
# never touched it. GCC and clang both write themselves into .comment,
# the loader names the shared objects the run will actually use, and
# glibc's own libc.so.6 answers --version, which a symlink cannot.
wm_build_line() {
  wm_bl_bin=$1
  # .comment holds one string per object the link took. crt1.o, crti.o
  # and libc_nonshared.a come from the distribution's GCC and stand
  # first on the link line, so a clang binary carries a GCC string
  # ahead of its own. A GCC binary carries no clang string at all, so
  # a clang string anywhere in the section names the compiler.
  wm_bl_comment=$(readelf -p .comment "$wm_bl_bin" 2>/dev/null)
  wm_bl_cc=$(printf '%s\n' "$wm_bl_comment" | grep -oE 'clang version.*' | head -1 | tr -s ' ')
  [ -n "$wm_bl_cc" ] ||
    wm_bl_cc=$(printf '%s\n' "$wm_bl_comment" | grep -oE 'GCC:.*' | head -1 | sed 's/^GCC: /gcc /' | tr -s ' ')
  wm_bl_cxx=$(ldd "$wm_bl_bin" 2>/dev/null | grep -oE '/[^ ]*libstdc\+\+\.so[^ ]*' | head -1)
  [ -n "$wm_bl_cxx" ] && wm_bl_cxx=$(basename "$(readlink -f "$wm_bl_cxx")")
  # Which libc, and whether there is one at all. The path answers the
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
  # Where the run happened, and not only what it was built with. Same
  # hardware, WSL2 against bare metal, read half the rate - so a row
  # that does not say which of the two it is cannot be compared with
  # one that is the other. host= is the machine's name and was never
  # this; on= is.
  #
  # systemd-detect-virt answers both questions at once (--vm and
  # --container), and where it is absent the hypervisor flag in
  # /proc/cpuinfo answers the first. Unreadable is said, never guessed.
  wm_bl_on=""
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    wm_bl_vm=$(systemd-detect-virt --vm 2>/dev/null)
    wm_bl_ct=$(systemd-detect-virt --container 2>/dev/null)
    [ "$wm_bl_vm" != none ] && [ -n "$wm_bl_vm" ] && wm_bl_on="$wm_bl_vm"
    if [ "$wm_bl_ct" != none ] && [ -n "$wm_bl_ct" ]; then
      wm_bl_on="${wm_bl_on:+$wm_bl_on/}$wm_bl_ct"
    fi
    [ -z "$wm_bl_on" ] && wm_bl_on=metal
  elif grep -q '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null; then
    wm_bl_on="a hypervisor, kind unreadable"
  elif [ -r /proc/cpuinfo ]; then
    wm_bl_on=metal
  else
    wm_bl_on=unreadable
  fi
  # What the hardware is, because nothing else in this line says it.
  # host= is the machine's name and on a Firecracker fleet every guest
  # is called vm whatever it runs on, so that field identifies nothing
  # and looks as though it does. The guest's model name is masked too -
  # "Intel(R) Xeon(R) Processor @ 2.80GHz", no model number, and no DMI
  # at all. What is left and does discriminate: the family, model and
  # stepping numbers, the base clock, and what -march=native resolves
  # to, which the harness line already carries.
  wm_bl_cpu=$(awk -F': ' '
      /^cpu family/ { f = $2 }
      /^model\t/    { m = $2 }
      /^stepping/   { s = $2 }
      /^cpu MHz/    { hz = $2 }
      END { if (f == "") { print "unreadable" }
            else { printf "%s:%s:%s@%dMHz", f, m, s, hz } }
    ' /proc/cpuinfo 2>/dev/null)
  # The caches and the feature set, which a guest does show. They are
  # what is left of the hardware's identity once the model name is
  # masked, and the L3 size narrows a family:model:stepping to a few
  # parts. The L1i is in there because this tree reasons about it: the
  # cold-path rule in CLAUDE.md measures against 32 KiB, and that is
  # read here rather than assumed.
  wm_bl_cache=$(
    for wm_bl_ix in /sys/devices/system/cpu/cpu0/cache/index*; do
      [ -r "$wm_bl_ix/level" ] || continue
      printf '%s%s ' "$(cat "$wm_bl_ix/type" | cut -c1)" "$(cat "$wm_bl_ix/size")"
    done 2>/dev/null
  )
  wm_bl_cache=$(printf '%s' "$wm_bl_cache" | tr ' ' '/' | sed 's,/$,,')
  [ -n "$wm_bl_cache" ] || wm_bl_cache=unreadable
  # 93 flags do not belong on every row, and a difference in any one of
  # them does. The count catches a gross difference at a glance and the
  # digest catches every other, so two rows can be told apart without
  # either carrying the list.
  wm_bl_flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null |
                cut -d: -f2- | tr ' ' '\n' | sed '/^$/d' | sort)
  if [ -n "$wm_bl_flags" ]; then
    wm_bl_flag_n=$(printf '%s\n' "$wm_bl_flags" | wc -l | tr -d ' ')
    wm_bl_flag_d=$(printf '%s\n' "$wm_bl_flags" | cksum | cut -d' ' -f1)
    wm_bl_flags="$wm_bl_flag_n:$wm_bl_flag_d"
  else
    wm_bl_flags=unreadable
  fi
  # Which scheduler actually placed the threads.
  #
  # kernel= does not answer this. A sched_ext scheduler is BPF, it is
  # loaded at run time, and it takes the decision out of the kernel the
  # name above belongs to: a CachyOS box reports kernel=...-bore-lto
  # while scx_pandemonium does the placing and BORE does nothing. It is
  # also swapped without a reboot, so the same binary on the same
  # machine gives different placements and different rates through the
  # day, and a row that does not name it cannot be read a month later.
  #
  # This was found by reading a row: server 94 percent on a 3.3 GHz E
  # core, client 80 percent on a 4.5 GHz P core, and the rate called
  # server-bound when it was slow-core-bound. The placement line says
  # where; this says who decided.
  #
  # The files sit at the top on this kernel and under root/ on others,
  # so both are read and the first that answers wins. Nothing here
  # guesses: a machine with no sched_ext says none, which is the whole
  # truth about it.
  wm_bl_scx=none
  if [ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" = enabled ] ||
     [ "$(cat /sys/kernel/sched_ext/root/state 2>/dev/null)" = enabled ]; then
    wm_bl_scx=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null ||
                cat /sys/kernel/sched_ext/ops 2>/dev/null || echo enabled-unnamed)
    # 1 means every task is on it, and that is the ordinary case, so it
    # is not printed. Anything else means the machine ran two
    # schedulers at once and the row has to say so.
    wm_bl_all=$(cat /sys/kernel/sched_ext/switch_all 2>/dev/null ||
                cat /sys/kernel/sched_ext/root/switch_all 2>/dev/null || echo "")
    [ "$wm_bl_all" = 1 ] || [ -z "$wm_bl_all" ] ||
      wm_bl_scx="$wm_bl_scx(switch_all=$wm_bl_all)"
  fi
  echo "build: $wm_bl_bin cc=${wm_bl_cc:-?} libstdc++=${wm_bl_cxx:-static}" \
       "libc=${wm_bl_libc:-?} kernel=$(uname -r) sched=$wm_bl_scx" \
       "host=$(uname -n) on=$wm_bl_on" \
       "cpu=${wm_bl_cpu:-unreadable} cache=$wm_bl_cache flags=$wm_bl_flags"
}
