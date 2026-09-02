#!/bin/bash
# The dynamic-body A/B through the REAL Ring<App> reactor.
#
# vm_floor.cpp answered "copy out of the VM, or freeze+register and send
# the VM's own buffer?" against blocking send()/sendmsg(). This answers
# the same question against io_uring, because the server has no blocking
# send path - everything goes through webmachine::Ring<App>, whose
# submit_and_wait carries several SQEs per enter.
#
#   bench/vm/ring_body.sh              # full matrix, appended to bench/results/
#   REPS=5 SIZES="65536" bench/vm/ring_body.sh
#
# MEASUREMENT DISCIPLINE, and why it is not optional here:
#
#   * PINNED. Unpinned on this shared 4-vCPU box the same configuration
#     spread over 3x run to run - enough to "prove" either variant. Ring
#     thread and client thread each get their own cpu; the spread drops
#     to roughly +/-10%. Every number below is pinned, and an unpinned
#     number from this harness is not evidence of anything.
#   * FRESH PROCESS per measurement. One process is one (variant, size)
#     data point - no allocator or GC state carried between them.
#   * PAIRED and INTERLEAVED. copy and zero run back to back inside one
#     rep, so a neighbour's burst lands on both. The headline is the
#     MEDIAN OF PER-REP RATIOS plus a sign count, not two independent
#     medians subtracted - that survives drift the medians do not.
#   * MEDIAN AND RANGE, never a single point number.
set -eu
cd "$(dirname "$0")/.."
cd ..

BIN=bench/vm/ring_body
SRC=bench/vm/ring_body.cpp
LIBMRUBY=mruby/build/host/lib/libmruby.a
LIBURING=mruby/build/host/mrbgems/mruby-slipstreamio/build/lib/liburing.a
OSSL=mruby/build/host/mrbgems/mruby-ktls/openssl
[ -f "$LIBMRUBY" ] || { echo "$LIBMRUBY missing - run: rake compile" >&2; exit 1; }
[ -f "$LIBURING" ] || { echo "$LIBURING missing - run: rake compile" >&2; exit 1; }

# Same paths and flags bench/vm.sh already uses for vm_floor; this needs
# no google-benchmark, because a completion-driven event loop does not
# fit a tight timed loop.
if [ ! -x "$BIN" ] || [ "$SRC" -nt "$BIN" ]; then
  g++ -O2 -g -std=c++20 \
    -Imruby/include -Imruby/build/host/include \
    -Ideps/ls-hpack -Ideps/ls-hpack/deps/xxhash \
    -Imruby/build/repos/host/mruby-string-is-utf8/include \
    -Imruby/build/host/mrbgems/mruby-slipstreamio/build/include \
    -Imruby/build/host/include/mruby/gems/mruby-ktls/include \
    "$SRC" "$LIBMRUBY" "$LIBURING" \
    -L"$OSSL" -lssl -lcrypto -Wl,-rpath,"$PWD/$OSSL" \
    -lpthread -lm -lz -o "$BIN"
fi

# 4096 is left out on purpose: it was the noisy size in the blocking-syscall
# run and buys nothing the 64/32768 pair does not already bracket.
SIZES="${SIZES:-64 32768 262144 1048576 4194304}"
REPS="${REPS:-13}"
CONNS="${CONNS:-8}"
PIN_RING="${PIN_RING:-0}"
PIN_CLIENT="${PIN_CLIENT:-1}"
# variant:hold. copy:0 is today's shape, zero:1 is the proposal, and
# copy:1 is the CONTROL - it copies like today but keeps the String
# frozen+registered for the same in-flight window as the proposal. It is
# in the default set because without it the harness cannot tell a copy
# saved from an allocator artifact of the hold, and at 8KB those two
# answers differ by 40 percentage points.
VARIANTS="${VARIANTS:-copy:0 copy:1 zero:1}"

# Requests per run, chosen so every size takes roughly a second: long
# enough to cover many GC cycles, short enough that one neighbour burst
# cannot own the whole matrix.
requests_for() {
  case "$1" in
    64)      echo 60000 ;;
    4096)    echo 40000 ;;
    8192)    echo 30000 ;;
    16384)   echo 25000 ;;
    32768)   echo 20000 ;;
    65536)   echo 12000 ;;
    131072) echo 8000 ;;
    262144)  echo 6000 ;;
    1048576) echo 3000 ;;
    4194304) echo 1000 ;;
    *)       echo 5000 ;;
  esac
}

RESULTS="bench/results/$(hostname)-ring-body.log"
mkdir -p bench/results
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
MRUBY_REV=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?')

{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV mruby=$MRUBY_REV ===="
  echo "harness: ring_body (real Ring<App>, AF_UNIX) $(uname -mr)"
  echo "conns=$CONNS reps=$REPS pin ring=$PIN_RING client=$PIN_CLIENT"
} | tee -a "$RESULTS"

for size in $SIZES; do
  n=$(requests_for "$size")
  for rep in $(seq 1 "$REPS"); do
    for spec in $VARIANTS; do
      variant=${spec%%:*}; hold=${spec##*:}
      line=$("$BIN" --variant "$variant" --size "$size" --requests "$n" --hold "$hold" \
                    --conns "$CONNS" --pin-ring "$PIN_RING" --pin-client "$PIN_CLIENT") || {
        echo "run failed: $spec $size" >&2
        continue
      }
      # RESULT variant=X size=N ... key=value ...
      echo "$rep $line" | tr ' ' '\n' | awk -v rep="$rep" '
        /^[0-9]+$/ && NR==1 { r=$0 }
        /=/ { split($0, kv, "="); v[kv[1]] = kv[2] }
        END { printf "%s %s %s %s %s %s %s\n", v["size"], v["variant"], rep,
                     v["wall_ns_per_req"], v["ring_cpu_ns_per_req"],
                     v["body_MiBps"], v["reqs_per_enter"] }' >> "$RAW"
    done
  done
done

awk '
  { size=$1; var=$2; rep=$3; wall=$4; cpu=$5; mib=$6; rpe=$7
    key=size" "var
    n[key]++; W[key,n[key]]=wall; C[key,n[key]]=cpu
    MIB[key]+=mib; RPE[key]+=rpe; cnt[key]++
    pair[size" "rep" "var]=wall
    seen[size]=1
    reps[size" "rep]=1
  }
  function median(k, cn,   i, j, t, a) {
    for (i=1;i<=cn;i++) a[i]=W[k,i]
    for (i=1;i<=cn;i++) for (j=i+1;j<=cn;j++) if (a[j]<a[i]) { t=a[i];a[i]=a[j];a[j]=t }
    return (cn%2) ? a[int(cn/2)+1] : (a[cn/2]+a[cn/2+1])/2
  }
  function lo(k, cn,   i, m) { m=W[k,1]; for(i=2;i<=cn;i++) if(W[k,i]<m) m=W[k,i]; return m }
  function hi(k, cn,   i, m) { m=W[k,1]; for(i=2;i<=cn;i++) if(W[k,i]>m) m=W[k,i]; return m }
  function cmed(k, cn,   i, j, t, a) {
    for (i=1;i<=cn;i++) a[i]=C[k,i]
    for (i=1;i<=cn;i++) for (j=i+1;j<=cn;j++) if (a[j]<a[i]) { t=a[i];a[i]=a[j];a[j]=t }
    return (cn%2) ? a[int(cn/2)+1] : (a[cn/2]+a[cn/2+1])/2
  }
  END {
    printf "\n%-9s %-9s %11s %11s %11s %10s %8s\n",
           "size","var","wall_med","wall_min","wall_max","ringcpu","req/entr"
    for (s in seen) order[++ns]=s+0
    for (i=1;i<=ns;i++) for (j=i+1;j<=ns;j++) if (order[j]<order[i]) { t=order[i];order[i]=order[j];order[j]=t }
    nv=split("copy copyhold zero", vlist, " ")
    for (i=1;i<=ns;i++) {
      s=order[i]
      for (vi=1; vi<=nv; vi++) {
        var = vlist[vi]
        k = s" "var; cn=n[k]; if (cn==0) continue
        printf "%-9d %-9s %11.0f %11.0f %11.0f %10.0f %8.2f\n",
               s, var, median(k,cn), lo(k,cn), hi(k,cn), cmed(k,cn), RPE[k]/cnt[k]
      }
      # Paired against copy, per rep: median ratio plus a sign count.
      # copyhold vs copy isolates the HOLD; zero vs copyhold isolates the
      # COPY; zero vs copy is the two together, which is the decision.
      for (vi=2; vi<=nv; vi++) {
        var=vlist[vi]; if (n[s" "var]==0) continue
        m=0; wins=0
        for (rk in reps) {
          split(rk, p, " ")
          if (p[1]+0 != s) continue
          a=pair[s" "p[2]" copy"]; b=pair[s" "p[2]" "var]
          if (a=="" || b=="") continue
          ratio[++m]=b/a
          if (b < a) wins++
        }
        if (m>0) {
          for (x=1;x<=m;x++) for (y=x+1;y<=m;y++) if (ratio[y]<ratio[x]) { t=ratio[x];ratio[x]=ratio[y];ratio[y]=t }
          med = (m%2) ? ratio[int(m/2)+1] : (ratio[m/2]+ratio[m/2+1])/2
          printf "%-9d   paired %-9s/copy median %.3f  (%+.1f%% vs copy)  won %d/%d reps\n",
                 s, var, med, (1-med)*100, wins, m
          delete ratio
        }
      }
    }
  }
' "$RAW" | tee -a "$RESULTS"

echo "raw + summary appended to $RESULTS"
