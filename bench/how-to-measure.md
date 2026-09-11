# How to bench so that a change in the code is visible

A bench number holds three parts: the code, the host, and the load.
Only the first one is interesting. This file says how to hold the other
two still, so that a difference of a few percent belongs to the code.

Read `bench/host-variance.md` first. It says how to measure what the
host adds, and what the answer was here.

## The rule

Both processes must be busy. The server and the client each need more
than 85 percent of a cpu for the whole run.

A run where one side sits at 65 percent measures wait time. The client
sends, then waits for the answers. The server answers, then waits for
the next requests. Each one sleeps while the other works. Such a run
moves with the scheduler, not with the code: on the host named `vm` it
spread 38 percent across 22 runs of one binary.

Every row of `bench/results/*.log` names both numbers. Read them
before you read the rate.

## The steps

1. Sweep the connection count once for the machine and the app. Keep
   every other knob the same.

       for c in 16 32 64 128; do
         CONNS=$c DURATION=10 PROTO=h2 STREAMS=128 \
           APP=bench/apps/hello.rb bench/floor.sh
       done

   Take the lowest count where the rate stops climbing and both sides
   stay above 85 percent. Below that count the run measures wait time.

   The two floors of this tree want different counts, because a
   connection carries one request at a time in HTTP/1 and 128 streams
   in HTTP/2. On the host named `vm`:

   | Floor | count | rate | server | client |
   | --- | --- | --- | --- | --- |
   | h2, 128 streams | 62 | 5.5M | 89-91% | 94-99% |
   | h1 | 1024 | 0.61M | 98-99% | 99-100% |

   The h1 sweep that found 1024: 128 gives 0.535M, 256 gives 0.581M,
   768 gives 0.587M, 1024 gives 0.602M, and 1536 to 4096 give the same
   0.57M to 0.60M. The rate stops climbing at about 768, and 1024 and
   1536 are one measurement - their medians differ by 1.1 percent.

   The counts above are the counts of a fast `vm`. The same host is
   sometimes half as fast: `sysbench cpu --threads=1` reads 2450 events
   per second in one container and 1100 in the next. Sweep again when
   that number falls, because the best count moves with it.

   A sweep on the slow `vm`, four runs of five seconds for each count,
   with the median and the spread (max minus min, over the median):

   | Floor | count | median | spread |
   | --- | --- | --- | --- |
   | h1 | 256 | 0.44M | 20% |
   | h1 | 512 | 0.26M | 84% |
   | h1 | 1024 | 0.40M | 42% |
   | h1 | 2048 | 0.24M | 23% |
   | h2, 128 streams | 8 | 3.04M | 17% |
   | h2, 128 streams | 16 | 3.12M | 9% |
   | h2, 128 streams | 32 | 3.28M | 7% |
   | h2, 128 streams | 62 | 3.65M | 19% |

   Five runs of ten seconds for the two best counts of each floor:

   | Floor | count | median | spread |
   | --- | --- | --- | --- |
   | h1 | 256 | 0.38M | 45% |
   | h1 | 1024 | 0.27M | 55% |
   | h2, 128 streams | 32 | 3.34M | 14% |
   | h2, 128 streams | 62 | 3.61M | 19% |

   So the best run on the slow `vm` is `PROTO=h2 STREAMS=128
   CONNS=32`. It is the only count that stays under 15 percent, and
   its median is 8 percent under the best rate. Take a difference of
   15 percent or more, and nothing smaller.

   The h1 floor is not measurable on the slow `vm` at all. Every count
   reads 40 percent or more, and ten seconds reads worse than five,
   which says the spread is not the sample size. `PIPELINE=8` raises
   the rate to 2.1M and cuts the spread to 31 percent, but the five
   runs fall in two groups, near 1.5M and near 2.1M. A bimodal run
   measures where the scheduler put the two processes. Use h2 for a
   comparison here, and take the h1 floor on `forgecore`.

2. Check that the client is not the limit. `bench/floor.sh` refuses a
   run when the client is pegged and the server is 15 or more points
   under it. A run near that edge still measures the client in part.
   The cure is a second machine for the client, not a bigger number.

3. Run five times for each arm of a comparison, and write down the
   median and the spread. One run is not a measurement.

   Compare the medians. Do not compare the spreads: five runs at 62
   connections read 3.4 percent one hour and 6.0 the next, on the same
   binary and the same count. A spread of five runs is itself a number
   with a wide error, and a claim that one setup repeats better than
   another needs many more runs than five.

4. Interleave the arms: A B A B A B, never five of A and then five of
   B. The machine drifts, and an interleaved order spreads that drift
   across both arms.

5. Keep a run that looks wrong. Read its two cpu numbers first. A slow
   run with a side under 85 percent is a wait, and it belongs out of
   the comparison for that reason and no other. Say so in the log.

## What the machine can then resolve

On `vm`, five runs at 64 connections gave 5.00M, 5.45M, 5.61M, 5.63M
and 5.71M requests per second. That is 14 percent for all five, and
4.7 percent for the four where the client held 97 percent or more.

So this host can see a change of about 5 percent, and not less. A
smaller change needs a machine with more cpus and the client on a
second machine. `bench/results/forgecore.log` is taken that way.

## What the script already holds still

`bench/floor.sh` does three things for every run, and the harness line
records each one.

- It takes the cpus its caller does not hold. An agent working in this
  tree keeps its own processes on one cpu, and the bench takes the
  rest. The line says `cpus=1,2,3`.
- It takes a nice value of -15 and puts every other process of this
  user at 15, through `bench/priority.sh`. The line says `nice=-15`.
- It bakes the commit of the server, the commit of the client and the
  compiler flags into the line, so a row can be repeated.

## Latency

`LATENCY=1` makes the client time every answer and print one line of
percentiles beside the counts. It needs `PIPELINE=1`, because a batch
carries one timestamp for every answer in it, and htgen refuses the
pair.

    LATENCY=1 CONNS=8 DURATION=10 APP=bench/apps/hello.rb bench/floor.sh

Read a latency at the concurrency you mean, and never at the one that
gives the best rate. At the rate's plateau the number is the queue and
not the server: 1024 connections at 0.6M requests per second is 1.7 ms
of waiting by Little's law, and the measurement agrees - p50 = 1690 us.

The same binary on the host named `vm`, microseconds:

| Floor | conns | rate | p50 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- |
| h1 | 1 | 0.035M | 26 | 53 | 85 |
| h1 | 8 | 0.19M | 48 | 85 | 119 |
| h1 | 62 | 0.51M | 111 | 252 | 510 |
| h1 | 1024 | 0.60M | 1682 | 2412 | 3122 |
| h2, 128 streams | 1 | 1.35M | 92 | 151 | 293 |
| h2, 128 streams | 62 | 2.44M | 3143 | 5914 | 9789 |

One connection and one request in flight is the closest this harness
comes to the service time: 26 us for an h1 request, and 92 us for an
h2 request that shares its connection with 127 others.

Timing costs two clock reads per answer, so a rate taken with
`LATENCY=1` is not a rate taken without it. Take the two from separate
runs. The h2 rate at 62 connections reads 2.44M here against 5.5M
without the timing, which is what that costs.

## What a rate cannot answer

A rate says that something changed. It does not say where.

For the where, use the profiler and the size of the function:

    gprofng collect app -o run.er mruby/build/host/bin/webmachine-server ...
    gprofng display text -functions run.er

    nm -S --size-sort mruby/build/host/bin/webmachine-server | tail -20

CLAUDE.md asks for `nm -S` on the host build before a hint or a split
is called an improvement. The L1 instruction cache is 32 KiB, and
`feed_parse`, `run_engine` and `h2_dispatch` are 11 to 15 KB each.
