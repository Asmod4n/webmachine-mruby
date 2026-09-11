# What a host adds to a bench number

A bench number holds two parts: what the code does, and what the host
does. This file says how to measure the second part, and what the
answer was on the host named `vm`.

Measure the host before you believe a difference of a few percent.

## How to measure it

Install two suites. Both are free and both run without a licence.

    apt-get install -y sysbench stress-ng

Run each load five times and keep the spread.

    sysbench cpu    --threads=1 --time=10 run   # events per second
    sysbench memory --threads=1 --time=10 run   # MiB per second
    sysbench threads --threads=4 --time=10 run  # total events
    stress-ng --matrix 1 --metrics-brief -t 10  # bogo ops per second

Read the steal time around a bench run. Field 9 of the first line of
`/proc/stat` counts the ticks the hypervisor took from this guest.

Then run the bench itself many times and compare the spreads.

## The answer on the host named vm, 2026-09-10

Four cpus, kernel 6.18.44. The machine was idle beside the bench.

| Load | min | max | spread |
| --- | --- | --- | --- |
| sysbench cpu, 1 thread | 2439.50 | 2477.30 | 1.55% |
| sysbench memory, 1 thread | 4944.33 MiB/s | 5035.94 MiB/s | 1.85% |
| sysbench threads, 4 threads | 123109 | 126369 | 2.65% |
| stress-ng matrix, 1 worker | 3796.32 | 4290.30 | 13.0% |

Steal time is 3 to 5 ticks of about 4400 in a ten second run. That is
0.1 percent, and the slow run has no more of it than the fast run.

The h2 floor bench, 22 runs of the same binary, 16 connections and 128
streams: 3.21M to 4.43M requests per second. The spread is 38 percent
and the median is 3.85M.

## Where that spread comes from

Two answers are ruled out by measurement.

The depth of a batch is steady. The requests per voluntary context
switch of the server stay between 2106 and 2439, whatever the rate is.

Lost cycles explain a part and not the whole. The requests per user
tick of the server move by 8 percent. The rate moves by 22 percent in
the same runs.

What is left is wait time on both sides. The server uses 73 to 85
percent of one cpu and the client uses 57 to 76 percent. Neither
reaches a full cpu, so each one waits for the other. Both processes
move across all four cpus in every run.

So the scheduler sets the number when it places two busy processes on
four shared cpus. A change of a few percent is not visible here.
`bench/priority.sh` already gives the run a nice value of -10, and that
does not remove the spread.

The way to a number you can compare is a machine with more cpus and the
client on a second machine. `bench/results/forgecore.log` is taken that
way.
