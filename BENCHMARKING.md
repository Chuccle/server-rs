# Benchmarking

Three different questions, three different tools. Using the wrong one is the
usual way to "prove" a change that did nothing.

| Question | Tool | Where |
| --- | --- | --- |
| Did throughput change? | closed-loop HTTP load | `examples/loadgen.rs` |
| Which piece changed? | criterion microbenchmarks | `benches/hot_path.rs` |
| Why did it change? | `strace -c`, `perf stat` | below |

Always measure a release build. A debug build's numbers are unrelated to
anything that ships.

## Pin the server and the load generator to disjoint cores

The generator is itself a multi-threaded Tokio program. Run unpinned on the
same box, it and the server each spawn one worker per CPU and then fight over
the same cores - so you measure the contention, not the server.

```bash
taskset -c 0-5  ./target/release/server-rs /path/to/corpus &
taskset -c 6-11 ./target/release/examples/loadgen --target '/get_dir_info?path=big'
```

How much this matters, measured: unpinned, the server peaked at ~145k req/s
with Tokio's default worker count and ~174k when hand-limited to 6 workers,
which looked like a 20% tuning win. Pinned to six dedicated cores, the default
reached ~196k - matching the hand-tuned figure exactly, because
`available_parallelism()` reads the affinity mask and Tokio's default is
already "one worker per available core". The apparent 20% was the co-location
artifact, not a tunable. There is nothing to configure here: Tokio's default
respects both CPU affinity and cgroup quotas, so a container with `--cpus=2`
gets two workers without being told.

Worth knowing in the other direction too - oversubscription is expensive.
Forcing 12 workers onto 6 available cores cost 27% throughput against the
6-worker default. If you ever set `TOKIO_WORKER_THREADS` by hand, you are
most likely making it worse.

## Throughput

`loadgen` speaks HTTP over a socket and knows nothing about the crate, so the
same binary measures any build — including `master`. That is what makes a real
before/after possible.

```bash
cargo build --release --example loadgen
```

Baseline, then candidate:

```bash
git checkout master && cargo build --release
./target/release/server-rs /path/to/corpus &
./target/release/examples/loadgen --target '/get_dir_info?path=big' --connections 64 --duration 30
```

Repeat on the branch. Compare `req/s` and `p50`. Two failure modes make the
numbers fiction:

- **The generator saturates first.** Then you are measuring the generator.
  Watch `top`; pin the two processes to disjoint cores with `taskset -c`.
- **Closed-loop tail distortion.** Offered load backs off as latency rises, so
  a saturated server reports a flattering tail. Trust the median; treat p99 as
  indicative.

Run each configuration at least three times and compare the spread, not single
runs.

## Attribution

```bash
cargo bench --bench hot_path -- --save-baseline before
# change something
cargo bench --bench hot_path -- --baseline before
```

Criterion times a *batch* of iterations and divides, which amortises the timer
down to nothing. That matters here: several of these operations are ~20 ns, and
a per-iteration timestamp would be a large fraction of the measurement.

These are branch-only — `master`'s internals have different names, so only the
`loadgen` numbers compare across the two.

## Why not `rdtsc`

`rdtsc` is a fine primitive and the wrong tool for this:

- **It measures latency, not throughput.** A cycle counter around one call site
  cannot see contention, queueing, or allocator behaviour under concurrency —
  which is exactly where a cache-layout change can pay off or backfire.
- **Its overhead is comparable to what we are measuring.** A serialising read
  (`lfence; rdtsc` or `rdtscp; lfence`) is tens of cycles. Criterion's batching
  sidesteps this; a hand-rolled per-iteration counter does not.
- **Plain `rdtsc` is not ordered** against surrounding instructions, so without
  the fences it times the wrong window — and with them it perturbs the pipeline
  it is measuring.
- **The TSC is a reference clock, not a cycle counter.** It is invariant on
  modern x86: it ticks at a fixed rate regardless of the core's actual
  frequency. It will not tell you cycles of work under turbo or thermal
  throttling. For that you want the PMU.
- **`Instant::now()` already is this.** On Linux `clock_gettime(CLOCK_MONOTONIC)`
  resolves through the vDSO to a TSC read plus a scale — no syscall, ~20 ns, and
  it gives you nanoseconds and portability for the same price.

## Evidence that does not depend on a timer

The headline claim of the cache rework is *fewer syscalls per request*. Counting
them is far more robust than timing them — it is immune to noise, frequency
scaling, and a noisy neighbour.

**`strace -p PID` (attaching to an already-running server) needs
`PTRACE_ATTACH`/`PTRACE_SEIZE`, which most container runtimes deny by default —
including plain `docker run` without `--cap-add=SYS_PTRACE`, even as root.**
Launching a process *directly under* `strace` is a different, unprivileged code
path (`PTRACE_TRACEME`) and works everywhere attach doesn't. That rules out
"start the server, then strace -p it," which is the natural first instinct.

Isolate the *warm, steady-state* cost by differencing two full launches rather
than attaching mid-run — this also cancels out one-time startup cost (this
server's watcher walks the whole tree once at startup, which otherwise swamps
a small request count):

```bash
# N requests
pkill -f ./server-rs; sleep 1
strace -f -c -o n.txt ./target/release/server-rs /path/to/corpus &
STRACE=$!
# wait for /healthcheck to return 200, then fire exactly N requests
CHILD=$(pgrep -P "$STRACE"); kill -TERM "$CHILD"; wait "$STRACE"

# N+M requests, identical setup, output to nm.txt

# statx/openat/getdents64 should be IDENTICAL between the two files.
# Any per-syscall delta, divided by M, is that syscall's true warm-request cost.
```

A pitfall worth naming: `pkill -f "$BIN"` run *from a script invoked with `$BIN`
as an argument* matches the script's own command line and kills the script,
not the server. Anchor the pattern (`pkill -f "^${BIN} "`) or match on
something the caller's own argv can't contain.

A warm request should show zero marginal `statx`/`openat`/`getdents64` — pure
socket work. If it does not, a cache tier is missing. Measured this way on this
branch: `statx` was bit-for-bit identical (6020) between a 50-request and a
250-request run of `/get_dir_info` against a 3000-file directory — zero
marginal filesystem syscalls per warm request. The same test against an
unmodified `master` showed exactly +1 `statx` and +3 `lstat` per additional
request, from `canonicalize` walking path components on every hit regardless
of cache state.

## perf / hardware counters may not be available at all

`perf_event_open` needs `CAP_SYS_ADMIN`, which plain `docker run` (no
`--privileged`, no `--cap-add=SYS_ADMIN`) does not grant — confirmed on this
branch: `perf stat` failed with "No permission to enable ... event" for
*every* event tried, hardware counters and pure software ones (`task-clock`,
`context-switches`) alike. Escalating a running container's privileges just to
get `perf` numbers is a bigger, riskier intervention than a benchmarking pass
should reach for on its own — ask first if that's genuinely needed. Absent it,
`strace -c` differencing (above) is the mechanism-level evidence actually
available, and for an I/O-bound metadata server it is arguably the more
relevant one anyway: syscalls are this server's real bottleneck, not L1
misses.

## Before reaching for a "faster" crate, benchmark it against what you have

`jwalk` (parallel directory walking, built on `rayon`) looks like an obvious
fit for "scanning a big directory is slow." Benchmarked head-to-head against
`DirNode::scan` in `benches/hot_path.rs` at 16/512/8192 entries, it lost at
every size — worse as directories got bigger, not better. The reason is
legible from its source, not just the numbers: jwalk parallelises *which
directory to read next* across a recursive tree. `DirEntry::metadata()` stays
one lazy, one-at-a-time call regardless of how the directory was read, so for
a single flat directory - this server's actual access pattern, since a request
is for one directory, not a subtree - there is no parallelism for jwalk to
offer, only extra wrapping (an `Arc<Path>` per entry, additional indirection)
over what `std::fs::read_dir` already gives you. The lesson isn't "jwalk is
bad," it's that a crate's parallelism model has to match your actual
bottleneck, which is exactly the kind of thing that stops being a guess once
you've written the 15-line benchmark.

What *did* help `DirNode::scan`: chunking the per-entry `stat` calls across
`std::thread::scope` workers (plain threads, not a new dependency) once a
directory crosses a size threshold, since those are independent syscalls on
unrelated files that the kernel can service concurrently. Measured on a
12-vCPU box: 8192 entries went from 23.1ms to 9.0ms (2.56x), 512 entries from
1.26ms to 954µs, with *zero* change at 16 entries once one thing was fixed:
`std::thread::available_parallelism()` (a `sched_getaffinity` syscall) was
initially called unconditionally, before checking whether the directory was
even large enough to bother parallelising. Under this environment's
virtualization that syscall alone cost more than scanning a 16-entry directory
outright - moving it behind the size check recovered small-directory
performance exactly back to baseline. The lesson here: a syscall added to a
"just in case" fast-path check is not free, and the fix was found by
benchmarking the "no-op" case, not by reasoning about it.

For cache-friendliness claims specifically (would the dense child index move
`cache-misses`), `perf stat -e cache-misses,...` is the right tool *if you have
it* — see the limitation above.

## A faster allocator only helps if you're still allocating

`mimalloc` as `#[global_allocator]` was tried and reverted. Measured both ways
via `store/warm/*` in `benches/hot_path.rs` and via `loadgen` under real load
(3 runs each, back to back, same corpus): warm-path throughput was
indistinguishable with mimalloc in or out (~70k req/s on a 3000-entry listing,
~160k req/s on entry metadata, both configurations, run-to-run spread larger
than the gap between them). `dir_node/scan` - the allocation-heavy cold path,
building `Vec<DirEntry>`, name strings, and the flatbuffer builder - did show
a real, repeatable 2-5% improvement with mimalloc.

The reason the warm path didn't move is the same reason it's fast: it was
already redesigned to not allocate on a hit (`Bytes::clone` is a refcount bump,
not a copy). A faster allocator has nothing to speed up on a path that isn't
calling the allocator. This is worth having tried and ruled out rather than
assumed either way - "swap in mimalloc" is exactly the kind of change that
*sounds* like free throughput and, once the actual bottleneck has already been
removed, measures as noise. If cache-miss-heavy traffic (low hit rate, high
directory churn) turns out to matter for a given deployment, mimalloc is still
worth revisiting for the 2-5% it gave the scan path specifically - it just
isn't a blanket win here.

## Finding the real floor before optimizing further

At some point the question stops being "what can I speed up" and becomes
"is there anything left worth speeding up." The way to answer that honestly:
compare the Store's own numbers against a request that does nothing at all.

`store/warm/*` in criterion was down to 170-600ns. But `loadgen` under real
load (32 connections) was showing 170-400*micro*seconds per request - a
~1000x gap. Before writing more Store optimizations, that gap needed an
explanation, or every further microsecond shaved off the Store would be
noise against whatever actually dominates.

Two measurements settled it:

1. **The 32-connection number was mostly queueing, not per-request cost.**
   At `--connections 1` (no contention), `/get_dir_entry_info` dropped to a
   76µs p50 - the 170-400µs figure was this environment's 12 shared vCPUs
   fighting over 32 concurrent requests, not a property of one request.
2. **`/healthcheck` - zero application logic, no extraction, no Store, no
   serialisation - measured 68µs p50 at the same concurrency.** Only ~8µs of
   the 76µs total was attributable to *everything the application does*
   combined, and the Store itself accounts for under 1µs of that. The other
   68µs is TCP handling, hyper's HTTP/1.1 parsing, the async runtime's task
   scheduling, and loopback networking through this VM - none of it
   reachable without kernel-bypass techniques (io_uring, a hand-rolled
   epoll loop bypassing hyper) that are a different, much larger project
   than tuning a metadata cache, and arguably the wrong shape for an async
   Tokio server in the first place.

That reframed where the remaining ~8µs actually was: `axum::extract::Query`'s
`serde`-based deserialisation (derive-generated visitor, field-name matching,
an unconditional `String` allocation for the value) to extract one required
query parameter. Replaced with a direct parse (`Uri::query()` - a cheap
`Bytes`-backed clone, not a fresh allocation - split on `&`, percent-decode
only the matched value, borrowing via `Cow` when nothing needed decoding,
which is the common case). Measured via five interleaved
healthcheck/entry-info trials rather than a single before/after pair, since
the absolute numbers drift several µs between runs in this environment even
for code that didn't change: the *gap* between the two endpoints - the part
attributable to the extractor plus the Store - narrowed from ~8µs to ~5-6µs.
Small in absolute terms (a few percent of total request latency), genuinely
measured rather than assumed, and it deleted a dependency (`serde`) as a side
effect rather than adding one.

The takeaway for what's left: this server's Store/cache layer is no longer
where the time goes. Any further "squeeze" has to either attack the ~68µs
floor (a different, much bigger undertaking) or accept that a well-cached
metadata server sitting on Tokio/hyper is close to as fast as that
architecture gets.
