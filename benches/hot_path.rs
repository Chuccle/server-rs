//! Microbenchmarks for the pieces a warm request actually touches.
//!
//! These measure *latency of a code region*, which is not the same thing as
//! server throughput - see `examples/loadgen.rs` for that. What they are for is
//! attribution: when the end-to-end number moves, these say which piece moved.
//!
//! Regression workflow:
//!
//! ```text
//! cargo bench --bench hot_path -- --save-baseline before
//! # ... change something ...
//! cargo bench --bench hot_path -- --baseline before
//! ```
//!
//! Criterion times a *batch* of iterations and divides, so the timer overhead
//! (~20 ns for `Instant::now`) amortises away rather than swamping the ~20 ns
//! operations below. That is the main reason not to hand-roll `rdtsc` here.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use server_rs::utils::{cache, flat, hash, meta::RawMeta, path};
use std::hint::black_box;

/// Directory sizes worth distinguishing: fits in L1, spills to L2, spills to
/// L3/memory. The child index change should show up as the gap between them
/// narrowing.
const SIZES: [usize; 3] = [16, 512, 8192];

fn populated_dir(entries: usize) -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("tempdir");

    for index in 0..entries {
        std::fs::write(temp.path().join(format!("entry_{index:05}.dat")), b"x").expect("write");
    }

    temp
}

/// Lexical normalisation runs on every single request, before anything else.
fn bench_normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("path/normalize");

    // The case the fast path exists for: already canonical, must not allocate.
    group.bench_function("borrowed", |b| {
        b.iter(|| path::normalize(black_box("some/nested/directory/file.txt")));
    });

    // Forces the rewrite branch, which does allocate.
    group.bench_function("rewritten", |b| {
        b.iter(|| path::normalize(black_box("./some\\nested/../nested/directory//file.txt")));
    });

    // Should never touch the filesystem, and should be cheap enough that
    // hammering it is not a denial of service.
    group.bench_function("rejected", |b| {
        b.iter(|| path::normalize(black_box("../../../../etc/passwd")));
    });

    group.finish();
}

/// Two of these run per request, on paths of roughly this length.
fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");

    for length in [8usize, 32, 128] {
        let key = "a".repeat(length);

        group.throughput(Throughput::Bytes(u64::try_from(length).expect("fits")));

        group.bench_with_input(BenchmarkId::new("fast", length), &key, |b, key| {
            b.iter(|| hash::name(black_box(key)));
        });

        // The default that `moka` would otherwise use, for comparison.
        group.bench_with_input(BenchmarkId::new("siphash", length), &key, |b, key| {
            use std::hash::BuildHasher as _;
            let state = std::collections::hash_map::RandomState::new();
            b.iter(|| state.hash_one(black_box(key)));
        });
    }

    group.finish();
}

/// The single-entry lookup. This is the benchmark the dense-hash-index change
/// exists for: with the old span/binary-search layout, cost grew with the
/// directory's *name blob* size, not just its entry count.
fn bench_child_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("dir_node/child");

    for entries in SIZES {
        let temp = populated_dir(entries);
        let node = cache::DirNode::scan(temp.path()).expect("scan");

        // Middle of the range, so neither the first nor last probe is lucky.
        let hit = format!("entry_{:05}.dat", entries / 2);
        let miss = "entry_99999.dat";

        group.bench_with_input(BenchmarkId::new("hit", entries), &hit, |b, name| {
            b.iter(|| node.child(black_box(name)));
        });

        group.bench_with_input(BenchmarkId::new("miss", entries), &miss, |b, name| {
            b.iter(|| node.child(black_box(name)));
        });
    }

    group.finish();
}

/// Runs once per `get_dir_entry_info`, so the pooled builder shows up here.
fn bench_encode_entry(c: &mut Criterion) {
    let meta = RawMeta {
        size: 4096,
        created: 133_000_000_000_000_000,
        modified: 133_000_000_000_000_001,
        accessed: 133_000_000_000_000_002,
        is_dir: false,
    };

    c.bench_function("flat/entry", |b| {
        b.iter(|| flat::entry(black_box(&meta)));
    });
}

/// Cold path - runs once per directory scan, not per request. Included because
/// it dominates the cost of a cache miss on a large directory.
///
/// `jwalk` was benchmarked here too, as a check on the "a well-known crate
/// already solved this faster" instinct - it did not stay, but the finding is
/// worth keeping: jwalk parallelises *which directory to read next* across a
/// recursive tree; `DirEntry::metadata()` is still one lazy call per entry
/// regardless, so within a single flat directory it adds wrapping overhead
/// with no parallelism to offset it. Measured slower than this module's
/// `stat_children` at every size tried (16/512/8192 entries), by roughly
/// 20-200%, worst at the largest size - the opposite of what pulling it in
/// would be for. See `BENCHMARKING.md` for the numbers.
fn bench_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("dir_node/scan");
    group.sample_size(20);

    for entries in SIZES {
        let temp = populated_dir(entries);

        group.throughput(Throughput::Elements(u64::try_from(entries).expect("fits")));
        group.bench_with_input(BenchmarkId::from_parameter(entries), &entries, |b, _| {
            b.iter(|| cache::DirNode::scan(black_box(temp.path())));
        });
    }

    group.finish();
}

/// The whole warm request path below the HTTP layer: normalise, resolve, look
/// up, hand back bytes. If this is not flat in directory size, something is
/// still re-serialising per request.
fn bench_warm_store(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let mut group = c.benchmark_group("store/warm");

    for entries in SIZES {
        let temp = populated_dir(entries);
        let store = cache::Store::new(temp.path(), cache::Config::default()).expect("store");

        let target = format!("entry_{:05}.dat", entries / 2);

        // Warm every cache tier before measuring.
        runtime.block_on(async {
            store.directory_listing("").await.expect("listing");
            store.entry_metadata(&target).await.expect("entry");
        });

        group.bench_with_input(
            BenchmarkId::new("directory_listing", entries),
            &entries,
            |b, _| {
                b.to_async(&runtime)
                    .iter(|| async { store.directory_listing(black_box("")).await });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("entry_metadata", entries),
            &target,
            |b, target| {
                b.to_async(&runtime)
                    .iter(|| async { store.entry_metadata(black_box(target)).await });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_normalize,
    bench_hash,
    bench_child_lookup,
    bench_encode_entry,
    bench_scan,
    bench_warm_store,
);
criterion_main!(benches);
