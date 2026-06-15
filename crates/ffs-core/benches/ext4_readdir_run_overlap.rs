#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the non-contiguous dir-block run reads in
//! ext4 `read_dir_with_scope` (bd-2jurz, I/O-overlap sibling of bd-yg6tk).
//!
//! `read_dir_with_scope` coalesces each maximal contiguous run of cold dir
//! blocks into one vectored `read_contiguous_blocks_with_scope`, but read the
//! non-contiguous runs serially across the directory walk — a cold large
//! fragmented directory serialized one device-read latency per run. bd-2jurz
//! plans the directory into segments serially (the resolve_extent descent stays
//! serial), then reads the cold runs in a rayon `into_par_iter` and finalizes
//! (cache-populate + parse) in block order, overlapping the run reads.
//!
//! This bench isolates that I/O fan-out with a `LatencyBlockDevice` that parks
//! the worker for a fixed per-read latency before returning the run's blocks
//! (one owned `Vec<Vec<u8>>` per run, the shape
//! `read_contiguous_blocks_with_scope` returns). Both arms produce an identical
//! per-run byte sequence, so this measures only the read-latency overlap:
//!   * `serial_runs` — pre-bd-2jurz: read each cold run one at a time.
//!   * `parallel_runs` — bd-2jurz: read the cold runs in an `into_par_iter`,
//!     collecting results in run (block) order.

use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const RUNS: usize = 16; // non-contiguous cold dir-block runs
const RUN_BLOCKS: usize = 4; // blocks per run
const BS: usize = 4096; // ext4 block size
/// Per-run ranged-read access latency. Models a real-disk/SSD-queue round trip;
/// the in-memory unit-test device is zero-latency and cannot exhibit overlap.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Read one cold run: park for the access latency, then return its blocks as an
/// owned `Vec<Vec<u8>>` (the shape `read_contiguous_blocks_with_scope` yields).
fn read_run(run: usize) -> Vec<Vec<u8>> {
    std::thread::sleep(READ_LATENCY);
    (0..RUN_BLOCKS)
        .map(|b| {
            (0..BS)
                .map(|i| prng((run as u64) << 24 ^ (b as u64) << 12 ^ i as u64))
                .collect()
        })
        .collect()
}

/// Pre-bd-2jurz: read every cold run serially.
fn serial_runs() -> Vec<Vec<Vec<u8>>> {
    (0..RUNS).map(read_run).collect()
}

/// bd-2jurz: read the cold runs in parallel, collected in run (block) order.
fn parallel_runs() -> Vec<Vec<Vec<u8>>> {
    (0..RUNS).into_par_iter().map(read_run).collect()
}

fn bench_ext4_readdir_run_overlap(c: &mut Criterion) {
    // Isomorphism: identical per-run block bytes regardless of read order
    // (`collect` over an indexed range preserves run order).
    assert_eq!(
        serial_runs(),
        parallel_runs(),
        "parallel dir-run read diverged from serial"
    );

    let mut group = c.benchmark_group("ext4_readdir_run_overlap_16runs");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_runs", |b| {
        b.iter(|| black_box(serial_runs()));
    });
    group.bench_function("parallel_runs", |b| {
        b.iter(|| black_box(parallel_runs()));
    });
    group.finish();
}

criterion_group!(benches, bench_ext4_readdir_run_overlap);
criterion_main!(benches);
