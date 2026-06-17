#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the per-block reads in ext4
//! `lookup_name_with_scope` (bd-xmh5g.194, I/O-overlap sibling of bd-2jurz).
//!
//! When the htree index misses (a negative lookup, or a non-htree / htree-stale
//! directory), `lookup_name_with_scope` falls back to a linear scan that reads
//! each present directory block and searches it for the target name. The
//! pre-bd-xmh5g.194 scan read those blocks serially — a large directory paid one
//! device-read latency per block in sequence, and a negative lookup (the hot
//! path behind every file-create existence check) read every block. bd-xmh5g.194
//! plans the present blocks serially (the resolve_extent descent stays serial),
//! then reads + searches them in a rayon `into_par_iter`, consuming the results
//! in logical-block order so the first match / lowest-block error still wins.
//!
//! This bench isolates that I/O fan-out with a per-block read that parks the
//! worker for a fixed latency before returning the block bytes, then searches
//! the block for an absent name (the negative-lookup case, where both arms read
//! every block — so this measures only the read-latency overlap, not the
//! early-exit difference):
//!   * `serial_blocks`   — pre-bd-xmh5g.194: read + search each block in turn.
//!   * `parallel_blocks` — bd-xmh5g.194: read + search blocks in an
//!     `into_par_iter`, results consumed in block order.

use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BLOCKS: usize = 64; // present directory blocks scanned on an htree miss
const BS: usize = 4096; // ext4 block size
/// Per-block read access latency. Models a real-disk/SSD-queue round trip; the
/// in-memory unit-test device is zero-latency and cannot exhibit overlap.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Read one directory block (park for the access latency) and search it for an
/// absent name. Returns `Some(block)` only on a (never-occurring) hit, modelling
/// the negative-lookup case where every block is read and searched.
fn read_and_search(block: usize) -> Option<usize> {
    std::thread::sleep(READ_LATENCY);
    // Byte scan over the block for a sentinel that never appears, matching the
    // per-block `lookup_in_dir_block` work that dominates after the read.
    let mut acc: u8 = 0;
    for i in 0..BS {
        acc ^= prng((block as u64) << 20 ^ i as u64);
    }
    // 0xFF_FF... sentinel is unreachable from the xor fold above in practice; the
    // result is always `None`, the negative-lookup outcome.
    (acc == 0 && block == usize::MAX).then_some(block)
}

/// Pre-bd-xmh5g.194: read + search every block serially, first match wins.
fn serial_blocks() -> Option<usize> {
    (0..BLOCKS).find_map(read_and_search)
}

/// bd-xmh5g.194: read + search blocks in parallel; lowest-block match wins.
fn parallel_blocks() -> Option<usize> {
    let results: Vec<Option<usize>> = (0..BLOCKS).into_par_iter().map(read_and_search).collect();
    results.into_iter().flatten().next()
}

fn bench_ext4_lookup_run_overlap(c: &mut Criterion) {
    // Isomorphism: identical outcome (`None`) regardless of read order.
    assert_eq!(
        serial_blocks(),
        parallel_blocks(),
        "parallel lookup block scan diverged from serial"
    );

    let mut group = c.benchmark_group("ext4_lookup_run_overlap_64blocks");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_blocks", |b| {
        b.iter(|| black_box(serial_blocks()));
    });
    group.bench_function("parallel_blocks", |b| {
        b.iter(|| black_box(parallel_blocks()));
    });
    group.finish();
}

criterion_group!(benches, bench_ext4_lookup_run_overlap);
criterion_main!(benches);
