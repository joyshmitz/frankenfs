#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the btrfs `btrfs_logical_chunk_end` lookup (bd-yrt8c).
//!
//! While reading a file, `btrfs_read_logical_into` resolves, for each chunk-span
//! of the read, the END of the chunk covering the current logical bytenr — a
//! second linear scan over `ctx.chunks` right next to the already-binary-searched
//! `map_logical_to_physical`. Chunks are sorted ascending by `key.offset` and
//! cover disjoint logical ranges, so the covering chunk is the last whose start
//! is `<=` the target. The old code scanned every chunk (O(N)); the new code
//! binary-searches (O(log N)). It runs once per chunk-span per read, itself
//! per-extent in `btrfs_read_file` — a scan inside a loop, so a multi-TB fs with
//! hundreds–thousands of chunks pays it on every data read.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const N: u64 = 1000; // a multi-TB filesystem's chunk count
const CHUNK_LEN: u64 = 1 << 30; // 1 GiB chunks

/// One chunk: (logical_start, length). Sorted ascending, disjoint.
fn build_chunks() -> Vec<(u64, u64)> {
    (0..N).map(|i| (i * CHUNK_LEN, CHUNK_LEN)).collect()
}

/// Linear scan (the pre-bd-yrt8c shape): end of the first chunk covering
/// `logical`.
fn linear(chunks: &[(u64, u64)], logical: u64) -> Option<u64> {
    for &(start, len) in chunks {
        let end = start + len;
        if logical >= start && logical < end {
            return Some(end);
        }
    }
    None
}

/// Binary search (new): last chunk with start <= logical, then verify cover.
fn binary(chunks: &[(u64, u64)], logical: u64) -> Option<u64> {
    let pp = chunks.partition_point(|&(start, _)| start <= logical);
    if pp == 0 {
        return None;
    }
    let (start, len) = chunks[pp - 1];
    let end = start + len;
    if logical < end { Some(end) } else { None }
}

fn bench_chunk_end_resolve(c: &mut Criterion) {
    let chunks = build_chunks();
    let max_logical = N * CHUNK_LEN;

    // Deterministic spread of probe addresses across the whole logical range.
    let probes: Vec<u64> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (x >> 11) % max_logical
            })
            .collect()
    };

    // Isomorphism: binary returns the same chunk end as linear for every probe.
    for &t in &probes {
        assert_eq!(linear(&chunks, t), binary(&chunks, t), "logical {t} diverged");
    }

    let mut group = c.benchmark_group("btrfs_chunk_end_1000");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(linear(black_box(&chunks), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(binary(black_box(&chunks), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(chunk_end_resolve, bench_chunk_end_resolve);
criterion_main!(chunk_end_resolve);
