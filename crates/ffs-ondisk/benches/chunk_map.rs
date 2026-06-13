#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the btrfs chunk-map lookup (bd-6u6xb).
//!
//! `map_logical_to_physical` finds the chunk covering a logical address. Chunks
//! cover disjoint logical ranges and the full list is sorted ascending by
//! `key.offset`, so the covering chunk is the last one whose start is `<=` the
//! target. The old code scanned every chunk (O(N)); the new code binary-searches
//! large lists (O(log N)). A large btrfs filesystem has hundreds–thousands of
//! chunks, and this runs on every logical->physical mapping (every tree-node and
//! data-block read).

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{BtrfsChunkEntry, BtrfsKey, BtrfsStripe, map_logical_to_physical};
use std::hint::black_box;

const N: u64 = 1000; // a multi-TB filesystem's chunk count
const CHUNK_LEN: u64 = 1 << 30; // 1 GiB data chunks

fn build_chunks() -> Vec<BtrfsChunkEntry> {
    (0..N)
        .map(|i| {
            let logical = i * CHUNK_LEN;
            BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228, // CHUNK_ITEM
                    offset: logical,
                },
                length: CHUNK_LEN,
                owner: 2,
                stripe_len: 0x1_0000,
                chunk_type: 1, // BTRFS_BLOCK_GROUP_DATA -> Single profile
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                num_stripes: 1,
                sub_stripes: 0,
                stripes: vec![BtrfsStripe {
                    devid: 1,
                    offset: 0x10_0000 + i * CHUNK_LEN,
                    dev_uuid: [0_u8; 16],
                }],
            }
        })
        .collect()
}

/// Linear scan (the pre-bd-6u6xb shape): first chunk covering `logical`.
fn linear(chunks: &[BtrfsChunkEntry], logical: u64) -> Option<u64> {
    for c in chunks {
        if logical >= c.key.offset && logical < c.key.offset + c.length {
            return Some(c.stripes[0].offset + (logical - c.key.offset));
        }
    }
    None
}

fn bench_chunk_map(c: &mut Criterion) {
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

    // Isomorphism: the binary-search map returns the same physical address the
    // linear scan does for every probe.
    for &t in &probes {
        let mapped = map_logical_to_physical(&chunks, t).unwrap().map(|m| m.physical);
        assert_eq!(mapped, linear(&chunks, t), "logical {t} diverged");
    }

    let mut group = c.benchmark_group("btrfs_chunk_map_1000");
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
                acc = acc.wrapping_add(
                    map_logical_to_physical(black_box(&chunks), t)
                        .unwrap()
                        .map_or(0, |m| m.physical),
                );
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(chunk_map, bench_chunk_map);
criterion_main!(chunk_map);
