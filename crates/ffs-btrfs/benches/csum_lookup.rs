#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the btrfs data-csum lookup (bd-dgih3).
//!
//! `lookup_data_block_csum` finds the EXTENT_CSUM item covering an on-disk
//! sector. Items are sorted ascending by `key.offset` (the order
//! `build_extent_csum_items` emits and a csum-tree walk yields), and the
//! covering item is the last whose offset is `<=` the target. The old code
//! scanned every item (O(items)); the new code binary-searches (O(log items)).
//!
//! Whole-file csum verification calls this once per sector against the *entire*
//! csum tree, so the scan made verification O(sectors * items): a multi-GiB file
//! has tens-to-hundreds of EXTENT_CSUM items and hundreds of thousands of
//! sectors.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_EXTENT_CSUM_OBJECTID, BTRFS_ITEM_EXTENT_CSUM, BtrfsKey, lookup_data_block_csum,
};
use std::hint::black_box;

const N: usize = 4096; // EXTENT_CSUM items in the tree (each covers a run of sectors)
const SECTORSIZE: usize = 4096;
const CSUMS_PER_ITEM: u64 = 64; // sectors covered by one item
const CSUM_SIZE: usize = 4;

/// Build a sorted-by-offset csum-tree item list: item `i` covers
/// `CSUMS_PER_ITEM` sectors starting at disk bytenr `i * stride`.
fn build_items() -> Vec<(BtrfsKey, Vec<u8>)> {
    let stride = CSUMS_PER_ITEM * SECTORSIZE as u64;
    (0..N as u64)
        .map(|i| {
            let key = BtrfsKey {
                objectid: BTRFS_EXTENT_CSUM_OBJECTID,
                item_type: BTRFS_ITEM_EXTENT_CSUM,
                offset: i * stride,
            };
            // Distinct per-sector crc bytes so divergence would be observable.
            let mut value = vec![0_u8; CSUMS_PER_ITEM as usize * CSUM_SIZE];
            for (s, chunk) in value.chunks_exact_mut(CSUM_SIZE).enumerate() {
                let v = (i.wrapping_mul(131) + s as u64) as u32;
                chunk.copy_from_slice(&v.to_le_bytes());
            }
            (key, value)
        })
        .collect()
}

/// Linear scan (the pre-bd-dgih3 shape): greatest offset `<=` target among
/// EXTENT_CSUM items, then unpack the covering sector's crc32c.
fn linear(items: &[(BtrfsKey, Vec<u8>)], disk_bytenr: u64, sectorsize: usize) -> Option<u32> {
    let mut best: Option<(u64, &[u8])> = None;
    for (key, value) in items {
        if key.item_type != BTRFS_ITEM_EXTENT_CSUM || key.objectid != BTRFS_EXTENT_CSUM_OBJECTID {
            continue;
        }
        if key.offset > disk_bytenr {
            continue;
        }
        if best.is_none_or(|(off, _)| key.offset > off) {
            best = Some((key.offset, value.as_slice()));
        }
    }
    let (item_offset, value) = best?;
    let delta = usize::try_from(disk_bytenr.checked_sub(item_offset)?).ok()?;
    if delta % sectorsize != 0 {
        return None;
    }
    let base = (delta / sectorsize).checked_mul(CSUM_SIZE)?;
    let end = base.checked_add(CSUM_SIZE)?;
    if end > value.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        value[base],
        value[base + 1],
        value[base + 2],
        value[base + 3],
    ]))
}

fn bench_csum_lookup(c: &mut Criterion) {
    let items = build_items();
    let stride = CSUMS_PER_ITEM * SECTORSIZE as u64;
    let max_bytenr = N as u64 * stride;

    // Deterministic spread of sector-aligned probe bytenrs across the range.
    let probes: Vec<u64> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                ((x >> 11) % max_bytenr) / SECTORSIZE as u64 * SECTORSIZE as u64
            })
            .collect()
    };

    // Isomorphism: the binary-search lookup returns the same crc the linear
    // scan does for every probe.
    for &t in &probes {
        assert_eq!(
            lookup_data_block_csum(&items, t, SECTORSIZE),
            linear(&items, t, SECTORSIZE),
            "disk_bytenr {t} diverged"
        );
    }

    let mut group = c.benchmark_group("btrfs_csum_lookup_4096");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(u64::from(
                    linear(black_box(&items), t, SECTORSIZE).unwrap_or(0),
                ));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(u64::from(
                    lookup_data_block_csum(black_box(&items), t, SECTORSIZE).unwrap_or(0),
                ));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(csum_lookup, bench_csum_lookup);
criterion_main!(csum_lookup);
