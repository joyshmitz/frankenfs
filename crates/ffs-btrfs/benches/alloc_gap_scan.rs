#![forbid(unsafe_code)]

//! Same-process A/B for binary-searching `alloc_extent`'s forward gap scan
//! (bd-8fbka).
//!
//! `alloc_extent` searches `allocated_ranges` (sorted ascending by start,
//! non-overlapping) for the first gap `>= num_bytes` at or after a cursor that
//! starts at `bg_start + alloc_offset`. `alloc_offset` is a bump pointer that
//! advances past prior allocations, so during a sequential fill the cursor sits
//! near the end of the range list and every allocation re-walks O(E) extents
//! below it that are pure no-ops. Because `ext_end` is monotonic over the
//! sorted, non-overlapping list, a `partition_point` skips that no-op prefix,
//! turning each allocation into O(log E + tail).
//!
//! Benches the steady-state sequential-fill case: a full E-extent block group
//! with the cursor just past the last extent (the next bump-pointer allocation).
//! OLD scans from index 0; NEW partition_points to the suffix. Same answer
//! (asserted across several cursor positions).

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_BLOCK_GROUP_DATA, BTRFS_ITEM_EXTENT_ITEM, BTRFS_ITEM_METADATA_ITEM, BlockGroupFreeSpace,
    BtrfsBTree, BtrfsBlockGroupItem, BtrfsExtentAllocator, BtrfsKey,
};
use std::hint::black_box;

const E: usize = 4096; // extents already allocated in the block group
const EXT_SIZE: u64 = 16_384; // 16 KiB per extent (nodesize-ish)
const BG_START: u64 = 1 << 30;
const NUM_BYTES: u64 = 4096; // a one-page allocation request

/// Densely-packed allocated ranges: [BG_START, BG_START+EXT_SIZE),
/// [BG_START+EXT_SIZE, ...), ... — sorted, non-overlapping, no internal gaps
/// (worst case: the only gap is after the last extent).
fn build_ranges() -> Vec<(u64, u64)> {
    (0..E)
        .map(|i| (BG_START + i as u64 * EXT_SIZE, EXT_SIZE))
        .collect()
}

fn bg_end() -> u64 {
    BG_START + (E as u64 + 16) * EXT_SIZE
}

/// OLD: linear scan from index 0.
fn old_scan(ranges: &[(u64, u64)], mut cursor: u64, num_bytes: u64, bg_end: u64) -> Option<u64> {
    for &(ext_start, ext_size) in ranges {
        let ext_end = ext_start + ext_size;
        if cursor < ext_start && ext_start - cursor >= num_bytes {
            return Some(cursor);
        }
        if ext_end > cursor {
            cursor = ext_end;
        }
    }
    if cursor + num_bytes <= bg_end {
        return Some(cursor);
    }
    None
}

/// NEW: binary-search past the no-op prefix, then scan the suffix.
fn new_scan(ranges: &[(u64, u64)], mut cursor: u64, num_bytes: u64, bg_end: u64) -> Option<u64> {
    let start = ranges.partition_point(|&(s, sz)| s + sz <= cursor);
    for &(ext_start, ext_size) in &ranges[start..] {
        let ext_end = ext_start + ext_size;
        if cursor < ext_start && ext_start - cursor >= num_bytes {
            return Some(cursor);
        }
        if ext_end > cursor {
            cursor = ext_end;
        }
    }
    if cursor + num_bytes <= bg_end {
        return Some(cursor);
    }
    None
}

fn bench_alloc_gap_scan(c: &mut Criterion) {
    let ranges = build_ranges();
    let end = bg_end();
    // Steady-state cursor: just past the last allocated extent.
    let cursor = BG_START + E as u64 * EXT_SIZE;

    // Isomorphism across several cursor positions (start, middle, end, inside a
    // gap-free region).
    for probe in [
        BG_START,
        BG_START + (E as u64 / 2) * EXT_SIZE,
        cursor,
        BG_START + (E as u64 / 4) * EXT_SIZE + 1,
    ] {
        assert_eq!(
            old_scan(&ranges, probe, NUM_BYTES, end),
            new_scan(&ranges, probe, NUM_BYTES, end),
            "scan diverged at cursor {probe}"
        );
    }

    let mut group = c.benchmark_group("alloc_gap_scan_seqfill_4096ext");
    group.bench_function("linear_from_zero", |b| {
        b.iter(|| black_box(old_scan(black_box(&ranges), cursor, NUM_BYTES, end)));
    });
    group.bench_function("partition_point_suffix", |b| {
        b.iter(|| black_box(new_scan(black_box(&ranges), cursor, NUM_BYTES, end)));
    });
    group.finish();
}

fn build_largest_free_allocator() -> BtrfsExtentAllocator {
    let mut alloc = BtrfsExtentAllocator::new(7).expect("allocator");
    alloc.add_block_group(
        BG_START,
        BtrfsBlockGroupItem {
            total_bytes: (E as u64 + 16) * EXT_SIZE,
            used_bytes: E as u64 * EXT_SIZE,
            flags: BTRFS_BLOCK_GROUP_DATA,
        },
    );
    for i in 0..E as u64 {
        alloc
            .insert_data_extent_item(BG_START + i * EXT_SIZE, EXT_SIZE, 5, 256, i * EXT_SIZE, 7)
            .expect("insert data extent item");
    }
    alloc
}

fn legacy_allocated_ranges(alloc: &BtrfsExtentAllocator) -> Vec<(u64, u64)> {
    let total_bytes = (E as u64 + 16) * EXT_SIZE;
    let end = bg_end();
    let range_start = BtrfsKey {
        objectid: BG_START,
        item_type: BTRFS_ITEM_EXTENT_ITEM,
        offset: 0,
    };
    let range_end = BtrfsKey {
        objectid: end,
        item_type: BTRFS_ITEM_METADATA_ITEM,
        offset: u64::MAX,
    };
    let mut allocated_ranges = Vec::new();
    let mut materialized_used = 0_u64;
    for (key, _) in alloc
        .extent_tree()
        .range(&range_start, &range_end)
        .expect("bench extent range")
    {
        if key.objectid >= end {
            break;
        }
        if !matches!(
            key.item_type,
            BTRFS_ITEM_EXTENT_ITEM | BTRFS_ITEM_METADATA_ITEM
        ) {
            continue;
        }
        let extent_start = key.objectid.max(BG_START);
        let extent_end = key
            .objectid
            .checked_add(key.offset)
            .expect("bench extent end")
            .min(end);
        if extent_start < extent_end {
            materialized_used = materialized_used
                .checked_add(extent_end - extent_start)
                .expect("bench materialized bytes");
            allocated_ranges.push((extent_start, extent_end));
        }
    }

    let used_bytes = E as u64 * EXT_SIZE;
    let untracked_used = used_bytes
        .saturating_sub(materialized_used)
        .min(total_bytes);
    if untracked_used > 0 {
        allocated_ranges.push((BG_START, BG_START + untracked_used));
    }
    allocated_ranges.sort_unstable_by_key(|&(start, end)| (start, end));
    allocated_ranges
}

fn legacy_largest_free_extent(alloc: &BtrfsExtentAllocator) -> u64 {
    let mut cursor = BG_START;
    let mut group_best = 0_u64;
    for (extent_start, extent_end) in legacy_allocated_ranges(alloc) {
        if extent_end <= cursor {
            continue;
        }
        if cursor < extent_start {
            group_best = group_best.max(extent_start - cursor);
        }
        cursor = extent_end;
    }
    let end = bg_end();
    if cursor < end {
        group_best = group_best.max(end - cursor);
    }
    group_best.min(16 * EXT_SIZE)
}

fn legacy_free_space_extents(alloc: &BtrfsExtentAllocator) -> Vec<BlockGroupFreeSpace> {
    let mut free_ranges = Vec::new();
    let mut cursor = BG_START;
    for (extent_start, extent_end) in legacy_allocated_ranges(alloc) {
        if extent_end <= cursor {
            continue;
        }
        if cursor < extent_start {
            free_ranges.push((cursor, extent_start - cursor));
        }
        cursor = extent_end;
    }
    let end = bg_end();
    if cursor < end {
        free_ranges.push((cursor, end - cursor));
    }
    vec![BlockGroupFreeSpace {
        start: BG_START,
        total_bytes: (E as u64 + 16) * EXT_SIZE,
        flags: BTRFS_BLOCK_GROUP_DATA,
        free_ranges,
    }]
}

fn bench_largest_free_extent(c: &mut Criterion) {
    let alloc = build_largest_free_allocator();
    let expected = 16 * EXT_SIZE;
    assert_eq!(legacy_largest_free_extent(&alloc), expected);
    assert_eq!(
        alloc
            .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
            .expect("largest free extent"),
        expected
    );

    let mut group = c.benchmark_group("btrfs_largest_free_extent_keyscan_4096");
    group.bench_function("legacy_range_vec_sort_largest", |b| {
        b.iter(|| black_box(legacy_largest_free_extent(black_box(&alloc))));
    });
    group.bench_function("streaming_largest_free_extent", |b| {
        b.iter(|| {
            black_box(
                alloc
                    .largest_free_extent(black_box(BTRFS_BLOCK_GROUP_DATA))
                    .expect("largest free extent"),
            )
        });
    });
    group.finish();
}

fn bench_free_space_extents(c: &mut Criterion) {
    let alloc = build_largest_free_allocator();
    let legacy = legacy_free_space_extents(&alloc);
    let free_space = alloc.free_space_extents().expect("free space extents");
    assert_eq!(legacy, free_space);
    assert_eq!(free_space.len(), 1);
    assert_eq!(
        free_space[0].free_ranges,
        vec![(BG_START + E as u64 * EXT_SIZE, 16 * EXT_SIZE)]
    );

    let mut group = c.benchmark_group("btrfs_free_space_extents_keyscan_4096");
    group.bench_function("legacy_range_vec_sort_free_space", |b| {
        b.iter(|| black_box(legacy_free_space_extents(black_box(&alloc))));
    });
    group.bench_function("streaming_free_space_extents", |b| {
        b.iter(|| black_box(alloc.free_space_extents().expect("free space extents")));
    });
    group.finish();
}

fn bench_sync_block_group_accounting(c: &mut Criterion) {
    let mut alloc = build_largest_free_allocator();
    assert_eq!(
        alloc
            .sync_block_group_accounting()
            .expect("sync block group accounting"),
        E as u64 * EXT_SIZE
    );

    let mut group = c.benchmark_group("btrfs_sync_block_group_accounting_keyscan_4096");
    group.bench_function("production_sync_block_group_accounting", |b| {
        b.iter(|| {
            black_box(
                alloc
                    .sync_block_group_accounting()
                    .expect("sync block group accounting"),
            )
        });
    });
    group.finish();
}

/// OLD commit sequence: two adjacent passes over the same per-block-group
/// extent keys — accounting recompute then free-space derivation.
fn commit_accounting_free_space_production(
    alloc: &mut BtrfsExtentAllocator,
) -> (u64, Vec<BlockGroupFreeSpace>) {
    let bytes_used = alloc
        .sync_block_group_accounting()
        .expect("sync block group accounting");
    let free_space = alloc.free_space_extents().expect("free space extents");
    (bytes_used, free_space)
}

/// NEW commit sequence (bd-xmh5g.193): one fused scan computing both the
/// accounting grand total and the free-space groups.
fn commit_accounting_free_space_fused(
    alloc: &mut BtrfsExtentAllocator,
) -> (u64, Vec<BlockGroupFreeSpace>) {
    alloc
        .sync_accounting_and_free_space()
        .expect("fused accounting + free space")
}

fn bench_commit_accounting_free_space(c: &mut Criterion) {
    // Isomorphism: the fused single-scan helper returns byte-identical
    // accounting totals AND free-space groups to the two-pass sequence.
    let mut alloc_two_pass = build_largest_free_allocator();
    let mut alloc_fused = build_largest_free_allocator();
    let two_pass = commit_accounting_free_space_production(&mut alloc_two_pass);
    let fused = commit_accounting_free_space_fused(&mut alloc_fused);
    assert_eq!(two_pass.0, E as u64 * EXT_SIZE);
    assert_eq!(
        two_pass, fused,
        "fused commit accounting diverged from two-pass"
    );

    let mut group = c.benchmark_group("btrfs_commit_accounting_free_space_scan_4096");
    group.bench_function("production_two_pass", |b| {
        b.iter(|| black_box(commit_accounting_free_space_production(&mut alloc_two_pass)));
    });
    group.bench_function("fused_single_scan", |b| {
        b.iter(|| black_box(commit_accounting_free_space_fused(&mut alloc_fused)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_alloc_gap_scan,
    bench_largest_free_extent,
    bench_free_space_extents,
    bench_sync_block_group_accounting,
    bench_commit_accounting_free_space
);
criterion_main!(benches);
