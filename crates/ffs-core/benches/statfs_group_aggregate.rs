#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for statfs free-count aggregation (bd-qsmav).
//!
//! ext4 `statfs` summed free blocks/inodes by reading + parsing EVERY group
//! descriptor on each call (`read_group_desc_with_scope` per group: a block
//! lookup + csum-verify + `Ext4GroupDesc::parse_from_bytes`, O(group_count)).
//! On a writable fs the in-memory ffs-alloc `GroupStats` already mirror the
//! descriptors and are kept current on every alloc/free, so statfs now sums
//! those plain `u32` fields under one lock instead.
//!
//! This benches the aggregation both ways over a `G`-group filesystem: OLD
//! parses each descriptor out of the GD table then sums; NEW sums the
//! pre-built `GroupStats`. Same totals (asserted). The real statfs win is at
//! least this, since the device path also csum-verifies each descriptor.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::GroupStats;
use ffs_ondisk::ext4::Ext4GroupDesc;
use ffs_types::GroupNumber;
use std::hint::black_box;

const DESC_SIZE: u16 = 64; // 64-bit feature descriptor size
const G: usize = 4096; // groups (~256 GiB fs at 128 MiB/group)

/// A GD table of `G` descriptors with a varying free-block / free-inode count
/// per group so the sums are non-trivial.
fn build_gd_table() -> Vec<u8> {
    let mut bytes = vec![0_u8; G * DESC_SIZE as usize];
    for g in 0..G {
        let base = g * DESC_SIZE as usize;
        // free_blocks_count_lo @ 0x0C (u16), free_inodes_count_lo @ 0x0E (u16).
        let free_blocks = (100 + (g % 500)) as u16;
        let free_inodes = (10 + (g % 50)) as u16;
        bytes[base + 0x0C..base + 0x0E].copy_from_slice(&free_blocks.to_le_bytes());
        bytes[base + 0x0E..base + 0x10].copy_from_slice(&free_inodes.to_le_bytes());
    }
    bytes
}

fn parse_desc(table: &[u8], g: usize) -> Ext4GroupDesc {
    let off = g * DESC_SIZE as usize;
    Ext4GroupDesc::parse_from_bytes(&table[off..off + DESC_SIZE as usize], DESC_SIZE).unwrap()
}

/// OLD: parse each descriptor out of the GD table, then sum.
fn aggregate_parse(table: &[u8]) -> (u64, u64) {
    let mut blocks = 0_u64;
    let mut inodes = 0_u64;
    for g in 0..G {
        let gd = parse_desc(table, g);
        blocks += u64::from(gd.free_blocks_count);
        inodes += u64::from(gd.free_inodes_count);
    }
    (blocks, inodes)
}

/// NEW: sum the pre-built in-memory group stats.
fn aggregate_group_stats(stats: &[GroupStats]) -> (u64, u64) {
    let blocks: u64 = stats.iter().map(|g| u64::from(g.free_blocks)).sum();
    let inodes: u64 = stats.iter().map(|g| u64::from(g.free_inodes)).sum();
    (blocks, inodes)
}

fn bench_statfs_aggregate(c: &mut Criterion) {
    let table = build_gd_table();
    let stats: Vec<GroupStats> = (0..G)
        .map(|g| GroupStats::from_group_desc(GroupNumber(g as u32), &parse_desc(&table, g)))
        .collect();

    // Isomorphism: identical free totals either way.
    assert_eq!(
        aggregate_parse(&table),
        aggregate_group_stats(&stats),
        "statfs aggregation diverged"
    );

    let mut group = c.benchmark_group("statfs_aggregate_4096_groups");
    group.bench_function("parse_each_descriptor", |b| {
        b.iter(|| black_box(aggregate_parse(black_box(&table))));
    });
    group.bench_function("sum_group_stats", |b| {
        b.iter(|| black_box(aggregate_group_stats(black_box(&stats))));
    });
    group.finish();
}

criterion_group!(benches, bench_statfs_aggregate);
criterion_main!(benches);
