#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Bench target for readdir-driven parallel inode-table prefetch (bd-xmh5g.399).
//!
//! `ls -l` over an N-entry directory does readdir then getattr() on each entry,
//! and each getattr reads that inode's inode-table block. The inodes are
//! scattered across blocks, so on a COLD cache the N getattrs each pay a SERIAL
//! inode-table-block I/O. The lever prefetches those blocks in PARALLEL during
//! readdir (warming the sharded `ext4_inode_table_block_cache`), so the getattrs
//! hit cache — the I/O-overlap class that robustly beats serial on this infra
//! (a blocking read parks its core, so sleeping reads overlap across the rayon
//! pool; see W152/W154).
//!
//! This models the per-directory headroom on a latency device: each
//! `read_inode_block` sleeps the per-block I/O cost (the W152 sleep+delegate
//! measurement device). `serial_getattr_reads` reads the N blocks one at a time;
//! `parallel_prefetch` reads them via `into_par_iter`. The delta is the cold
//! directory-listing latency the prefetch removes.

use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::*;
use std::hint::black_box;
use std::time::Duration;

const ENTRIES: usize = 256; // an `ls -l` over a 256-entry directory
const READ_LATENCY: Duration = Duration::from_micros(40); // per inode-table-block I/O

fn read_inode_block(block: usize) -> u64 {
    // Model the inode-table-block device read: a blocking read that parks the
    // core (so parallel reads overlap), not CPU work.
    std::thread::sleep(READ_LATENCY);
    black_box(block as u64)
}

fn bench_inode_prefetch(c: &mut Criterion) {
    let blocks: Vec<usize> = (0..ENTRIES).collect();
    let serial_order_checksum = blocks
        .iter()
        .fold(0_u64, |acc, &blk| acc.wrapping_add(blk as u64));
    let parallel_order_checksum = blocks
        .par_iter()
        .map(|&blk| blk as u64)
        .reduce(|| 0, u64::wrapping_add);
    assert_eq!(
        serial_order_checksum, parallel_order_checksum,
        "parallel prefetch must cover the same inode-table block set"
    );

    let mut group = c.benchmark_group("ls_dir_inode_prefetch_256");

    // Current cold path: each getattr reads its inode-table block serially.
    group.bench_function("serial_getattr_reads", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &blk in &blocks {
                acc = acc.wrapping_add(read_inode_block(blk));
            }
            black_box(acc)
        });
    });

    // Lever: readdir prefetches all the inode-table blocks in parallel; the
    // blocking reads overlap across the rayon pool.
    group.bench_function("parallel_prefetch", |b| {
        b.iter(|| {
            black_box(
                blocks
                    .par_iter()
                    .map(|&blk| read_inode_block(blk))
                    .sum::<u64>(),
            )
        });
    });

    group.finish();
}

criterion_group!(ls_dir_inode_prefetch, bench_inode_prefetch);
criterion_main!(ls_dir_inode_prefetch);
