#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the physical-version visibility lookup (bd-xmh5g-class
//! lever): the prior `read_visible_physical` did an O(n) reverse linear scan
//! (`.iter().rev().find(commit_seq <= snapshot.high)`) over the physical chain.
//!
//! Under a long-running reader that holds the GC watermark down, the chain
//! cannot be trimmed and grows large, so the old reader's scan walks past every
//! newer version each read. The lever replaces it with the binary search
//! already used for logical chains (`newest_visible_index_by`): check the newest
//! element first (O(1) for fresh readers) else `partition_point` in O(log n).
//!
//! This bench reproduces the pathology in-binary: a deep ascending chain read at
//! an OLD snapshot whose visible version sits near the front.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_mvcc::PhysicalBlockVersion;
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::hint::black_box;

fn build_chain(n: u64) -> Vec<PhysicalBlockVersion> {
    // Strictly-ascending commit_seq chain (seq = i+1), as commits append.
    (0..n)
        .map(|i| PhysicalBlockVersion {
            logical: BlockNumber(7),
            physical: BlockNumber(1000 + i),
            commit_seq: CommitSeq(i + 1),
            writer: TxnId(i + 1),
        })
        .collect()
}

/// Prior implementation: reverse linear scan.
#[inline]
fn old_linear(versions: &[PhysicalBlockVersion], high: CommitSeq) -> Option<BlockNumber> {
    versions
        .iter()
        .rev()
        .find(|v| v.commit_seq <= high)
        .map(|v| v.physical)
}

/// New implementation: newest-first check, else binary search (mirrors
/// `newest_visible_index_by`).
#[inline]
fn new_binary(versions: &[PhysicalBlockVersion], high: CommitSeq) -> Option<BlockNumber> {
    let last = versions.len().checked_sub(1)?;
    let idx = if versions[last].commit_seq <= high {
        last
    } else {
        versions
            .partition_point(|v| v.commit_seq <= high)
            .checked_sub(1)?
    };
    Some(versions[idx].physical)
}

fn bench_physical_visibility_ab(c: &mut Criterion) {
    const N: u64 = 512;
    let chain = build_chain(N);
    // Old reader: visible version sits near the front (index 4), so the reverse
    // scan must walk past ~507 newer versions.
    let old_snapshot = CommitSeq(5);

    // Isomorphism: both return the identical physical block, at every snapshot.
    for high in [0u64, 1, 5, 100, 256, N, N + 10] {
        assert_eq!(
            old_linear(&chain, CommitSeq(high)),
            new_binary(&chain, CommitSeq(high)),
            "visibility lookup diverged at high={high}"
        );
    }

    let mut group = c.benchmark_group("mvcc_physical_visibility_ab_chain512_oldsnapshot");
    group.bench_function("old_reverse_linear_scan", |b| {
        b.iter(|| black_box(old_linear(black_box(&chain), black_box(old_snapshot))));
    });
    group.bench_function("new_binary_search", |b| {
        b.iter(|| black_box(new_binary(black_box(&chain), black_box(old_snapshot))));
    });
    group.finish();
}

criterion_group!(physical_visibility, bench_physical_visibility_ab);
criterion_main!(physical_visibility);
