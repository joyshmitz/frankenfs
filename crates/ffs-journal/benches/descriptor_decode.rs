#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for JBD2 crash-recovery decode paths (guards commit `05ce88c5` and
//! the revoke event fusion path).
//!
//! `replay_jbd2_inner` used to decode every descriptor block's tag region TWICE
//! — `strict_descriptor_tag_count_with_format` (validate + count) immediately
//! followed by `parse_descriptor_tags_with_format` (build the `Vec`) — an
//! identical O(tags) scan run back-to-back over the same buffer. The single
//! strict pass (`parse_descriptor_tags_strict_with_format`) validates AND builds
//! the tags at once. This benches the old two-pass vs the new one-pass on a
//! descriptor with 32 tags (via the `bench_descriptor_decode` shim).
//!
//! The revoke row compares the legacy replay shape (strict revoke parse into a
//! temporary `Vec<BlockNumber>`, then append `TxnBodyEvent::Revoke`) with the
//! fused scanner that appends events while decoding the fixed-width revoke
//! payload.
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig5 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-journal --bench descriptor_decode

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const BLOCKTYPE_DESCRIPTOR: u32 = 1;
const BLOCKTYPE_REVOKE: u32 = 5;
const HEADER_SIZE: usize = 12;
const REVOKE_HEADER_SIZE: usize = 16;
const FLAGS_OFFSET_V1_V2: usize = 6;
const FLAG_SAME_UUID: u16 = 0x0002;
const FLAG_LAST: u16 = 0x0008;
const N_TAGS: usize = 32;
const N_REVOKES: usize = 1020;

/// Build a Legacy JBD2 descriptor block with `n` SAME_UUID tags (8-byte
/// records), the last one LAST-terminated — the shape replay decodes.
fn build_descriptor(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    b[4..8].copy_from_slice(&BLOCKTYPE_DESCRIPTOR.to_be_bytes());
    b[8..12].copy_from_slice(&7u32.to_be_bytes()); // sequence
    for i in 0..n {
        let off = HEADER_SIZE + i * 8;
        b[off..off + 4].copy_from_slice(&((i as u32) + 1).to_be_bytes()); // blocknr
        let mut fl = FLAG_SAME_UUID;
        if i == n - 1 {
            fl |= FLAG_LAST;
        }
        b[off + FLAGS_OFFSET_V1_V2..off + FLAGS_OFFSET_V1_V2 + 2]
            .copy_from_slice(&fl.to_be_bytes());
    }
    b
}

/// Build a 4 KiB 32-bit JBD2 revoke block with a dense payload. The entry count
/// matches `(4096 - 16) / 4`, which is the full block shape replay validates.
fn build_revoke(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    b[4..8].copy_from_slice(&BLOCKTYPE_REVOKE.to_be_bytes());
    b[8..12].copy_from_slice(&7u32.to_be_bytes());

    let r_count = REVOKE_HEADER_SIZE + n * 4;
    b[12..16].copy_from_slice(&(r_count as u32).to_be_bytes());

    for i in 0..n {
        let off = REVOKE_HEADER_SIZE + i * 4;
        let block = (i as u32).wrapping_mul(17).wrapping_add(11);
        b[off..off + 4].copy_from_slice(&block.to_be_bytes());
    }

    b
}

fn bench(c: &mut Criterion) {
    let block = build_descriptor(N_TAGS);
    // format=0 (Legacy), is_64bit=false, has_tail=false.
    let two = ffs_journal::bench_descriptor_decode(&block, false, false, 0, false);
    let one = ffs_journal::bench_descriptor_decode(&block, false, false, 0, true);
    assert_eq!(two, N_TAGS, "two-pass must decode all {N_TAGS} tags");
    assert_eq!(one, two, "one-pass must match two-pass count");

    {
        let mut g = c.benchmark_group("jbd2_descriptor_decode_32tags");
        g.bench_function("two_pass_count_then_parse", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_descriptor_decode(
                    black_box(&block),
                    false,
                    false,
                    0,
                    false,
                ))
            });
        });
        g.bench_function("one_pass_strict_parse", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_descriptor_decode(
                    black_box(&block),
                    false,
                    false,
                    0,
                    true,
                ))
            });
        });
        g.finish();
    }

    let revoke = build_revoke(N_REVOKES);
    let legacy = ffs_journal::bench_revoke_decode(&revoke, false, false, false);
    let fused = ffs_journal::bench_revoke_decode(&revoke, false, false, true);
    assert_ne!(legacy, 0, "legacy revoke decode must consume entries");
    assert_eq!(fused, legacy, "fused revoke decode must match legacy");

    {
        let mut g = c.benchmark_group("jbd2_revoke_decode_1020entries");
        g.bench_function("legacy_vec_then_events", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_revoke_decode(
                    black_box(&revoke),
                    false,
                    false,
                    false,
                ))
            });
        });
        g.bench_function("fused_decode_events", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_revoke_decode(
                    black_box(&revoke),
                    false,
                    false,
                    true,
                ))
            });
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
