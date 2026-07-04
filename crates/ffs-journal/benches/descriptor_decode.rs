#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for the JBD2 crash-recovery descriptor-tag decode (guards commit
//! `05ce88c5`).
//!
//! `replay_jbd2_inner` used to decode every descriptor block's tag region TWICE
//! — `strict_descriptor_tag_count_with_format` (validate + count) immediately
//! followed by `parse_descriptor_tags_with_format` (build the `Vec`) — an
//! identical O(tags) scan run back-to-back over the same buffer. The single
//! strict pass (`parse_descriptor_tags_strict_with_format`) validates AND builds
//! the tags at once. This benches the old two-pass vs the new one-pass on a
//! descriptor with 32 tags (via the `bench_descriptor_decode` shim).
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig5 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-journal --bench descriptor_decode

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const BLOCKTYPE_DESCRIPTOR: u32 = 1;
const HEADER_SIZE: usize = 12;
const FLAGS_OFFSET_V1_V2: usize = 6;
const FLAG_SAME_UUID: u16 = 0x0002;
const FLAG_LAST: u16 = 0x0008;
const N_TAGS: usize = 32;

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
        b[off + FLAGS_OFFSET_V1_V2..off + FLAGS_OFFSET_V1_V2 + 2].copy_from_slice(&fl.to_be_bytes());
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

criterion_group!(benches, bench);
criterion_main!(benches);
