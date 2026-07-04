#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for btrfs `listxattr` names-only parsing.
//!
//! `btrfs_listxattr` collects every XATTR_ITEM's attributes via
//! `parse_xattr_items`, which copies each attribute's VALUE into a fresh `Vec`
//! (`data[name_end..value_end].to_vec()`) — then uses only the names and drops
//! the values. `parse_xattr_item_names` does the identical walk + bounds
//! validation but skips the value copy.
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig8 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench xattr_names

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{parse_xattr_item_names, parse_xattr_items};
use std::hint::black_box;

const HEADER: usize = 30;
const N: usize = 24;

/// Build a btrfs XATTR_ITEM payload of `n` attributes, each `user.attrNN` with a
/// `value_len`-byte value. Layout per item: 30-byte header (data_len @25..27,
/// name_len @27..29, rest ignored), name, value.
fn build_payload(n: usize, value_len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    for i in 0..n {
        let name = format!("user.attr{i:02}");
        let name_bytes = name.as_bytes();
        let mut hdr = [0u8; HEADER];
        hdr[25..27].copy_from_slice(&(value_len as u16).to_le_bytes());
        hdr[27..29].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(name_bytes);
        buf.extend(std::iter::repeat((i as u8).wrapping_mul(31)).take(value_len));
    }
    buf
}

fn bench_group(c: &mut Criterion, value_len: usize, label: &str) {
    let payload = build_payload(N, value_len);
    // Isomorphism: names-only yields the same names as materialise-all.
    let full = parse_xattr_items(&payload).unwrap();
    let names = parse_xattr_item_names(&payload).unwrap();
    assert_eq!(names.len(), full.len());
    for (nm, item) in names.iter().zip(full.iter()) {
        assert_eq!(nm, &item.name, "names-only diverged ({label})");
    }

    let mut g = c.benchmark_group(format!("btrfs_listxattr_24_{label}"));
    g.bench_function("parse_items_with_values", |b| {
        b.iter(|| black_box(parse_xattr_items(black_box(&payload)).unwrap()));
    });
    g.bench_function("parse_names_only", |b| {
        b.iter(|| black_box(parse_xattr_item_names(black_box(&payload)).unwrap()));
    });
    g.finish();
}

fn bench(c: &mut Criterion) {
    bench_group(c, 32, "smallval");
    bench_group(c, 128, "largeval");
}

criterion_group!(xattr_names, bench);
criterion_main!(xattr_names);
