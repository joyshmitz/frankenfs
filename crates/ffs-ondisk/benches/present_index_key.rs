#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Hypothesis test for a lookup cache-locality lever (bd-cc-present-index-inline).
//!
//! The ext4 present-index is `FxHashMap<Vec<u8>, (u32, Ext4FileType)>` — each name
//! KEY is a separate heap allocation, so a `get(&[u8])` derefs the stored `Vec`'s
//! heap pointer to compare bytes = a cache miss per probed candidate. `lookup-bench`
//! measured cache-miss-bound (~37% miss rate, ~9 misses/lookup). This bench asks: does
//! an INLINE small-string key (`SmallVec<[u8; 24]>`, storing short names in the bucket
//! itself, no heap deref) beat the `Vec<u8>` key — or does the bigger key hurt bucket
//! density enough to offset it? Realistic short filenames (~17 bytes, inline in 24).

use criterion::{Criterion, criterion_group, criterion_main};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::hint::black_box;

type InlineKey = SmallVec<[u8; 24]>;

fn names(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("file_{i:08}.txt").into_bytes())
        .collect()
}

fn bench_present_index_key(c: &mut Criterion) {
    let keys = names(30_000);

    let vec_map: FxHashMap<Vec<u8>, u32> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u32))
        .collect();
    let inline_map: FxHashMap<InlineKey, u32> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (SmallVec::from_slice(k), i as u32))
        .collect();

    // Correctness: both resolve every key identically.
    for k in &keys {
        assert_eq!(vec_map.get(k.as_slice()), inline_map.get(k.as_slice()));
    }

    let mut group = c.benchmark_group("present_index_key_30k");
    group.bench_function("vec_u8_key", |b| {
        b.iter(|| {
            let mut acc = 0u32;
            for k in &keys {
                if let Some(v) = vec_map.get(black_box(k.as_slice())) {
                    acc = acc.wrapping_add(*v);
                }
            }
            black_box(acc)
        });
    });
    group.bench_function("inline_smallvec_key", |b| {
        b.iter(|| {
            let mut acc = 0u32;
            for k in &keys {
                if let Some(v) = inline_map.get(black_box(k.as_slice())) {
                    acc = acc.wrapping_add(*v);
                }
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_present_index_key);
criterion_main!(benches);
