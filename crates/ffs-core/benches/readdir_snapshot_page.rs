#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the readdir snapshot page path (bd-cbqd7, bd-gn4zb).
//!
//! `OpenFs::readdir` serves a paginated listing from a cached full snapshot via
//! `slice_readdir_snapshot`: binary-search the start cookie, then clone the tail.
//! The FUSE layer fills its reply buffer (~`PAGE` entries on a 4 KiB readdir
//! buffer), breaks once full, and re-requests at the next cookie. The old code
//! cloned the *entire* remaining tail on every call, so a full enumeration of an
//! N-entry directory cloned `N + (N-p) + (N-2p) + … = O(N²/p)` `DirEntry`s, each
//! copying a heap-allocated name. The capped code bounded that clone to O(N)
//! total. The shared-page path returns an `Arc` plus slice bounds, so the hot
//! FUSE drain borrows each page without per-call `DirEntry`/name clones. This
//! benches a complete paginated drain of a large directory the way FUSE drives
//! it.
//!
//! The `slice_*` functions below mirror the production `slice_readdir_snapshot`
//! before/after exactly (same `partition_point` start; the differences are the
//! page bound and owned-vs-shared page representation), the established pattern
//! for ffs-core micro-A/Bs.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

/// Directory entry mirroring `ffs_core::DirEntry`'s clone cost (heap name).
#[allow(dead_code)]
#[derive(Clone)]
struct Entry {
    ino: u64,
    offset: u64,
    name: Vec<u8>,
}

const N: u64 = 20_000; // a large directory
const PAGE_FILL: usize = 170; // entries that fit a default 4 KiB FUSE readdir buffer
const PAGE_MAX: usize = 512; // production READDIR_SNAPSHOT_PAGE_MAX

fn build_listing() -> Vec<Entry> {
    (0..N)
        .map(|i| Entry {
            ino: i + 100,
            offset: i + 1,
            name: format!("entry_{i:08}").into_bytes(),
        })
        .collect()
}

/// OLD: clone the entire remaining tail after `offset`.
fn slice_old(entries: &[Entry], offset: u64) -> Vec<Entry> {
    let start = entries.partition_point(|e| e.offset <= offset);
    entries[start..].to_vec()
}

/// NEW: clone at most `PAGE_MAX` entries after `offset`.
fn slice_new(entries: &[Entry], offset: u64) -> Vec<Entry> {
    let start = entries.partition_point(|e| e.offset <= offset);
    let end = start.saturating_add(PAGE_MAX).min(entries.len());
    entries[start..end].to_vec()
}

/// SHARED: return the cached listing plus visible page bounds.
fn slice_shared(entries: &Arc<Vec<Entry>>, offset: u64) -> (Arc<Vec<Entry>>, usize, usize) {
    let start = entries.partition_point(|e| e.offset <= offset);
    let end = start.saturating_add(PAGE_MAX).min(entries.len());
    (Arc::clone(entries), start, end)
}

/// Drive a full paginated readdir the way the FUSE layer does: serve a page,
/// consume up to `PAGE_FILL` entries (buffer fills, break), re-request at the
/// last cookie. Returns total entries delivered (must equal N for both).
fn drain<F: Fn(&[Entry], u64) -> Vec<Entry>>(entries: &[Entry], serve: F) -> u64 {
    let mut delivered = 0_u64;
    let mut offset = 0_u64;
    loop {
        let page = serve(entries, offset);
        if page.is_empty() {
            break;
        }
        let take = page.len().min(PAGE_FILL);
        delivered += take as u64;
        offset = page[take - 1].offset;
        black_box(&page);
    }
    delivered
}

fn drain_shared(entries: &Arc<Vec<Entry>>) -> u64 {
    let mut delivered = 0_u64;
    let mut offset = 0_u64;
    loop {
        let (page, start, end) = slice_shared(entries, offset);
        if start == end {
            break;
        }
        let take = (end - start).min(PAGE_FILL);
        delivered += take as u64;
        offset = page[start + take - 1].offset;
        black_box((&page, start, end));
    }
    delivered
}

fn bench_readdir_snapshot_page(c: &mut Criterion) {
    let listing = build_listing();
    let shared_listing = Arc::new(listing.clone());
    assert_eq!(drain(&listing, slice_old), N);
    assert_eq!(
        drain(&listing, slice_new),
        N,
        "cap must deliver the full listing"
    );
    assert_eq!(
        drain_shared(&shared_listing),
        N,
        "shared page must deliver the full listing"
    );

    let mut group = c.benchmark_group("readdir_snapshot_full_enumeration_20k");
    group.bench_function("old_clone_whole_tail", |b| {
        b.iter(|| black_box(drain(black_box(&listing), slice_old)));
    });
    group.bench_function("new_capped_page", |b| {
        b.iter(|| black_box(drain(black_box(&listing), slice_new)));
    });
    group.bench_function("new_shared_arc_page", |b| {
        b.iter(|| black_box(drain_shared(black_box(&shared_listing))));
    });
    group.finish();
}

criterion_group!(benches, bench_readdir_snapshot_page);
criterion_main!(benches);
