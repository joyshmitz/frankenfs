#![forbid(unsafe_code)]
//! A/B for the transactional free path (free_blocks_persist): old per-bit
//! clear-with-undo (clear each bit + push its index to a rollback Vec) + per-bit
//! double-free validation, vs new range-clear + a 4-wide find-free double-free
//! scan (undo is the segment's own range, no per-bit Vec). Freeing a large
//! contiguous extent (unlink/truncate) on the write serial floor.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench free_range_undo
use criterion::{Criterion, criterion_group, criterion_main, BatchSize};
use std::hint::black_box;

fn get_bit(bitmap: &[u8], idx: u32) -> bool {
    bitmap.get((idx / 8) as usize).is_some_and(|b| (b >> (idx % 8)) & 1 == 1)
}
// OLD: per-bit validate + clear-with-undo.
fn old_free(bitmap: &mut [u8], start: u32, count: u32) -> u32 {
    let mut undo: Vec<u32> = Vec::with_capacity(count as usize);
    for i in start..start + count { if !get_bit(bitmap, i) { return i; } }
    for i in start..start + count {
        let byte = (i / 8) as usize;
        if let Some(b) = bitmap.get_mut(byte) { *b &= !(1 << (i % 8)); undo.push(i); }
    }
    black_box(&undo);
    u32::MAX
}
// NEW: word-scan validate (first free = double-free) + range clear.
fn find_free(bitmap: &[u8], start: u32, end: u32) -> Option<u32> {
    let mut idx = start;
    while end.saturating_sub(idx) >= 64 {
        let b = (idx / 8) as usize;
        let w = u64::from_le_bytes(bitmap[b..b + 8].try_into().unwrap());
        if w != u64::MAX { return Some(idx + (!w).trailing_zeros()); }
        idx += 64;
    }
    while idx < end { if !get_bit(bitmap, idx) { return Some(idx); } idx += 1; }
    None
}
fn new_free(bitmap: &mut [u8], start: u32, count: u32) -> u32 {
    let end = start + count;
    if let Some(bad) = find_free(bitmap, start, end) { return bad; }
    // range clear
    let mut idx = start;
    while idx < end && idx % 8 != 0 { let b=(idx/8) as usize; bitmap[b] &= !(1<<(idx%8)); idx+=1; }
    let bs = (idx/8) as usize; let fe = end - (end%8); let be = ((fe/8) as usize).min(bitmap.len());
    if be > bs { bitmap[bs..be].fill(0); idx = (be as u32)*8; }
    while idx < end { let b=(idx/8) as usize; bitmap[b] &= !(1<<(idx%8)); idx+=1; }
    u32::MAX
}
fn bench(c: &mut Criterion) {
    for count in [256u32, 4096] {
        let bytes = 8192usize; let start = 40u32;
        let template = vec![0xFFu8; bytes]; // all allocated (valid free)
        let mut oa = template.clone(); let mut nb = template.clone();
        assert_eq!(old_free(&mut oa, start, count), new_free(&mut nb, start, count));
        assert_eq!(oa, nb, "count={count}");
        let mut g = c.benchmark_group(format!("free_range_c{count}"));
        g.bench_function("old_bitloop_undo", |b| b.iter_batched(|| template.clone(), |mut bm| black_box(old_free(&mut bm, start, count)), BatchSize::SmallInput));
        g.bench_function("new_range", |b| b.iter_batched(|| template.clone(), |mut bm| black_box(new_free(&mut bm, start, count)), BatchSize::SmallInput));
        g.finish();
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
