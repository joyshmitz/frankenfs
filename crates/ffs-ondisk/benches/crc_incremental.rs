#![forbid(unsafe_code)]
//! Incremental crc32c update vs full recompute for a bitmap change.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench crc_incremental
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use ffs_ondisk::crc_incremental::crc32c_update_region;
fn bench(c: &mut Criterion) {
    let mut bitmap = vec![0xA5u8; 4096];
    let old_crc = crc32c::crc32c(&bitmap);
    // simulate a small contiguous alloc: set 8 bytes (64 blocks) at offset 3000.
    let start = 3000usize;
    let new_bytes = [0xFFu8; 8];
    let delta: Vec<u8> = new_bytes.iter().zip(&bitmap[start..start+8]).map(|(n,o)| n^o).collect();
    let suffix = bitmap.len() - start - 8;
    // equivalence check
    let mut after = bitmap.clone(); after[start..start+8].copy_from_slice(&new_bytes);
    assert_eq!(crc32c_update_region(old_crc, &delta, suffix), crc32c::crc32c(&after));
    bitmap[start..start+8].copy_from_slice(&new_bytes); // reflect the change for the full-recompute arm
    let mut g = c.benchmark_group("crc_bitmap_update");
    g.bench_function("full_recompute", |b| b.iter(|| black_box(crc32c::crc32c(black_box(&bitmap)))));
    g.bench_function("incremental", |b| b.iter(|| black_box(crc32c_update_region(black_box(old_crc), black_box(&delta), black_box(suffix)))));
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
