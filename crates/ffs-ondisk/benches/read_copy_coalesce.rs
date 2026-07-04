#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Throwaway A/B: does coalescing `read_inode_data`'s per-4KiB-block copies into
//! one bulk copy of a contiguous physical run matter? read_inode_data currently
//! does one `copy_from_slice(4 KiB)` per logical block (256 for a 1 MiB read of a
//! contiguous file); a run-coalesced reader would do one `copy_from_slice` of the
//! whole run. Both move the same bytes (bandwidth-bound), so this measures the
//! per-call + loop overhead difference on an in-memory image (the FS-side cost;
//! production adds kernel pread I/O that dominates and masks this).
//!
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig13 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench read_copy_coalesce

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const BS: usize = 4096;

fn per_block_copy(src: &[u8], dst: &mut [u8], nblocks: usize) {
    for i in 0..nblocks {
        let o = i * BS;
        // mirror read_inode_data: resolve (contiguous here) then copy one block.
        dst[o..o + BS].copy_from_slice(&src[o..o + BS]);
    }
}

fn coalesced_copy(src: &[u8], dst: &mut [u8], nblocks: usize) {
    let len = nblocks * BS;
    dst[..len].copy_from_slice(&src[..len]);
}

fn bench(c: &mut Criterion) {
    for nblocks in [32usize, 256] {
        let len = nblocks * BS;
        let src = vec![0xABu8; len];
        let mut dst = vec![0u8; len];
        let kib = len / 1024;
        let mut g = c.benchmark_group(format!("read_copy_{kib}kib"));
        g.bench_function("per_block", |b| {
            b.iter(|| per_block_copy(black_box(&src), black_box(&mut dst), black_box(nblocks)));
        });
        g.bench_function("coalesced", |b| {
            b.iter(|| coalesced_copy(black_box(&src), black_box(&mut dst), black_box(nblocks)));
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
