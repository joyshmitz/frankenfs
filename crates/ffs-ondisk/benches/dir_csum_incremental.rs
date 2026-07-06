#![forbid(unsafe_code)]
//! Incremental dir-block csum update vs full recompute (per create/unlink).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench dir_csum_incremental
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use ffs_ondisk::ext4::{stamp_dir_block_checksum, stamp_dir_block_checksum_incremental};
fn bench(c: &mut Criterion) {
    let bs = 4096usize;
    let seed = 0xDEAD_BEEFu32; let ino = 42u32; let generation = 7u32;
    let mut base = vec![0xA5u8; bs];
    stamp_dir_block_checksum(&mut base, seed, ino, generation);
    // a ~28-byte entry insert region near the middle (apply the change to the content)
    let start = 2000usize; let delta = vec![0x5Au8; 28];
    let mut changed = base.clone();
    for (i,d) in delta.iter().enumerate() { changed[start+i] ^= d; }
    // equivalence check (incremental on the changed block carrying base's old tail)
    let mut inc0 = changed.clone(); inc0[bs-4..bs].copy_from_slice(&base[bs-4..bs]);
    let mut full0 = changed.clone();
    assert!(stamp_dir_block_checksum_incremental(&mut inc0, start, &delta));
    stamp_dir_block_checksum(&mut full0, seed, ino, generation);
    assert_eq!(&inc0[bs-4..], &full0[bs-4..]);

    // separate blocks per arm; no per-iter clone.
    let mut block_full = changed.clone();
    let mut block_inc = changed.clone();
    let old_tail = [base[bs-4], base[bs-3], base[bs-2], base[bs-1]];
    let mut g = c.benchmark_group("dir_csum");
    g.bench_function("full_recompute", |b| b.iter(|| { stamp_dir_block_checksum(black_box(&mut block_full), black_box(seed), black_box(ino), black_box(generation)); black_box(block_full[bs-1]) }));
    g.bench_function("incremental", |b| b.iter(|| { block_inc[bs-4..bs].copy_from_slice(&old_tail); black_box(stamp_dir_block_checksum_incremental(black_box(&mut block_inc), black_box(start), black_box(&delta))) }));
    g.finish();

    // Fresh dir block: a short entry prefix (. and ..) then a large zero gap —
    // the mkdir / new-leaf / large-slack full-stamp case. The zero-aware
    // crc_dir_coverage inside stamp_dir_block_checksum skips the ~4 KiB zero tail
    // via the algebraic shift, vs the ORIG straight ext4_chksum over the whole
    // coverage region.
    let cov = bs - 12;
    let mut fresh = vec![0u8; bs];
    for (i, byte) in fresh.iter_mut().take(24).enumerate() {
        *byte = (i as u8).wrapping_add(1);
    }
    let mut gf = c.benchmark_group("dir_csum_fresh");
    gf.bench_function("full_recompute", |b| {
        b.iter(|| {
            let s = ffs_ondisk::ext4::ext4_chksum(
                ffs_ondisk::ext4::ext4_chksum(black_box(seed), &ino.to_le_bytes()),
                &generation.to_le_bytes(),
            );
            black_box(ffs_ondisk::ext4::ext4_chksum(s, black_box(&fresh[..cov])))
        })
    });
    gf.bench_function("zero_aware", |b| {
        b.iter(|| {
            stamp_dir_block_checksum(
                black_box(&mut fresh),
                black_box(seed),
                black_box(ino),
                black_box(generation),
            );
            black_box(fresh[bs - 1])
        })
    });
    gf.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
