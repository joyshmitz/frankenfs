#![forbid(unsafe_code)]

//! Same-machine A/B for the default version-store compression policy (bd-i5gwr).
//!
//! `MvccStore::new()` (every production OpenFs store) used to default to
//! `algo: Zstd`, so `apply_fcw_commit` ran `zstd::encode_all` on every 4 KiB
//! block written through the MVCC store — ~29 µs/block of pure CPU on the commit
//! hot path, and a stored-`Full` no-op on incompressible data. Upstream
//! ext4/btrfs keep dirty data uncompressed in the page cache; the default is now
//! `algo: None` to match. Compression stays available via explicit policies.
//!
//! This benches a 1 MiB (256-block) contiguous write under both policies.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_mvcc::MvccStore;
use ffs_mvcc::compression::{CompressionAlgo, CompressionPolicy};
use ffs_types::BlockNumber;
use std::hint::black_box;

const N: u64 = 256; // a 1 MiB contiguous write at 4 KiB blocks
const BS: usize = 4096;

/// Incompressible block data so zstd does real work and still stores `Full`.
fn block_data() -> Vec<u8> {
    let mut v = vec![0_u8; BS];
    let mut x: u32 = 0x9e37_79b9;
    for b in &mut v {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    v
}

fn write_run(store: &mut MvccStore, data: &[u8]) {
    for i in 0..N {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(i), data.to_vec());
        store.commit(txn).expect("commit");
    }
}

fn bench_write_batch(c: &mut Criterion) {
    let data = block_data();
    let zstd = CompressionPolicy {
        dedup_identical: true,
        max_chain_length: Some(64),
        algo: CompressionAlgo::Zstd { level: 0 },
    };

    let mut group = c.benchmark_group("mvcc_contiguous_write_1mib");
    // Old default: zstd every block on commit.
    group.bench_function("default_zstd", |b| {
        b.iter(|| {
            let mut store = MvccStore::with_compression_policy(zstd.clone());
            write_run(&mut store, &data);
            black_box(&store);
        });
    });
    // New default (MvccStore::new()): no compression.
    group.bench_function("default_none", |b| {
        b.iter(|| {
            let mut store = MvccStore::new();
            write_run(&mut store, &data);
            black_box(&store);
        });
    });
    group.finish();
}

criterion_group!(write_batch, bench_write_batch);
criterion_main!(write_batch);
