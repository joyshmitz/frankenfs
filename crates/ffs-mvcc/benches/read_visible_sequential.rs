#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Realistic-workload read bench: a SEQUENTIAL scan over many distinct blocks,
//! each with a shallow version chain, read at the latest snapshot.
//!
//! The existing `read_visible` bench is the PATHOLOGICAL case (one block, a
//! 512-deep chain, read at an old snapshot). This is the COMMON case: a large
//! sequential read touches thousands of distinct blocks once each, at HEAD. It
//! exercises the integrated per-block read cost — the version-store lookup
//! (`newest_visible_index`) PLUS owned materialization of the resolved bytes.
//! The paired `read_visible_block_buf` arm covers the production block-device
//! read surface used by the sharded OpenFs store.

use asupersync::Cx;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ffs_block::{AlignedVec, BlockBuf, BlockDevice, DEFAULT_BLOCK_ALIGNMENT};
use ffs_error::{FfsError, Result};
use ffs_mvcc::{MvccBlockDevice, MvccStore, sharded::ShardedMvccStore};
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use parking_lot::RwLock;
use std::hint::black_box;
use std::sync::Arc;

const BLOCKS: u64 = 2_000;
const BLOCK_SIZE: usize = 4096;
const BLOCK_SIZE_U32: u32 = 4096;
const BLOCK_SIZE_U64: u64 = 4096;

fn build_store() -> (ShardedMvccStore, CommitSeq) {
    let store = ShardedMvccStore::new(8);
    let mut last = CommitSeq(0);
    for b in 0..BLOCKS {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(b), vec![(b & 0xff) as u8; BLOCK_SIZE]);
        last = store.commit(txn).expect("commit");
    }
    (store, last)
}

#[derive(Debug, Clone)]
struct SharedReadDevice {
    blocks: Vec<Arc<AlignedVec>>,
}

impl SharedReadDevice {
    fn new() -> Self {
        let blocks = (0..BLOCKS)
            .map(|block| {
                let byte = u8::try_from(block & 0xff).expect("masked to one byte");
                let bytes = vec![byte; BLOCK_SIZE];
                Arc::new(AlignedVec::from_vec(bytes, DEFAULT_BLOCK_ALIGNMENT))
            })
            .collect();
        Self { blocks }
    }
}

impl BlockDevice for SharedReadDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("block index does not fit usize".to_owned()))?;
        let Some(bytes) = self.blocks.get(idx) else {
            return Err(FfsError::Format(format!(
                "block {} out of range for device length {}",
                block.0,
                self.blocks.len()
            )));
        };
        Ok(BlockBuf::from_shared_aligned(Arc::clone(bytes)))
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::UnsupportedFeature(
            "SharedReadDevice is read-only".to_owned(),
        ))
    }

    fn block_size(&self) -> u32 {
        BLOCK_SIZE_U32
    }

    fn block_count(&self) -> u64 {
        u64::try_from(self.blocks.len()).expect("bench device length fits u64")
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn bench_sequential_scan(c: &mut Criterion) {
    let (store, latest) = build_store();
    let snap = Snapshot { high: latest };
    let first = store
        .read_visible(BlockNumber(0), snap)
        .expect("first block");
    let first_buf = store
        .read_visible_block_buf(BlockNumber(0), snap)
        .expect("first block buf");
    assert_eq!(first_buf.as_slice(), first.as_slice());
    assert!(store.read_visible(BlockNumber(BLOCKS - 1), snap).is_some());

    let mut group = c.benchmark_group("mvcc_read_visible_sequential");
    group.throughput(Throughput::Bytes(BLOCKS * BLOCK_SIZE as u64));
    group.bench_function("scan_2000_blocks", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                // The sharded read_visible resolves the visible version AND
                // materializes it into an owned Vec: the per-block lookup plus
                // block-sized copy that dominates overlay reads under churn.
                let data = store.read_visible(black_box(BlockNumber(blk)), snap);
                black_box(data);
            }
        });
    });
    group.bench_function("scan_2000_blocks_block_buf", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                let data = store.read_visible_block_buf(black_box(BlockNumber(blk)), snap);
                black_box(data);
            }
        });
    });
    group.finish();
}

fn bench_unregistered_device_read(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let direct = SharedReadDevice::new();
    let store = MvccStore::new();
    let snap = store.current_snapshot();
    let wrapped =
        MvccBlockDevice::new_unregistered(direct.clone(), Arc::new(RwLock::new(store)), snap);

    assert_eq!(
        direct
            .read_block(&cx, BlockNumber(17))
            .expect("direct read")
            .as_slice(),
        wrapped
            .read_block(&cx, BlockNumber(17))
            .expect("wrapped read")
            .as_slice(),
        "read-only unregistered wrapper must expose base-device bytes"
    );

    let mut group = c.benchmark_group("mvcc_read_only_base_fallback_2000");
    group.throughput(Throughput::Bytes(BLOCKS * BLOCK_SIZE_U64));

    group.bench_function("direct_base", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                let data = direct
                    .read_block(&cx, black_box(BlockNumber(blk)))
                    .expect("direct read");
                black_box(data);
            }
        });
    });

    group.bench_function("unregistered_mvcc", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                let data = wrapped
                    .read_block(&cx, black_box(BlockNumber(blk)))
                    .expect("wrapped read");
                black_box(data);
            }
        });
    });

    group.finish();
}

criterion_group!(
    read_visible_sequential,
    bench_sequential_scan,
    bench_unregistered_device_read
);
criterion_main!(read_visible_sequential);
