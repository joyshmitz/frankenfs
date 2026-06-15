#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for the extent-insert overlap check (bd-8mbyr).
//!
//! `ffs_btree::insert` validates a new extent against existing ones. The old
//! check used `walk` over the WHOLE tree (O(N) per insert), so building an
//! N-extent tree was O(N²). Extents are sorted and non-overlapping, so only the
//! new extent's own logical range can hold a conflict; the fix uses `walk_range`
//! over that range (O(log N) per insert).
//!
//! Both strategies are benched in ONE process against the same built tree using
//! the public `walk` / `walk_range` (so the comparison is on one rch worker — no
//! cross-worker skew). The visitor is the exact overlap predicate the production
//! validator runs. The validated extent sits just past the tree (logical 2N), so
//! `walk` scans all N extents while `walk_range` reads only the covering tail.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_btree::{BlockAllocator, insert, walk, walk_range};
use ffs_error::{FfsError, Result};
use ffs_ondisk::Ext4Extent;
use ffs_types::BlockNumber;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Mutex;

struct MemBlockDevice {
    block_size: u32,
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
}

impl MemBlockDevice {
    fn new(block_size: u32) -> Self {
        Self {
            block_size,
            blocks: Mutex::new(HashMap::new()),
        }
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let blocks = self.blocks.lock().unwrap();
        blocks.get(&block.0).map_or_else(
            || Ok(BlockBuf::new(vec![0u8; self.block_size as usize])),
            |data| Ok(BlockBuf::new(data.clone())),
        )
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.blocks.lock().unwrap().insert(block.0, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        100_000_000
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

struct SeqAllocator {
    next: u64,
}

impl BlockAllocator for SeqAllocator {
    fn alloc_block(&mut self, _cx: &Cx) -> Result<BlockNumber> {
        let bn = BlockNumber(self.next);
        self.next += 1;
        Ok(bn)
    }

    fn free_block(&mut self, _cx: &Cx, _block: BlockNumber) -> Result<()> {
        Ok(())
    }
}

fn empty_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    root[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
    root[2..4].copy_from_slice(&0u16.to_le_bytes()); // entries
    root[4..6].copy_from_slice(&4u16.to_le_bytes()); // max_entries
    root[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth
    root[8..12].copy_from_slice(&0u32.to_le_bytes()); // generation
    root
}

fn extent_range(e: &Ext4Extent) -> (u64, u64) {
    let start = u64::from(e.logical_block);
    let len = u64::from(e.raw_len); // benched extents are written (raw_len == len)
    (start, start + len)
}

/// Build an N-extent tree (disjoint single-block extents at logical 0,2,4,...).
fn build_tree(n: u32) -> (MemBlockDevice, [u8; 60]) {
    let dev = MemBlockDevice::new(4096);
    let cx = Cx::for_testing();
    let mut alloc = SeqAllocator { next: 1 };
    let mut root = empty_root();
    for i in 0..n {
        let ext = Ext4Extent {
            logical_block: i * 2,
            raw_len: 1,
            physical_start: u64::from(i) + 1_000_000,
        };
        insert(&cx, &dev, &mut root, ext, &mut alloc).expect("insert");
    }
    (dev, root)
}

/// OLD overlap check: full-tree walk.
fn validate_walk(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    probe: &Ext4Extent,
) -> Result<()> {
    let (ns, ne) = extent_range(probe);
    walk(cx, dev, root, &mut |e| {
        let (es, ee) = extent_range(e);
        if ns < ee && ne > es {
            return Err(FfsError::InvalidGeometry("overlap".into()));
        }
        Ok(())
    })?;
    Ok(())
}

/// NEW overlap check: walk_range over the probe's logical range.
fn validate_walk_range(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    probe: &Ext4Extent,
) -> Result<()> {
    let (ns, ne) = extent_range(probe);
    let count = ne.min(1_u64 << 32).saturating_sub(ns);
    walk_range(cx, dev, root, probe.logical_block, count, &mut |e| {
        let (es, ee) = extent_range(e);
        if ns < ee && ne > es {
            return Err(FfsError::InvalidGeometry("overlap".into()));
        }
        Ok(())
    })?;
    Ok(())
}

fn bench_overlap_check(c: &mut Criterion) {
    let cx = Cx::for_testing();
    for &n in &[2000_u32, 8000] {
        let (dev, root) = build_tree(n);
        // Probe extent just past the tree (no real overlap): `walk` still scans
        // all N extents; `walk_range` reads only the covering tail.
        let probe = Ext4Extent {
            logical_block: n * 2,
            raw_len: 1,
            physical_start: 9_000_000,
        };
        // Sanity: both agree (no overlap).
        assert!(validate_walk(&cx, &dev, &root, &probe).is_ok());
        assert!(validate_walk_range(&cx, &dev, &root, &probe).is_ok());

        let mut group = c.benchmark_group(format!("extent_overlap_check_{n}"));
        group.bench_function("walk_full_tree", |b| {
            b.iter(|| {
                black_box(validate_walk(
                    &cx,
                    &dev,
                    black_box(&root),
                    black_box(&probe),
                ))
            });
        });
        group.bench_function("walk_range", |b| {
            b.iter(|| {
                black_box(validate_walk_range(
                    &cx,
                    &dev,
                    black_box(&root),
                    black_box(&probe),
                ))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench_overlap_check);
criterion_main!(benches);
