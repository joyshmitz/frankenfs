#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the extent-insert overlap check (bd-8mbyr).
//!
//! `ffs_btree::insert` validates that a new extent does not overlap any existing
//! one. The old check walked the WHOLE tree (O(N) per insert), so building an
//! N-extent tree was O(N²). Extents are sorted and non-overlapping, so only the
//! new extent's own logical range can hold a conflict; the fix uses `walk_range`
//! over that range (O(log N) per insert) → O(N log N) to build the tree.
//!
//! This benches building a fragmented N-extent file the way a sequential write
//! of a hole-punched / non-contiguous file does: insert N sorted, disjoint,
//! single-block extents into an initially empty inode extent-tree root.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_btree::{BlockAllocator, insert};
use ffs_error::Result;
use ffs_ondisk::Ext4Extent;
use ffs_types::BlockNumber;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Mutex;

/// In-memory block device (mirrors the ffs-btree test device).
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

/// Sequential block allocator for tree node blocks.
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

/// Build an empty depth-0 extent-tree root (12-byte ext4 extent header,
/// magic 0xF30A, max_entries 4, the inode i_block layout).
fn empty_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    root[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
    root[2..4].copy_from_slice(&0u16.to_le_bytes()); // entries
    root[4..6].copy_from_slice(&4u16.to_le_bytes()); // max_entries
    root[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth
    root[8..12].copy_from_slice(&0u32.to_le_bytes()); // generation
    root
}

/// Insert `n` disjoint single-block extents (logical 0,2,4,... so each is a
/// distinct non-overlapping run separated by a 1-block hole).
fn build_tree(n: u32) -> u64 {
    let dev = MemBlockDevice::new(4096);
    let cx = Cx::for_testing();
    let mut alloc = SeqAllocator { next: 1 };
    let mut root = empty_root();
    let mut ok = 0_u64;
    for i in 0..n {
        let ext = Ext4Extent {
            logical_block: i * 2,
            raw_len: 1,
            physical_start: u64::from(i) + 1_000_000,
        };
        if insert(&cx, &dev, &mut root, ext, &mut alloc).is_ok() {
            ok += 1;
        }
    }
    ok
}

fn bench_extent_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("extent_insert_overlap_validate");
    for &n in &[512_u32, 2000] {
        assert_eq!(build_tree(n), u64::from(n), "all inserts must succeed");
        group.bench_function(format!("build_{n}_extents"), |b| {
            b.iter(|| black_box(build_tree(black_box(n))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_extent_insert);
criterion_main!(benches);
