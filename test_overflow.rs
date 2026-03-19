use asupersync::Cx;
use ffs_alloc::{AllocHint, FsGeometry, GroupStats};
use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::Result;
use ffs_extent::{allocate_extent, punch_hole};
use ffs_types::BlockNumber;
use std::sync::atomic::AtomicU64;

#[derive(Debug)]
struct MemBlockDevice {
    block_size: u32,
}
impl MemBlockDevice {
    fn new(block_size: u32) -> Self { Self { block_size } }
}
impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, _block: BlockNumber) -> Result<BlockBuf> { Ok(BlockBuf::new(self.block_size)) }
    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> { Ok(()) }
    fn block_size(&self) -> u32 { self.block_size }
    fn block_count(&self) -> u64 { 1000 }
    fn sync(&self, _cx: &Cx) -> Result<()> { Ok(()) }
}

fn test_punch_hole_overflow() {
    let cx = Cx::for_testing();
    let dev = MemBlockDevice::new(4096);
    let geo = FsGeometry {
        blocks_per_group: 1000,
        inodes_per_group: 1000,
        inode_size: 256,
        desc_size: 64,
        block_size: 4096,
        first_data_block: BlockNumber(0),
        group_count: 1,
    };
    let mut groups = vec![GroupStats::default()];
    let mut root_bytes = [0u8; 60];
    root_bytes[0..12].copy_from_slice(&[0x0a, 0xf3, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]); // magic, 0 entries, 4 max
    let pctx = ffs_alloc::PersistCtx::mock();

    for i in 0..4 {
        allocate_extent(&cx, &dev, &mut root_bytes, &geo, &mut groups, i * 10, 5, &AllocHint::default(), &pctx).unwrap();
    }
    // Now root has 4 entries.
    // Punch hole in the middle of the first one: [2..3]
    println!("Punching hole in the middle of a full node...");
    punch_hole(&cx, &dev, &mut root_bytes, &geo, &mut groups, 2, 1, &pctx).unwrap();
    println!("Punch hole succeeded!");
}

fn main() {
    test_punch_hole_overflow();
}
