#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_alloc::{FsGeometry, GroupStats};
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_ondisk::{self, Ext4CompatFeatures, Ext4IncompatFeatures, Ext4Inode, Ext4RoCompatFeatures};
use ffs_types::{BlockNumber, ByteOffset, EXT4_EXTENTS_FL, GroupNumber, InodeNumber};
use parking_lot::Mutex;
use proptest::prelude::*;

const INODE_CHECKSUM_LO_OFFSET: usize = 0x7C;
const INODE_CHECKSUM_HI_OFFSET: usize = 0x82;

#[derive(Debug)]
struct MemByteDevice {
    bytes: Mutex<Vec<u8>>,
}

impl MemByteDevice {
    fn new(size: usize) -> Self {
        Self {
            bytes: Mutex::new(vec![0_u8; size]),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> FfsResult<()> {
        let off = usize::try_from(offset.0).map_err(|_| {
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offset does not fit usize",
            ))
        })?;
        let bytes = self.bytes.lock();
        if off + buf.len() > bytes.len() {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read past end",
            )));
        }
        buf.copy_from_slice(&bytes[off..off + buf.len()]);
        drop(bytes);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> FfsResult<()> {
        let off = usize::try_from(offset.0).map_err(|_| {
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offset does not fit usize",
            ))
        })?;
        let mut bytes = self.bytes.lock();
        if off + buf.len() > bytes.len() {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "write past end",
            )));
        }
        bytes[off..off + buf.len()].copy_from_slice(buf);
        drop(bytes);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

fn mem_block_device(block_size: u32, block_count: usize) -> ByteBlockDevice<MemByteDevice> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    ByteBlockDevice::new(mem, block_size).expect("valid in-memory device")
}

fn representative_geometry() -> FsGeometry {
    FsGeometry {
        blocks_per_group: 128,
        inodes_per_group: 32,
        block_size: 4096,
        total_blocks: 128,
        total_inodes: 32,
        first_data_block: 0,
        group_count: 1,
        inode_size: 256,
        desc_size: 32,
        reserved_gdt_blocks: 0,
        feature_compat: Ext4CompatFeatures(0),
        feature_incompat: Ext4IncompatFeatures(0),
        feature_ro_compat: Ext4RoCompatFeatures(0),
        log_groups_per_flex: 0,
        backup_bgs: [0, 0],
        first_inode: 11,
        cluster_ratio: 1,
    }
}

fn representative_groups() -> Vec<GroupStats> {
    vec![GroupStats {
        group: GroupNumber(0),
        free_blocks: 0,
        free_inodes: 0,
        used_dirs: 0,
        block_bitmap_block: BlockNumber(0),
        inode_bitmap_block: BlockNumber(0),
        inode_table_block: BlockNumber(1),
        flags: 0,
        block_bitmap_csum: 0,
        inode_bitmap_csum: 0,
    }]
}

fn representative_inode(generation: u32) -> Ext4Inode {
    Ext4Inode {
        mode: 0o100_644,
        uid: 1000,
        gid: 1000,
        size: 4096,
        links_count: 1,
        blocks: 8,
        flags: EXT4_EXTENTS_FL,
        version: 0,
        generation,
        file_acl: 0,
        atime: 1_700_000_000,
        ctime: 1_700_000_000,
        mtime: 1_700_000_000,
        dtime: 0,
        atime_extra: 0,
        ctime_extra: 0,
        mtime_extra: 0,
        crtime: 1_700_000_000,
        crtime_extra: 0,
        extra_isize: 32,
        checksum: 0,
        version_hi: 0,
        projid: 0,
        extent_bytes: vec![0_u8; 60],
        xattr_ibody: Vec::new(),
    }
}

fn restamp_inode_checksum(raw: &mut [u8], csum_seed: u32, ino: u32) {
    let ino_seed = ffs_ondisk::ext4_chksum(csum_seed, &ino.to_le_bytes());
    let generation = u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]);
    let ino_seed = ffs_ondisk::ext4_chksum(ino_seed, &generation.to_le_bytes());

    raw[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2].fill(0);
    raw[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2].fill(0);

    let checksum = ffs_ondisk::ext4_chksum(ino_seed, raw);
    let lo = u16::try_from(checksum & u32::from(u16::MAX)).expect("masked to 16 bits");
    let hi = u16::try_from((checksum >> 16) & u32::from(u16::MAX)).expect("masked to 16 bits");
    raw[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2].copy_from_slice(&lo.to_le_bytes());
    raw[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2].copy_from_slice(&hi.to_le_bytes());
}

fn read_raw_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &[GroupStats],
    ino: InodeNumber,
) -> FfsResult<Vec<u8>> {
    let loc = ffs_inode::locate_inode(ino, geo, groups).expect("test inode should be locatable");
    let block = dev.read_block(cx, loc.block)?;
    Ok(block.as_slice()[loc.byte_offset..loc.byte_offset + usize::from(geo.inode_size)].to_vec())
}

proptest! {
    #[test]
    fn inode_checksum_field_content_invariance(
        csum_seed in any::<u32>(),
        ino_raw in 1_u32..33,
        generation in any::<u32>(),
        checksum_lo_garbage in any::<u16>(),
        checksum_hi_garbage in any::<u16>(),
    ) {
        let cx = Cx::for_testing();
        let geo = representative_geometry();
        let groups = representative_groups();
        let dev = mem_block_device(geo.block_size, 8);
        let inode = representative_inode(generation);
        let ino = InodeNumber(u64::from(ino_raw));

        ffs_inode::write_inode(&cx, &dev, &geo, &groups, ino, &inode, csum_seed)
            .expect("representative inode write should succeed");
        let stamped = read_raw_inode(&cx, &dev, &geo, &groups, ino)
            .expect("raw inode should be readable after write");

        prop_assert!(
            ffs_ondisk::verify_inode_checksum(&stamped, csum_seed, ino_raw, geo.inode_size).is_ok(),
            "freshly written inode checksum must verify"
        );

        let mut restamped_from_dirty = stamped.clone();
        restamped_from_dirty[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2]
            .copy_from_slice(&checksum_lo_garbage.to_le_bytes());
        restamped_from_dirty[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2]
            .copy_from_slice(&checksum_hi_garbage.to_le_bytes());
        restamp_inode_checksum(&mut restamped_from_dirty, csum_seed, ino_raw);

        prop_assert_eq!(
            &restamped_from_dirty,
            &stamped,
            "restamping must ignore prior checksum-field bytes"
        );
        prop_assert!(
            ffs_ondisk::verify_inode_checksum(
                &restamped_from_dirty,
                csum_seed,
                ino_raw,
                geo.inode_size,
            ).is_ok(),
            "restamped inode checksum must still verify"
        );
    }
}
