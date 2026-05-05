#![no_main]
use ffs_ondisk::{Ext4GroupDesc, Ext4Inode, Ext4Superblock};
use ffs_types::{
    ext4_block_size_from_log, EXT4_EXTENTS_FL, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    EXT4_SUPER_MAGIC, S_IFDIR, S_IFMT, S_IFREG,
};
use libfuzzer_sys::fuzz_target;

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn raw_u16(data: &[u8], offset: usize) -> u16 {
    le_u16(data, offset).unwrap_or(0)
}

fn raw_u32(data: &[u8], offset: usize) -> u32 {
    le_u32(data, offset).unwrap_or(0)
}

fn assert_superblock_invariants(data: &[u8]) {
    let parsed = Ext4Superblock::parse_superblock_region(data);
    assert_eq!(
        parsed,
        Ext4Superblock::parse_superblock_region(data),
        "ext4 superblock region parsing must be deterministic"
    );

    let image_end = EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE;
    if data.len() >= image_end {
        let from_image = Ext4Superblock::parse_from_image(data);
        assert_eq!(
            from_image,
            Ext4Superblock::parse_from_image(data),
            "ext4 full-image superblock parsing must be deterministic"
        );
        assert_eq!(
            from_image,
            Ext4Superblock::parse_superblock_region(&data[EXT4_SUPERBLOCK_OFFSET..image_end]),
            "full-image parser must read the region at offset 1024"
        );
    }

    let Ok(superblock) = parsed else {
        return;
    };

    assert_eq!(superblock.magic, EXT4_SUPER_MAGIC);
    assert_eq!(le_u32(data, 0x00), Some(superblock.inodes_count));
    assert_eq!(le_u32(data, 0x14), Some(superblock.first_data_block));
    assert_eq!(le_u32(data, 0x20), Some(superblock.blocks_per_group));
    assert_eq!(le_u32(data, 0x24), Some(superblock.clusters_per_group));
    assert_eq!(le_u32(data, 0x28), Some(superblock.inodes_per_group));
    assert_eq!(le_u16(data, 0x58), Some(superblock.inode_size));
    assert!(matches!(superblock.block_size, 1024 | 2048 | 4096));
    assert!(superblock.block_size.is_power_of_two());
    assert!(superblock.cluster_size.is_power_of_two());
    assert_eq!(
        ext4_block_size_from_log(raw_u32(data, 0x18)),
        Some(superblock.block_size)
    );
    assert_eq!(
        ext4_block_size_from_log(superblock.log_cluster_size),
        Some(superblock.cluster_size)
    );
}

fn assert_group_desc_invariants(data: &[u8], desc_size: u16) {
    let parsed = Ext4GroupDesc::parse_from_bytes(data, desc_size);
    assert_eq!(
        parsed,
        Ext4GroupDesc::parse_from_bytes(data, desc_size),
        "{desc_size}-byte ext4 group descriptor parsing must be deterministic"
    );

    let Ok(desc) = parsed else {
        return;
    };

    let block_bitmap_lo = u64::from(raw_u32(data, 0x00));
    let inode_bitmap_lo = u64::from(raw_u32(data, 0x04));
    let inode_table_lo = u64::from(raw_u32(data, 0x08));
    let free_blocks_lo = u32::from(raw_u16(data, 0x0C));
    let free_inodes_lo = u32::from(raw_u16(data, 0x0E));
    let used_dirs_lo = u32::from(raw_u16(data, 0x10));
    let itable_unused_lo = u32::from(raw_u16(data, 0x1C));
    let block_bitmap_csum_lo = u32::from(raw_u16(data, 0x18));
    let inode_bitmap_csum_lo = u32::from(raw_u16(data, 0x1A));

    assert_eq!(desc.flags, raw_u16(data, 0x12));
    assert_eq!(desc.checksum, raw_u16(data, 0x1E));

    if desc_size >= 64 {
        assert_eq!(
            desc.block_bitmap,
            block_bitmap_lo | (u64::from(raw_u32(data, 0x20)) << 32)
        );
        assert_eq!(
            desc.inode_bitmap,
            inode_bitmap_lo | (u64::from(raw_u32(data, 0x24)) << 32)
        );
        assert_eq!(
            desc.inode_table,
            inode_table_lo | (u64::from(raw_u32(data, 0x28)) << 32)
        );
        assert_eq!(
            desc.free_blocks_count,
            free_blocks_lo | (u32::from(raw_u16(data, 0x2C)) << 16)
        );
        assert_eq!(
            desc.free_inodes_count,
            free_inodes_lo | (u32::from(raw_u16(data, 0x2E)) << 16)
        );
        assert_eq!(
            desc.used_dirs_count,
            used_dirs_lo | (u32::from(raw_u16(data, 0x30)) << 16)
        );
        assert_eq!(
            desc.itable_unused,
            itable_unused_lo | (u32::from(raw_u16(data, 0x32)) << 16)
        );
        assert_eq!(
            desc.block_bitmap_csum,
            block_bitmap_csum_lo | (u32::from(raw_u16(data, 0x38)) << 16)
        );
        assert_eq!(
            desc.inode_bitmap_csum,
            inode_bitmap_csum_lo | (u32::from(raw_u16(data, 0x3A)) << 16)
        );
    } else {
        assert_eq!(desc.block_bitmap, block_bitmap_lo);
        assert_eq!(desc.inode_bitmap, inode_bitmap_lo);
        assert_eq!(desc.inode_table, inode_table_lo);
        assert_eq!(desc.free_blocks_count, free_blocks_lo);
        assert_eq!(desc.free_inodes_count, free_inodes_lo);
        assert_eq!(desc.used_dirs_count, used_dirs_lo);
        assert_eq!(desc.itable_unused, itable_unused_lo);
        assert_eq!(desc.block_bitmap_csum, block_bitmap_csum_lo);
        assert_eq!(desc.inode_bitmap_csum, inode_bitmap_csum_lo);
    }
}

fn assert_inode_invariants(data: &[u8]) {
    let parsed = Ext4Inode::parse_from_bytes(data);
    assert_eq!(
        parsed,
        Ext4Inode::parse_from_bytes(data),
        "ext4 inode parsing must be deterministic"
    );

    let Ok(inode) = parsed else {
        return;
    };

    let mode = raw_u16(data, 0x00);
    let uid = u32::from(raw_u16(data, 0x02)) | (u32::from(raw_u16(data, 0x78)) << 16);
    let gid = u32::from(raw_u16(data, 0x18)) | (u32::from(raw_u16(data, 0x7A)) << 16);
    let size_hi = if matches!(mode & S_IFMT, S_IFREG | S_IFDIR) {
        u64::from(raw_u32(data, 0x6C))
    } else {
        0
    };
    let file_acl = u64::from(raw_u32(data, 0x68)) | (u64::from(raw_u16(data, 0x76)) << 32);

    assert_eq!(inode.mode, mode);
    assert_eq!(inode.uid, uid);
    assert_eq!(inode.gid, gid);
    assert_eq!(inode.size, u64::from(raw_u32(data, 0x04)) | (size_hi << 32));
    assert_eq!(inode.links_count, raw_u16(data, 0x1A));
    assert_eq!(
        inode.blocks,
        u64::from(raw_u32(data, 0x1C)) | (u64::from(raw_u16(data, 0x74)) << 32)
    );
    assert_eq!(inode.flags, raw_u32(data, 0x20));
    assert_eq!(inode.version, raw_u32(data, 0x24));
    assert_eq!(inode.generation, raw_u32(data, 0x64));
    assert_eq!(inode.file_acl, file_acl);
    assert_eq!(inode.file_type_mode(), mode & S_IFMT);
    assert_eq!(inode.is_regular(), (mode & S_IFMT) == S_IFREG);
    assert_eq!(inode.is_dir(), (mode & S_IFMT) == S_IFDIR);
    assert_eq!(inode.uses_extents(), (inode.flags & EXT4_EXTENTS_FL) != 0);
    assert_eq!(inode.extent_bytes.len(), 60);
    assert_eq!(inode.extent_bytes.as_slice(), &data[0x28..0x28 + 60]);

    let expected_extra_isize = if data.len() >= 0x82 {
        raw_u16(data, 0x80)
    } else {
        0
    };
    assert_eq!(inode.extra_isize, expected_extra_isize);
    if inode.extra_isize == 0 {
        assert!(inode.xattr_ibody.is_empty());
    } else {
        let xattr_start = 128 + usize::from(inode.extra_isize);
        if xattr_start < data.len() {
            assert_eq!(inode.xattr_ibody.as_slice(), &data[xattr_start..]);
        } else {
            assert!(inode.xattr_ibody.is_empty());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    assert_superblock_invariants(data);
    assert_group_desc_invariants(data, 32);
    assert_group_desc_invariants(data, 64);

    assert_inode_invariants(data);
});
