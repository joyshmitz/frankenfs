use ffs_ext4::{
    Ext4GroupDesc, Ext4GroupDescChecksumKind, Ext4IncompatFeatures, Ext4RoCompatFeatures,
    Ext4Superblock, ext4_chksum, stamp_group_desc_checksum, verify_group_desc_checksum,
};

const TEST_UUID: [u8; 16] = [1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16];
const TEST_GROUP: u32 = 17;

fn sample_group_desc(desc_size: u16) -> Vec<u8> {
    let gd = Ext4GroupDesc {
        block_bitmap: 0x0000_0001_0000_0100,
        inode_bitmap: 0x0000_0002_0000_0200,
        inode_table: 0x0000_0003_0000_0300,
        free_blocks_count: 0x0001_0040,
        free_inodes_count: 0x0002_0020,
        used_dirs_count: 0x0003_0003,
        itable_unused: 0x0004_0010,
        flags: 0x0005,
        checksum: 0,
        block_bitmap_csum: 0xAAAA_1357,
        inode_bitmap_csum: 0xBBBB_2468,
    };

    let mut buf = vec![0_u8; usize::from(desc_size)];
    gd.write_to_bytes(&mut buf, desc_size)
        .expect("group descriptor write");
    buf
}

fn sample_superblock_region(
    ro_compat: Ext4RoCompatFeatures,
    incompat: Ext4IncompatFeatures,
) -> [u8; 1024] {
    let mut sb = [0_u8; 1024];
    sb[0x38..0x3A].copy_from_slice(&0xEF53_u16.to_le_bytes());
    sb[0x4C..0x50].copy_from_slice(&1_u32.to_le_bytes());
    sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes());
    sb[0x20..0x24].copy_from_slice(&8192_u32.to_le_bytes());
    sb[0x24..0x28].copy_from_slice(&8192_u32.to_le_bytes());
    sb[0x28..0x2C].copy_from_slice(&2048_u32.to_le_bytes());
    sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes());
    sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
    sb[0x60..0x64].copy_from_slice(&incompat.0.to_le_bytes());
    sb[0x64..0x68].copy_from_slice(&ro_compat.0.to_le_bytes());
    sb[0x68..0x78].copy_from_slice(&TEST_UUID);
    sb[0xFE..0x100].copy_from_slice(&64_u16.to_le_bytes());
    sb
}

#[test]
fn group_desc_csum_v2_and_v3_use_distinct_checksums_on_same_descriptor() {
    let mut legacy = sample_group_desc(64);
    let mut metadata = sample_group_desc(64);
    let metadata_seed = ext4_chksum(!0u32, &TEST_UUID);

    stamp_group_desc_checksum(
        &mut legacy,
        &TEST_UUID,
        metadata_seed,
        TEST_GROUP,
        64,
        Ext4GroupDescChecksumKind::GdtCsum,
    );
    stamp_group_desc_checksum(
        &mut metadata,
        &TEST_UUID,
        metadata_seed,
        TEST_GROUP,
        64,
        Ext4GroupDescChecksumKind::MetadataCsum,
    );

    let legacy_stored = u16::from_le_bytes([legacy[0x1E], legacy[0x1F]]);
    let metadata_stored = u16::from_le_bytes([metadata[0x1E], metadata[0x1F]]);
    assert_ne!(
        legacy_stored, metadata_stored,
        "legacy gdt_csum and metadata_csum must not collapse to the same checksum on the same 64-byte descriptor"
    );

    verify_group_desc_checksum(
        &legacy,
        &TEST_UUID,
        metadata_seed,
        TEST_GROUP,
        64,
        Ext4GroupDescChecksumKind::GdtCsum,
    )
    .expect("legacy checksum verifies");
    verify_group_desc_checksum(
        &metadata,
        &TEST_UUID,
        metadata_seed,
        TEST_GROUP,
        64,
        Ext4GroupDescChecksumKind::MetadataCsum,
    )
    .expect("metadata checksum verifies");

    assert!(
        verify_group_desc_checksum(
            &legacy,
            &TEST_UUID,
            metadata_seed,
            TEST_GROUP,
            64,
            Ext4GroupDescChecksumKind::MetadataCsum,
        )
        .is_err(),
        "legacy crc16-stamped descriptor must be rejected by metadata_csum verification"
    );
    assert!(
        verify_group_desc_checksum(
            &metadata,
            &TEST_UUID,
            metadata_seed,
            TEST_GROUP,
            64,
            Ext4GroupDescChecksumKind::GdtCsum,
        )
        .is_err(),
        "metadata crc32c-stamped descriptor must be rejected by legacy gdt_csum verification"
    );
}

#[test]
fn group_desc_csum_kind_prefers_metadata_csum_even_with_meta_bg() {
    let sb = Ext4Superblock::parse_superblock_region(&sample_superblock_region(
        Ext4RoCompatFeatures(
            Ext4RoCompatFeatures::GDT_CSUM.0 | Ext4RoCompatFeatures::METADATA_CSUM.0,
        ),
        Ext4IncompatFeatures::META_BG,
    ))
    .expect("superblock parse");

    assert_eq!(
        sb.group_desc_checksum_kind(),
        Ext4GroupDescChecksumKind::MetadataCsum
    );
}

#[test]
fn group_desc_csum_kind_keeps_legacy_crc16_with_meta_bg_only() {
    let sb = Ext4Superblock::parse_superblock_region(&sample_superblock_region(
        Ext4RoCompatFeatures::GDT_CSUM,
        Ext4IncompatFeatures::META_BG,
    ))
    .expect("superblock parse");

    assert_eq!(
        sb.group_desc_checksum_kind(),
        Ext4GroupDescChecksumKind::GdtCsum
    );
}
