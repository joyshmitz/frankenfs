use ffs_ext4::{
    EXT4_RESIZE_INO, Ext4CompatFeatures, Ext4IncompatFeatures, Ext4RoCompatFeatures,
    Ext4SuperFlags, Ext4Superblock,
};
use ffs_types::GroupNumber;

fn make_online_resize_superblock() -> Ext4Superblock {
    Ext4Superblock {
        inodes_count: 2048,
        blocks_count: 256,
        reserved_blocks_count: 0,
        free_blocks_count: 200,
        free_inodes_count: 1900,
        first_data_block: 0,
        block_size: 1024,
        log_cluster_size: 0,
        cluster_size: 1024,
        blocks_per_group: 16,
        clusters_per_group: 16,
        inodes_per_group: 128,
        inode_size: 256,
        first_ino: 11,
        desc_size: 64,
        reserved_gdt_blocks: 2,
        first_meta_bg: 2,
        magic: 0xEF53,
        uuid: [0; 16],
        volume_name: String::new(),
        last_mounted: String::new(),
        rev_level: 1,
        minor_rev_level: 0,
        creator_os: 0,
        feature_compat: Ext4CompatFeatures(Ext4CompatFeatures::RESIZE_INODE.0),
        feature_incompat: Ext4IncompatFeatures(
            Ext4IncompatFeatures::META_BG.0 | Ext4IncompatFeatures::BIT64.0,
        ),
        feature_ro_compat: Ext4RoCompatFeatures(Ext4RoCompatFeatures::SPARSE_SUPER.0),
        super_flags: Ext4SuperFlags(0),
        default_mount_opts: 0,
        state: 1,
        errors: 1,
        mnt_count: 0,
        max_mnt_count: 20,
        error_count: 0,
        mtime: 0,
        wtime: 0,
        lastcheck: 0,
        mkfs_time: 0,
        first_error_time: 0,
        last_error_time: 0,
        journal_inum: 8,
        journal_dev: 0,
        last_orphan: 0,
        journal_uuid: [0; 16],
        hash_seed: [0; 4],
        def_hash_version: 0,
        log_groups_per_flex: 0,
        mmp_update_interval: 0,
        mmp_block: 0,
        usr_quota_inum: 0,
        grp_quota_inum: 0,
        prj_quota_inum: 0,
        backup_bgs: [0; 2],
        checksum_type: 1,
        checksum_seed: 0,
        checksum: 0,
    }
}

#[test]
fn resize_inode_reserved_gdt_blocks_require_feature_and_stop_at_first_meta_bg() {
    let mut sb = make_online_resize_superblock();
    assert_eq!(sb.resize_inode_number(), Some(EXT4_RESIZE_INO));
    assert_eq!(sb.reserved_gdt_blocks_in_group(GroupNumber(1)), 2);
    assert_eq!(sb.reserved_gdt_blocks_in_group(GroupNumber(3)), 0);

    sb.feature_compat = Ext4CompatFeatures(0);
    assert_eq!(sb.resize_inode_number(), None);
    assert_eq!(sb.reserved_gdt_blocks_in_group(GroupNumber(1)), 0);
}

#[test]
fn group_add_plan_consumes_reserved_gdt_budget_before_overflowing() {
    let sb = make_online_resize_superblock();

    let within_reserved = sb.plan_group_add(20).expect("resize inode plan");
    assert_eq!(within_reserved.resize_inode, EXT4_RESIZE_INO);
    assert_eq!(within_reserved.old_groups, 16);
    assert_eq!(within_reserved.new_groups, 36);
    assert_eq!(within_reserved.old_group_desc_blocks, 1);
    assert_eq!(within_reserved.new_group_desc_blocks, 3);
    assert_eq!(within_reserved.added_group_desc_blocks_per_copy, 2);
    assert_eq!(within_reserved.reserved_gdt_blocks_consumed_per_copy, 2);
    assert_eq!(within_reserved.reserved_gdt_blocks_remaining_per_copy, 0);
    assert_eq!(
        within_reserved.descriptor_blocks_outside_reserved_window_per_copy,
        0
    );

    let overflow = sb.plan_group_add(33).expect("overflow resize inode plan");
    assert_eq!(overflow.new_groups, 49);
    assert_eq!(overflow.new_group_desc_blocks, 4);
    assert_eq!(overflow.added_group_desc_blocks_per_copy, 3);
    assert_eq!(overflow.reserved_gdt_blocks_consumed_per_copy, 2);
    assert_eq!(overflow.reserved_gdt_blocks_remaining_per_copy, 0);
    assert_eq!(
        overflow.descriptor_blocks_outside_reserved_window_per_copy,
        1
    );
}
