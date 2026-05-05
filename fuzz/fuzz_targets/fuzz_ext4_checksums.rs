#![no_main]
use ffs_ondisk::ext4::{
    stamp_group_desc_checksum, verify_block_bitmap_free_count, verify_inode_bitmap_free_count,
};
use ffs_ondisk::{
    dx_hash, ext4_casefold_key, iter_dir_block, lookup_in_dir_block, lookup_in_dir_block_casefold,
    parse_dir_block, parse_ibody_xattrs, parse_inode_extent_tree, stamp_block_bitmap_checksum,
    stamp_dir_block_checksum, stamp_extent_block_checksum, stamp_inode_bitmap_checksum,
    verify_block_bitmap_checksum, verify_dir_block_checksum, verify_extent_block_checksum,
    verify_group_desc_checksum, verify_inode_bitmap_checksum, verify_inode_checksum, Ext4GroupDesc,
    Ext4Inode, Ext4Superblock, EXT4_FT_DIR_CSUM,
};
use libfuzzer_sys::fuzz_target;

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn raw_u32(data: &[u8], offset: usize) -> u32 {
    le_u32(data, offset).unwrap_or(0)
}

fn put_u8(data: &mut [u8], offset: usize, value: u8) -> bool {
    let Some(byte) = data.get_mut(offset) else {
        return false;
    };
    *byte = value;
    true
}

fn put_u16(data: &mut [u8], offset: usize, value: u16) -> bool {
    let Some(bytes) = data.get_mut(offset..offset.saturating_add(2)) else {
        return false;
    };
    bytes.copy_from_slice(&value.to_le_bytes());
    true
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) -> bool {
    let Some(bytes) = data.get_mut(offset..offset.saturating_add(4)) else {
        return false;
    };
    bytes.copy_from_slice(&value.to_le_bytes());
    true
}

fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    let copy_len = dst.len().min(src.len());
    let Some(dst_prefix) = dst.get_mut(..copy_len) else {
        return;
    };
    let Some(src_prefix) = src.get(..copy_len) else {
        return;
    };
    dst_prefix.copy_from_slice(src_prefix);
}

fn flip_byte(data: &mut [u8], offset: usize) -> bool {
    let Some(byte) = data.get_mut(offset) else {
        return false;
    };
    *byte ^= 1;
    true
}

fn expected_free_bits(raw_bitmap: &[u8], total_bits: u32) -> Option<u32> {
    let bytes_needed = usize::try_from(total_bits.div_ceil(8)).ok()?;
    if raw_bitmap.len() < bytes_needed {
        return None;
    }

    let full_bytes = usize::try_from(total_bits / 8).ok()?;
    let used_bits_full: u32 = raw_bitmap
        .get(..full_bytes)?
        .iter()
        .map(|byte| byte.count_ones())
        .sum();
    let rem_bits = total_bits % 8;
    let used_bits_rem = if rem_bits == 0 {
        0
    } else {
        let rem_bits_u8 = u8::try_from(rem_bits).ok()?;
        let mask = (1_u8 << rem_bits_u8) - 1;
        raw_bitmap
            .get(full_bytes)
            .map_or(0, |byte| (*byte & mask).count_ones())
    };

    Some(total_bits.saturating_sub(used_bits_full.saturating_add(used_bits_rem)))
}

fn assert_group_desc_and_bitmap_checksum_invariants(data: &[u8]) {
    let csum_seed = raw_u32(data, 0);
    let clusters_per_group = raw_u32(data, 4);
    let inodes_per_group = raw_u32(data, 8);

    for desc_size in [32u16, 64] {
        let parsed = Ext4GroupDesc::parse_from_bytes(data, desc_size);
        assert_eq!(
            parsed,
            Ext4GroupDesc::parse_from_bytes(data, desc_size),
            "{desc_size}-byte ext4 group descriptor parsing must be deterministic"
        );

        let block_value32 =
            ffs_ondisk::ext4::block_bitmap_checksum_value(data, csum_seed, clusters_per_group, 32);
        let block_value64 =
            ffs_ondisk::ext4::block_bitmap_checksum_value(data, csum_seed, clusters_per_group, 64);
        assert_eq!(block_value32, block_value64 & 0xFFFF);

        let inode_value32 =
            ffs_ondisk::ext4::inode_bitmap_checksum_value(data, csum_seed, inodes_per_group, 32);
        let inode_value64 =
            ffs_ondisk::ext4::inode_bitmap_checksum_value(data, csum_seed, inodes_per_group, 64);
        assert_eq!(inode_value32, inode_value64 & 0xFFFF);

        let Ok(mut desc) = parsed else {
            continue;
        };

        stamp_block_bitmap_checksum(data, csum_seed, clusters_per_group, &mut desc, desc_size);
        assert!(
            verify_block_bitmap_checksum(data, csum_seed, clusters_per_group, &desc, desc_size)
                .is_ok(),
            "stamped block bitmap checksum must verify"
        );

        stamp_inode_bitmap_checksum(data, csum_seed, inodes_per_group, &mut desc, desc_size);
        assert!(
            verify_inode_bitmap_checksum(data, csum_seed, inodes_per_group, &desc, desc_size)
                .is_ok(),
            "stamped inode bitmap checksum must verify"
        );
    }
}

fn assert_superblock_checksum_invariants(data: &[u8]) {
    let parsed = Ext4Superblock::parse_superblock_region(data);
    assert_eq!(
        parsed,
        Ext4Superblock::parse_superblock_region(data),
        "ext4 superblock checksum paths must see deterministic superblock parsing"
    );

    let Ok(sb) = parsed else {
        return;
    };

    let desc_size = sb.group_desc_size();
    let checksum_kind = sb.group_desc_checksum_kind();
    assert_eq!(
        verify_inode_checksum(data, sb.checksum_seed, 2, 256),
        verify_inode_checksum(data, sb.checksum_seed, 2, 256),
        "inode checksum verification must be deterministic"
    );
    assert_eq!(
        verify_dir_block_checksum(data, sb.checksum_seed, 2, 1),
        verify_dir_block_checksum(data, sb.checksum_seed, 2, 1),
        "directory block checksum verification must be deterministic"
    );
    assert_eq!(
        verify_extent_block_checksum(data, sb.checksum_seed, 11, 1),
        verify_extent_block_checksum(data, sb.checksum_seed, 11, 1),
        "extent block checksum verification must be deterministic"
    );
    assert_eq!(
        verify_group_desc_checksum(
            data,
            &sb.uuid,
            sb.checksum_seed,
            0,
            desc_size,
            checksum_kind,
        ),
        verify_group_desc_checksum(
            data,
            &sb.uuid,
            sb.checksum_seed,
            0,
            desc_size,
            checksum_kind,
        ),
        "group descriptor checksum verification must be deterministic"
    );

    if !(32..=4096).contains(&desc_size) {
        return;
    }
    let mut raw_desc = vec![0; usize::from(desc_size)];
    copy_prefix(&mut raw_desc, data);
    stamp_group_desc_checksum(
        &mut raw_desc,
        &sb.uuid,
        sb.checksum_seed,
        0,
        desc_size,
        checksum_kind,
    );
    assert!(
        verify_group_desc_checksum(
            &raw_desc,
            &sb.uuid,
            sb.checksum_seed,
            0,
            desc_size,
            checksum_kind,
        )
        .is_ok(),
        "stamped group descriptor checksum must verify"
    );
}

fn assert_inode_derivative_invariants(data: &[u8]) {
    let parsed = Ext4Inode::parse_from_bytes(data);
    assert_eq!(
        parsed,
        Ext4Inode::parse_from_bytes(data),
        "ext4 inode parsing must be deterministic"
    );

    let Ok(inode) = parsed else {
        return;
    };

    assert_eq!(
        parse_inode_extent_tree(&inode),
        parse_inode_extent_tree(&inode),
        "inode extent-tree parsing must be deterministic"
    );
    assert_eq!(
        parse_ibody_xattrs(&inode),
        parse_ibody_xattrs(&inode),
        "inode ibody xattr parsing must be deterministic"
    );
}

fn assert_bitmap_free_count_invariants(data: &[u8]) {
    for total_bits in [0_u32, 1, 7, 8, 9, 256, 8192] {
        let arbitrary_expected = raw_u32(data, 12);
        assert_eq!(
            verify_inode_bitmap_free_count(data, total_bits, arbitrary_expected),
            verify_inode_bitmap_free_count(data, total_bits, arbitrary_expected),
            "inode bitmap free-count verification must be deterministic"
        );
        assert_eq!(
            verify_block_bitmap_free_count(data, total_bits, arbitrary_expected),
            verify_block_bitmap_free_count(data, total_bits, arbitrary_expected),
            "block bitmap free-count verification must be deterministic"
        );

        let Some(free_bits) = expected_free_bits(data, total_bits) else {
            assert!(verify_inode_bitmap_free_count(data, total_bits, arbitrary_expected).is_err());
            assert!(verify_block_bitmap_free_count(data, total_bits, arbitrary_expected).is_err());
            continue;
        };

        assert!(
            verify_inode_bitmap_free_count(data, total_bits, free_bits).is_ok(),
            "modeled inode bitmap free count must verify"
        );
        assert!(
            verify_block_bitmap_free_count(data, total_bits, free_bits).is_ok(),
            "modeled block bitmap free count must verify"
        );

        let wrong_count = free_bits.saturating_add(1);
        if wrong_count != free_bits {
            assert!(verify_inode_bitmap_free_count(data, total_bits, wrong_count).is_err());
            assert!(verify_block_bitmap_free_count(data, total_bits, wrong_count).is_err());
        }
    }
}

fn assert_dir_checksum_roundtrip(data: &[u8]) {
    if data.len() < 12 {
        return;
    }

    let csum_seed = raw_u32(data, 0);
    let ino = raw_u32(data, 4);
    let generation = raw_u32(data, 8);
    let mut block = data.to_vec();
    let tail_off = block.len() - 12;

    if !put_u32(&mut block, tail_off, 0)
        || !put_u16(&mut block, tail_off + 4, 12)
        || !put_u8(&mut block, tail_off + 6, 0)
        || !put_u8(&mut block, tail_off + 7, EXT4_FT_DIR_CSUM)
    {
        return;
    }

    stamp_dir_block_checksum(&mut block, csum_seed, ino, generation);
    assert!(
        verify_dir_block_checksum(&block, csum_seed, ino, generation).is_ok(),
        "stamped directory block checksum must verify"
    );

    if tail_off > 0 {
        assert!(flip_byte(&mut block, 0));
        assert!(
            verify_dir_block_checksum(&block, csum_seed, ino, generation).is_err(),
            "single-bit corruption in covered directory bytes must reject"
        );
    }
}

fn assert_extent_checksum_roundtrip(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let csum_seed = raw_u32(data, 0);
    let ino = raw_u32(data, 4);
    let generation = raw_u32(data, 8);
    let mut block = data.to_vec();
    let max_entries = block.len().saturating_sub(16) / 12;
    let capped_entries = max_entries.min(usize::from(u16::MAX));
    let Some(eh_max) = u16::try_from(capped_entries).ok() else {
        return;
    };
    if !put_u16(&mut block, 4, eh_max) {
        return;
    }

    stamp_extent_block_checksum(&mut block, csum_seed, ino, generation);
    assert!(
        verify_extent_block_checksum(&block, csum_seed, ino, generation).is_ok(),
        "stamped extent block checksum must verify"
    );

    if flip_byte(&mut block, 0) {
        assert!(
            verify_extent_block_checksum(&block, csum_seed, ino, generation).is_err(),
            "single-bit corruption in covered extent bytes must reject"
        );
    }
}

fn assert_dx_hash_invariants(data: &[u8]) {
    let name_len = data.len().min(64);
    let Some(name) = data.get(..name_len) else {
        return;
    };
    let seed = [
        raw_u32(data, 0),
        raw_u32(data, 4),
        raw_u32(data, 8),
        raw_u32(data, 12),
    ];
    let zero_seed = [0_u32; 4];

    for hash_version in [0_u8, 1, 2, 3, 4, 5, 255] {
        assert_eq!(
            dx_hash(hash_version, name, &seed),
            dx_hash(hash_version, name, &seed),
            "DX hash must be deterministic for fuzz-derived seed"
        );
        assert_eq!(
            dx_hash(hash_version, name, &zero_seed),
            dx_hash(hash_version, name, &zero_seed),
            "DX hash must be deterministic for zero seed"
        );
    }
}

fn assert_dir_lookup_invariants(data: &[u8]) {
    for block_size in [1024_u32, 2048, 4096] {
        let exact = lookup_in_dir_block(data, block_size, b"test_file");
        let casefold = lookup_in_dir_block_casefold(data, block_size, b"Test_File");
        assert_eq!(
            exact,
            lookup_in_dir_block(data, block_size, b"test_file"),
            "exact directory lookup must be deterministic"
        );
        assert_eq!(
            casefold,
            lookup_in_dir_block_casefold(data, block_size, b"Test_File"),
            "casefold directory lookup must be deterministic"
        );

        if let Ok((entries, _tail)) = parse_dir_block(data, block_size) {
            let expected_exact = entries
                .iter()
                .find(|entry| entry.name == b"test_file")
                .cloned();
            assert_eq!(exact, Ok(expected_exact));

            let target_key = ext4_casefold_key(b"Test_File");
            let expected_casefold = entries
                .iter()
                .find(|entry| ext4_casefold_key(&entry.name) == target_key)
                .cloned();
            assert_eq!(casefold, Ok(expected_casefold));
        }

        let mut iter_first = iter_dir_block(data, block_size);
        let mut iter_second = iter_dir_block(data, block_size);
        loop {
            let left = iter_first.next();
            let right = iter_second.next();
            assert_eq!(
                left, right,
                "directory block iterator must be deterministic"
            );
            if left.is_none() {
                break;
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    assert_group_desc_and_bitmap_checksum_invariants(data);
    assert_superblock_checksum_invariants(data);
    assert_inode_derivative_invariants(data);
    assert_bitmap_free_count_invariants(data);
    assert_dir_checksum_roundtrip(data);
    assert_extent_checksum_roundtrip(data);
    assert_dx_hash_invariants(data);
    assert_dir_lookup_invariants(data);
});
