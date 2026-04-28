#![no_main]

use ffs_btrfs::{
    parse_dir_items, parse_extent_data, parse_inode_item, parse_root_item, parse_root_ref,
    parse_xattr_items, BtrfsDirItem, BtrfsExtentData, BtrfsInodeItem, BtrfsRootItem, BtrfsRootRef,
    BtrfsXattrItem, BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_PREALLOC, BTRFS_FILE_EXTENT_REG,
};
use libfuzzer_sys::fuzz_target;

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes = data.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_array_16(data: &[u8], off: usize) -> Option<[u8; 16]> {
    let bytes = data.get(off..off + 16)?;
    let mut out = [0_u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

fn assert_root_item_invariants(data: &[u8], parsed: &BtrfsRootItem) {
    assert_eq!(parsed.generation, read_u64(data, 160).unwrap_or_default());
    assert_eq!(parsed.root_dirid, read_u64(data, 168).unwrap_or_default());
    assert_eq!(parsed.bytenr, read_u64(data, 176).unwrap_or_default());
    assert_eq!(parsed.flags, read_u64(data, 208).unwrap_or_default());
    assert_eq!(
        parsed.refs,
        u64::from(read_u32(data, 216).unwrap_or_default())
    );
    assert_ne!(
        parsed.bytenr, 0,
        "successful root items must carry a non-zero bytenr"
    );
    assert_eq!(Some(parsed.level), data.get(238).copied());

    let extended_fields_valid =
        data.len() >= 247 && read_u64(data, 239).unwrap_or_default() == parsed.generation;
    let expected_uuid = if extended_fields_valid {
        read_array_16(data, 247).unwrap_or([0_u8; 16])
    } else {
        [0_u8; 16]
    };
    let expected_parent_uuid = if extended_fields_valid {
        read_array_16(data, 263).unwrap_or([0_u8; 16])
    } else {
        [0_u8; 16]
    };
    assert_eq!(parsed.uuid, expected_uuid);
    assert_eq!(parsed.parent_uuid, expected_parent_uuid);
}

fn assert_root_ref_invariants(data: &[u8], parsed: &BtrfsRootRef) {
    let name_len = usize::from(read_u16(data, 16).unwrap_or_default());
    let name_end = 18 + name_len;

    assert_eq!(parsed.dirid, read_u64(data, 0).unwrap_or_default());
    assert_eq!(parsed.sequence, read_u64(data, 8).unwrap_or_default());
    assert_eq!(parsed.name.len(), name_len);
    assert_eq!(parsed.name.as_slice(), &data[18..name_end]);
}

fn assert_inode_item_invariants(data: &[u8], parsed: &BtrfsInodeItem) {
    assert_eq!(parsed.generation, read_u64(data, 0).unwrap_or_default());
    assert_eq!(parsed.size, read_u64(data, 16).unwrap_or_default());
    assert_eq!(parsed.nbytes, read_u64(data, 24).unwrap_or_default());
    assert_eq!(parsed.nlink, read_u32(data, 40).unwrap_or_default());
    assert_eq!(parsed.uid, read_u32(data, 44).unwrap_or_default());
    assert_eq!(parsed.gid, read_u32(data, 48).unwrap_or_default());
    assert_eq!(parsed.mode, read_u32(data, 52).unwrap_or_default());
    assert_eq!(parsed.rdev, read_u64(data, 56).unwrap_or_default());
    assert_eq!(parsed.atime_sec, read_u64(data, 112).unwrap_or_default());
    assert_eq!(parsed.atime_nsec, read_u32(data, 120).unwrap_or_default());
    assert_eq!(parsed.ctime_sec, read_u64(data, 124).unwrap_or_default());
    assert_eq!(parsed.ctime_nsec, read_u32(data, 132).unwrap_or_default());
    assert_eq!(parsed.mtime_sec, read_u64(data, 136).unwrap_or_default());
    assert_eq!(parsed.mtime_nsec, read_u32(data, 144).unwrap_or_default());
    assert_eq!(parsed.otime_sec, read_u64(data, 148).unwrap_or_default());
    assert_eq!(parsed.otime_nsec, read_u32(data, 156).unwrap_or_default());
}

fn assert_dir_item_invariants(data: &[u8], parsed: &[BtrfsDirItem]) {
    const HEADER: usize = 30;

    if parsed.is_empty() {
        assert!(
            data.is_empty(),
            "successful empty DIR_ITEM decode should only happen on an empty payload"
        );
        return;
    }

    let mut cur = 0_usize;
    for item in parsed {
        assert!(
            cur + HEADER <= data.len(),
            "successful parse must leave a full dir-item header at {cur}"
        );

        let data_len = usize::from(read_u16(data, cur + 25).unwrap_or_default());
        let name_len = usize::from(read_u16(data, cur + 27).unwrap_or_default());
        let name_start = cur + HEADER;
        let Some(name_end) = name_start.checked_add(name_len) else {
            return;
        };
        let Some(payload_end) = name_end.checked_add(data_len) else {
            return;
        };

        assert!(
            payload_end <= data.len(),
            "successful dir-item parse must stay within the payload"
        );
        assert_eq!(item.child_objectid, read_u64(data, cur).unwrap_or_default());
        assert_eq!(item.child_key_type, data[cur + 8]);
        assert_eq!(
            item.child_key_offset,
            read_u64(data, cur + 9).unwrap_or_default()
        );
        assert_eq!(item.file_type, data[cur + 29]);
        assert_eq!(item.name.as_slice(), &data[name_start..name_end]);

        cur = payload_end;
    }

    assert_eq!(
        cur,
        data.len(),
        "successful dir-item decode must consume the full concatenated payload"
    );
}

fn assert_xattr_item_invariants(data: &[u8], parsed: &[BtrfsXattrItem]) {
    const HEADER: usize = 30;

    if parsed.is_empty() {
        assert!(
            data.is_empty(),
            "successful empty XATTR_ITEM decode should only happen on an empty payload"
        );
        return;
    }

    let mut cur = 0_usize;
    for item in parsed {
        assert!(
            cur + HEADER <= data.len(),
            "successful parse must leave a full xattr-item header at {cur}"
        );

        let data_len = usize::from(read_u16(data, cur + 25).unwrap_or_default());
        let name_len = usize::from(read_u16(data, cur + 27).unwrap_or_default());
        let name_start = cur + HEADER;
        let Some(name_end) = name_start.checked_add(name_len) else {
            return;
        };
        let Some(value_end) = name_end.checked_add(data_len) else {
            return;
        };

        assert!(
            value_end <= data.len(),
            "successful xattr-item parse must stay within the payload"
        );
        assert_eq!(item.name.as_slice(), &data[name_start..name_end]);
        assert_eq!(item.value.as_slice(), &data[name_end..value_end]);

        cur = value_end;
    }

    assert_eq!(
        cur,
        data.len(),
        "successful xattr-item decode must consume the full concatenated payload"
    );
}

fn assert_extent_data_invariants(data: &[u8], parsed: &BtrfsExtentData) {
    let generation = read_u64(data, 0).unwrap_or_default();
    let ram_bytes = read_u64(data, 8).unwrap_or_default();
    let compression = data.get(16).copied().unwrap_or_default();
    let extent_type = data.get(20).copied().unwrap_or_default();

    match parsed {
        BtrfsExtentData::Inline {
            generation: parsed_generation,
            ram_bytes: parsed_ram_bytes,
            compression: parsed_compression,
            data: parsed_data,
        } => {
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_INLINE);
            assert_eq!(*parsed_generation, generation);
            assert_eq!(*parsed_ram_bytes, ram_bytes);
            assert_eq!(*parsed_compression, compression);
            assert_eq!(parsed_data.as_slice(), &data[21..]);
        }
        BtrfsExtentData::Regular {
            generation: parsed_generation,
            ram_bytes: parsed_ram_bytes,
            extent_type: parsed_extent_type,
            compression: parsed_compression,
            disk_bytenr,
            disk_num_bytes,
            extent_offset,
            num_bytes,
        } => {
            assert!(matches!(
                extent_type,
                BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC
            ));
            assert_eq!(*parsed_generation, generation);
            assert_eq!(*parsed_ram_bytes, ram_bytes);
            assert_eq!(*parsed_extent_type, extent_type);
            assert_eq!(*parsed_compression, compression);
            assert_eq!(*disk_bytenr, read_u64(data, 21).unwrap_or_default());
            assert_eq!(*disk_num_bytes, read_u64(data, 29).unwrap_or_default());
            assert_eq!(*extent_offset, read_u64(data, 37).unwrap_or_default());
            assert_eq!(*num_bytes, read_u64(data, 45).unwrap_or_default());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let root_item = parse_root_item(data);
    assert_eq!(
        root_item,
        parse_root_item(data),
        "root-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &root_item {
        assert_root_item_invariants(data, parsed);
    }

    let root_ref = parse_root_ref(data);
    assert_eq!(
        root_ref,
        parse_root_ref(data),
        "root-ref parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &root_ref {
        assert_root_ref_invariants(data, parsed);
    }

    let inode_item = parse_inode_item(data);
    assert_eq!(
        inode_item,
        parse_inode_item(data),
        "inode-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &inode_item {
        assert_inode_item_invariants(data, parsed);
    }

    let dir_items = parse_dir_items(data);
    assert_eq!(
        dir_items,
        parse_dir_items(data),
        "dir-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &dir_items {
        assert_dir_item_invariants(data, parsed);
    }

    let xattr_items = parse_xattr_items(data);
    assert_eq!(
        xattr_items,
        parse_xattr_items(data),
        "xattr-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &xattr_items {
        assert_xattr_item_invariants(data, parsed);
    }

    let extent_data = parse_extent_data(data);
    assert_eq!(
        extent_data,
        parse_extent_data(data),
        "extent-data parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &extent_data {
        assert_extent_data_invariants(data, parsed);
    }
});
