#![no_main]
use ffs_ondisk::{
    iter_dir_block, parse_dir_block, parse_dx_root, parse_extent_tree, Ext4DirEntry, Ext4DxRoot,
    ExtentTree,
};
use ffs_types::ParseError;
use libfuzzer_sys::fuzz_target;

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

fn assert_dir_block_invariants(data: &[u8], block_size: u32) {
    let parsed = parse_dir_block(data, block_size);
    assert_eq!(
        parsed,
        parse_dir_block(data, block_size),
        "dir-block parsing must be deterministic for identical bytes"
    );

    let Ok((entries, tail)) = parsed else {
        return;
    };

    let mut iter = iter_dir_block(data, block_size);
    let iter_entries = iter
        .by_ref()
        .map(|entry| entry.map(|entry| entry.to_owned()))
        .collect::<Result<Vec<Ext4DirEntry>, ParseError>>()
        .expect("iterator decode must agree with owned dir-block parser");
    assert_eq!(
        entries, iter_entries,
        "owned and borrowed dir-block parsers must return the same live entries"
    );
    assert_eq!(
        tail,
        iter.checksum_tail(),
        "owned and borrowed dir-block parsers must agree on checksum tail"
    );

    for entry in entries {
        assert_eq!(
            usize::from(entry.name_len),
            entry.name.len(),
            "successful dir entries must preserve name_len exactly"
        );
        assert!(
            entry.actual_size() <= entry.rec_len as usize,
            "dir entry actual size must fit inside rec_len"
        );
        assert!(
            entry.rec_len >= 12,
            "successful dir entries must have ext4 minimum rec_len"
        );
        assert_eq!(
            entry.rec_len % 4,
            0,
            "successful small-block dir entries must be 4-byte aligned"
        );
    }
}

fn assert_extent_tree_invariants(data: &[u8]) {
    let parsed = parse_extent_tree(data);
    assert_eq!(
        parsed,
        parse_extent_tree(data),
        "extent-tree parsing must be deterministic for identical bytes"
    );

    let Ok((header, tree)) = parsed else {
        return;
    };

    assert_eq!(header.magic, EXT4_EXTENT_MAGIC);
    assert!(
        header.entries <= header.max_entries,
        "successful extent headers must not overfill the node"
    );

    match tree {
        ExtentTree::Leaf(extents) => {
            assert_eq!(usize::from(header.entries), extents.len());
            let mut prev_end = None;
            for extent in extents {
                let actual_len = extent.actual_len();
                assert_ne!(actual_len, 0, "successful extents must be non-empty");
                if let Some(prev_end) = prev_end {
                    assert!(
                        u64::from(extent.logical_block) >= prev_end,
                        "successful extents must be sorted and non-overlapping"
                    );
                }
                prev_end = Some(u64::from(extent.logical_block) + u64::from(actual_len));
            }
        }
        ExtentTree::Index(indexes) => {
            assert_eq!(usize::from(header.entries), indexes.len());
            let mut prev_logical = None;
            for index in indexes {
                if let Some(prev_logical) = prev_logical {
                    assert!(
                        index.logical_block > prev_logical,
                        "successful extent indexes must be strictly sorted"
                    );
                }
                prev_logical = Some(index.logical_block);
            }
        }
    }
}

fn dx_root_signature(root: &Ext4DxRoot) -> (u8, u8, Vec<(u32, u32)>) {
    (
        root.hash_version,
        root.indirect_levels,
        root.entries
            .iter()
            .map(|entry| (entry.hash, entry.block))
            .collect(),
    )
}

fn assert_dx_root_invariants(data: &[u8]) {
    let parsed = parse_dx_root(data);
    let Ok(root) = parsed else {
        return;
    };
    let reparsed = parse_dx_root(data).expect("DX root reparse must match first successful parse");
    assert_eq!(
        dx_root_signature(&root),
        dx_root_signature(&reparsed),
        "DX root parsing must be deterministic for identical bytes"
    );

    assert!(
        root.indirect_levels <= 2,
        "default DX root parsing must enforce the non-LARGEDIR depth limit"
    );
    if let Some(first) = root.entries.first() {
        assert_eq!(first.hash, 0, "DX entry 0 has an implicit zero hash");
    }
    assert!(
        root.entries.len() <= data.len().saturating_sub(0x20) / 8 + 1,
        "DX parser must not synthesize more entries than fit in the source bytes"
    );
}

fuzz_target!(|data: &[u8]| {
    for block_size in [1024, 2048, 4096] {
        assert_dir_block_invariants(data, block_size);
    }

    assert_extent_tree_invariants(data);
    assert_dx_root_invariants(data);
});
