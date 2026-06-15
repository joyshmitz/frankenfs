#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Whole-stream benchmark for btrfs send path construction (bd-h3087).
//!
//! The fixture is a deep directory chain with many regular files at the leaf.
//! It exercises `generate_send_stream` exactly where parent-chain PATH and
//! directory-depth reconstruction used to walk the same ancestors per inode.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_FIRST_FREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_INODE_REF, BtrfsKey,
    BtrfsLeafEntry, generate_send_stream,
};
use std::hint::black_box;

const DEPTH: u64 = 128;
const FILES: u64 = 768;
const ROOT_INO: u64 = BTRFS_FIRST_FREE_OBJECTID;
const FIRST_DIR_INO: u64 = ROOT_INO + 1;
const FIRST_FILE_INO: u64 = FIRST_DIR_INO + DEPTH;

fn make_inode_item(mode: u32, size: u64, nlink: u32) -> Vec<u8> {
    let mut buf = vec![0_u8; 160];
    buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
    buf[16..24].copy_from_slice(&size.to_le_bytes());
    buf[24..32].copy_from_slice(&size.to_le_bytes());
    buf[40..44].copy_from_slice(&nlink.to_le_bytes());
    buf[52..56].copy_from_slice(&mode.to_le_bytes());
    buf
}

fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + name.len());
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(name);
    buf
}

fn push_inode(
    items: &mut Vec<BtrfsLeafEntry>,
    objectid: u64,
    mode: u32,
    nlink: u32,
    parent: u64,
    name: &[u8],
) {
    items.push(BtrfsLeafEntry {
        key: BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        },
        data: make_inode_item(mode, 0, nlink),
    });
    items.push(BtrfsLeafEntry {
        key: BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_REF,
            offset: parent,
        },
        data: make_inode_ref(1, name),
    });
}

fn build_deep_send_items() -> Vec<BtrfsLeafEntry> {
    let mut items = Vec::with_capacity(((DEPTH + FILES) * 2 + FILES / 4 + 2) as usize);
    let dir_mode = u32::from(ffs_types::S_IFDIR | 0o755);
    let file_mode = u32::from(ffs_types::S_IFREG | 0o644);

    items.push(BtrfsLeafEntry {
        key: BtrfsKey {
            objectid: ROOT_INO,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        },
        data: make_inode_item(dir_mode, 0, 1),
    });

    let mut parent = ROOT_INO;
    for depth in 0..DEPTH {
        let ino = FIRST_DIR_INO + depth;
        let name = format!("d{depth:03}");
        push_inode(&mut items, ino, dir_mode, 1, parent, name.as_bytes());
        parent = ino;
    }

    for idx in 0..FILES {
        let ino = FIRST_FILE_INO + idx;
        let name = format!("f{idx:04}");
        let nlink = if idx % 4 == 0 { 2 } else { 1 };
        push_inode(&mut items, ino, file_mode, nlink, parent, name.as_bytes());
        if nlink > 1 {
            let link_name = format!("l{idx:04}");
            items.push(BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: ino,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: parent,
                },
                data: make_inode_ref(2, link_name.as_bytes()),
            });
        }
    }

    items
}

fn bench_send_stream_path_cache(c: &mut Criterion) {
    let items = build_deep_send_items();
    let uuid = [0x5a_u8; 16];
    let subvol: &[u8] = b"bench_subvol";

    let stream = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate send stream");
    assert!(
        stream.len() > 1_000_000,
        "fixture should emit enough PATH bytes to stress parent-chain work"
    );

    let mut group = c.benchmark_group("btrfs_send_stream_deep_paths");
    group.sample_size(10);
    group.bench_function("generate_send_stream", |b| {
        b.iter(|| {
            let out = generate_send_stream(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
                |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
            )
            .expect("generate send stream");
            black_box(out.len())
        });
    });
    group.finish();
}

criterion_group!(send_stream_path_cache, bench_send_stream_path_cache);
criterion_main!(send_stream_path_cache);
