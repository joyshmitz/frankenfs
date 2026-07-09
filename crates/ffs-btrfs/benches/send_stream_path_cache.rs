#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Whole-stream benchmark for btrfs send path construction (bd-h3087).
//!
//! The fixture is a deep directory chain with many regular files at the leaf.
//! It exercises `generate_send_stream` exactly where parent-chain PATH and
//! directory-depth reconstruction used to walk the same ancestors per inode.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_FIRST_FREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_INODE_REF,
    BTRFS_SEND_STREAM_MAGIC, BTRFS_SEND_STREAM_VERSION, BtrfsKey, BtrfsLeafEntry, SendAttr,
    SendCommand, build_chmod_command, build_chown_command, build_link_command, build_mkdir_command,
    build_mkfile_command, build_subvol_command, build_truncate_command, build_utimes_command,
    generate_send_stream, parse_inode_item, parse_inode_refs,
};
use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;

const DEPTH: u64 = 128;
const FILES: u64 = 768;
const ROOT_INO: u64 = BTRFS_FIRST_FREE_OBJECTID;
const FIRST_DIR_INO: u64 = ROOT_INO + 1;
const FIRST_FILE_INO: u64 = FIRST_DIR_INO + DEPTH;
const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;

#[derive(Debug, Clone, Default)]
struct LegacySendStreamBuilder {
    buffer: Vec<u8>,
    has_header: bool,
    finalized: bool,
}

impl LegacySendStreamBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn write_header(&mut self) {
        assert!(!self.has_header, "header already written");
        self.buffer.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        self.buffer
            .extend_from_slice(&BTRFS_SEND_STREAM_VERSION.to_le_bytes());
        self.has_header = true;
    }

    fn add_command(&mut self, cmd: SendCommand, attrs: &[(SendAttr, &[u8])]) {
        assert!(self.has_header, "must write header first");
        assert!(!self.finalized, "stream already finalized");

        let mut payload = Vec::new();
        for (atype, adata) in attrs {
            assert!(
                u16::try_from(adata.len()).is_ok(),
                "send-stream attribute data exceeds u16 TLV limit"
            );
            payload.extend_from_slice(&(*atype as u16).to_le_bytes());
            payload.extend_from_slice(&(adata.len() as u16).to_le_bytes());
            payload.extend_from_slice(adata);
        }

        let payload_len = payload.len() as u32;
        let full_len = 10 + payload.len();
        let mut frame = Vec::with_capacity(full_len);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&(cmd as u16).to_le_bytes());
        frame.extend_from_slice(&[0_u8; 4]);
        frame.extend_from_slice(&payload);

        let crc = send_stream_command_crc32c(&frame);
        frame[6..10].copy_from_slice(&crc.to_le_bytes());
        self.buffer.extend_from_slice(&frame);
    }

    fn finalize(&mut self) {
        assert!(!self.finalized, "stream already finalized");
        self.add_command(SendCommand::End, &[]);
        self.finalized = true;
    }

    fn finish(self) -> Vec<u8> {
        assert!(self.finalized, "must call finalize() before finish()");
        self.buffer
    }
}

fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn send_stream_command_crc32c(command: &[u8]) -> u32 {
    let mut crc = btrfs_send_crc32c(0, &command[..6]);
    crc = btrfs_send_crc32c(crc, &[0_u8; 4]);
    btrfs_send_crc32c(crc, &command[10..])
}

fn legacy_add_command(
    builder: &mut LegacySendStreamBuilder,
    command: (SendCommand, Vec<(SendAttr, Vec<u8>)>),
) {
    let (cmd, attrs) = command;
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);
}

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

fn legacy_generate_send_stream_for_fixture(
    items: &[BtrfsLeafEntry],
    subvol_name: &[u8],
    subvol_uuid: &[u8; 16],
    ctransid: u64,
) -> Vec<u8> {
    let mut builder = LegacySendStreamBuilder::new();
    builder.write_header();
    legacy_add_command(
        &mut builder,
        build_subvol_command(subvol_name, subvol_uuid, ctransid),
    );

    let mut inode_links: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
    for entry in items {
        if entry.key.item_type == BTRFS_ITEM_INODE_REF {
            if let Ok(refs) = parse_inode_refs(&entry.data) {
                let links = inode_links.entry(entry.key.objectid).or_default();
                for inode_ref in refs {
                    links.push((entry.key.offset, inode_ref.name));
                }
            }
        }
    }
    let inode_parents: BTreeMap<u64, (u64, Vec<u8>)> = inode_links
        .iter()
        .filter_map(|(&ino, links)| links.first().map(|(p, n)| (ino, (*p, n.clone()))))
        .collect();

    let mut path_cache: HashMap<u64, Vec<u8>> =
        HashMap::with_capacity(inode_parents.len().saturating_add(1));
    path_cache.insert(BTRFS_FIRST_FREE_OBJECTID, Vec::new());
    let mut build_path = |ino: u64| -> Vec<u8> {
        if let Some(path) = path_cache.get(&ino) {
            return path.clone();
        }

        let mut trail = Vec::new();
        let mut current = ino;
        let mut base_path = Vec::new();
        loop {
            if let Some(path) = path_cache.get(&current) {
                base_path.clone_from(path);
                break;
            }
            let Some((parent, name)) = inode_parents.get(&current) else {
                break;
            };
            trail.push((current, name.clone()));
            if *parent == current || *parent == BTRFS_FIRST_FREE_OBJECTID {
                break;
            }
            current = *parent;
        }

        let mut path = base_path;
        for (node, name) in trail.iter().rev() {
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            path_cache.insert(*node, path.clone());
        }
        if trail.is_empty() {
            path_cache.insert(ino, path.clone());
        }
        path
    };

    let mut inodes: BTreeMap<u64, Vec<&BtrfsLeafEntry>> = BTreeMap::new();
    for entry in items {
        inodes.entry(entry.key.objectid).or_default().push(entry);
    }

    let mut dir_inos = Vec::new();
    let mut other_inos = Vec::new();
    for (&ino, entries) in &inodes {
        let Some(inode) = entries
            .iter()
            .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .and_then(|e| parse_inode_item(&e.data).ok())
        else {
            continue;
        };
        if (inode.mode as u16) & ffs_types::S_IFMT == ffs_types::S_IFDIR {
            dir_inos.push(ino);
        } else {
            other_inos.push(ino);
        }
    }

    let mut depth_cache: HashMap<u64, usize> =
        HashMap::with_capacity(inode_parents.len().saturating_add(1));
    depth_cache.insert(BTRFS_FIRST_FREE_OBJECTID, 0);
    let mut dir_depth = |start: u64| -> usize {
        if let Some(&depth) = depth_cache.get(&start) {
            return depth;
        }

        let mut trail = Vec::new();
        let mut cur = start;
        let mut base_depth = 0usize;
        loop {
            if let Some(&depth) = depth_cache.get(&cur) {
                base_depth = depth;
                break;
            }
            let Some((parent, _)) = inode_parents.get(&cur) else {
                break;
            };
            if *parent == cur || *parent == BTRFS_FIRST_FREE_OBJECTID {
                break;
            }
            trail.push(cur);
            cur = *parent;
            if trail.len() > inodes.len() {
                let depth = trail.len();
                depth_cache.insert(start, depth);
                return depth;
            }
        }

        let mut depth = base_depth;
        for node in trail.iter().rev() {
            depth += 1;
            depth_cache.insert(*node, depth);
        }
        let depth = depth_cache.get(&start).copied().unwrap_or(base_depth);
        depth_cache.insert(start, depth);
        depth
    };
    dir_inos.sort_by_key(|&ino| (dir_depth(ino), ino));
    let emit_order: Vec<u64> = dir_inos.into_iter().chain(other_inos).collect();

    for &ino in &emit_order {
        let entries = &inodes[&ino];
        let Some(inode) = entries
            .iter()
            .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .and_then(|e| parse_inode_item(&e.data).ok())
        else {
            continue;
        };

        let path = build_path(ino);
        let file_type = (inode.mode as u16) & ffs_types::S_IFMT;

        match file_type {
            ffs_types::S_IFDIR => {
                if ino != BTRFS_FIRST_FREE_OBJECTID {
                    legacy_add_command(&mut builder, build_mkdir_command(&path, ino));
                }
            }
            ffs_types::S_IFREG => {
                legacy_add_command(&mut builder, build_mkfile_command(&path, ino));
                legacy_add_command(&mut builder, build_truncate_command(&path, inode.size));
            }
            _ => continue,
        }

        if file_type != ffs_types::S_IFDIR {
            if let Some(links) = inode_links.get(&ino) {
                for (parent, name) in links.iter().skip(1) {
                    let mut link_path = build_path(*parent);
                    if !link_path.is_empty() {
                        link_path.push(b'/');
                    }
                    link_path.extend_from_slice(name);
                    legacy_add_command(&mut builder, build_link_command(&link_path, &path));
                }
            }
        }

        let mode_bits = u64::from(inode.mode & 0o7777);
        legacy_add_command(&mut builder, build_chmod_command(&path, mode_bits));
        legacy_add_command(
            &mut builder,
            build_chown_command(&path, u64::from(inode.uid), u64::from(inode.gid)),
        );
        legacy_add_command(
            &mut builder,
            build_utimes_command(
                &path,
                inode.atime_sec as i64,
                inode.atime_nsec as i32,
                inode.mtime_sec as i64,
                inode.mtime_nsec as i32,
                inode.ctime_sec as i64,
                inode.ctime_nsec as i32,
            ),
        );
    }

    builder.finalize();
    builder.finish()
}

fn bench_send_stream_path_cache(c: &mut Criterion) {
    let items = build_deep_send_items();
    let uuid = [0x5a_u8; 16];
    let subvol: &[u8] = b"bench_subvol";

    let stream = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate send stream");
    let legacy_stream = legacy_generate_send_stream_for_fixture(&items, subvol, &uuid, 1);
    assert_eq!(
        stream, legacy_stream,
        "fused send stream must be byte-identical to legacy materialized construction"
    );
    assert!(
        stream.len() > 1_000_000,
        "fixture should emit enough PATH bytes to stress parent-chain work"
    );

    let mut group = c.benchmark_group("btrfs_send_stream_deep_paths");
    group.sample_size(10);
    group.bench_function("legacy_materialized_commands", |b| {
        b.iter(|| {
            let out = legacy_generate_send_stream_for_fixture(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
            );
            black_box(out.len())
        });
    });
    group.bench_function("fused_direct_commands", |b| {
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
