#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmark for ext4 directory-block lookup.
//!
//! `lookup_in_dir_block` / `lookup_in_dir_block_casefold` are on the hottest FS
//! path — every path resolution scans a directory block for a name. This builds
//! a densely packed block and measures a worst-case lookup (absent name → full
//! walk) to establish per-lookup latency.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{
    dx_hash,
    ext4::{
        DX_NODE_COUNT_OFFSET, EXT4_FT_REG_FILE, Ext4DxEntry, build_htree_directory,
        build_htree_directory_stamped, dx_find_leaf_idx, pack_dir_block_entries, parse_dir_block,
        split_htree_leaf_in_dx_node, stamp_dir_block_checksum, verify_dx_block_checksum,
    },
    htree_target_leaf_block, lookup_in_dir_block, lookup_in_dir_block_casefold, parse_dx_root,
};
use ffs_types::all_zero_bytes;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

const BLOCK_SIZE: u32 = 4096;
const EXT4_FT_DIR_CSUM: u8 = 0xDE;
const HTREE_SPLIT_BLOCK_SIZE: usize = 1024;
const HTREE_SPLIT_ENTRIES: usize = 8000;
const HTREE_SPLIT_HASH_VERSION: u8 = 1;
const HTREE_SPLIT_SEED: [u32; 4] = [0x0bad_f00d, 0xfeed_face, 0xdead_beef, 0xcafe_b0ba];
const HTREE_SPLIT_CSUM_SEED: u32 = 0x2222_3333;
const HTREE_SPLIT_DIR_INO: u32 = 313;
const HTREE_SPLIT_GENERATION: u32 = 12;
const HTREE_SPLIT_NEW_INO: u32 = 999_001;
const HTREE_SPLIT_NEW_NAME: &[u8] = b"fresh_dx_node_split_entry";

/// Build a valid, densely packed ext4 directory block of fixed-width entries
/// (`fileNNNN`, 8-byte names → 16-byte records). The final entry's `rec_len`
/// absorbs the remainder so the block parses cleanly with no checksum tail.
fn build_dense_dir_block() -> Vec<u8> {
    let block_size = BLOCK_SIZE as usize;
    let mut block = vec![0_u8; block_size];
    let rec = 16_usize; // (8 header + 8 name) already 4-aligned
    let count = block_size / rec;
    let mut offset = 0_usize;
    for idx in 0..count {
        let is_last = idx == count - 1;
        let this_rec = if is_last { block_size - offset } else { rec };
        let name = format!("file{idx:04}");
        let name_bytes = name.as_bytes();
        block[offset..offset + 4].copy_from_slice(&(idx as u32 + 2).to_le_bytes()); // inode
        block[offset + 4..offset + 6].copy_from_slice(&(this_rec as u16).to_le_bytes()); // rec_len
        block[offset + 6] = name_bytes.len() as u8; // name_len
        block[offset + 7] = 1; // file_type = regular
        block[offset + 8..offset + 8 + name_bytes.len()].copy_from_slice(name_bytes);
        offset += this_rec;
    }
    block
}

fn build_htree_blocks() -> (Vec<Arc<[u8]>>, Vec<Vec<u8>>) {
    let names: Vec<Vec<u8>> = (0..250)
        .map(|idx| format!("entry_{idx:04}").into_bytes())
        .collect();
    let entries: Vec<(u32, u8, &[u8])> = names
        .iter()
        .enumerate()
        .map(|(idx, name)| (idx as u32 + 2, 1, name.as_slice()))
        .collect();
    let blocks = build_htree_directory(2, 2, &entries, BLOCK_SIZE as usize, 1, &[0; 4], false)
        .expect("benchmark htree directory builds");
    let blocks = blocks
        .into_iter()
        .map(|block| Arc::<[u8]>::from(block.into_boxed_slice()))
        .collect();
    (blocks, names)
}

fn bench_rec_len_from_disk(raw: u16) -> usize {
    if raw == 0xFFFC || raw == 0 {
        return BLOCK_SIZE as usize;
    }
    let len = usize::from(raw);
    (len & 0xFFFC) | ((len & 0x3) << 16)
}

fn eager_tail_scan_probe(block: &[u8]) -> usize {
    let mut offset = 0_usize;
    let mut zero_suffixes = 0_usize;
    while offset + 8 <= block.len() {
        let rec_len_raw = u16::from_le_bytes([block[offset + 4], block[offset + 5]]);
        let rec_len = bench_rec_len_from_disk(rec_len_raw);
        let Some(entry_end) = offset.checked_add(rec_len) else {
            break;
        };
        if entry_end <= block.len() && all_zero_bytes(&block[entry_end..]) {
            zero_suffixes += 1;
        }
        if rec_len < 12 || entry_end <= offset || entry_end > block.len() {
            break;
        }
        offset = entry_end;
    }
    zero_suffixes
}

fn gated_tail_scan_probe(block: &[u8]) -> usize {
    let mut offset = 0_usize;
    let mut malformed_tail_positions = 0_usize;
    while offset + 8 <= block.len() {
        let inode = u32::from_le_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
        let rec_len_raw = u16::from_le_bytes([block[offset + 4], block[offset + 5]]);
        let rec_len = bench_rec_len_from_disk(rec_len_raw);
        let name_len = block[offset + 6];
        let file_type_raw = block[offset + 7];
        let Some(entry_end) = offset.checked_add(rec_len) else {
            break;
        };
        if inode == 0
            && name_len != 0
            && file_type_raw == EXT4_FT_DIR_CSUM
            && rec_len == 12
            && entry_end <= block.len()
            && all_zero_bytes(&block[entry_end..])
        {
            malformed_tail_positions += 1;
        }
        if rec_len < 12 || entry_end <= offset || entry_end > block.len() {
            break;
        }
        offset = entry_end;
    }
    malformed_tail_positions
}

fn bench_dx_find_leaf_idx(entries: &[Ext4DxEntry], hash: u32) -> usize {
    let mut lo = 0_usize;
    let mut hi = entries.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entries[mid].hash <= hash {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo.saturating_sub(1)
}

fn htree_target_leaf_block_allocating_root(
    hash_seed: &[u32; 4],
    name: &[u8],
    read_logical_dir_block: impl FnOnce(u32) -> Option<Arc<[u8]>>,
) -> Option<u32> {
    let block0 = read_logical_dir_block(0)?;
    let root = parse_dx_root(block0.as_ref()).ok()?;
    if root.entries.is_empty() || root.indirect_levels != 0 {
        return None;
    }
    let hash_version = root.hash_version;
    let (hash, _) = dx_hash(hash_version, name, hash_seed);
    root.entries
        .get(bench_dx_find_leaf_idx(&root.entries, hash))
        .map(|entry| entry.block)
}

fn htree_split_names() -> Vec<Vec<u8>> {
    (0..HTREE_SPLIT_ENTRIES)
        .map(|i| format!("file_{i:06}").into_bytes())
        .collect()
}

fn htree_split_blocks(names: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let entries: Vec<(u32, u8, &[u8])> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                100 + u32::try_from(i).expect("benchmark inode index fits u32"),
                EXT4_FT_REG_FILE,
                n.as_slice(),
            )
        })
        .collect();
    let blocks = build_htree_directory_stamped(
        2,
        2,
        &entries,
        HTREE_SPLIT_BLOCK_SIZE,
        HTREE_SPLIT_HASH_VERSION,
        &HTREE_SPLIT_SEED,
        HTREE_SPLIT_CSUM_SEED,
        HTREE_SPLIT_DIR_INO,
        HTREE_SPLIT_GENERATION,
    )
    .expect("benchmark two-level htree builds");
    assert_eq!(
        parse_dx_root(&blocks[0])
            .expect("benchmark htree root parses")
            .indirect_levels,
        1,
        "benchmark fixture must force a two-level htree"
    );
    blocks
}

fn htree_full_rebuild_with_extra(names: &[Vec<u8>]) -> usize {
    let mut entries: Vec<(u32, u8, &[u8])> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                100 + u32::try_from(i).expect("benchmark inode index fits u32"),
                EXT4_FT_REG_FILE,
                n.as_slice(),
            )
        })
        .collect();
    entries.push((HTREE_SPLIT_NEW_INO, EXT4_FT_REG_FILE, HTREE_SPLIT_NEW_NAME));

    let rebuilt = build_htree_directory_stamped(
        2,
        2,
        &entries,
        HTREE_SPLIT_BLOCK_SIZE,
        HTREE_SPLIT_HASH_VERSION,
        &HTREE_SPLIT_SEED,
        HTREE_SPLIT_CSUM_SEED,
        HTREE_SPLIT_DIR_INO,
        HTREE_SPLIT_GENERATION,
    )
    .expect("benchmark full htree rebuild succeeds");
    rebuilt.len()
}

fn htree_dx_node_leaf_split_with_extra(blocks: &[Vec<u8>]) -> usize {
    let root = parse_dx_root(&blocks[0]).expect("benchmark htree root parses");
    let new_hash = dx_hash(
        HTREE_SPLIT_HASH_VERSION,
        HTREE_SPLIT_NEW_NAME,
        &HTREE_SPLIT_SEED,
    )
    .0;
    let node_logical = root.entries[dx_find_leaf_idx(&root.entries, new_hash)].block;
    let target_logical = htree_target_leaf_block(
        &HTREE_SPLIT_SEED,
        false,
        HTREE_SPLIT_NEW_NAME,
        |v| v,
        |lb| blocks.get(lb as usize).cloned(),
    )
    .expect("benchmark target leaf resolves");
    let new_leaf_logical =
        u32::try_from(blocks.len()).expect("benchmark htree block count fits u32");

    let split = split_htree_leaf_in_dx_node(
        &blocks[node_logical as usize],
        &blocks[target_logical as usize],
        target_logical,
        new_leaf_logical,
        HTREE_SPLIT_BLOCK_SIZE,
        HTREE_SPLIT_HASH_VERSION,
        &HTREE_SPLIT_SEED,
        true,
        HTREE_SPLIT_CSUM_SEED,
        HTREE_SPLIT_DIR_INO,
        HTREE_SPLIT_GENERATION,
    )
    .expect("benchmark dx_node leaf split succeeds");

    let mut leaf = if new_hash >= split.split_hash {
        split.new_leaf
    } else {
        split.old_leaf
    };
    let (existing, _tail) = parse_dir_block(
        &leaf,
        u32::try_from(HTREE_SPLIT_BLOCK_SIZE).expect("block size fits u32"),
    )
    .expect("benchmark split leaf parses");
    let mut refs: Vec<(u32, u8, Vec<u8>)> = existing
        .into_iter()
        .filter(|e| e.inode != 0 && e.name != b"." && e.name != b".." && !e.name.is_empty())
        .map(|e| (e.inode, e.file_type.to_raw(), e.name))
        .collect();
    refs.push((
        HTREE_SPLIT_NEW_INO,
        EXT4_FT_REG_FILE,
        HTREE_SPLIT_NEW_NAME.to_vec(),
    ));
    let packed_refs: Vec<(u32, u8, &[u8])> = refs
        .iter()
        .map(|(ino, ft, name)| (*ino, *ft, name.as_slice()))
        .collect();
    leaf = pack_dir_block_entries(&packed_refs, HTREE_SPLIT_BLOCK_SIZE, true)
        .expect("benchmark split leaf repacks");
    stamp_dir_block_checksum(
        &mut leaf,
        HTREE_SPLIT_CSUM_SEED,
        HTREE_SPLIT_DIR_INO,
        HTREE_SPLIT_GENERATION,
    );

    assert!(verify_dx_block_checksum(
        &split.dx_node,
        HTREE_SPLIT_CSUM_SEED,
        HTREE_SPLIT_DIR_INO,
        HTREE_SPLIT_GENERATION,
        DX_NODE_COUNT_OFFSET
    ));

    split.dx_node.len() + leaf.len() + usize::from(split.split_hash != 0)
}

fn bench_dir_lookup(c: &mut Criterion) {
    let block = build_dense_dir_block();
    let (htree_blocks, htree_names) = build_htree_blocks();
    let htree_name = htree_names
        .last()
        .expect("benchmark htree has names")
        .as_slice();
    // Absent name → the lookup must walk every entry (worst case).
    let absent: &[u8] = b"zzzzzzzz";

    // Sanity: block parses and the absent name is not found.
    assert!(
        lookup_in_dir_block(&block, BLOCK_SIZE, absent)
            .unwrap()
            .is_none()
    );

    let mut group = c.benchmark_group("dir_lookup");
    group.bench_function("lookup_absent_dense_4k", |b| {
        b.iter(|| {
            black_box(
                lookup_in_dir_block(black_box(&block), BLOCK_SIZE, black_box(absent)).unwrap(),
            )
        });
    });
    group.bench_function("lookup_casefold_absent_dense_4k", |b| {
        b.iter(|| {
            black_box(
                lookup_in_dir_block_casefold(black_box(&block), BLOCK_SIZE, black_box(absent))
                    .unwrap(),
            )
        });
    });
    group.bench_function("tail_scan_eager_suffix_probe_dense_4k", |b| {
        b.iter(|| black_box(eager_tail_scan_probe(black_box(&block))));
    });
    group.bench_function("tail_scan_gated_suffix_probe_dense_4k", |b| {
        b.iter(|| black_box(gated_tail_scan_probe(black_box(&block))));
    });
    group.bench_function("htree_target_leaf_vec_owner", |b| {
        b.iter(|| {
            black_box(htree_target_leaf_block(
                black_box(&[0; 4]),
                false,
                black_box(htree_name),
                |v| v,
                |lb| {
                    htree_blocks
                        .get(lb as usize)
                        .map(|block| block.as_ref().to_vec())
                },
            ))
        });
    });
    group.bench_function("htree_target_leaf_arc_owner", |b| {
        b.iter(|| {
            black_box(htree_target_leaf_block(
                black_box(&[0; 4]),
                false,
                black_box(htree_name),
                |v| v,
                |lb| htree_blocks.get(lb as usize).map(Arc::clone),
            ))
        });
    });
    group.bench_function("htree_target_leaf_allocating_root_arc_owner", |b| {
        b.iter(|| {
            black_box(htree_target_leaf_block_allocating_root(
                black_box(&[0; 4]),
                black_box(htree_name),
                |lb| htree_blocks.get(lb as usize).map(Arc::clone),
            ))
        });
    });
    group.finish();
}

fn bench_htree_dx_node_leaf_split(c: &mut Criterion) {
    let names = htree_split_names();
    let blocks = htree_split_blocks(&names);
    assert_ne!(
        htree_full_rebuild_with_extra(&names),
        0,
        "full rebuild sanity check"
    );
    assert_ne!(
        htree_dx_node_leaf_split_with_extra(&blocks),
        0,
        "dx_node split sanity check"
    );

    let mut group = c.benchmark_group("htree_dx_node_leaf_overflow_8000x1k");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(200))
        .measurement_time(Duration::from_secs(2));
    group.bench_function("full_rebuild_orig", |b| {
        b.iter(|| black_box(htree_full_rebuild_with_extra(black_box(&names))));
    });
    group.bench_function("dx_node_leaf_split", |b| {
        b.iter(|| black_box(htree_dx_node_leaf_split_with_extra(black_box(&blocks))));
    });
    group.finish();
}

criterion_group!(dir_lookup, bench_dir_lookup, bench_htree_dx_node_leaf_split);
criterion_main!(dir_lookup);
