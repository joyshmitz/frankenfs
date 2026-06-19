#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmark for ext4 directory-block lookup.
//!
//! `lookup_in_dir_block` / `lookup_in_dir_block_casefold` are on the hottest FS
//! path — every path resolution scans a directory block for a name. This builds
//! a densely packed block and measures a worst-case lookup (absent name → full
//! walk) to establish per-lookup latency.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{lookup_in_dir_block, lookup_in_dir_block_casefold};
use ffs_types::all_zero_bytes;
use std::hint::black_box;

const BLOCK_SIZE: u32 = 4096;
const EXT4_FT_DIR_CSUM: u8 = 0xDE;

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

fn bench_dir_lookup(c: &mut Criterion) {
    let block = build_dense_dir_block();
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
    group.finish();
}

criterion_group!(dir_lookup, bench_dir_lookup);
criterion_main!(dir_lookup);
