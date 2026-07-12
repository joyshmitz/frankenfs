#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the ext4 `listxattr` names-only enumeration.
//!
//! `listxattr` needs only the attribute NAMES, but the reader backend built the
//! full name list via `parse_xattr_block` — which allocates a name `Vec` AND a
//! value `Vec` per entry (and validates every value's in-block bounds) — then
//! mapped `full_name()` over the result and dropped the values.
//! `parse_xattr_block_names` builds the `full_name` strings during a single
//! entry-table walk and never touches the value region.
//!
//! Benches a 24-entry external xattr block; VALUE_LEN sweeps small (SELinux/caps
//! sized) vs large (ACL/EA sized) so the value-copy avoided is visible.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{parse_xattr_block, parse_xattr_block_names};
use std::hint::black_box;

const N: usize = 24;
const BLOCK_LEN: usize = 4096;
const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;
const EXT4_XATTR_INDEX_USER: u8 = 1;

fn build_block(value_len: usize) -> Vec<u8> {
    let mut block = vec![0_u8; BLOCK_LEN];
    block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let mut entry_off = 32_usize;
    for i in 0..N {
        let name = format!("attr{i:02}");
        let name_bytes = name.as_bytes();
        // Pack values backwards from the end of the block. The previous
        // `2048 + i * value_len` layout overflowed the 4 KiB fixture for the
        // 24 x 128-byte row before Criterion could benchmark it.
        let value_offs = BLOCK_LEN - (i + 1) * value_len;
        block[entry_off] = name_bytes.len() as u8;
        block[entry_off + 1] = EXT4_XATTR_INDEX_USER;
        block[entry_off + 2..entry_off + 4].copy_from_slice(&(value_offs as u16).to_le_bytes());
        block[entry_off + 4..entry_off + 8].copy_from_slice(&0_u32.to_le_bytes());
        block[entry_off + 8..entry_off + 12].copy_from_slice(&(value_len as u32).to_le_bytes());
        block[entry_off + 12..entry_off + 16].copy_from_slice(&0_u32.to_le_bytes());
        block[entry_off + 16..entry_off + 16 + name_bytes.len()].copy_from_slice(name_bytes);
        for (j, b) in block[value_offs..value_offs + value_len]
            .iter_mut()
            .enumerate()
        {
            *b = (i as u8).wrapping_mul(31).wrapping_add(j as u8);
        }
        entry_off = (entry_off + 16 + name_bytes.len() + 3) & !3;
    }
    block[entry_off] = 0;
    block[entry_off + 1] = 0;
    block
}

/// Old path: materialise every attribute (name + value), then map full_name.
fn parse_all_then_names(block: &[u8]) -> Vec<String> {
    parse_xattr_block(block)
        .unwrap()
        .iter()
        .map(ffs_ondisk::Ext4Xattr::full_name)
        .collect()
}

/// Frozen control for the former names-only formatter. This intentionally
/// mirrors the old `format!("{}{}", prefix, from_utf8_lossy(name))` shape while
/// walking the same valid user-namespace fixture as the production parser.
fn parse_names_format_control(block: &[u8]) -> Vec<String> {
    assert_eq!(
        u32::from_le_bytes(block[0..4].try_into().unwrap()),
        EXT4_XATTR_MAGIC
    );
    let data = &block[32..];
    let mut names = Vec::new();
    let mut offset = 0_usize;
    loop {
        let name_len = usize::from(data[offset]);
        let name_index = data[offset + 1];
        if name_len == 0 && name_index == 0 {
            break;
        }
        assert_eq!(name_index, EXT4_XATTR_INDEX_USER);
        let name_start = offset + 16;
        let name_end = name_start + name_len;
        names.push(format!(
            "user.{}",
            String::from_utf8_lossy(&data[name_start..name_end])
        ));
        offset = (name_end + 3) & !3;
    }
    names
}

fn bench_group(c: &mut Criterion, value_len: usize, label: &str) {
    let block = build_block(value_len);
    // Isomorphism: names-only returns the same full names as materialise-all.
    let old = parse_all_then_names(&block);
    let new = parse_xattr_block_names(&block).unwrap();
    assert_eq!(
        old, new,
        "names-only diverged from materialise-all ({label})"
    );
    assert_eq!(new.len(), N);

    let mut g = c.benchmark_group(format!("ext4_listxattr_block_24_{label}"));
    g.bench_function("parse_all_then_names", |b| {
        b.iter(|| black_box(parse_all_then_names(black_box(&block))));
    });
    g.bench_function("names_only", |b| {
        b.iter(|| black_box(parse_xattr_block_names(black_box(&block)).unwrap()));
    });
    g.finish();
}

fn bench_formatter_ab(c: &mut Criterion) {
    let block = build_block(32);
    let control = parse_names_format_control(&block);
    let candidate = parse_xattr_block_names(&block).unwrap();
    assert_eq!(
        control, candidate,
        "formatter candidate changed listxattr output"
    );

    let mut g = c.benchmark_group("ext4_listxattr_block_24_formatter_ab");
    g.bench_function("format_control_a", |b| {
        b.iter(|| black_box(parse_names_format_control(black_box(&block))));
    });
    g.bench_function("format_control_b", |b| {
        b.iter(|| black_box(parse_names_format_control(black_box(&block))));
    });
    g.bench_function("preallocated", |b| {
        b.iter(|| black_box(parse_xattr_block_names(black_box(&block)).unwrap()));
    });
    g.finish();
}

fn bench(c: &mut Criterion) {
    bench_group(c, 32, "smallval"); // SELinux/caps-sized values
    bench_group(c, 128, "largeval"); // ACL/EA-sized values
    bench_formatter_ab(c);
}

criterion_group!(listxattr_names, bench);
criterion_main!(listxattr_names);
