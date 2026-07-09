#![forbid(unsafe_code)]
//! `add_entry_tracked` / lookup / remove all walk a dir block reading 3 header
//! fields per entry — inode (u32 @off), rec_len (u16 @off+4), name_len (u8
//! @off+6) — via 3 separate bounds-checked reads, inside a loop guarded by
//! `off + 8 <= limit`. My prior `walk_dir_block_entries` finding said a
//! read_fixed hoist LOSES here — but that used the array-COPY form (`read_fixed`
//! copies 8 bytes to a stack array). This measures the array-REF reslice
//! (`&block[off..off+8] as &[u8; 8]`, one check, NO copy) — the form that won
//! on the write side (`entry_header_write`, 1.16x). Which wins for the READ?
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-dir --bench entry_header_read
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

const HDR: usize = 8;

/// Build a 4 KiB dir block packed with entries (name_len 11, rec_len 24).
fn make_block() -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    let rec_len: u16 = 24;
    let mut off = 0usize;
    let mut ino: u32 = 12;
    while off + rec_len as usize <= 4096 {
        block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        block[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
        block[off + 6] = 11; // name_len
        block[off + 7] = 1; // file_type
        block[off + 8..off + 19].copy_from_slice(b"file_abcdef");
        off += rec_len as usize;
        ino += 1;
    }
    block
}

/// Production shape: 3 separate bounds-checked reads per entry.
#[inline]
fn walk_checked(block: &[u8]) -> u64 {
    let limit = block.len();
    let mut off = 0usize;
    let mut acc: u64 = 0;
    while off + HDR <= limit {
        let rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
        if rec_len < HDR {
            break;
        }
        let ino = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        let name_len = block[off + 6] as u64;
        acc = acc.wrapping_add(ino as u64).wrapping_add(name_len);
        off += rec_len;
    }
    acc
}

/// Array-ref reslice: one bounds check per entry, then const-offset reads.
#[inline]
fn walk_arrayref(block: &[u8]) -> u64 {
    let limit = block.len();
    let mut off = 0usize;
    let mut acc: u64 = 0;
    while off + HDR <= limit {
        let h: &[u8; 8] = match block[off..off + HDR].try_into() {
            Ok(h) => h,
            Err(_) => break,
        };
        let rec_len = u16::from_le_bytes([h[4], h[5]]) as usize;
        if rec_len < HDR {
            break;
        }
        let ino = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let name_len = h[6] as u64;
        acc = acc.wrapping_add(ino as u64).wrapping_add(name_len);
        off += rec_len;
    }
    acc
}

fn bench(c: &mut Criterion) {
    let block = make_block();
    assert_eq!(walk_checked(&block), walk_arrayref(&block));

    let mut g = c.benchmark_group("entry_header_read");
    g.bench_function("checked", |b| b.iter(|| black_box(walk_checked(black_box(&block)))));
    g.bench_function("arrayref", |b| b.iter(|| black_box(walk_arrayref(black_box(&block)))));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
