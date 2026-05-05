#![no_main]
//! Stamp/verify round-trip fuzz target for ext4 dir-block and
//! extent-block checksums (bd-nkfga).
//!
//! Companion to fuzz_ext4_checksums.rs (no-panic over arbitrary bytes).
//! This target lifts the bd-by4bc / bd-aofgb / proptest-layer fixed-input
//! round-trip tests
//! (`stamp_dir_block_checksum_round_trips_with_verify`,
//! `stamp_extent_block_checksum_round_trips_with_verify`) to libfuzzer
//! scale (millions of inputs/session) and pins:
//!
//!   MR-1 — dir_block: for any payload with a valid 12-byte tail
//!          (inode=0, rec_len=12, name_len=0, file_type=EXT4_FT_DIR_CSUM)
//!          and any (csum_seed, ino, generation) triple,
//!          stamp_dir_block_checksum(buf, ...) followed by
//!          verify_dir_block_checksum(buf, ...) MUST return Ok.
//!
//!   MR-2 — extent_block: for any buffer with a valid extent header
//!          (eh_max small enough that the tail fits), stamp followed
//!          by verify must succeed.
//!
//! A regression that drifted the stamp coverage range or the seed
//! formula would silently make every newly-mutated dir/extent block
//! fail verification on read; this target would catch it as a fuzzer
//! failure rather than a silent on-disk corruption.

use ffs_ondisk::{
    EXT4_FT_DIR_CSUM, Ext4GroupDesc, stamp_block_bitmap_checksum, stamp_dir_block_checksum,
    stamp_extent_block_checksum, stamp_inode_bitmap_checksum, verify_block_bitmap_checksum,
    verify_dir_block_checksum, verify_extent_block_checksum, verify_inode_bitmap_checksum,
};
use libfuzzer_sys::fuzz_target;

const MIN_DIR_BLOCK_BYTES: usize = 32;
const MAX_DIR_BLOCK_BYTES: usize = 4096;
const MIN_EXTENT_BLOCK_BYTES: usize = 32;
const MAX_EXTENT_BLOCK_BYTES: usize = 4096;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        value
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    let csum_seed = cursor.next_u32();
    let ino = cursor.next_u32();
    let generation = cursor.next_u32();

    // ── MR-1 — dir_block stamp/verify round-trip ────────────────────────
    let dir_block_size = MIN_DIR_BLOCK_BYTES
        .saturating_add(usize::from(cursor.next_u16()) % (MAX_DIR_BLOCK_BYTES - MIN_DIR_BLOCK_BYTES));
    let mut dir_block = vec![0_u8; dir_block_size];

    // Fill the body with cursor bytes so the checksum covers structured
    // (not all-zero) data. Body is everything before the 12-byte tail.
    let body_end = dir_block_size.saturating_sub(12);
    for byte in &mut dir_block[..body_end] {
        *byte = cursor.next_u8();
    }

    // Set up the 12-byte tail per ext4_dir_entry_tail layout (kernel):
    //   [0..4]  det_reserved_zero1 (inode = 0)
    //   [4..6]  det_rec_len        (= 12)
    //   [6]     det_reserved_zero2 (name_len = 0)
    //   [7]     det_reserved_ft    (= EXT4_FT_DIR_CSUM = 0xDE)
    //   [8..12] det_checksum       (filled by stamp)
    let tail_off = body_end;
    dir_block[tail_off..tail_off + 4].copy_from_slice(&0_u32.to_le_bytes()); // inode
    dir_block[tail_off + 4..tail_off + 6].copy_from_slice(&12_u16.to_le_bytes()); // rec_len
    dir_block[tail_off + 6] = 0; // name_len
    dir_block[tail_off + 7] = EXT4_FT_DIR_CSUM;
    // tail_off + 8..12 left zero; stamp will fill it.

    stamp_dir_block_checksum(&mut dir_block, csum_seed, ino, generation);
    verify_dir_block_checksum(&dir_block, csum_seed, ino, generation)
        .expect("MR-1: stamped dir_block must verify successfully");

    // ── MR-2 — extent_block stamp/verify round-trip ────────────────────
    let mut cursor2 = ByteCursor::new(cursor.remainder());

    // Bound eh_max so the resulting block size stays below
    // MAX_EXTENT_BLOCK_BYTES. Block layout: 12-byte header +
    // 12 * eh_max bytes of slot space + 4-byte checksum trailer.
    // Max safe eh_max for a 4096-byte cap: (4096 - 16) / 12 ≈ 340.
    let raw_eh_max = u16::from(cursor2.next_u8()) % 200; // [0, 200)
    let eh_max = raw_eh_max.max(1); // ensure at least one slot
    let extent_block_size = 12_usize
        .saturating_add(12 * usize::from(eh_max))
        .saturating_add(4);
    let extent_block_size =
        extent_block_size.clamp(MIN_EXTENT_BLOCK_BYTES, MAX_EXTENT_BLOCK_BYTES);
    let mut extent_block = vec![0_u8; extent_block_size];

    // ext4_extent_header layout (12 bytes):
    //   [0..2]   eh_magic (kernel: 0xF30A — but irrelevant for the
    //            checksum stamp/verify path which doesn't validate magic)
    //   [2..4]   eh_entries
    //   [4..6]   eh_max ← must be set so verify computes the right tail offset
    //   [6..8]   eh_depth
    //   [8..12]  eh_generation
    extent_block[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
    extent_block[4..6].copy_from_slice(&eh_max.to_le_bytes()); // eh_max
    // tail_off computed inside verify as 12 + 12 * eh_max — must fit in
    // extent_block. We sized the buffer to fit, so no overflow risk.

    // Fill body with structured bytes so the checksum is non-trivial.
    // Body covers offsets 12..tail_off (the slot table).
    let extent_body_end = (12_usize + 12 * usize::from(eh_max)).min(extent_block_size);
    for byte in &mut extent_block[12..extent_body_end] {
        *byte = cursor2.next_u8();
    }

    stamp_extent_block_checksum(&mut extent_block, csum_seed, ino, generation);
    verify_extent_block_checksum(&extent_block, csum_seed, ino, generation)
        .expect("MR-2: stamped extent_block must verify successfully");

    // ── MR-3 — block-bitmap stamp/verify round-trip ────────────────────
    // (bd-7x87u — extends bd-nkfga's dir/extent coverage to bitmaps.)
    // The bitmap checksum is computed over `clusters_per_group / 8`
    // bytes of bitmap; the result is stored in
    // `gd.block_bitmap_csum`, with the high half preserved only when
    // desc_size >= 64. We exercise both 32-byte and 64-byte desc paths.
    let mut cursor3 = ByteCursor::new(cursor2.remainder());

    // Bound bitmap size (8..=1024 bytes) and clusters_per_group so that
    // checksum_len = clusters_per_group/8 stays within bitmap.len().
    let raw_bitmap_len = 8_usize + (usize::from(cursor3.next_u8() % 128)) * 8; // [8, 1032)
    let bitmap_len = raw_bitmap_len.min(1024);
    let mut block_bitmap = vec![0_u8; bitmap_len];
    for byte in &mut block_bitmap {
        *byte = cursor3.next_u8();
    }
    // clusters_per_group must be a multiple of 8 and <= bitmap_len * 8;
    // pick a value that keeps `checksum_len = clusters_per_group/8`
    // strictly within the bitmap.
    let clusters_per_group = (u32::from(cursor3.next_u8()) % 32 + 1) * 8 // [8, 264) clusters
        .min(u32::try_from(bitmap_len).unwrap_or(u32::MAX) * 8);
    let desc_size: u16 = if cursor3.next_u8() & 1 == 0 { 32 } else { 64 };

    let mut block_gd = Ext4GroupDesc {
        block_bitmap: 0,
        inode_bitmap: 0,
        inode_table: 0,
        free_blocks_count: 0,
        free_inodes_count: 0,
        used_dirs_count: 0,
        itable_unused: 0,
        flags: 0,
        checksum: 0,
        block_bitmap_csum: 0,
        inode_bitmap_csum: 0,
    };
    stamp_block_bitmap_checksum(
        &block_bitmap,
        csum_seed,
        clusters_per_group,
        &mut block_gd,
        desc_size,
    );
    verify_block_bitmap_checksum(
        &block_bitmap,
        csum_seed,
        clusters_per_group,
        &block_gd,
        desc_size,
    )
    .expect("MR-3: stamped block_bitmap must verify against its own gd");

    // ── MR-4 — inode-bitmap stamp/verify round-trip ───────────────────
    // Same shape, distinct code path: writes to gd.inode_bitmap_csum,
    // uses `inodes_per_group / 8` for the checksum coverage length.
    let raw_inode_bitmap_len = 8_usize + (usize::from(cursor3.next_u8() % 128)) * 8;
    let inode_bitmap_len = raw_inode_bitmap_len.min(1024);
    let mut inode_bitmap = vec![0_u8; inode_bitmap_len];
    for byte in &mut inode_bitmap {
        *byte = cursor3.next_u8();
    }
    let inodes_per_group = (u32::from(cursor3.next_u8()) % 32 + 1) * 8
        .min(u32::try_from(inode_bitmap_len).unwrap_or(u32::MAX) * 8);
    let inode_desc_size: u16 = if cursor3.next_u8() & 1 == 0 { 32 } else { 64 };

    let mut inode_gd = Ext4GroupDesc {
        block_bitmap: 0,
        inode_bitmap: 0,
        inode_table: 0,
        free_blocks_count: 0,
        free_inodes_count: 0,
        used_dirs_count: 0,
        itable_unused: 0,
        flags: 0,
        checksum: 0,
        block_bitmap_csum: 0,
        inode_bitmap_csum: 0,
    };
    stamp_inode_bitmap_checksum(
        &inode_bitmap,
        csum_seed,
        inodes_per_group,
        &mut inode_gd,
        inode_desc_size,
    );
    verify_inode_bitmap_checksum(
        &inode_bitmap,
        csum_seed,
        inodes_per_group,
        &inode_gd,
        inode_desc_size,
    )
    .expect("MR-4: stamped inode_bitmap must verify against its own gd");
});
