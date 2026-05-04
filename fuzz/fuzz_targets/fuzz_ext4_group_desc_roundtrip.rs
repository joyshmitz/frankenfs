#![no_main]
//! Round-trip metamorphic fuzz target for `Ext4GroupDesc` encode/decode (bd-38xrn).
//!
//! Pins, at fuzzer scale, the bijection contract that the bd-ov7zr proptest
//! suite establishes at the proptest layer:
//!
//!   MR1 — at `desc_size=64`: parse(write(gd, 64), 64) == gd
//!         (full bijection over the 304-bit Ext4GroupDesc input space)
//!
//!   MR2 — at `desc_size=32`: parse(write(gd, 32), 32) == truncate_lo_halves(gd)
//!         (high halves are dropped on encode AND zeroed on decode — a
//!         regression here would silently corrupt 64-bit-mode block-bitmap
//!         pointers on any image written through a 32-byte path)
//!
//!   MR3 — write_to_bytes overwrites every parsed-field byte regardless of
//!         the destination buffer's prior contents.
//!
//! Companion to fuzz_ext4_metadata.rs (which fuzzes parse_from_bytes against
//! arbitrary bytes) and fuzz_ext4_checksums.rs (which exercises checksum
//! verification at desc_size in [32, 64]). Neither of those exercises the
//! encode side, so any drift in the lo/hi split, the 32-vs-64 branching, or
//! the field offset table currently goes undetected by the fuzz suite.

use ffs_ondisk::Ext4GroupDesc;
use libfuzzer_sys::fuzz_target;

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

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    let gd = Ext4GroupDesc {
        block_bitmap: cursor.next_u64(),
        inode_bitmap: cursor.next_u64(),
        inode_table: cursor.next_u64(),
        free_blocks_count: cursor.next_u32(),
        free_inodes_count: cursor.next_u32(),
        used_dirs_count: cursor.next_u32(),
        itable_unused: cursor.next_u32(),
        flags: cursor.next_u16(),
        checksum: cursor.next_u16(),
        block_bitmap_csum: cursor.next_u32(),
        inode_bitmap_csum: cursor.next_u32(),
    };

    // ── MR1 — full bijection at desc_size=64 ─────────────────────────────
    let mut buf64 = [0_u8; 64];
    gd.write_to_bytes(&mut buf64, 64)
        .expect("write_to_bytes(.., 64) on a 64-byte buffer must succeed");
    let parsed64 = Ext4GroupDesc::parse_from_bytes(&buf64, 64)
        .expect("parse_from_bytes must succeed on a buffer just written by write_to_bytes");
    assert_eq!(
        parsed64, gd,
        "MR1 violation: 64-byte encode/decode bijection broken"
    );

    // ── MR2 — truncating bijection at desc_size=32 ───────────────────────
    // The 32-byte writer drops the hi halves of every multi-byte field;
    // the 32-byte parser must read them as zero.
    #[allow(clippy::cast_possible_truncation)]
    let truncated = Ext4GroupDesc {
        block_bitmap: u64::from(gd.block_bitmap as u32),
        inode_bitmap: u64::from(gd.inode_bitmap as u32),
        inode_table: u64::from(gd.inode_table as u32),
        free_blocks_count: u32::from(gd.free_blocks_count as u16),
        free_inodes_count: u32::from(gd.free_inodes_count as u16),
        used_dirs_count: u32::from(gd.used_dirs_count as u16),
        itable_unused: u32::from(gd.itable_unused as u16),
        flags: gd.flags,
        checksum: gd.checksum,
        block_bitmap_csum: u32::from(gd.block_bitmap_csum as u16),
        inode_bitmap_csum: u32::from(gd.inode_bitmap_csum as u16),
    };
    let mut buf32 = [0_u8; 32];
    gd.write_to_bytes(&mut buf32, 32)
        .expect("write_to_bytes(.., 32) on a 32-byte buffer must succeed");
    let parsed32 = Ext4GroupDesc::parse_from_bytes(&buf32, 32)
        .expect("parse_from_bytes must succeed on a buffer just written by write_to_bytes");
    assert_eq!(
        parsed32, truncated,
        "MR2 violation: 32-byte truncating bijection broken"
    );

    // ── MR3 — writer overwrites every parsed-field byte ──────────────────
    // The doc on write_to_bytes promises the *parsed-field* bytes are written
    // (padding windows like 0x14..0x18 / 0x34..0x38 / 0x3C..0x40 at ds=64
    // are documented as untouched). This MR pins that contract by writing
    // gd into a buffer pre-filled with 0xCC and verifying the parsed result
    // still equals gd at desc_size=64 and the truncated form at desc_size=32.
    let mut buf64_pre = [0xCC_u8; 64];
    gd.write_to_bytes(&mut buf64_pre, 64)
        .expect("write into pre-filled 64-byte buffer must succeed");
    let parsed64_pre = Ext4GroupDesc::parse_from_bytes(&buf64_pre, 64)
        .expect("parse of pre-filled buffer must succeed");
    assert_eq!(
        parsed64_pre, gd,
        "MR3 violation: writer left a parsed-field byte unwritten at desc_size=64"
    );

    let mut buf32_pre = [0xAA_u8; 32];
    gd.write_to_bytes(&mut buf32_pre, 32)
        .expect("write into pre-filled 32-byte buffer must succeed");
    let parsed32_pre = Ext4GroupDesc::parse_from_bytes(&buf32_pre, 32)
        .expect("parse of pre-filled buffer must succeed");
    assert_eq!(
        parsed32_pre, truncated,
        "MR3 violation: writer left a parsed-field byte unwritten at desc_size=32"
    );
});
