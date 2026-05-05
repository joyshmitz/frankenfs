#![no_main]
//! Round-trip / tail-invariance fuzz target for btrfs `parse_dev_item`
//! (bd-rivds).
//!
//! Companion to fuzz_btrfs_devitem.rs (which is a 7-line no-panic guard
//! over arbitrary bytes). This target lifts the bd-t2nrx proptest MRs
//! into libfuzzer scale (millions of inputs per session) and pins:
//!
//!   MR-1 — Field round-trip / byte-offset contract: every documented
//!          field offset (devid@0, total_bytes@8, bytes_used@16,
//!          io_align@24, io_width@28, sector_size@32, dev_type@36,
//!          generation@44, start_offset@52, dev_group@60,
//!          seek_speed@64, bandwidth@65, uuid@66..82, fsid@82..98) is
//!          honored across the input space.
//!
//!   MR-2 — Tail-invariance: the parser reads exactly the first 98
//!          bytes (BTRFS_DEV_ITEM_SIZE). Appending arbitrary suffix
//!          bytes MUST yield the same parse result.
//!
//! A regression that drifted the offset table or accidentally hashed
//! tail bytes would manifest as a fuzzer failure rather than silently
//! corrupting btrfs multi-device reads.

use ffs_ondisk::parse_dev_item;
use libfuzzer_sys::fuzz_target;

const BTRFS_DEV_ITEM_SIZE: usize = 98;

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

    fn next_array_16(&mut self) -> [u8; 16] {
        let mut arr = [0_u8; 16];
        for byte in &mut arr {
            *byte = self.next_u8();
        }
        arr
    }

    fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    // Generate field values that satisfy parse_dev_item's accounting
    // invariants: devid != 0, total_bytes != 0, bytes_used <= total_bytes.
    let raw_devid = cursor.next_u64();
    let devid = if raw_devid == 0 { 1 } else { raw_devid };
    let raw_total = cursor.next_u64();
    let total_bytes = if raw_total == 0 { 1 } else { raw_total };
    // bytes_used <= total_bytes; cursor selects 0..=100 percent.
    let pct = u64::from(cursor.next_u8()) % 101;
    let bytes_used = total_bytes / 100 * pct;

    let io_align = cursor.next_u32();
    let io_width = cursor.next_u32();
    let sector_size = cursor.next_u32();
    let dev_type = cursor.next_u64();
    let generation = cursor.next_u64();
    let start_offset = cursor.next_u64();
    let dev_group = cursor.next_u32();
    let seek_speed = cursor.next_u8();
    let bandwidth = cursor.next_u8();
    let uuid = cursor.next_array_16();
    let fsid = cursor.next_array_16();

    // ── Materialise canonical 98-byte payload ───────────────────────────
    let mut buf = [0_u8; BTRFS_DEV_ITEM_SIZE];
    buf[0..8].copy_from_slice(&devid.to_le_bytes());
    buf[8..16].copy_from_slice(&total_bytes.to_le_bytes());
    buf[16..24].copy_from_slice(&bytes_used.to_le_bytes());
    buf[24..28].copy_from_slice(&io_align.to_le_bytes());
    buf[28..32].copy_from_slice(&io_width.to_le_bytes());
    buf[32..36].copy_from_slice(&sector_size.to_le_bytes());
    buf[36..44].copy_from_slice(&dev_type.to_le_bytes());
    buf[44..52].copy_from_slice(&generation.to_le_bytes());
    buf[52..60].copy_from_slice(&start_offset.to_le_bytes());
    buf[60..64].copy_from_slice(&dev_group.to_le_bytes());
    buf[64] = seek_speed;
    buf[65] = bandwidth;
    buf[66..82].copy_from_slice(&uuid);
    buf[82..98].copy_from_slice(&fsid);

    let canonical = parse_dev_item(&buf)
        .expect("synthesised 98-byte payload with valid accounting must parse");

    // MR-1: every field round-trips through its documented offset.
    assert_eq!(canonical.devid, devid, "MR-1: devid round-trip @0");
    assert_eq!(
        canonical.total_bytes, total_bytes,
        "MR-1: total_bytes round-trip @8"
    );
    assert_eq!(
        canonical.bytes_used, bytes_used,
        "MR-1: bytes_used round-trip @16"
    );
    assert_eq!(canonical.io_align, io_align, "MR-1: io_align round-trip @24");
    assert_eq!(canonical.io_width, io_width, "MR-1: io_width round-trip @28");
    assert_eq!(
        canonical.sector_size, sector_size,
        "MR-1: sector_size round-trip @32"
    );
    assert_eq!(
        canonical.dev_type, dev_type,
        "MR-1: dev_type round-trip @36"
    );
    assert_eq!(
        canonical.generation, generation,
        "MR-1: generation round-trip @44"
    );
    assert_eq!(
        canonical.start_offset, start_offset,
        "MR-1: start_offset round-trip @52"
    );
    assert_eq!(
        canonical.dev_group, dev_group,
        "MR-1: dev_group round-trip @60"
    );
    assert_eq!(
        canonical.seek_speed, seek_speed,
        "MR-1: seek_speed round-trip @64"
    );
    assert_eq!(
        canonical.bandwidth, bandwidth,
        "MR-1: bandwidth round-trip @65"
    );
    assert_eq!(canonical.uuid, uuid, "MR-1: uuid round-trip @66..82");
    assert_eq!(canonical.fsid, fsid, "MR-1: fsid round-trip @82..98");

    // MR-2: tail-invariance — bytes >= 98 must not affect parse output.
    let tail = cursor.remainder();
    if !tail.is_empty() {
        let mut extended = buf.to_vec();
        extended.extend_from_slice(tail);
        let extended_parsed = parse_dev_item(&extended)
            .expect("extended payload must parse since the parser ignores bytes >= 98");
        assert_eq!(
            extended_parsed, canonical,
            "MR-2: parse_dev_item must ignore bytes at offset >= 98"
        );
    }
});
