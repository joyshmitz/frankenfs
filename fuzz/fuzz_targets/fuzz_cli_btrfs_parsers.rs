#![no_main]

#[path = "../../crates/ffs-cli/src/repair_btrfs_parsers.rs"]
mod repair_btrfs_parsers;

use libfuzzer_sys::fuzz_target;
use repair_btrfs_parsers::{parse_btrfs_block_group_total_bytes, parse_btrfs_root_item_bytenr};

const ROOT_ITEM_MIN_LEN: usize = 184;
const BLOCK_GROUP_MIN_LEN: usize = 16;
const MAX_TAIL: usize = 32;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
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

fn normalize_u64_result(result: anyhow::Result<u64>) -> String {
    match result {
        Ok(value) => format!("ok:{value}"),
        Err(error) => format!("err:{error}"),
    }
}

fn build_payload(
    cursor: &mut ByteCursor<'_>,
    min_len: usize,
    field_range: std::ops::Range<usize>,
) -> (Vec<u8>, usize, u64) {
    let len_mode = cursor.next_u8() % 4;
    let tail = usize::from(cursor.next_u8()) % (MAX_TAIL + 1);
    let len = match len_mode {
        0 => min_len.saturating_sub(1),
        1 => min_len,
        2 => min_len.saturating_add(tail),
        _ => usize::from(cursor.next_u8()) % min_len.max(1),
    };
    let mut payload = vec![0_u8; len];
    for byte in &mut payload {
        *byte = cursor.next_u8();
    }

    let value_mode = cursor.next_u8() % 3;
    let mut encoded = cursor.next_u64();
    if value_mode == 0 {
        encoded = 0;
    } else if encoded == 0 {
        encoded = 1;
    }

    if payload.len() >= field_range.end {
        payload[field_range].copy_from_slice(&encoded.to_le_bytes());
    }

    (payload, len_mode as usize, encoded)
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    let (root_payload, root_len_mode, root_bytenr) =
        build_payload(&mut cursor, ROOT_ITEM_MIN_LEN, 176..184);
    let root_first = normalize_u64_result(parse_btrfs_root_item_bytenr(&root_payload));
    let root_second = normalize_u64_result(parse_btrfs_root_item_bytenr(&root_payload));
    assert_eq!(
        root_first, root_second,
        "root-item parser must be deterministic for identical payloads"
    );
    if root_payload.len() < ROOT_ITEM_MIN_LEN || root_len_mode == 0 {
        assert!(
            root_first.contains("payload too short"),
            "short root-item payloads must be rejected with a length error"
        );
    } else if root_bytenr == 0 {
        assert!(
            root_first.contains("must be non-zero"),
            "zero root-item bytenr must be rejected"
        );
    } else {
        assert_eq!(
            root_first,
            format!("ok:{root_bytenr}"),
            "well-formed root-item payloads must decode the embedded bytenr exactly"
        );
    }

    let (block_group_payload, block_group_len_mode, total_bytes) =
        build_payload(&mut cursor, BLOCK_GROUP_MIN_LEN, 8..16);
    let block_group_first =
        normalize_u64_result(parse_btrfs_block_group_total_bytes(&block_group_payload));
    let block_group_second =
        normalize_u64_result(parse_btrfs_block_group_total_bytes(&block_group_payload));
    assert_eq!(
        block_group_first, block_group_second,
        "block-group parser must be deterministic for identical payloads"
    );
    if block_group_payload.len() < BLOCK_GROUP_MIN_LEN || block_group_len_mode == 0 {
        assert!(
            block_group_first.contains("payload too short"),
            "short block-group payloads must be rejected with a length error"
        );
    } else if total_bytes == 0 {
        assert!(
            block_group_first.contains("must be non-zero"),
            "zero block-group total_bytes must be rejected"
        );
    } else {
        assert_eq!(
            block_group_first,
            format!("ok:{total_bytes}"),
            "well-formed block-group payloads must decode total_bytes exactly"
        );
    }
});
