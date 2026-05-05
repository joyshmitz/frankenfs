#![no_main]

use ffs_ondisk::{parse_dev_item, BtrfsDevItem};
use ffs_types::ParseError;
use libfuzzer_sys::fuzz_target;

const BTRFS_DEV_ITEM_SIZE: usize = 98;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DevItemOutcome {
    Item(DevItemSig),
    Error(ParseErrorSig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DevItemSig {
    devid: u64,
    total_bytes: u64,
    bytes_used: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    dev_type: u64,
    generation: u64,
    start_offset: u64,
    dev_group: u32,
    seek_speed: u8,
    bandwidth: u8,
    uuid: [u8; 16],
    fsid: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseErrorSig {
    InsufficientData {
        needed: usize,
        offset: usize,
        actual: usize,
    },
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    Other,
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn read_array_16(data: &[u8], offset: usize) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&data[offset..offset + 16]);
    bytes
}

fn item_sig(item: &BtrfsDevItem) -> DevItemSig {
    DevItemSig {
        devid: item.devid,
        total_bytes: item.total_bytes,
        bytes_used: item.bytes_used,
        io_align: item.io_align,
        io_width: item.io_width,
        sector_size: item.sector_size,
        dev_type: item.dev_type,
        generation: item.generation,
        start_offset: item.start_offset,
        dev_group: item.dev_group,
        seek_speed: item.seek_speed,
        bandwidth: item.bandwidth,
        uuid: item.uuid,
        fsid: item.fsid,
    }
}

fn normalize_result(result: Result<BtrfsDevItem, ParseError>) -> DevItemOutcome {
    match result {
        Ok(item) => DevItemOutcome::Item(item_sig(&item)),
        Err(ParseError::InsufficientData {
            needed,
            offset,
            actual,
        }) => DevItemOutcome::Error(ParseErrorSig::InsufficientData {
            needed,
            offset,
            actual,
        }),
        Err(ParseError::InvalidField { field, reason }) => {
            DevItemOutcome::Error(ParseErrorSig::InvalidField { field, reason })
        }
        Err(ParseError::InvalidMagic { .. } | ParseError::IntegerConversion { .. }) => {
            DevItemOutcome::Error(ParseErrorSig::Other)
        }
    }
}

fn expected_outcome(data: &[u8]) -> DevItemOutcome {
    if data.len() < BTRFS_DEV_ITEM_SIZE {
        return DevItemOutcome::Error(ParseErrorSig::InsufficientData {
            needed: BTRFS_DEV_ITEM_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }

    let devid = read_u64(data, 0);
    let total_bytes = read_u64(data, 8);
    let bytes_used = read_u64(data, 16);

    if devid == 0 {
        return DevItemOutcome::Error(ParseErrorSig::InvalidField {
            field: "devid",
            reason: "must be non-zero",
        });
    }
    if total_bytes == 0 {
        return DevItemOutcome::Error(ParseErrorSig::InvalidField {
            field: "total_bytes",
            reason: "must be non-zero",
        });
    }
    if bytes_used > total_bytes {
        return DevItemOutcome::Error(ParseErrorSig::InvalidField {
            field: "bytes_used",
            reason: "exceeds total_bytes",
        });
    }

    DevItemOutcome::Item(DevItemSig {
        devid,
        total_bytes,
        bytes_used,
        io_align: read_u32(data, 24),
        io_width: read_u32(data, 28),
        sector_size: read_u32(data, 32),
        dev_type: read_u64(data, 36),
        generation: read_u64(data, 44),
        start_offset: read_u64(data, 52),
        dev_group: read_u32(data, 60),
        seek_speed: data[64],
        bandwidth: data[65],
        uuid: read_array_16(data, 66),
        fsid: read_array_16(data, 82),
    })
}

fn seed_u8(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}

fn seed_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        seed_u8(data, offset),
        seed_u8(data, offset + 1),
        seed_u8(data, offset + 2),
        seed_u8(data, offset + 3),
    ])
}

fn seed_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        seed_u8(data, offset),
        seed_u8(data, offset + 1),
        seed_u8(data, offset + 2),
        seed_u8(data, offset + 3),
        seed_u8(data, offset + 4),
        seed_u8(data, offset + 5),
        seed_u8(data, offset + 6),
        seed_u8(data, offset + 7),
    ])
}

fn seed_array_16(data: &[u8], offset: usize, fallback_seed: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data
            .get(offset.saturating_add(idx))
            .copied()
            .unwrap_or(fallback_seed.wrapping_add(u8::try_from(idx).unwrap_or(0)));
    }
    bytes
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn bounded_bytes_used(seed: u64, total_bytes: u64) -> u64 {
    if total_bytes == u64::MAX {
        seed
    } else {
        seed % (total_bytes + 1)
    }
}

fn synthetic_valid_devitem(data: &[u8]) -> Vec<u8> {
    let devid = seed_u64(data, 0) | 1;
    let total_bytes = seed_u64(data, 8) | 1;
    let bytes_used = bounded_bytes_used(seed_u64(data, 16), total_bytes);

    let mut bytes = vec![0_u8; BTRFS_DEV_ITEM_SIZE];
    write_u64(&mut bytes, 0, devid);
    write_u64(&mut bytes, 8, total_bytes);
    write_u64(&mut bytes, 16, bytes_used);
    write_u32(&mut bytes, 24, seed_u32(data, 24));
    write_u32(&mut bytes, 28, seed_u32(data, 28));
    write_u32(&mut bytes, 32, seed_u32(data, 32));
    write_u64(&mut bytes, 36, seed_u64(data, 36));
    write_u64(&mut bytes, 44, seed_u64(data, 44));
    write_u64(&mut bytes, 52, seed_u64(data, 52));
    write_u32(&mut bytes, 60, seed_u32(data, 60));
    bytes[64] = seed_u8(data, 64);
    bytes[65] = seed_u8(data, 65);
    bytes[66..82].copy_from_slice(&seed_array_16(data, 66, b'd'));
    bytes[82..98].copy_from_slice(&seed_array_16(data, 82, b'f'));
    bytes
}

fn assert_devitem_contract(data: &[u8]) {
    let actual = normalize_result(parse_dev_item(data));
    assert_eq!(
        actual,
        normalize_result(parse_dev_item(data)),
        "parse_dev_item must be deterministic"
    );
    assert_eq!(
        actual,
        expected_outcome(data),
        "parse_dev_item must follow the documented 98-byte DEV_ITEM layout"
    );

    if data.len() >= BTRFS_DEV_ITEM_SIZE {
        assert_eq!(
            actual,
            normalize_result(parse_dev_item(&data[..BTRFS_DEV_ITEM_SIZE])),
            "parse_dev_item must ignore bytes after the 98-byte DEV_ITEM payload"
        );
    }
}

fn assert_synthetic_contracts(data: &[u8]) {
    let valid = synthetic_valid_devitem(data);
    assert_eq!(
        normalize_result(parse_dev_item(&valid)),
        expected_outcome(&valid),
        "synthesized valid DEV_ITEM must parse according to the offset contract"
    );

    let mut zero_devid = valid.clone();
    write_u64(&mut zero_devid, 0, 0);
    assert_eq!(
        normalize_result(parse_dev_item(&zero_devid)),
        DevItemOutcome::Error(ParseErrorSig::InvalidField {
            field: "devid",
            reason: "must be non-zero",
        }),
        "zero devid must reject before later accounting checks"
    );

    let mut zero_total = valid.clone();
    write_u64(&mut zero_total, 8, 0);
    write_u64(&mut zero_total, 16, 0);
    assert_eq!(
        normalize_result(parse_dev_item(&zero_total)),
        DevItemOutcome::Error(ParseErrorSig::InvalidField {
            field: "total_bytes",
            reason: "must be non-zero",
        }),
        "zero total_bytes must reject"
    );

    let mut overused = valid.clone();
    write_u64(&mut overused, 8, 1);
    write_u64(&mut overused, 16, 2);
    assert_eq!(
        normalize_result(parse_dev_item(&overused)),
        DevItemOutcome::Error(ParseErrorSig::InvalidField {
            field: "bytes_used",
            reason: "exceeds total_bytes",
        }),
        "bytes_used greater than total_bytes must reject"
    );

    let truncated_len = usize::from(seed_u8(data, 96)) % BTRFS_DEV_ITEM_SIZE;
    assert_eq!(
        normalize_result(parse_dev_item(&valid[..truncated_len])),
        DevItemOutcome::Error(ParseErrorSig::InsufficientData {
            needed: BTRFS_DEV_ITEM_SIZE,
            offset: 0,
            actual: truncated_len,
        }),
        "truncated DEV_ITEM payload must report exact input length"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_devitem_contract(data);
    assert_synthetic_contracts(data);
});
