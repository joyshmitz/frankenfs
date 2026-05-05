#![no_main]

use ffs_repair::symbol::{
    RepairBlockHeader, RepairGroupDescExt, RepairParseError, SymbolDigest, REPAIR_BLOCK_MAGIC,
    REPAIR_GROUP_DESC_MAGIC,
};
use ffs_types::{BlockNumber, GroupNumber};
use libfuzzer_sys::fuzz_target;

const MAX_TAIL_BYTES: usize = 64;

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

    fn next_digest(&mut self) -> [u8; 32] {
        let mut digest = [0_u8; 32];
        for byte in &mut digest {
            *byte = self.next_u8();
        }
        digest
    }

    fn tail(&mut self) -> Vec<u8> {
        let len = usize::from(self.next_u8()) % (MAX_TAIL_BYTES + 1);
        (0..len).map(|_| self.next_u8()).collect()
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let Some(raw) = bytes.get(offset..offset.saturating_add(4)) else {
        return 0;
    };
    let mut out = [0_u8; 4];
    out.copy_from_slice(raw);
    u32::from_le_bytes(out)
}

fn assert_tail_invariance<T, F>(canonical: &[u8], expected: &T, tail: &[u8], parse: F, label: &str)
where
    T: Clone + Eq + std::fmt::Debug,
    F: Fn(&[u8]) -> Result<T, RepairParseError>,
{
    let mut extended = canonical.to_vec();
    extended.extend_from_slice(tail);
    assert_eq!(
        parse(&extended),
        Ok(expected.clone()),
        "{label} parser must ignore trailing bytes beyond its fixed on-disk size"
    );
}

fn assert_truncation_rejected<T, F>(canonical: &[u8], size: usize, parse: F, label: &str)
where
    T: Eq + std::fmt::Debug,
    F: Fn(&[u8]) -> Result<T, RepairParseError>,
{
    for len in 0..size {
        let Some(prefix) = canonical.get(..len) else {
            continue;
        };
        match parse(prefix) {
            Err(RepairParseError::InsufficientData { needed, actual }) => {
                assert_eq!(needed, size, "{label} truncation must report fixed size");
                assert_eq!(actual, len, "{label} truncation must report observed len");
            }
            other => {
                assert!(
                    matches!(other, Err(RepairParseError::InsufficientData { .. })),
                    "{label} parser accepted or misclassified a {len}-byte truncation: {other:?}"
                );
            }
        }
    }
}

fn canonical_block_header(cursor: &mut ByteCursor<'_>) -> (RepairBlockHeader, [u8; 32]) {
    let mut header = RepairBlockHeader {
        first_esi: cursor.next_u32(),
        symbol_count: cursor.next_u16(),
        symbol_size: cursor.next_u16(),
        block_group: GroupNumber(cursor.next_u32()),
        repair_generation: cursor.next_u64(),
        checksum: 0,
    };
    let bytes = header.to_bytes();
    header.checksum = read_u32(&bytes, 24);
    (header, bytes)
}

fn assert_block_header_contracts(cursor: &mut ByteCursor<'_>) {
    let (header, bytes) = canonical_block_header(cursor);
    assert_eq!(
        RepairBlockHeader::parse(&bytes),
        Ok(header.clone()),
        "canonical repair block header must parse exactly"
    );
    assert_eq!(
        header.payload_size(),
        usize::from(header.symbol_count) * usize::from(header.symbol_size),
        "payload_size must match symbol geometry"
    );

    let tail = cursor.tail();
    assert_tail_invariance(
        &bytes,
        &header,
        &tail,
        RepairBlockHeader::parse,
        "RepairBlockHeader",
    );
    assert_truncation_rejected::<RepairBlockHeader, _>(
        &bytes,
        RepairBlockHeader::SIZE,
        RepairBlockHeader::parse,
        "RepairBlockHeader",
    );

    let mut bad_magic = bytes;
    if let Some(byte) = bad_magic.get_mut(0) {
        *byte ^= 1;
    }
    match RepairBlockHeader::parse(&bad_magic) {
        Err(RepairParseError::BadMagic { expected, actual }) => {
            assert_eq!(expected, REPAIR_BLOCK_MAGIC);
            assert_ne!(actual, expected);
        }
        other => {
            assert!(
                matches!(other, Err(RepairParseError::BadMagic { .. })),
                "RepairBlockHeader bad magic must be rejected as BadMagic: {other:?}"
            );
        }
    }

    let mut bad_checksum = bytes;
    if let Some(byte) = bad_checksum.get_mut(24) {
        *byte ^= 1;
    }
    match RepairBlockHeader::parse(&bad_checksum) {
        Err(RepairParseError::ChecksumMismatch { stored, computed }) => {
            assert_ne!(stored, computed);
        }
        other => {
            assert!(
                matches!(other, Err(RepairParseError::ChecksumMismatch { .. })),
                "RepairBlockHeader bad checksum must be rejected as ChecksumMismatch: {other:?}"
            );
        }
    }
}

fn canonical_group_desc(cursor: &mut ByteCursor<'_>) -> (RepairGroupDescExt, [u8; 48]) {
    let mut desc = RepairGroupDescExt {
        transfer_length: cursor.next_u64(),
        symbol_size: cursor.next_u16(),
        source_block_count: cursor.next_u16(),
        sub_blocks: cursor.next_u16(),
        symbol_alignment: cursor.next_u16(),
        repair_start_block: BlockNumber(cursor.next_u64()),
        repair_block_count: cursor.next_u32(),
        repair_generation: cursor.next_u64(),
        checksum: 0,
    };
    let bytes = desc.to_bytes();
    desc.checksum = read_u32(&bytes, 40);
    (desc, bytes)
}

fn assert_group_desc_contracts(cursor: &mut ByteCursor<'_>) {
    let (desc, bytes) = canonical_group_desc(cursor);
    assert_eq!(
        RepairGroupDescExt::parse(&bytes),
        Ok(desc.clone()),
        "canonical repair group descriptor must parse exactly"
    );

    let tail = cursor.tail();
    assert_tail_invariance(
        &bytes,
        &desc,
        &tail,
        RepairGroupDescExt::parse,
        "RepairGroupDescExt",
    );
    assert_truncation_rejected::<RepairGroupDescExt, _>(
        &bytes,
        RepairGroupDescExt::SIZE,
        RepairGroupDescExt::parse,
        "RepairGroupDescExt",
    );

    let mut bad_magic = bytes;
    if let Some(byte) = bad_magic.get_mut(0) {
        *byte ^= 1;
    }
    match RepairGroupDescExt::parse(&bad_magic) {
        Err(RepairParseError::BadMagic { expected, actual }) => {
            assert_eq!(expected, REPAIR_GROUP_DESC_MAGIC);
            assert_ne!(actual, expected);
        }
        other => {
            assert!(
                matches!(other, Err(RepairParseError::BadMagic { .. })),
                "RepairGroupDescExt bad magic must be rejected as BadMagic: {other:?}"
            );
        }
    }

    let mut bad_checksum = bytes;
    if let Some(byte) = bad_checksum.get_mut(40) {
        *byte ^= 1;
    }
    match RepairGroupDescExt::parse(&bad_checksum) {
        Err(RepairParseError::ChecksumMismatch { stored, computed }) => {
            assert_ne!(stored, computed);
        }
        other => {
            assert!(
                matches!(other, Err(RepairParseError::ChecksumMismatch { .. })),
                "RepairGroupDescExt bad checksum must be rejected as ChecksumMismatch: {other:?}"
            );
        }
    }
}

fn assert_symbol_digest_contracts(cursor: &mut ByteCursor<'_>) {
    let digest = SymbolDigest {
        esi: cursor.next_u32(),
        digest: cursor.next_digest(),
    };
    let bytes = digest.to_bytes();
    assert_eq!(
        SymbolDigest::parse(&bytes),
        Ok(digest.clone()),
        "canonical symbol digest must parse exactly"
    );

    let tail = cursor.tail();
    assert_tail_invariance(&bytes, &digest, &tail, SymbolDigest::parse, "SymbolDigest");
    assert_truncation_rejected::<SymbolDigest, _>(
        &bytes,
        SymbolDigest::SIZE,
        SymbolDigest::parse,
        "SymbolDigest",
    );
}

fn assert_arbitrary_parse_contracts(data: &[u8]) {
    let block_header_first = RepairBlockHeader::parse(data);
    let block_header_second = RepairBlockHeader::parse(data);
    assert_eq!(
        block_header_first, block_header_second,
        "repair block header parsing should be deterministic"
    );
    if let Ok(header) = block_header_first {
        assert_eq!(
            RepairBlockHeader::parse(&header.to_bytes()),
            Ok(header.clone()),
            "repair block headers should round-trip through their canonical encoding"
        );
        assert_eq!(
            header.payload_size(),
            usize::from(header.symbol_count) * usize::from(header.symbol_size),
            "payload_size should match the encoded symbol geometry"
        );
    }

    let group_desc_first = RepairGroupDescExt::parse(data);
    let group_desc_second = RepairGroupDescExt::parse(data);
    assert_eq!(
        group_desc_first, group_desc_second,
        "repair group descriptor parsing should be deterministic"
    );
    if let Ok(desc) = group_desc_first {
        assert_eq!(
            RepairGroupDescExt::parse(&desc.to_bytes()),
            Ok(desc.clone()),
            "repair group descriptors should round-trip through their canonical encoding"
        );
    }

    let symbol_digest_first = SymbolDigest::parse(data);
    let symbol_digest_second = SymbolDigest::parse(data);
    assert_eq!(
        symbol_digest_first, symbol_digest_second,
        "symbol digest parsing should be deterministic"
    );
    if let Ok(digest) = symbol_digest_first {
        assert_eq!(
            SymbolDigest::parse(&digest.to_bytes()),
            Ok(digest),
            "symbol digests should round-trip through their canonical encoding"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    assert_arbitrary_parse_contracts(data);

    let mut cursor = ByteCursor::new(data);
    assert_block_header_contracts(&mut cursor);
    assert_group_desc_contracts(&mut cursor);
    assert_symbol_digest_contracts(&mut cursor);
});
