#![no_main]

use ffs_core::{fuzz_btrfs_parse_inode_ref_payload, fuzz_btrfs_serialize_inode_ref_payload};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 64;

#[derive(Clone, Copy)]
enum SeedPayload {
    Raw,
    ValidSingle,
    ValidPair,
    TruncatedTail,
    DeclaredTooLong,
}

impl SeedPayload {
    fn from_selector(selector: u8) -> Self {
        match selector % 5 {
            0 => Self::Raw,
            1 => Self::ValidSingle,
            2 => Self::ValidPair,
            3 => Self::TruncatedTail,
            _ => Self::DeclaredTooLong,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseOutcome {
    Ok(Vec<(u64, Vec<u8>)>),
    Err(String),
}

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

    fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fn bounded_name(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let len = usize::from(cursor.next_u8()) % (MAX_NAME_BYTES + 1);
    (0..len).map(|_| cursor.next_u8()).collect()
}

fn encode_entry(index: u64, name: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(10 + name.len());
    payload.extend_from_slice(&index.to_le_bytes());
    payload.extend_from_slice(&(u16::try_from(name.len()).unwrap_or(u16::MAX)).to_le_bytes());
    payload.extend_from_slice(name);
    payload
}

fn build_payload(mode: SeedPayload, cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    match mode {
        SeedPayload::Raw => {
            cursor.remaining()[..cursor.remaining().len().min(MAX_INPUT_BYTES)].to_vec()
        }
        SeedPayload::ValidSingle => {
            let name = bounded_name(cursor);
            encode_entry(cursor.next_u64(), &name)
        }
        SeedPayload::ValidPair => {
            let first = encode_entry(cursor.next_u64(), &bounded_name(cursor));
            let second = encode_entry(cursor.next_u64(), &bounded_name(cursor));
            [first, second].concat()
        }
        SeedPayload::TruncatedTail => {
            let mut payload = encode_entry(cursor.next_u64(), &bounded_name(cursor));
            let trim = usize::from(cursor.next_u8()) % payload.len().max(1);
            payload.truncate(payload.len().saturating_sub(trim.max(1)));
            payload
        }
        SeedPayload::DeclaredTooLong => {
            let mut payload = Vec::new();
            let name = bounded_name(cursor);
            payload.extend_from_slice(&cursor.next_u64().to_le_bytes());
            let declared = u16::try_from(
                name.len()
                    .saturating_add(1 + usize::from(cursor.next_u8() % 32)),
            )
            .unwrap_or(u16::MAX);
            payload.extend_from_slice(&declared.to_le_bytes());
            payload.extend_from_slice(&name);
            payload
        }
    }
}

fn normalize(payload: &[u8]) -> ParseOutcome {
    match fuzz_btrfs_parse_inode_ref_payload(payload) {
        Ok(entries) => ParseOutcome::Ok(entries),
        Err(err) => ParseOutcome::Err(err.to_string()),
    }
}

fn assert_success_invariants(payload: &[u8], entries: &[(u64, Vec<u8>)]) {
    let reparsed = fuzz_btrfs_parse_inode_ref_payload(payload).expect("payload should parse");
    assert_eq!(
        entries,
        reparsed.as_slice(),
        "parsed entries must be stable"
    );

    let encoded = fuzz_btrfs_serialize_inode_ref_payload(entries).expect("serialize parsed refs");
    assert_eq!(
        encoded, payload,
        "serialize(parse(payload)) must roundtrip exactly"
    );

    let total_name_bytes: usize = entries.iter().map(|(_, name)| name.len()).sum();
    assert!(
        total_name_bytes <= payload.len(),
        "name bytes must remain bounded by payload length"
    );
    assert_eq!(
        entries.len().saturating_mul(10) + total_name_bytes,
        payload.len(),
        "successful parse must account for the full payload"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let mode = SeedPayload::from_selector(cursor.next_u8());
    let payload = build_payload(mode, &mut cursor);

    let first = normalize(&payload);
    let second = normalize(&payload);
    assert_eq!(
        first, second,
        "inode_ref payload parsing must be deterministic for identical inputs"
    );

    if let ParseOutcome::Ok(entries) = &first {
        assert_success_invariants(&payload, entries);
    }
});
