#![no_main]

use ffs_journal::{replay_fast_commit, FcDelRange, FcDentry, FcExtentRange, FcOperation};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_NAME_LEN: usize = 32;

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

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = usize::from(self.next_u8()) % max_len.saturating_add(1);
        (0..len).map(|_| self.next_u8()).collect()
    }
}

fn build_fc_tag(tag_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut tag = Vec::with_capacity(4 + payload.len());
    tag.extend_from_slice(&tag_type.to_le_bytes());
    let payload_len = u16::try_from(payload.len()).expect("fuzz payload length fits u16");
    tag.extend_from_slice(&payload_len.to_le_bytes());
    tag.extend_from_slice(payload);
    tag
}

fn build_dentry_payload(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, FcDentry) {
    let parent_ino = cursor.next_u32();
    let ino = cursor.next_u32();
    let name = cursor.take_vec(MAX_NAME_LEN);
    let mut payload = Vec::with_capacity(8 + name.len());
    payload.extend_from_slice(&parent_ino.to_le_bytes());
    payload.extend_from_slice(&ino.to_le_bytes());
    payload.extend_from_slice(&name);
    (
        payload,
        FcDentry {
            parent_ino,
            ino,
            name,
        },
    )
}

fn build_extent_payload(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, FcExtentRange) {
    let range = FcExtentRange {
        ino: cursor.next_u32(),
        logical_block: cursor.next_u32(),
        len: cursor.next_u32(),
        physical_block: cursor.next_u32(),
    };
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&range.ino.to_le_bytes());
    payload.extend_from_slice(&range.logical_block.to_le_bytes());
    payload.extend_from_slice(&range.len.to_le_bytes());
    payload.extend_from_slice(&range.physical_block.to_le_bytes());
    (payload, range)
}

fn build_del_range_payload(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, FcDelRange) {
    let range = FcDelRange {
        ino: cursor.next_u32(),
        logical_block: cursor.next_u32(),
        len: cursor.next_u32(),
    };
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&range.ino.to_le_bytes());
    payload.extend_from_slice(&range.logical_block.to_le_bytes());
    payload.extend_from_slice(&range.len.to_le_bytes());
    (payload, range)
}

fn build_structured_commit(data: &[u8]) -> (Vec<u8>, FcOperation, u32) {
    let mut cursor = ByteCursor::new(data);
    let operation_selector = cursor.next_u8() % 6;
    let tid = cursor.next_u32();
    let mut stream = Vec::new();
    let head_payload: Vec<_> = (0..16).map(|_| cursor.next_u8()).collect();
    stream.extend(build_fc_tag(0x0A, &head_payload));

    let expected = match operation_selector {
        0 => {
            let ino = cursor.next_u32();
            stream.extend(build_fc_tag(0x07, &ino.to_le_bytes()));
            FcOperation::InodeUpdate(ino)
        }
        1 => {
            let (payload, range) = build_extent_payload(&mut cursor);
            stream.extend(build_fc_tag(0x03, &payload));
            FcOperation::AddRange(range)
        }
        2 => {
            let (payload, range) = build_del_range_payload(&mut cursor);
            stream.extend(build_fc_tag(0x04, &payload));
            FcOperation::DelRange(range)
        }
        3 => {
            let (payload, dentry) = build_dentry_payload(&mut cursor);
            stream.extend(build_fc_tag(0x05, &payload));
            FcOperation::Create(dentry)
        }
        4 => {
            let (payload, dentry) = build_dentry_payload(&mut cursor);
            stream.extend(build_fc_tag(0x01, &payload));
            FcOperation::Link(dentry)
        }
        _ => {
            let (payload, dentry) = build_dentry_payload(&mut cursor);
            stream.extend(build_fc_tag(0x02, &payload));
            FcOperation::Unlink(dentry)
        }
    };

    let mut tail = Vec::with_capacity(8);
    tail.extend_from_slice(&tid.to_le_bytes());
    tail.extend_from_slice(&cursor.next_u32().to_le_bytes());
    stream.extend(build_fc_tag(0x09, &tail));

    (stream, expected, tid)
}

fn assert_clean_structured_commit(stream: &[u8], expected: &FcOperation, tid: u32) {
    let result = replay_fast_commit(stream).expect("structured fast-commit stream replays");
    assert_eq!(result.transactions_found, 1);
    assert_eq!(result.last_tid, tid);
    assert_eq!(result.blocks_scanned, 1);
    assert_eq!(result.incomplete_transactions, 0);
    assert!(!result.fallback_required);
    assert_eq!(result.operations.as_slice(), std::slice::from_ref(expected));
}

fn assert_structured_padding_oracles(stream: &[u8], expected: &FcOperation, tid: u32) {
    let mut zero_padded = stream.to_vec();
    zero_padded.extend_from_slice(&[0_u8; 32]);
    assert_clean_structured_commit(&zero_padded, expected, tid);

    let mut nonzero_tail = stream.to_vec();
    nonzero_tail.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    let result = replay_fast_commit(&nonzero_tail).expect("nonzero tail returns fallback result");
    assert_eq!(result.transactions_found, 1);
    assert_eq!(result.last_tid, tid);
    assert_eq!(result.incomplete_transactions, 0);
    assert!(result.fallback_required);
    assert_eq!(result.operations.as_slice(), std::slice::from_ref(expected));
}

fn assert_malformed_in_transaction_requires_fallback(data: &[u8]) {
    let mut cursor = ByteCursor::new(data);
    let mut stream = Vec::new();
    let head_payload: Vec<_> = (0..16).map(|_| cursor.next_u8()).collect();
    stream.extend(build_fc_tag(0x0A, &head_payload));
    stream.extend(build_fc_tag(0x07, &[cursor.next_u8(), cursor.next_u8()]));
    let mut tail = Vec::with_capacity(8);
    tail.extend_from_slice(&cursor.next_u32().to_le_bytes());
    tail.extend_from_slice(&cursor.next_u32().to_le_bytes());
    stream.extend(build_fc_tag(0x09, &tail));

    let result = replay_fast_commit(&stream).expect("malformed operation returns fallback result");
    assert!(result.operations.is_empty());
    assert_eq!(result.transactions_found, 0);
    assert_eq!(result.incomplete_transactions, 1);
    assert!(result.fallback_required);
}

fn assert_arbitrary_replay_determinism(data: &[u8]) {
    let first = replay_fast_commit(data);
    let second = replay_fast_commit(data);

    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(
                first, second,
                "fast-commit replay should be deterministic for successful parses"
            );

            assert!(
                first.transactions_found <= first.blocks_scanned,
                "committed transactions cannot exceed scanned HEAD blocks"
            );
            assert!(
                first.transactions_found + first.incomplete_transactions <= first.blocks_scanned,
                "each scanned HEAD can contribute at most one committed or discarded transaction"
            );
            assert!(
                first.operations.is_empty() || first.transactions_found > 0,
                "replayed operations require at least one committed transaction"
            );

            if first.transactions_found == 0 {
                assert_eq!(
                    first.last_tid, 0,
                    "without a committed transaction there must be no replayed tid"
                );
                assert!(
                    first.operations.is_empty(),
                    "operations should only be committed after a valid TAIL tag"
                );
            }

            if !first.fallback_required {
                assert_eq!(
                    first.incomplete_transactions, 0,
                    "clean replay should not discard incomplete transactions"
                );
            }
        }
        (Err(first), Err(second)) => {
            assert_eq!(
                first.to_string(),
                second.to_string(),
                "fast-commit replay should deterministically reject the same malformed input"
            );
        }
        _ => std::process::abort(),
    };
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let (stream, expected, tid) = build_structured_commit(data);
    assert_clean_structured_commit(&stream, &expected, tid);
    assert_structured_padding_oracles(&stream, &expected, tid);
    assert_malformed_in_transaction_requires_fallback(data);
    assert_arbitrary_replay_determinism(data);
});
