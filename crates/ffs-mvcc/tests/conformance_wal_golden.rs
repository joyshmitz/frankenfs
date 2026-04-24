//! Conformance Family C: MVCC WAL on-disk record format golden round-trip.
//!
//! The WAL is the durability boundary for MVCC commits: a single-byte
//! drift in the `encode_commit` / `decode_commit` layout silently loses
//! or duplicates committed transactions on replay. This suite freezes
//! every public layout point via golden byte fixtures and requires
//! `encode(decode(bytes)) == bytes` bit-exact across the full reachable
//! surface (header + commit records with 0 / 1 / N writes, with both
//! zero-length and non-trivial payloads).
//!
//! See the module-level docstring in `crates/ffs-mvcc/src/wal.rs` for the
//! canonical layout diagram. Known divergences documented in
//! `DISCREPANCIES.md`.

use ffs_mvcc::wal::{
    CHECKSUM_TYPE_CRC32C, DecodeResult, HEADER_SIZE, MIN_COMMIT_RECORD_SIZE, RECORD_TYPE_COMMIT,
    WAL_MAGIC, WAL_VERSION, WalCommit, WalHeader, WalWrite, commit_byte_size, decode_commit,
    decode_header, encode_commit, encode_header,
};
use ffs_types::{BlockNumber, CommitSeq, TxnId};

// Helpers

/// Assert the encode -> decode -> encode cycle is bit-exact and the decoded
/// commit equals `expected`.
fn assert_commit_roundtrip(fixture_name: &str, expected: &WalCommit) {
    let encoded = encode_commit(expected).expect("encode");
    let decoded = match decode_commit(&encoded) {
        DecodeResult::Commit(c) => c,
        other => panic!("{fixture_name}: expected Commit, got {other:?}"),
    };
    assert_eq!(
        &decoded, expected,
        "{fixture_name}: decode(encode(x)) diverged from x"
    );
    let reencoded = encode_commit(&decoded).expect("reencode");
    assert_eq!(
        reencoded, encoded,
        "{fixture_name}: encode/decode/encode diverged"
    );
    // `commit_byte_size` must match the actual on-disk length.
    let reported = commit_byte_size(&encoded).expect("commit_byte_size");
    assert_eq!(
        reported,
        encoded.len(),
        "{fixture_name}: commit_byte_size != encoded.len()"
    );
}

// Header layout (16 bytes fixed)

/// Golden WAL header bytes. Layout is frozen by the crate-level docstring:
///
///   offset 0..4  : magic = 0x4D56_4357 ("MVCW" LE-scrambled)
///   offset 4..6  : version = 1
///   offset 6..8  : checksum_type = 0 (CRC32C)
///   offset 8..16 : reserved zeros
const GOLDEN_WAL_HEADER: [u8; 16] = [
    // magic 0x4D56_4357 LE
    0x57, 0x43, 0x56, 0x4D, // 0..4
    // version = 1 LE
    0x01, 0x00, // 4..6
    // checksum_type = 0 LE
    0x00, 0x00, // 6..8
    // reserved
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8..16
];

#[test]
fn golden_wal_header_bitexact() {
    let default_header = WalHeader::default();
    let encoded = encode_header(&default_header);
    assert_eq!(
        encoded, GOLDEN_WAL_HEADER,
        "default header encode diverged from fixture"
    );

    let decoded = decode_header(&GOLDEN_WAL_HEADER).expect("decode header");
    assert_eq!(decoded.magic, WAL_MAGIC);
    assert_eq!(decoded.version, WAL_VERSION);
    assert_eq!(decoded.checksum_type, CHECKSUM_TYPE_CRC32C);

    // Round-trip
    let reencoded = encode_header(&decoded);
    assert_eq!(reencoded, GOLDEN_WAL_HEADER, "encode/decode diverged");
}

#[test]
fn wal_header_magic_mismatch_rejected() {
    let mut bad = GOLDEN_WAL_HEADER;
    bad[0] ^= 0xFF; // corrupt magic
    let err = decode_header(&bad).unwrap_err();
    assert!(format!("{err:?}").contains("magic"));
}

#[test]
fn wal_header_version_mismatch_rejected() {
    let mut bad = GOLDEN_WAL_HEADER;
    bad[4] = 99; // bogus version
    let err = decode_header(&bad).unwrap_err();
    assert!(format!("{err:?}").contains("version"));
}

#[test]
fn wal_header_checksum_type_mismatch_rejected() {
    let mut bad = GOLDEN_WAL_HEADER;
    bad[6] = 99; // bogus checksum type
    let err = decode_header(&bad).unwrap_err();
    assert!(format!("{err:?}").contains("checksum type"));
}

#[test]
fn wal_header_short_payload_rejected() {
    for len in 0..HEADER_SIZE {
        let err = decode_header(&GOLDEN_WAL_HEADER[..len]).unwrap_err();
        assert!(
            format!("{err:?}").contains("too short"),
            "len={len}: expected 'too short', got {err:?}"
        );
    }
}

// Empty-writes commit (minimum-size record)

#[test]
fn golden_wal_commit_zero_writes_roundtrip() {
    let commit = WalCommit {
        commit_seq: CommitSeq(7),
        txn_id: TxnId(42),
        writes: Vec::new(),
    };
    let encoded = encode_commit(&commit).expect("encode");

    // Total size: record_len(4) + type(1) + commit_seq(8) + txn_id(8) +
    // num_writes(4) + crc(4) = 29 bytes. MIN_COMMIT_RECORD_SIZE = 29.
    assert_eq!(encoded.len(), MIN_COMMIT_RECORD_SIZE);

    // Byte-level layout assertions:
    // record_len field (offset 0..4) = total - 4
    let record_len = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
    assert_eq!(
        usize::try_from(record_len).expect("record_len fits usize"),
        encoded.len() - 4
    );

    // record_type (offset 4) = 1 (COMMIT)
    assert_eq!(encoded[4], RECORD_TYPE_COMMIT);

    // commit_seq (offset 5..13) = 7 LE
    assert_eq!(
        u64::from_le_bytes([
            encoded[5],
            encoded[6],
            encoded[7],
            encoded[8],
            encoded[9],
            encoded[10],
            encoded[11],
            encoded[12],
        ]),
        7
    );

    // txn_id (offset 13..21) = 42 LE
    assert_eq!(
        u64::from_le_bytes([
            encoded[13],
            encoded[14],
            encoded[15],
            encoded[16],
            encoded[17],
            encoded[18],
            encoded[19],
            encoded[20],
        ]),
        42
    );

    // num_writes (offset 21..25) = 0
    assert_eq!(
        u32::from_le_bytes([encoded[21], encoded[22], encoded[23], encoded[24]]),
        0
    );

    // CRC (offset 25..29) should verify.
    assert_commit_roundtrip("zero-writes commit", &commit);
}

// Single-write commit

#[test]
fn golden_wal_commit_single_write_roundtrip() {
    let commit = WalCommit {
        commit_seq: CommitSeq(0x1234_5678_9ABC_DEF0),
        txn_id: TxnId(1),
        writes: vec![WalWrite {
            block: BlockNumber(100),
            data: vec![0xAB; 64],
        }],
    };
    assert_commit_roundtrip("single-write commit", &commit);

    // Verify explicit byte layout: record_len + body(25 + write_len + 4) must
    // match encoded total. write_len = 8 (block) + 4 (len) + 64 (payload).
    let encoded = encode_commit(&commit).expect("encode");
    let expected_total = 4 + 1 + 8 + 8 + 4 + (8 + 4 + 64) + 4;
    assert_eq!(encoded.len(), expected_total);
}

// Multi-write commit (tests ordering + offset accounting)

#[test]
fn golden_wal_commit_multi_write_preserves_ordering() {
    let commit = WalCommit {
        commit_seq: CommitSeq(100),
        txn_id: TxnId(200),
        writes: vec![
            WalWrite {
                block: BlockNumber(1),
                data: vec![0xAA; 16],
            },
            WalWrite {
                block: BlockNumber(2),
                data: vec![0xBB; 32],
            },
            WalWrite {
                block: BlockNumber(3),
                data: vec![0xCC; 48],
            },
        ],
    };
    assert_commit_roundtrip("multi-write commit", &commit);

    // Decode and verify order preserved.
    let encoded = encode_commit(&commit).expect("encode");
    let decoded = match decode_commit(&encoded) {
        DecodeResult::Commit(c) => c,
        other => panic!("expected Commit, got {other:?}"),
    };
    assert_eq!(decoded.writes.len(), 3);
    assert_eq!(decoded.writes[0].block.0, 1);
    assert_eq!(decoded.writes[1].block.0, 2);
    assert_eq!(decoded.writes[2].block.0, 3);
    assert_eq!(decoded.writes[0].data, vec![0xAA; 16]);
    assert_eq!(decoded.writes[1].data, vec![0xBB; 32]);
    assert_eq!(decoded.writes[2].data, vec![0xCC; 48]);
}

#[test]
fn golden_wal_commit_zero_length_payload_per_write_roundtrips() {
    // Edge case: writes with empty `data` payloads. Kernel WAL analogues
    // (JBD2 revoke blocks) use this shape as an implicit delete marker.
    let commit = WalCommit {
        commit_seq: CommitSeq(5),
        txn_id: TxnId(5),
        writes: vec![
            WalWrite {
                block: BlockNumber(10),
                data: Vec::new(),
            },
            WalWrite {
                block: BlockNumber(11),
                data: Vec::new(),
            },
        ],
    };
    assert_commit_roundtrip("empty-payload writes", &commit);
}

// Corruption / partial-record detection

#[test]
fn wal_commit_crc_mismatch_reported_as_corrupted() {
    let commit = WalCommit {
        commit_seq: CommitSeq(1),
        txn_id: TxnId(2),
        writes: vec![WalWrite {
            block: BlockNumber(42),
            data: vec![0x11, 0x22, 0x33, 0x44],
        }],
    };
    let mut encoded = encode_commit(&commit).expect("encode");
    // Flip a bit in the middle of the payload; CRC won't match.
    let mid = encoded.len() / 2;
    encoded[mid] ^= 0xFF;
    match decode_commit(&encoded) {
        DecodeResult::Corrupted(msg) => {
            assert!(
                msg.contains("CRC mismatch") || msg.contains("crc"),
                "expected CRC error, got: {msg}"
            );
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

#[test]
fn wal_commit_truncated_mid_record_reported_as_need_more() {
    let commit = WalCommit {
        commit_seq: CommitSeq(1),
        txn_id: TxnId(2),
        writes: vec![WalWrite {
            block: BlockNumber(1),
            data: vec![0u8; 32],
        }],
    };
    let full = encode_commit(&commit).expect("encode");

    // Truncate to half the record; decoder should ask for more.
    let half = &full[..full.len() / 2];
    match decode_commit(half) {
        DecodeResult::NeedMore(n) => {
            assert_eq!(n, full.len(), "NeedMore must return full record size");
        }
        other => panic!("expected NeedMore, got {other:?}"),
    }
}

#[test]
fn wal_commit_zero_length_with_nonzero_tail_reported_as_corrupted() {
    // 4-byte record_len = 0 but tail has non-zero bytes (simulating disk
    // corruption after a genuine end-of-data marker).
    let mut bytes = vec![0u8; 16];
    // bytes[0..4] = 0 (record_len)
    bytes[8] = 0xFF; // corrupt the tail
    match decode_commit(&bytes) {
        DecodeResult::Corrupted(msg) => {
            assert!(
                msg.contains("zero record length"),
                "expected zero-len-nonzero-tail error, got: {msg}"
            );
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

#[test]
fn wal_commit_empty_input_reports_end_of_data() {
    match decode_commit(&[]) {
        DecodeResult::EndOfData => {}
        other => panic!("expected EndOfData on empty input, got {other:?}"),
    }
}

#[test]
fn wal_commit_all_zeros_tail_reports_end_of_data() {
    let zeros = vec![0u8; 256];
    match decode_commit(&zeros) {
        DecodeResult::EndOfData => {}
        other => panic!("expected EndOfData on all-zero tail, got {other:?}"),
    }
}

#[test]
fn wal_commit_record_len_below_minimum_reported_as_corrupted() {
    // record_len = 1 (way below the 25-byte minimum body size)
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4] = 0xFF; // non-zero tail so it's not taken as EOF
    match decode_commit(&bytes) {
        DecodeResult::Corrupted(msg) => {
            assert!(
                msg.contains("too small"),
                "expected 'too small' error, got: {msg}"
            );
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

#[test]
fn wal_commit_unknown_record_type_reported_as_corrupted() {
    // Build a valid-shaped record but with record_type = 99
    let commit = WalCommit {
        commit_seq: CommitSeq(1),
        txn_id: TxnId(1),
        writes: Vec::new(),
    };
    let mut encoded = encode_commit(&commit).expect("encode");
    // record_type is at offset 4. Flip it.
    encoded[4] = 99;
    // Recompute CRC so we get past the CRC check and hit the type-check.
    let body_start = 4;
    let crc_offset = encoded.len() - 4;
    let new_crc = crc32c::crc32c(&encoded[body_start..crc_offset]);
    encoded[crc_offset..crc_offset + 4].copy_from_slice(&new_crc.to_le_bytes());

    match decode_commit(&encoded) {
        DecodeResult::Corrupted(msg) => {
            assert!(
                msg.contains("unknown record type"),
                "expected type error, got: {msg}"
            );
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

#[test]
fn wal_commit_num_writes_past_body_capacity_reported_as_corrupted() {
    // A malicious/malformed record claiming thousands of writes in a tiny body
    // would make a naive parser allocate and loop. The parser must early-reject.
    let commit = WalCommit {
        commit_seq: CommitSeq(1),
        txn_id: TxnId(1),
        writes: vec![WalWrite {
            block: BlockNumber(1),
            data: vec![0u8; 0],
        }],
    };
    let mut encoded = encode_commit(&commit).expect("encode");
    // num_writes field is at offset 4 (record_len) + 1 (type) + 8 (commit_seq)
    // + 8 (txn_id) = 21.
    encoded[21..25].copy_from_slice(&1_000_000u32.to_le_bytes());
    // Recompute CRC.
    let body_start = 4;
    let crc_offset = encoded.len() - 4;
    let new_crc = crc32c::crc32c(&encoded[body_start..crc_offset]);
    encoded[crc_offset..crc_offset + 4].copy_from_slice(&new_crc.to_le_bytes());

    match decode_commit(&encoded) {
        DecodeResult::Corrupted(msg) => {
            assert!(
                msg.contains("num_writes") && msg.contains("exceeds"),
                "expected num_writes-overflow rejection, got: {msg}"
            );
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

// Extremal CommitSeq / TxnId round-trip (u64 bounds)

#[test]
fn wal_commit_u64_bounds_roundtrip() {
    let commit = WalCommit {
        commit_seq: CommitSeq(u64::MAX - 1),
        txn_id: TxnId(u64::MAX - 1),
        writes: vec![WalWrite {
            block: BlockNumber(u64::MAX),
            data: vec![0xFF; 4],
        }],
    };
    assert_commit_roundtrip("u64-bounds commit", &commit);
}

// commit_byte_size contract

#[test]
fn commit_byte_size_matches_encoded_length() {
    for num_writes in 0_u8..5 {
        let writes: Vec<WalWrite> = (0..num_writes)
            .map(|i| WalWrite {
                block: BlockNumber(u64::from(i)),
                data: vec![i; usize::from(i) * 17],
            })
            .collect();
        let commit = WalCommit {
            commit_seq: CommitSeq(1),
            txn_id: TxnId(1),
            writes,
        };
        let encoded = encode_commit(&commit).expect("encode");
        let reported = commit_byte_size(&encoded).expect("commit_byte_size");
        assert_eq!(
            reported,
            encoded.len(),
            "commit_byte_size != len for num_writes={num_writes}"
        );
    }
}

#[test]
fn commit_byte_size_returns_none_for_short_input() {
    // Less than 4 bytes: cannot even read record_len.
    for len in 0..4 {
        assert!(commit_byte_size(&vec![0u8; len]).is_none());
    }
}
