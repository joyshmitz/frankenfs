#![no_main]
use ffs_mvcc::wal::{
    commit_byte_size, decode_commit, decode_header, encode_commit, encode_header, DecodeResult,
    WalCommit, WalHeader, WalWrite, CHECKSUM_TYPE_CRC32C, HEADER_SIZE, WAL_MAGIC, WAL_VERSION,
};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeaderOutcome {
    Header {
        magic: u32,
        version: u16,
        checksum_type: u16,
    },
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommitOutcome {
    Commit {
        commit_seq: u64,
        txn_id: u64,
        writes: Vec<(u64, Vec<u8>)>,
    },
    NeedMore(usize),
    Corrupted(String),
    EndOfData,
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn raw_u16(data: &[u8], offset: usize) -> u16 {
    le_u16(data, offset).unwrap_or(0)
}

fn raw_u32(data: &[u8], offset: usize) -> u32 {
    le_u32(data, offset).unwrap_or(0)
}

fn raw_u64(data: &[u8], offset: usize) -> u64 {
    le_u64(data, offset).unwrap_or(0)
}

fn normalize_header(data: &[u8]) -> HeaderOutcome {
    match decode_header(data) {
        Ok(header) => HeaderOutcome::Header {
            magic: header.magic,
            version: header.version,
            checksum_type: header.checksum_type,
        },
        Err(err) => HeaderOutcome::Error(err.to_string()),
    }
}

fn normalize_commit(data: &[u8]) -> CommitOutcome {
    match decode_commit(data) {
        DecodeResult::Commit(commit) => CommitOutcome::Commit {
            commit_seq: commit.commit_seq.0,
            txn_id: commit.txn_id.0,
            writes: commit
                .writes
                .into_iter()
                .map(|write| (write.block.0, write.data))
                .collect(),
        },
        DecodeResult::NeedMore(needed) => CommitOutcome::NeedMore(needed),
        DecodeResult::Corrupted(reason) => CommitOutcome::Corrupted(reason),
        DecodeResult::EndOfData => CommitOutcome::EndOfData,
    }
}

fn expected_commit_outcome(commit: &WalCommit) -> CommitOutcome {
    CommitOutcome::Commit {
        commit_seq: commit.commit_seq.0,
        txn_id: commit.txn_id.0,
        writes: commit
            .writes
            .iter()
            .map(|write| (write.block.0, write.data.clone()))
            .collect(),
    }
}

fn flip_byte(data: &mut [u8], offset: usize) -> bool {
    let Some(byte) = data.get_mut(offset) else {
        return false;
    };
    *byte ^= 1;
    true
}

fn fuzz_commit(data: &[u8]) -> WalCommit {
    let write_count = usize::from(data.first().copied().unwrap_or(0) % 4);
    let mut cursor = 1_usize;
    let mut writes = Vec::with_capacity(write_count);

    for write_idx in 0..write_count {
        let block = BlockNumber(raw_u64(data, cursor));
        cursor = cursor.saturating_add(8);
        let data_len = usize::from(data.get(cursor).copied().unwrap_or(0) % 17);
        cursor = cursor.saturating_add(1);

        let mut payload = Vec::with_capacity(data_len);
        for byte_idx in 0..data_len {
            let fallback = u8::try_from(write_idx ^ byte_idx).unwrap_or(0xA5);
            payload.push(
                data.get(cursor.saturating_add(byte_idx))
                    .copied()
                    .unwrap_or(fallback),
            );
        }
        cursor = cursor.saturating_add(data_len);
        writes.push(WalWrite {
            block,
            data: payload,
        });
    }

    WalCommit {
        commit_seq: CommitSeq(raw_u64(data, cursor)),
        txn_id: TxnId(raw_u64(data, cursor.saturating_add(8))),
        writes,
    }
}

fn assert_header_invariants(data: &[u8]) {
    assert_eq!(
        normalize_header(data),
        normalize_header(data),
        "WAL header decoding must be deterministic"
    );

    let default_header = WalHeader::default();
    let encoded_default = encode_header(&default_header);
    assert_eq!(encoded_default.len(), HEADER_SIZE);
    assert_eq!(
        normalize_header(&encoded_default),
        HeaderOutcome::Header {
            magic: WAL_MAGIC,
            version: WAL_VERSION,
            checksum_type: CHECKSUM_TYPE_CRC32C,
        }
    );

    let fuzz_header = WalHeader {
        magic: raw_u32(data, 0),
        version: raw_u16(data, 4),
        checksum_type: raw_u16(data, 6),
    };
    let encoded_fuzz = encode_header(&fuzz_header);
    let decoded_fuzz = normalize_header(&encoded_fuzz);
    if fuzz_header == default_header {
        assert_eq!(
            decoded_fuzz,
            HeaderOutcome::Header {
                magic: WAL_MAGIC,
                version: WAL_VERSION,
                checksum_type: CHECKSUM_TYPE_CRC32C,
            }
        );
    } else {
        assert!(
            matches!(decoded_fuzz, HeaderOutcome::Error(_)),
            "non-canonical encoded WAL headers must be rejected"
        );
    }
}

fn assert_arbitrary_commit_decode_invariants(data: &[u8]) {
    let decoded = normalize_commit(data);
    assert_eq!(
        decoded,
        normalize_commit(data),
        "WAL commit decoding must be deterministic"
    );
    assert_eq!(
        commit_byte_size(data),
        commit_byte_size(data),
        "WAL commit byte-size detection must be deterministic"
    );

    match decoded {
        CommitOutcome::Commit { .. } => {
            let frame_size = commit_byte_size(data);
            assert!(
                frame_size.is_some(),
                "successfully decoded commits must expose a frame size"
            );
            if let Some(size) = frame_size {
                assert!(size <= data.len());
                if let Some(prefix) = data.get(..size) {
                    assert_eq!(
                        normalize_commit(prefix),
                        normalize_commit(data),
                        "a decoded commit must be determined entirely by its advertised frame"
                    );
                }
            }
        }
        CommitOutcome::NeedMore(needed) => {
            assert!(needed > data.len());
            if data.len() >= 4 {
                assert_eq!(commit_byte_size(data), Some(needed));
            } else {
                assert_eq!(commit_byte_size(data), None);
            }
        }
        CommitOutcome::EndOfData => {
            assert_eq!(commit_byte_size(data), None);
        }
        CommitOutcome::Corrupted(_) => {}
    }
}

fn assert_encoded_commit_invariants(data: &[u8]) {
    let commit = fuzz_commit(data);
    let Ok(encoded) = encode_commit(&commit) else {
        return;
    };
    let expected = expected_commit_outcome(&commit);

    assert_eq!(commit_byte_size(&encoded), Some(encoded.len()));
    assert_eq!(
        normalize_commit(&encoded),
        expected,
        "encoded WAL commits must decode to their source commit"
    );

    for trunc_len in [
        0_usize,
        1,
        3,
        4,
        encoded.len() / 2,
        encoded.len().saturating_sub(1),
    ] {
        if trunc_len >= encoded.len() {
            continue;
        }
        let Some(prefix) = encoded.get(..trunc_len) else {
            continue;
        };
        let outcome = normalize_commit(prefix);
        if trunc_len == 0 {
            assert_eq!(outcome, CommitOutcome::EndOfData);
            continue;
        }
        assert!(
            matches!(outcome, CommitOutcome::NeedMore(_)),
            "truncated encoded WAL commit produced unexpected outcome: {outcome:?}"
        );
        if let CommitOutcome::NeedMore(needed) = outcome {
            if trunc_len < 4 {
                assert_eq!(needed, 4);
                assert_eq!(commit_byte_size(prefix), None);
            } else {
                assert_eq!(needed, encoded.len());
                assert_eq!(commit_byte_size(prefix), Some(encoded.len()));
            }
        }
    }

    let mut corrupted = encoded.clone();
    if flip_byte(&mut corrupted, 4) {
        assert!(
            matches!(normalize_commit(&corrupted), CommitOutcome::Corrupted(_)),
            "single-byte corruption inside an encoded WAL commit must reject"
        );
        assert_eq!(commit_byte_size(&corrupted), Some(encoded.len()));
    }
}

fn assert_zero_record_len_invariants() {
    assert_eq!(normalize_commit(&[0, 0, 0, 0]), CommitOutcome::EndOfData);
    assert_eq!(commit_byte_size(&[0, 0, 0, 0]), None);

    let nonzero_tail = [0_u8, 0, 0, 0, 1];
    assert!(
        matches!(normalize_commit(&nonzero_tail), CommitOutcome::Corrupted(_)),
        "zero record length with non-zero tail bytes must reject"
    );
    assert_eq!(commit_byte_size(&nonzero_tail), None);
}

fuzz_target!(|data: &[u8]| {
    assert_header_invariants(data);
    assert_arbitrary_commit_decode_invariants(data);
    assert_encoded_commit_invariants(data);
    assert_zero_record_len_invariants();
});
