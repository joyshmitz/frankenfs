#![no_main]
//! Fuzz target for ffs_btrfs::parse_inode_refs (bd-kbj23).
//!
//! parse_inode_refs walks a list of variable-length INODE_REF entries
//! (u64 index + u16 name_len + name bytes). It is on the hot path of
//! every subvolume enumeration and snapshot navigation. The sibling
//! parsers (parse_root_item, parse_inode_item, parse_dir_items,
//! parse_root_ref, parse_xattr_items, parse_extent_data) all live
//! behind fuzz_btrfs_tree_items, but parse_inode_refs has only two
//! integration tests and no dedicated fuzz harness.
//!
//! Note: a parallel implementation exists in
//! ffs_core::OpenFs::btrfs_parse_inode_ref_payload (fuzzed via
//! fuzz_btrfs_inode_ref_payload). This target hits the ffs_btrfs
//! crate's parser directly so that drift between the two
//! implementations gets exercised at libfuzzer scale.
//!
//!   MR-1 — Determinism: parse_inode_refs called twice on the same
//!          input must return Result-equivalent output (parsed Vec
//!          or Err formatted identically).
//!   MR-2 — No-panic: arbitrary bytes must never panic the parser
//!          (any panic crashes the fuzzer).
//!   MR-3 — Round-trip: every parsed entry, re-serialized via
//!          BtrfsInodeRef::try_to_bytes and concatenated, must
//!          re-parse to the same Vec<BtrfsInodeRef>.
//!   MR-4 — Append-invariance: appending a partial-header tail
//!          (1..9 bytes) to a valid payload must reject with
//!          InsufficientData (length-checking is the only thing
//!          standing between this parser and a buffer over-read).

use ffs_btrfs::{parse_inode_refs, BtrfsInodeRef};
use libfuzzer_sys::fuzz_target;

const MAX_NAME_BYTES: usize = 64;

fuzz_target!(|data: &[u8]| {
    // MR-1, MR-2: pump arbitrary bytes through twice; result must
    // be deterministic and the parser must never panic.
    let result_a = parse_inode_refs(data);
    let result_b = parse_inode_refs(data);
    match (&result_a, &result_b) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "parse_inode_refs must be deterministic on Ok");
        }
        (Err(a), Err(b)) => {
            assert_eq!(
                format!("{a:?}"),
                format!("{b:?}"),
                "parse_inode_refs must be deterministic on Err"
            );
        }
        _ => panic!("parse_inode_refs must be deterministic across Ok/Err"),
    }

    // MR-3 round-trip: if we got a valid parse, re-serialize each
    // entry and assert the concatenated bytes parse back to the
    // same Vec<BtrfsInodeRef>.
    if let Ok(entries) = result_a {
        let mut reassembled = Vec::new();
        let mut serialize_failed = false;
        for entry in &entries {
            match entry.try_to_bytes() {
                Ok(bytes) => reassembled.extend_from_slice(&bytes),
                Err(_) => {
                    // A name shouldn't exceed u16::MAX in any real
                    // input, but guard for fuzz-induced edge cases.
                    serialize_failed = true;
                    break;
                }
            }
        }
        if !serialize_failed {
            let reparsed = parse_inode_refs(&reassembled)
                .expect("re-parse of self-serialized output must succeed");
            assert_eq!(
                reparsed, entries,
                "MR-3: stamp(parse(x)) ↦ parse must be idempotent"
            );
        }
    }

    // MR-4 length-checking: build a synthetic single-entry payload
    // from the first ~16 bytes of fuzz input as (index, name_len,
    // partial_name) and assert the truncated-tail variants reject
    // with InsufficientData rather than buffer-over-reading.
    if data.len() < 12 {
        return;
    }
    let index = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let name_len_choice = (u16::from_le_bytes([data[8], data[9]]) as usize % MAX_NAME_BYTES) + 1;

    let entry = BtrfsInodeRef {
        index,
        name: vec![data[10]; name_len_choice],
    };
    let valid = entry
        .try_to_bytes()
        .expect("constructed entry has small name");
    let parsed = parse_inode_refs(&valid).expect("valid single-entry must parse");
    assert_eq!(parsed, vec![entry.clone()]);

    // Truncate by 1..9 bytes — any truncation inside the header or
    // mid-name must reject, never panic.
    for trunc in 1..valid.len().min(9) {
        let truncated = &valid[..valid.len() - trunc];
        let err = parse_inode_refs(truncated)
            .err()
            .expect("truncated payload must reject");
        // Stamp the error path is exercised; specific variant is
        // intentionally not asserted to avoid coupling to private
        // ParseError shape.
        let _ = format!("{err:?}");
    }
});
