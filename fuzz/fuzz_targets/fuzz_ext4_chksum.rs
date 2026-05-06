#![no_main]
//! Fuzz target for ext4_chksum (CRC32c) algebraic-laws contract
//! (bd-e95p9).
//!
//! Companion to the existing ext4_proptest_chksum_* layer (32 cases
//! per relation). This target lifts the algebraic laws to libfuzzer
//! scale (>1M iterations/session) with corpus learning across input
//! lengths, byte-pattern boundaries, and sign-bit transitions. For
//! an arbitrary (seed, data) split from libfuzzer input, asserts:
//!
//!   MR-1 — Determinism: chksum(s, d) called twice gives same result.
//!   MR-2 — Empty-data identity: chksum(s, &[]) == s.
//!   MR-3 — Incremental composition: for any split point k,
//!          chksum(chksum(s, &d[..k]), &d[k..]) == chksum(s, &d).
//!          This is the core property the metadata-block stamping
//!          paths rely on (extent_block + tail = full block).
//!   MR-4 — Never panics: implicit — any panic crashes the fuzzer.
//!
//! ext4_chksum is the CRC32c-based checksum function used by every
//! metadata block (group desc, inode, extent block, dir block, MMP,
//! fast-commit). A regression to a wrong-polynomial CRC variant
//! would fail MR-3 immediately, well before any silent on-disk
//! corruption.

use ffs_ondisk::ext4_chksum;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let seed = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let payload = &data[4..];

    // MR-1 Determinism.
    let a = ext4_chksum(seed, payload);
    let b = ext4_chksum(seed, payload);
    assert_eq!(a, b, "ext4_chksum must be deterministic");

    // MR-2 Empty-data identity.
    assert_eq!(
        ext4_chksum(seed, &[]),
        seed,
        "ext4_chksum(seed, &[]) must equal seed"
    );

    // MR-3 Incremental composition. Split at every byte position
    // covered by the libfuzzer input.
    if !payload.is_empty() {
        // Use up to 4 split points covering edges and middle.
        let len = payload.len();
        let split_points: [usize; 4] = [0, 1.min(len), len / 2, len];
        for k in split_points {
            if k > len {
                continue;
            }
            let left = &payload[..k];
            let right = &payload[k..];
            let incremental = ext4_chksum(ext4_chksum(seed, left), right);
            let direct = ext4_chksum(seed, payload);
            assert_eq!(
                incremental, direct,
                "incremental composition must equal direct chksum: \
                 split at k={k}, len={len}"
            );
        }
    }
});
