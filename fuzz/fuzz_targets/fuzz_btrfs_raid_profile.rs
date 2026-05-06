#![no_main]
//! Raid-profile fuzz target for `BtrfsRaidProfile::from_chunk_type` /
//! `data_copies` / `is_redundant` (bd-luedn).
//!
//! Companion to bd-kansf proptest layer (32 cases of the algebraic
//! laws). This target lifts those laws to libfuzzer scale (>1M
//! iterations/session, with corpus learning across multi-bit RAID
//! combinations, mask-edge inputs, and pathological bit patterns)
//! and pins the same contract on each input:
//!
//!   MR-1 — Determinism:        from_chunk_type(x) called twice
//!                              MUST give the same result.
//!   MR-2 — Non-RAID-bit:       toggling bits OUTSIDE RAID_MASK MUST
//!                              NOT change the classification.
//!   MR-3 — Single is default:  clearing all RAID bits MUST yield
//!                              Single.
//!   MR-4 — data_copies bounds: 1 ≤ data_copies ≤ 4 for ALL profiles.
//!   MR-5 — Redundancy:         is_redundant ⇔ (data_copies > 1 OR
//!                              profile is Raid5/Raid6).
//!   MR-6 — Never panics:       implicit — any panic crashes the
//!                              fuzzer.
//!
//! The classifier is on every read path on a multi-device btrfs
//! filesystem; a regression that swapped two arms of the if/else
//! cascade or consulted DATA/METADATA bits would silently mis-route
//! reads to the wrong stripes. This target catches such regressions
//! as fuzzer failures rather than silent on-disk corruption.

use ffs_ondisk::{chunk_type_flags, BtrfsRaidProfile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut chunk_bytes = [0_u8; 8];
    let chunk_len = data.len().min(chunk_bytes.len());
    chunk_bytes[..chunk_len].copy_from_slice(&data[..chunk_len]);

    let mut xor_bytes = [0_u8; 8];
    if data.len() > chunk_bytes.len() {
        let xor_len = (data.len() - chunk_bytes.len()).min(xor_bytes.len());
        xor_bytes[..xor_len].copy_from_slice(&data[chunk_bytes.len()..chunk_bytes.len() + xor_len]);
    }

    // Two zero-padded u64s: the first as the chunk_type under
    // classification, the second as the bit-XOR mask used for MR-2
    // invariance. Padding keeps the classifier exercised from an empty
    // corpus instead of discarding short inputs.
    let chunk_type = u64::from_le_bytes(chunk_bytes);
    let xor_mask = u64::from_le_bytes(xor_bytes);

    // MR-1 Determinism + MR-6 implicit no-panic.
    let profile_a = BtrfsRaidProfile::from_chunk_type(chunk_type);
    let profile_b = BtrfsRaidProfile::from_chunk_type(chunk_type);
    assert_eq!(
        profile_a, profile_b,
        "BtrfsRaidProfile::from_chunk_type must be deterministic"
    );

    // MR-2 Non-RAID-bit invariance: only RAID_MASK bits matter.
    let non_raid_mask = !chunk_type_flags::RAID_MASK;
    let toggle = xor_mask & non_raid_mask;
    let profile_toggled = BtrfsRaidProfile::from_chunk_type(chunk_type ^ toggle);
    assert_eq!(
        profile_a, profile_toggled,
        "BtrfsRaidProfile must depend ONLY on RAID_MASK bits, but \
         toggling non-RAID bits changed the classification"
    );

    // MR-3 Single is the default.
    let cleared = chunk_type & !chunk_type_flags::RAID_MASK;
    assert_eq!(
        BtrfsRaidProfile::from_chunk_type(cleared),
        BtrfsRaidProfile::Single,
        "Clearing all RAID bits must yield BtrfsRaidProfile::Single"
    );

    // MR-4 data_copies bounded.
    let copies = profile_a.data_copies();
    assert!(
        (1..=4).contains(&copies),
        "data_copies must be in 1..=4, got {copies} for {profile_a:?}"
    );

    // MR-5 Redundancy contract.
    let mirror_redundant = copies > 1;
    let parity_redundant = matches!(profile_a, BtrfsRaidProfile::Raid5 | BtrfsRaidProfile::Raid6);
    assert_eq!(
        profile_a.is_redundant(),
        mirror_redundant || parity_redundant,
        "is_redundant ⇔ (data_copies > 1 OR Raid5/Raid6) violated for {profile_a:?}"
    );
});
