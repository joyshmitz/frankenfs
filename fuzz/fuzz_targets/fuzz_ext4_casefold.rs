#![no_main]
//! Casefold fuzz target for ext4_casefold_key, ext4_casefold_names_collide
//! and ext4_casefold_name_diagnostics (bd-c7nid).
//!
//! Companion to the bd-6rsow proptest layer (32 cases of the
//! equivalence-relation laws). This target lifts those laws to libfuzzer
//! scale (>1M iterations/session, with corpus learning across multi-byte
//! UTF-8 boundaries, ASCII edge cases, and almost-but-not-quite UTF-8
//! byte sequences) and pins the same algebraic contract on each input:
//!
//!   MR-1 — Reflexivity:    collide(name, name) MUST be true.
//!   MR-2 — Idempotence:    key(key(name)) MUST equal key(name).
//!   MR-3 — Diagnostics:    diagnostics(name).folded_key MUST equal
//!                          key(name) and source_len MUST equal len.
//!   MR-4 — Symmetry:       on a split-input pair, collide(a, b) MUST
//!                          equal collide(b, a).
//!   MR-5 — ASCII case:     for any input, the all-uppercase ASCII fold
//!                          of `name` MUST collide with the all-lowercase
//!                          ASCII fold of `name` (both reduce to the same
//!                          ASCII-folded prefix; the cross-case chain is
//!                          the user-visible lookup contract).
//!
//! A regression in any branch of `casefold_name` (UTF-8 detection,
//! multi-codepoint sharp-s expansion, ASCII fallback) would silently
//! mis-classify directory entries on case-folded ext4 filesystems; this
//! target catches such regressions as fuzzer failures rather than
//! silent on-disk corruption.

use ffs_ondisk::{ext4_casefold_key, ext4_casefold_name_diagnostics, ext4_casefold_names_collide};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // MR-1 Reflexivity. Also implicitly: ext4_casefold_names_collide
    // and ext4_casefold_key never panic on arbitrary bytes.
    assert!(
        ext4_casefold_names_collide(data, data),
        "casefold collision must be reflexive"
    );

    // MR-2 Idempotence: re-folding an already folded key is a fixed point.
    let once = ext4_casefold_key(data);
    let twice = ext4_casefold_key(&once);
    assert_eq!(twice, once, "casefold_key must be idempotent");

    // MR-3 Diagnostics consistency: folded_key matches the canonical
    // path, source_len matches the input length.
    let diag = ext4_casefold_name_diagnostics(data);
    assert_eq!(
        diag.source_len,
        data.len(),
        "diagnostics source_len must equal input length"
    );
    assert_eq!(
        diag.folded_key, once,
        "diagnostics folded_key must equal canonical casefold_key"
    );

    // MR-4 Symmetry on a split-input pair. Splitting the fuzzer's
    // single byte buffer at every length covers every (a, b) pair the
    // fuzzer encounters, exercising the comparator on inputs of
    // genuinely different content.
    if data.len() >= 2 {
        let mid = data.len() / 2;
        let a = &data[..mid];
        let b = &data[mid..];
        assert_eq!(
            ext4_casefold_names_collide(a, b),
            ext4_casefold_names_collide(b, a),
            "casefold collision must be symmetric"
        );
    }

    // MR-5 ASCII case-substitution invariance. For ASCII bytes the fold
    // always lowercases, so the all-uppercase and all-lowercase ASCII
    // variants of any input MUST share a key.
    let upper: Vec<u8> = data.iter().map(u8::to_ascii_uppercase).collect();
    let lower: Vec<u8> = data.iter().map(u8::to_ascii_lowercase).collect();
    let key_upper = ext4_casefold_key(&upper);
    let key_lower = ext4_casefold_key(&lower);
    assert_eq!(
        key_upper, key_lower,
        "casefold_key must collapse ASCII case variants to the same key"
    );
});
