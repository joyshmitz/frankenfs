# bd-6m4bt safe scan optimization evidence

## Target

`bd-6m4bt` tracks the remaining safe-Rust SIMD/SWAR scan gap: `simd_capabilities()`
was detection-only, while hot byte scans still used scalar iterator patterns such
as `bytes.iter().all(|&byte| byte == 0)`.

`perf`/flamegraph collection remains blocked by `perf_event_paranoid=4`, so this
pass used a same-binary Criterion A/B over the exact production scalar all-zero
scan pattern before changing production code.

## Alien recommendation card

- Symptom: 4 KiB all-zero/tail-padding scans rely on scalar iterator checks.
- Primitive: broadword/SWAR byte scan over 16-byte chunks, compiled as safe
  `u128::from_ne_bytes` loads plus a scalar remainder.
- Source match: alien graveyard SIMD packing/broadword scan family, especially
  the SIMD metadata/search and vectorized byte-kernel entries.
- EV: Impact 4 x Confidence 5 x Reuse 3 / Effort 2 / Friction 1 = 30.0.
- Fallback: keep the existing scalar `iter().all` checks if the same-binary
  Criterion ratio is below Score 2.0 or if any parser behavior test changes.

## Alien-artifact proof obligations

For any byte slice `s`, `all_zero_bytes(s)` partitions `s` into disjoint
16-byte chunks plus one disjoint remainder. A 16-byte chunk converted with
`u128::from_ne_bytes` equals zero iff all 16 input bytes are zero. The remainder
uses the original scalar predicate. Therefore the helper returns true iff every
byte in the original slice is zero.

No ordering, tie-breaking, floating-point, or RNG behavior is introduced.

## Baseline and A/B

Accepted baseline/probe:
`zero_scan_ab_measurement.txt`, rch remote `vmi1149989`.

- Scalar all-zero 4 KiB: 1.7678 us mean [1.6801, 1.8576].
- Safe `u128` chunk all-zero 4 KiB: 134.59 ns mean [130.24, 139.06].
- Scalar late-nonzero 4 KiB: 1.3832 us mean [1.3256, 1.4468].
- Safe `u128` chunk late-nonzero 4 KiB: 116.27 ns mean [111.61, 120.90].

Rejected evidence:
`zero_scan_after_chunked_helper.txt` fell back to local after an rch SSH reset
and is not used for keep/reject decisions.

Accepted after:
`zero_scan_after_chunked_helper_remote.txt`, rch remote `vmi1227854`.

- Scalar all-zero 4 KiB: 2.0966 us mean [1.9961, 2.2104].
- Production `ffs_types::all_zero_bytes` all-zero 4 KiB: 145.80 ns mean
  [142.99, 148.73], 14.38x faster.
- Scalar late-nonzero 4 KiB: 2.1221 us mean [1.9362, 2.3706].
- Production `ffs_types::all_zero_bytes` late-nonzero 4 KiB: 154.05 ns mean
  [146.05, 164.22], 13.78x faster.

Score: Impact 4 x Confidence 5 / Effort 2 = 10.0, keep.

## Behavior proof

Isomorphism:

- Ordering preserved: yes. Directory parsing visits entries in the same offset
  order; only the boolean zero-padding predicate changed.
- Tie-breaking unchanged: N/A.
- Floating-point: N/A.
- RNG seeds: N/A.
- Error classes unchanged: yes. The same parser branches return the same
  `ParseError` variants; only the all-zero suffix predicate implementation
  changed.

Validation:

- `cargo fmt --package ffs-types --package ffs-ondisk --check`: passed.
- `cargo test -p ffs-types all_zero_bytes -- --nocapture`: 1/1 passed.
- `cargo test -p ffs-ondisk dir_block -- --nocapture`: 36/36 focused
  tests/proptests passed.
- `cargo check -p ffs-types -p ffs-ondisk --all-targets`: passed.
- `cargo clippy -p ffs-types -p ffs-ondisk --all-targets -- -D warnings`:
  passed.
- `git diff --check`: passed.
- `sha256sum -c conformance/fixtures/checksums.sha256`: passed.
- `sha256sum -c conformance/golden/checksums.sha256`: passed.
- `sha256sum -c tests/fixtures/golden/checksums.txt`: passed.
