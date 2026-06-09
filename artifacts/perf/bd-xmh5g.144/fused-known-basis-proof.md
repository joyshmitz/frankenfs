# bd-xmh5g.144 proof: fused direct-erasure known+basis encoder

## Target

Profile-backed residual after `bd-xmh5g.143`: `ffs-repair` RaptorQ
`decode_group` for the common 1-2 corrupt-block case still spent time building
separate `SystematicEncoder` solves for:

- the block-size known-source contribution, and
- each one-byte missing-source basis coefficient.

Alien/artifact primitive: batched RHS / product-space linear transform fusion
over GF(256). Because the RaptorQ constraint solve and repair projection are
linear per byte lane, one encoder over `block_size + missing_count` lanes can
carry the known contribution prefix and missing-basis coefficient suffixes
exactly.

## One Lever

`crates/ffs-repair/src/codec.rs` now builds one fused `SystematicEncoder` for
the direct small-erasure path:

- known source blocks occupy bytes `0..block_size`;
- corrupt source blocks have zero known bytes and a one-hot suffix lane;
- each repair projection is split into `known_contribution` plus the
  coefficients used by the tiny GF(256) solve.

The full inactivation-decoder fallback is unchanged.

## RCH Baseline

Command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_bd_xmh5g_144 cargo bench -p ffs-repair --bench scrub_codec -- raptorq_decode_group --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

RCH selected local fallback because no remote worker was admissible.

| Row | Before |
| --- | --- |
| `raptorq_decode_group_16blocks` | `[4.2856, 4.8516, 5.1633] ms` |
| `raptorq_decode_group_owned_symbols_16blocks` | `[3.8677, 3.9906, 4.1454] ms` |
| `raptorq_decode_group_no_corruption_16blocks` | `[169.10, 179.10, 187.22] ns` |

## RCH After

Same RCH command and same local fallback path.

| Row | After | Speedup |
| --- | --- | --- |
| `raptorq_decode_group_16blocks` | `[2.8445, 2.9338, 3.0647] ms` | 1.65x midpoint, 1.40x conservative |
| `raptorq_decode_group_owned_symbols_16blocks` | `[2.8359, 2.8765, 2.9222] ms` | 1.39x midpoint, 1.32x conservative |
| `raptorq_decode_group_no_corruption_16blocks` | `[151.31, 152.55, 154.64] ns` | unchanged fast no-corruption path |

## Behavior Isomorphism

- Ordering preserved: yes. `recover_from_direct_solution` still emits recovered
  blocks in the input `corrupt_indices` order, including duplicates.
- Tie-breaking unchanged: yes. Full-rank row selection still scans repair rows
  in input order and picks the first usable one-row or two-row basis.
- Floating point: N/A.
- RNG/seed behavior: unchanged. The fused encoder uses the same deterministic
  `repair_seed(fs_uuid, group)` seed.
- Fallback behavior: unchanged for unsupported sizes, invalid repair equations,
  singular/rank-deficient row sets, and failed full-row validation.
- Algebraic equivalence: `direct_known_basis_encoder_matches_separate_linear_projections`
  proves the fused prefix equals the old known-source encoder projection and
  each suffix lane equals the old one-byte missing-basis encoder coefficient for
  the same repair ESI.
- Full repair validation: unchanged. All supplied repair rows are still checked
  against the solved corrupt blocks before the direct path returns.

## Golden SHA Verification

```text
266a75f96df99a397f78bff54632acc9b5b025577392366d2cd90ee3f5ad4b42  crates/ffs-repair/src/snapshots/ffs_repair__scrub__tests__scrub_report_human_output.snap
8e8f33e7d37cca4bc7f156596c4ef9a910fe5c9b93d19186665c054b65aeb51b  crates/ffs-repair/tests/codec_corruption_fixtures.rs
39dbb35241b6374a121bcae93ab9f08dd739ed08846f8b6ddc82d67ed5df9323  crates/ffs-repair/baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_remote_artifacts/recovery_evidence.jsonl
```

## Gates

- `cargo fmt -p ffs-repair --check`
- `RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_bd_xmh5g_144 cargo check -p ffs-repair --all-targets`
  - remote `ovh-a`, pass
- `RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_bd_xmh5g_144 cargo test -p ffs-repair --lib -- --nocapture`
  - remote `vmi1227854`, 435 passed
- `RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_bd_xmh5g_144 cargo clippy -p ffs-repair --all-targets -- -D warnings`
  - RCH local fallback after a remote lint-only failure was fixed, pass

## Score

Score = Impact 4.1 x Confidence 0.9 / Effort 0.8 = 4.6.

Decision: keep and close `bd-xmh5g.144`.
