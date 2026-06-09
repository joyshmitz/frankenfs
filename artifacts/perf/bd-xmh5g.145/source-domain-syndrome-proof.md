# bd-xmh5g.145 Source-Domain Syndrome Direct Decode

## Target

- Bead: `bd-xmh5g.145`
- Crate: `ffs-repair`
- Hotspot: `raptorq_decode_group_16blocks` and
  `raptorq_decode_group_owned_symbols_16blocks`
- Primitive: source-domain syndrome projection / dual-code coefficient rows
- Lever: replace the widened `block_size + missing_count` direct encoder solve
  with a K-byte source coefficient encoder and cached repair residual syndromes.

## Baseline

Command:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_bd_xmh5g_145 \
  cargo bench -p ffs-repair --bench scrub_codec -- \
  raptorq_decode_group --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

RCH route: local fallback (`critical_pressure=1,active_project_exclusion=1`).

Rows:

- `raptorq_decode_group_16blocks`: `[2.8986, 2.9594, 3.0035] ms`
- `raptorq_decode_group_owned_symbols_16blocks`: `[2.9056, 2.9954, 3.1448] ms`
- `raptorq_decode_group_no_corruption_16blocks`: `[153.85, 157.16, 161.12] ns`

## After

Command: same as baseline.

RCH route: same local fallback.

Rows:

- `raptorq_decode_group_16blocks`: `[551.69, 562.51, 581.12] us`
- `raptorq_decode_group_owned_symbols_16blocks`: `[546.73, 553.77, 563.39] us`
- `raptorq_decode_group_no_corruption_16blocks`: `[159.41, 161.35, 164.16] ns`

## Delta

- `raptorq_decode_group_16blocks`: 5.26x midpoint speedup; 4.99x conservative
  lower/upper speedup.
- `raptorq_decode_group_owned_symbols_16blocks`: 5.41x midpoint speedup; 5.16x
  conservative lower/upper speedup.
- `raptorq_decode_group_no_corruption_16blocks`: unchanged path; minor ns-scale
  noise outside the optimized corrupt-block branch.

## Isomorphism Proof

- Ordering preserved: yes. `recover_from_direct_solution` still iterates the
  original `corrupt_indices` slice and emits duplicates in caller order.
- Tie-breaking unchanged: yes. `select_full_rank_pair` still scans repair rows
  in input order and selects the first full-rank pair.
- Floating point: N/A. The path is byte/GF(256) arithmetic only.
- RNG seeds unchanged: yes. The encoder still uses `repair_seed(fs_uuid, group)`.
- Invalid ESI behavior preserved: yes. Direct-row selection still calls
  `InactivationDecoder::repair_equation`; invalid rows fall back to the generic
  decoder/error path instead of returning a direct solution.
- Linear projection equivalence: proven by
  `codec::tests::direct_source_coefficients_match_fused_known_basis_projection`,
  which compares the K-byte source coefficient encoder against the previous
  fused known+basis encoder for the same ESIs.
- Repair-row validation unchanged in effect: every supplied repair row still
  validates against the solved missing blocks before the direct path returns.

## Golden SHA256

```text
266a75f96df99a397f78bff54632acc9b5b025577392366d2cd90ee3f5ad4b42  crates/ffs-repair/src/snapshots/ffs_repair__scrub__tests__scrub_report_human_output.snap
8e8f33e7d37cca4bc7f156596c4ef9a910fe5c9b93d19186665c054b65aeb51b  crates/ffs-repair/tests/codec_corruption_fixtures.rs
39dbb35241b6374a121bcae93ab9f08dd739ed08846f8b6ddc82d67ed5df9323  crates/ffs-repair/baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_remote_artifacts/recovery_evidence.jsonl
```

## Gates

- `cargo fmt -p ffs-repair --check`
- RCH `cargo check -p ffs-repair --all-targets`
- RCH `cargo test -p ffs-repair --lib -- --nocapture`: 435 passed
- RCH `cargo clippy -p ffs-repair --all-targets -- -D warnings`

## Score

- Impact: 4.7
- Confidence: 0.95
- Effort: 0.5
- Score: 8.9

Decision: keep.
