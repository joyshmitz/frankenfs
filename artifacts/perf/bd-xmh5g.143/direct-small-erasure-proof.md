# bd-xmh5g.143 - ffs-repair RaptorQ Direct Small-Erasure Decode

## Target

- Bead: `bd-xmh5g.143`
- Lever: direct safe-Rust GF(256) solve for RaptorQ decode when the corrupt source set has one or two unique blocks and `source_block_count <= 64`.
- Profile-backed hotspot: `raptorq_decode_group_16blocks` / `raptorq_decode_group_owned_symbols_16blocks`.
- Final keep gate worker: `ovh-a`
- Corroborating profile/baseline worker: `vmi1227854`

## Commands

Final baseline from clean worktree `/data/projects/frankenfs-bd-xmh5g-143-baseline`
(RCH selected `ovh-a`):

```bash
RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair_ovha_baseline cargo bench -p ffs-repair --bench scrub_codec -- --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

Final after run from patched worktree `/data/projects/frankenfs` (RCH selected
`ovh-a`):

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo bench -p ffs-repair --bench scrub_codec -- --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

Corroborating clean baseline from `/data/projects/frankenfs-bd-xmh5g-143-baseline`
on `vmi1227854`:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair_ovha_baseline cargo bench -p ffs-repair --bench scrub_codec -- --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

Validation:

```bash
cargo fmt --check -p ffs-repair
git diff --check -- crates/ffs-repair/src/codec.rs
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo check -p ffs-repair --all-targets
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo clippy -p ffs-repair --all-targets -- -D warnings
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo test -p ffs-repair codec -- --nocapture
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo test -p ffs-repair -- --nocapture
```

Golden SHA validation:

```bash
git show HEAD:crates/ffs-repair/src/snapshots/ffs_repair__scrub__tests__scrub_report_human_output.snap | sha256sum
sha256sum crates/ffs-repair/src/snapshots/ffs_repair__scrub__tests__scrub_report_human_output.snap
sha256sum crates/ffs-repair/tests/codec_corruption_fixtures.rs
sha256sum crates/ffs-repair/baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_remote_artifacts/recovery_evidence.jsonl
```

## Criterion Results

Final keep gate rows are Criterion lower/midpoint/upper estimates from
same-worker `ovh-a`.

| Row | Baseline | After | Ratio |
| --- | ---: | ---: | ---: |
| `raptorq_decode_group_16blocks` | [5.3660, 5.6875, 6.1589] ms | [3.2563, 3.2752, 3.2968] ms | 1.74x midpoint, 1.63x conservative |
| `raptorq_decode_group_owned_symbols_16blocks` | [5.5824, 5.7001, 5.9253] ms | [3.2315, 3.2986, 3.4837] ms | 1.73x midpoint, 1.60x conservative |
| `raptorq_decode_group_no_corruption_16blocks` | [146.72, 147.97, 149.75] ns | [144.64, 144.80, 145.00] ns | unchanged control |
| `raptorq_encode_group_16blocks` | [2.5714, 2.5768, 2.5830] ms | [2.6264, 2.7436, 2.9748] ms | non-target control |
| `lrc_encode_global_64blocks_8parity` | [302.50, 306.80, 312.38] us | [316.85, 369.07, 444.55] us | non-target noisy control |

Notes:

- The no-corruption row returns before direct small-erasure decode dispatch and
  is unchanged on the final same-worker pair.
- Encode and LRC rows do not call the new decode path and are recorded only as
  controls.
- Independent clean baseline on `vmi1227854` measured
  `raptorq_decode_group_16blocks` [5.2063, 5.4811, 5.7854] ms and
  `raptorq_decode_group_owned_symbols_16blocks` [5.0656, 5.4635, 6.0215] ms,
  consistent with the original profile-backed hotspot scale.

## Isomorphism Proof

- Ordering preserved: yes. `recover_from_direct_solution` emits `corrupt_indices` in caller-provided order and preserves duplicates by mapping each requested index back to the unique solved slot.
- Tie-breaking unchanged: yes. The direct path returns only when the repair rows contain a nonzero 1x1 coefficient or the first full-rank 2x2 row pair. It validates the solved blocks against every supplied repair row before returning; otherwise it falls back to the existing inactivation decoder.
- Floating point identical: N/A. The solve is bytewise GF(256) arithmetic.
- RNG seeds unchanged: yes. Both basis encoders and the known-source encoder use the existing `repair_seed(fs_uuid, group)`.
- Error behavior preserved: yes. Length validation, insufficient redundancy checks, and full-decoder fallback remain in place. Invalid repair equations return `None` from plan selection and continue through the original decoder path.
- Goldens verified: `scrub_report_human_output.snap` matched `HEAD` exactly,
  sha256 `266a75f96df99a397f78bff54632acc9b5b025577392366d2cd90ee3f5ad4b42`.
  Additional stable fixture digests:
  `codec_corruption_fixtures.rs`
  `8e8f33e7d37cca4bc7f156596c4ef9a910fe5c9b93d19186665c054b65aeb51b`;
  `recovery_evidence.jsonl`
  `39dbb35241b6374a121bcae93ab9f08dd739ed08846f8b6ddc82d67ed5df9323`.

## Decision

Keep. The target corrupted decode rows improved 1.74x and 1.73x midpoint on
the same worker, with conservative lower/upper ratios still 1.63x and 1.60x.
Score: Impact 4.6 x Confidence 0.9 / Effort 0.6 = 6.9.
