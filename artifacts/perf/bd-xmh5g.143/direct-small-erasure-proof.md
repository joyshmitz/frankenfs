# bd-xmh5g.143 - ffs-repair RaptorQ Direct Small-Erasure Decode

## Target

- Bead: `bd-xmh5g.143`
- Lever: direct safe-Rust GF(256) solve for RaptorQ decode when the corrupt source set has one or two unique blocks and `source_block_count <= 64`.
- Profile-backed hotspot: `raptorq_decode_group_16blocks` / `raptorq_decode_group_owned_symbols_16blocks`.
- Worker: `vmi1227854`

## Commands

Baseline from clean worktree `/data/projects/frankenfs-bd-xmh5g-143-baseline`:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env cargo bench -p ffs-repair --bench scrub_codec -- --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

After from patched worktree `/data/projects/frankenfs`:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env cargo bench -p ffs-repair --bench scrub_codec -- --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

Validation:

```bash
rustfmt --edition 2024 --check crates/ffs-repair/src/codec.rs
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo check -p ffs-repair --all-targets
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo clippy -p ffs-repair --all-targets -- -D warnings
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo test -p ffs-repair direct_small_erasure -- --nocapture
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_perf_pass6_repair cargo test -p ffs-repair codec -- --nocapture
```

Golden SHA validation:

```bash
(cd conformance/golden && sha256sum -c checksums.sha256)
(cd conformance/fixtures && sha256sum -c checksums.sha256)
```

## Criterion Results

All rows are Criterion mean point estimates from `vmi1227854`.

| Row | Baseline | After | Ratio |
| --- | ---: | ---: | ---: |
| `raptorq_decode_group_16blocks` | 5.360 ms | 4.143 ms | 1.29x faster |
| `raptorq_decode_group_owned_symbols_16blocks` | 5.607 ms | 3.930 ms | 1.43x faster |
| `raptorq_decode_group_no_corruption_16blocks` | 183.5 ns | 207.2 ns | 0.89x control |
| `raptorq_encode_group_16blocks` | 2.969 ms | 3.422 ms | 0.87x control |
| `lrc_encode_global_64blocks_8parity` | 265.4 us | 252.7 us | 1.05x control |

Notes:

- The no-corruption row returns before direct small-erasure decode dispatch, so its slower row is a same-worker run-to-run control movement rather than a changed path.
- Encode and LRC rows do not call the new decode path and are recorded only as controls.

## Isomorphism Proof

- Ordering preserved: yes. `recover_from_direct_solution` emits `corrupt_indices` in caller-provided order and preserves duplicates by mapping each requested index back to the unique solved slot.
- Tie-breaking unchanged: yes. The direct path returns only when the repair rows contain a nonzero 1x1 coefficient or the first full-rank 2x2 row pair. It validates the solved blocks against every supplied repair row before returning; otherwise it falls back to the existing inactivation decoder.
- Floating point identical: N/A. The solve is bytewise GF(256) arithmetic.
- RNG seeds unchanged: yes. Both basis encoders and the known-source encoder use the existing `repair_seed(fs_uuid, group)`.
- Error behavior preserved: yes. Length validation, insufficient redundancy checks, and full-decoder fallback remain in place. Invalid repair equations return `None` from plan selection and continue through the original decoder path.
- Goldens verified: `conformance/golden/checksums.sha256` and `conformance/fixtures/checksums.sha256` passed. Repair soak before/after checksum artifacts also remained identical: `e76e1fc1240ed05850e1894e4312fc881d3ebd71fe396f636ee68400b5b67e54`.

## Decision

Keep. The target corrupted decode rows improved 1.29x and 1.43x on the same worker with behavior proof and crate-scoped validation. Score: Impact 3 x Confidence 0.8 / Effort 1 = 2.4.
