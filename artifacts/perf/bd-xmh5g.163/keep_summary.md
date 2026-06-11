# bd-xmh5g.163 keep summary

## Target

- Crate: `ffs-repair`
- Benchmark row: `raptorq_decode_group_no_corruption_16blocks`
- Lever: return the empty `DecodeOutcome` before deriving `block_size`, `k`,
  and `repair_seed` when `corrupt_indices` is empty.

## Decision Measurements

Same-worker RCH remote `vmi1152480` controlled source-state pair:

| State | Artifact | Criterion time |
| --- | --- | --- |
| Baseline, pre-lever source state | `baseline_no_corruption_vmi1152480.txt` | `[219.47 ns, 247.44 ns, 290.49 ns]` |
| Candidate, optimized source state | `rebench_no_corruption_vmi1227854.txt` | `[34.107 ns, 36.683 ns, 39.784 ns]` |

The candidate artifact name is historical from an attempted worker pin. Its log
line shows `Selected worker: vmi1152480`, and the final line is
`[RCH] remote vmi1152480 (915.6s)`.

Speedup:

- Midpoint: `247.44 / 36.683 = 6.74x`
- Conservative lower/upper: `219.47 / 39.784 = 5.52x`

Ignored timing artifacts:

- `baseline_no_corruption_vmi1227854.txt`: valid pre-lever routing baseline on
  `vmi1227854`, not paired with same-worker after timing.
- `rebench_no_corruption_vmi1152480.txt`: selected `vmi1153651` and timed out
  during the benchmark; it is not decision evidence.

## Behavior Proof

- Ordering preserved: yes. Empty-corruption decode still returns an empty
  `recovered` vector and `complete=true`; all non-empty corrupt paths are below
  the unchanged branch and preserve existing recovery ordering.
- Tie-breaking unchanged: yes. Empty-corruption decode performs no row
  selection; all non-empty repair row selection and fallback ordering are
  unchanged.
- Floating-point identical: N/A.
- RNG seeds unchanged: yes. Empty-corruption decode no longer derives an unused
  seed; all non-empty paths still call `repair_seed(fs_uuid, group)` before
  coefficient generation.
- Golden output verified: marker-bounded `RAPTORQ_DECODE_GOLDEN` stdout SHA256
  stayed `5e11bf11a354338c346ceffaa88d681e03a0cd794bd4ffb280f31a14dc58608f`.

## Gates

- `cargo fmt --check -p ffs-repair`
- `git diff --check`
- RCH remote `vmi1227854`: `cargo test -j 1 -p ffs-repair decode_no_corruption_succeeds -- --nocapture`
- RCH remote `vmi1227854`: `cargo test -j 1 -p ffs-repair raptorq_decode_golden_report -- --nocapture`
- RCH remote `vmi1227854`: `cargo check -j 1 -p ffs-repair --all-targets`
- RCH remote `vmi1227854`: `cargo clippy -j 1 -p ffs-repair --all-targets -- -D warnings`

## Score

Kept. Score `20.9` using conservative Impact `5.52`, Confidence `0.95`, Effort
`0.25`: `5.52 * 0.95 / 0.25 = 20.98`.
