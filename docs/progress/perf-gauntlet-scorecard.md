# Perf Gauntlet Scorecard

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-journal` code-first backlog rows `bd-xmh5g.406` and `bd-xmh5g.404`
Commit under measurement: `01872c46`
RCH worker: `ovh-a`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH: `.rch-target-ovh-a-pool-2beeb9204616d289df744a9cc897c5df`

## Verdict

This cluster is release-ready only as a measured rejection. Both production
optimizations were benchmarked with same-worker Criterion runs and reverted
because the realistic rows lost. The A/B benchmark rows remain as guards so the
same levers are not rediscovered and retried without new evidence.

## Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined | 2 |
| RCH Criterion rows completed | 2 / 2 |
| Same-worker evidence | Yes, `ovh-a` for both runs |
| Direct ext4/btrfs-kernel ratios | 0 / 2 direct; no kernel comparator exists for these internal JBD2/Rust materialization microprimitives |
| Production levers kept | 0 |
| Production levers rejected/reverted | 2 |
| Conformance/build guard after revert | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-journal` passed |
| Release-readiness score for perf-superiority claims | 35 / 100: honest local evidence, but no direct kernel ratio for these primitives and both tested levers lost on realistic rows |
| Release-readiness score for this cluster's hygiene | 95 / 100: measurements recorded, dead ends ledgered, production paths reverted, crate check passed |

## Measured Rows

| Bead | Workload | Old | New | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.406` | Commit checksum, 1024 B block | `220.86 ns` | `158.52 ns` | `1.393x` old/new | Win, but not the normal block size |
| `bd-xmh5g.406` | Commit checksum, 4096 B block | `595.89 ns` | `742.02 ns` | `0.803x` old/new | Reject: segmented path is `24.5%` slower |
| `bd-xmh5g.406` | Commit checksum, 16384 B block | `2.8403 us` | `2.2867 us` | `1.242x` old/new | Win, but outweighed by the 4 KiB row |
| `bd-xmh5g.404` | Replay materialize, 16 blocks | `3.9888 us` | `4.2087 us` | `0.948x` old/new | Reject: `into_inner` is `5.5%` slower |
| `bd-xmh5g.404` | Replay materialize, 64 blocks | `21.282 us` | `22.110 us` | `0.963x` old/new | Reject: `3.9%` slower |
| `bd-xmh5g.404` | Replay materialize, 256 blocks | `71.482 us` | `77.324 us` | `0.924x` old/new | Reject: `8.2%` slower |

## Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator was available for these two internals:

- `bd-xmh5g.406` changes the Rust implementation strategy for verifying a JBD2
  commit-block checksum. The repository has kernel conformance tests for
  on-disk behavior, but no timed kernel JBD2 checksum microharness.
- `bd-xmh5g.404` changes a Rust `BlockBuf` materialization detail after journal
  block reads. There is no kernel-equivalent primitive to time.

The existing broad mount reference artifact
`benchmarks/baselines/history/20260503-bd-rchk5-3-mount-sudo-comparison.json`
is non-isolating for these commits and remains worse than the 2026-02-18
reference: cold-mount p99 `171096 us` vs `36029 us` (`4.75x` slower),
warm-mount p99 `300114 us` vs `58275 us` (`5.15x` slower), and recovery p99
`74217 us` vs `35020 us` (`2.12x` slower). Those rows must not be used as
evidence for or against either micro-optimization.

## Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-journal \
  --bench journal_replay_apply_io_overlap -- \
  journal_commit_checksum_zero_field_clone_vs_segmented

RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-journal \
  --bench journal_replay_apply_io_overlap -- \
  journal_replay_blockbuf_materialize

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  cargo check -p ffs-journal
```
