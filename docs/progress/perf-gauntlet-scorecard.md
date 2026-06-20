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

## `bd-xmh5g.403` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-mvcc` code-first backlog row `bd-xmh5g.403`
Commit under measurement: `1cd8de6f`
RCH worker: `vmi1227854`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH:
`.rch-target-vmi1227854-pool-cbd309d7d1ec6129ad21bdb51108009f`

### Verdict

This row is release-ready only as a measured rejection. The fused SSI write-key
log construction lost every tested write-count row against the old prebuilt
`BTreeSet` path, so the production optimization was reverted. The Criterion A/B
rows remain in `wal_throughput` as negative-evidence guards.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 |
| Same-worker evidence | Yes, `vmi1227854` for all rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator exists for this internal SSI `CommittedTxnRecord.write_set` construction primitive |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/build guard after revert | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-mvcc --bench wal_throughput` passed on `vmi1227854`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-mvcc ssi -- --nocapture` passed on `hz2` with 70 filtered SSI lib tests, 1 evidence integration test, and 2 stress tests passing |
| Format guard | `cargo fmt -p ffs-mvcc --check` failed on existing formatting drift in unrelated `ffs-mvcc` benches/tests and distant test blocks; the `.403` revert hunk was not listed in the rustfmt diff and this commit does not broaden into a format cleanup |
| Release-readiness score for perf-superiority claims | 20 / 100: decisive negative Rust-internal evidence, no valid kernel comparator, no keep claim |
| Release-readiness score for this row's hygiene | 90 / 100: same-worker A/B completed, ratios ledgered, production reverted, retry predicate written, focused post-revert gates passed; package fmt drift remains pre-existing follow-up work |

### Measured Rows

| Bead | Workload | Old prebuild | New fused | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.403` | SSI write-key log, 64 writes | `437.77 ns` | `790.80 ns` | `0.554x` old/new | Reject: fused is `80.6%` slower |
| `bd-xmh5g.403` | SSI write-key log, 256 writes | `1.8957 us` | `4.1605 us` | `0.456x` old/new | Reject: fused is `119.5%` slower |
| `bd-xmh5g.403` | SSI write-key log, 1024 writes | `8.0965 us` | `24.173 us` | `0.335x` old/new | Reject: fused is `198.6%` slower |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes how FrankenFS constructs the in-memory SSI `CommittedTxnRecord.write_set`
for `commit_ssi_internal`; ext4/btrfs-kernel does not expose an equivalent
timed primitive. A whole-filesystem kernel write benchmark would include syscall,
VFS, journal, allocator, and page-cache behavior, and would still not isolate
this lever because FrankenFS's current write path uses plain `commit`, not
`commit_ssi`.

### Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-mvcc \
  --bench wal_throughput -- \
  mvcc_commit_ssi_writekey_log_ab

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-mvcc --bench wal_throughput

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-mvcc ssi -- --nocapture

cargo fmt -p ffs-mvcc --check
```

## `bd-xmh5g.400` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-btrfs` code-first backlog row `bd-xmh5g.400`
Commit under measurement: `e55bb16e`
RCH Criterion worker: `ovh-a`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH:
`.rch-target-ovh-a-pool-42ea7743fa151ef0fd4b694270dc5239`

### Verdict

This row is release-ready only as a measured rejection. Moving the owned
`BtrfsCowNode` child vector into the production `DagNode` was slower than the
old double-clone construction on the existing realistic btrfs writeback DAG
benchmark, so the production lever was reverted. The same A/B benchmark remains
as a guard against rediscovering the moved-child shape.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 |
| Same-worker evidence | Yes, `ovh-a` for all benchmark rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator exists for this Rust-internal `WriteDependencyDag` child-vector materialization primitive |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/build guard after revert | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` passed on `hz1`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` passed on `hz2` with 37 passed / 0 failed; local `cargo fmt -p ffs-btrfs --check` passed |
| Release-readiness score for perf-superiority claims | 20 / 100: decisive negative Rust-internal evidence, no valid kernel comparator, no keep claim |
| Release-readiness score for this row's hygiene | 95 / 100: same-worker A/B completed, ratios ledgered, production reverted, retry predicate written, focused post-revert gates and formatting passed |

### Measured Rows

| Bead | Workload | Old double-clone | New moved-child | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.400` | DAG build, old double-clone model vs single-clone model | `89.928 us` | `112.58 us` | `0.799x` old/new | Reject: single-clone model is `25.2%` slower |
| `bd-xmh5g.400` | DAG build, old double-clone model vs production moved-child path | `89.928 us` | `110.91 us` | `0.811x` old/new | Reject: production moved-child path is `23.3%` slower |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes how FrankenFS builds an in-memory btrfs metadata writeback DAG from the
safe Rust `InMemoryCowBtrfsTree` snapshot. Linux btrfs does not expose an
equivalent timed primitive, and a whole-filesystem btrfs writeback benchmark
would include VFS, page-cache, allocator, checksum, and device latency without
isolating `WriteDependencyDag::collect_nodes`.

The prior broad vs-kernel attempt on this branch captured a kernel ext4 read
baseline but could not FUSE-mount FrankenFS in the execution environment. That
artifact is useful as environment context only; it is not evidence for this
in-memory btrfs DAG construction lever.

### Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-btrfs \
  --bench writeback_dag_order -- \
  writeback_dag_build_child_vector_ab

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture

cargo fmt -p ffs-btrfs --check
```

## `bd-xmh5g.389` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-a`)
Scope: `ffs-inode` code-first backlog row `bd-xmh5g.389`
Base commit under closeout: `f064ef29`
RCH Criterion worker: `vmi1227854`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`
Remote target dir used by RCH:
`.rch-target-vmi1227854-pool-cbd309d7d1ec6129ad21bdb51108009f`

### Verdict

This row is release-ready only as a measured rejection. `BlockBuf::into_inner()`
showed a small 4 KiB win but regressed the wider 16 KiB and 64 KiB rows that the
same owned-buffer materialization primitive claims to cover. The three
production `ffs-inode` RMW sites are back on `as_slice().to_vec()`; the
Criterion A/B benchmark remains as a guard.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 |
| Same-worker evidence | Yes, `vmi1227854` for all benchmark rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator exists for this Rust-internal owned-buffer materialization primitive |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/build guard after revert | `cargo fmt -p ffs-inode --check` passed locally; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo check -p ffs-inode --all-targets` passed on `hz1`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo test -p ffs-inode --lib -- --nocapture` passed on `ovh-a` with 129 passed / 0 failed; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings` passed on `hz2`; focused post-clippy test `inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes` passed on `ovh-a` |
| Known adjacent gate limitation | Full dependency-lint clippy without `--no-deps` is blocked by an unrelated existing `ffs-extent` `clippy::significant_drop_tightening` lint at `crates/ffs-extent/src/lib.rs:1487`; this addendum does not take ownership of that crate |
| Release-readiness score for perf-superiority claims | 20 / 100: decisive negative Rust-internal evidence, no valid kernel comparator, no keep claim |
| Release-readiness score for this row's hygiene | 95 / 100: same-worker A/B completed, ratios ledgered, production reverted, retry predicate written, focused post-revert gates and formatting passed |

### Measured Rows

| Bead | Workload | Old copy | New move | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.389` | Owned `BlockBuf` materialization, 4096 B | `576.96 ns` | `534.36 ns` | `1.080x` old/new | Small 4 KiB win, not enough to carry the wider rows |
| `bd-xmh5g.389` | Owned `BlockBuf` materialization, 16384 B | `1.3722 us` | `1.5633 us` | `0.878x` old/new | Reject: move is `13.9%` slower |
| `bd-xmh5g.389` | Owned `BlockBuf` materialization, 65536 B | `3.7725 us` | `4.2885 us` | `0.880x` old/new | Reject: move is `13.7%` slower |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes how FrankenFS materializes an owned Rust `BlockBuf` into a mutable `Vec`
inside three inode read-modify-write helpers. Linux ext4/btrfs does not expose
an equivalent timed primitive, and a whole-filesystem inode update benchmark
would include syscall, VFS, journal, allocator, page-cache, and block-layer
latency without isolating the `into_inner()` vs `to_vec()` choice.

### Commands

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release-perf -p ffs-mvcc \
  --bench blockbuf_into_inner -- \
  blockbuf_into_inner_vs_to_vec

cargo fmt -p ffs-inode --check

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo check -p ffs-inode --all-targets

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-inode --lib -- --nocapture

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings

RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-inode --lib \
  inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes -- --nocapture
```

## `bd-f759f` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-btrfs` code-first backlog row `bd-f759f`
Code-first implementation commit: `c7b28426`
Commit under measurement: `44e41db2`
RCH Criterion worker: `ovh-a`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH:
`.rch-target-ovh-a-pool-42ea7743fa151ef0fd4b694270dc5239`

### Verdict

This row is release-ready as a measured Rust-internal keep. The production
capacity-sized `HashSet` visited set is materially faster than the old
`BTreeSet` visited membership model on the existing btrfs metadata writeback DAG
scheduler benchmark, while the old-model oracle and WB-I1 prefix checks preserve
the deterministic flush-order contract. No revert was applied.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 1 / 1 |
| Same-worker evidence | Yes, `ovh-a` for both A/B arms in one Criterion run |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no valid kernel comparator exists for this Rust-internal `WriteDependencyDag` visited-set membership primitive |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Conformance/build guard after keep | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` passed on `hz1`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` passed on `hz2` with 37 passed / 0 failed; local `cargo fmt -p ffs-btrfs --check` passed |
| Release-readiness score for perf-superiority claims | 60 / 100: decisive same-worker Rust-internal keep, exact old-model order guard, but no valid direct ext4/btrfs-kernel comparator for the primitive |
| Release-readiness score for this row's hygiene | 98 / 100: A/B benchmark completed, ratio ledgered, conformance/check/fmt passed, production kept without broadening the change |

### Measured Rows

| Bead | Workload | Old `BTreeSet` | New `HashSet` | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-f759f` | Reverse-topological writeback DAG scheduling | `18.969 us` | `13.220 us` | `1.435x` old/new; `0.697x` new/old latency | Keep: production `HashSet` is `30.3%` lower latency |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes the in-memory membership set used by FrankenFS
`WriteDependencyDag::reverse_topological_order`; Linux btrfs does not expose an
equivalent timed primitive. A whole-filesystem btrfs writeback benchmark would
include VFS, page-cache, allocator, checksum, journal, and device latency, and
would not isolate the visited-set membership choice.

The prior broad vs-kernel mount/read artifacts remain environment context only
for this row. They are not evidence for or against this isolated scheduler
membership lever.

### Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-btrfs \
  --bench writeback_dag_order -- \
  writeback_dag_order_hashset_ab

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture

cargo fmt -p ffs-btrfs --check
```

---

## WIN — parallel-read chunk default 256 -> 32 blocks on real many-core hw (cc 2026-06-19, bd-vffrx / 3671522c)

The `FFS_READ_CHUNK_BLOCKS` default splits a large contiguous run into block-aligned chunks read concurrently
on the rayon pool. c110c39b cut it 16 MiB -> 1 MiB (256 blocks) after the 4096 default was found tuned for a
~2-core box; the same under-fill bug survived one level down. On a real **64-core** box (rayon pool ~62
threads), 256 blocks yields only ~32 chunks for a 32 MiB read — about half the pool — leaving most of the
I/O-overlap on the table. Dropped the default to **32 blocks = 128 KiB** at BOTH parallel-read sites (ext4
`read_file_data`, btrfs `btrfs_read_file`).

Measured (engine `duration_us`, A/B via `FFS_READ_CHUNK_BLOCKS` on one fresh release binary, min of N,
default-32 vs forced-256):

| Workload | warm 32 vs 256 | cold 32 vs 256 |
|---|---|---|
| ext4 128 MiB extent read   | **1.41x** (32.9 -> 23.3 ms) | **1.31x** (53.9 -> 41.2 ms) |
| btrfs 100 MiB uncompressed  | **3.17x** (106 -> 33.5 ms)  | **1.69x** (117 -> 69.1 ms)  |

Byte-identical output (md5 of a 128 MiB ext4 read matches the source for chunk 1/32/256/4096). ffs-core
release tests green. Output is invariant in chunk size — only parallel-read granularity changes; the env
override is preserved. Narrows the warm-seq kernel gap (ext4 warm ~2.4x -> read-only ~19.6ms vs kernel ~8ms).
Residual gap root-caused to `FileByteDevice` pread-per-chunk syscall + page-cache copy (perf: sys 0.277s >>
user 0.108s, IPC 0.35) — see bd-jgbam (mmap-backed ByteDevice deep swing). Adaptive (core-count-scaled) chunk
sizing evaluated and rejected as overfit — see perf-negative-results.md.

cod-b 2026-06-20 `bd-27x9a` verification on a real btrfs image with one 100 MiB uncompressed extent
(`/data/tmp/btrperf_1231197.img:/m.bin`) keeps the direction but not the domination claim. Local hyperfine,
warm/shared-cache, release-perf CLI: kernel btrfs `dd` mean `48.7 ms`; current ffs default-32 mean `76.3 ms`;
forced old 256-block chunk mean `91.1 ms`. So current ffs is still `1.57x` slower than kernel on this comparator,
while remaining `1.19x` faster than forced old chunking. RCH primitive proof is stronger but Rust-internal:
`btrfs_uncompressed_read_overlap_16extents` on `ovh-a` measured serial `5.0966 ms` vs parallel `405.27 us`
median (`12.58x`) with byte-identical output asserted by the bench. A follow-up direct-overwrite `FileByteDevice`
fast path was measured and reverted (`76.3 -> 75.7 ms`, `0.8%`, inside noise; forced 256 flipped faster under the
same noisy run). Release-readiness verdict: chunking is a real keep versus the old setting, but btrfs-kernel
domination remains open and should route to file-device/syscall/copy work, not more chunk retuning.
