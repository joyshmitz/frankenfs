# Perf Profiling Pass — Scenario Definition

> Run ID: `2026-06-01_plumfern` · Owner: PlumFern (cc) · Pass type: **measurement only**
> Hand-off target: `extreme-software-optimization` (one lever per change, behavior-proven).

## Why these scenarios

FrankenFS is a FUSE filesystem, but kernel FUSE mounting is denied on the
profiling host (`fusermount3: Permission denied`, same constraint the
2026-05-10 profile hit). The realistic, reproducible, FUSE-free workloads that
exercise the dominant code paths are the **CLI read/parse/validate** paths over
the canonical ext4 fixture, plus the **criterion microbenchmarks** that already
have statistical baselines.

This pass deliberately profiles a path the prior 2026-05-10 analysis did **not**
cover: `fsck -f` (full offline validate), which walks every group, inode,
bitmap, and extent and verifies checksums — the heaviest single-shot read path.

## Scenarios

### S1 — Full offline check (primary macro scenario)
- **Command:** `ffs fsck -f --json conformance/golden/ext4_8mb_reference.ext4`
- **Path exercised:** format detect → superblock/group-desc parse → per-group
  bitmap + inode walk → extent-tree validation → checksum verification.
- **Success metric:** p95 wall-clock latency (warm cache) + **peak RSS**.
- **Budget:** _populated from baseline_ (regression gate = baseline p95 × 1.10).

### S2 — Metadata info dump
- **Command:** `ffs info --groups --mvcc --journal --json conformance/golden/ext4_8mb_reference.ext4`
- **Path exercised:** superblock + all group descriptors + journal superblock +
  MVCC status assembly + JSON serialization.
- **Success metric:** p95 wall-clock latency (warm) + peak RSS.

### S3 — Microbenchmark hot paths (criterion, intra-operation)
- **Command:** `cargo bench -p <crate>` for the established 11 targets.
- **Success metric:** per-operation p50/throughput vs `benchmarks/baselines/latest.json`.
- Used for function-level attribution + to confirm which subsystems carry cost.

## Method
- Build: `release-perf` profile (`opt-level=3`, `lto=thin`, `debug=line-tables-only`,
  `strip=false`) with `RUSTFLAGS="-C force-frame-pointers=yes"`.
- Baseline: hyperfine `--warmup 5 --runs 25` per scenario → p50/p95/p99 + JSON export.
- Peak RSS: `/usr/bin/time -v` (Maximum resident set size).
- CPU hotspots: `samply record` (perf_event_paranoid=1 permits user-space stacks)
  over a repeated-scenario loop → flamegraph + ranked self-% table.
- All cargo builds/benches routed via `rch exec --`, crate-scoped.
- Same-host discipline; variance envelope ≤10% p95 drift = noise.

## Golden / correctness anchor
`conformance/golden/ext4_8mb_reference.json` is the checked-in metadata golden;
fsck/info output must remain consistent with it (the optimizer must prove
behavior unchanged after any lever).

## Out of scope (this pass)
No optimization. No kernel tuning beyond the already-permissive
`perf_event_paranoid=1`. Live kernel FUSE mount profiling (host-denied).
