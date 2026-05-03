# Performance Baseline Manifest (bd-rchk5.1)

This manifest defines what counts as performance evidence for FrankenFS
and which artifacts must accompany every published baseline. It is
versioned (see "Manifest version" below) so future runs can be compared
apples-to-apples against this contract.

The machine-readable source of truth is
[`benchmarks/performance_baseline_manifest.json`](../../benchmarks/performance_baseline_manifest.json).
Validate it without running heavyweight benchmarks:

```bash
cargo run -p ffs-harness -- validate-performance-baseline-manifest \
  --manifest benchmarks/performance_baseline_manifest.json \
  --artifact-root artifacts/performance/dry-run \
  --out artifacts/performance/manifest_report.json \
  --artifact-out artifacts/performance/sample_artifact_manifest.json
```

The validator expands every command template, checks workload ids,
capability names, thresholds, metric units, environment fields, aggregatable
artifact fields, and emits a sample shared QA artifact manifest compatible with
the operational artifact schema from `bd-rchk0.4.1`.

## Manifest version

`v1` — initial baseline contract. Increment for any change to the
**workload list**, **environment-field schema**, or **artifact format**.

## Coverage matrix

A complete baseline run produces a numerical result for every cell in
this matrix. Cells marked SKIP must publish the skip reason as part
of the run artifact.

| Workstream      | Workload                                  | Owning bench                                                          | Image / dataset                                                |
|-----------------|-------------------------------------------|-----------------------------------------------------------------------|----------------------------------------------------------------|
| Block I/O       | direct sequential 4K read                 | `crates/ffs-block/benches/arc_cache.rs`                               | 64 MiB synthetic + 4K page workload                            |
| Block I/O       | direct sequential 4K write                | (extend `arc_cache.rs`)                                               | 64 MiB synthetic                                               |
| Block I/O       | random 4K read mix                        | `crates/ffs-block/benches/arc_cache.rs`                               | 64 MiB synthetic + 80% read/20% write                          |
| ARC cache       | warm-cache read latency                   | `crates/ffs-block/benches/arc_cache.rs`                               | 256 KiB working set vs ARC capacity                            |
| ARC cache       | cold-cache miss path                      | `crates/ffs-block/benches/arc_cache.rs`                               | working set > ARC capacity                                     |
| MVCC            | optimistic commit (no conflict)           | `crates/ffs-mvcc/benches/wal_throughput.rs`                           | 1k-block append-only workload                                  |
| MVCC            | conflict-detection rate                   | (extend `wal_throughput.rs`)                                          | concurrent writers, hot-block contention                       |
| MVCC            | merge-proof success rate                  | (extend `wal_throughput.rs`)                                          | append-only proof variant                                      |
| Repair / scrub  | encode throughput (LRC)                   | `crates/ffs-repair/benches/scrub_codec.rs`                            | group_size × group_count × global_parity matrix                |
| Repair / scrub  | decode throughput (LRC)                   | `crates/ffs-repair/benches/scrub_codec.rs`                            | corrupt 1, k/2, and k blocks                                   |
| Repair / scrub  | symbol refresh staleness latency          | (new bench — bd-TBD)                                                  | rolling refresh interval × block-group count                   |
| Allocator       | bitmap find_free                          | `crates/ffs-alloc/benches/bitmap_ops.rs`                              | 128-byte bitmap, varied density                                |
| Allocator       | batch allocation                          | `crates/ffs-alloc/benches/batch_alloc.rs`                             | 1k-allocation batch                                            |
| BTree           | bw_tree insert / lookup                   | `crates/ffs-btree/benches/bwtree_vs_locked.rs`                        | 1k-page workload                                               |
| Extent          | resolve logical→physical                  | `crates/ffs-extent/benches/extent_resolve.rs`                         | varied extent-tree depth                                       |
| CLI inspect     | metadata parse                            | `crates/ffs-harness/benches/metadata_parse.rs`                        | conformance fixtures                                           |
| CLI inspect     | on-disk parse (cold)                      | `crates/ffs-harness/benches/ondisk_parse.rs`                          | mkfs-generated 64 MiB image                                    |
| FUSE mount      | metadata-only readdir                     | `crates/ffs-fuse/benches/mount_runtime.rs`                            | 1k-entry directory, mount required                             |
| FUSE mount      | sequential read 4K                        | `crates/ffs-fuse/benches/mount_runtime.rs`                            | 16 MiB file, mount required                                    |
| FUSE mount      | degraded-pressure read                    | `crates/ffs-fuse/benches/degraded_pressure.rs`                        | varied dirty-block ratio                                       |

## Required environment-field schema

Every run artifact must include a `meta.json` capturing:

- `manifest_version` — currently `"v1"`.
- `git_sha` — output of `git rev-parse HEAD`.
- `built_with` — `cargo --version` output.
- `os` — `uname -srv` output (kernel version matters for FUSE benches).
- `cpu_model` — first `model name` line from `/proc/cpuinfo`.
- `cpu_cores_logical` / `cpu_cores_physical`.
- `ram_total_gb` — `/proc/meminfo MemTotal` rounded to integer GiB.
- `storage_class` — one of `nvme-ssd`, `sata-ssd`, `hdd`, `ramdisk`,
  `unknown`. Established by inspecting `/sys/block/<dev>/queue/rotational`
  and the device's transport type.
- `governor` — CPU frequency governor (`/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`).
- `mitigations` — `/sys/devices/system/cpu/vulnerabilities/*` summary.
- `capabilities.fuse` — `true` when `/dev/fuse` exists, `fusermount3 -V`
  succeeds, and the harness's FUSE capability probe passes (see
  bd-rchk4.1 artifact). `false` triggers SKIP for all FUSE rows.

## Run protocol

Each numerical result must include:

- **Warmup**: at least 10 iterations (criterion default) before timing
  begins. For workloads that touch disk, also pre-touch every block
  the workload will read so cold-cache effects are isolated to the
  designated cold-cache rows.
- **Measurement runs**: at least 30 timed iterations. Report median,
  p95, p99, and the CV (coefficient of variation). Reject the run
  artifact if CV > 0.10 for any row — high variance indicates a noisy
  run that other comparisons cannot meaningfully use.
- **Profile capture**: optional but encouraged. When recorded, attach
  a flamegraph (perf + flamegraph.pl) or `perf stat` output for the
  hottest workload of the run.
- **Cooldown**: 1 second of idle between rows so background I/O
  settles.

## Artifact format

A baseline run publishes a directory tree:

```
baselines/<git_sha>/<timestamp>/
  meta.json                  # environment fields above
  results.json               # one row per coverage-matrix cell
  flamegraphs/               # optional, one .svg per row
  raw/                       # criterion's per-bench output if available
  README.md                  # one-paragraph human summary
```

`results.json` schema:

```json
{
  "manifest_version": "v1",
  "rows": [
    {
      "workstream": "block_io",
      "workload": "direct_sequential_4k_read",
      "image": "synth_64mib_4k_seq",
      "median_ns": 12345,
      "p95_ns": 14000,
      "p99_ns": 15800,
      "cv": 0.04,
      "skipped": false,
      "skip_reason": null
    }
  ]
}
```

## Open items vs the existing benchmark set

The benchmark inventory above maps each row to a bench that already
exists, except for two gaps that need new benches before this manifest
can be exercised end-to-end:

1. **Repair symbol refresh staleness latency** — no current bench
   covers the rolling-refresh path. Filed as a follow-up.
2. **MVCC merge-proof success rate** — `wal_throughput.rs` measures
   commit throughput but not the proof-validation success ratio.
   Filed as an extension.

The "Block I/O direct sequential 4K write" and "Block I/O random 4K
read mix" rows reuse `arc_cache.rs` but require additional
`Criterion::bench_function` blocks; they are extensions of the
existing bench file rather than new files.

## What this manifest is not

- Not a CI gate. CI runs benchmarks as part of `make bench-smoke`
  with a 5-second budget per row; this manifest is for proper baseline
  publication on dedicated hardware.
- Not a tuning guide. Reading the manifest tells you what numbers to
  collect, not what to do about them.
- Not a substitute for profiling. The manifest captures one number
  per row; latency hotspots inside a row need the optional flamegraph
  capture or out-of-band perf work.
