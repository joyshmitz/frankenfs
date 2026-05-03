# FrankenFS Baseline — 20260503-arc-hot64

## Metadata

- Date (UTC): `2026-05-03T19:56:41Z`
- Commit: `94e1aeb71b956520f8bfe1f3a566ef24ef4c54ed`
- Branch: `main`
- Hostname: `thinkstation2`
- Host kernel: `Linux 6.17.0-22-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5995WX 64-Cores`
- Memory: `247.247 GiB (259257084 KiB)`
- rustc: `rustc 1.97.0-nightly (f53b654a8 2026-04-30)`
- cargo: `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
- hyperfine: `hyperfine 1.19.0`
- Cargo profile: `release-perf`
- Cargo executor: `cargo`
- Cargo target dir: `/data/tmp/rch_target_frankenfs_bd_rchk5_2_fresh_arc`
- Benchmark runners: `hyperfine` for command probes, `criterion_once` for `cargo bench` workloads
- Operation filter: `block_cache_arc_concurrent_hot_read_64threads`
- Baseline latest update: skipped for targeted operation run
- Warmup runs: `3`
- Measured runs: `10`
- Thresholds file: `benchmarks/thresholds.toml`
- Warn threshold (default): `10%`
- Fail threshold (default): `20%`

## Preflight Conformance Gate

- `scripts/verify_golden.sh`: SKIPPED (`--skip-verify-golden`)

## Commands

- `cargo bench --profile release-perf -p ffs-block --bench arc_cache -- block_cache_arc_concurrent_hot_read_64threads`

### Cache Metrics Reports

- policy `arc` -> `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_arc.tsv`
- policy `s3fifo` -> `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_s3fifo.tsv`

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|
| ffs-block arc concurrent hot read 64 threads (criterion) | criterion_once | 288.630 | 7.707 | 288.630 | 303.490 | 303.490 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_arc_concurrent_hot_read_64threads.json` |

## Cache Workload Metrics (ArcCache::metrics)

| Policy | Workload | Accesses | Hit Rate | Memory Overhead / Cached Block | Hits | Misses | Resident | Capacity | Ghost (B1+B2) | Source |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| arc | sequential_scan | 16384 | 0.000000 | 0.000000 | 0 | 16384 | 512 | 512 | 0 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_arc.tsv` |
| arc | zipf_distribution | 24000 | 0.773917 | 1.000000 | 18574 | 5426 | 512 | 512 | 512 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_arc.tsv` |
| arc | mixed_seq70_hot30 | 24000 | 0.310292 | 0.125000 | 7447 | 16553 | 512 | 512 | 64 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_arc.tsv` |
| arc | compile_like | 14848 | 0.153893 | 1.000000 | 2285 | 12563 | 640 | 640 | 640 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_arc.tsv` |
| arc | database_like | 38880 | 0.852160 | 1.000000 | 33132 | 5748 | 768 | 768 | 768 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_arc.tsv` |
| s3fifo | sequential_scan | 16384 | 0.000000 | 10.039216 | 0 | 16384 | 51 | 512 | 512 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_s3fifo.tsv` |
| s3fifo | zipf_distribution | 24000 | 0.767250 | 1.000000 | 18414 | 5586 | 512 | 512 | 512 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_s3fifo.tsv` |
| s3fifo | mixed_seq70_hot30 | 24000 | 0.308792 | 4.452174 | 7411 | 16589 | 115 | 512 | 512 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_s3fifo.tsv` |
| s3fifo | compile_like | 14848 | 0.147023 | 1.000000 | 2183 | 12665 | 640 | 640 | 640 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_s3fifo.tsv` |
| s3fifo | database_like | 38880 | 0.846682 | 1.000000 | 32919 | 5961 | 768 | 768 | 768 | `baselines/hyperfine/20260503-arc-hot64/ffs_block_cache_workloads_s3fifo.tsv` |
