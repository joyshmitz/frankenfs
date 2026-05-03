# FrankenFS Baseline — 20260503-mvcc8

## Metadata

- Date (UTC): `2026-05-03T18:52:16Z`
- Commit: `c215add526d58d4552744364abe0c9dae42cc1d4`
- Branch: `main`
- Host kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5975WX 32-Cores`
- rustc: `rustc 1.97.0-nightly (37d85e592 2026-04-28)`
- cargo: `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
- hyperfine: `hyperfine 1.19.0`
- Cargo profile: `release-perf`
- Cargo executor: `rch exec -- cargo`
- Benchmark runners: `hyperfine` for command probes, `criterion_once` for `cargo bench` workloads
- Operation filter: `mvcc_contention_8writers`
- Baseline latest update: skipped for targeted operation run
- Warmup runs: `3`
- Measured runs: `10`
- Thresholds file: `benchmarks/thresholds.toml`
- Warn threshold (default): `10%`
- Fail threshold (default): `20%`

## Preflight Conformance Gate

- `scripts/verify_golden.sh`: SKIPPED (`--skip-verify-golden`)

## Commands

- `rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- mvcc_contention_8writers`

### Skipped

- ffs-block cache metrics skipped by --op mvcc_contention_8writers

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|
| ffs-mvcc contention 8 writers (criterion) | criterion_once | 0.010 | 0.000 | 0.010 | 0.011 | 0.011 | `baselines/hyperfine/20260503-mvcc8/ffs_mvcc_contention_8writers.json` |

## Cache Workload Metrics (ArcCache::metrics)

No cache workload metrics were captured.
