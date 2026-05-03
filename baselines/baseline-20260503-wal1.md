# FrankenFS Baseline — 20260503-wal1

## Metadata

- Date (UTC): `2026-05-03T18:50:20Z`
- Commit: `7d12fd4c3f3855e565fbf257ff753f018fef61dc`
- Branch: `main`
- Host kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5975WX 32-Cores`
- rustc: `rustc 1.97.0-nightly (37d85e592 2026-04-28)`
- cargo: `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
- hyperfine: `hyperfine 1.19.0`
- Cargo profile: `release-perf`
- Cargo executor: `rch exec -- cargo`
- Benchmark runners: `hyperfine` for command probes, `criterion_once` for `cargo bench` workloads
- Operation filter: `wal_write_amplification_1block`
- Baseline latest update: skipped for targeted operation run
- Warmup runs: `3`
- Measured runs: `10`
- Thresholds file: `benchmarks/thresholds.toml`
- Warn threshold (default): `10%`
- Fail threshold (default): `20%`

## Preflight Conformance Gate

- `scripts/verify_golden.sh`: SKIPPED (`--skip-verify-golden`)

## Commands

- `rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- wal_write_amplification_1block`

### Skipped

- ffs-block cache metrics skipped by --op wal_write_amplification_1block

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|
| ffs-mvcc WAL write amplification 1-block (criterion) | criterion_once | 6.649 | 0.112 | 6.649 | 6.870 | 6.870 | `baselines/hyperfine/20260503-wal1/ffs_mvcc_wal_write_amplification_1block.json` |

## Cache Workload Metrics (ArcCache::metrics)

No cache workload metrics were captured.
