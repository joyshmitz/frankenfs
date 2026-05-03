# FrankenFS Baseline — 20260503-bd-rchk5-2-refresh-staleness

## Metadata

- Date (UTC): `2026-05-03T19:52:17Z`
- Commit: `94e1aeb71b956520f8bfe1f3a566ef24ef4c54ed`
- Branch: `main`
- Hostname: `thinkstation1`
- Host kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5975WX 32-Cores`
- Memory: `215.780 GiB (226261604 KiB)`
- rustc: `rustc 1.97.0-nightly (37d85e592 2026-04-28)`
- cargo: `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
- hyperfine: `hyperfine 1.19.0`
- Cargo profile: `release-perf`
- Cargo executor: `cargo`
- Cargo target dir: `/data/tmp/frankenfs_bd_rchk5_2_bench`
- Benchmark runners: `hyperfine` for command probes, `criterion_once` for `cargo bench` workloads
- Operation filter: `repair_symbol_refresh_staleness_latency`
- Baseline latest update: skipped for targeted operation run
- Warmup runs: `3`
- Measured runs: `10`
- Thresholds file: `benchmarks/thresholds.toml`
- Warn threshold (default): `10%`
- Fail threshold (default): `20%`

## Preflight Conformance Gate

- `scripts/verify_golden.sh`: SKIPPED (`--skip-verify-golden`)

## Commands

- `cargo bench --profile release-perf -p ffs-repair --bench scrub_codec -- repair_symbol_refresh_staleness_latency`

### Skipped

- ffs-block cache metrics skipped by --op repair_symbol_refresh_staleness_latency

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|
| ffs-repair symbol refresh staleness latency (criterion) | criterion_once | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | `baselines/hyperfine/20260503-bd-rchk5-2-refresh-staleness/ffs_repair_symbol_refresh_staleness_latency.json` |

## Cache Workload Metrics (ArcCache::metrics)

No cache workload metrics were captured.
