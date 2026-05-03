# FrankenFS Baseline — 20260503-raptorq16dec

## Metadata

- Date (UTC): `2026-05-03T19:08:10Z`
- Commit: `0a502b5b290d3dc7d48c4beff83bb6a6ada8e97f`
- Branch: `main`
- Host kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5975WX 32-Cores`
- rustc: `rustc 1.97.0-nightly (37d85e592 2026-04-28)`
- cargo: `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
- hyperfine: `hyperfine 1.19.0`
- Cargo profile: `release-perf`
- Cargo executor: `rch exec -- cargo`
- Benchmark runners: `hyperfine` for command probes, `criterion_once` for `cargo bench` workloads
- Operation filter: `raptorq_decode_group_16blocks`
- Baseline latest update: skipped for targeted operation run
- Warmup runs: `3`
- Measured runs: `10`
- Thresholds file: `benchmarks/thresholds.toml`
- Warn threshold (default): `10%`
- Fail threshold (default): `20%`

## Preflight Conformance Gate

- `scripts/verify_golden.sh`: SKIPPED (`--skip-verify-golden`)

## Commands

- `rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_codec -- raptorq_decode_group_16blocks`

### Skipped

- ffs-block cache metrics skipped by --op raptorq_decode_group_16blocks

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|
| ffs-repair raptorq decode 16-block group (criterion) | criterion_once | 1.122 | 0.013 | 1.122 | 1.146 | 1.146 | `baselines/hyperfine/20260503-raptorq16dec/ffs_repair_raptorq_decode_group_16blocks.json` |

## Cache Workload Metrics (ArcCache::metrics)

No cache workload metrics were captured.
