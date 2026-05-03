# FrankenFS Baseline — 20260503-bd-rchk5-3-mount-warm-sudo-measured

## Metadata

- Date (UTC): `2026-05-03T21:14:12Z`
- Commit: `13271f096188daf9513db841eee7d720d137260e`
- Branch: ``
- Hostname: `thinkstation2`
- Host kernel: `Linux 6.17.0-22-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5995WX 64-Cores`
- Memory: `247.247 GiB (259257084 KiB)`
- rustc: `rustc 1.97.0-nightly (f53b654a8 2026-04-30)`
- cargo: `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
- hyperfine: `hyperfine 1.19.0`
- Cargo profile: `release-perf`
- Cargo executor: `cargo`
- Cargo target dir: `/data/tmp/rch_target_frankenfs_bd_rchk5_3_mount_warm`
- Benchmark runners: `hyperfine` for command probes, `criterion_once` for `cargo bench` workloads
- Operation filter: `mount_warm`
- Baseline latest update: skipped for targeted operation run
- Warmup runs: `3`
- Measured runs: `10`
- Thresholds file: `benchmarks/thresholds.toml`
- Warn threshold (default): `10%`
- Fail threshold (default): `20%`

## Preflight Conformance Gate

- `scripts/verify_golden.sh`: SKIPPED (`--skip-verify-golden`)

## Commands

- `sudo -n scripts/mount_benchmark_probe.sh --bin /data/tmp/rch_target_frankenfs_bd_rchk5_3_mount_warm/release-perf/ffs-cli --image baselines/hyperfine/20260503-bd-rchk5-3-mount-warm/mount_probe.ext4 --mount-root baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/mount_probe_mounts --mode warm --out-json baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/ffs_cli_mount_warm_probe_report.json`

### Skipped

- ffs-cli inspect ext4_8mb_reference.ext4 --json (missing conformance/golden/ext4_8mb_reference.ext4)
- ffs-cli scrub ext4_8mb_reference.ext4 --json (missing conformance/golden/ext4_8mb_reference.ext4)
- ffs-block cache metrics skipped by --op mount_warm

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|
| ffs-cli mount warm ext4 probe (fuse) | hyperfine | 293.477 | 6.719 | 291.845 | 300.114 | 300.114 | `baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/ffs_cli_mount_warm_probe.json` |

## Cache Workload Metrics (ArcCache::metrics)

No cache workload metrics were captured.
