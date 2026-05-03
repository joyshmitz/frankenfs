# FrankenFS Baseline — 20260503-bd-rchk5-3-mount-warm-pending

## Metadata

- Date (UTC): `2026-05-03T20:52:55Z`
- Commit: `7ed77b0053aadbc33b94258410af5956b6c44816`
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


### Skipped

- ffs-cli inspect ext4_8mb_reference.ext4 --json (missing conformance/golden/ext4_8mb_reference.ext4)
- ffs-cli scrub ext4_8mb_reference.ext4 --json (missing conformance/golden/ext4_8mb_reference.ext4)
- mount_warm (pending: mount benchmark probe failed on this host: Mounting ext4 image (block_size=4096, blocks=4096, ro, runtime=standard) at baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-pending/mount_probe_mounts/cold error: FUSE mount failed at baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-pending/mount_probe_mounts/cold: mount I/O error: fusermount3: mount failed: Permission denied : fusermount3: mount failed: Permission denied (set FFS_MOUNT_PROBE_USE_SUDO=1 or --mount-probe-use-sudo if passwordless sudo is available))
- ffs-block cache metrics skipped by --op mount_warm

## Benchmark Summary

| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |
|---|---|---:|---:|---:|---:|---:|---|

## Cache Workload Metrics (ArcCache::metrics)

No cache workload metrics were captured.
