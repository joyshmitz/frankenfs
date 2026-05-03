# FrankenFS Mounted FUSE Comparison - 20260503 bd-rchk5.3

## Scope

This comparison maps the 2026-05-03 sudo FUSE mount measurements against the
checked-in 2026-02-18 supplementary mounted reference rows.

- Reference artifact: `benchmarks/baselines/history/20260218.json`
- Current artifacts:
  - `benchmarks/baselines/history/20260503-bd-rchk5-3-mount-cold-sudo-measured.json`
  - `benchmarks/baselines/history/20260503-bd-rchk5-3-mount-warm-sudo-measured.json`
  - `benchmarks/baselines/history/20260503-bd-rchk5-3-mount-recovery-sudo-measured.json`
- Machine-readable comparison: `benchmarks/baselines/history/20260503-bd-rchk5-3-mount-sudo-comparison.json`

## Caveats

- The 2026-02-18 reference rows were supplementary sudo measurements with 3
  samples; the 2026-05-03 rows use `benchmark_record.sh` with 10 samples.
- The reference used the `release` profile and the current rows use
  `release-perf`, so deltas are regression signals rather than a fail gate by
  themselves.
- Current rows preserve structured mount probe reports with
  `kernel_fuse_mode=permissioned_required`, `writeback_cache=disabled`, and
  `cleanup_status=unmounted`.

## Summary

| Operation | Reference p99 (us) | Current p99 (us) | p99 Delta | Reference ops/s | Current ops/s | Throughput Delta | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| mount_cold | 36029 | 171096 | +374.884% | 27.018364 | 5.981086 | -77.863% | slower_than_reference |
| mount_warm | 58275 | 300114 | +414.996% | 17.138407 | 3.407422 | -80.118% | slower_than_reference |
| mount_recovery | 35020 | 74217 | +111.927% | 28.458766 | 14.143184 | -50.303% | slower_than_reference |

## Evidence

All current measured rows were collected through the permissioned sudo FUSE
lane on `thinkstation2` with `hyperfine 1.19.0`, `rustc 1.97.0-nightly`, and
the `release-perf` profile. Each current mount probe report records a passing
probe with every mountpoint unmounted during cleanup.
