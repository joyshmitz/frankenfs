# FrankenFS Performance Baseline Refresh - 20260521 bd-xuo95.32

## Scope

This refresh records a dated partial performance baseline for `bd-xuo95.32`.
It includes:

- `ffs-repair` Criterion run via `rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_codec`
- `ffs-cli` release-perf prerequisite build via `rch exec -- cargo build --profile release-perf -p ffs-cli`
- Mounted FUSE cold, warm, and recovery probes through `hyperfine` and `scripts/mount_benchmark_probe.sh`

Machine-readable artifact: `benchmarks/baselines/history/20260521-bd-xuo95-32.json`.
Raw logs and probe outputs: `baselines/hyperfine/20260521-bd-xuo95-32/`.

## Environment

| Field | Value |
|---|---|
| Host | `thinkstation1` |
| RCH worker | `ts1` |
| CPU | `AMD Ryzen Threadripper PRO 5975WX 32-Cores` |
| Kernel | `Linux 6.17.0-14-generic #14-Ubuntu SMP PREEMPT_DYNAMIC Fri Jan  9 17:01:16 UTC 2026 x86_64 GNU/Linux` |
| Rust | `rustc 1.97.0-nightly (37d85e592 2026-04-28)` |
| Hyperfine | `hyperfine 1.19.0` |
| Target dir | `/data/tmp/rch_target_frankenfs_bd_xuo95_32` |

## Criterion Results

Criterion reports confidence intervals; the table uses the middle estimate as `mean`.

| Operation | Low | Mean | High | Throughput |
|---|---:|---:|---:|---:|
| `scrub_clean_256blocks` | 69.112 us | 69.782 us | 70.514 us | 14330.343 ops/s |
| `scrub_corrupted_256blocks` | 69.962 us | 70.981 us | 72.077 us | 14088.277 ops/s |
| `raptorq_encode_group_16blocks` | 276.30 us | 278.68 us | 281.12 us | 3588.345 ops/s |
| `raptorq_decode_group_16blocks` | 616.50 us | 625.09 us | 634.56 us | 1599.770 ops/s |
| `raptorq_decode_group_owned_symbols_16blocks` | 613.69 us | 620.65 us | 628.14 us | 1611.214 ops/s |
| `raptorq_decode_group_no_corruption_16blocks` | 90.619 ns | 91.721 ns | 92.921 ns | 10902628.624 ops/s |
| `lrc_encode_global_64blocks_8parity` | 726.59 us | 735.55 us | 745.49 us | 1359.527 ops/s |
| `repair_symbol_refresh_staleness_latency` | 64.598 ns | 65.609 ns | 66.704 ns | 15241811.337 ops/s |

## Mounted Results

All mounted rows completed with `cleanup_status=unmounted`, 10 measured
hyperfine runs, and passing probe reports.

| Operation | Mean | p50 | p99 | CV | Throughput |
|---|---:|---:|---:|---:|---:|
| `mount_cold` | 82084.883 us | 82242.792 us | 86371.938 us | 0.037343 | 12.182511 ops/s |
| `mount_warm` | 112768.562 us | 112901.631 us | 117835.652 us | 0.031549 | 8.867720 ops/s |
| `mount_recovery` | 83436.198 us | 82838.842 us | 89621.198 us | 0.043136 | 11.985206 ops/s |

## Claim Handling

The mounted latency claims are substantiated as fresh measured-local
permissioned evidence, but not upgraded to regression-free public wording.
Compared with the 2026-02-18 mounted reference, current p99 remains slower:

| Operation | Current p99 | Delta vs 20260218 reference | Delta vs 20260503 sudo current | Claim state |
|---|---:|---:|---:|---|
| `mount_cold` | 86371.938 us | +139.729% | -49.518% | measured-local, not regression-free |
| `mount_warm` | 117835.652 us | +102.206% | -60.736% | measured-local, not regression-free |
| `mount_recovery` | 89621.198 us | +155.914% | +20.756% | measured-local, not regression-free |

`README.md`, `FEATURE_PARITY.md`, and
`COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` were intentionally untouched because
they were reserved by another agent.
