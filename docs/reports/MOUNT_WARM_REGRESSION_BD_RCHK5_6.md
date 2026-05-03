# bd-rchk5.6 Warm Mount Regression Closeout

Verdict: median improved, tail latency still quarantined.

## Evidence

| Run | p50 us | p99 us | throughput ops/s | Source |
| --- | ---: | ---: | ---: | --- |
| 20260218 reference | 58275 | 58275 | 17.138407 | `baselines/hyperfine/20260218/ffs_cli_mount_warm_probe.json` |
| 20260503 checked-in current | 291845 | 300114 | 3.407422 | `baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/ffs_cli_mount_warm_probe.json` |
| final after | 137268 | 302981 | 6.335343 | `baselines/hyperfine/20260503-bd-rchk5-6-after-rerun/ffs_cli_mount_warm_probe.json` |

Compared with the checked-in 20260503 run, final median improved by -52.965% and throughput improved by 85.928%. Final p99 changed by 0.955%, so the warm-mount tail claim remains downgraded. Compared with the 20260218 reference, final p99 is still 419.916% higher.

## Diagnosis

The `bd-rchk5.5` probe fix also applies to warm mode: both `warm_prepare` and `warm_measure` now run with `--no-background-scrub`, 5 ms readiness polling, and `cleanup_status=unmounted`. The remaining cost is dominated by running two full sudo/bash/FUSE mount lifecycles per measured command; ffs-cli logs in the final artifact show each individual mount command completes around 19-20 ms, while end-to-end warm probe samples remain 114-303 ms.

## Isomorphism Proof

- Ordering preserved: warm mode still performs `warm_prepare` then `warm_measure`, each with mount, readiness check, unmount, child wait, and cleanup evidence.
- Tie-breaking unchanged: n/a.
- Floating point: n/a for filesystem behavior; timing math is reporting only.
- RNG seeds unchanged: n/a.
- Golden cleanup: final probe report has attempt labels `warm_prepare,warm_measure` and both cleanup statuses are `unmounted`.
