# bd-rchk5.7 Recovery Mount Regression Closeout

Verdict: tail latency still regressed; claim quarantined.

## Evidence

| Run | p50 us | p99 us | throughput ops/s | Source |
| --- | ---: | ---: | ---: | --- |
| 20260218 reference | 35020 | 35020 | 28.458766 | `baselines/hyperfine/20260218/ffs_cli_mount_recovery_probe.json` |
| 20260503 checked-in current | 68972 | 74217 | 14.143184 | `baselines/hyperfine/20260503-bd-rchk5-3-mount-recovery-sudo-measured/ffs_cli_mount_recovery_probe.json` |
| final after | 76204 | 82198 | 13.015201 | `baselines/hyperfine/20260503-bd-rchk5-7-after-rerun/ffs_cli_mount_recovery_probe.json` |

Compared with the checked-in 20260503 run, final p99 changed by 10.754% and throughput changed by -7.975%. Compared with the 20260218 reference, final p99 is still 134.717% higher.

## Diagnosis

The updated probe runs recovery with `--no-background-scrub`, 5 ms readiness polling, and `cleanup_status=unmounted`. That still does not beat the checked-in 20260503 tail number. Final logs show `mount_complete` and `command_succeeded` around 18.5 ms, while end-to-end hyperfine remains 73-82 ms due to the sudo/bash/FUSE lifecycle. Recovery performance stays downgraded until the benchmark distinguishes product readiness from wrapper overhead or the permissioned runner gets lower-overhead orchestration.

## Isomorphism Proof

- Ordering preserved: recovery mode still performs one recovery mount attempt, readiness check, unmount, child wait, and cleanup evidence.
- Tie-breaking unchanged: n/a.
- Floating point: n/a for filesystem behavior; timing math is reporting only.
- RNG seeds unchanged: n/a.
- Golden cleanup: final probe report has label `recovery` and cleanup status `unmounted`.
