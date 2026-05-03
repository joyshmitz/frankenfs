# bd-rchk5.7 Recovery Mount Regression Closeout

Verdict: tail latency remains regressed against the 2026-02-18 reference, so
the `mount_recovery` performance claim stays downgraded/quarantined.

## Evidence

| Run | p50/mean | p99/max | Throughput | Source |
| --- | ---: | ---: | ---: | --- |
| 20260218 reference | 35020 us p50 | 35020 us p99 | 28.458766 ops/s | `baselines/hyperfine/20260218/ffs_cli_mount_recovery_probe.json` |
| 20260503 checked-in current | 68972 us p50 | 74217 us p99 | 14.143184 ops/s | `baselines/hyperfine/20260503-bd-rchk5-3-mount-recovery-sudo-measured/ffs_cli_mount_recovery_probe.json` |
| bd-rchk5.7 before rerun | 77.817 ms mean | 84.643 ms max | n/a | `baselines/hyperfine/20260503-bd-rchk5-7-before/ffs_cli_mount_recovery_probe.json` |
| final after rerun | 76204 us p50 | 82198 us p99 | 13.015201 ops/s | `baselines/hyperfine/20260503-bd-rchk5-7-after-rerun/ffs_cli_mount_recovery_probe.json` |
| downgraded-current rerun | 77.507 ms mean | 82.917 ms max | n/a | `baselines/hyperfine/20260503-bd-rchk5-7-downgraded-current/ffs_cli_mount_recovery_probe.json` |

Compared with the checked-in 20260503 row, final p99 changed by 10.754% and
throughput changed by -7.975%. Compared with the 20260218 reference, final p99
is still 134.717% higher.

## Diagnosis

The updated probe runs recovery with `--no-background-scrub`, 5 ms readiness
polling, and `cleanup_status=unmounted`. That still does not beat the checked-in
20260503 tail number. Final logs show `mount_complete` and `command_succeeded`
around 18.5 ms, while end-to-end hyperfine remains 73-82 ms due to the
sudo/bash/FUSE lifecycle. Recovery performance stays downgraded until the
benchmark distinguishes product readiness from wrapper overhead or the
permissioned runner gets lower-overhead orchestration.

## Rejected Probe Levers

Replacing the external `seq` helper in the mount readiness loop with a shell
counter did not improve the recovery probe. The candidate run measured
183.350 ms mean with a 93.656-273.751 ms range
(`baselines/hyperfine/20260503-bd-rchk5-7-after-seqless/ffs_cli_mount_recovery_probe.json`).
That code change was not retained.

A `/proc/self/mountinfo` polling experiment was also rejected before commit. It
initially failed on relative mount paths and then measured slower than the
existing `mountpoint` command path. No procfs polling code is shipped.

## Isomorphism Proof

- Ordering preserved: recovery mode still performs one recovery mount attempt,
  readiness check, unmount, child wait, and cleanup evidence.
- Tie-breaking unchanged: n/a.
- Floating point: n/a for filesystem behavior; timing math is reporting only.
- RNG seeds unchanged: n/a.
- Golden cleanup: final probe reports use label `recovery` and cleanup status
  `unmounted`.
