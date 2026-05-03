# bd-rchk5.5 Mount Cold Regression Closeout

Verdict: improved, residual public claim quarantined.

## What changed

- `scripts/mount_benchmark_probe.sh` now invokes `ffs-cli mount --no-background-scrub` for mount latency probes.
- Probe readiness polling is 5 ms with the same 10 second maximum wait.
- Probe artifacts now record `background_scrub=disabled_by_probe` and the readiness polling policy.

## Evidence

| Run | p50 us | p99 us | throughput ops/s | Source |
| --- | ---: | ---: | ---: | --- |
| 20260218 reference | 36029 | 36029 | 27.018364 | `baselines/hyperfine/20260218/ffs_cli_mount_cold_probe.json` |
| 20260503 checked-in current | 166197 | 171096 | 5.981086 | `baselines/hyperfine/20260503-bd-rchk5-3-mount-cold-sudo-measured/ffs_cli_mount_cold_probe.json` |
| fresh local before | 344070 | 490597 | 3.045682 | `baselines/hyperfine/20260503-bd-rchk5-5-before/ffs_cli_mount_cold_probe.json` |
| final after | 75749 | 84602 | 13.030434 | `baselines/hyperfine/20260503-bd-rchk5-5-after-final/ffs_cli_mount_cold_probe.json` |

Compared with the checked-in 20260503 run, final p99 improved by -50.553% and throughput improved by 117.861%. Compared with the 20260218 reference, final p99 is still 134.816% higher, so the cold-mount public claim remains downgraded.

## Diagnosis

The before profile showed default read-only background scrub was part of the benchmarked process. The strace summary is `baselines/hyperfine/20260503-bd-rchk5-5-before/ffs_cli_mount_cold_probe_strace_summary.txt`; the before logs contain `mount_background_scrub_start`, `scrub_round_complete`, and `mount_background_scrub_stop`. The final after logs contain `mount_complete` and `command_succeeded` around 18.5 ms with no scrub daemon events, while end-to-end hyperfine remains around 75-85 ms because it still includes sudo, bash, mountpoint, FUSE helper, and unmount orchestration.

## Isomorphism Proof

- Ordering preserved: cold mode still performs one mount attempt, waits for readiness, unmounts, waits for the child process, and records cleanup evidence.
- Tie-breaking unchanged: n/a.
- Floating point: n/a for filesystem behavior; timing math is reporting only.
- RNG seeds unchanged: n/a.
- Golden cleanup: final probe report has `cleanup_status=unmounted`.
