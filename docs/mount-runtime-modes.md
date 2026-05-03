# Mount Runtime Modes — Operator Guide

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| `standard` | `--runtime-mode standard` (default) | Blocking mount via `fuser::mount2`. Process exits on unmount. |
| `managed` | `--runtime-mode managed` | Background mount with graceful Ctrl+C shutdown and metrics. |
| `per-core` | `--runtime-mode per-core` | Managed mount with thread-per-core dispatch and per-core metrics. |

## Hostile-Image Boundary

Mount runtime mode does not upgrade hostile-image readiness by itself. Malformed
images, hostile proof artifacts, tampered repair ledgers, resource-exhaustion
seeds, unsupported mount options, and unsafe operator command combinations are
controlled by `security/adversarial_image_threat_model.json`.

Operators should distinguish:

| Case | Expected public status |
|------|------------------------|
| Hostile or malformed image containment | Evidence-gated by `validate-adversarial-threat-model` and security E2E artifacts. |
| Ordinary corruption repair | Covered by scrub/repair evidence; does not imply hostile-image containment. |
| Unsupported mount option or unavailable host capability | Deterministic unsupported/skip classification, not readiness. |
| Detection-only scrub | May inspect and log findings but must not mutate the image. |
| Mutating repair | Requires explicit opt-in plus fresh preflight, ledger, backup/rollback, and release-gate evidence. |

## Soak And Canary Campaigns

Single mounted smoke tests do not prove endurance. The campaign contract in
`benchmarks/soak_canary_campaign_manifest.json` defines bounded `smoke`,
`nightly`, `stress`, and `canary` profiles for repeated mount/unmount/reopen,
metadata churn, read/write/verify, repair scrub dry-runs, writeback-cache gate
checks, and artifact aggregation.

The local dry-run validator is:

```bash
cargo run -p ffs-harness -- validate-soak-canary-campaigns \
  --manifest benchmarks/soak_canary_campaign_manifest.json \
  --artifact-root artifacts/soak/dry-run \
  --out artifacts/soak/campaign_report.json \
  --artifact-out artifacts/soak/sample_artifact_manifest.json \
  --summary-out artifacts/soak/campaign_summary.md
```

Long `nightly`, `stress`, and `canary` profiles are for RCH, CI, or manual
permissioned hosts. They must record kernel, FUSE capability, toolchain, git
SHA, workload IDs, seeds, duration, resource usage, cleanup status, and the
reproduction command. Recurring flakes must preserve a repro pack and link a
follow-up bead; they are not allowed to silently soften release gates.

## Startup Banner

The CLI prints the active runtime mode in the startup banner:
```
Mounting ext4 image (block_size=4096, blocks=131072, ro, runtime=managed) at /mnt/ffs
```

Structured logs also include `runtime_mode` in the `mount_start` and
`mount_runtime_mode_selected` events at target `ffs::cli::mount`.

## Pressure Telemetry

FrankenFS tracks backpressure events in two counters:

| Counter | Meaning |
|---------|---------|
| `requests_throttled` | Requests delayed (but completed) due to degraded state. |
| `requests_shed` | Requests rejected entirely due to critical/emergency state. |

These appear in:
- **Structured logs** at `ffs::cli::mount` on `managed_mount_shutdown_complete`
- **FUSE unmount log** at unmount time

### Interpreting Pressure Events

- **`requests_throttled > 0`**: The filesystem entered `Degraded` state during
  operation. Write operations were delayed by 10ms each. Investigate storage
  I/O latency or CPU contention.

- **`requests_shed > 0`**: The filesystem entered `Critical` or `Emergency`
  state. Metadata writes were rejected (`ENOSPC`-style). This typically
  indicates severe resource exhaustion — check disk space, I/O errors, and
  system load.

- **Both zero**: Normal operation. No backpressure was applied.

## Timeout Configuration

The `--managed-unmount-timeout-secs` flag controls the grace period for
in-flight requests during shutdown (default: 30s). Only valid with `managed`
or `per-core` modes.

If you see "unmount timed out" warnings, increase this value or investigate
why requests are taking longer than expected to complete.

## Per-Core Mode Details

Per-core mode logs additional metrics on shutdown:
- `num_cores`: Number of worker threads used.
- `imbalance_ratio`: Max/min request distribution across cores (1.0 = perfect).
- Per-core cache hit/miss rates (at `debug` level).

High `imbalance_ratio` (>3.0) indicates hot inodes concentrating on one core.
Consider whether your workload is amenable to the inode-based routing strategy.
