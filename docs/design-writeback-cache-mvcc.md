# Writeback-Cache MVCC Boundary Design

**Status:** Accepted for V1.x policy, explicit opt-in wiring gated by evidence
**Date:** 2026-03-14
**Bead:** bd-m5wf.2.1
**Scope:** FUSE kernel `writeback_cache` ordering vs. FrankenFS MVCC visibility and durability

## Current Code Facts

The live code establishes a strict V1.x contract:

- `ffs-fuse` defaults `writeback_cache` off and only forwards the kernel option
  when `MountOptions::writeback_cache` is explicitly set on a read-write mount.
  Read-only opt-in rejects before the FUSE session is created.
- `ffs-cli mount --writeback-cache` requires `--rw`, an accepted
  writeback-cache audit gate, an accepted dirty-page ordering oracle, an
  accepted crash/replay oracle, and a fresh runtime guard with the kill switch
  disarmed before it passes the option to `ffs-fuse`.
- `flush` is a non-durable lifecycle hook. `ffs-core::OpenFs::flush()` logs `durability_boundary = "none"` and does not call device sync.
- `fsync` / `fsyncdir` are the only explicit durability boundaries in the FUSE layer. `ffs-core::OpenFs::{ext4,btrfs}_sync_with_logging()` call `self.dev.sync(cx)`.
- `ffs-core::WritebackEpochBarrier` models `staged_epoch >= visible_epoch >= durable_epoch` and the proof harness now has the negative-option gate (`bd-rchk0.2.1.1`), dirty-page ordering oracle (`bd-8pz7h`), and 12-point crash/replay oracle (`bd-rchk0.2.3`).
- Operator-facing README and `ffs mount --help` wording are part of the same
  contract: default-off, explicit `--rw --writeback-cache`, accepted
  audit/ordering/crash-replay artifacts, fresh runtime guard, matching host/lane
  manifest, disarmed kill switch, and no production wording until permissioned
  mounted, xfstests, performance, and soak/canary evidence land.

That combination keeps ordinary mounts conservative while allowing a narrow,
evidence-gated experimental opt-in. User-facing readiness wording must stay
tied to accepted audit, ordering, crash/replay, runtime-guard, and host/lane
artifacts rather than implying unconditional writeback-cache support.

## Problem Statement

Kernel FUSE `writeback_cache` changes the meaning of request delivery:

1. Userspace `write()` may return before the daemon sees the corresponding writeback request.
2. The kernel may batch multiple writes, merge adjacent writes, or deliver them out of original syscall order.
3. Metadata requests such as `rename`, `unlink`, or `fsync` can reach the daemon while earlier dirty pages still live only in kernel cache.

FrankenFS currently treats the arrival order of daemon requests as the real mutation order. With `writeback_cache` enabled, that assumption becomes false.

## Reordering Model

| Scenario | Kernel behavior | Safe under current V1 code? | Why |
|----------|-----------------|-----------------------------|-----|
| Disjoint write batching | Two writes to different blocks delivered together or swapped | No | Current code commits each `write()` immediately on arrival; request order becomes the de facto MVCC order. |
| Adjacent write merge | Kernel combines neighboring writes into one daemon request | No | MVCC / FCW sees fewer logical mutation boundaries than the application issued. |
| Delayed page writeback | Dirty pages remain in kernel cache after `write()` returns | No | Other daemon requests can commit against a stale MVCC snapshot that excludes acknowledged data. |
| Metadata overtakes data | `rename`/`unlink`/`fsyncdir` reaches daemon before prior dirty file data | No | Namespace durability can overtake data durability. |
| `flush` before delayed writeback | `flush` is delivered while dirty data is still kernel-resident | No | V1 contract says `flush` is not a durability boundary and must not advance visible or durable state. |
| `fsync` with pending writeback | `fsync` arrives before all earlier dirty pages have reached the daemon | No | `fsync` acknowledgment would overstate what is actually committed and durable. |

## Required Invariants

These invariants are the minimum contract for any future enablement path.

### I1. Snapshot Visibility Boundary

An MVCC request scope may observe only epochs that have crossed the daemon visibility barrier:

```text
visible_epoch <= durable_epoch <= delivered_epoch
request_snapshot.high == committed_epoch_at_scope_start
```

Kernel-cached dirty pages that have not yet crossed the daemon barrier MUST NOT be visible to MVCC readers.

### I2. Alias Order Preservation

Two writes that alias the same logical block/range MUST preserve source order within an epoch.

Disjoint writes may be reordered only if the barrier model proves they cannot race on the same logical bytes or metadata fanout.

### I3. Metadata-After-Data Dependency

A metadata mutation that semantically depends on earlier file data must not become visible or durable before that data.

Examples:

- `rename(new)` of a file whose contents were just written
- link-count changes that finalize a file lifecycle
- directory `fsyncdir` that acknowledges prior create/unlink/rename mutations

### I4. Sync Boundary Completeness

For a target inode or directory epoch `E`, `fsync` / `fsyncdir` acknowledgement implies:

```text
all mutations with epoch <= E and dependency(target) have:
  delivered_to_daemon == true
  committed_to_mvcc == true
  device_sync_completed == true
```

If any earlier mutation in the barrier set is still kernel-resident or only staged, `fsync` / `fsyncdir` MUST wait or fail.

### I5. Flush Non-Durability

`flush` and `release` remain lifecycle hooks:

- they may surface delayed write errors,
- they may drop per-handle state,
- they MUST NOT advance `visible_epoch`,
- they MUST NOT advance `durable_epoch`.

### I6. Cross-Epoch Order

If writeback reordering is allowed at all, it may occur only within a single barrier epoch. Cross-epoch reordering is forbidden.

This prevents a newer epoch from becoming visible or durable ahead of an earlier epoch that the application logically issued first.

## Why V1.x Must Keep `writeback_cache` Default-Off and Evidence-Gated

The default path must not enable `writeback_cache` opportunistically:

1. The kernel can still reorder, batch, or delay dirty pages in ways that are
   invisible to a default mount request.
2. Operators need a concrete audit artifact proving the epoch barrier, FUSE
   capability, repair-serialization, crash matrix, and fsync/fsyncdir evidence
   are fresh for the mount they are attempting.
3. The dirty-page ordering oracle must show that raw FUSE options under test
   include `writeback_cache`, that `flush` remains non-durable, and that
   fsync/fsyncdir advance the durable survivor set before release gates can
   promote the claim.

Therefore the correct V1.x decision is:

- **Operational policy:** keep kernel `writeback_cache` disabled by default.
- **Opt-in policy:** only `--writeback-cache --rw` with accepted gate/oracle
  artifacts forwards the kernel option.
- **Contract:** `flush` is non-durable; `fsync` / `fsyncdir` are the only durability boundaries.

## Future Enablement Design: Writeback Epoch Fence

If `writeback_cache` is ever enabled, FrankenFS needs an explicit daemon-side barrier layer.

### State Machine

For each inode (and for parent directories participating in metadata durability):

```text
staged_epoch   = latest epoch whose dirty pages have arrived from kernel
visible_epoch  = latest epoch committed to MVCC and admissible for readers
durable_epoch  = latest epoch whose commit reached stable storage
```

Required monotonicity:

```text
staged_epoch >= visible_epoch >= durable_epoch
```

### Mutation Flow

1. Kernel-delivered writeback pages are staged into a daemon-side writeback epoch, not applied directly to live filesystem state.
2. Aliasing writes within the epoch are serialized by logical-block key.
3. Metadata operations record explicit data dependencies on the child inode or block set they finalize.
4. `fsync` / `fsyncdir` acquire a fence `F`, wait for all prerequisite pages with epoch `<= F` to arrive, then commit that epoch into MVCC and sync the device.
5. Only after successful device sync does FrankenFS advance `durable_epoch` and acknowledge `fsync` / `fsyncdir`.

### Commit Barrier Shape

The barrier needs three checks before acknowledging `fsync` / `fsyncdir`:

1. **Delivery completeness:** no pending kernel-dirty writes remain for the fenced epoch.
2. **MVCC completeness:** all staged writes in the fenced epoch have been committed with deterministic alias order.
3. **Storage completeness:** the resulting commit has crossed `self.dev.sync(cx)`.

### Interaction with Request Scopes

Request-scope snapshots remain valid only if they cut at `visible_epoch`, not at “latest thing the kernel has acknowledged to the application.”

That means:

- read scopes see only committed epochs;
- mutating scopes may accumulate staged pages in `staged_epoch`;
- `flush` never publishes staged epochs;
- `fsync` / `fsyncdir` are the publication gates.

## Expected-Loss Decision Matrix

Scoring model:

- Probability scale: `0.0` to `1.0`
- Severity / cost scale: `1` (minor) to `5` (catastrophic)
- Total expected loss = semantic-loss + operational-cost

```text
semantic-loss   = P(visibility_or_durability_violation) * severity
operational-cost = P(perf_or_complexity_cost) * cost
```

| Option | P(semantic violation) | Severity | Semantic loss | P(operational cost) | Cost | Operational cost | Total |
|--------|------------------------|----------|---------------|----------------------|------|------------------|-------|
| A. Keep disabled in V1.x | 0.01 | 5 | 0.05 | 0.55 | 1 | 0.55 | 0.60 |
| B. Enable now without barrier | 0.40 | 5 | 2.00 | 0.10 | 1 | 0.10 | 2.10 |
| C. Enable later with epoch fence | 0.06 | 4 | 0.24 | 0.35 | 2 | 0.70 | 0.94 |

Decision:

- **Ship-now choice:** Option A.
- **Only admissible future enablement path:** Option C.
- **Rejected path:** Option B.

The barrier design costs complexity, but the unbarriered path has unacceptable expected semantic loss.

## Executable Guardrail

`crates/ffs-core/src/lib.rs` now includes a small writeback schedule checker used by unit tests to assert:

- reordering without a barrier is rejected,
- aliased writes cannot reorder even with an epoch fence,
- metadata cannot overtake dependent data,
- `fsync` / `fsyncdir` cannot acknowledge before prior epoch writes deliver,
- `flush` cannot be treated as a durability boundary.

That checker is not the production barrier implementation; it is the executable statement of the invariants above.

## Mount-Option Acceptance Gate

`writeback_cache` remains default-off. No mount implementation may forward the
kernel FUSE `writeback_cache` option until the harness audit gate accepts a
schema-valid gate artifact for the exact mount scenario. The current gate is
`bd-rchk0.2.1-gate-v1`, exposed through:

```bash
ffs-harness validate-writeback-cache-audit --gate FILE --scenario-id ID --require-accept
```

The audit report records:

| Field family | Required content |
|--------------|------------------|
| Mount options | raw options, mode, `fs_name`, `allow_other`, `auto_unmount`, `default_permissions` |
| Gate identity | schema version, gate version, bead id, scenario id, reproduction command |
| Runtime guard | kill-switch state, feature state, config source, gate hash/freshness, host fingerprint, lane-manifest id/path/freshness/match, release-gate consumer |
| FUSE capability | probe status, kernel writeback-cache support, helper binary presence |
| Evidence artifacts | epoch-barrier proof, crash matrix, fsync/fsyncdir evidence |
| Decision data | decision, invariant IDs, stable rejection reason, remediation |

The acceptance mapping is:

| Invariant | Gate requirement |
|-----------|------------------|
| I1 Snapshot Visibility Boundary | `epoch_barrier_artifact` is present, fresh, and passing |
| I2 Alias Order Preservation | `operation_class` is in the audited mounted-write envelope |
| I3 Metadata-After-Data Dependency | rw repair-write serialization is accepted and conflicting flags are absent |
| I4 Sync Boundary Completeness | `fsync_evidence_artifact` is present, fresh, and passing |
| I5 Flush Non-Durability | mount is `rw` with explicit opt-in; flush-only evidence is not sufficient |
| I6 Cross-Epoch Order | `crash_matrix_artifact` is present, fresh, and passing |

Stable rejection reasons are part of the contract and are intentionally machine
readable:

- `missing_epoch_barrier_artifact`
- `stale_epoch_barrier_artifact`
- `rw_repair_serialization_unsupported`
- `default_or_read_only_mount`
- `unsupported_filesystem_or_operation`
- `fuse_capability_unavailable`
- `stale_crash_matrix_or_missing_fsync_evidence`
- `conflicting_cli_flags`
- `runtime_kill_switch_engaged`
- `writeback_feature_downgraded`
- `stale_gate_artifact`
- `host_capability_mismatch`
- `config_default_attempt`

The dry-run e2e suite
`scripts/e2e/ffs_writeback_cache_audit_e2e.sh` covers:

- `writeback_cache_audit_cli_wired`
- `writeback_cache_audit_accepts_complete_gate`
- `writeback_cache_audit_rejects_default_mount`
- `writeback_cache_audit_fuse_unavailable_rejected`
- `writeback_cache_audit_unsupported_mode_rejected`
- `writeback_cache_audit_repeated_mount_attempts`
- `writeback_cache_audit_stale_gate_rejected`
- `writeback_cache_audit_repeated_downgrade_rejections`
- `writeback_cache_audit_config_default_rejected`
- `writeback_cache_audit_host_manifest_mismatch_rejected`
- `writeback_cache_audit_fuser_options_default_off`
- `writeback_cache_audit_bad_schema_fails`
- `writeback_cache_audit_report_fields`
- `writeback_cache_audit_unit_tests`
- `writeback_cache_audit_help_docs_consistent`
- `writeback_cache_opt_in_cli_help_boundaries`
- `writeback_cache_opt_in_cli_rejects_missing_gate`
- `writeback_cache_opt_in_cli_rejects_read_only`
- `writeback_cache_opt_in_cli_accepts_gate_before_image_open`
- `writeback_cache_opt_in_cli_repeated_rejections`
- `writeback_cache_runtime_kill_switch_rejected`
- `writeback_cache_opt_in_fuser_options_enabled`
- `writeback_cache_opt_in_unit_tests`
- `writeback_cache_audit_catalog_valid`
- `writeback_cache_ordering_cli_wired`
- `writeback_cache_ordering_accepts_complete_oracle`
- `writeback_cache_ordering_rejects_default_off`
- `writeback_cache_ordering_rejects_missing_fsync`
- `writeback_cache_ordering_rejects_missing_fsyncdir`
- `writeback_cache_ordering_cancellation_classified`
- `writeback_cache_ordering_crash_reopen_artifact`
- `writeback_cache_ordering_report_fields`
- `writeback_cache_ordering_unit_tests`
- `writeback_cache_crash_replay_cli_wired`
- `writeback_cache_crash_replay_accepts_complete_matrix`
- `writeback_cache_crash_replay_rejects_missing_crash_point`
- `writeback_cache_crash_replay_rejects_survivor_mismatch`
- `writeback_cache_crash_replay_rejects_flush_durability`
- `writeback_cache_crash_replay_rejects_missing_fsyncdir`
- `writeback_cache_crash_replay_report_fields`
- `writeback_cache_crash_replay_unit_tests`
- `writeback_cache_ext4_opt_in_flush_fsyncdir_reopen`

These tests prove default-off behavior, explicit opt-in acceptance, rejection
classes, schema failure, report artifact fields, dirty-page ordering, twelve
declared crash/replay points, and unit policy coverage. The mounted ext4
opt-in regression attempts the actual FUSE `writeback_cache` option and emits a
host-classified scenario result when the current lane cannot mount.

README and help text must also cite the companion unit-test groups
(`ffs-fuse writeback_cache`, `ffs-cli mount_writeback_cache`, and the
`ffs-harness` audit/ordering/crash-replay filters), because operators should be
able to connect the policy wording to executable checks without source
archaeology.

## Positive Ordering Oracle

The negative mount-option audit only proves that unsafe or unaudited paths do
not forward `writeback_cache`. A separate positive oracle is required before a
release gate may classify kernel writeback-cache support as stronger than
experimental:

```bash
ffs-harness validate-writeback-cache-ordering --oracle FILE --scenario-id ID --require-accept
```

The ordering oracle report records the exact raw FUSE option list, gate
version, invariant evidence for I1-I6, dirty-page state, flush/fsync/fsyncdir
observations, epoch identity, unmount and crash/reopen survivor-set state,
repair-symbol generation and refresh state, expected ordering, observed
ordering, artifact paths, cleanup status through the e2e log, and a
reproduction command.

Every invariant must have an executable test id, artifact field, and named
release-gate consumer. Unsupported rationales are documented, but they still
fail closed for positive opt-in. Release gates therefore cannot mark
writeback-cache stronger than experimental unless both the negative-option
audit and this positive ordering oracle pass with fresh authoritative
evidence.

## Crash/Replay Matrix Oracle

The ordering oracle proves local sync-boundary semantics; the crash/replay
oracle ties that proof to the mounted-path QA artifact shape required by
`bd-rchk0.2.3`:

```bash
ffs-harness validate-writeback-cache-crash-replay --oracle FILE --scenario-id ID --require-accept
```

The report records gate version, matrix id, raw mount options, raw FUSE
options, host and lane identifiers, fresh epoch state, the mounted operation
trace, all twelve required crash point ids, expected and actual survivor sets,
flush/fsync/fsyncdir observations, metadata-after-data evidence, cancellation
classification, repeated-write state, replay status, stdout/stderr paths,
cleanup status, unsupported-combination rejections, artifact paths, and a
reproduction command. A release gate can therefore distinguish a real survivor
set mismatch from missing host support or an unsupported writeback-cache
combination without parsing prose.

## Follow-On Work

1. Add a daemon-side staged writeback epoch structure instead of immediate live writes.
2. Attach dependency metadata from namespace mutations to child inode/data epochs.
3. Make `fsync` / `fsyncdir` wait on staged-kernel delivery before device sync.
4. Keep `writeback_cache` default-off; only explicit opt-in mounts with fresh accepted audit, ordering, runtime-guard, and crash/replay artifacts may forward the kernel option.
