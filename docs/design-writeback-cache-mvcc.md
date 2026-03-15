# Writeback-Cache MVCC Boundary Design

**Status:** Accepted for V1.x policy, design-ready for future enablement
**Date:** 2026-03-14
**Bead:** bd-m5wf.2.1
**Scope:** FUSE kernel `writeback_cache` ordering vs. FrankenFS MVCC visibility and durability

## Current Code Facts

The live code establishes a strict V1.x contract:

- `ffs-fuse` does **not** mount with kernel `writeback_cache`; `build_mount_options_excludes_kernel_writeback_cache_mode` enforces that.
- `flush` is a non-durable lifecycle hook. `ffs-core::OpenFs::flush()` logs `durability_boundary = "none"` and does not call device sync.
- `fsync` / `fsyncdir` are the only explicit durability boundaries in the FUSE layer. `ffs-core::OpenFs::{ext4,btrfs}_sync_with_logging()` call `self.dev.sync(cx)`.
- Request scopes currently register and release an MVCC snapshot around each FUSE callback, but they do **not** attach a transaction or hidden write epoch. `begin_request_scope()` captures `current_snapshot()` and `end_request_scope()` releases it.
- The ext4 and btrfs write paths mutate live filesystem state directly during `write()`, `rename()`, `create()`, etc. There is no daemon-side staging layer for “kernel accepted the write, but the daemon has not committed it yet.”

That combination is coherent only while kernel-side write reordering is disabled.

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

## Why V1.x Must Keep `writeback_cache` Disabled

The current implementation violates the prerequisites for `writeback_cache` in three ways:

1. **No staging epoch:** arriving `write()` requests mutate live ext4/btrfs state immediately.
2. **No commit fence:** `begin_request_scope()` captures a snapshot, but it does not establish a per-request or per-handle writeback epoch.
3. **No sync wait-set:** `fsync` / `fsyncdir` sync the underlying device, but they do not first wait for all earlier kernel-dirty pages to be delivered into daemon-visible state.

Therefore the correct V1.x decision is:

- **Operational policy:** keep kernel `writeback_cache` disabled.
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

## Follow-On Work

1. Add a daemon-side staged writeback epoch structure instead of immediate live writes.
2. Attach dependency metadata from namespace mutations to child inode/data epochs.
3. Make `fsync` / `fsyncdir` wait on staged-kernel delivery before device sync.
4. Revisit `writeback_cache` mount options only after the barrier exists and the checker is backed by real implementation state.
