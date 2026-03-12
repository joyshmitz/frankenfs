# OQ1 Decision Record: Native-Mode On-Disk Boundary and Mutation Contract

**Status:** Accepted
**Date:** 2026-03-12
**Bead:** bd-h6nz.6.1
**Resolves:** OQ1 (COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md §21.2)

## Context

FrankenFS reimplements ext4/btrfs in Rust with additional MVCC, RaptorQ repair,
and BLAKE3 integrity features. A core design tension exists: when mounted on an
existing ext4 or btrfs image, which on-disk bytes may FrankenFS mutate?

Two modes of operation are defined to resolve this tension.

## Decision

### Mode Definitions

| Mode | Default | CLI Flag | Description |
|------|---------|----------|-------------|
| **Compat** | Yes | (none) | Only standard ext4/btrfs on-disk structures are read and written. The resulting image remains mountable by the Linux kernel driver. |
| **Native** | No | `--native` | FrankenFS may additionally write MVCC version chains, RaptorQ repair symbols, and BLAKE3 checksums to reserved areas. |

### Compatibility-Mode Mutation Contract

In compat mode, FrankenFS MAY read and write the following standard structures:

| Structure | Read | Write | Notes |
|-----------|------|-------|-------|
| Superblock | Yes | Yes | Standard ext4/btrfs fields only |
| Group descriptors | Yes | Yes | Free counts, flags, CRC32C checksums |
| Inode table entries | Yes | Yes | Standard ext4 inode layout |
| Block/inode bitmaps | Yes | Yes | Allocation tracking |
| Directory blocks | Yes | Yes | Standard ext4 dir entry format |
| Extent tree blocks | Yes | Yes | Standard ext4 extent layout |
| JBD2 journal | Yes | Yes | Physical journaling for crash safety |
| Xattr blocks | Yes | Yes | Standard ext4 xattr format |

In compat mode, FrankenFS MUST NOT write:

| Structure | Reason |
|-----------|--------|
| Repair symbols (reserved tail blocks) | FrankenFS-native feature |
| Version store inode | MVCC version chains are native-only |
| BLAKE3 checksums | Native integrity feature |
| COW journal entries | Native journaling mode |

All checksums in compat mode use CRC32C (ext4-standard convention with
`ext4_chksum()` wrapper for kernel compatibility).

### Native-Mode Additional Mutations

In native mode, all compat-mode mutations are permitted, plus:

| Structure | Location | Purpose |
|-----------|----------|---------|
| Repair symbols | Reserved blocks at tail of each block group | RaptorQ erasure coding for self-healing |
| Repair group desc ext | Dual-slot reserved descriptor blocks | Symbol metadata with generation ordering |
| Version store | Dedicated inode (future) | MVCC version chains for snapshot isolation |
| BLAKE3 checksums | Native metadata fields | Integrity verification for native structures |
| COW journal | Dedicated region (future) | Append-only journal for MVCC commits |

### Opt-In Mechanism

- **CLI:** `ffs mount --native <image> <mountpoint>`
- **API:** `OpenOptions { mount_mode: MountMode::Native, .. }`
- **Default:** `MountMode::Compat` (safe by default)

### Fallback Semantics

- A native-mode image can be opened in compat mode. Standard ext4 data is
  fully readable. Native-only metadata (repair symbols, version store) is
  simply ignored — it resides in reserved blocks that the kernel ext4 driver
  also ignores.
- To revert a native-mode image to pure ext4, discard the version store inode
  and clear reserved tail blocks. The standard ext4 structures remain valid.

### Enforcement

Boundary enforcement is implemented via `require_native_mode(operation)` guard
methods on `OpenFs`. Any attempt to perform a native-only operation in compat
mode returns `FfsError::ModeViolation` (errno `EPERM`).

Guard methods:
- `require_repair_write_access()` — gates repair symbol writes
- `require_version_store_access()` — gates version store writes
- `require_blake3_write_access()` — gates BLAKE3 checksum writes

All guards emit structured log events at `warn` level with fields:
`mount_mode`, `rejected_operation`, `operation_id`, `scenario_id`, `outcome`.

### Structured Logging

| Event | Target | Level | Fields |
|-------|--------|-------|--------|
| `mount_mode_selected` | `ffs::core` | `info` | `mount_mode`, `operation_id` |
| `native_mode_boundary_violation` | `ffs::core` | `warn` | `mount_mode`, `rejected_operation`, `operation_id`, `scenario_id`, `outcome` |

## Alternatives Considered

### Alternative A: Single mode (always allow native writes)

**Rejected.** Silently writing FrankenFS-specific data to ext4 images violates
the principle of least surprise. Users mounting ext4 images expect kernel
compatibility.

**Expected loss:** High compatibility risk. Images could become unmountable
by Linux ext4 driver if native metadata overwrites reserved blocks that a
future kernel version uses differently.

### Alternative B: Image-level marker (auto-detect native mode)

**Deferred to V2.** Storing a marker in a superblock reserved field or xattr
would allow auto-detection, but requires spec work on the exact field location
and risks format lock-in before the native format stabilizes.

**Expected loss:** Low — explicit opt-in is sufficient for V1.x. Can be added
later without breaking existing images.

### Alternative C: Per-operation granularity (e.g., --repair-only, --mvcc-only)

**Deferred.** Fine-grained feature flags add complexity without clear V1.x
benefit. The binary compat/native split is sufficient for the current feature
set.

## Validation Matrix

| Decision Rule | Unit Test | E2E Scenario |
|---------------|-----------|--------------|
| Default mode is Compat | `mount_mode_default_is_compat` | `mode_default_compat` |
| Native mode requires opt-in | `mount_mode_native_opt_in` | `mode_native_opt_in` |
| Compat blocks repair writes | `compat_mode_blocks_all_native_operations` | `mode_compat_blocks_repair` |
| Compat blocks version store | `compat_mode_blocks_all_native_operations` | `mode_compat_blocks_version_store` |
| Compat blocks BLAKE3 | `compat_mode_blocks_all_native_operations` | `mode_compat_blocks_blake3` |
| Native allows all operations | `require_native_mode_allows_in_native` | `mode_native_allows_all` |
| ModeViolation → EPERM | `require_native_mode_rejects_in_compat` | `mode_violation_errno` |
| Error includes operation name | `mode_violation_error_includes_operation_name` | — |
| Structured log on violation | — | `mode_boundary_log_emission` |

## Follow-On Implementation Beads

- **bd-h6nz.6.7** (OQ7: version-store format): Must respect `require_version_store_access()` gate.
- **bd-h6nz.1.2** (P0: durable MVCC log writer): Must check `mount_mode.is_native()` before writing.
- Future: Image-level native marker (V2.x scope).
