# xfstests Known Failures — FrankenFS

Initial baseline analysis for the curated xfstests subset against FrankenFS
FUSE mount. Established 2026-03-18.

## Status Summary

| Test | Expected | Disposition | Root Cause Category |
|------|----------|-------------|---------------------|
| generic/001 | pass | — | Basic file ops (creat/write/unlink) |
| generic/013 | pass | — | fsstress (mkdir/rmdir/link/stat/rename) |
| generic/030 | skip | known_fail | FUSE mmap + mremap ioctl |
| generic/035 | pass | — | rename overwrite semantics |
| generic/068 | skip | wont_fix | FIFREEZE ioctl (kernel-only) |
| generic/112 | skip | likely_pass | AIO + preallocation (fallocate) |
| generic/231 | skip | wont_fix | Disk quotas (kernel-only) |
| ext4/001 | skip | known_fail | fallocate zero_range + FIEMAP |
| ext4/003 | skip | known_fail | bigalloc scratch mkfs |
| ext4/005 | skip | known_fail | chattr -e extent conversion |
| ext4/013 | skip | wont_fix | debugfs raw inode corruption |

**Passable: 3/11** — generic/001, generic/013, generic/035
**Likely passable: 1/11** — generic/112 (pending runtime validation)

## Root Cause Analysis

### Category 1: FUSE Transport Limitation (wont_fix)

These tests require kernel-level operations that FUSE cannot intercept or forward.

**generic/068 — Filesystem Freeze**
- Requires `xfs_freeze` (FIFREEZE ioctl) which is handled by the kernel VFS layer.
- FUSE filesystems receive no notification of freeze/thaw requests.
- FrankenFS could implement freeze via a custom ioctl, but xfstests expects the
  standard kernel interface.

**generic/231 — Disk Quotas**
- Requires Linux quota subsystem (`quotaon`, `repquota`, etc.).
- Quotas are enforced at the kernel block device layer; FUSE filesystems
  operate in userspace and do not integrate with quota accounting.
- FrankenFS could implement its own quota system, but xfstests expects
  kernel-standard quota commands.

**ext4/013 — Inode Corruption via debugfs**
- Test corrupts raw inode bytes via `debugfs -w` on SCRATCH_DEV, then
  checks kernel behavior and `e2fsck` repair.
- Requires direct raw device access, which conflicts with FUSE mount.
- FrankenFS has its own repair subsystem (ffs-repair) that should be
  tested separately.

### Category 2: Missing ioctl / Feature (known_fail)

These tests require specific ioctls or ext4 features that FrankenFS does not
currently expose through the FUSE interface.

**generic/030 — mmap + mremap**
- Uses `xfs_io mremap` to remap file size during mmap writes.
- FUSE mmap semantics have consistency limitations (page cache coherence).
- mremap is not part of the standard FUSE operation set.
- **Path to fix**: Implement FUSE writeback cache + mmap support in ffs-fuse.

**ext4/001 — fallocate zero_range + FIEMAP**
- Requires `FALLOC_FL_ZERO_RANGE` via fallocate and FIEMAP ioctl to verify
  extent layout after zeroing.
- FUSE does not forward FIEMAP; fallocate modes may not be fully exposed.
- **Path to fix**: Implement fallocate passthrough and FIEMAP ioctl in ffs-fuse.

**ext4/003 — bigalloc scratch filesystem**
- Requires creating a scratch ext4 filesystem with bigalloc feature enabled.
- Test infrastructure assumes direct device access for mkfs.
- **Path to fix**: Set up proper SCRATCH_DEV with loop device + ext4 bigalloc.

**ext4/005 — chattr extent conversion**
- Uses `chattr -e` to convert inodes from extent to non-extent format.
- This is an ext4-internal operation that modifies inode flags directly.
- **Path to fix**: Implement EXT4_IOC_SETFLAGS ioctl passthrough in ffs-fuse.

### Category 3: Likely Passable (Pending Runtime Validation)

**generic/112 — FSX with AIO + Preallocation**
- Runs FSX with `-A` (AIO) and `-x` (preallocation via fallocate) flags.
- **AIO support**: Linux FUSE supports AIO since kernel 4.2 via `FUSE_ASYNC_DIO`.
  FrankenFS does not need code changes for AIO — it is handled transparently
  by the kernel FUSE layer.
- **Preallocation support**: FrankenFS implements `fallocate(mode=0)` and
  `FALLOC_FL_KEEP_SIZE` in both ext4 and btrfs code paths (see
  `ffs-core::ext4_fallocate` and `ffs-core::btrfs_validate_fallocate_mode`).
  Preallocated extents are properly marked as unwritten.
- **Remaining blocker**: Requires `ltp/aio-stress` binary from compiled xfstests.
  Cannot validate without building xfstests-dev and setting up the FUSE mount
  test environment.
- **Status**: Reclassified from `investigating` to `likely_pass` based on code
  analysis. Needs runtime validation when xfstests build environment is available.

## Infrastructure Notes

### xfstests Build Prerequisites

xfstests requires compilation from source. Key dependencies:
- `xfsprogs` (xfs_io, mkfs.xfs)
- `e2fsprogs` (mkfs.ext4, e2fsck, debugfs)
- `libaio-dev` (AIO support)
- `libattr1-dev` and `libacl1-dev` (xattr/ACL support)
- `autoconf`, `automake`, `libtool` (build system)
- `fsstress` (built as part of xfstests)

### FrankenFS FUSE Mount Configuration

xfstests local.config for FrankenFS:

```bash
export FSTYP=fuse
export TEST_DEV=/path/to/ext4.img
export TEST_DIR=/mnt/ffs-test
export MOUNT_CMD="ffs-cli mount --read-write"
export UMOUNT_CMD="fusermount -u"
```

## Triage Summary (bd-m5wf.7.4)

Completed 2026-03-18. All 8 known failures investigated (100%).

| Test | Disposition | Fixable? | Effort | Rationale |
|------|------------|----------|--------|-----------|
| generic/030 | known_fail | Yes (high) | FUSE mmap + mremap support | Requires ffs-fuse writeback cache + mmap coherence |
| generic/068 | wont_fix | No | — | FIFREEZE ioctl is kernel VFS, no FUSE path |
| generic/112 | likely_pass | N/A | Runtime test | AIO + fallocate both supported; needs xfstests build |
| generic/231 | wont_fix | No | — | Quota subsystem is kernel-only |
| ext4/001 | known_fail | Yes (medium) | ZERO_RANGE + FIEMAP | Implement FALLOC_FL_ZERO_RANGE in ext4_fallocate |
| ext4/003 | known_fail | Yes (low) | Test infra | Set up SCRATCH_DEV loop device with bigalloc |
| ext4/005 | known_fail | Yes (medium) | EXT4_IOC_SETFLAGS | Implement chattr ioctl passthrough in ffs-fuse |
| ext4/013 | wont_fix | No | — | Requires raw device access (debugfs -w) |

**Actionable items for future work:**
1. Build xfstests-dev and validate generic/112 (likely_pass)
2. Implement `FALLOC_FL_ZERO_RANGE` in `ext4_fallocate` (unblocks ext4/001 partially)
3. Set up SCRATCH_DEV loop device infrastructure (unblocks ext4/003)
4. Implement `EXT4_IOC_SETFLAGS` ioctl passthrough (unblocks ext4/005)

### Next Steps

1. Install xfstests build dependencies and compile
2. Create proper TEST_DEV/SCRATCH_DEV loop device setup
3. Run passable subset (generic/001, generic/013, generic/035) to validate
4. Validate generic/112 (reclassified as likely_pass)
5. Update baseline with actual results
