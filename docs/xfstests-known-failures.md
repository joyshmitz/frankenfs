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
| generic/112 | skip | investigating | AIO + preallocation (fallocate) |
| generic/231 | skip | wont_fix | Disk quotas (kernel-only) |
| ext4/001 | skip | known_fail | fallocate zero_range + FIEMAP |
| ext4/003 | skip | known_fail | bigalloc scratch mkfs |
| ext4/005 | skip | known_fail | chattr -e extent conversion |
| ext4/013 | skip | wont_fix | debugfs raw inode corruption |

**Passable: 3/11** — generic/001, generic/013, generic/035

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

### Category 3: Under Investigation

**generic/112 — FSX with AIO + Preallocation**
- Runs FSX with `-x` flag (preallocation, unwritten extents) and AIO.
- AIO over FUSE may work but preallocation semantics need verification.
- **Path to fix**: Test with `libaio` and verify fallocate behavior through FUSE.
- May move to known_fail or pass depending on testing results.

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

### Next Steps

1. Install xfstests build dependencies and compile
2. Create proper TEST_DEV/SCRATCH_DEV loop device setup
3. Run passable subset (generic/001, generic/013, generic/035) to validate
4. Update baseline with actual results
5. Triage known_fail items for FUSE ioctl support (bd-m5wf.7.4)
