# xfstests Known Failures — FrankenFS

Initial baseline analysis for the curated xfstests subset against FrankenFS
FUSE mount. Established 2026-03-18.

> **Freshness note (2026-05-05):** The current host prerequisite preflight now
> passes with explicit `XFSTESTS_DIR`, `TEST_DIR`, and `SCRATCH_MNT`. The host
> has xfs headers, libaio headers, built `ltp/fsstress`, xfstests helpers,
> `/dev/fuse`, `fusermount3`, mount helpers, and writable scratch/test
> directories. This is prerequisite evidence only. `bd-rchk3.3` now also emits
> safe dry-run planning artifacts, but the curated subset still has no fresh
> product pass/fail signal until a permissioned real xfstests run is authorized.
>
> **Policy refresh (2026-05-04):** The dry-run subset policy now also includes
> explicit btrfs planning rows (`btrfs/001`, `btrfs/008`) so the xfstests
> artifacts distinguish generic, ext4, and btrfs scope. These rows are not new
> pass/fail runtime evidence; they are classified before execution until the
> permissioned xfstests lane is available.

## Prerequisite Preflight - 2026-05-05

| Item | Result |
|------|--------|
| Commit | `226e763e` (`main`) |
| Host/kernel | `thinkstation1`, Linux `6.17.0-14-generic` |
| Rust | `rustc 1.97.0-nightly (37d85e592 2026-04-28)` |
| Package install command | `sudo apt-get install -y xfslibs-dev libaio-dev` |
| xfstests build command | `make -C third_party/xfstests-dev` |
| Preflight command | `XFSTESTS_DIR=third_party/xfstests-dev TEST_DIR=artifacts/e2e/20260505_blacklynx_xfstests_preflight/test_dir SCRATCH_MNT=artifacts/e2e/20260505_blacklynx_xfstests_preflight/scratch_mnt ./scripts/e2e/ffs_xfstests_preflight_e2e.sh --out artifacts/e2e/20260505_blacklynx_xfstests_preflight/preflight.json` |
| Preflight artifact | `artifacts/e2e/20260505_blacklynx_xfstests_preflight/preflight.json` |
| Preflight verdict | `pass` |
| Blocking prerequisites | none |
| Satisfied host prerequisites | `xfs_headers`, `libaio`, `ltp_fsstress`, `xfstests_helpers`, `mkfs_mount_helpers`, `/dev/fuse`, `fusermount3`, `user_namespace_or_mount_permissions`, `scratch_test_directories`, `dpkg_lock_state` |
| Worker/release lane | `rch_ci_worker_identity=unsupported-locally`; release evidence still requires an RCH/CI worker run |
| Side-effect policy | `read_only_probe_no_install_no_mount_no_host_mutation`; remediation is manual-only and requires a fresh follow-up probe |
| Script-test command | `./scripts/e2e/ffs_xfstests_preflight_e2e.sh --self-test` |
| Script-test artifact | `artifacts/e2e/20260505_020103_xfstests_preflight_selftest/self_test_summary.json` |
| Script-test outcome | PASS for current host plus all-present, blocked, host-missing, permission-denied, dpkg-locked, worker, worker-mismatch, and unsupported-local fixtures |

The remaining gap is runtime execution, not prerequisite setup. The next real
xfstests attempt should reuse the explicit `XFSTESTS_DIR`, `TEST_DIR`, and
`SCRATCH_MNT` values above, refresh the preflight artifact, then execute
`bd-rchk3.3`.

## Fresh Baseline Attempt - 2026-05-05

| Item | Result |
|------|--------|
| Base commit | `4625abc0` (`main`); evidence captured before this `bd-rchk3.3` guard/documentation commit |
| Host/kernel | `thinkstation1`, Linux `6.17.0-14-generic` |
| Rust | `rustc 1.97.0-nightly (37d85e592 2026-04-28)` |
| Safe dry-run command | `XFSTESTS_MODE=run XFSTESTS_DRY_RUN=1 XFSTESTS_STRICT=1 XFSTESTS_DIR=third_party/xfstests-dev ./scripts/e2e/ffs_xfstests_e2e.sh` |
| Safe dry-run artifacts | `artifacts/e2e/20260505_022349_ffs_xfstests_e2e/xfstests/{selected_tests.txt,summary.json,results.json,junit.xml,check.log,policy_plan.json,policy_report.md,preflight.json,stdout.log,stderr.log}` |
| Safe dry-run outcome | `status=planned`, `mode=run`, `dry_run=1`, `check_rc=0`, `selected_count=17`, `planned=17`, `passed=0`, `failed=0`, `skipped=0`, `not_run=0` |
| Side-effect policy | `safe_dry_run_no_xfstests_check_no_mount_no_mkfs`; upstream `./check -n` is not invoked because xfstests validates and can mount/mkfs/unmount `TEST_DEV`/`SCRATCH_DEV` before listing tests |
| Image setup recorded | `FSTYP=fuse`, `TEST_DEV=frankenfs-dryrun-test`, `SCRATCH_DEV=frankenfs-dryrun-scratch`, artifact-scoped `TEST_DIR`, `SCRATCH_MNT`, and `RESULT_BASE` paths in `summary.json` |
| Direct `./check -n` probe evidence | Earlier strict attempts at `artifacts/e2e/20260505_021807_ffs_xfstests_e2e` and `artifacts/e2e/20260505_022011_ffs_xfstests_e2e` reached xfstests but failed before selected cases while requiring `TEST_DEV` or mount validation |
| Permission guard command | `XFSTESTS_MODE=run XFSTESTS_DRY_RUN=0 XFSTESTS_STRICT=0 XFSTESTS_DIR=third_party/xfstests-dev TEST_DIR=artifacts/e2e/20260505_blacklynx_xfstests_preflight/test_dir SCRATCH_MNT=artifacts/e2e/20260505_blacklynx_xfstests_preflight/scratch_mnt ./scripts/e2e/ffs_xfstests_e2e.sh` |
| Permission guard artifacts | `artifacts/e2e/20260505_022456_ffs_xfstests_e2e/xfstests/{selected_tests.txt,summary.json,results.json,junit.xml,check.log,policy_plan.json,policy_report.md,preflight.json,stdout.log,stderr.log}` |
| Permission guard outcome | Real xfstests execution was not started; `summary.json` records `cleanup_status=real_run_not_started_missing_ack` and requires `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` |
| Product pass/fail signal | none; no curated case is counted as product pass/fail from the safe dry-run or permission guard |
| Tracker state | `bd-rchk3.3` remains the execution bead; `bd-rchk3.4` must not classify product failures from these planned/not-run artifacts |

## Fresh Baseline Attempt - 2026-05-01

| Item | Result |
|------|--------|
| Commit | `8c0c969` (`main`) |
| Host/kernel | `thinkstation1`, Linux `6.17.0-14-generic` |
| Rust | `rustc 1.97.0-nightly (37d85e592 2026-04-28)` |
| FUSE/tools preflight | `/dev/fuse` present, `fusermount3 3.17.4`, `mkfs.ext4`, `debugfs`, `xfs_io`, and `xfs_freeze` present |
| xfstests checkout | `third_party/xfstests-dev/check` present |
| Wrapper command | `XFSTESTS_MODE=auto XFSTESTS_DRY_RUN=1 XFSTESTS_STRICT=0 ./scripts/e2e/ffs_xfstests_e2e.sh` |
| Wrapper artifacts | `artifacts/e2e/20260501_000535_ffs_xfstests_e2e/xfstests/{selected_tests.txt,summary.json,results.json,junit.xml,check.log}` |
| Selected subset | 11 tests at execution time: 7 generic, 4 ext4 |
| Wrapper outcome | `status=skipped`, `mode=run`, `dry_run=1`, `check_rc=1` |
| Current counts | passed 0, failed 0, skipped 0, not_run 11 |
| Immediate blocker | `check.log`: `fsstress not found or executable` |
| xfstests build command | `make -C third_party/xfstests-dev` |
| Build blocker | `FATAL ERROR: cannot find a valid <xfs/xfs.h> header file. Run "make install-dev" from the xfsprogs source.` |
| Package install blocker | `sudo apt-get install -y xfslibs-dev libaio-dev` could not acquire `/var/lib/dpkg/lock-frontend`; lock held by PID `1500480` running `apt-get upgrade -y` |
| Regression gate command | `XFSTESTS_RESULTS_JSON=artifacts/e2e/20260501_000535_ffs_xfstests_e2e/xfstests/results.json XFSTESTS_STRICT=0 ./scripts/e2e/ffs_xfstests_regression_gate.sh` |
| Regression gate artifacts | `artifacts/e2e/20260501_000725_ffs_xfstests_regression_gate/regression_gate/gate_report.json` |
| Regression gate outcome | PASS: compared 11 tests, unchanged 3, new passes 0, regressions 0 |

**Classification:** environment/tooling blocked, not a product failure. No
FrankenFS pass/fail signal was produced because xfstests stopped before running
the selected cases.

**Historical next required run at the time:** after the package lock cleared,
install `xfslibs-dev` and `libaio-dev`, rerun
`make -C third_party/xfstests-dev`, provide a non-destructive
`local.config`/loop-image setup for `TEST_DEV` and `SCRATCH_DEV`, then rerun
the wrapper with `XFSTESTS_DRY_RUN=0`. The current prerequisite state is
superseded by the 2026-05-05 preflight pass above.

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
| ext4/001 | skip | known_fail | FIEMAP kernel/VFS boundary: `EOPNOTSUPP` before `ffs-fuse::ioctl` |
| ext4/003 | skip | known_fail | bigalloc scratch mkfs |
| ext4/005 | skip | known_fail | EXT4 ioctl kernel/VFS boundary: `ENOTTY` before `ffs-fuse::ioctl` |
| ext4/013 | skip | wont_fix | debugfs raw inode corruption |
| btrfs/001 | skip | likely_pass | subvolume/snapshot scratch lane requires btrfs-progs, built xfstests, and permissioned FUSE execution |
| btrfs/008 | skip | wont_fix | full btrfs send/receive apply parity remains explicit follow-up work (`bd-naww5`) |

**Passable: 3/11** — generic/001, generic/013, generic/035
**Likely passable: 1/11** — generic/112 (pending runtime validation)

**Current policy rows: 17** — 11 generic, 4 ext4, 2 btrfs. Runtime passability
counts above remain tied to the 2026-05-01 execution attempt. The 2026-05-05
`bd-rchk3.3` artifacts are safe planning and permission-guard evidence only
until a real permissioned xfstests run updates the baseline.

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

**ext4/001 — ZERO_RANGE implemented, FIEMAP transport still blocked**
- FrankenFS has a live ext4 `FALLOC_FL_ZERO_RANGE` implementation in
  `ffs-core::ext4_fallocate`, and regression coverage exercises both data
  zeroing and `KEEP_SIZE` behavior.
- FIEMAP ioctl passthrough is now implemented in `ffs-fuse` (bd-pqpu,
  2026-03-31). The `FsOps::fiemap` trait method queries the ext4 extent tree
  via `collect_extents_with_scope` and returns `FiemapExtent` entries with
  proper `FIEMAP_EXTENT_LAST` and `FIEMAP_EXTENT_UNWRITTEN` flags. The FUSE
  `ioctl` handler parses `FS_IOC_FIEMAP` (0xC020660B), marshals the fiemap
  header and extent array, and replies via `ReplyIoctl`.
- The workspace now pins `fuser` to the vendored copy in `vendor/fuser`, which
  forwards ioctl requests instead of short-circuiting them in the dispatcher.
- Focused FUSE E2E coverage on 2026-04-18 (`cargo test -p ffs-harness ioctl`)
  added an append-only `ioctl_trace_path` probe to `ffs-fuse`. The mounted
  FIEMAP path still returns `EOPNOTSUPP`, and the probe file remains empty.
  That proves the request never enters `ffs-fuse::ioctl`; the current boundary
  is kernel/VFS handling for `FS_IOC_FIEMAP` on FUSE regular files, not
  FrankenFS FIEMAP marshaling logic.
- **Status**: Remains `known_fail` for xfstests/runtime validation until the
  kernel/VFS path can deliver `FS_IOC_FIEMAP` to FUSE userspace handlers.

**ext4/003 — bigalloc scratch filesystem**
- Requires creating a scratch ext4 filesystem with bigalloc feature enabled.
- Test infrastructure assumes direct device access for mkfs.
- **Path to fix**: Set up proper SCRATCH_DEV with loop device + ext4 bigalloc.

**ext4/005 — chattr extent conversion**
- Uses `chattr -e` to convert inodes from extent to non-extent format.
- This is an ext4-internal operation that modifies inode flags directly.
- `EXT4_IOC_GETFLAGS` and `EXT4_IOC_SETFLAGS` ioctl passthrough is now
  implemented in `ffs-fuse` (bd-o30c, 2026-03-31). User-settable flags are
  masked; system flags (EXTENTS, HUGE_FILE, etc.) are protected.
- Focused FUSE E2E coverage on 2026-04-18 (`cargo test -p ffs-harness ioctl`)
  now records each `ffs-fuse::ioctl` callback to an append-only probe file.
  `EXT4_IOC_GETFLAGS` succeeds on the mounted path, but `EXT4_IOC_SETFLAGS`
  still returns `ENOTTY` with no corresponding probe entry. That narrows the
  remaining gap to kernel/VFS handling of the write-side ext4 flag ioctl on
  FUSE regular files, not the FrankenFS userspace setter implementation.

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
- **Remaining blocker**: Requires a permissioned real xfstests execution with
  the explicit `XFSTESTS_REAL_RUN_ACK` guard and artifacted FUSE test/scratch
  setup. The current explicit-path preflight proves the helper/build
  prerequisites are present; it does not produce runtime pass/fail evidence.
- **Status**: Reclassified from `investigating` to `likely_pass` based on code
  analysis. Needs runtime validation when the permissioned xfstests lane is
  authorized.

## Infrastructure Notes

### xfstests Build Prerequisites

xfstests requires compilation from source. Key dependencies:
- `xfsprogs` (xfs_io, mkfs.xfs)
- `e2fsprogs` (mkfs.ext4, e2fsck, debugfs)
- `libaio-dev` (AIO support)
- `libattr1-dev` and `libacl1-dev` (xattr/ACL support)
- `autoconf`, `automake`, `libtool` (build system)
- `fsstress` (built as part of xfstests)

As of the 2026-05-05 explicit-path preflight, these prerequisites are present
on the current host when `XFSTESTS_DIR=third_party/xfstests-dev`, `TEST_DIR`,
and `SCRATCH_MNT` are provided explicitly. Fresh runtime evidence still requires
the guarded real run.

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
| generic/112 | likely_pass | N/A | Runtime test | AIO + fallocate both supported; needs permissioned real xfstests validation |
| generic/231 | wont_fix | No | — | Quota subsystem is kernel-only |
| ext4/001 | known_fail | Partial | Kernel/VFS FIEMAP investigation | FIEMAP marshaling is implemented, and ioctl probe coverage shows `EOPNOTSUPP` occurs before `ffs-fuse::ioctl` |
| ext4/003 | known_fail | Yes (low) | Test infra | Set up SCRATCH_DEV loop device with bigalloc |
| ext4/005 | known_fail | Partial | Kernel/VFS ext4 ioctl investigation | `EXT4_IOC_GETFLAGS` works, but `SETFLAGS` still returns `ENOTTY` before `ffs-fuse::ioctl` |
| ext4/013 | wont_fix | No | — | Requires raw device access (debugfs -w) |

**Actionable items for future work:**
1. `bd-rchk3.3`: run the permissioned xfstests lane and validate generic/112 (likely_pass)
2. `bd-rchk3`: rerun the passable subset and update this document with dated results
3. `bd-rchk4`: revisit ext4/001 only after identifying whether Linux forwards `FS_IOC_FIEMAP` to FUSE userspace at all
4. `bd-rchk3`: set up SCRATCH_DEV loop device infrastructure (unblocks ext4/003)
5. `bd-rchk4`: validate whether Linux forwards `EXT4_IOC_SETFLAGS` to FUSE userspace, ideally with a standalone libfuse reproducer (ext4/005)

### Next Steps

1. `bd-rchk3.3`: provide explicit authorization for real xfstests execution with `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices`
2. `bd-rchk3.3`: refresh the explicit-path preflight immediately before execution
3. `bd-rchk3.3`: run the curated subset with artifact-scoped `TEST_DIR`, `SCRATCH_MNT`, `RESULT_BASE`, stdout/stderr, raw xfstests logs, and cleanup status
4. `bd-rchk3.4`: convert each product-actionable failure row into a narrow follow-up bead
5. `bd-rchk3`: update this baseline with actual pass/fail/not-run counts and tracker links
