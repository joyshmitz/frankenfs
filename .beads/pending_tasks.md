# Pending Tasks (Database Congestion)

Created by CC agent 2026-04-22. Import when bead database clears.

## DEADLOCK AUDIT: ffs-core - FIXED

**Status:** FIXED in commit 3b8db67

**Location:** `crates/ffs-core/src/degradation.rs:302-305`

**Fix applied:** Clone Arc pointers, drop lock, then iterate - prevents callback reentrancy.

**Audit result:** ffs-core is CLEAN - consistent lock ordering, no nested acquisitions,
no async/.await patterns, no OnceLock/Lazy hazards.

## Task 1: CLI Binary E2E Tests
```
br create --type task --priority 2 --title "add CLI binary E2E tests for ffs inspect/mount/repair"
```

**Scope:**
- Spawn actual `cargo run -p ffs-cli -- inspect` on real ext4/btrfs images
- Test `ffs mount` with FUSE via CLI (not just library)
- Test `ffs repair` on corrupted images
- Use temp directories for isolation (no mocks)
- Add SCENARIO_RESULT structured output

**Acceptance:**
- CLI inspect returns correct JSON for ext4/btrfs
- CLI mount succeeds and allows file operations
- CLI repair fixes known corruption patterns

## Task 2: Expand SCENARIO_RESULT Coverage
```
br create --type task --priority 2 --title "expand SCENARIO_RESULT structured logging in fuse_e2e tests"
```

**Scope:**
- Currently only 2 SCENARIO_RESULT emissions in 170+ tests
- Add to all fuse_e2e.rs tests (ext4 and btrfs paths)
- Include phase markers: setup, act, assert
- Include timing for performance regression detection

**Acceptance:**
- Every test emits at least one SCENARIO_RESULT line
- CI can parse test output as JSON-lines

## Task 3: Centralize Test Image Factories
```
br create --type task --priority 2 --title "centralize test image factory helpers in ffs-harness"
```

**Scope:**
- Current helpers scattered: create_test_image, build_ext4_*, create_btrfs_*
- Create unified TestImageFactory module
- Document options for each image type
- Add builder pattern for customization

**Acceptance:**
- Single import for all image factory needs
- Documentation for each factory method

## Task 4: Error Path E2E Coverage
```
br create --type task --priority 2 --title "add E2E tests for malformed image and permission error paths"
```

**Scope:**
- Test CLI behavior on truncated images
- Test CLI behavior on corrupted superblocks
- Test CLI behavior on permission-denied paths
- Verify error messages are actionable

**Acceptance:**
- Truncated image returns clear error (not panic)
- Corrupted superblock returns diagnostic message
- Permission errors suggest fix
