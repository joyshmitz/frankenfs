# Pending Tasks (Database Congestion)

Created by CC agent 2026-04-22. Import when bead database clears.

## DEADLOCK AUDIT: ffs-core - FIXED

**Status:** FIXED in commit 3b8db67

**Location:** `crates/ffs-core/src/degradation.rs:302-305`

**Fix applied:** Clone Arc pointers, drop lock, then iterate - prevents callback reentrancy.

**Audit result:** ffs-core is CLEAN - consistent lock ordering, no nested acquisitions,
no async/.await patterns, no OnceLock/Lazy hazards.

## Task 1: CLI Binary E2E Tests - DONE

**Status:** DONE in commit 63c93fe (bd-8bdla)

**Completed:**
- 8 E2E tests in crates/ffs-cli/tests/cli_e2e.rs
- Tests spawn actual cargo run processes against real ext4 images
- All tests emit SCENARIO_RESULT markers for CI parsing
- No mocks used - real images via mkfs.ext4/debugfs

**Tests added:**
- cli_inspect_ext4_returns_json
- cli_inspect_ext4_human_readable
- cli_inspect_truncated_image_returns_error
- cli_inspect_nonexistent_file_returns_error
- cli_info_ext4_shows_superblock
- cli_fsck_ext4_clean_image
- cli_fsck_json_output
- cli_repair_verify_only_ext4

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
