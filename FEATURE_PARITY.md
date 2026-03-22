# FEATURE_PARITY

> Quantitative feature coverage tracking for FrankenFS.

## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 22 | 22 | 100.0% |
| btrfs metadata parsing | 22 | 22 | 100.0% |
| MVCC/COW core | 14 | 14 | 100.0% |
| FUSE surface | 12 | 12 | 100.0% |
| self-healing durability policy | 10 | 10 | 100.0% |
| **Overall** | **80** | **80** | **100.0%** |

> **Canonical source:** This Coverage Summary table in `FEATURE_PARITY.md` is the
> single source of truth for implemented/total counts. `ParityReport::current()`
> in `ffs-harness` parses this file, and a CI test
> (`parity_report_matches_feature_parity_md`) enforces the mapping.

## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| ext4 superblock decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4`, including `s_mmp_*`, flex-group sizing, reserved GDT fields, and `s_backup_bgs` parsing |
| ext4 inode core decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent header decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent entry decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 feature flag validation | `fs/ext4/super.c` | ✅ | Mount validation includes supported incompat/ro_compat policy plus conservative MMP enforcement |
| ext4 group descriptor decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ondisk` (`Ext4GroupDesc`), including bitmap checksum fields |
| ext4 directory entry parsing | `fs/ext4/dir.c` | ✅ | Implemented in `ffs-ondisk` |
| ext4 inode device read | `fs/ext4/inode.c` | ✅ | `OpenFs::read_inode` via `ByteDevice` |
| ext4 path resolution | `fs/ext4/namei.c` | ✅ | `OpenFs::resolve_path` |
| ext4 bitmap free space reading | `fs/ext4/balloc.c` | ✅ | `OpenFs::free_space_summary`, bitmap-derived free block/inode counts, bitmap checksum verification, and allocator-side reservation of sparse/flex metadata blocks |
| ext4 journal replay parity | `fs/ext4/ext4_jbd2.c` | ✅ | Journal replay and write-side transaction integration are implemented and validated through harness + E2E coverage. |
| ext4 allocator parity | `fs/ext4/mballoc.c` | ✅ | Allocator mutation path is implemented with persistence, correctness guards, and validated mutation coverage. |
| ext4 orphan recovery parity | `fs/ext4/orphan.c` | ✅ | Mount-time orphan cleanup implemented in `ffs-core` (`OpenFs::maybe_recover_ext4_orphans`): tolerant chain traversal (cycle/out-of-range guardrails), delete-or-truncate recovery actions, and superblock orphan-state clearing (`s_last_orphan`, `EXT4_ORPHAN_FS`). Read-only orphan diagnostics remain available via `OpenFs::read_ext4_orphan_list` + CLI inspect output. |
| btrfs superblock decode | `fs/btrfs/disk-io.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs btree header decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs leaf item metadata decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs internal node parsing | `fs/btrfs/ctree.c` | ✅ | `parse_internal_items` in `ffs-ondisk` |
| btrfs sys_chunk mapping | `fs/btrfs/volumes.c` | ✅ | `map_logical_to_physical` in `ffs-ondisk` |
| btrfs read-only tree walk | `fs/btrfs/ctree.c` | ✅ | `walk_tree` in `ffs-btrfs` |
| btrfs item payload decode (ROOT/INODE/DIR/EXTENT_DATA) | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-btrfs` (`parse_root_item`, `parse_inode_item`, `parse_dir_items`, `parse_extent_data`) |
| btrfs open/validate pipeline | `fs/btrfs/disk-io.c` | ✅ | `BtrfsContext` in `ffs-core` |
| btrfs transaction parity | `fs/btrfs/transaction.c` | ✅ | Transaction begin/commit/abort semantics and integration paths are implemented with coverage in unit + E2E suites. |
| btrfs delayed refs parity | `fs/btrfs/delayed-ref.c` | ✅ | `DelayedRefQueue` + `BtrfsRef` model + bounded flush/refcount tracking in `ffs-btrfs::BtrfsExtentAllocator`, with queue/refcount/stress tests |
| btrfs scrub parity | `fs/btrfs/scrub.c` | ✅ | Scrub validation and repair-path coverage are implemented in the current test matrix. |
| btrfs transparent decompression (ZLIB/ZSTD) | `fs/btrfs/compression.c` | ✅ | `btrfs_decompress()` in `ffs-core` with flate2 (ZLIB) and zstd crates; LZO deferred. Inline + regular extent decompression wired into read path. |
| btrfs subvolume mount | `fs/btrfs/ioctl.c` | ✅ | `BtrfsContext::subvol_objectid` configurable; `walk_btrfs_fs_tree` resolves correct subvolume root. |
| ext4 inline data read | `fs/ext4/inline.c` | ✅ | `read_ext4_inline_data()` reads from inode extent_bytes + system.data xattr. `INLINE_DATA` removed from rejected features. |
| ext4 indirect block addressing | `fs/ext4/inode.c` | ✅ | `resolve_indirect_block()` handles direct + single/double/triple indirect pointers. `EXTENTS` no longer required at mount. |
| ext4 FALLOC_FL_ZERO_RANGE | `fs/ext4/extents.c` | ✅ | ZERO_RANGE mode (0x10) zeroes allocated blocks in range via write path. |

### 2.1 btrfs Experimental RW Capability Contract (Machine-Checkable)

The table below is the authoritative btrfs experimental RW contract for `bd-h6nz.3.1`.
Each row maps directly to deterministic unit/E2E coverage by stable test/scenario ID.

| Contract ID | Operation / Edge Case | Class | Expected Result |
|-------------|------------------------|-------|-----------------|
| `unit::btrfs_write_create_file` | `create` regular file | supported | success |
| `unit::btrfs_write_mkdir` | `mkdir` | supported | success |
| `unit::btrfs_write_rename` | `rename` (same/cross parent) | supported | success |
| `unit::btrfs_write_setattr_truncate` | `setattr(size)` truncate path | supported | success |
| `unit::btrfs_write_xattr_set_get_list` | `setxattr/getxattr/listxattr` | supported | success |
| `unit::btrfs_write_xattr_respects_create_and_replace_modes` | `setxattr` mode semantics (`Create`/`Replace`) | supported | existing key rejects `Create` with `EEXIST`; missing key rejects `Replace` with `ENOENT`; no side effects |
| `unit::btrfs_write_fallocate_basic` | `fallocate` preallocation (`mode=0`) | supported | success |
| `unit::btrfs_write_fallocate_keep_size_does_not_extend_file` | `fallocate` with `FALLOC_FL_KEEP_SIZE` | partially supported | success, file size unchanged |
| `unit::btrfs_write_fallocate_punch_hole_zeroes_data` | `fallocate` with `FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE` | supported | success, file size preserved, punched range reads back as zeros, unaffected bytes remain intact |
| `unit::btrfs_write_fallocate_zero_range_zeroes_data` | `fallocate` with `FALLOC_FL_ZERO_RANGE` | supported | success, requested range reads back as zeros, unaffected bytes remain intact |
| `unit::btrfs_write_fallocate_zero_range_keep_size_does_not_extend_file` | `fallocate` with `FALLOC_FL_ZERO_RANGE|FALLOC_FL_KEEP_SIZE` | supported | success, file size unchanged when range extends past EOF |
| `unit::btrfs_write_fallocate_unsupported_mode_bits_rejected` | `fallocate` with unsupported mode bits | unsupported | `FfsError::UnsupportedFeature` -> `EOPNOTSUPP` |
| `unit::btrfs_write_fallocate_success_log_contract` | supported fallocate log contract | observability | structured log includes `operation_id`, `scenario_id`, `outcome=applied` |
| `unit::btrfs_write_fallocate_rejection_log_contract` | unsupported fallocate log contract | observability | structured log includes `operation_id`, `scenario_id`, `outcome=rejected`, `error_class` |
| `unit::btrfs_write_fallocate_unsupported_mode_bits_log_contract` | unsupported mode-bits fallocate log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fallocate_unsupported_mode_bits`, `outcome=rejected`, `error_class=unsupported_mode_bits` |
| `unit::btrfs_write_fsync_log_contract_success` | `fsync` success log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsync`, `outcome=applied` |
| `unit::btrfs_write_fsync_rejection_log_contract_read_only` | `fsync` read-only rejection log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsync`, `outcome=rejected`, `error_class=read_only` |
| `unit::btrfs_write_fsyncdir_log_contract_success` | `fsyncdir` success log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsyncdir`, `outcome=applied` |
| `e2e::btrfs_rw_fallocate_punch_hole_keep_size_zeroes_range` | FUSE path punch-hole zero-fill under `KEEP_SIZE` | supported | shell-visible success, file size unchanged, punched range zeroed, unaffected suffix preserved |
| `e2e::btrfs_rw_fallocate_zero_range_zeroes_range` | FUSE path zero-range contract | supported | shell-visible success, requested range zeroed, unaffected suffix preserved |
| `e2e::btrfs_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp` | FUSE path unsupported mode-bit rejection | unsupported | shell-visible `EOPNOTSUPP`, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_crash_matrix_01_create_alpha_no_fsync` | crash point 1 (create) | crash-consistency | post-crash RO remount invariants verified; `CRASH_MATRIX_EVENT` + `SCENARIO_RESULT` emitted |
| `e2e::btrfs_rw_crash_matrix_02_append_alpha_no_fsync` | crash point 2 (append write) | crash-consistency | post-crash RO remount invariants verified; `CRASH_MATRIX_EVENT` + `SCENARIO_RESULT` emitted |
| `e2e::btrfs_rw_crash_matrix_03_fsync_alpha_and_parent` | crash point 3 (fsync file/parent boundary) | crash-consistency | fsync durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::btrfs_rw_crash_matrix_04_rename_alpha_to_beta_no_fsync` | crash point 4 (rename) | crash-consistency | post-crash rename-state envelope verified (old/new name admissible set) |
| `e2e::btrfs_rw_crash_matrix_05_fsync_rename_parent` | crash point 5 (rename fsync boundary) | crash-consistency | rename durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::btrfs_rw_crash_matrix_06_create_gamma_no_fsync` | crash point 6 (create second file) | crash-consistency | post-crash non-fsync create envelope verified without metadata divergence |
| `e2e::btrfs_rw_crash_matrix_07_fsync_gamma_and_parent` | crash point 7 (second fsync boundary) | crash-consistency | fsync durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::btrfs_rw_crash_matrix_08_unlink_beta_no_fsync` | crash point 8 (unlink beta) | crash-consistency | post-crash non-fsync unlink envelope verified without metadata divergence |
| `e2e::btrfs_rw_crash_matrix_09_unlink_gamma_no_fsync` | crash point 9 (unlink gamma) | crash-consistency | post-crash non-fsync unlink envelope verified without metadata divergence |
| `e2e::btrfs_rw_crash_matrix_10_fsync_unlink_parent` | crash point 10 (unlink fsync boundary) | crash-consistency | unlink durability boundary verified with structured sync logs and RO remount invariants |
| MVCC snapshot visibility | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| MVCC commit sequencing | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| FCW conflict detection | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc`; OQ2 (`bd-h6nz.6.2`) resolved for V1.x as strict FCW+SSI (safe-merge/adaptive arbitration deferred) with deterministic contention evidence in `crates/ffs-mvcc/tests/mvcc_stress_suite.rs` |
| version retention policy | FrankenFS spec §3 | ✅ | In-memory retention with `VersionData::Identical` dedup (zero-copy for unchanged blocks), configurable `CompressionPolicy` (dedup + max chain length cap), watermark-safe pruning, chain-pressure handling (oldest-snapshot force-advance + `CommitError::ChainBackpressure`), and crossbeam-epoch deferred reclamation counters/collection (`ebr_stats`, `ebr_collect`) in `ffs-mvcc` |
| COW block rewrite path | FrankenFS spec §3 | ✅ | Allocation-backed COW rewrite path implemented in `ffs-mvcc` (`write_cow`, logical→physical mapping visibility, deferred-free + watermark GC integration) |
| durability policy model | FrankenFS spec §4 | ✅ | Bayesian expected-loss selector |
| asupersync config mapping | FrankenFS spec §4 | ✅ | `RaptorQConfig` mapping implemented |
| format-aware scrub superblock validation | FrankenFS spec §4 | ✅ | `Ext4SuperblockValidator` + `BtrfsSuperblockValidator` in `ffs-repair`, wired into `ffs-cli scrub` |
| repair symbol storage I/O (dual-slot generation commit) | FrankenFS spec §4 | ✅ | `RepairGroupStorage` in `ffs-repair::storage` with symbol-block validation + torn-generation fallback; OQ3 (`bd-h6nz.6.3`) resolved for V1.x as bounded staleness (lazy 30s default + timeout/adaptive-eager escalation) with deterministic refresh-policy evidence in `crates/ffs-repair/src/pipeline.rs` tests and `scripts/e2e/ffs_repair_recovery_smoke.sh` |
| corruption recovery orchestrator + evidence ledger | FrankenFS spec §4 | ✅ | `GroupRecoveryOrchestrator` in `ffs-repair::recovery` (decode + writeback + post-verify + JSON evidence) |
| FUSE getattr | FrankenFS spec §9 | ✅ | `FsOps::getattr` via `OpenFs` |
| FUSE lookup | FrankenFS spec §9 | ✅ | `FsOps::lookup` via `OpenFs` |
| FUSE readdir | FrankenFS spec §9 | ✅ | `FsOps::readdir` via `OpenFs` |
| FUSE read | FrankenFS spec §9 | ✅ | `FsOps::read` via `OpenFs` |
| FUSE readlink | FrankenFS spec §9 | ✅ | `FsOps::readlink` via `OpenFs` |
| FUSE mount runtime | FrankenFS spec §9 | ✅ | Production runtime lifecycle, signal handling, dispatch coverage, and CI-safe skip behavior are implemented; OQ4 (`bd-h6nz.6.4`) is resolved for V1.x with explicit `flush` (non-durable) vs `fsync`/`fsyncdir` (durability boundary) contract and writeback-cache-disabled policy. |
| CLI inspect command | FrankenFS spec §6 | ✅ | Implemented in `ffs-cli` |
| CLI info command | FrankenFS spec §14.2 | ✅ | `ffs info` implemented in `ffs-cli` with optional `--groups`, `--mvcc`, `--repair`, and `--journal` sections plus `--json` output |
| CLI dump command | FrankenFS spec §14.4 | ✅ | `ffs dump` implemented in `ffs-cli` with subcommands `superblock`, `group`, `inode`, `extents`, and `dir`, each supporting `--json` and `--hex` |
| CLI fsck command | FrankenFS spec §14.1 | ✅ | `ffs fsck` implemented in `ffs-cli` with `--repair`, `--force`, `--verbose`, `--block-group`, and `--json`; checks include superblock/group-descriptor validation + scoped scrub reporting, `--block-group` now supports ext4 groups and btrfs block-group indexes (extent-tree discovered), and `--repair` executes ext4 mount-time journal/orphan recovery plus btrfs primary-superblock restoration from validated backup mirrors with post-write scrub verification, including bootstrap recovery when initial btrfs detection fails due to primary-superblock corruption. V1.x write-side repair is explicitly single-host only via a persistent per-image coordination record (`.<image>.ffs-repair-owner.json`); foreign-host ownership blocks mutation but still reports read-only diagnostics. |
| CLI repair command | FrankenFS spec §14.3 | ✅ | `ffs repair` implemented in `ffs-cli` with `--full-scrub`, `--block-group`, `--rebuild-symbols`, `--verify-only`, `--max-threads`, and `--json`; ext4 path performs stale-scope selection, block-symbol reconstruction attempts, symbol re-encoding (`--rebuild-symbols` + post-recovery refresh), and post-write verification scrub, while btrfs now supports scoped `--block-group` scrub by discovered block-group index plus primary-superblock restoration from validated backup mirrors, including bootstrap recovery when initial btrfs detection fails due to primary-superblock corruption. V1.x write-side repair is explicitly single-host only via a persistent per-image coordination record (`.<image>.ffs-repair-owner.json`); broader multi-host write-side recovery and symbol rebuild remain unsupported. |
| fixture conformance harness | FrankenFS spec §7 | ✅ | Implemented in `ffs-harness` |
| benchmark harness | FrankenFS spec §8 | ✅ | Criterion benchmark added |
| xfstests generic/ext4 subset infrastructure | xfstests (`check`, generic/, ext4/) | ✅ | Curated subset manifests, planner/runner automation, CI planning gate, and regression guard workflow are implemented. |

Legend: `✅` implemented.

## 3. Blocking Gaps to 100%

No blocking gaps in the tracked V1 parity matrix.

## 4. Update Rule

Any change touching compatibility behavior MUST update this file in the same patch.
