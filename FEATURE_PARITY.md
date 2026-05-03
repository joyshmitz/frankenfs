# FEATURE_PARITY

> Quantitative feature coverage tracking for FrankenFS.

## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 27 | 27 | 100.0% |
| btrfs metadata parsing | 27 | 27 | 100.0% |
| MVCC/COW core | 14 | 14 | 100.0% |
| FUSE surface | 19 | 19 | 100.0% |
| self-healing durability policy | 10 | 10 | 100.0% |
| **Overall** | **97** | **97** | **100.0%** |

> **Canonical source:** This Coverage Summary table in `FEATURE_PARITY.md` is the
> single source of truth for implemented/total counts. `ParityReport::current()`
> in `ffs-harness` parses this file, and a CI test
> (`parity_report_matches_feature_parity_md`) enforces the mapping.
>
> **Interpretation rule:** "100% coverage" means every capability row in the
> tracked V1 denominator has a defined, implemented, and tested contract. That
> contract may be success, bounded partial behavior, or deterministic
> rejection. Unsupported operations that are intentionally part of the V1
> surface therefore remain compatible with 100% tracked parity when their
> rejection behavior is itself implemented and validated.
>
> **Boundary rule:** this table measures the tracked V1 feature denominator.
> It does not certify production readiness, current xfstests pass rate,
> performance targets, or every future hardening task. Those operational bridge
> items are tracked separately in Section 4.

## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| ext4 superblock decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4`, including `s_mmp_*`, flex-group sizing, reserved GDT fields, `s_backup_bgs`, and quota-inode metadata parsing (`s_usr_quota_inum`, `s_grp_quota_inum`, `s_prj_quota_inum`) with feature-aware accessors |
| ext4 inode core decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent header decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent entry decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4`, with `crates/ffs-harness/tests/kernel_reference.rs` now differentially comparing `collect_extents` against `debugfs blocks` on generated contiguous and deterministic two-extent reference files. |
| ext4 feature flag validation | `fs/ext4/super.c` | ✅ | Mount validation includes supported incompat/ro_compat policy plus conservative MMP enforcement: clean MMP state mounts, and `fsck`, active-writer, or unsafe/unknown MMP states reject deterministically with `EOPNOTSUPP` because FrankenFS V1 does not participate in periodic MMP heartbeat updates. |
| ext4 group descriptor decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ondisk` (`Ext4GroupDesc`), including bitmap checksum fields |
| ext4 directory entry parsing | `fs/ext4/dir.c` | ✅ | Implemented in `ffs-ondisk` |
| ext4 inode device read | `fs/ext4/inode.c` | ✅ | `OpenFs::read_inode` via `ByteDevice` |
| ext4 path resolution | `fs/ext4/namei.c` | ✅ | `OpenFs::resolve_path` handles absolute paths, including `..` parent traversal via on-disk directory entries. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies multi-level nested resolution and absolute dot-dot traversal. |
| ext4 bitmap free space reading | `fs/ext4/balloc.c` | ✅ | `OpenFs::free_space_summary`, bitmap-derived free block/inode counts, bitmap checksum verification, and allocator-side reservation of sparse/flex metadata blocks |
| ext4 journal replay parity | `fs/ext4/ext4_jbd2.c` | ✅ | Journal replay and write-side transaction integration are implemented and validated through harness + E2E coverage. |
| ext4 allocator parity | `fs/ext4/mballoc.c` | ✅ | Allocator mutation path is implemented with persistence, correctness guards, and validated mutation coverage. |
| ext4 orphan recovery parity | `fs/ext4/orphan.c` | ✅ | Mount-time orphan cleanup implemented in `ffs-core` (`OpenFs::maybe_recover_ext4_orphans`): tolerant chain traversal (cycle/out-of-range guardrails), delete-or-truncate recovery actions, and superblock orphan-state clearing (`s_last_orphan`, `EXT4_ORPHAN_FS`). Read-only orphan diagnostics remain available via `OpenFs::read_ext4_orphan_list` + CLI inspect output. |
| btrfs superblock decode | `fs/btrfs/disk-io.c` | ✅ | Implemented in `ffs-ondisk`, including sector/node/stripe size-field validation, zero-capacity, zero-device, and impossible `bytes_used > total_bytes` accounting rejection, root/chunk/log tree-level validation against the kernel maximum level, and fail-closed checksum-type validation for the currently supported CRC32C superblock format. |
| btrfs btree header decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs leaf item metadata decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs internal node parsing | `fs/btrfs/ctree.c` | ✅ | `parse_internal_items` in `ffs-ondisk` |
| btrfs sys_chunk mapping | `fs/btrfs/volumes.c` | ✅ | `map_logical_to_physical` in `ffs-ondisk`, with proptest + metamorphic coverage in `crates/ffs-ondisk/src/btrfs.rs` for translation covariance, chunk-order permutation invariance, and Single-vs-DUP primary mapping equivalence. |
| btrfs read-only tree walk | `fs/btrfs/ctree.c` | ✅ | `walk_tree` in `ffs-btrfs` |
| btrfs item payload decode (ROOT/INODE/DIR/EXTENT_DATA) | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-btrfs` (`parse_root_item`, `parse_root_ref`, `parse_inode_refs`, `parse_inode_item`, `parse_dir_items`, `parse_xattr_items`, `parse_extent_data`) with direct cargo-fuzz coverage in `fuzz_btrfs_tree_items` for deterministic decode and field-level payload invariants. `parse_root_item()` reads level/UUID fields from the packed kernel layout, invalidates UUID-era fields when `generation_v2` is stale, rejects impossible tree levels, and rejects partial extension-field fragments; `parse_root_ref()` rejects zero-length names and trailing bytes after the declared name; `parse_inode_refs()`, `parse_dir_items()`, and `parse_xattr_items()` reject zero-length names; `parse_dir_items()` rejects nonzero `data_len` payloads that belong to xattr-shaped items instead of directory entries; `parse_inode_item()` rejects payloads that are not the fixed 160-byte `btrfs_inode_item` size and rejects impossible timestamp nanoseconds before they reach `Duration`/`SystemTime` conversion paths; and `parse_extent_data()` rejects unsupported extent compression values, nonzero encryption/other-encoding fields, trailing bytes after fixed regular/prealloc payloads, invalid source-slice arithmetic, and uncompressed regular/prealloc disk ranges that exceed `disk_num_bytes`. |
| btrfs open/validate pipeline | `fs/btrfs/disk-io.c` | ✅ | `BtrfsContext` in `ffs-core` |
| btrfs transaction parity | `fs/btrfs/transaction.c` | ✅ | Transaction begin/commit/abort semantics and integration paths are implemented with coverage in unit + E2E suites. |
| btrfs delayed refs parity | `fs/btrfs/delayed-ref.c` | ✅ | `DelayedRefQueue` + `BtrfsRef` model + bounded flush/refcount tracking in `ffs-btrfs::BtrfsExtentAllocator`, with queue/refcount/stress tests, deterministic property coverage, failed-flush atomicity, and checked insert-overflow rejection so retry preserves both the queue and materialized refcounts. The allocator now also exposes fragmentation-aware largest-free-extent discovery from block-group/extent-tree gaps, and `OpenFs::largest_contiguous_free_run` uses that value for btrfs instead of reporting total free bytes as a conservative upper bound. |
| btrfs scrub parity | `fs/btrfs/scrub.c` | ✅ | Scrub validation and repair-path coverage are implemented in the current test matrix. |
| btrfs transparent decompression (ZLIB/LZO/ZSTD) | `fs/btrfs/compression.c` | ✅ | `btrfs_decompress()` in `ffs-core` with flate2 (ZLIB), lzokay-native (LZO), and zstd crates. Inline + regular extent decompression wired into read path, with exact `ram_bytes` decoded-length validation and malformed LZO frame rejection. All 3 codecs supported. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies mounted-root `lookup` plus exact regular-extent reads for ZLIB, LZO, and ZSTD compressed files, including a cross-page read slice through the decompressed view. |
| btrfs subvolume mount | `fs/btrfs/ioctl.c` | ✅ | `BtrfsContext::subvol_objectid` configurable; `walk_btrfs_fs_tree` resolves the requested tree root. `BTRFS_IOC_INO_LOOKUP` now follows the requested `treeid` contract: `treeid=0` reports the mounted subvolume objectid, explicit tree ids walk their matching ROOT_ITEM fs tree, and root-object lookups return a NUL-terminated empty path. Harness coverage still proves the default root alias, and `crates/ffs-cli/src/main.rs` now adds operator-path coverage for named `--subvol` and `--snapshot` selection through the mount open path, including mounted-root `getattr`/`lookup`/`readdir`/`read` behavior scoped to the selected tree. `crates/ffs-harness/tests/fuse_e2e.rs` now adds FUSE E2E coverage (`#[ignore]` requiring sudo) for subvolume/snapshot mount selection proving root scoping to selected tree and `NotFound` errors for missing subvolumes, plus a mounted-path `BTRFS_IOC_INO_LOOKUP` ioctl probe covering `treeid=0` root resolution, seeded workspace path lookup, runtime-created child lookup through the writable COW tree, and missing-object `ENOENT`. |
| ext4 inline data read | `fs/ext4/inline.c` | ✅ | `read_ext4_inline_data()` reads from inode extent_bytes + system.data xattr. `INLINE_DATA` removed from rejected features. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies real `OpenFs::read` behavior for both pure-`i_block` inline payloads and `system.data` xattr continuation payloads, and `crates/ffs-harness/tests/fuse_e2e.rs` now verifies mounted-path ordinary reads plus near-EOF short reads for both storage layouts. |
| ext4 indirect block addressing | `fs/ext4/inode.c` | ✅ | `resolve_indirect_block()` handles direct + single/double/triple indirect pointers. `EXTENTS` no longer required at mount. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies single/double indirect block resolution and I/O boundaries for non-extent inodes. |
| ext4 fallocate range operations | `fs/ext4/extents.c` | ✅ | ZERO_RANGE mode (0x10) zeroes allocated blocks in range via the write path. COLLAPSE_RANGE (0x08) removes a block-aligned interior range, shifts the tail left, shrinks `i_size`, and now rejects ranges that reach EOF with `EINVAL`; INSERT_RANGE (0x20) inserts a zero-reading block-aligned hole inside the file, shifts the tail right, and grows `i_size`. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies `OpenFs::fallocate` zero-range preservation, collapse shifting/shrinking plus EOF rejection with no mutation, and insert hole/growth behavior, while `crates/ffs-harness/tests/fuse_e2e.rs` verifies the real FUSE path emits the `ext4_rw_fallocate_zero_range_zeroes_range` contract while preserving unaffected bytes. |
| ext4 fast commit replay | `fs/ext4/fast_commit.c` | ✅ | `replay_fast_commit()` in `ffs-journal` parses FC tag streams (HEAD/TAIL/INODE/ADD_RANGE/DEL_RANGE/CREAT/LINK/UNLINK/PAD), buffers operations until commit `TAIL`, and forces fallback when the stream is truncated or incomplete. `OpenFs` extracts deterministic fast-commit evidence and applies committed FC operations at mount time via `apply_fast_commit_operations()`. FC operations are processed after JBD2 replay: Create/Link/Unlink/AddRange/DelRange are logged as observational evidence (JBD2 replay provides the authoritative block-level recovery); InodeUpdate triggers a verification read to confirm the inode is accessible. Truncated or incomplete FC streams fall back to JBD2-only replay. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies committed fast-commit evidence extraction plus deterministic JBD2-only fallback for truncated FC streams, and `fuzz/fuzz_targets/fuzz_ext4_fast_commit.rs` now coverage-fuzzes the raw fast-commit replay parser with golden-derived committed and truncated seeds. |
| btrfs tree-log replay | `fs/btrfs/tree-log.c` | ✅ | `replay_tree_log()` in ffs-btrfs walks tree-log tree when `log_root != 0`, returns items for FS tree merge, and is wired into the mount path. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies multilevel log-tree replay through chunk mapping plus the zero-`log_root` fast path, and `fuzz/fuzz_targets/fuzz_btrfs_tree_log.rs` now coverage-fuzzes synthesized tree-log recovery over valid multilevel trees, absent log roots, checksum/structure failures, and equivalent chunk mappings. |
| ext4 casefold (case-insensitive dirs) | `fs/ext4/namei.c` | ✅ | `lookup_in_dir_block_casefold()` with Unicode lowercase comparison. CASEFOLD removed from rejected features. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies real `OpenFs` lookup/readdir behavior on a CASEFOLD-flagged ext4 directory image. |
| ext4 fscrypt (nokey read-only mode) | `fs/ext4/crypto.c` | ✅ | ENCRYPT removed from rejected features. Encrypted filenames shown as raw bytes (nokey mode). Full decryption requires key management not in V1. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies raw-byte `readdir`/`lookup` on an `ENCRYPT`-flagged ext4 image, and `crates/ffs-harness/tests/fuse_e2e.rs` now freezes the same operator-visible mounted-path contract for raw-byte `readdir` plus path lookup. `crates/ffs-core/src/lib.rs` now unit-tests v1 and v2 fscrypt context extraction for `get_encryption_policy_ex()`, plus `ENODATA` on unencrypted inodes. `crates/ffs-fuse/src/lib.rs` unit-tests both the legacy `_IOW` request shape for `FS_IOC_GET_ENCRYPTION_POLICY` and the `_IOWR` `FS_IOC_GET_ENCRYPTION_POLICY_EX` path, including v1 encoding, v2-context passthrough, short-buffer rejection, and `ENODATA` on unencrypted inodes. `crates/ffs-harness/tests/fuse_e2e.rs` also verifies mounted-path `ENODATA` for an unencrypted inode and makes current restricted-FUSE ioctl transport gaps auditable: the request reaches `ffs-fuse::ioctl`, but current kernels can surface `EIO` for the legacy getter's `out_size == 0` shape and for `_EX` variable-size output that this `fuser` reply path cannot renegotiate with retry iovecs. |
| btrfs multi-device RAID | `fs/btrfs/volumes.c` | ✅ | `BtrfsDeviceSet` in ffs-btrfs with multi-device read dispatch and stripe fallback. `read_logical()` resolves via `map_logical_to_stripes` with RAID0/1/5/6/10/DUP support. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies RAID0/RAID5/RAID6 stripe dispatch, RAID10 mirror-stripe dispatch, DUP mirror dispatch, and RAID1 mirror fallback, while `crates/ffs-ondisk/src/btrfs.rs` now adds metamorphic coverage for stripe translation covariance and chunk-order permutation invariance. |
| btrfs send/receive streams | `fs/btrfs/send.c` | ✅ | `parse_send_stream()` in ffs-btrfs parses the btrfs send stream format (magic, version, per-command CRC32C, required END terminator, 22 command types, attribute TLV encoding). Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies multi-command TLV parsing, missing-END rejection, plus unknown-command fallback to `Unspec` while preserving attributes, and `crates/ffs-harness/tests/btrfs_kernel_reference.rs` differentially compares FrankenFS normalization against upstream `btrfs receive --dump` on a CRC-valid synthetic send stream. |
| btrfs chunk tree walking | `fs/btrfs/volumes.c` | ✅ | `walk_chunk_tree()` in ffs-btrfs walks chunk tree beyond sys_chunk_array for complete chunk map. `parse_chunk_item()` parses individual chunk items, rejects zero stripe device IDs and zero io_align/io_width/sector_size geometry fields at the parser boundary, and rejects trailing bytes after the declared stripe array. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies chunk-tree discovery extends the bootstrap chunk map and returns sorted parsed entries. |
| btrfs device tree discovery | `fs/btrfs/volumes.c`, `fs/btrfs/ioctl.c` | ✅ | `walk_device_tree()` in ffs-btrfs walks device tree to enumerate all physical devices. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies multilevel device-tree traversal returns both discovered `DEV_ITEM` payloads and that each parses into the expected device metadata, with zero device IDs, zero-capacity devices, and impossible `bytes_used > total_bytes` accounting rejected at the on-disk parser boundary. `BTRFS_IOC_DEV_INFO` is wired through the FUSE ioctl surface, and `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path wildcard, exact `devid+uuid`, and missing-device `ENODEV` contracts for the image-backed single-device case. |
| ext4 COMPRESSION (e2compr R/W) | `fs/ext4/inode.c` | ✅ | Full bidirectional e2compr support for the V1 codec set. **Read**: cluster detection via `EXT4_COMPRBLK_FL` + sentinel `0xFFFFFFFF` block pointer, 16-byte cluster header parsing (magic `0x8EC7`, method, holemap, checksum, ulen/clen), seeded Adler-32 checksum verification, gzip/LZO decompression, and checked holemap-based block unpacking that rejects unconsumed decoded bytes. **Write**: cluster-aligned compression with automatic fallback to uncompressed when compression doesn't help, holemap construction for zero-block holes, Adler-32 checksumming, sentinel block pointer management. Gzip (flate2, levels 1-9), LZO (lzokay-native), and passthrough none codecs are supported bidirectionally. Rare legacy method indices 0 (`lzv1`), 4 (`bzip2`), and 8 (`lzrw3a`) are explicit V1 exclusions and reject with codec-specific `EOPNOTSUPP` for both compression and decompression. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now exercises real ext4 e2compr write/read/rewrite behavior for both gzip and LZO on a writable mkfs image, including COMPRBLK marking and stable free-block accounting across rewrites. |
| ext4 JOURNAL_DEV paired-open | `fs/ext4/super.c` | ✅ | Standalone journal device detection (JOURNAL_DEV incompat flag → clear error with guidance). Data filesystems with non-zero `journal_dev` now support paired-open replay through `OpenOptions::external_journal_path`: UUID and block-size validation, external JBD2 replay into the data device, and deterministic refusal when crash recovery is required but the external journal is missing or mismatched. Harness integration coverage in `crates/ffs-harness/tests/ext4_journal_recovery.rs` exercises paired-open replay plus missing/mismatched journal refusal, and `fuzz/fuzz_targets/fuzz_jbd2_replay.rs` now coverage-fuzzes the main JBD2 descriptor/commit/revoke replay engine over equivalent region and segment layouts. |
| ext4 JBD2 checksum verification | `fs/jbd2/recovery.c` | ✅ | CRC32C verification for JBD2 descriptor, revoke, and commit blocks (V2/V3 features). Implemented in `verify_jbd2_block_checksum()` with V3 UUID-seeded checksums and tail-position validation. Direct `ffs-journal` coverage now proves descriptor/revoke checksum roundtrips, tamper detection, and commit-block V3 UUID-seed validation. |

Ext4 xattr parity includes the POSIX ACL namespaces in addition to `user.*` and
`security.*`: `crates/ffs-harness/tests/kernel_reference.rs` now differentially
validates `system.posix_acl_access` and `system.posix_acl_default` against
`debugfs`, while `crates/ffs-harness/tests/fuse_e2e.rs` covers mounted-path
list/get behavior, `XATTR_CREATE`=`EEXIST` and `XATTR_REPLACE`=`ENODATA`
failure semantics for `user.*`, exact public `ENODATA` for missing
`getxattr`/`removexattr` on `user.*`, empty `listxattr` length-0 probe and
exact-fit zero-length success on mounted files with no visible xattrs, plus
missing-default `ENODATA` on the public FUSE surface. `crates/ffs-fuse/src/lib.rs` now also unit-freezes the
shared FUSE dispatcher contract for invalid `setxattr` requests: conflicting
`CREATE|REPLACE`, unsupported flag bits, and nonzero `position` all reject with
exact `EINVAL` before any backend mutation call.

Mounted-path read-only setattr coverage now also freezes the public `EROFS`
contract for `chmod`, `truncate(2)`, and `utime(2)` on both ext4 and btrfs,
including a no-drift postcondition on file bytes and visible metadata.
Mounted-path btrfs read-only namespace coverage now also freezes exact `EROFS`
for `create`, `mkdir`, `link`, and `symlink`, with no directory-entry or seed-file drift.
Mounted-path btrfs read-only regular-file coverage now also freezes exact `EROFS`
for create-via-write and overwrite-on-existing-file paths, with no file-byte or directory-entry drift.
Mounted-path read-only namespace-removal coverage now also freezes exact `EROFS`
for `unlink`, `rmdir`, and `rename` on both ext4 and btrfs, with no
directory-entry drift and no surviving-file data drift.
Mounted-path ext4 namespace-refusal coverage now also freezes exact `ENOTDIR`
for create and mkdir attempts beneath a regular-file parent, with no visible
root-entry or parent-file drift.
Mounted-path ext4 mkdir/rmdir coverage now also freezes parent `st_nlink`
accounting across child-directory creation/removal, with visible root entries
returning to baseline after `rmdir`.
Mounted-path ext4 write-path coverage now also freezes exact `EISDIR` for
opening a directory for write, with no directory-entry drift and no child-file drift.
Mounted-path btrfs write-path coverage now also freezes exact `EISDIR` for
opening a directory for write, with no directory-entry drift and no child-file drift.
Mounted-path unlink-vs-directory coverage now also freezes exact `EISDIR` for
directory targets on both ext4 and btrfs, with no directory-entry or child-file drift.
Mounted-path btrfs namespace-refusal coverage now also freezes exact `ENOTDIR`
for create and mkdir attempts beneath a regular-file parent, with no visible
workspace-entry or parent-file drift.
Mounted-path btrfs symlink refusal coverage now also freezes exact `EEXIST` for
occupied destinations and exact `ENOTDIR` for non-directory parents, with no
visible workspace-entry or parent-file drift.
Mounted-path ext4 `renameat2` flag-rejection coverage now also freezes exact
`EINVAL` for `RENAME_NOREPLACE` and `RENAME_EXCHANGE`, with no source,
destination, or root-entry drift.
Mounted-path btrfs `renameat2` flag-rejection coverage now also freezes exact
`EINVAL` for `RENAME_NOREPLACE` and `RENAME_EXCHANGE`, with no source,
destination, or workspace-entry drift.
Mounted-path ext4 read-only `fallocate` coverage now also freezes exact `EROFS`
for representative preallocate and punch-hole mutation attempts, with no
file-byte or apparent-size drift.
Mounted-path ext4 directory `fallocate` coverage now also freezes exact
`EISDIR`, with no directory-entry drift and no child-file drift regardless of
whether the kernel rejects at directory open or at the `fallocate` boundary.
Mounted-path btrfs read-only `fallocate` coverage now also freezes exact `EROFS`
for representative preallocate and punch-hole mutation attempts, with no
file-byte or apparent-size drift.
Mounted-path btrfs directory `fallocate` coverage now also freezes exact
`EISDIR`, with no directory-entry drift and no child-file drift regardless of
whether the kernel rejects at directory open or at the `fallocate` boundary.
Mounted-path ext4 directory-fd `FIEMAP` coverage now also freezes exact
`EISDIR` once the ioctl reaches FrankenFS userspace, with an explicit soft-skip
for transport-layer `EOPNOTSUPP` before dispatch and no directory or child-file drift.
Mounted-path btrfs directory-fd `FIEMAP` coverage now also freezes exact
`EISDIR` once the ioctl reaches FrankenFS userspace, with an explicit soft-skip
for transport-layer `EOPNOTSUPP` before dispatch and no directory or child-file drift.
Mounted-path read-only `flush` coverage now also freezes success on both ext4
and btrfs, with no file-byte drift and no implied durability boundary.
Mounted-path ext4 namespace refusal coverage now also freezes exact `ENOTDIR`
for `rmdir` on a regular file, distinct from the existing missing-directory and
non-empty-directory contracts.
Mounted-path btrfs namespace refusal coverage now also freezes exact `ENOTDIR`
for `rmdir` on a regular file, distinct from the existing missing-directory and
unlink-vs-directory contracts.
Mounted-path ext4 rename-over-hardlink coverage now also freezes same-inode
destination semantics as a visible no-op: both names stay bound to the original
inode/data and `st_nlink` remains 2.
Mounted-path ext4 rename coverage now also freezes same-name source/destination
semantics as a visible no-op, with no directory-entry drift and no inode/data
drift.
Mounted-path ext4 rename refusal coverage now also freezes exact `EISDIR` for
file-over-directory overwrites and exact `ENOTDIR` for directory-over-file
overwrites, with no root-entry, source-child, or file-byte drift.
Mounted-path ext4 rename refusal coverage now also freezes exact `ENOTEMPTY`
for rename-over-nonempty-directory attempts, with no root-entry, child-entry,
or child-file drift after the rejected overwrite.
Mounted-path btrfs rename coverage now also freezes same-name source/destination
semantics as a visible no-op, with no directory-entry drift and no inode/data
drift.
Mounted-path btrfs rename-over-hardlink coverage now also freezes same-inode
destination semantics as a visible no-op: both names stay bound to the original
inode/data and `st_nlink` remains 2.
Mounted-path btrfs rename refusal coverage now also freezes exact `EISDIR` for
file-over-directory overwrites and exact `ENOTDIR` for directory-over-file
overwrites, with no root-entry, source-child, or file-byte drift.
Mounted-path btrfs rename refusal coverage now also freezes exact `ENOTEMPTY`
for rename-over-nonempty-directory attempts, with no root-entry, child-entry,
or child-file drift after the rejected overwrite.
Mounted-path btrfs cross-parent directory rename coverage now also freezes
parent `st_nlink` accounting: moving a child directory decrements the source
parent, increments the destination parent, and preserves the moved inode.
Mounted-path btrfs hard-link unlink coverage now also freezes `st_nlink`
accounting: removing one hard-link alias deletes only that directory entry,
preserves the surviving inode/data, and restores the survivor link count to 1.
Mounted-path btrfs hard-link refusal coverage now also freezes exact `EPERM`
for directory sources, `ENOTDIR` for non-directory parents, and `EEXIST` for
occupied destinations, with no dirent or source-`st_nlink` drift.
Mounted-path btrfs symlink/refusal coverage now also freezes exact `EINVAL` for
`readlink` on both regular-file and directory non-symlink paths, with no
directory-entry or file-byte drift.
Mounted-path btrfs unlink coverage now also freezes exact `ENOENT` for missing
targets, with no visible workspace-entry or witness-file drift.
Mounted-path btrfs rename refusal coverage now also freezes exact `ENOTDIR`
for rename attempts whose destination parent is a regular file, with no source
or parent-file drift.
Mounted-path btrfs rename coverage now also freezes exact `ENOENT` for missing
source paths, with no visible workspace-entry or witness-file drift.
Mounted-path ext4 symlink/refusal coverage now also freezes exact `EINVAL` for
`readlink` on both regular-file and directory non-symlink paths, with no
directory-entry or file-byte drift.
FUSE/statfs parity now also freezes the ext4 group-descriptor accounting
contract: total geometry still comes from the superblock, while free block and
inode counts are aggregated from live group descriptors so write-side allocation
changes are visible to `statfs` without relying on stale open-time superblock
counters.
FUSE splice/sendfile parity now also has an implemented large-transfer
contract: the mount negotiates splice read/write/move capability bits, the
vendored FUSE ABI exposes `FUSE_COPY_FILE_RANGE`, `FrankenFuse` routes
`copy_file_range` through the MVCC-aware `FsOps` read/write contract with
Linux-compatible validation for flags, negative offsets, and overlapping
same-inode ranges; validated zero-length requests now return `0` without
opening a backend request scope, committing, reading, writing, or invalidating
readahead, matching the Linux no-op contract. Mounted-path coverage writes 16
MiB through `splice(2)` pipe-to-file transfer and verifies byte-for-byte
SHA-256 equality, while direct ext4 and btrfs `copy_file_range(2)` probes now
exercise cross-file offset copies, same-inode non-overlapping copies,
zero-length no-ops, and same-inode overlap `EINVAL`/no-drift behavior through
the mounted FUSE path.
Additional mounted-path probes mirror the local xfstests splice/sendfile cases
that actually exercise this surface (`generic/249`, `generic/591`, and
`generic/680`). The 1 GiB `sendfile(2)` throughput comparison is retained as an
ignored benchmark gate for `bd-qpoys`; the current measured gate emits
`SCENARIO_RESULT|scenario_id=ext4_rw_sendfile_1g_vs_naive_read_write|outcome=PASS`
for the >=2x contract. Coverage-guided parity stress now also includes
`fuzz_fuse_splice_mount`, which exercises the no-live-mount FUSE read/write
and `copy_file_range` dispatch paths used by splice/sendfile-style transfers
while checking deterministic mount-option labels and the explicit
writeback-cache-disabled policy.

### 2.1 btrfs Experimental RW Capability Contract (Machine-Checkable)

The table below is the authoritative btrfs experimental RW contract for `bd-h6nz.3.1`.
Each row maps directly to deterministic unit/E2E coverage by stable test/scenario ID.
`supported`, `partially supported`, and `unsupported` classify the expected V1
behavior of that operation, not whether the row is unimplemented.

| Contract ID | Operation / Edge Case | Class | Expected Result |
|-------------|------------------------|-------|-----------------|
| `unit::btrfs_write_create_file` | `create` regular file | supported | success |
| `unit::btrfs_write_mkdir` | `mkdir` | supported | success |
| `unit::btrfs_write_rename` | `rename` (same/cross parent) | supported | success |
| `unit::btrfs_write_setattr_truncate` | `setattr(size)` truncate path | supported | success |
| `unit::btrfs_write_xattr_set_get_list` | `setxattr/getxattr/listxattr` | supported | success |
| `unit::btrfs_write_xattr_respects_create_and_replace_modes` | `setxattr` mode semantics (`Create`/`Replace`) | supported | existing key rejects `Create` with `EEXIST`; missing key rejects `Replace` with `ENOENT` in `ffs-core`, and mounted Linux FUSE remaps that public path to `ENODATA`; mounted-path `getxattr`/`removexattr` on missing `user.*` names also now freeze exact `ENODATA`; mounted-path zero-sized `getxattr`/`listxattr` probes now freeze exact required lengths, undersized buffers return `ERANGE`, and empty `listxattr` now freezes length 0 plus exact-fit zero-length success; read-only mounted-path `setxattr`/`removexattr` now freeze exact `EROFS`; no side effects |
| `unit::btrfs_write_fallocate_basic` | `fallocate` preallocation (`mode=0`) | supported | success |
| `unit::btrfs_write_fallocate_keep_size_does_not_extend_file` | `fallocate` with `FALLOC_FL_KEEP_SIZE` | supported | success, file size unchanged, backing blocks reserved, allocator free space decreases |
| `harness::btrfs_fallocate_does_not_prealloc_over_live_data_conforms` | `fallocate` over initialized btrfs extents | supported | success, preallocation over live data does not insert overlapping unwritten FIEMAP extents, the initialized extent remains initialized, and readback preserves data |
| `unit::btrfs_write_fallocate_punch_hole_zeroes_data` | `fallocate` with `FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE` | supported | success, file size preserved, punched range reads back as zeros, unaffected bytes remain intact |
| `unit::btrfs_write_fallocate_zero_range_zeroes_data` | `fallocate` with `FALLOC_FL_ZERO_RANGE` | supported | success, requested range reads back as zeros, unaffected bytes remain intact |
| `unit::btrfs_write_fallocate_zero_range_keep_size_does_not_extend_file` | `fallocate` with `FALLOC_FL_ZERO_RANGE|FALLOC_FL_KEEP_SIZE` | supported | success, file size unchanged when range extends past EOF |
| `unit::btrfs_write_fallocate_collapse_range_shifts_tail_and_shrinks_file` | `fallocate` with `FALLOC_FL_COLLAPSE_RANGE` | supported | success, aligned range is removed, tail data shifts left, and file size shrinks |
| `unit::btrfs_write_fallocate_insert_range_shifts_tail_and_grows_file` | `fallocate` with `FALLOC_FL_INSERT_RANGE` | supported | success, aligned zero hole is inserted, tail data shifts right, and file size grows |
| `unit::btrfs_write_fallocate_collapse_range_preserves_shifted_prealloc_fiemap` | `FALLOC_FL_COLLAPSE_RANGE` shifting a prealloc extent | supported | success, shifted prealloc remains allocated and reports `FIEMAP_EXTENT_UNWRITTEN` at its new logical offset |
| `unit::btrfs_write_fallocate_insert_range_preserves_shifted_prealloc_fiemap` | `FALLOC_FL_INSERT_RANGE` shifting a prealloc extent | supported | success, inserted range is a hole while shifted prealloc remains allocated and reports `FIEMAP_EXTENT_UNWRITTEN` |
| `unit::btrfs_write_fallocate_collapse_range_reaching_eof_rejects_without_mutation` | `FALLOC_FL_COLLAPSE_RANGE` reaching EOF | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_insert_range_at_eof_rejects_without_mutation` | `FALLOC_FL_INSERT_RANGE` at EOF | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_range_modes_reject_unaligned_with_einval_without_mutation` | exclusive range modes with unaligned offset/length | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_range_modes_reject_invalid_combinations_without_mutation` | exclusive range modes combined with other flags | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_unsupported_mode_bits_rejected` | `fallocate` with unsupported mode bits | unsupported | `FfsError::UnsupportedFeature` -> `EOPNOTSUPP` |
| `unit::btrfs_write_fallocate_success_log_contract` | supported fallocate log contract | observability | structured log includes `operation_id`, `scenario_id`, `outcome=applied` |
| `unit::btrfs_write_fallocate_rejection_log_contract` | unsupported fallocate log contract | observability | structured log includes `operation_id`, `scenario_id`, `outcome=rejected`, `error_class` |
| `unit::btrfs_write_fallocate_unsupported_mode_bits_log_contract` | unsupported mode-bits fallocate log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fallocate_unsupported_mode_bits`, `outcome=rejected`, `error_class=unsupported_mode_bits` |
| `unit::btrfs_write_fsync_log_contract_success` | `fsync` success log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsync`, `outcome=applied` |
| `unit::btrfs_write_fsync_rejection_log_contract_read_only` | `fsync` read-only rejection log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsync`, `outcome=rejected`, `error_class=read_only` |
| `unit::btrfs_write_fsyncdir_log_contract_success` | `fsyncdir` success log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsyncdir`, `outcome=applied` |
| `e2e::ext4_rw_flush` | FUSE path ext4 flush contract | observability | shell-visible success, file contents remain readable after explicit `flush` + close within the mounted session, emitted `SCENARIO_RESULT` marker, and does not claim a durability boundary |
| `e2e::btrfs_rw_flush` | FUSE path btrfs flush contract | observability | shell-visible success, file contents remain readable after explicit `flush` + close within the mounted session, emitted `SCENARIO_RESULT` marker, and does not claim a durability boundary |
| `e2e::btrfs_rw_fallocate_preallocate_extends_size` | FUSE path btrfs preallocation contract | supported | shell-visible success, file size extends to requested length, data blocks are allocated, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_keep_size_preserves_size` | FUSE path btrfs keep-size preallocation contract | supported | shell-visible success, apparent file size is preserved, original bytes remain readable, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_punch_hole_keep_size_zeroes_range` | FUSE path punch-hole zero-fill under `KEEP_SIZE` | supported | shell-visible success, file size unchanged, punched range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_zero_range_zeroes_range` | FUSE path zero-range contract | supported | shell-visible success, requested range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_collapse_range` | FUSE path collapse-range contract | supported | shell-visible success, requested aligned range removed, tail shifted left, file size shrunk, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_insert_range` | FUSE path insert-range contract | supported | shell-visible success, aligned zero hole inserted, tail shifted right, file size grown, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_invalid_punch_hole_without_keep_size_errno_einval` | FUSE path invalid `PUNCH_HOLE` without `KEEP_SIZE` rejection | supported | when the request reaches FrankenFS userspace dispatch, shell-visible errno 22 (`EINVAL`) is frozen with no file-size or data drift; current kernel/FUSE stacks that collapse the invalid mode to errno 95 (`ENOTSUP`/`EOPNOTSUPP`) before dispatch soft-skip after still proving no drift |
| `e2e::btrfs_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp` | FUSE path unsupported mode-bit rejection | unsupported | shell-visible errno 95 (`EOPNOTSUPP`/`ENOTSUP`), emitted `SCENARIO_RESULT` marker, file contents preserved |
| `e2e::ext4_rw_fallocate_preallocate_extends_size` | FUSE path ext4 preallocation contract | supported | shell-visible success, file size extends to requested length, data blocks are allocated, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_fallocate_keep_size_preserves_size` | FUSE path ext4 keep-size preallocation contract | supported | shell-visible success, apparent file size is preserved, data blocks are allocated, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_fallocate_punch_hole_keep_size_zeroes_range` | FUSE path ext4 punch-hole zero-fill under `KEEP_SIZE` | supported | shell-visible success, file size unchanged, punched range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_fallocate_zero_range_zeroes_range` | FUSE path ext4 zero-range contract | supported | shell-visible success, requested range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_invalid_punch_hole_without_keep_size_errno_einval` | FUSE path ext4 invalid `PUNCH_HOLE` without `KEEP_SIZE` rejection | supported | when the request reaches FrankenFS userspace dispatch, shell-visible errno 22 (`EINVAL`) is frozen with no file-size or data drift; current kernel/FUSE stacks that collapse the invalid mode to errno 95 (`ENOTSUP`/`EOPNOTSUPP`) before dispatch soft-skip after still proving no drift |
| `e2e::ext4_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp` | FUSE path ext4 unsupported mode-bit rejection | unsupported | shell-visible errno 95 (`EOPNOTSUPP`/`ENOTSUP`), emitted `SCENARIO_RESULT` marker, file contents preserved |
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
| `e2e::ext4_rw_crash_matrix_01_create_alpha_no_fsync` | crash point 1 (create) | crash-consistency | post-crash RO remount tolerates absent-or-empty file state; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_02_append_alpha_no_fsync` | crash point 2 (append write) | crash-consistency | post-crash RO remount bounds recovered data to the pre-crash payload envelope; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_03_fsync_alpha_and_parent` | crash point 3 (fsync file/parent boundary) | crash-consistency | durable file data + directory entry survive crash after `fsync` + `fsyncdir`; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_04_rename_alpha_to_beta_no_fsync` | crash point 4 (rename) | crash-consistency | post-crash rename envelope verified (`alpha` xor `beta` present); `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_05_fsync_rename_parent` | crash point 5 (rename fsync boundary) | crash-consistency | durable rename boundary verified after parent directory fsync; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_06_unlink_beta_no_fsync` | crash point 6 (unlink beta) | crash-consistency | post-crash non-fsync unlink envelope verified without stale-data divergence; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_07_truncate_beta_fsync` | crash point 7 (truncate fsync boundary) | crash-consistency | durable truncate boundary verified after post-truncate `fsync`; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_08_multi_file_interleaved_fsync` | crash point 8 (multi-file interleaving) | crash-consistency | fsynced file survives while later non-fsynced file remains within recovery envelope; `CRASH_MATRIX_EVENT` emitted |
| MVCC snapshot visibility | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| MVCC commit sequencing | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| FCW conflict detection | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc`; OQ2 (`bd-h6nz.6.2`) resolved for V1.x as strict FCW+SSI (safe-merge/adaptive arbitration deferred) with deterministic contention evidence in `crates/ffs-mvcc/tests/mvcc_stress_suite.rs` |
| version retention policy | FrankenFS spec §3 | ✅ | In-memory retention with `VersionData::Identical` dedup (zero-copy for unchanged blocks), configurable `CompressionPolicy` (dedup + max chain length cap), watermark-safe pruning, chain-pressure handling (oldest-snapshot force-advance + `CommitError::ChainBackpressure`), and crossbeam-epoch deferred reclamation counters/collection (`ebr_stats`, `ebr_collect`) in `ffs-mvcc` |
| COW block rewrite path | FrankenFS spec §3 | ✅ | Allocation-backed COW rewrite path implemented in `ffs-mvcc` (`write_cow`, logical→physical mapping visibility, deferred-free + watermark GC integration) |
| durability policy model | FrankenFS spec §4 | ✅ | Bayesian expected-loss selector |
| asupersync config mapping | FrankenFS spec §4 | ✅ | `RaptorQConfig` mapping implemented |
| format-aware scrub superblock validation | FrankenFS spec §4 | ✅ | `Ext4SuperblockValidator` + `BtrfsSuperblockValidator` in `ffs-repair`, wired into `ffs-cli scrub` |
| repair symbol storage I/O (dual-slot generation commit) | FrankenFS spec §4 | ✅ | `RepairGroupStorage` in `ffs-repair::storage` with symbol-block validation + torn-generation fallback; OQ3 (`bd-h6nz.6.3`) resolved for V1.x as bounded staleness (lazy 30s default + timeout/adaptive-eager escalation) with deterministic refresh-policy evidence in `crates/ffs-repair/src/pipeline.rs` tests and `scripts/e2e/ffs_repair_recovery_smoke.sh`. `fuzz/fuzz_targets/fuzz_repair_symbols.rs` now coverage-fuzzes the raw repair block header, repair group descriptor, and symbol digest parsers with valid and truncated corpus seeds. |
| corruption recovery orchestrator + evidence ledger | FrankenFS spec §4 | ✅ | `GroupRecoveryOrchestrator` in `ffs-repair::recovery` (decode + explicit `RecoveryWriteback` authority + post-verify + JSON evidence). `OpenFs::repair_writeback_blocks_via_mounted_mutation_path` now provides the mounted MVCC request-scope authority for recovered physical blocks, rejects stale `expected_current` bytes before staging, and performs durable flush plus verification before repair-symbol refresh. |
| FUSE getattr | FrankenFS spec §9 | ✅ | `FsOps::getattr` via `OpenFs` |
| FUSE lookup | FrankenFS spec §9 | ✅ | `FsOps::lookup` via `OpenFs` |
| FUSE readdir | FrankenFS spec §9 | ✅ | `FsOps::readdir` via `OpenFs` |
| FUSE read | FrankenFS spec §9 | ✅ | `FsOps::read` via `OpenFs` |
| FUSE readlink | FrankenFS spec §9 | ✅ | `FsOps::readlink` via `OpenFs` |
| FUSE mount runtime | FrankenFS spec §9 | ✅ | Production runtime lifecycle, signal handling, dispatch coverage, and CI-safe skip behavior are implemented; OQ4 (`bd-h6nz.6.4`) is resolved for V1.x with explicit `flush` (non-durable) vs `fsync`/`fsyncdir` (durability boundary) contract and writeback-cache-disabled policy. `crates/ffs-harness/tests/fuse_e2e.rs` now emits `SCENARIO_RESULT` coverage for ext4 (`ext4_rw_flush`, `ext4_rw_fdatasync`, `ext4_rw_fsync`, `ext4_rw_fsyncdir`, `ext4_rw_seek_data_hole`, `ext4_rw_seek_hole_fully_allocated`, `ext4_rw_seek_leading_hole`, `ext4_rw_seek_all_hole`) and btrfs (`btrfs_rw_flush`, `btrfs_rw_fdatasync`, `btrfs_rw_fsync`, `btrfs_rw_fsyncdir`, `btrfs_rw_seek_data_hole`, `btrfs_rw_seek_hole_fully_allocated`, `btrfs_rw_seek_leading_hole`, `btrfs_rw_seek_all_hole`) through real file flushes, file- and directory-FD sync calls, and mounted-path `SEEK_DATA`/`SEEK_HOLE` probes for punched-hole, fully allocated, leading-hole, and all-hole layouts with EOF `ENXIO` verification. The ext4 syscall-level differential probe now compares the mounted FrankenFS path against a Linux reference directory for file lifecycle, metadata, link, mmap, fsync, offset I/O (`pread`/`pwrite`), `SEEK_END`, `fdatasync`, `utime`, `access`, `openat`-style directory-relative lookup, and normalized `statvfs` semantics; btrfs read-only mounted-path `fsync`, `fdatasync`, and `fsyncdir` now also freeze exact `EROFS` with no data or dirent drift. |
| FUSE mount background scrub lifecycle | FrankenFS spec §4 / §9 | ✅ | `ffs mount` now starts a detection-only `ffs-repair::ScrubDaemon` automatically for default read-only mounts, owns cancellation through a mount lifecycle guard, joins the worker on shutdown, and emits structured start/stop/error logs. CLI controls cover `--background-scrub`, `--no-background-scrub`, `--background-scrub-interval-secs`, `--background-scrub-ledger`, and `--background-repair`; the repair flag implies scrub, requires a durable ledger, checks writable backing-image access, and runs the recovery/writeback plus repair-symbol refresh path. Client read-only mounted repair uses an explicit direct-device authority. Read-write mounted repair uses the mounted MVCC request-scope authority, carries scrub-time bytes into stale-snapshot rejection, keeps kernel FUSE writeback-cache mode disabled, and remains opt-in because read-write mounts keep background scrub disabled by default. Coverage: `crates/ffs-cli/src/main.rs` mount config/start-stop tests, `crates/ffs-core/src/lib.rs` mounted repair-writeback request-scope and deterministic repair/client-write race tests, `crates/ffs-repair/src/pipeline.rs` repair-enabled, custom-authority, stale expected-current, rejection, and detection-only daemon tests, and `scripts/e2e/ffs_repair_writeback_route_e2e.sh` route/CLI/writeback-cache scenarios. |
| FUSE ABI 7.40 protocol surface | FUSE kernel ABI 7.40 / libfuse 3.x | ✅ | Workspace builds the vendored `fuser` crate with `abi-7-40`, and `FrankenFuse::init` now negotiates `FUSE_SPLICE_READ`, `FUSE_SPLICE_WRITE`, `FUSE_SPLICE_MOVE`, and `FUSE_PASSTHROUGH` with stack depth 1 when the kernel advertises support. The vendored `fuser` protocol layer now exposes opcode 52 (`FUSE_STATX`), parses `fuse_statx_in`, replies with Linux statx-compatible `fuse_statx_out`, and preserves `FileAttr::crtime` as `STATX_BTIME`; `FrankenFuse::statx` routes that opcode through the existing `getattr` backend. The vendored ABI surface also exposes `FUSE_WRITE_KILL_SUIDGID`/legacy `FUSE_WRITE_KILL_PRIV` plus Linux `RWF_*` constants for write-intent propagation. Unit coverage freezes ABI constants, STATX request parsing, birth-time reply encoding, and mounted splice pipe-to-file transfer. |
| FUSE pwritev2/io_uring RWF write intent propagation | `pwritev2(2)`, FUSE `WRITE` request flags | ✅ | `FrankenFuse::write` now decodes synchronous write intent from the FUSE `flags` field (`O_DSYNC`/`O_SYNC`) and routes it through `FsOps::fsync` after the normal MVCC commit, so `RWF_DSYNC` uses a data-sync boundary and `RWF_SYNC` uses a full sync boundary. The implementation deliberately does not treat `fuse_write_in.write_flags` bit 1 as `RWF_DSYNC`, because that bit is already `FUSE_WRITE_LOCKOWNER`; unit coverage freezes that collision and verifies no accidental fsync. `RWF_HIPRI` is treated as a harmless priority/cache hint because bit 0 is also `FUSE_WRITE_CACHE`; coverage freezes that it preserves the normal write contract without sync, NOWAIT, append, or unsupported-intent side effects, and mounted-path ext4 plus btrfs `os.pwritev(..., RWF_HIPRI)` coverage now proves accepted calls preserve caller-offset overwrite semantics. `FUSE_WRITE_KILL_SUIDGID` is likewise kept as a metadata write hint despite sharing raw bit 2 with `RWF_SYNC`; unit coverage freezes that it preserves the normal write contract without an accidental full fsync. `RWF_NOWAIT` uses the non-conflicting RWF bit to attempt inode mutation-lock acquisition without blocking and returns `EAGAIN` when the lock is already held; mounted-path ext4 plus btrfs coverage now proves accepted uncontended `RWF_NOWAIT` calls preserve normal caller-offset overwrite semantics. `RWF_APPEND` and `O_APPEND` resolve the write offset to current EOF under the inode mutation guard, while `RWF_NOAPPEND` preserves the caller offset on an append-open file; the Linux-invalid `RWF_APPEND|RWF_NOAPPEND` combination rejects with `EINVAL` before EOF lookup or mutation. Unsupported non-conflicting write intents that require guarantees FrankenFS does not provide yet (`RWF_ATOMIC` torn-write protection and `RWF_DONTCACHE` cache-bypass/drop semantics) reject with `EOPNOTSUPP` before backend mutation. `crates/ffs-fuse/src/lib.rs` unit tests cover DSync, Sync, flag-collision hints, NOWAIT fast-fail, append, NOAPPEND, invalid append/NOAPPEND conflicts, and unsupported-intent rejection behavior, while `crates/ffs-harness/tests/fuse_e2e.rs` adds mounted-path `os.pwritev(...)` probes for `RWF_DSYNC`, `RWF_SYNC`, `RWF_HIPRI`, `RWF_NOWAIT`, `RWF_APPEND`, `RWF_NOAPPEND`, the invalid `RWF_APPEND|RWF_NOAPPEND` pair, and unsupported `RWF_ATOMIC`/`RWF_DONTCACHE` intents, proving sync writes become immediately readable and survive remount on both ext4 and btrfs, and that harmless hints, NOWAIT uncontended offset writes, append/NOAPPEND offset semantics, and unsupported-intent no-mutation contracts are exercised on both formats when the host permits FUSE and forwards the flags. |
| FUSE inotify rename + dentry notification lifecycle | `fs/notify/fsnotify.c`, `fs/notify/inotify/inotify_user.c`, FUSE notify protocol | ✅ | `FrankenFuse` captures a `fuser::Notifier` during blocking, background, and managed mount setup, then issues `FUSE_NOTIFY_INVAL_ENTRY` for successfully committed `unlink`, `rmdir`, and both old/new directory entries after `rename`. Plain renames deliberately avoid `FUSE_NOTIFY_DELETE`, preserving the kernel/VFS `IN_MOVED_FROM` + `IN_MOVED_TO` cookie-pair contract instead of synthesizing delete/create observations. `crates/ffs-harness/tests/fuse_e2e.rs` now carries mounted-path inotify probes for 100 same-parent renames and a cross-directory rename; both assert non-zero matching cookies and reject `IN_CREATE`, `IN_DELETE`, `IN_Q_OVERFLOW`, and `IN_IGNORED` during plain rename bursts, with the standard CI soft-skip when the current host denies FUSE mounting. |
| FUSE ioctl FIEMAP / FIBMAP | `include/linux/fiemap.h`, `fs/ext4/inode.c::ext4_bmap` | ✅ | `FsOps::fiemap` queries ext4 extent tree via `collect_extents_with_scope` and btrfs extent data items via `btrfs_fiemap_extent_items`. FUSE `ioctl` handler parses `FS_IOC_FIEMAP` (0xC020660B), rejects unsupported request flags with `EBADR`, honors `FIEMAP_FLAG_SYNC` by fsyncing writable mounts before extent lookup, and marshals the fiemap header plus extent array. Legacy `FIBMAP` routes through the same 1-block FIEMAP lookup and now maps holes plus `FIEMAP_EXTENT_UNWRITTEN` prealloc extents to physical block `0`, matching ext4's unwritten-extent bmap contract. `crates/ffs-core` has deterministic btrfs coverage for inline extents (`physical=0`, `FIEMAP_EXTENT_LAST`) and keep-size prealloc extents (`FIEMAP_EXTENT_UNWRITTEN`), while `crates/ffs-fuse` pins FIBMAP written vs unwritten dispatch behavior and `crates/ffs-harness/tests/fuse_e2e.rs` verifies mounted-path FIEMAP reporting for ext4 regular files, ext4 `SYNC` and invalid-request-flag contracts, plus btrfs regular, inline, and keep-size prealloc files. Note: FUSE transport may not deliver these ioctls to userspace on all kernel versions. |
| FUSE ioctl EXT4_IOC_GETFLAGS | `fs/ext4/ioctl.c` | ✅ | `FsOps::get_inode_flags` returns raw ext4 `i_flags` field. FUSE `ioctl` handler dispatches `EXT4_IOC_GETFLAGS` (0x80086601). Harness integration coverage in `crates/ffs-harness/tests/fuse_e2e.rs` now verifies mounted-path `GETFLAGS` on a writable ext4 file. |
| FUSE ioctl EXT4_IOC_GETVERSION / EXT4_IOC_SETVERSION | `fs/ext4/ioctl.c` | ✅ | `FsOps::get_inode_generation` returns ext4 `i_generation`, and `FsOps::set_inode_generation` now updates that field in-place, persists it via `ffs_inode::write_inode`, and keeps the ext4-only contract explicit. `ffs-fuse` dispatches `EXT4_IOC_GETVERSION` (0x80086603) and `EXT4_IOC_SETVERSION` (0x40086604), enforces the 4-byte userspace payload contract, and commits `SETVERSION` through the normal write request scope. `crates/ffs-core` unit tests cover direct ext4 mutation plus reopen persistence, `crates/ffs-fuse` unit tests cover getter encoding and setter routing, and `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path `SETVERSION`/`GETVERSION` roundtrips when the current kernel/FUSE stack forwards the ioctl. The mounted-path test soft-skips with explicit scenario results when the kernel/VFS rejects `GETVERSION` or `SETVERSION` before userspace dispatch. |
| FUSE ioctl EXT4_IOC_SETFLAGS | `fs/ext4/ioctl.c` | ✅ | `FsOps::set_inode_flags` with user-settable flag masking (`EXT4_USER_SETTABLE_FLAGS`). System flags (EXTENTS, HUGE_FILE, etc.) protected. FUSE `ioctl` handler dispatches `EXT4_IOC_SETFLAGS` (0x40086602), requires write mode. Direct `ffs-fuse` dispatch coverage verifies write-scope routing and masked flag persistence; mounted-path E2E in `crates/ffs-harness/tests/fuse_e2e.rs` now covers generic flag roundtrips plus ext4 `EXT4_COMPR_FL` enable-on-empty-file behavior on COMPRESSION-feature images, post-ioctl compressed write/readback, and stable `EOPNOTSUPP` rejection when the COMPRESSION incompat bit is absent. The tests still soft-skip when the current kernel/FUSE stack rejects the write ioctl with `ENOTTY` before userspace dispatch. |
| FUSE ioctl FS_IOC_GETFSLABEL / FS_IOC_SETFSLABEL | `fs/ioctl.c`, ext4 superblock volume name field | ✅ | `OpenFs::get_fs_label` now rereads the ext4 superblock on each request so mounted and direct-image callers observe post-mutation labels instead of the open-time cache. `OpenFs::set_fs_label` rewrites `s_volume_name`, preserves the ext4 16-byte limit, rejects interior NULs with `EINVAL`, and recomputes the superblock checksum when `metadata_csum` is enabled. `ffs-fuse` dispatches `FS_IOC_GETFSLABEL` (0x81009431) and `FS_IOC_SETFSLABEL` (0x41009432), enforces the 256-byte userspace buffer contract, rejects unterminated setter payloads with `EINVAL`, and commits through the normal write request scope. `crates/ffs-core` unit tests cover direct ext4 mutation and reopen persistence; `crates/ffs-fuse` unit tests cover getter sizing plus setter routing; `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path ext4 label updates survive remount, with direct-image verification fallback when the current kernel/FUSE stack blocks remount `GETFSLABEL` before userspace dispatch. |
| FUSE ioctl EXT4_IOC_MOVE_EXT | `fs/ext4/ioctl.c`, kernel ext4 admin-guide ioctl table | ✅ | `ffs-fuse` parses and validates `struct move_extent`, resolves the caller's donor fd from `/proc/<pid>/fd/<n>`, verifies the donor stays on the mounted filesystem, temporarily registers the donor inode for `OpenFs::move_ext`, and emits structured `operation_id` / `scenario_id` / `outcome` / `error_class` logs for success and rejection. `crates/ffs-core` keeps mkfs-backed backend tests for `EBADF`, short moved-length-at-EOF behavior, hole rejection, and middle-range extent swapping, while `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path middle-range exchange plus hole-backed rejection over a real ext4 FUSE mount with ioctl-trace evidence. |
| CLI inspect command | FrankenFS spec §6 | ✅ | Implemented in `ffs-cli` |
| CLI info command | FrankenFS spec §14.2 | ✅ | `ffs info` implemented in `ffs-cli` with optional `--groups`, `--mvcc`, `--repair`, and `--journal` sections plus `--json` output |
| CLI dump command | FrankenFS spec §14.4 | ✅ | `ffs dump` implemented in `ffs-cli` with subcommands `superblock`, `group`, `inode`, `extents`, and `dir`, each supporting `--json` and `--hex` |
| CLI fsck command | FrankenFS spec §14.1 | ✅ | `ffs fsck` implemented in `ffs-cli` with `--repair`, `--force`, `--verbose`, `--block-group`, and `--json`; checks include superblock/group-descriptor validation + scoped scrub reporting, `--block-group` now supports ext4 groups and btrfs block-group indexes (extent-tree discovered), and `--repair` executes ext4 mount-time journal/orphan recovery plus btrfs primary-superblock restoration from validated backup mirrors with post-write scrub verification, including bootstrap recovery when initial btrfs detection fails due to primary-superblock corruption. V1.x write-side repair is explicitly single-host only via a persistent per-image coordination record (`.<image>.ffs-repair-owner.json`); foreign-host ownership blocks mutation but still reports read-only diagnostics. |
| CLI repair command | FrankenFS spec §14.3 | ✅ | `ffs repair` implemented in `ffs-cli` with `--full-scrub`, `--block-group`, `--rebuild-symbols`, `--verify-only`, `--max-threads`, and `--json`; ext4 path performs stale-scope selection, block-symbol reconstruction attempts, symbol re-encoding (`--rebuild-symbols` + post-recovery refresh), and post-write verification scrub, while btrfs now supports scoped `--block-group` scrub by discovered block-group index plus primary-superblock restoration from validated backup mirrors, including bootstrap recovery when initial btrfs detection fails due to primary-superblock corruption. V1.x write-side repair is explicitly single-host only via a persistent per-image coordination record (`.<image>.ffs-repair-owner.json`); broader multi-host write-side recovery and symbol rebuild remain unsupported. |
| fixture conformance harness | FrankenFS spec §7 | ✅ | Implemented in `ffs-harness`, including kernel-reference differential coverage for ext4 xattrs via `debugfs ea_list`/`ea_get` and write-path parity coverage that replays `ea_set` mutations through `ffs-xattr::set_xattr` in `crates/ffs-harness/tests/kernel_reference.rs` |
| benchmark harness | FrankenFS spec §8 | ✅ | Criterion benchmark added |
| xfstests generic/ext4 subset infrastructure | xfstests (`check`, generic/, ext4/) | ✅ | Curated subset manifests, planner/runner automation, CI planning gate, and regression guard workflow are implemented. The allowlist is revalidated against mounted-path ioctl/fallocate evidence: `ext4/001` is now tracked as likely-pass pending direct xfstests rerun because FrankenFS already proves ZERO_RANGE + FIEMAP separately, while `ext4/005` remains allowlisted only for the narrower unsupported `chattr -e` extent-to-non-extent conversion path. |

Legend: `✅` implemented.

## 3. Blocking Gaps in the Tracked V1 Matrix

No blocking gaps in the tracked V1 parity matrix.

## 4. Operational Bridge Items Outside the Parity Denominator

These items do not reduce the 97/97 tracked feature count because they are not
additional rows in the current denominator. They are still required before this
project can honestly claim operational readiness beyond the current V1 contract.

| Bead | Area | Status |
|------|------|--------|
| `bd-rchk1` | Docs/status reconciliation | Complete: canonical docs separate tracked parity from runtime readiness |
| `bd-rchk2` | btrfs delayed-reference semantics | Complete: `DISC-004` accepted as a scoped V1 model with retry-safe failed-flush and overflow coverage |
| `bd-rchk3` | xfstests baseline | In progress: 2026-05-01 subset/regression gate recorded; real execution blocked by unbuilt xfstests helpers and a dpkg lock blocking `xfslibs-dev`/`libaio-dev` install |
| `bd-rchk4` | CI-compatible mounted FUSE coverage | Open: make critical mounted-path tests run in a permissioned environment with explicit skip diagnostics |
| `bd-rchk5` | Performance baselines | Open: re-measure throughput/latency claims against current code |
| `bd-rchk6` | Mounted self-healing lifecycle | Complete: automatic mounted repair is implemented for explicit `--background-repair --background-scrub-ledger <jsonl>` mounts; read-write repair routes recovered source blocks through the mounted MVCC repair-writeback serializer and rejects stale scrub snapshots before mutation |
| `bd-rchk7` | Fuzz/conformance expansion | Open: close or bead remaining open-ended corpus expansion notes |

## 5. Update Rule

Any change touching compatibility behavior MUST update this file in the same patch.
