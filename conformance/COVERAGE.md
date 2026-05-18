# Conformance Coverage Matrix

> Tracks what's tested vs what's not. Score < 0.95 for MUST clauses = NOT conformant.

## ext4 On-Disk Structures

| Structure | Fixture | Test | MUST Clauses | Passing | Score | Notes |
|-----------|:-------:|:----:|:------------:|:-------:|:-----:|-------|
| Ext4Superblock | ✅ | ✅ | 12 | 12 | 100% | sparse + mkfs variants |
| Ext4GroupDesc | ✅ | ✅ | 8 | 8 | 100% | 32-byte + 64-byte variants |
| Ext4Inode | ✅ | ✅ | 10 | 10 | 100% | regular file + directory + inline data |
| Ext4DirEntry | ✅ | ✅ | 6 | 6 | 100% | with tail, deleted, edge cases |
| Ext4DirEntryTail | ✅ | ✅ | 3 | 3 | 100% | checksum verification |
| Ext4Extent | ✅ | ✅ | 5 | 5 | 100% | leaf + unwritten extent |
| Ext4ExtentHeader | ✅ | ✅ | 4 | 4 | 100% | via leaf + index fixtures |
| Ext4ExtentIndex | ✅ | ✅ | 3 | 3 | 100% | via index fixture |
| Ext4Xattr (ibody) | ✅ | ✅ | 4 | 4 | 100% | via inline_data_with_continuation |
| Ext4Xattr (block) | ✅ | ✅ | 4 | 4 | 100% | user + security attrs |
| Ext4DxRoot | ✅ | ✅ | 3 | 3 | 100% | htree DX root with 3 entries |
| Ext4DxEntry | ✅ | ✅ | 2 | 2 | 100% | via dx_root fixture |
| Ext4MmpBlock | ✅ | ✅ | 2 | 2 | 100% | clean state, status decoding |
| Ext4InlineData read boundary | ✅ | ✅ | 2 | 2 | 100% | reads crossing, at, and past EOF return exact bytes/empty output for inode-body and xattr continuation storage |
| Ext4InlineData extreme read boundary | ✅ | ✅ | 2 | 2 | 100% | zero-size reads return empty and oversized/extreme-offset reads clamp safely for inode-body and xattr-continuation storage |
| Ext4InlineData VFS surface | ✅ | ✅ | 3 | 3 | 100% | mounted root `readdir`, `lookup`/`getattr`, path resolution, and readback through looked-up inode for inline and xattr-continuation storage |
| Ext4InlineData RW boundary | ✅ | ✅ | 2 | 2 | 100% | read-compatible; write/fallocate mutation rejects with `EOPNOTSUPP` and preserves data |

**ext4 Total: 75 MUST clauses, 75 passing = 100.0%**

## btrfs On-Disk Structures

| Structure | Fixture | Test | MUST Clauses | Passing | Score | Notes |
|-----------|:-------:|:----:|:------------:|:-------:|:-----:|-------|
| BtrfsSuperblock | ✅ | ✅ | 18 | 18 | 100% | sparse + with_chunks variants plus invalid accounting rejection |
| BtrfsChunkEntry | ✅ | ✅ | 9 | 9 | 100% | via superblock sys_chunk_array plus zero geometry-field rejection |
| BtrfsStripe | ✅ | ✅ | 4 | 4 | 100% | via chunk entries plus non-zero device ID rejection |
| BtrfsHeader | ✅ | ✅ | 5 | 5 | 100% | via leaf fixtures |
| BtrfsItem | ✅ | ✅ | 4 | 4 | 100% | via leaf fixtures |
| BtrfsKey | ✅ | ✅ | 3 | 3 | 100% | via leaf fixtures |
| BtrfsKeyPtr | ✅ | ✅ | 2 | 2 | 100% | internal node pointers |
| BtrfsDevItem | ✅ | ✅ | 7 | 7 | 100% | 1TB device with 512GB used plus invalid ID/accounting rejection |
| BtrfsRootItem | ✅ | ✅ | 8 | 8 | 100% | via roottree_leaf fixture plus fixed-offset level/UUID layout, stale generation_v2 invalidation, impossible level rejection, and partial extension-field rejection |
| BtrfsRootRef | ✅ | ✅ | 4 | 4 | 100% | parse-only root refs with exact payload length, short-name rejection, zero-name rejection, and trailing-byte rejection |
| BtrfsInodeRef | ✅ | ✅ | 1 | 1 | 100% | zero-length name rejection plus encoder guard |
| BtrfsInodeItem | ✅ | ✅ | 8 | 8 | 100% | via fstree_leaf fixture plus timestamp nanosecond bound rejection and fixed-size trailing-byte rejection |
| BtrfsDirItem | ✅ | ✅ | 6 | 6 | 100% | via fstree_leaf fixture plus nonzero data_len rejection and zero-length name rejection |
| BtrfsXattrItem | ✅ | ✅ | 1 | 1 | 100% | zero-length name rejection while zero-length values remain accepted |
| BtrfsExtentData | ✅ | ✅ | 7 | 7 | 100% | via fstree_leaf fixture plus fixed-size regular/prealloc payload trailing-byte rejection and uncompressed disk-range rejection |

**btrfs Total: 86 MUST clauses, 86 passing = 100.0%**

## Full-Gate Runtime Semantic Coverage

`crates/ffs-harness/tests/conformance.rs::full_conformance_gate_pass()` also
executes runtime semantic checks that are not field-layout rows in the on-disk
structure matrices above. The counts below are scenario-level semantic
requirements, not additional structure-field MUST clauses.

### ext4 Runtime Semantics

| Surface | Full-gate test function(s) | Requirements | Passing | Status | Notes |
|---------|----------------------------|:------------:|:-------:|:------:|-------|
| Inline-data OpenFs read and VFS behavior | `ext4_inline_data_openfs_read_conforms`, `ext4_inline_data_xattr_continuation_openfs_read_conforms`, `ext4_inline_data_openfs_read_boundaries_conform`, `ext4_inline_data_zero_size_and_extreme_read_bounds_conform`, `ext4_inline_data_vfs_lookup_readdir_conforms`, `ext4_inline_data_write_rejects_without_mutating_contents`, `ext4_inline_data_fallocate_rejects_without_mutating_contents` | 7 | 7 | PASS | Covers inode-body and xattr-continuation readback, boundary clamps, VFS lookup/readdir, and unsupported mutation non-effects. |
| Casefold lookup semantics | `ext4_dir_block_casefold_lookup_conforms`, `ext4_casefold_openfs_lookup_is_case_insensitive` | 2 | 2 | PASS | Covers directory-block casefold lookup and mounted OpenFs case-insensitive lookup. |
| fscrypt raw-name and legacy policy transport | `ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes`, `ext4_fscrypt_legacy_policy_transport_discrepancy_conforms` | 3 | 3 | PASS | Covers no-key raw-byte readdir, no-key lookup, and the documented legacy policy ioctl transport discrepancy without requiring a new accepted divergence row. |
| Recovery, path resolution, and journal replay | `ext4_orphan_recovery_conforms`, `ext4_path_resolution_conforms`, `ext4_reference_image_opens_with_journal_replay_segments` | 3 | 3 | PASS | Covers orphan cleanup, multi-component path traversal, and reference-image open with journal replay segments. |
| Fallocate and preallocation contracts | `ext4_fallocate_zero_range_zeroes_target_range`, `ext4_fallocate_collapse_range_shifts_tail_and_shrinks_file`, `ext4_fallocate_collapse_range_reaching_eof_rejects_without_mutation`, `ext4_fallocate_insert_range_inserts_hole_and_grows_file`, `ext4_generic_112_preallocation_contract_conforms` | 5 | 5 | PASS | Covers zero-range, collapse-range, EOF rejection, insert-range, and generic/112 preallocation behavior. |
| Legacy data mapping and compression readback | `ext4_indirect_block_addressing_conforms`, `ext4_e2compr_write_readback_conforms_for_gzip_and_lzo` | 3 | 3 | PASS | Counts indirect block addressing plus gzip and lzo e2compr readback scenarios. |
| Fast-commit replay and fallback | `ext4_fast_commit_replay_openfs_evidence_conforms`, `ext4_fast_commit_truncated_stream_falls_back_to_jbd2_only` | 2 | 2 | PASS | Covers complete fast-commit replay and truncated-stream fallback to JBD2-only replay. |
| Active MMP write rejection | `ext4_active_mmp_write_open_is_rejected` | 1 | 1 | PASS | Complements the on-disk MMP fixture row with the runtime write-open rejection contract. |

**ext4 runtime semantic total: 26 scenario requirements, 26 passing = 100.0%**

### btrfs Runtime Semantics

| Surface | Full-gate test function(s) | Requirements | Passing | Status | Notes |
|---------|----------------------------|:------------:|:-------:|:------:|-------|
| Fallocate and preallocation contracts | `btrfs_generic_112_preallocation_contract_conforms`, `btrfs_fallocate_does_not_prealloc_over_live_data_conforms` | 2 | 2 | PASS | Covers generic/112 preallocation and prevention of preallocation over live data. |
| Send-stream behavior | `btrfs_send_stream_multi_command_conforms`, `btrfs_send_stream_unknown_command_preserves_attrs_as_unspec`, `btrfs_send_stream_rejects_missing_end_command` | 3 | 3 | PASS | Covers multi-command replay, unknown command attribute preservation, and missing-END rejection. |
| Transparent decompression | `btrfs_transparent_decompression_zlib_regular_extent_conforms`, `btrfs_transparent_decompression_lzo_regular_extent_conforms`, `btrfs_transparent_decompression_zstd_regular_extent_conforms` | 3 | 3 | PASS | Covers zlib, lzo, and zstd regular extent readback. |
| Subvolume mount root aliasing | `btrfs_subvolume_mount_root_alias_conforms` | 1 | 1 | PASS | Covers alternate subvolume root exposure through the mount surface. |
| Tree-log replay | `btrfs_tree_log_replay_multilevel_conforms`, `btrfs_tree_log_replay_skips_when_log_root_absent` | 2 | 2 | PASS | Covers multilevel replay and absent-log-root fast path. |
| Chunk and device tree walking | `btrfs_chunk_tree_walk_adds_and_sorts_new_chunks`, `btrfs_device_tree_walk_enumerates_all_devices`, `btrfs_chunk_mapping_fixture_conforms` | 3 | 3 | PASS | Covers chunk-tree discovery/sorting, device enumeration, and fixture-backed logical-to-physical mapping. |
| Multi-device RAID and DUP reads | `btrfs_multi_device_raid6_read_conforms`, `btrfs_multi_device_raid10_read_conforms`, `btrfs_multi_device_raid5_read_conforms`, `btrfs_multi_device_dup_read_conforms`, `btrfs_multi_device_raid1_read_falls_back_to_second_mirror`, `btrfs_multi_device_raid0_dispatches_to_correct_stripe` | 6 | 6 | PASS | Covers RAID6, RAID10, RAID5, DUP, RAID1 mirror fallback, and RAID0 stripe dispatch. |

**btrfs runtime semantic total: 20 scenario requirements, 20 passing = 100.0%**

## Coverage Accounting

| Coverage family | Requirements | Passing | Score | Notes |
|-----------------|:------------:|:-------:|:-----:|-------|
| ext4 on-disk structures | 75 | 75 | 100.0% | Field-layout and parser MUST clauses from the ext4 matrix. |
| btrfs on-disk structures | 86 | 86 | 100.0% | Field-layout and parser MUST clauses from the btrfs matrix. |
| ext4 full-gate runtime semantics | 26 | 26 | 100.0% | Scenario-level semantic requirements exercised by `full_conformance_gate_pass()`. |
| btrfs full-gate runtime semantics | 20 | 20 | 100.0% | Scenario-level semantic requirements exercised by `full_conformance_gate_pass()`. |

**Structure + runtime semantic total: 207 requirements, 207 passing = 100.0%**

Policy, provenance, checksum-manifest, legacy-golden shape, fuzz-smoke, and
open-ended-inventory validators are required full-gate controls, but they are
tracked in their dedicated provenance/checksum/inventory rows instead of being
folded into the structure or runtime semantic denominators.

## Priority Gaps

None. All identified on-disk structures have conformance fixtures.

## Fuzz/Adversarial Parser Coverage

| Surface | Corpus/Test | Passing | Notes |
|---------|-------------|:-------:|-------|
| Ext4 superblocks | ✅ | ✅ | synthetic adversarial seeds cover valid region/image parsing, bad magic, unsupported block-size shifts, invalid cluster-size shifts, metadata checksum stamping/corruption, geometry validation failures, and short region/image rejection |
| Ext4 inline-data ibody xattrs | ✅ | ✅ | synthetic adversarial seeds cover inline-data flags with huge `i_size`, oversized `i_extra_isize`, ibody xattr magic-only, name overflow, value overflow, and a valid ibody xattr smoke path through the deterministic fuzz regression harness |
| Ext4 inode checksums | ✅ | ✅ | synthetic adversarial seeds cover 132-byte and 256-byte inode checksum layouts with low/high checksum halves, checksum-field corruption, covered-byte corruption, wrong inode-number checksum seed rejection, short inode buffers, and below-minimum inode-size rejection |
| Ext4 external xattr blocks | ✅ | ✅ | synthetic adversarial seeds cover bad magic, header-only empty block, name overflow, value overflow, and a valid user xattr smoke path through the deterministic fuzz regression harness |
| Ext4 directory blocks | ✅ | ✅ | synthetic adversarial seeds cover valid multi-entry checksum-tail iteration, checksum stamping/verification, checksum-field corruption, covered-entry-byte corruption, wrong inode/generation checksum seed rejection, malformed tails, too-small checksum blocks, short/unaligned/out-of-bounds `rec_len`, name overflow, and nonzero checksum-tail padding |
| Ext4 HTree dx roots | ✅ | ✅ | synthetic adversarial seeds cover valid root entries, unknown hash-version preservation for hash fallback, zero-count roots, nonzero reserved fields, bad root-info length, excessive indirect levels, nonzero unused flags, entry count greater than limit, and short-root rejection |
| Ext4 extent trees | ✅ | ✅ | synthetic adversarial seeds cover valid leaf and index nodes, bad magic, `eh_entries > eh_max`, truncated entries, overlapping leaf extents, unsorted index entries, and extent-block checksum stamping/corruption |
| Ext4 group descriptors | ✅ | ✅ | synthetic adversarial seeds cover 32-byte and 64-byte descriptor field composition, metadata checksum stamping/verification, checksum corruption rejection, invalid descriptor size, and short descriptor rejection |
| Ext4 MMP blocks | ✅ | ✅ | synthetic adversarial seeds cover clean/fsck/active/unknown sequence statuses, bad magic rejection, checksum corruption rejection, and short-block rejection; the JSON conformance fixture carries a seeded CRC32C checksum and fails on checksum drift |
| Btrfs tree blocks | ✅ | ✅ | synthetic adversarial seeds cover valid leaf and internal nodes, excessive tree level, leaf payload overlap with the item table, payload out-of-block bounds, overlapping leaf payload ranges, zero child block pointers, and tree-block checksum stamping/corruption |
| Btrfs sys_chunk_array | ✅ | ✅ | synthetic adversarial seeds cover valid single-device bootstrap mapping, bad chunk key type/objectid, zero chunk length, zero stripe length, zero io_align/io_width/sector_size geometry fields, zero stripes, zero stripe device IDs, multiple RAID profile bits, and truncated stripe data |
| Btrfs chunk-tree items | ✅ | ✅ | deterministic adversarial regression tests cover valid multi-stripe chunk-tree item parsing, fixed header truncation, declared stripe payload truncation, trailing payload rejection after declared stripes, zero chunk length, zero stripe length, zero io_align/io_width/sector_size geometry fields, zero stripes, zero stripe device IDs, and multiple RAID profile bit rejection |
| Btrfs dev items | ✅ | ✅ | synthetic adversarial seeds cover full field-layout parsing, max numeric/classification values, trailing bytes after the fixed 98-byte item, zero device ID rejection, zero-capacity device rejection, impossible `bytes_used > total_bytes` accounting, and truncated payload rejection |
| Btrfs superblocks | ✅ | ✅ | synthetic adversarial seeds cover valid superblock-region parsing, image-offset parsing, bad magic, zero and non-power-of-two sizing fields, oversized sector/node/stripe sizing fields, zero-capacity, zero-device, and `bytes_used > total_bytes` accounting rejection, unsupported checksum types, oversized sys_chunk_array declarations, invalid root/chunk/log tree levels, and short region/image rejection |
| Btrfs item payload parsers | ✅ | ✅ | deterministic adversarial regression tests cover root/root_ref/inode/dir/xattr/extent payload valid boundaries, multi-entry dir/xattr payloads, short headers, length overflows, zero-length name rejection for ROOT_REF/INODE_REF/DIR_ITEM/XATTR_ITEM, ROOT_ITEM partial extension-field rejection, nonzero DIR_ITEM data_len rejection, fixed-size INODE_ITEM trailing-byte rejection, fixed-size regular EXTENT_DATA trailing-byte rejection, uncompressed EXTENT_DATA disk-range rejection, unsupported extent types, compression values, encoding fields, invalid inode timestamp nanoseconds, zero root bytenr rejection, and malformed ROOT_REF fallback behavior for subvolumes/snapshots |
| Btrfs send streams | ✅ | ✅ | deterministic adversarial regression tests cover command CRC32C validation, missing-END rejection, unknown command fallback, zero-length and unknown attributes, multi-attribute commands, trailing partial command headers, and END payload TLV validation |
| Btrfs delayed refs | ✅ | ✅ | deterministic adversarial regression tests cover zero-limit flush preservation, bounded partial flush accounting, delete-underflow queue preservation, failed-flush refcount atomicity, insert-overflow atomicity for retry safety, and sequence-ordered drain across extent key order |
| Btrfs transactions | ✅ | ✅ | deterministic adversarial mutation tests cover same-tree root replacement, delayed-ref commit failure nonvisibility, and tree-root address overflow nonvisibility |
| Btrfs extent allocator | ✅ | ✅ | deterministic adversarial mutation tests cover overflowing block-group range rejection without accounting side effects and exact block-group tail-fit allocation |
| Btrfs COW tree mutations | ✅ | ✅ | deterministic COW tests cover positive internal split height growth, parent-rewrite update, and left/right delete-borrow success paths plus allocator-failure atomicity for duplicate/missing-key short-circuits, leaf split child allocation, internal split child allocation, internal-root allocation, root split, insert/update parent rewrite, update leaf, delete left/right borrow, and delete merge/root-shrink paths without publishing deferred frees for still-reachable nodes |

## Open-Ended Fuzz and Conformance Inventory

`ffs-harness validate-open-ended-inventory` parses this table, validates the
proof-type and disposition vocabulary, and emits the machine-readable inventory
report used to close `bd-rchk7.1`.

| Row | Source location | Matched note | Risk surface | Current evidence | Required proof type | Unit-test coverage | E2E/fuzz-smoke coverage | Required logs | Required artifacts | Decision | Linked bead/artifact and owner/status |
|-----|-----------------|--------------|--------------|------------------|---------------------|--------------------|-------------------------|---------------|--------------------|----------|----------------------------------------|
| OEI-001 | conformance/COVERAGE.md#next-actions | Consider additional edge cases | Parser and mutation boundary cases can be lost behind a green aggregate coverage score | Coverage matrix lists covered structures and adversarial parser rows, and the fixed seed manifest now pins representative parser outcomes with per-seed provenance, expected checksum, minimization, resource budget, and quarantine state | fuzz_smoke | `fuzz_smoke::tests::default_manifest_validates_and_runs` plus manifest parser, expected-class drift, checksum drift, panic, timeout, resource-cap, minimization, quarantine, and artifact-contract unit tests | `ffs-harness validate-fuzz-smoke --out artifacts/fuzz-smoke/fuzz_smoke_report.json` and `scripts/e2e/ffs_fuzz_smoke_e2e.sh` emit fixed seed IDs, seed hashes, provenance, corpus checksum, resource counters, minimization status, quarantine status, duration, stdout/stderr paths, cleanup status, and target summary | source_path; row_id; decision; artifact_paths; reproduction_command | report_json; run_log; source_path; row_id | completed_artifact | bd-rchk7.4 + bd-u8hx5 / `tests/fuzz-smoke/fuzz_smoke_manifest.json`, `crates/ffs-harness/src/fuzz_smoke.rs`, `scripts/e2e/ffs_fuzz_smoke_e2e.sh` |
| OEI-002 | conformance/COVERAGE.md#next-actions | Continue targeted adversarial corpus expansion for remaining mutation surfaces | Remaining mutation surfaces need explicit corpus or fixture ownership instead of open prose | Btrfs delayed refs, transactions, allocator, and COW mutation rows are covered; repair and ledger corruption corpus fixtures are closed through `bd-rchk7.2`, mounted repair fixtures are closed through `bd-rchk7.3`, and repair corpus metadata is decoded by fixed fuzz-smoke seed `fs_repair_corpus_manifest` | repair_corpus | Inventory row validation here plus `repair_corpus::tests::default_corpus_validates_required_negative_cases` and the ledger/hash/symbol/refusal negative validators from `bd-rchk7.2` | Repair/ledger corpus metadata is included as fixed seed `fs_repair_corpus_manifest` in `tests/fuzz-smoke/fuzz_smoke_manifest.json` with checksum/provenance/minimization metadata | source_path; row_id; decision; artifact_paths; reproduction_command | report_json; run_log; source_path; row_id | completed_artifact | bd-rchk7.2 closed repair corpus; bd-rchk7.3 closed mounted repair fixtures; bd-u8hx5 fixed-seed smoke policy current |
| OEI-003 | tests/fuzz_corpus/README.md#coverage-intent | Every sample is processed by ext4 and btrfs parser entry points without panics | Existing deterministic corpus intent must stay tied to executable parser checks | `crates/ffs-ondisk/tests/adversarial_corpus.rs` owns the full corpus count and parser no-panic oracle; `bd-rchk7.4` adds a smaller artifact-producing smoke subset and `bd-u8hx5` pins provenance/quarantine policy for that subset | parser_unit | `open_ended_inventory::tests::parses_inventory_rows` validates completed-artifact rows and field vocabulary | Existing adversarial corpus test plus `ffs-harness validate-fuzz-smoke` fixed-seed report | source_path; row_id; decision; artifact_paths; reproduction_command | report_json; run_log; source_path; row_id | completed_artifact | tests/fuzz_corpus/README.md, crates/ffs-ondisk/tests/adversarial_corpus.rs, and tests/fuzz-smoke/fuzz_smoke_manifest.json / current |
| OEI-004 | README.md#whats-next | Replace remaining open-ended corpus notes with completed fixtures or narrow beads | Public status must not imply unowned fuzz or conformance work is already closed | This inventory is now the docs-traceability artifact; dependent beads cover source-scope and stale-note refinements | docs_traceability | Current inventory validator checks row schema, linked beads, proof vocabulary, log fields, and artifact fields | `ffs-harness validate-open-ended-inventory --out artifacts/conformance/open_ended_inventory.json` emits the smoke report | source_path; row_id; decision; artifact_paths; reproduction_command | report_json; run_log; source_path; row_id | completed_artifact | conformance/COVERAGE.md#open-ended-fuzz-and-conformance-inventory / current |

## Next Actions

- [x] Add ext4_mmp_block.json fixture - DONE
- [x] OEI-001 / `bd-rchk7.4` and `bd-u8hx5` track fixed-seed fuzz-smoke work with provenance, minimization, quarantine, log, and artifact requirements - DONE
- [x] Add ext4 superblock adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 inline-data adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 inode checksum adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 xattr block adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 directory block adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 directory checksum adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 HTree dx root adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 extent tree adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 group descriptor adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 MMP block adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs tree block adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs sys_chunk_array adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs chunk-tree item adversarial parser regression coverage - DONE
- [x] Add btrfs dev item adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs superblock adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs send stream adversarial parser regression coverage - DONE
- [x] Add btrfs item payload parser adversarial regression coverage - DONE
- [x] Add btrfs ROOT_REF adversarial parser regression coverage - DONE
- [x] Add btrfs delayed ref adversarial mutation coverage - DONE
- [x] Add btrfs transaction adversarial mutation coverage - DONE
- [x] Harden btrfs extent allocator overflow boundaries - DONE
- [x] Add btrfs COW tree allocator-failure mutation coverage - DONE
- [x] Add btrfs COW delete allocator-failure mutation coverage - DONE
- [x] Add btrfs COW update allocator-failure mutation coverage - DONE
- [x] Add btrfs COW leaf-split allocator-failure mutation coverage - DONE
- [x] Add btrfs COW key-error mutation short-circuit coverage - DONE
- [x] Add btrfs COW delete left-borrow allocator-failure mutation coverage - DONE
- [x] Add btrfs COW internal-split allocator-failure mutation coverage - DONE
- [x] Add btrfs COW internal-root allocator-failure mutation coverage - DONE
- [x] Add btrfs COW internal-split success coverage - DONE
- [x] Add btrfs COW left-borrow delete success coverage - DONE
- [x] Add btrfs COW parent-rewrite update success coverage - DONE
- [x] OEI-002 / `bd-rchk7.2` closed remaining deep repair corpus expansion; `bd-rchk7.3` closed mounted repair fixtures; `bd-u8hx5` covers deterministic fuzz-smoke expansion with fixed seeds, provenance, minimization, quarantine, and artifact requirements - DONE

---

*Last updated: 2026-05-18*
