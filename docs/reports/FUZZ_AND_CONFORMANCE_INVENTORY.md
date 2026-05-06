# Fuzz and Conformance Coverage Inventory (bd-rchk7.1)

This inventory enumerates open-ended fuzz / conformance work captured
across the codebase as of the session that filed this document. Each
entry is structured so it can be checked off independently.

## Methodology

Search performed across:
- `crates/ffs-harness/tests/*.rs` — conformance and end-to-end test files
- `fuzz/fuzz_targets/*.rs` — libFuzzer harness sources
- `docs/**/*.md` — design docs, reports, and status files
- Phrases scanned: "add more", "expand corpus", "adversarial", "future
  fuzz", "TODO", "FIXME", "XXX"

---

## Open-Ended Inventory Registry

Rows in this table are the machine-checkable closeout surface for
`bd-rchk7.1`. The harness command
`ffs-harness validate-open-ended-inventory` parses this table and
fails if a row lacks proof vocabulary, a concrete artifact/log contract,
or a bead/artifact owner.

| ID | Source location | Risk surface | Current evidence | Required proof type | Expected unit coverage | Expected E2E/fuzz-smoke coverage | Log/artifact expectations | Decision | Linked bead or artifact | Owner/status | Non-applicability rationale |
|----|-----------------|--------------|------------------|---------------------|------------------------|----------------------------------|---------------------------|----------|-------------------------|--------------|-----------------------------|
| A1 | fuzz/fuzz_targets/fuzz_fuse_splice_mount.rs; fuzz/fuzz_targets/fuzz_ioctl_dispatch.rs | FUSE and ioctl parser cursor saturation | Targets exist but synthetic seed value is limited by wide cursor consumption | long-campaign | deferred | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | active-bead | bd-rchk7.4 | open long-campaign | n/a |
| A2 | fuzz/fuzz_targets/fuzz_inode_roundtrip.rs | Inode round-trip extra-area branches | Post-fix harness ran 8M+ clean iterations; branch-specific seeds remain useful | corpus-seed | required | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | active-bead | bd-rchk7.4 | open corpus expansion | n/a |
| B1 | crates/ffs-dir/src/lib.rs; crates/ffs-harness/tests/ext4_dir_rec_len_kernel_reference.rs | ext4 directory entry rec_len after unlink | `ext4_dir_rec_len_kernel_reference_coalesces_after_unlink` now pins debugfs `rm` rec_len coalescing end-to-end | golden-fixture | existing | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | artifact-covered | crates/ffs-harness/tests/ext4_dir_rec_len_kernel_reference.rs::ext4_dir_rec_len_kernel_reference_coalesces_after_unlink | covered by kernel-reference harness | n/a |
| B2 | conformance/fixtures/ext4_inode_inline_data.json; conformance/fixtures/ext4_inode_inline_data_with_continuation.json | ext4 inline data continuation fixtures | Inline fixtures exist but e2fsprogs continuation coverage is not pinned as a kernel-reference lane | golden-fixture | required | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | needs-follow-up | docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md#B2 | unowned follow-up needed | n/a |
| B3 | crates/ffs-harness/tests/conformance.rs | ext4 large file i_size_high over 4 GiB | Fast tests avoid multi-GB images; large-file parity needs artifact-sized execution | long-campaign | deferred | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | active-bead | bd-rchk7.4 | open long-campaign | n/a |
| B4 | conformance/fixtures/ext4_xattr_block.json; crates/ffs-harness/tests/kernel_reference.rs | ext4 xattr block CRC32C parity vs debugfs ea_set | `ext4_debugfs_vs_ffs_xattr_writer_reference` compares FFS external xattr block bytes against debugfs after checksum normalization | golden-fixture | existing | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | artifact-covered | crates/ffs-harness/tests/kernel_reference.rs::ext4_debugfs_vs_ffs_xattr_writer_reference | covered by kernel-reference harness | n/a |
| B5 | crates/ffs-inode/src/lib.rs; crates/ffs-harness/tests/kernel_reference.rs | ext4 i_extra_isize preservation across xattr writes | `ext4_debugfs_vs_ffs_xattr_writer_reference` verifies inline and external inode ibody bytes match the debugfs-written reference image | golden-fixture | existing | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | artifact-covered | crates/ffs-harness/tests/kernel_reference.rs::ext4_debugfs_vs_ffs_xattr_writer_reference | covered by kernel-reference harness | n/a |
| C1 | crates/ffs-btrfs/src/lib.rs | ffs-btrfs property coverage | `bd-rchk0.55` added `proptest!` coverage for `snapshot_diff_by_generation` self-diff, empty snapshot symmetry, and generation-increase modification invariants | property-test | existing | deferred | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | artifact-covered | bd-rchk0.55; crates/ffs-btrfs/src/lib.rs::snapshot_diff_self_diff_proptest_is_empty | closed bead + proptest artifact | n/a |
| C2 | crates/ffs-mvcc/src/wal_replay.rs | MVCC WAL replay invariant coverage | `wal_replay.rs` contains `proptest!` coverage for clean monotonic replay and skip cutoff invariants | property-test | existing | deferred | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | artifact-covered | crates/ffs-mvcc/src/wal_replay.rs::proptest_clean_monotonic_replay_applies_every_commit | covered by wal_replay proptests | n/a |
| E1 | docs/reports/MODES_OF_REASONING_REPORT_AND_ANALYSIS_OF_PROJECT.md:320; crates/ffs-fuse/src/lib.rs | FIEMAP short-buffer panic risk | Report flags possible panic; dedicated FUSE ioctl proof is not linked here | security-audit | required | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | needs-follow-up | docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md#E1 | unowned security follow-up needed | n/a |
| E2 | docs/reports/MODES_OF_REASONING_REPORT_AND_ANALYSIS_OF_PROJECT.md:67; crates/ffs-fuse/src/lib.rs | setattr privilege escalation at FUSE boundary | Report flags FUSE trust-boundary risk; mounted permission proof is not linked here | mounted-e2e | required | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | active-bead | bd-rchk0.3.2 | open mounted matrix | n/a |
| E3 | scripts/e2e/ffs_fuse_production.sh; scripts/e2e/scenario_catalog.json | Empty-filesystem mount coverage | Critical mounted matrix exists; empty-image scenario remains separate | mounted-e2e | deferred | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | active-bead | bd-rchk0.3.2 | open mounted matrix | n/a |
| E4 | fuzz/fuzz_targets/fuzz_block_mem_io_engine.rs; crates/ffs-fuse/src/lib.rs | Backpressure boundary at mounted FUSE layer | Block-level fuzz exists but no mounted boundary scenario pins user-visible behavior | mounted-e2e | required | required | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | active-bead | bd-rchk0.3.4 | open error-evidence follow-up | n/a |
| E5 | docs/design-multi-host-repair.md; crates/ffs-repair/src/lib.rs | Multi-host repair ownership protocol | Current read-only scrub does not require ownership; write-side shared-storage repair remains future scope | docs-non-goal | deferred | deferred | source_path,row_id,decision,reproduction_command,artifact_path,owner_status | explicit-non-goal | docs/design-multi-host-repair.md | scoped non-goal for this inventory | Multi-host write-side repair is outside this fuzz/conformance inventory; readiness stays blocked by repair ownership follow-up work. |

## A. Fuzz target corpora — saturation status

44 fuzz targets exist under `fuzz/fuzz_targets/`. Recent corpus
expansion this session (commits `f27cebb` through `0fed288`) raised
the floor for previously under-corpused targets. As of this writing:

| Status                   | Count | Notes |
|--------------------------|-------|-------|
| Well-corpused (>= 100)   | ~18   | btrfs_send_stream (93+), btrfs_tree_items (98+), cli_btrfs_parsers (111+), ext4_htree_mmp (113+), and all targets routinely run |
| Mid-coverage (30–99)     | ~14   | all extended this session with structured seeds |
| Newly-expanded (20–35)   | ~8    | native-cow, btrfs-tree-log, alloc-succinct, alloc-bitmap, block-aligned-vec, block-mem-io-engine, btree-bw-tree, btrfs-devitem, dir-operations, repair-codec-roundtrip, repair-evidence-ledger, verify-ext4-integrity, extent-tree |
| Stateful-complex (15–22) | 4     | fuse_splice_mount, ioctl_dispatch, openfs_mvcc_wal_recovery, path_encoding_mount — complex cursor consumption, lower marginal value of synthetic seeds |

**Open items in this category:**
- A1: corpus growth on `fuse_splice_mount` and `ioctl_dispatch` would
  benefit from harness simplification (cursor consumption is currently
  ~30 fields of varying types per seed).
- A2: `fuzz_inode_roundtrip` had six oracle bugs in the round-trip
  contract (commits `0fed288`, `45dc836`); the post-fix harness
  surfaces 8M+ runs clean. Future work: add structured synthetic seeds
  exercising the now-correct extra-area branches.

## B. Conformance harnesses — kernel-reference parity

Existing kernel-reference harnesses under `crates/ffs-harness/tests/`:

| Harness | Pins | Status |
|---------|------|--------|
| `ext4_bitmap_csum_kernel_reference` | block/inode bitmap CRC32C | covered |
| `ext4_extent_block_csum_kernel_reference` | extent-block tail checksum | covered |
| `ext4_group_desc_kernel_reference` | group descriptor checksum | covered |
| `ext4_iblocks_kernel_reference` | i_blocks (Blockcount) | covered |
| `ext4_inode_flags_uidgid_kernel_reference` | mode/uid/gid/flags | covered |
| `ext4_sparse_read_kernel_reference` | sparse hole zero-fill on read | covered |
| `ext4_symlink_kernel_reference` | fast/extent symlink targets | covered |
| `ext4_journal_recovery` | jbd2 replay | covered |
| `ext4_generation_kernel_reference` | i_generation (NFS change cookie) | added this session (commit `9681843`) |

**Open items in this category:**
- B2: `ext4` inline data parsing (`EXT4_INLINE_DATA_FL`, defined as a
  constant in ffs-types but not yet exercised against e2fsprogs
  fixtures with continuation extents).
- B3: `ext4` large file `i_size_high` for files > 4 GiB — requires
  building a multi-GB image, infeasible for a fast unit test.

**Covered since the original inventory:**
- B1: `crates/ffs-harness/tests/ext4_dir_rec_len_kernel_reference.rs`
  now pins the debugfs `rm` rec_len coalescing contract end-to-end.
- B4/B5: `ext4_debugfs_vs_ffs_xattr_writer_reference` now compares
  inline ibody bytes, external ibody bytes, parsed xattr values, and the
  canonicalized external xattr block against the debugfs-written
  reference image.

## C. Property tests (proptest!)

By crate:

| Crate | proptest! blocks | Notes |
|-------|------------------|-------|
| ffs-alloc | 1 (5+ test fns) | bitmap/find_free/contiguous well-covered |
| ffs-block | 3 | io_engine, aligned_vec |
| ffs-btree | 1 (added this session, commit `7b8fd90`) | bw_tree materialize/consolidate |
| ffs-dir | 1 (5+ test fns) | add/remove/htree round-trips + new swap-involution (commit `ebe105b`) |
| ffs-extent | 1 (8+ test fns) | split/punch/insert/collapse roundtrips |
| ffs-inode | 1 (4+ test fns) | extra_timestamp / touch_atime / bump_inode_version (added this session, commit `c6677dc`) |
| ffs-journal | 1 (8+ test fns) | jbd2 commit/descriptor checksum invariants |
| ffs-mvcc | 6 across submodules | rcu, sharded, wal, wal_writer, compression, wal_replay — well covered |
| ffs-xattr | 1 (7+ test fns) | set/get/remove/order invariance |
| ffs-btrfs | 1 (3 test fns) | snapshot_diff_by_generation invariants added in bd-rchk0.55 |
| ffs-ondisk | scattered | extent-tree leaf/index roundtrip in tests module |

**Covered since the original inventory:**
- C1: `bd-rchk0.55` added `ffs-btrfs` `proptest!` coverage for
  `snapshot_diff_by_generation` self-diff, empty snapshot symmetry, and
  same-inode generation-increase invariants.
- C2: `crates/ffs-mvcc/src/wal_replay.rs` already contains a
  `proptest!` block for clean monotonic replay and `skip_up_to_seq`
  apply-filter invariants, so this row is now tracked as covered rather
  than unowned.

## D. Defects fixed during this session

For audit trail. Each was a real bug surfaced by structured fuzz
seeds + libFuzzer mutation, with a regression seed promoted to corpus:

1. `fuzz_native_cow_recovery` snapshot oracle (commit `f27cebb`)
2. `fuzz_btree_bw_tree` `entries_count` oracle for already-consolidated pages (commit `13a34c0`)
3. `fuzz_dir_operations` duplicate-name remove oracle (commit `092ecf2`)
4. `ffs-core verify_ext4_integrity` divide-by-zero + 2 OOM paths (commit `b9f00e3`, regression test `5f97f0d`, regression seeds `5a3fdc9`)
5. `ffs-core enable_writes` OOM via `Vec::with_capacity(group_count)` on corrupted `blocks_count` (commit `f7597e2`)
6. `fuzz_inode_roundtrip` six serialize/parse oracle mismatches (commits `0fed288`, `45dc836`)

## E. Known infrastructure gaps

From `MODES_OF_REASONING_REPORT_AND_ANALYSIS_OF_PROJECT.md` and
session observations:

- E1: FIEMAP ioctl handler short-buffer panic risk (line 320 of
  modes-of-reasoning report).
- E2: setattr privilege escalation gap on the FUSE trust boundary
  (line 67 of same report).
- E3: Empty-filesystem mount test (no corresponding harness exists).
- E4: Backpressure boundary test — exists in `fuzz_block_mem_io_engine`
  but not at FUSE-mount layer.
- E5: Multi-host repair ownership protocol (3rd trust boundary,
  unimplemented per line 67 of same report).

---

This inventory will go stale as work progresses. Sweep again with the
same phrase set quarterly or when a new round of fuzz / conformance
work begins.
