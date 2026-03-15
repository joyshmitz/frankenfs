# Safe-Merge Taxonomy and Proof Obligations

**Status:** Design-ready, backing executable taxonomy tests
**Date:** 2026-03-14
**Bead:** bd-m5wf.3.1
**Scope:** Pairwise classification of concurrent filesystem mutations that may eventually bypass raw block-level FCW

## Current Code Facts

The live code is still conservative:

- `ffs-mvcc::Transaction` records writes as `BTreeMap<BlockNumber, Vec<u8>>`, and FCW conflicts are checked per logical block in `crates/ffs-mvcc/src/lib.rs`.
- `OpenFs::{ext4,btrfs}_write`, namespace mutations, xattr updates, extent edits, and allocator updates all mutate live filesystem state directly in `crates/ffs-core/src/lib.rs`.
- `ffs-dir::add_entry` and `ffs-dir::remove_entry` rewrite shared `rec_len` topology inside one directory block.
- `ffs-xattr::set_xattr` / `remove_xattr` rewrite the whole inline xattr region or an external xattr block, even when the logical change is “one key”.
- `ffs-extent` delegates to `ffs-btree::{insert,delete_range}`, which may split, collapse, or shrink tree nodes while also calling `ffs-alloc`.
- `ffs-alloc` updates block/inode bitmaps plus cached/persisted group descriptor counters; a missed or doubled bit flip is corruption, not a benign conflict.

That means raw block-level FCW is still the correctness baseline. Any future “safe merge” path must prove that two higher-level mutations commute before they are collapsed into one MVCC decision.

## Canonical Merge Keys

Safe merge cannot be defined over raw block bytes alone. The merge key must be the smallest semantic object whose independent updates can be proven to commute.

| Mutation family | Canonical merge key | Why raw block granularity is too coarse |
|---|---|---|
| Data write | `(inode, logical_block_or_byte_range)` | One file block can share inode-size / timestamp side effects with other writes. |
| Directory append | `(parent_inode, entry_name)` plus isolated slot identity | Two distinct names can still alias the same `rec_len` slack slot. |
| Xattr update | `(inode, name_index, name)` | One external xattr block can hold many keys. |
| Extent edit | `(inode, logical_interval)` | Tree rebalancing touches structural nodes beyond the user interval. |
| Inode timestamp-only metadata | `(inode, timestamp_field_set)` | Timestamps are derivable metadata, not independent user payload. |
| Bitmap/accounting update | none admissible for merge in V1 | Exact free-space accounting must stay single-writer. |

## Taxonomy

| Family | Verdict | Safe only when | Why |
|---|---|---|---|
| Disjoint data block writes | Safe | Canonical data keys are disjoint and final inode metadata is recomputed once | The payload bytes commute if they do not alias the same logical block/range. |
| Same data block write | Unsafe | Never | Last-writer-wins is not semantically valid for arbitrary overlapping bytes. |
| Append-only directory adds | Safe | Names are distinct and slot materialization avoids `rec_len` aliasing | The logical namespace change commutes, but the physical block layout must be canonicalized. |
| Directory remove / unlink / rmdir | Unsafe | Never in V1 | Removal coalesces free space, updates link counts, and may delete the child inode. |
| Directory rename | Unsafe | Never in V1 | Rename has atomic replace semantics and may update two parents plus `..`. |
| Compound namespace create / mkdir / link / symlink | Unsafe by default | Only after decomposition into separately-proven primitives | These operations combine inode allocation, namespace mutation, and metadata repair. |
| Independent xattr updates | Safe | Canonical xattr keys are distinct and shared external blocks use COW/materialization | Logical key-value edits commute even when the storage block does not. |
| Same xattr key update/remove | Unsafe | Never | The operation is a true key conflict. |
| Non-overlapping extent edits | Safe | Logical intervals are disjoint and file-size ownership is not contested | The user-visible mapping can commute if tree rebalancing is normalized. |
| Overlapping extent edits | Unsafe | Never | They race on the same file logical address space. |
| Bitmap alloc/free or inode alloc/free | Unsafe | Never in V1 | Exact accounting, double-free detection, and reserved-bit protection require a single serialized decision. |
| Timestamp-only inode metadata | Safe | Only timestamp fields change and final timestamps are recomputed from the merged commit | Timestamps are derivable from the merged boundary. |
| Inode size / link-count / mode / structural metadata | Unsafe | Never in V1 | These fields encode real semantic ownership and cannot be merged by a generic commutativity rule. |

## Proof Obligations for Safe Families

### 1. Disjoint Data Writes

**Preconditions**

- Canonical keys `(inode, logical_range)` are disjoint.
- Neither mutation claims exclusive ownership of final file size outside its own range.

**Postconditions**

- The merged payload equals either serial order.
- Final inode size, `mtime`, and `ctime` equal a single deterministic repair pass over both writes.

**Proof sketch**

- Payload commutes by range disjointness.
- Metadata does not commute as raw writes, so it must be recomputed from the union of touched ranges.
- Commit evidence must record both subwrites under one merged decision.

### 2. Append-Only Directory Adds

**Preconditions**

- Entry names are distinct in the same parent directory epoch.
- The merge implementation materializes entries from a canonical name set or reserves non-overlapping slots before publication.
- Parent timestamps and directory indexing (`dx` state, if present) are repaired once after merge.

**Postconditions**

- Lookup for each added name succeeds.
- No unrelated entry is lost or overwritten.
- Directory block topology is valid (`rec_len` chain covers the block exactly once).

**Proof sketch**

- Logical namespace inserts commute on distinct names.
- Physical ext4 directory layout does not commute by itself because `add_entry` may split slack in a live record.
- Therefore the proof must operate on a canonical directory-entry multiset, not on arrival-order block edits.

### 3. Independent Xattr Updates

**Preconditions**

- Canonical xattr keys `(inode, namespace, name)` are distinct.
- If the inode uses an external xattr block and it is shared, the merged path performs COW before publishing.
- Final inode `ctime` is repaired once.

**Postconditions**

- `getxattr` returns both updated key values.
- No unrelated xattr entry is lost.
- Inline/external storage layout remains valid.

**Proof sketch**

- Logical map updates commute on distinct keys.
- Physical storage may not commute because one block contains many entries.
- The proof therefore requires keyspace materialization followed by one canonical serialization of the xattr region.

### 4. Non-Overlapping Extent Edits

**Preconditions**

- Logical extent intervals are disjoint.
- The pair does not contend on final inode size.
- Tree rebalancing is canonicalized before commit.
- Block allocation side effects are merged via one exact accounting pass.

**Postconditions**

- `map_logical_to_physical` yields the union of both interval mappings.
- B-tree invariants hold after node split/shrink repair.
- Block/inode accounting matches the published extent set exactly.

**Proof sketch**

- User-visible intervals commute by disjointness.
- Structural node splits do not commute as raw block edits, so the merge target must be the canonical extent set plus a deterministic tree serializer.
- Allocation/free side effects must be derived from the final extent delta, not unioned as independent bitmap edits.

### 5. Timestamp-Only Inode Metadata

**Preconditions**

- Only timestamp fields change.
- Timestamp merge rule is deterministic, for example “recompute from merged commit boundary” or “take commit-max”.

**Postconditions**

- Final timestamps are monotone.
- No size, link-count, or permission semantics are altered.

**Proof sketch**

- Timestamp updates carry no independent user payload.
- They are safe only as derived metadata repair, never as first-class competing ownership of the inode.

## Unsafe Families and Why They Stay Serialized

| Family | Serialization reason |
|---|---|
| Directory remove / rename | Namespace topology, child lifecycle, and atomic replace semantics must appear as one decision. |
| Bitmap allocation/free | Exact accounting and double-free detection cannot tolerate pairwise merge heuristics. |
| Inode size / link-count / mode updates | These fields express real semantic ownership, not derived repair data. |
| Same-key xattr or same-block data writes | They are direct conflicts on the same logical object. |

## Implementation Consequence for `bd-m5wf.3.2`

`bd-m5wf.3.2` should not try to “merge raw blocks.” It should:

1. Lift candidate mutations into a canonical operation family with a canonical merge key.
2. Apply the proof obligations above before declaring a pair merge-safe.
3. Materialize a single repaired structural result for directory/xattr/extent families.
4. Keep bitmap/accounting and structural inode ownership on the serialized conflict path.

## Executable Guardrail

`crates/ffs-core/src/lib.rs` includes a test-only merge taxonomy helper that mirrors this document. Its role is the same as the writeback schedule checker: it is not the production merge engine, but it gives `bd-m5wf.3.2` an executable statement of which categories are supposed to remain safe versus serialized.
