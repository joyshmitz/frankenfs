# Inode Generation Number Policy (OQ6)

## State Machine

```
  ┌─────────────────────────────────────────────────────────────┐
  │                     ext4 Generation                         │
  │                                                             │
  │  [FREE SLOT]──create_inode()──▶[ALLOCATED]                  │
  │   gen=N          gen=N+1 (wrapping)   gen=N+1               │
  │                                                             │
  │  [ALLOCATED]──delete_inode()──▶[FREE SLOT]                  │
  │   gen=N+1        gen preserved on-disk  gen=N+1             │
  │                                                             │
  │  [FREE SLOT]──create_inode()──▶[ALLOCATED]                  │
  │   gen=N+1        gen=N+2 (wrapping)   gen=N+2               │
  │                                                             │
  │  Invariant: same inode number ⇒ different generation        │
  │             after any delete+reuse cycle.                   │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │                    btrfs Generation                         │
  │                                                             │
  │  create() ──▶ generation = alloc.generation (txn gen)       │
  │                                                             │
  │  Objectids are never reused, so the creation-time txn       │
  │  generation is a unique discriminator per inode lifetime.   │
  └─────────────────────────────────────────────────────────────┘
```

## Propagation Path

```
On-disk inode ──▶ inode_to_attr() ──▶ InodeAttr.generation ──▶ FUSE reply.entry()/reply.created()
     │                                       │
     │  ext4: offset 0x64 (u32)              │  FUSE kernel caches (ino, gen) pairs;
     │  btrfs: inode_item bytes 0..8 (u64)   │  stale handles detected on mismatch.
```

## Key Decisions

1. **ext4 generation bump uses `wrapping_add(1)`** on the old on-disk value at
   create time. This matches Linux kernel `ext4_ialloc.c` behavior.

2. **ext4 `delete_inode()` preserves the generation on disk.** The bump happens
   only at the next `create_inode()` that reuses the slot.

3. **btrfs uses transaction generation** (`BtrfsAllocState.generation`) since
   objectids are allocated monotonically and never reused.

4. **InodeAttr.generation is `u64`** to accommodate both ext4 (zero-extended
   from `u32`) and btrfs (native `u64`).

5. **FUSE layer passes `attr.generation`** instead of hardcoded `0` in all
   `reply.entry()` and `reply.created()` calls.

## Test Coverage

| Test | Crate | What it verifies |
|------|-------|-----------------|
| `create_inode_bumps_generation_on_reuse` | ffs-inode | gen 0→1→2 across delete+reuse |
| `serialize_generation_preserved` | ffs-inode | on-disk round-trip at offset 0x64 |
| `touch_atime_preserves_generation_size_blocks` | ffs-inode | gen immutable on atime update |
| `touch_mtime_ctime_preserves_atime_and_generation` | ffs-inode | gen immutable on mtime/ctime update |
| `inode_to_attr_propagates_ext4_generation` | ffs-core | ext4 gen=42 flows to InodeAttr |
| `inode_to_attr_zero_generation_when_not_set` | ffs-core | 128-byte inode defaults to gen=0 |
| `btrfs_inode_item_generation_round_trip` | ffs-core | btrfs gen=99 serialize+parse |
| `inode_attr_to_file_attr_conversion` | ffs-fuse | gen=7 survives to_file_attr |
| proptest `inode_roundtrip` | ffs-inode | arbitrary gen round-trips |
| proptest `inode_checksum_roundtrip` | ffs-inode | gen included in CRC32C seed |

## Structured Logging

Two `tracing::debug!` events at target `ffs::inode::generation`:

- **`inode_generation_bump`**: Emitted in `create_inode()` with fields
  `ino`, `old_generation`, `new_generation`.
- **`inode_delete_preserving_generation`**: Emitted in `delete_inode()` with
  fields `ino`, `current_generation`.
