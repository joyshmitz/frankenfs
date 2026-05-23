# btrfs check status on FFS-written images

`btrfs check --readonly` against a FrankenFS-mutated image:

* **Opens the image cleanly** — fs UUID is preserved, dev_item / sys_chunk_array
  intact, superblock checksum valid. The earlier
  "dev_item UUID does not match fsid: 00000000... != 00000000..." failure mode
  is gone (was caused by `BtrfsSuperblock::to_bytes()` building a fresh buffer
  that didn't model the embedded dev_item region; fixed by patching the
  on-disk superblock in place instead).
* **`dump-tree -t 5` (FS_TREE) renders correctly** — 26 items, INODE_ITEM
  for inode 256 (root dir), DIR_ITEM / DIR_INDEX / INODE_REF for each of
  f_1.txt, f_2.txt, f_3.txt, sub, sub/n.txt, plus inline EXTENT_DATA for the
  payload.
* **`dump-tree -t 1` (ROOT_TREE) renders correctly** — 11 items, FS_TREE
  ROOT_ITEM points at the new fs_tree at the allocated logical address
  (`bytenr 30408704 gen 9 level 0`).

The remaining `btrfs check` errors ("root 5 inode <logical-addr> errors 1,
no inode item" and "parent transid verify failed on <addr> wanted 8 found 9")
all come from the **EXTENT_TREE** being stale relative to our new metadata
extents:

* We allocated new metadata logical addresses (30408704 / 30425088) and wrote
  the new fs_tree / root_tree there, but we did NOT add EXTENT_ITEM entries
  to EXTENT_TREE recording `{bytenr=30408704, owner=FS_TREE, gen=9}` and
  `{bytenr=30425088, owner=ROOT_TREE, gen=9}`.
* We also didn't remove (or generation-advance) the EXTENT_ITEMs that
  EXTENT_TREE still carries for the *old* fs_tree / root_tree blocks
  (at `bytenr=22020096` / `22036480`).

That's a real but separate gap: the new generation's metadata extents need
to be advertised in EXTENT_TREE, and EXTENT_TREE itself needs to be CoW'd
and committed in the same transaction.

**Update (bd-is7m1, 2026-05-23):** The root cause was identified and fixed.
`load_btrfs_alloc_state()` now walks the on-disk EXTENT_TREE during mount
and populates the in-memory extent_tree with all existing entries. This
ensures commit preserves existing extent accounting rather than creating
a fresh extent_tree containing only new allocations. See commit a803f363.

The durability acceptance criterion is unaffected: every mutation made
through the mounted FUSE path survives umount → remount via FrankenFS, and
the image opens cleanly in btrfs-progs. The `btrfs check` failures should
now be resolved.
