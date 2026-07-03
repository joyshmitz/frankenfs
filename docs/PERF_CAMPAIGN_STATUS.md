# Perf campaign status — read this first

**As of 2026-07-03 (BlackThrush).** A ~25-turn single-turn profile-and-optimize
campaign against ext4/btrfs. This is the one-glance synthesis; the chronological
detail is in `docs/NEGATIVE_EVIDENCE.md`, and the one open lever has its own plan
in `docs/bd-bhh0i-parallel-create-plan.md`.

## TL;DR

Single-turn optimization is **exhausted**. Every op on both filesystems is at its
floor; every lever *category* is closed. The **only** substantive remaining lever
is **bd-bhh0i** (parallel metadata-write serialization, proven ~7x) — a
multi-turn, loom-gated, correctness-critical effort that must not be rushed into
one commit (two prior attempts corrupted the filesystem).

## Landed wins (all measured, gated, on `main`)

| win | commit | ratio |
| --- | --- | --- |
| ext4 rename skips redundant 2nd htree descent (preflight probe) | eb6a2229 | ~1.13x |
| btrfs zlib decode `miniz_oxide` → `zlib-rs` | 9c39e74f | ~2.95x cold |
| btrfs LZO decode `lzokay-native` → `lzo` crate | 0fc63561 | ~4.45x |
| (earlier) mkdir/mknod/link/symlink htree dedup, eager unlink/rmdir | — | 1.05–2.85x |

## Lever categories — ALL closed

- **redundant-descent** — harvested (create/mkdir/mknod/link/symlink dedup; rename probe).
- **decode library** — swapped (zlib-rs, lzo); zstd already C-fast; brotli unused.
- **crc32c** — already optimal (crate 0.6.8, SSE4.2 3-way parallel).
- **SipHash→FxHash** — swept (no benchable hot-path default-hasher map left).
- **eager-vs-batched commit** — harvested (unlink/rmdir eager conversion).
- **copy / alloc / read elision** — REFUTED 4×: alloc-churn (0778ddfc), `load_full`
  (9513e82a), `write_block_owned` (8690f3f9), double-inode-read (9fb56052). Meta:
  `__memmove`/alloc self-time OVERCOUNTS; it does not translate to throughput.
- **build config (fat LTO)** — INCONCLUSIVE (4aba3de2): signal below this session's
  ±40% machine-noise floor; retry on a quiet machine.

## Floor map (every benchable op re-verified at its floor)

- **Metadata write** (create/mkdir/rename/unlink/rmdir/link/symlink/mknod): crc +
  MVCC-commit + inherent per-op work; single-thread syscall-bound at the durability
  boundary.
- **Data write**: MVCC-commit + syscall bound (write-bench 460k IOPS).
- **Reads**: ext4 rand-read I/O-bound; btrfs uncompressed I/O-bound; btrfs
  compressed = decode-then-cached (bd-4tw2n cache 55×); lookup + readdir at the
  parallel-safe-cache floor (arc_swap + ShardedCache are intentional).
- **fsck --force**: I/O-bound (78% kernel `copy_to_user`).

## The one open lever — bd-bhh0i (decision needed)

**Symptom:** in-process parallel create NEGATIVE-scales (1t 118k → 16t 59k). All
ext4 metadata-write ops convoy on the single whole-state `alloc_mutex.write()`.

**Proven ceiling:** ~7x (8 independent processes hit ~747k aggregate vs 118k single;
work parallelizes, in-process serialization is the whole gap).

**Fix (two-part, both required):** shard `alloc_mutex` per group AND spread inode
allocation so concurrent creates touch disjoint inode-table blocks (per-group
sharding alone re-serializes on shared inode-table-block RMW — the failure mode
that corrupted both prior attempts). Full plan + gating in
`docs/bd-bhh0i-parallel-create-plan.md`.

**Why not done here:** it is a loom-gated concurrency refactor (mandatory loom +
e2fsck gating), spans multiple turns, and its parallel result cannot even be
measured under this session's ±40% benchmark noise. Rushing it risks a third
filesystem-corrupting refutation.

## The decision

1. **Authorize the multi-turn bd-bhh0i effort** — land safe, loom+e2fsck-gated
   increments over several turns (ideally on a quiet machine for the final A/B), or
2. **Consider the single-turn perf campaign complete** — the frontier is fully
   mapped and the remaining gap is a known, planned, owner-lane concurrency project.

Everything reachable in single-turn increments has been landed or rigorously
refuted. There is no honest single-turn measured win left to ship.
