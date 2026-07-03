# Perf campaign status — read this first

**As of 2026-07-03 (BlackThrush).** A ~25-turn single-turn profile-and-optimize
campaign against ext4/btrfs. This is the one-glance synthesis; the chronological
detail is in `docs/NEGATIVE_EVIDENCE.md`, and the one open lever has its own plan
in `docs/bd-bhh0i-parallel-create-plan.md`.

## TL;DR

Single-turn *code* optimization is **exhausted** (every op on both filesystems at
its floor, verified at the hardware-counter level). Three veins were mined after the
whole-op floors: **build-config** (fat LTO landed; target-cpu=v3 + PGO surfaced and
scripted — noise-immune `perf stat` metric), **per-function allocs** (str2hashbuf,
serialize landed via criterion), and a **microarch verify phase** (every hot op
stall-analyzed; six promising levers built as real binaries and A/B-refuted — see
the verify-phase section). The **only** substantive *code* lever left is **bd-bhh0i**
(parallel metadata-write serialization, proven ~7x) — a multi-turn, loom-gated,
correctness-critical effort that must not be rushed into one commit (two prior
attempts corrupted the filesystem).

## Landed wins (all measured, gated, on `main`)

| win | commit | ratio |
| --- | --- | --- |
| ext4 rename skips redundant 2nd htree descent (preflight probe) | eb6a2229 | ~1.13x |
| btrfs zlib decode `miniz_oxide` → `zlib-rs` | 9c39e74f | ~2.95x cold |
| btrfs LZO decode `lzokay-native` → `lzo` crate | 0fc63561 | ~4.45x |
| (earlier) mkdir/mknod/link/symlink htree dedup, eager unlink/rmdir | — | 1.05–2.85x |
| `release-perf` fat LTO (thin→fat) | cd251273 | ~2–3% (instr) |
| `scripts/build-perf.sh` — validated one-command max-perf build | d8f898ce | see below |
| `str2hashbuf` → `[u32;8]` stack array (htree hash, per insert/lookup) | a6c4c505 | ~1.34x (fn) |
| `write_inode` serializes into a stack buffer (`serialize_inode_into`) | dab75bb3 | ~1.13x (fn) |

## Build-config levers (perf-stat-measured; the late vein)

The machine's wall-clock swung ±40%, hiding sub-10% wins. `perf stat`
instruction/cycle counts (deterministic for fixed work) exposed them:

- **fat LTO** — LANDED (cd251273): ~2–3% fewer instructions, broad.
- **target-cpu=x86-64-v3** — surfaced (4ec26bd4): ~8.5% create / ~3% lookup fewer
  instructions; portable to 2015+ CPUs (native gives nothing more). Opt-in: it
  removes the runtime scalar fallback frankenfs deliberately keeps (CPU-baseline
  = maintainer call), and Cargo can't scope `target-cpu` to one profile.
- **PGO** — surfaced (7f0c6ff4): **~10% create / ~24% lookup** fewer instructions;
  a two-stage release process, not a Cargo flag.
- **stacked (fat LTO + v3 + PGO)** — validated via `scripts/build-perf.sh`
  (d8f898ce): **create −14.3%, lookup −27%** vs plain fat-LTO, e2fsck-clean. Run
  `scripts/build-perf.sh` for the max-perf binary; the default build stays portable.
- allocator already jemalloc-optimal (0303500d); crc32c already optimal.

## Per-function + microarch verify phase (criterion + real-binary A/B)

After the whole-op floors, a re-profile reopened a **per-function** vein — criterion
(noise-robust on this loaded machine) surfaced masked per-call heap allocs in hot
functions. Two landed (both byte-identical, criterion-verified):

- **`str2hashbuf`** (a6c4c505): `vec![0;buf_size]` → `[u32;8]` stack array on the
  ext4 htree hash (every create/mkdir/rename/link/symlink insert + htree lookup) —
  −34% on the `dir_lookup` htree bench.
- **`serialize_inode_into`** (dab75bb3): `write_inode` serializes into a stack buffer
  instead of `vec![0;inode_size]` — −12.5% on a new `serialize_inode` bench.

Then every hot op was stall-analyzed (`perf stat` counters) and its promising levers
**built as real binaries and A/B'd** — six refuted, none shipped on a microbench:

- **lookup** = cache-miss-bound (37% miss, hashmap pointer-chasing), NOT dTLB-bound
  (THP refuted). **create** = user-side cache-stall-bound (`ext4_add_dir_entry` #1
  @18% = 4 KiB dir-leaf RMW memcpy + `dir_csum` crc), NOT syscall-bound. **btrfs
  lookup** = attr-cache + `read_inode_attr` (cache-latency floor). **btrfs write** =
  memmove/I/O-bound.
- Refuted with measurement: present-index inline-key (neutral), MVCC chain inline
  (3× slower reads), `prepare_inode` inline (slower), jemalloc THP (not TLB-bound),
  `btrfs_canonical_inode` inline (real-binary A/B neutral), **attr-cache
  `Arc<InodeAttr>`** (microbench said 6.6× faster, **real-binary A/B was +7% cycles**
  — 66402846).
- ⚠️**META-LESSON**: a *streaming* microbench (iterate all keys) exaggerates
  table-size/density and can INVERT the real-path result. Pure-function microbenches
  translate; structural cache-layout changes MUST be verified with a real-binary A/B.

## Lever categories — ALL closed

- **redundant-descent** — harvested (create/mkdir/mknod/link/symlink dedup; rename probe).
- **decode library** — swapped (zlib-rs, lzo); zstd already C-fast; brotli unused.
- **crc32c** — already optimal (crate 0.6.8, SSE4.2 3-way parallel).
- **SipHash→FxHash** — swept (no benchable hot-path default-hasher map left).
- **eager-vs-batched commit** — harvested (unlink/rmdir eager conversion).
- **copy / alloc / read elision** — REFUTED 4×: alloc-churn (0778ddfc), `load_full`
  (9513e82a), `write_block_owned` (8690f3f9), double-inode-read (9fb56052). Meta:
  `__memmove`/alloc self-time OVERCOUNTS; it does not translate to throughput.
- **build config** — MINED via `perf stat` (see the Build-config section above): fat
  LTO landed; target-cpu=v3 + PGO surfaced and scripted (`build-perf.sh`); allocator +
  crc already optimal. The initial fat-LTO wall-clock test was inconclusive (4aba3de2)
  until the perf-stat instruction metric resolved it.

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
