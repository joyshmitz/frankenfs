# Refreshed Hotspot Table — `2026-06-02_tealmarten` (strace, profiler-unblocked)

> Follow-up to `docs/perf/2026-06-01_plumfern/HOTSPOT_TABLE.md` after rank-1
> (bd-a384r) and rank-2-fsck (bd-xmh5g.6) landed. CPU flamegraphs remain blocked
> (perf_event_paranoid); this pass uses strace syscall accounting, which is
> unblocked and was the strongest rank-1 evidence.

## Scenario
`ffs-cli fsck -f --json conformance/golden/ext4_8mb_reference.ext4` (8 MiB ext4,
4 KiB blocks). Release build on rch worker. Artifact: `fsck_force_strace_c.txt`.

## Current syscall profile (`strace -f -c`, total 2.144 ms, 152 calls)

| syscall | calls | %time | note |
|---------|-------|-------|------|
| execve  | 1     | 20.6% | process start (fixed) |
| openat  | 9     | 18.2% | start + image/journal opens |
| **preadv** | **32** | **16.1%** | scrubber batched reads — 2048 blocks / 64-per-batch = 32 (was 2048 scalar preads pre-bd-a384r) |
| mmap    | 19    | 13.1% | allocator/loader |
| brk     | 18    | 8.5%  | heap growth |
| read    | 11    | 4.6%  | **whole-image `std::fs::read` GONE (bd-xmh5g.6)** — these are libc/loader reads |
| pread64 | 4     | 1.3%  | superblock + GDT prefix |

## Findings

1. **fsck I/O is now optimal.** Rank-1 (per-block pread) → 32 batched preadv;
   rank-2 (8 MiB whole-image read) → eliminated. No remaining I/O hotspot; total
   syscall time is 2.1 ms of a ~16 ms wall — the rest is **CPU** (per-block parse +
   crc32c validation across 2048 blocks; crc32c is HW-accelerated and optimal).

2. **Residual rank-2 (CPU/alloc): redundant buffer zeroing on the scrub read path.**
   `BlockDevice::read_contiguous_blocks` (`ffs-core/src/lib.rs:1104`) does
   `*buf = BlockBuf::zeroed(block_size)` for every buffer on every batch, then
   `read_vectored_exact_at` (preadv) immediately overwrites all bytes (it fully
   fills or returns `UnexpectedEof`). The scrub loop (`ffs-repair/src/scrub.rs:295`)
   also re-allocates the `bufs` vec every batch. For an 8 MiB scrub that is
   ~8 MiB of `__memset` (rank-2 symptom in the PlumFern table) + 2048 allocations
   that are pure waste — the bytes are never read before being overwritten.
   **Lever (bd-xmh5g.7):** reuse the buffer allocation across batches and skip the
   re-zero when a buffer is already `block_size` (preadv overwrites it). Filed.

## Hypothesis ledger
- read coalescing → **rejects as a remaining gap** (done; 32 batched preadv).
- whole-image read → **rejects** (done, bd-xmh5g.6; no large `read` in trace).
- scrub buffer zero+alloc churn → **supports** (8 MiB memset + 2048 allocs,
  fully redundant given preadv full-fill) → bd-xmh5g.7.
- parser-primitive CPU density (rank-3) → unmeasurable here (needs flamegraph,
  blocked); ~1-2% self each in the prior table — low priority.

## Hand-off
fsck I/O surface is converged. Next code-readable lever is bd-xmh5g.7 (eliminate
redundant scrub buffer zeroing). Deeper CPU attribution needs a working profiler
(perf_event_paranoid) or belongs to the subsystem-benchmark track (PlumFern).
