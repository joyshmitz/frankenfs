# Hypothesis Ledger — Perf Profiling Pass `2026-06-01_plumfern`

Each candidate explanation marked `supports` / `rejects` / `open` with evidence.
Triangulation rule: a hypothesis is actionable only when ≥2 orthogonal angles agree.

| # | Hypothesis | Verdict | Evidence |
|---|-----------|---------|----------|
| H1 | The offline read/validate path is **syscall-bound**: it issues one `pread64` per 4 KiB block instead of batching | **supports** | `strace_fsck_syscalls.txt`: 2051 pread64 (58.45% syscall time) for an 8 MiB / 2048-block image; `strace_fsck_read_sizes.txt`: 2048 reads are exactly 4096 B. fsck wall split is User 4.3 ms / **System 10.9 ms** (`baseline_fsck.json`) — system/IO dominates. Two angles agree (strace + user/sys split). |
| H2 | fsck/validate is **CPU-bound** | **rejects** | User CPU is only ~4.3 ms of ~15.6 ms wall; 70% is system time in `pread64`/`read`. |
| H3 | Read-path CPU cost is **concentrated in one hot function** (a single dominant self-symbol) | **rejects** | Prior same-CPU flamegraph (`docs/reports/PROFILE_ANALYSIS.md`) shows a **flat** profile: top self-symbols all 1–3% (`memmove` 2.7%, `Cx::checkpoint` 2.0%, `ensure_slice` 1.9%, `memset` 1.8%, parser `branch` 1.4%, `read_le_u32` 1.1%). No single dominant leaf. |
| H4 | Per-block read **drives buffer-movement cost** (`memmove`/`memset`) seen in the flat CPU profile | **supports** | The cumulative "file read stack" is 13.5% (CLI) / 22.8% (FUSE) in the prior flamegraph, dominated by `__memmove_avx`/`__memset_avx` — consistent with allocating + zero-filling + copying one 4 KiB buffer per block (H1's 2048 reads). Mechanism (strace) + symptom (flamegraph) agree. |
| H5 | Parser primitive overhead (`ensure_slice` bounds checks, `read_le_*`) is a **meaningful** read-path cost | **open** | ~1.9% `ensure_slice` + ~1.1% `read_le_u32` + ~1.4% `Result::branch` self in prior profile; real but small, and CI touches 1%. Needs call-density check before acting (per prior Opportunity Matrix, still Open). |
| H6 | `Cx::checkpoint` (asupersync request-scope) adds avoidable per-iteration overhead on the hot read loop | **open** | 1.8–2.0% self in both CLI and FUSE read profiles. Worth a call-frequency check; not yet root-caused. |
| H7 | Peak memory is a concern for the offline path | **rejects (small scale)** | fsck peak RSS ~11.5–14 MB on an 8 MiB image; bounded. RSS scaling with FS size is the open question, not absolute footprint here. |

## Notes
- Kernel FUSE mount is host-denied (`fusermount3: Permission denied`), so the live
  mounted read/write path is not directly measured; `direct-read` / `cli-inspect`
  in-process modes are the proxy.
- The 8 MiB fixture makes single-shot CLI scenarios (`info`, `inspect`) fall below
  hyperfine's ~5 ms reliability floor; only `fsck -f` clears it. The strace
  syscall count (= exact block count) is the size-independent signal.
