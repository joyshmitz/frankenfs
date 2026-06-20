# Negative Evidence Ledger

This is the canonical no-gaps ledger entry point requested by the bold-verify
campaign. Historical rows live in `docs/progress/perf-negative-results.md`; new
campaign closeouts should either update that file directly or add a summary row
here that points to the detailed progress ledger.

## 2026-06-20 cod-a Verification

| Date | Bead | Surface | Verdict | Ratio vs ext4/btrfs-kernel | Internal win/loss/neutral | Direct kernel win/loss/neutral | Gates |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-06-20 | `bd-w3hol` | `ffs-fuse` writeback-cache path, 32 x 32 KiB writes to one file handle followed by flush | KEEP / production retained | Neutral/unavailable: Linux ext4/btrfs do not expose a timed comparator for FrankenFS's in-process per-`(ino, fh)` deferred `RequestScope` table. A mounted write+fsync comparator is still required for whole-filesystem domination claims. | `1/0/0`: fresh cod-a RCH Criterion on `hz1` measured old per-write commit median `75.412 us` vs deferred flush median `64.716 us`, old/new `1.165x`, production latency `0.858x` (`14.2%` lower). Fresh core primitive rerun on `hz1` measured per-write `8.7549 ms` vs request-scope batched `6.7427 ms`, old/new `1.299x`; request-scope remained `1.7%` slower than raw batched commit (`6.6308 ms`). | `0/0/1` | RCH `cargo bench --profile release-perf -p ffs-fuse --bench mount_runtime -- mount_runtime_writeback` passed on `hz1`; RCH `cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- mvcc_commit_batching_2000` passed on `hz1`; RCH `cargo build --release -p ffs-fuse` passed on `hz1`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `vmi1152480` (12/12); RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1153651` (100 passed / 0 failed / 2 ignored). |

Detailed historical context and retry predicates remain in
`docs/progress/perf-negative-results.md`.
