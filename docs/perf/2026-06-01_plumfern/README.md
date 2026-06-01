# Perf Profiling Run `2026-06-01_plumfern`

Measurement-only profiling pass (owner: PlumFern, cc) via the
`profiling-software-performance` skill. **No optimization performed** — this is
the input for `extreme-software-optimization`.

## Contents
| File | What |
|------|------|
| `SCENARIO.md` | Scenario definitions (S1 fsck, S2 info, S3 criterion) + method + budgets |
| `fingerprint.json` | Host/toolchain/build env fingerprint |
| `baseline_macro.json` | hyperfine (warmup 5, 25 runs): fsck / info / inspect |
| `baseline_fsck.json` | hyperfine `-N` (warmup 5, 30 runs): fsck -f, the only scenario above the reliability floor |
| `strace_fsck_syscalls.txt` | `strace -c` syscall summary for fsck -f (headline: 2051 pread64, 58% time) |
| `strace_fsck_read_sizes.txt` | pread64 size histogram (2048 × 4096 B = one syscall/block) |
| `perf_read_path_selfsymbols.txt` | Fresh `perf report` self-symbols of in-process `profile-read-path --mode direct-read` (this host, current HEAD) |
| `HOTSPOT_TABLE.md` | **Ranked hotspot table** (the hand-off artifact) |
| `HYPOTHESIS_LEDGER.md` | Hypotheses with supports/rejects/open verdicts + evidence |

## Headline
The offline read/validate path is **syscall-bound**: `fsck -f` issues one
`pread64` per 4 KiB block (2048 for an 8 MiB image; scales linearly with FS
size), spending ~70% of wall in system time. The CPU profile is **flat**
(no single dominant function) and its top symbols (`memmove`/`memset`/parser
primitives) are the side effects of that per-block read+copy structure.

## Filed perf beads (label `perf`)
- `bd-l4lxw` (P1) — per-block pread64 read path → batch / vectored / read-ahead
- `bd-kq3b4` (P2) — read-buffer movement memmove/memset → reusable aligned buffers
- `bd-r8zw8` (P2) — parser primitive density (ensure_slice/read_le_*/branch)
- `bd-htsob` (P3) — asupersync Cx::checkpoint frequency on hot read loop

## Reproduce
```bash
export RUSTFLAGS="-C force-frame-pointers=yes"
rch exec -- cargo build -p ffs-cli --profile release-perf
BIN=$CARGO_TARGET_DIR/release-perf/ffs-cli
IMG=conformance/golden/ext4_8mb_reference.ext4
RUST_LOG=off hyperfine -N --warmup 5 --runs 30 "$BIN fsck -f --json $IMG"
strace -f -c $BIN fsck -f --json $IMG
# CPU flamegraph (in-process read loop):
rch exec -- cargo build --profile release-perf -p ffs-harness --bin ffs-harness
perf record -F 999 -m 8 --call-graph fp -- \
  $CARGO_TARGET_DIR/release-perf/ffs-harness profile-read-path \
  --fixture $IMG --duration-sec 15 --mode direct-read
perf report --stdio --no-children
```

## Caveats
- Kernel FUSE mount host-denied; live mounted path measured via in-process proxy.
- `perf_event_mlock_kb` on the host is misconfigured; perf needs `-m 8`.
- 8 MiB fixture puts `info`/`inspect` below hyperfine's ~5 ms floor; the
  size-independent signal is the strace syscall count (= block count).
