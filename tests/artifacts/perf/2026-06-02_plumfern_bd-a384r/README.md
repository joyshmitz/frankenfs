# bd-a384r closeout evidence

Owner: PlumFern
Date: 2026-06-02
Bead: `bd-a384r`

## Target

Close out the already-landed file-read coalescing lever:

- `1051687b` coalesces contiguous btrfs file-data block reads.
- `48d81a6a` coalesces contiguous ext4 file-data block reads.
- `0b24b1e7` proves a 4-block btrfs file-data read collapses to exactly one vectored device op.

The remaining question was rch-built release-perf evidence for the original
rank-1 syscall-bound profile target.

## rch build proof

- `RCH_FORCE_REMOTE=true TMPDIR=/data/tmp RUSTFLAGS='-C force-frame-pointers=yes' timeout 1600 rch exec -- cargo build --profile release-perf -p ffs-cli --bin ffs-cli`
  - Worker: `vmi1149989`
  - Result: pass, artifact `/data/tmp/cargo-target/release-perf/ffs-cli`
- `RCH_FORCE_REMOTE=true TMPDIR=/data/tmp RUSTFLAGS='-C force-frame-pointers=yes' timeout 1600 rch exec -- cargo build --profile release-perf -p ffs-harness --bin ffs-harness`
  - Worker: `vmi1293453`
  - Result: pass, artifact `/data/tmp/cargo-target/release-perf/ffs-harness`

## Hyperfine

Command:

```bash
RUST_LOG=off hyperfine -N --warmup 5 --runs 30 \
  '/data/tmp/cargo-target/release-perf/ffs-cli fsck -f --json conformance/golden/ext4_8mb_reference.ext4'
```

Baseline source: `tests/artifacts/perf/2026-06-01_plumfern/baseline_fsck.json`.
Current artifact: `post_fsck_hyperfine.json`.

| metric | baseline | current | delta |
|---|---:|---:|---:|
| mean | 15.566 ms | 14.952 ms | -3.95% |
| median | 15.284 ms | 15.001 ms | -1.85% |
| p95 | 17.800 ms | 16.512 ms | -7.24% |
| p99 | 18.877 ms | 17.916 ms | -5.09% |
| user | 4.307 ms | 3.283 ms | -23.77% |
| system | 10.917 ms | 11.373 ms | +4.18% |

Interpretation: wall-clock is a modest improvement with overlapping variance on
the small 8 MiB fixture. This is not a large throughput claim.

## Syscall Profile

Baseline source: `tests/artifacts/perf/2026-06-01_plumfern/strace_fsck_syscalls.txt`.
Current artifact: `post_fsck_strace.txt`.

| metric | baseline | current | delta |
|---|---:|---:|---:|
| total syscalls | 2,155 | 152 | -92.95% |
| scalar `pread64` calls | 2,051 | 3 | -99.85% |
| vectored `preadv` calls | 0 | 32 | +32 |
| pread-family calls | 2,051 | 35 | -98.29% |

Interpretation: the profile-backed rank-1 target, one syscall per 4 KiB block,
is eliminated on the measured fsck read path.

## Isomorphism Proof

- Ordering preserved: yes. Reads visit the same logical block order; only contiguous physical spans are batched into one vectored device op.
- Tie-breaking unchanged: N/A. File reads have no ranking or tie decision.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- Golden outputs verified:
  - `(cd conformance/golden && sha256sum -c checksums.sha256)`
  - `(cd tests/fixtures/golden && sha256sum -c checksums.txt)`
- Fixed checksum verified:
  - `/data/tmp/cargo-target/release-perf/ffs-harness profile-read-path --fixture conformance/golden/ext4_8mb_reference.ext4 --iterations 1 --mode direct-read`
  - Result checksum: `16877`

## Score

`Impact 4 x Confidence 4 / Effort 2 = 8.0`

Keep/close rationale: the wall-clock win is small, but the original profile was
syscall-bound and the measured syscall collapse is large, deterministic, and
consistent with the already-landed device-op-count unit proof.
