# bd-defgb cod-a closeout: btrfs compressed read oversubscription

Date: 2026-06-20
Agent: BlackThrush (`cod-a`)
Verdict: rejected, no production source kept

## Surface

The target was `bd-defgb`: btrfs zstd compressed reads are faster when the
process-wide rayon pool is capped to 8 threads, but the earlier proposed
decompress-specific fixes did not move the real workload. The live comparator
image was `/data/tmp/btrdiff2_1340519.img`, already mounted read-only by the
kernel at `/data/tmp/btrdiff2mnt_1340519`.

Kernel shape:

- `compressible.bin`: 42,000,000 bytes, zstd-compressed, 128 KiB encoded
  extents.
- `reflink.bin`: 42,000,000 bytes, shared with the same encoded extents.
- Full root data walk: 94,585,777 bytes / 90.2 MiB.

## Measurements

### Direct kernel comparator

Command family:

```text
hyperfine --warmup 3 --runs 10
  'RUST_LOG=warn ffs-cli walk /data/tmp/btrdiff2_1340519.img --read-data --no-stat >/dev/null 2>/dev/null'
  'RAYON_NUM_THREADS=8 RUST_LOG=warn ffs-cli walk /data/tmp/btrdiff2_1340519.img --read-data --no-stat >/dev/null 2>/dev/null'
  'RUST_LOG=warn ffs-cli read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>/dev/null'
  'RAYON_NUM_THREADS=8 RUST_LOG=warn ffs-cli read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>/dev/null'
  'cat /data/tmp/btrdiff2mnt_1340519/* >/dev/null'
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null'
```

| Case | Mean | Ratio |
| --- | ---: | ---: |
| Kernel btrfs `cat *` | `8.006 ms` | baseline |
| FrankenFS `walk --read-data --no-stat` | `40.282 ms` | `5.03x` slower than kernel |
| FrankenFS walk with `RAYON_NUM_THREADS=8` | `28.669 ms` | `3.58x` slower than kernel; `1.41x` faster than default |
| Kernel btrfs `cat compressible.bin` | `5.198 ms` | baseline |
| FrankenFS `read --discard /compressible.bin` | `87.616 ms` | `16.86x` slower than kernel |
| FrankenFS read with `RAYON_NUM_THREADS=8` | `81.685 ms` | `15.72x` slower than kernel |

`perf stat` could not run in this environment: `/proc/sys/kernel/perf_event_paranoid`
is `4`. Fallback `/usr/bin/time -v` still showed the same oversubscription
shape for `walk --read-data`: default pool `0.34s user / 0.18s sys`, 2,813
voluntary context switches and 324 involuntary; `RAYON_NUM_THREADS=8` reduced
that to `0.08s user / 0.03s sys`, 859 voluntary and 129 involuntary.

### Dedicated-pool synthetic gate

RCH command:

```text
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release-perf -p ffs-core \
  --bench btrfs_decompress_extents -- --warm-up-time 1 --measurement-time 3
```

Worker: `vmi1293453`.

| Case | Global/current | Candidate | Verdict |
| --- | ---: | ---: | --- |
| large 272 x 128 KiB zstd file | `9.0318 ms` | dedicated max16 `15.322 ms` | candidate `1.70x` slower |
| multi-file 64 x 4 x 128 KiB | always-install `52.085 ms` | gated small-files `59.538 ms` | candidate `1.14x` slower |
| 16 x 128 KiB simple parallelism | serial `1.3523 ms` | rayon `2.2867 ms` | parallel arm `1.69x` slower |

This independently confirms that the dedicated decompression pool is not a keep.

### Walk read-window sweep

Temporary code added an env override for `walk --read-data` chunk size, with the
production default still at 1 MiB. After measurement, the source edit was
reverted.

| Window | Mean | Old/new |
| --- | ---: | ---: |
| 1 MiB current default | `42.227 ms` | baseline |
| 4 MiB | `48.754 ms` | `0.87x` |
| 8 MiB | `66.773 ms` | `0.63x` |
| 16 MiB | `93.516 ms` | `0.45x` |
| 64 MiB | `146.659 ms` | `0.29x` |

Larger windows reduce metadata descents, but they create much larger
per-call compressed jobs and make the wall-clock path worse. The existing 1 MiB
walk window remains the least bad measured setting.

## Isomorphism

- Ordering preserved: yes. Chunk/window experiments only changed read request
  segmentation; `read_into` still advances by returned byte count and the walk
  still visits entries in readdir order.
- Tie-breaking unchanged: yes. No production code retained.
- Floating-point identical: not applicable.
- RNG seeds unchanged: not applicable.
- Goldens verified: no source code retained; the validation gate was the
  successful RCH benchmark plus direct byte-count smoke (`read 42000000 bytes`
  and walk total `94585777` bytes).

## Release-Readiness Scorecard

| Dimension | Status | Evidence |
| --- | --- | --- |
| Direct btrfs-kernel domination | red | Current walk is `5.03x` slower than kernel on the compressed/reflink data walk; single-file read is `16.86x` slower. |
| Proposed decompressor cap | red | `with_min_len` and dedicated pool both failed; fresh RCH dedicated-pool gate regressed by `1.70x` on the large case. |
| Read-window lever | red | 4/8/16/64 MiB walk windows all regressed vs 1 MiB. |
| Conformance risk | green | No production source retained. |
| Next viable frontier | open | Localize the global-pool sensitivity outside the decompressor map, likely metadata/tree descent, checksum/pread staging, or rayon usage in btrfs tree walking. Use sampled profiler or explicit per-symbol timers before another cap. |

## Retry Predicate

Do not retry `with_min_len`, dedicated decompression pools, or larger
`walk --read-data` windows for this bead. The next attempt needs a profile that
names the pool-size-sensitive symbol under the real mounted compressed workload,
then a same-worker A/B that beats both current default and the kernel comparator
without requiring a process-global `RAYON_NUM_THREADS` cap.
