# Profile Analysis (bd-3ib.1 / bd-1ieht)

## Metadata

- Profile date (UTC): `2026-05-10T06:05:07Z` through `2026-05-10T06:10:09Z`
- Captured git head: `8b149b28b77b93af5a20dc4e9c94b7b4db8c3b65`
- Kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- CPU: `AMD Ryzen Threadripper PRO 5975WX 32-Cores`
- CPU governor: `powersave`
- Toolchain:
  - `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`
  - `rustc 1.97.0-nightly (37d85e592 2026-04-28)`
  - `linux-perf record -F 4999 --call-graph fp`

## Scope

Target bead: `bd-1ieht`, completion debt for `bd-3ib.1`.

Committed artifacts:

| Artifact | Target | Samples | Duration |
|---|---|---:|---:|
| `profiles/flamegraph_cli_inspect.svg` | canonical ext4 inspect/read-path loop | `297160` | `60544 ms` |
| `profiles/flamegraph_fuse_read.svg` | `FrankenFuse` adapter read dispatch via `read_for_fuzzing` | `297190` | `60525 ms` |
| `profiles/flamegraph_diff_vs_baseline.svg` | metadata diff against `baselines/baseline-20260213.md` | `4000` | `0 ms` |

The original 2026-02-13 profile used a temporary no-journal image and collected
only 18 samples. The 2026-05-10 run uses the canonical generated fixture path
`conformance/golden/ext4_8mb_reference.ext4`; the raw ext4 image is regenerated
when missing and remains ignored, while the checked-in JSON golden remains the
freshness anchor.

Kernel FUSE mounting was denied on the available host (`fusermount3: Permission
denied`), so the FUSE artifact profiles `FrankenFuse::read_for_fuzzing` instead
of a live kernel mount. That path still exercises the FUSE adapter's request
scope, readahead, metric accounting, and backend `OpenFs` read path.

## Hotspots

`perf report --stdio --no-children` now shows application-level symbols instead
of loader-only startup noise.

CLI/read-path top self symbols:

| Self % | Symbol | Object | Interpretation |
|---:|---|---|---|
| 2.42% | `__memmove_avx_unaligned_erms` | `libc.so.6` | buffer movement during repeated metadata reads |
| 1.97% | `ffs_types::ensure_slice` | `ffs-harness` | bounds checking in little-endian parsers |
| 1.84% | `Cx::checkpoint` | `ffs-harness` | asupersync request checkpoint overhead |
| 1.50% | `__memset_avx2_unaligned_erms` | `libc.so.6` | allocation/zero-fill on block buffers |
| 1.25% | `Result<&[u8], ParseError>::branch` | `ffs-harness` | parser error-path branching |
| 1.10% | `ffs_types::read_le_u32` | `ffs-harness` | primitive ext4 field decode |
| 1.00% | `Ext4Superblock::parse_superblock_region` | `ffs-harness` | superblock parse loop |

FUSE-adapter top self symbols:

| Self % | Symbol | Object | Interpretation |
|---:|---|---|---|
| 2.73% | `__memmove_avx_unaligned_erms` | `libc.so.6` | read-buffer movement |
| 1.98% | `Cx::checkpoint` | `ffs-harness` | request-scope checkpoint overhead |
| 1.92% | `ffs_types::ensure_slice` | `ffs-harness` | metadata parser bounds checks |
| 1.78% | `__memset_avx2_unaligned_erms` | `libc.so.6` | buffer zero-fill |
| 1.45% | `Result<&[u8], ParseError>::branch` | `ffs-harness` | parser branch overhead |
| 1.27% | `Ext4Inode::parse_from_bytes` | `ffs-harness` | inode decode on read path |

Bootstrap note: the rendered folded stacks contain `166283` CLI user-space stack
samples and `195274` FUSE-adapter user-space stack samples after unresolved
kernel frames are excluded. The top rendered stack CIs are well above 1%:
CLI file read stack `13.53% [13.37, 13.70]`; FUSE file read stack
`22.83% [22.64, 23.01]`. The lower self-symbol rows above are hotspot leads,
not final optimization claims when their confidence interval would touch 1%.

## Baseline Tie-In

From `baselines/baseline-20260213.md`:

- `ffs-cli inspect ext4_8mb_reference.ext4 --json` was skipped at baseline time
  due to the now-resolved non-contiguous journal extent limitation.
- Available baseline numbers were only parity/check-fixtures commands
  (`~0.9-1.2 ms` range).

`profiles/flamegraph_diff_vs_baseline.svg` records this as a metadata-only diff
because the prior snapshot has no comparable canonical inspect or FUSE stack
profile.

## Opportunity Matrix

| Candidate | Impact | Confidence | Effort | Status |
|---|---|---|---|---|
| Implement ext4 non-contiguous journal extent support | High | High | Medium | Done before this bead |
| Add repeatable in-process inspect profiling | Medium | High | Low | Done in `ffs-harness profile-read-path` |
| Add FUSE read-path profiling | Medium | Medium | Low | Done via `FrankenFuse` adapter dispatch; live kernel mount still blocked by host permissions |
| Reduce repeated metadata buffer movement | Medium | Medium | Medium | Open; investigate `memmove`/`memset` and `FileExt::read_at` stacks |
| Reduce parser primitive overhead | Low-Medium | Medium | Medium | Open; inspect `ensure_slice` and `read_le_*` call density before optimizing |
| Add live kernel-mounted FUSE profile on a permitted host | Medium | High | Low | Open environment follow-up |

## Limitations

- `git_clean` is recorded as false in metadata because this was captured in an
  active swarm worktree with unrelated agent edits present.
- Kernel symbols are partially unresolved due `/proc/kallsyms` restrictions.
- The FUSE artifact is adapter-level, not kernel-mounted, because both the rch
  worker and local host denied `fusermount3`.
