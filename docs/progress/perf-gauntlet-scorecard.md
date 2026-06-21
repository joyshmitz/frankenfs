# Perf Gauntlet Scorecard

## `bd-xmh5g.414` cod-a Btrfs Compressed Input Scratch Rejection

Date: 2026-06-21
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs compressed-read input staging in
`btrfs_read_file_into`
Commit under measurement: local WIP on `ef5038b9`; production hunk manually
reverted after the focused A/B gate
RCH workers: `hz2` baseline/candidate release builds, `hz2` clean-source check
and bench, `vmi1152480` clean-source conformance
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

REJECT. The radical lever came from the allocation/arena/buffer-reuse family:
retain one compressed input `Vec` per Rayon worker/thread and reuse it for tiny
zstd compressed extents, instead of allocating and zero-initializing
`vec![0; compressed_len]` for each compressed read job. The hypothesis was that
the btrfs compressed-read gap was still paying allocator and first-touch tax
after the earlier zero-fill and direct-zstd-output wins.

The direct 15-run smoke row looked barely positive, but the longer 50-run
focused A/B rejected it. Candidate mean was `16.2 ms` versus baseline
`15.9 ms`; hyperfine reported baseline `1.02 +/- 0.13x` faster than the
candidate. The source hunk was reverted; only this ledger evidence remains.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | 1 rejected 15-run A/B row on `/data/tmp/btrdiff2_1340519.img:/compressible.bin`, mounted read-only at `/data/tmp/btrdiff2mnt_1340519`; 1 focused 50-run FrankenFS-only A/B row for keep/reject |
| Direct ext4/btrfs-kernel ratios | Smoke candidate `16.1 ms` vs kernel btrfs `cat` `6.9 ms`: kernel `cat` is `2.31x` faster. Candidate vs materializing kernel `dd bs=8M` `29.2 ms`: FrankenFS candidate is `1.81x` faster. Baseline in the same smoke row was `17.0 ms`; kernel `cat` was `2.45x` faster than baseline. |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal A/B win/loss/neutral | `0 / 0 / 1`: 15-run smoke old/new was `1.056x` (`17.0 ms` -> `16.1 ms`), but the 50-run focused A/B was baseline `15.9 ms` vs candidate `16.2 ms`; baseline ran `1.02 +/- 0.13x` faster, so the result is neutral/no-ship |
| Direct kernel win/loss/neutral | `1 / 1 / 0`: candidate wins vs materializing `dd bs=8M`, loses to fastest mounted-kernel `cat`; no production lever remains after revert |
| Behavior proof | Baseline stdout, candidate stdout, and mounted kernel file SHA-256 all matched: `2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9` |
| Build/check guard | RCH `cargo build --release -p ffs-cli` passed for baseline and candidate on `hz2`; candidate binary SHA-256 `9a39bfcac53f3165a1f3b14850b375f8f14dcd94d8c85263239fe028c72c7150`, baseline binary SHA-256 `bb75561ce0b1d14f5dc1b3ccd7e15de855a838ba4841684d84ba5ae8c7a77597`; local `cargo fmt -p ffs-core --check` and `git diff --check` passed; production hunk was manually reverted and `git diff -- crates/ffs-core/src/lib.rs` was zero after revert; RCH `cargo check -p ffs-core --all-targets` passed on `hz2`; RCH conformance `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1152480` (`100 passed / 0 failed / 2 ignored`). |
| Per-crate bench | RCH `cargo bench --profile release -p ffs-core --bench btrfs_decompress_extents -- btrfs_decompress_tiny_zstd_8x4k_to_128k --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot` passed on `hz2`; serial reused decompressor estimate `387.98 us`, parallel reused decompressor estimate `149.18 us` with wide interval `[99.283 us, 248.44 us]`. |
| Clippy | Not rerun for this evidence-only closeout. No production source remains after revert; current scoped `ffs-core` clippy debt is already attributed in adjacent rows to pre-existing pedantic issues outside this lane. |
| Release-readiness score for perf-superiority claims | 42 / 100: direct mounted-kernel evidence is real and the materializing `dd` comparator is still beaten, but the candidate failed the focused same-binary A/B and fastest kernel `cat` remains `2.31x` faster. |
| Release-readiness score for this row's hygiene | 96 / 100: exact baseline/candidate binaries, direct kernel comparators, longer focused rejection, byte proof, clean-source revert, RCH build/check/bench/conformance, and ledger row are complete. Deduction is no fresh clippy rerun because no source survived. |

### Measured Rows

| Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 15-run `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `17.0 ms +/- 1.5 ms` | `16.1 ms +/- 1.1 ms` | `6.9 ms +/- 0.9 ms` | candidate `1.056x` faster by mean | candidate `2.31x` slower than kernel `cat` | Smoke only |
| 15-run `ffs-cli read --discard /compressible.bin` vs kernel `dd bs=8M` | `17.0 ms` | `16.1 ms` | `29.2 ms +/- 1.5 ms` | candidate `1.056x` faster | candidate `1.81x` faster than kernel `dd` | No keep |
| 50-run focused FrankenFS A/B | `15.9 ms +/- 1.2 ms` | `16.2 ms +/- 1.6 ms` | N/A | candidate `0.982x` old/new by mean; hyperfine says baseline `1.02 +/- 0.13x` faster | N/A | REJECT |

### Isomorphism

Ordering preserved: yes before revert. The candidate changed only compressed
input staging inside each existing `ReadCompressed` job; job order, result
collection order, and assembly order were unchanged.

Tie-breaking unchanged: yes before revert. The existing idx-ordered
`deferred_by_idx` population and first-error handling were unchanged.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: baseline stdout, candidate stdout, and mounted kernel
file SHA-256 all matched:
`2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --release -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-a-btrfs-compressed-scratch-ab-20260621.json \
  --command-name frankenfs-baseline-read \
  '/tmp/ffs-cli-btrfs-scratch-baseline-ef5038b9 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-scratch-candidate \
  '/tmp/ffs-cli-btrfs-scratch-candidate --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null' \
  --command-name btrfs-kernel-dd-8m \
  'dd if=/data/tmp/btrdiff2mnt_1340519/compressible.bin of=/dev/null bs=8M status=none'

hyperfine --warmup 5 --runs 50 \
  --export-json /tmp/frankenfs-cod-a-btrfs-compressed-scratch-ab-focused-20260621.json \
  --command-name frankenfs-baseline-read \
  '/tmp/ffs-cli-btrfs-scratch-baseline-ef5038b9 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-scratch-candidate \
  '/tmp/ffs-cli-btrfs-scratch-candidate --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1'

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo check -p ffs-core --all-targets

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release -p ffs-core \
  --bench btrfs_decompress_extents -- \
  btrfs_decompress_tiny_zstd_8x4k_to_128k \
  --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

Note: the user-requested `cargo bench --release` spelling is not accepted by
Cargo for bench runs, so this used the Cargo-equivalent `--profile release`
spelling.

## `bd-xmh5g.414` cod-a Btrfs Full-Regular Plan Fast-Path Rejection

Date: 2026-06-21
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs compressed-read planning in `btrfs_read_file_into`
Commit under measurement: local WIP on `ffa99c6f`; production hunk manually
reverted after the A/B gate
RCH workers: `hz2` baseline release build, `hz1` candidate release build,
`ovh-a` clean-source conformance
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

REJECT. The candidate tried a full-regular-output fast path: when the planned
compressed/uncompressed regular read jobs cover the whole requested window, skip
the `deferred_by_idx` vector and the second extent-assembly pass. The intended
win was to delete serial bookkeeping in the `.414` "PLAN" region without
touching the already-rejected thread-cap family.

The direct A/B did not clear the keep bar. Candidate mean was `18.575 ms` versus
baseline `19.289 ms`, only `1.038x` old/new with overlapping variance. The
candidate still lost to the fastest mounted btrfs kernel path (`cat`) by
`2.76x`. The source hunk was reverted; only this ledger evidence remains.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | 1 rejected 15-run A/B row on `/data/tmp/btrdiff2_1340519.img:/compressible.bin`, mounted read-only at `/data/tmp/btrdiff2mnt_1340519` |
| Direct ext4/btrfs-kernel ratios | Candidate `18.575 ms` vs kernel btrfs `cat` `6.724 ms` = `2.76x` slower; candidate vs materializing kernel `dd bs=8M` `29.110 ms` = `1.57x` faster. Clean-source post-revert baseline-only row was `16.011 ms` vs kernel `cat` `6.444 ms` and kernel `dd bs=8M` `30.219 ms`. |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal A/B win/loss/neutral | `0 / 0 / 1`: baseline `19.289 ms` vs candidate `18.575 ms`, old/new `1.038x` by mean; median `1.077x` was not accepted under `2.1-2.6 ms` sigma |
| Direct kernel win/loss/neutral | `1 / 1 / 0`: candidate wins vs materializing `dd`, loses to fastest mounted-kernel `cat`; no production lever remains after revert |
| Behavior proof | Candidate stdout matched mounted kernel file SHA-256: `2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9` |
| Build/check guard | RCH `cargo build --release -p ffs-cli` passed for baseline on `hz2` and candidate on `hz1`; RCH `cargo bench --profile release -p ffs-core --bench btrfs_decompress_extents -- btrfs_decompress_tiny_zstd_8x4k_to_128k --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot` passed on `hz2` (serial reused decoder `400.81 us`, parallel reused decoder `174.52 us`); local `cargo fmt -p ffs-core --check` and `git diff --check` passed; production hunk was manually reverted and `git diff -- crates/ffs-core/src/lib.rs` was zero after revert; RCH clean-source `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `ovh-a` (`100 passed / 0 failed / 2 ignored`). |
| Clippy | Not rerun for this evidence-only closeout. No production source remains after revert; current scoped `ffs-core` clippy is already attributed in adjacent rows to pre-existing pedantic debt outside this lane. |
| Release-readiness score for perf-superiority claims | 40 / 100: direct mounted-kernel evidence is real and the materializing `dd` comparator is still beaten, but no new source survived and fastest kernel `cat` remains `2.76x` faster than the candidate. |
| Release-readiness score for this row's hygiene | 94 / 100: exact baseline/candidate binaries, direct kernel comparators, byte proof, clean-source revert, RCH build/conformance gates, and ledger row are complete. Deductions are the rejected lever and no fresh clippy rerun because no source survived. |

### Measured Rows

| Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `19.289 ms` mean, `19.528 ms` median | `18.575 ms` mean, `18.123 ms` median | `6.724 ms` mean | candidate `1.038x` faster by mean | candidate `2.76x` slower than kernel `cat` | REJECT |
| `ffs-cli read --discard /compressible.bin` vs kernel `dd bs=8M` | `19.289 ms` | `18.575 ms` | `29.110 ms` | candidate `1.038x` faster | candidate `1.57x` faster than kernel `dd` | No keep |

### Isomorphism

Ordering preserved: yes before revert. The candidate only returned early after
all regular read jobs completed successfully and only when those jobs covered
the full requested window; sparse holes, inline extents, prealloc extents, and
unsupported extent types stayed on the existing assembly path.

Tie-breaking unchanged: yes before revert for the candidate's fast path. Results
were consumed in planned job order, which is extent order for the full-regular
coverage case. The code was reverted, so the shipping path is exactly the prior
ordering.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: candidate stdout matched the mounted kernel file
SHA-256:
`2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --release -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-a-btrfs-planfast-ab-20260621.json \
  --command-name frankenfs-baseline-read \
  '/tmp/ffs-cli-btrfs-planfast-baseline-ffa99c6f --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-planfast-candidate \
  '/tmp/ffs-cli-btrfs-planfast-candidate --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null' \
  --command-name btrfs-kernel-dd-8m \
  'dd if=/data/tmp/btrdiff2mnt_1340519/compressible.bin of=/dev/null bs=8M status=none'

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release -p ffs-core \
  --bench btrfs_decompress_extents -- \
  btrfs_decompress_tiny_zstd_8x4k_to_128k \
  --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot
```

## `bd-xmh5g` cod-a Ext4 Indirect Zero-Fill Elision Keep

Date: 2026-06-21
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` ext4 legacy indirect read assembly in `read_ext4_indirect_into`
Commit under measurement: local candidate on `665e1cc6`
RCH workers: `ovh-a` release CLI build, `vmi1227854` check,
`vmi1264463` focused test, `vmi1293453` bench, `hz2` conformance/clippy attempt
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

KEEP. The radical lever was data-movement deletion at the read-buffer boundary:
do not zero the whole requested output window before planning ext4 indirect
segments. Instead, zero exactly the ranges proven to be sparse holes while
data segments are planned, and leave data-backed ranges untouched until the
existing parallel segment reader overwrites them.

This is a narrow transfer of the btrfs zero-fill elision to the remaining ext4
indirect loss path. It cuts the exact fixture from `28.8 ms` to `15.5 ms`
(`1.86x` faster), but it does not dominate the fastest mounted ext4 kernel path:
kernel `cat` still wins at `5.2 ms` (`2.99x` faster than the candidate).

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted ext4 rows completed | 1 accepted 15-run A/B row on `/data/tmp/extind2_1501351.img:/double_ind.bin`, mounted read-only at `/data/tmp/extind2mnt_1501351` |
| Direct mounted btrfs rows completed | None for this lever; btrfs unchanged/N/A |
| Direct ext4/btrfs-kernel ratios | Candidate `15.5 ms` vs kernel ext4 `cat` `5.2 ms` = `2.99x` slower. The prior same-source baseline was `28.8 ms`, `5.56x` slower than kernel. |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Internal A/B win/loss/neutral | `1 / 0 / 0`: baseline `28.8 ms` vs candidate `15.5 ms`, old/new `1.86x` by mean |
| Direct kernel win/loss/neutral | `0 / 1 / 0`: exact mounted ext4 indirect read still loses to fastest kernel `cat` |
| Behavior proof | Baseline stdout, candidate stdout, and mounted kernel file SHA-256 all matched: `c0d8240d06d2b4e07ac97735ae497c82b55909a489fd429f937f61ff396ea9be` |
| Build/check guard | Local `cargo fmt -p ffs-core --check` passed; RCH `cargo build --release -p ffs-cli` passed on `ovh-a`; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1227854`; RCH focused `cargo test -p ffs-core ext4_indirect_read_ -- --nocapture` passed on `vmi1264463`; RCH `cargo bench --profile release -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap/large_run_chunked_128blocks --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot` passed on `vmi1293453`; RCH conformance `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `hz2` (`100 passed / 0 failed / 2 ignored`). |
| Clippy | RCH scoped clippy `cargo clippy -p ffs-core --lib --no-deps -- -D warnings` failed on pre-existing `ffs-core` pedantic rows: `vfs.rs` derivable default, old item-after-statement rows, redundant closures, and old indirect-pointer cast rows in the allocating reader/resolvers. The changed zero-fill-elision function had no candidate-local lint. |
| Release-readiness score for perf-superiority claims | 62 / 100: internal improvement is large and conformance is green, but direct mounted-kernel dominance is still not achieved for ext4 indirect reads. |
| Release-readiness score for this row's hygiene | 94 / 100: same-image baseline/candidate binaries, direct kernel comparator, byte proof, RCH build/check/test/bench/conformance, clippy attribution, and ledger row are complete. Deduction is the existing scoped clippy debt plus remaining kernel loss. |

### Measured Rows

| Workload | Baseline | Candidate | Kernel ext4 | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `ffs-cli read --discard /double_ind.bin` vs kernel `cat` | `28.8 ms` mean | `15.5 ms` mean | `5.2 ms` mean | candidate `1.86x` faster | candidate `2.99x` slower than kernel `cat` | KEEP |

### Isomorphism

Ordering preserved: yes. The indirect segment plan and read execution order are
unchanged; only sparse ranges are zero-filled at the point they are identified.

Tie-breaking unchanged: yes. Error priority and segment ordering remain the
existing ordered `Vec<Result<_, _>>` surface.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: baseline stdout, candidate stdout, and mounted kernel
file SHA-256 all matched:
`c0d8240d06d2b4e07ac97735ae497c82b55909a489fd429f937f61ff396ea9be`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --release -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-ext4-indirect-zero-fill-ab-20260621.json \
  '/tmp/ffs-cli-ext4-indirect-zero-fill-baseline-665e1cc6 --log-format json read /data/tmp/extind2_1501351.img /double_ind.bin --discard >/dev/null 2>&1' \
  '/tmp/ffs-cli-ext4-indirect-zero-fill-candidate --log-format json read /data/tmp/extind2_1501351.img /double_ind.bin --discard >/dev/null 2>&1' \
  'cat /data/tmp/extind2mnt_1501351/double_ind.bin >/dev/null'

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release -p ffs-core \
  --bench ext4_indirect_read_overlap -- \
  ext4_indirect_read_overlap/large_run_chunked_128blocks \
  --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

Note: the user-requested `cargo bench --release` spelling is not accepted by
Cargo for bench runs, so this used the Cargo-equivalent `--profile release`
spelling.

## `bd-xmh5g.417` cod-b Ext4 Indirect Materialized-Kernel Addendum

Date: 2026-06-21
Agent: BlackThrush (`cod-b`)
Scope: independent proof and direct-kernel `dd bs=1M` comparator for the ext4
indirect zero-fill elision already retained in the current source
RCH workers: `vmi1227854` check/focused test, `ovh-a` release build/conformance,
`vmi1153651` per-crate bench
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

KEEP / VERIFIED. This pass did not add a second production lever on top of the
source-retained ext4 sparse zero-fill change; it added a reused-buffer
correctness test and a cod-b head-to-head materialized-kernel comparator.

The important routing change is that ext4 no-extents indirect reads now beat a
materializing kernel read path: candidate `14.2 ms` vs kernel `dd bs=1M`
`17.7 ms` (`1.25x` faster). Kernel `cat` remains faster at `5.7 ms`
(`2.51x` faster than FrankenFS), so the remaining loss is the splice-class
path, not the materialized read path.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted ext4 rows completed | 1 current no-extents double-indirect read row on `/data/tmp/extind2_1501351.img:/double_ind.bin` |
| Direct ext4/btrfs-kernel ratios | Candidate `14.2 ms` vs saved baseline `28.0 ms` = `1.97x` faster. Candidate vs kernel `dd bs=1M` `17.7 ms` = FrankenFS `1.25x` faster. Candidate vs kernel `cat` `5.7 ms` = FrankenFS `2.51x` slower. |
| Updated aggregate current frontier | `3 / 4 / 0`: metadata walk, ext4 extent materialize, and ext4 indirect materialize are wins; ext4 extent `cat`, ext4 indirect `cat`, btrfs compressed `dd`, and btrfs compressed `cat` remain losses. |
| Production levers kept | 0 new production levers in this addendum; 1 correctness test added for the retained zero-fill lever |
| Production levers rejected/reverted | 0 |
| Internal win/loss/neutral | `1 / 0 / 0`: same-host saved-binary A/B old/new mean `1.97x` |
| Direct kernel win/loss/neutral | `1 / 1 / 0`: win vs materializing kernel `dd bs=1M`, loss vs kernel `cat` |
| Behavior proof | Baseline binary, candidate binary, and mounted-kernel file all SHA-256 `c0d8240d06d2b4e07ac97735ae497c82b55909a489fd429f937f61ff396ea9be`. The new unit test pre-fills the destination with `0xA5` and verifies both a full-block hole and trailing partial hole are zeroed. |
| Build/check guard | Local `cargo fmt -p ffs-core --check` and `git diff --check` passed. RCH `cargo check -p ffs-core --lib` passed on `vmi1227854`. RCH focused `cargo test -p ffs-core read_ext4_indirect -- --nocapture` passed on `vmi1227854` (2 tests). RCH `cargo build --release -p ffs-cli` passed on `ovh-a`. RCH conformance passed on `ovh-a`: `100 passed / 0 failed / 2 ignored`. |
| Per-crate bench | RCH `cargo bench --profile release -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap/large_run_chunked_in_place_128blocks/8192 --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot` passed on `vmi1153651`; estimate `28.539 ms`, interval `[24.336 ms, 33.695 ms]`. |
| Clippy | Not rerun for this addendum. The cod-a row above records the scoped clippy attempt and attributes failures to pre-existing `ffs-core` pedantic debt outside the zero-fill lever. |
| Release-readiness score for perf-superiority claims | 74 / 100: materialized ext4 indirect domination is now measured and conformance-green, but kernel `cat` remains `2.51x` faster and btrfs compressed remains open. |
| Release-readiness score for this row's hygiene | 91 / 100: direct baseline/candidate/kernel A/B, byte proof, reused-buffer test, RCH check/build/bench/conformance, and ledger update are complete. Deductions are cold-worker target drift and deferred clippy because of known unrelated lint debt. |

### Measured Rows

| Workload | FrankenFS / baseline | Comparator | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| ext4 no-extents indirect read, 50 MiB | candidate `14.2 ms` | saved baseline `28.0 ms` | candidate `1.97x` faster | KEEP |
| ext4 no-extents indirect read, 50 MiB | candidate `14.2 ms` | kernel `dd bs=1M` `17.7 ms` | FrankenFS `1.25x` faster | WIN vs materialize |
| ext4 no-extents indirect read, 50 MiB | candidate `14.2 ms` | kernel `cat` `5.7 ms` | FrankenFS `2.51x` slower | Loss vs splice-class |

### Isomorphism

Ordering preserved: yes. The indirect pointer walk still emits the same mapped
data segments in logical byte order; sparse ranges are zero-filled only where
the same resolver proves there is no mapped block.

Tie-breaking unchanged: yes. Pointer resolution, error priority, and segment
ordering are unchanged.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: yes. Baseline, candidate, and mounted-kernel bytes match
the same SHA-256, and conformance passed `100 / 0 / 2 ignored`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-core --lib

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-core read_ext4_indirect -- --nocapture

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --release -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-b-bd-xmh5g-417-ext4-indirect-zero-fill-ab.json \
  '/tmp/frankenfs-cod-b-bd-xmh5g-417-baseline-ffs-cli read --discard /data/tmp/extind2_1501351.img /double_ind.bin >/dev/null' \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli read --discard /data/tmp/extind2_1501351.img /double_ind.bin >/dev/null' \
  'dd if=/data/tmp/extind2mnt_1501351/double_ind.bin of=/dev/null bs=1M status=none' \
  'cat /data/tmp/extind2mnt_1501351/double_ind.bin >/dev/null'

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release -p ffs-core \
  --bench ext4_indirect_read_overlap -- \
  ext4_indirect_read_overlap/large_run_chunked_in_place_128blocks/8192 \
  --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-xmh5g.416` cod-b Direct-Kernel Scorecard Refresh

Date: 2026-06-21
Agent: BlackThrush (`cod-b`)
Scope: evidence-only current-HEAD scorecard after the CLI metadata-walk pool cap
Commit under measurement: `a20bff76`
RCH workers: `vmi1167313` release CLI compile, `vmi1153651` conformance
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

EVIDENCE-ONLY. No production code changed in this pass. The goal was to refresh
the honest mounted-kernel frontier after `e9800e82`/`a20bff76`, keep the wins and
losses in one ledger, and stop carrying the stale `31x` ext4-indirect framing as
the current gap.

The two headline wins still hold on the warm current binary: metadata walk beats
kernel `find+stat`, and common ext4 extent reads beat a materializing kernel
`dd`. The remaining measured losses are ext4 no-extents indirect reads, btrfs
compressed reads, and all comparisons against kernel `cat`/splice-class paths.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted ext4 rows completed | 3 current rows: 30k-file metadata walk, 128 MiB extent read, and 50 MiB no-extents double-indirect read |
| Direct mounted btrfs rows completed | 1 current compressed-file row on `/data/tmp/btrdiff2_1340519.img:/compressible.bin` |
| Direct ext4/btrfs-kernel ratios | Metadata walk: FrankenFS `34.1 ms` vs kernel `find+stat` `93.3 ms` = `2.73x` faster. Ext4 extent read: FrankenFS `28.5 ms` vs kernel `dd bs=1M` `53.0 ms` = `1.86x` faster, but vs kernel `cat` `12.2 ms` = `2.33x` slower. Ext4 no-extents indirect: FrankenFS `27.7 ms` vs kernel `dd` `17.9 ms` = `1.55x` slower and vs `cat` `5.5 ms` = `5.01x` slower. Btrfs compressed: FrankenFS `37.3 ms` vs kernel `dd` `25.0 ms` = `1.49x` slower and vs `cat` `6.8 ms` = `5.52x` slower. |
| Production levers kept | 0 in this pass; previously shipped CLI metadata-walk cap remains under measurement |
| Production levers rejected/reverted | 0 in this pass |
| Internal win/loss/neutral | N/A: no candidate A/B was introduced |
| Direct kernel win/loss/neutral | `2 / 5 / 0`: two materialized/metadata wins; five remaining kernel comparator losses |
| Behavior proof | SHA-256 of FrankenFS output matched mounted kernel bytes for ext4 extent `b6cfaf9d2c51918b0af3f212577081cc7a41997cbf08de21418c4c5dce631247`, ext4 indirect `c0d8240d06d2b4e07ac97735ae497c82b55909a489fd429f937f61ff396ea9be`, and btrfs compressed `2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`. The metadata walk reported `30003` entries and `30002` stats. |
| Build/check guard | RCH `cargo build --release -p ffs-cli` compiled successfully on `vmi1167313`, then artifact retrieval returned `RCH-E309`; the warm target-dir binary existed at `/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli` and was used for timings. RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1153651` (`100 passed / 0 failed / 2 ignored`). |
| Clippy | Not rerun: this pass changed only docs/tracker evidence and introduced no Rust source. Existing scoped clippy debt remains tracked in prior rows. |
| Release-readiness score for perf-superiority claims | 66 / 100: current evidence proves real domination on metadata walk and materialized ext4 extent reads, but ext4 indirect, btrfs compressed, and kernel splice-class rows remain losses. |
| Release-readiness score for this row's hygiene | 93 / 100: direct mounted ext4/btrfs ratios, byte hashes, warm target-dir binary, RCH build/conformance, and hyperfine JSONs are captured. Deductions are the RCH artifact-sync error and absence of a new production A/B candidate. |

### Measured Rows

| Workload | FrankenFS | Kernel comparator | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| ext4 metadata walk, 30k files | `34.1 ms` | `find+stat` `93.3 ms` | FrankenFS `2.73x` faster | WIN |
| ext4 extent read, 128 MiB | `28.5 ms` | `dd bs=1M` `53.0 ms` | FrankenFS `1.86x` faster | WIN vs materialize |
| ext4 extent read, 128 MiB | `28.5 ms` | `cat` `12.2 ms` | FrankenFS `2.33x` slower | Loss vs splice-class |
| ext4 no-extents indirect read, 50 MiB | `27.7 ms` | `dd` `17.9 ms` | FrankenFS `1.55x` slower | Loss, residual target |
| ext4 no-extents indirect read, 50 MiB | `27.7 ms` | `cat` `5.5 ms` | FrankenFS `5.01x` slower | Loss vs splice-class |
| btrfs compressed read | `37.3 ms` | `dd` `25.0 ms` | FrankenFS `1.49x` slower | Loss, residual target |
| btrfs compressed read | `37.3 ms` | `cat` `6.8 ms` | FrankenFS `5.52x` slower | Loss vs splice-class |

The old `31.78x` ext4-indirect loss row is superseded for current routing. After
the journal-replay memoization and read-into-dst work, the current loss is
`1.55x` vs materializing kernel `dd` and `5.01x` vs fastest kernel `cat`.

### Isomorphism

Ordering preserved: N/A. No production source changed in this pass.

Tie-breaking unchanged: N/A.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: yes. FrankenFS output hashes matched mounted-kernel
bytes for the three direct read comparators, and conformance passed
`100 / 0 / 2 ignored`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --release -p ffs-cli

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-b-meta-walk-20260621.json \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli walk /tmp/ffs_meta_3476799.img >/dev/null' \
  'find /tmp/ffs_metamnt_1695258/bigdir -maxdepth 1 -type f -printf "%s\n" >/dev/null'

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-b-ext4-extent-read-20260621.json \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli read --discard /tmp/ffs_e2e.img /big.bin >/dev/null' \
  'dd if=/tmp/ffs_rmnt_3672057/big.bin of=/dev/null bs=1M status=none' \
  'cat /tmp/ffs_rmnt_3672057/big.bin >/dev/null'

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-b-ext4-indirect-read-20260621.json \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli read --discard /data/tmp/extind2_1501351.img /double_ind.bin >/dev/null' \
  'dd if=/data/tmp/extind2mnt_1501351/double_ind.bin of=/dev/null status=none' \
  'cat /data/tmp/extind2mnt_1501351/double_ind.bin >/dev/null'

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-cod-b-btrfs-compressed-read-20260621.json \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli read --discard /data/tmp/btrdiff2_1340519.img /compressible.bin >/dev/null' \
  'dd if=/data/tmp/btrdiff2mnt_1340519/compressible.bin of=/dev/null status=none' \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null'
```

## `bd-xmh5g.411` cod-b Ext4 Indirect Direct-Output Keep

Date: 2026-06-21
Agent: BlackThrush (`cod-b`)
Scope: `ffs-core` ext4 non-extent indirect read path and
`crates/ffs-core/benches/ext4_indirect_read_overlap.rs`
Commit under measurement: local candidate for `bd-xmh5g.411`
RCH workers: `vmi1152480` check/test, `vmi1153651` bench/conformance,
`hz2` release CLI build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

KEEP the direct-output segment fill. The old ext4 indirect read path allocated
one `Vec` per planned data segment, read into those temporary buffers in
parallel, then copied every segment into the caller output buffer serially. The
candidate splits the final output buffer into disjoint windows up front and lets
each Rayon job fill its final destination directly. Holes remain zero-filled,
partial-block reads keep the existing full-block read plus slice-copy behavior,
and ordered collection preserves the prior first-error surface.

The keep is internal and measured. It does not close the mounted-kernel gap:
exact ext4 no-extents indirect reads still lose badly to kernel ext4 `cat`, and
the rechecked btrfs scorecard row also remains a kernel loss.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted ext4 rows completed | 1 exact no-extents indirect row on `/data/tmp/extind2_1501351.img:/double_ind.bin`, mounted read-only at `/data/tmp/extind2mnt_1501351` |
| Direct mounted btrfs rows completed | 1 current-scorecard row on `/data/tmp/btrdiff2_1340519.img:/compressible.bin`, already mounted read-only |
| Direct ext4/btrfs-kernel ratios | Ext4 indirect: FrankenFS `147.9 ms` vs kernel ext4 `cat` `4.7 ms` = `31.78x` slower. Btrfs scorecard read: FrankenFS `37.7 ms` vs kernel btrfs `cat` `6.8 ms` = `5.56x` slower. |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Internal win/loss/neutral | `1 / 0 / 0` primary: default 128-block chunked temp-buffer path `57.593 ms` mean vs in-place direct-output `24.090 ms` mean = `2.39x`. Supporting chunk-size rows also won; fragmented 256-run row is treated as noisy/neutral routing evidence. |
| Direct kernel win/loss/neutral | `0 / 2 / 0`: exact ext4 indirect and btrfs scorecard reads both lose to fastest mounted-kernel `cat`. |
| Behavior proof | SHA-256 of FrankenFS stdout matched mounted kernel file for both direct comparators: ext4 double-indirect `c0d8240d06d2b4e07ac97735ae497c82b55909a489fd429f937f61ff396ea9be`; btrfs compressible `2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`. Benchmark assertions compare old chunked output and in-place output against the single-run reference. |
| Build/check guard | Local `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --lib` passed on `vmi1152480`; after helper extraction it passed again on `ovh-a`; RCH focused `cargo test -p ffs-core ext4_indirect_read_ -- --nocapture` passed on `vmi1152480`; after helper extraction it passed again on `hz1`; RCH conformance `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1153651` (`100 passed / 0 failed / 2 ignored`) and after helper extraction passed again on `vmi1227854` (`100 passed / 0 failed / 2 ignored`); RCH `cargo build --release -p ffs-cli` passed on `hz2`. |
| Clippy | RCH scoped clippy `cargo clippy -p ffs-core --bench ext4_indirect_read_overlap --no-deps -- -D warnings` initially caught candidate-local item-placement and `read_ext4_indirect` line-count lints. After extracting the job enum/helper, the rerun failed only on pre-existing `ffs-core` pedantic debt: `vfs.rs` derivable default, old item-after-statement rows, redundant closures, and old indirect-pointer cast truncation rows. No candidate-caused clippy lint remains. |
| Release-readiness score for perf-superiority claims | 45 / 100: the internal lever is real and conformance is green, but direct mounted-kernel read rows still lose. |
| Release-readiness score for this row's hygiene | 96 / 100: exact RCH target dir, per-crate bench, behavior hash, mounted ext4/btrfs ratios, conformance, focused check/test reruns after helper extraction, scoped clippy attribution, and ledger rows are complete. Deduction is the remaining unrelated `ffs-core` pedantic clippy debt. |

### Measured Rows

| Workload | Previous path | Candidate | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| `large_run_chunked_128blocks/8192` | `57.593 ms` mean | `24.090 ms` mean | `2.39x` old/new | KEEP |
| `large_run_chunked_64blocks/8192` | `47.148 ms` mean | `21.147 ms` mean | `2.23x` old/new | Supporting win |
| `large_run_chunked_256blocks/8192` | `52.573 ms` mean | `24.064 ms` mean | `2.18x` old/new | Supporting win |
| Mounted ext4 `cat /double_ind.bin` vs FrankenFS | `4.7 ms` kernel | `147.9 ms` FrankenFS | kernel `31.78x` faster | Direct loss |
| Mounted btrfs `cat /compressible.bin` vs FrankenFS | `6.8 ms` kernel | `37.7 ms` FrankenFS | kernel `5.56x` faster | Direct loss |

### Isomorphism

Ordering preserved: yes. Segment planning order is unchanged; the code only
changes where each planned segment is read.

Tie-breaking unchanged: yes. Rayon collection into `Vec<Result<_, _>>`
preserves job order for the indexed vector iterator, and the serial result loop
surfaces the first byte-ordered read error as before.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: yes. The benchmark asserts in-place output equals the
single-run reference, and mounted ext4/btrfs SHA-256 hashes matched the kernel
files before timing. Harness conformance passed `100 / 0 / 2 ignored`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release -p ffs-core \
  --bench ext4_indirect_read_overlap -- \
  ext4_indirect_read_overlap \
  --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture

hyperfine --warmup 3 --runs 15 \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli read --discard /data/tmp/extind2_1501351.img /double_ind.bin' \
  'cat /data/tmp/extind2mnt_1501351/double_ind.bin > /dev/null'

hyperfine --warmup 3 --runs 15 \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli read --discard /data/tmp/btrdiff2_1340519.img /compressible.bin' \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin > /dev/null'
```

Note: the user-requested `cargo bench --release` spelling is not accepted by
Cargo for bench runs, so this used the Cargo-equivalent `--profile release`
spelling.

## `bd-xmh5g` cod-a Btrfs Zero-Fill Elision Keep

Date: 2026-06-21
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs read assembly in `btrfs_read_file_into`
Commit under measurement: baseline and candidate built from `796605c4` plus the
local zero-fill elision candidate
RCH workers: `hz2` build/check, `vmi1152480` conformance/clippy attempt
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

KEEP. The alien-graveyard lever was data-movement elimination: stop paying a
whole-window zero write before every btrfs file read, then prove holes directly
inside the ordered extent assembly pass. This is the same zero-copy/Arrakis
principle applied at the read buffer boundary: do not touch bytes that a later
copy/decompress step is guaranteed to overwrite.

The change removes `out.fill(0)` from `btrfs_read_file_into` and explicitly
zero-fills only these ranges:

- gaps before the next overlapping inline or regular extent
- preallocated or `disk_bytenr == 0` extent overlap
- trailing gap after the last covered extent

Fully covered data reads now skip an avoidable memory write over the entire
destination window. The direct btrfs fixture improved from `37.853 ms` to
`16.450 ms` mean (`2.30x`), with byte identity against both the baseline and the
mounted kernel file.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | 1 accepted 15-run A/B row on `/data/tmp/btrdiff2_1340519.img:/compressible.bin` with two mounted-kernel comparators |
| Direct ext4/btrfs-kernel ratios | Candidate `16.450 ms` vs kernel `cat` `7.048 ms` (`2.33x` slower); candidate vs materializing kernel `dd bs=8M` `29.755 ms` (`1.81x` faster). Ext4 unchanged/N/A because this is btrfs-specific read assembly. |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Internal A/B win/loss/neutral | `1 / 0 / 0`: baseline `37.853 ms` vs candidate `16.450 ms`, old/new `2.30x` by mean and `2.39x` by median |
| Direct kernel win/loss/neutral | `1 / 1 / 0`: wins vs materializing `dd bs=8M`; loses vs `cat` to `/dev/null` |
| Behavior proof | Baseline, candidate, and mounted kernel file SHA-256 all matched: `2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9` |
| Build/check guard | Local `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --all-targets` passed on `hz2`; RCH `cargo build --release -p ffs-cli` passed for baseline and candidate on `hz2`; focused RCH btrfs sparse/prealloc/extend zero-read tests passed; RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1152480` (`100 passed / 0 failed / 2 ignored`). |
| Clippy | Full/scoped RCH clippy remains blocked by pre-existing `ffs-repair` and `ffs-core` pedantic debt: `ffs-repair/src/storage.rs` manual saturating arithmetic/unused-self, `ffs-core/src/vfs.rs` derivable default, old item-after-statement rows, old indirect-pointer casts, and redundant closures. No zero-fill candidate lint was reported. |
| Release-readiness score for perf-superiority claims | 74 / 100: direct mounted-kernel evidence is real and the materializing read comparison wins, but the fastest kernel `cat` path still leads by `2.33x`. |
| Release-readiness score for this row's hygiene | 94 / 100: same-image baseline/candidate binaries, direct kernel comparators, byte proof, focused behavior tests, RCH check/build/conformance, and ledger row are complete. Deductions are the existing clippy debt and remaining loss to kernel `cat`. |

### Measured Rows

| Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `37.853 ms` mean, `38.501 ms` median | `16.450 ms` mean, `16.091 ms` median | `7.048 ms` mean | candidate `2.30x` faster by mean, `2.39x` faster by median | candidate `2.33x` slower than kernel `cat` | KEEP |
| `ffs-cli read --discard /compressible.bin` vs kernel `dd bs=8M` | `37.853 ms` | `16.450 ms` | `29.755 ms` | candidate `2.30x` faster | candidate `1.81x` faster than kernel `dd` | KEEP |

### Isomorphism

Ordering preserved: yes. The extent scan and copy/decompress order are
unchanged; the only change is when uncovered ranges are zero-filled.

Tie-breaking unchanged: yes/N/A.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: baseline stdout, candidate stdout, and mounted kernel
file SHA-256 all matched:
`2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --release -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs-btrfs-zero-fill-hyperfine.json \
  '/tmp/ffs-cli-btrfs-zero-fill-baseline-796605c4 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  '/tmp/ffs-cli-btrfs-zero-fill-candidate-796605c4 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null' \
  'dd if=/data/tmp/btrdiff2mnt_1340519/compressible.bin of=/dev/null bs=8M status=none'

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo check -p ffs-core --all-targets

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-xmh5g` cod-a Btrfs Tiny-Frame Scheduling Rejection

Date: 2026-06-21
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs zstd decompression scheduling, benchmark-only guard in
`crates/ffs-core/benches/btrfs_decompress_extents.rs`
Commit under measurement: production source unchanged; candidate was the
serial-scheduling hypothesis only
RCH worker: `vmi1153651`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

REJECT as a production lever. The alien-graveyard scheduling idea was to avoid
Rayon overhead for the small compressed-frame groups produced by a one-megabyte
`ffs-cli read` tile. The measured shape was `8` independent 128 KiB zstd frames
with the existing thread-local decompressor reuse, comparing current parallel
execution with a serial single-thread loop.

The probe did not justify touching `btrfs_read_file_into`. The current parallel
path measured faster by median (`406.30 us` vs serial `471.70 us`), while the
parallel row was noisy enough that this is routing evidence, not a new keep. No
production source changed.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | None for this candidate; it was rejected at the synthetic scheduling gate before production code changed |
| Direct ext4/btrfs-kernel ratios | Unchanged from current retained btrfs compressed-read scorecard: final-source single-file `35.9 ms` vs kernel `cat` `6.7 ms` (`5.38x` slower); whole-tree walk `31.9 ms` vs kernel `cat *` `11.2 ms` (`2.85x` slower) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 rejected before production edit |
| Internal A/B win/loss/neutral | `0 / 1 / 0`: serial scheduling `471.70 us` vs current parallel scheduling `406.30 us`; serial candidate is `0.861x` the current path by median |
| Direct kernel win/loss/neutral | `0 / 0 / 1`: no production candidate reached the mounted-kernel A/B |
| Behavior proof | Benchmark assertion verifies serial and parallel reused-decoder paths produce identical decompressed byte counts |
| Build/check guard | Local `cargo fmt -p ffs-core --check` passed; RCH Criterion bench passed on `vmi1153651`; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1152480`; `rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture` fell back local because no admissible workers were available and passed `100 / 0 / 2 ignored`; RCH `cargo build --release -p ffs-core` passed on `ovh-a`; no production source changed |
| Clippy | Blocked before the benchmark target: RCH `cargo clippy -p ffs-core --bench btrfs_decompress_extents --no-deps -- -D warnings` failed on pre-existing/current shared `ffs-core` library pedantic rows (`vfs.rs` derivable default, item-after-statement rows, redundant closures, old indirect-pointer casts, and cod-b's in-progress ext4 direct-output enum). No benchmark/doc-caused lint was reported. |
| Release-readiness score for perf-superiority claims | 38 / 100: the residual btrfs compressed-read kernel gap remains large and this scheduling lever did not transfer |
| Release-readiness score for this row's hygiene | 88 / 100: targeted per-crate RCH bench, exact command, ratio, and ledger row are complete; deductions are no mounted-kernel A/B because the lever died before production and no clippy/conformance rerun was needed for production |

### Measured Rows

| Workload | Current path | Serial candidate | Ratio vs current | Kernel btrfs | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| `btrfs_decompress_tiny_zstd_8x4k_to_128k` reused decoder scheduling | `406.30 us` median, interval `[292.57, 630.26] us` | `471.70 us` median, interval `[444.38, 525.59] us` | serial `0.861x` current speed | N/A synthetic gate; direct retained workload still loses to kernel by `5.38x` single-file and `2.85x` walk | REJECT |

### Isomorphism

Ordering preserved: yes for the benchmarked decompression-only primitive; the
assertion compares total decompressed bytes between serial and parallel paths.
No production ordering policy changed.

Tie-breaking unchanged: N/A.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: no production candidate; existing direct-kernel byte
identity from the retained btrfs compressed-read rows remains the last mounted
proof.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release -p ffs-core \
  --bench btrfs_decompress_extents -- \
  btrfs_decompress_tiny_zstd_8x4k_to_128k \
  --warm-up-time 1 --measurement-time 1 --sample-size 10 --noplot
```

Note: the user-requested `cargo bench --release` spelling is not accepted by
Cargo for bench runs, so this used the Cargo-equivalent `--profile release`
spelling.

## `bd-xmh5g.409` cod-a Btrfs Physical-Order Read Rejection

Date: 2026-06-21
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs read job planning in `btrfs_read_file_into`
Commit under measurement: baseline `922ff58b`; candidate was local WIP only and
was manually reverted after the A/B gate
RCH workers: `hz1` check, `hz2` conformance, `vmi1149989` release-perf build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

REJECT. The physical-order scheduling candidate tried to sort btrfs read jobs by
mapped physical offset only when the planned I/O jobs showed a physical
inversion. The intended win was to make the converted btrfs fixture's scattered
128 KiB preads more readahead-friendly without changing already-monotonic
layouts.

The direct converted-image A/B did not pay. Baseline was `64.590 ms`; candidate
was `64.874 ms` (`0.996x` old/new). That is neutral-to-slightly-negative and
below the keep bar. The code was reverted; only this ledger and scorecard remain.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | 1 accepted 15-run A/B row on `/tmp/ffs_btrfs_3704674.img:/big.bin` with three mounted-kernel comparators |
| Direct ext4/btrfs-kernel ratios | Candidate `64.874 ms` vs kernel `cat` `14.977 ms` (`4.33x` slower); candidate vs `dd bs=8M` `67.523 ms` (`1.04x` faster); candidate vs `dd bs=128M` `141.113 ms` (`2.18x` faster) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal A/B win/loss/neutral | `0 / 0 / 1`: baseline `64.590 ms` vs candidate `64.874 ms`, old/new `0.996x` |
| Direct kernel win/loss/neutral | `2 / 1 / 0`: wins only vs materializing `dd`; loses to fastest mounted-kernel `cat` |
| Behavior proof | Baseline and candidate stdout SHA-256 matched the mounted kernel file: `b6cfaf9d2c51918b0af3f212577081cc7a41997cbf08de21418c4c5dce631247` |
| Build/check guard | Clean-source local `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --all-targets` passed on `hz1`; RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `hz2` (`100 passed / 0 failed / 2 ignored`); RCH `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`. |
| Clippy | Not rerun for this evidence-only closeout. No production source remains after revert; the prior scorecard records pre-existing scoped `ffs-core` pedantic debt outside this lane. |
| Release-readiness score for perf-superiority claims | 42 / 100: direct mounted-kernel evidence is real and materializing `dd` remains beaten, but no production lever was kept and fastest kernel `cat` still leads by `4.33x`. |
| Release-readiness score for this row's hygiene | 96 / 100: exact baseline/candidate binaries, direct kernel comparators, byte proof, clean-source revert, RCH check/conformance/build gates, and ledger row are complete. Deductions are the rejected lever and no fresh clippy rerun because no source survived. |

### Measured Rows

| Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `ffs-cli read --discard /big.bin` vs kernel `cat` | `64.590 ms` | `64.874 ms` | `14.977 ms` | `0.996x` old/new | candidate `4.33x` slower than kernel | REJECT |
| `ffs-cli read --discard /big.bin` vs kernel `dd bs=8M` | `64.590 ms` | `64.874 ms` | `67.523 ms` | `0.996x` old/new | candidate `1.04x` faster than kernel `dd` | No keep |
| `ffs-cli read --discard /big.bin` vs kernel `dd bs=128M` | `64.590 ms` | `64.874 ms` | `141.113 ms` | `0.996x` old/new | candidate `2.18x` faster than kernel `dd` | No keep |

### Isomorphism

Ordering preserved: N/A after revert. The candidate proof before revert used the
same file bytes as the mounted kernel path.

Tie-breaking unchanged: N/A after revert.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: baseline and candidate stdout matched the mounted kernel
file SHA-256 before revert. Harness conformance passed after revert.

### Commands

```bash
hyperfine --warmup 3 --runs 15 \
  --export-json /data/projects/.scratch/bd-xmh5g-409-physical-sort-btrfs-bigbin-20260621.json \
  --command-name frankenfs-baseline-read \
  '/data/projects/.scratch/ffs-cli-922ff58b-bd-xmh5g-409-baseline-20260621T0028 --log-format json read /tmp/ffs_btrfs_3704674.img /big.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-physical-sort-read \
  '/data/projects/.scratch/ffs-cli-bd-xmh5g-409-physical-sort-candidate-20260621T0028 --log-format json read /tmp/ffs_btrfs_3704674.img /big.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /tmp/ffs_bmnt_3705579/big.bin >/dev/null' \
  --command-name btrfs-kernel-dd-8m \
  'dd if=/tmp/ffs_bmnt_3705579/big.bin of=/dev/null bs=8M status=none' \
  --command-name btrfs-kernel-dd-128m \
  'dd if=/tmp/ffs_bmnt_3705579/big.bin of=/dev/null bs=128M status=none'

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo check -p ffs-core --all-targets

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --profile release-perf -p ffs-cli
```

## `bd-xmh5g.410` cod-b Disk-Low Code-Only Pending Bench

Date: 2026-06-20
Agent: BlackThrush (`cod-b`)
Scope: `ffs-block::FileByteDevice::read_vectored_exact_at`
Commit under measurement: pending
RCH worker: pending
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

PENDING-BENCH. Disk pressure paused all new cargo build/check/test/bench and
RCH execution for this turn. The code-only lever is retained for the next bench
window: large vectored reads now use one positioned `preadv` directly into the
caller-provided `IoSliceMut`s when the total read is at least the existing
`FileByteDevice` direct-read threshold and the iovec count is within Linux
`IOV_MAX`. Small reads and over-wide iovec arrays keep the old staging scratch.

The intended win surface is the same syscall count as the old large vectored
path, but without allocating and zeroing a full staging `Vec`, first-touching
those pages, then scatter-copying into the block buffers. This is unscored until
the next-turn A/B and conformance gates run.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-only lever committed | Yes: `FileByteDevice::read_vectored_exact_at` single-`preadv` fast path |
| Cargo build/check/test/bench this turn | Not run by disk-low directive |
| Direct ext4/btrfs-kernel ratios | Pending |
| Internal A/B win/loss/neutral | Pending |
| Direct kernel win/loss/neutral | Pending |
| Behavior proof | Static isomorphism only this turn: ordering of caller slices is preserved by `preadv`; offset/end bounds are unchanged; an up-front live-length check preserves destination-on-shrink behavior before mutation; small and over-`IOV_MAX` paths retain the old fallback. |
| Release-readiness score for perf-superiority claims | Unchanged / no upgrade: candidate is not benchmark-verified yet |
| Release-readiness score for this row's hygiene | 70 / 100: clean source branch and explicit pending gates, but no executable cargo or direct-kernel evidence yet by directive. |

### Pending Commands

```bash
AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-block --all-targets

AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-block file_byte_device_vectored -- --nocapture

AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-block --bench file_device_read -- file_device_vectored_read_128k

AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-block --bench read_contiguous -- read_contiguous
```

### Stop Rule

Keep only if the accepted same-source A/B clears `>1.05x` on the real vectored
read surface and conformance stays green. Revert and move this row to rejected
negative evidence if the win is neutral/regressive or if any behavior gate
fails.

## `bd-xmh5g` cod-a Btrfs Compressed Fused-Copy Keep

Date: 2026-06-20
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs regular compressed-extent read/decompress assembly in
`btrfs_read_file_into`
Commit under measurement: final-source clean worktree candidate
RCH worker: `vmi1149989` remote compile gate
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`
Measured local target dir: `/data/projects/.local-targets/frankenfs-cod-a-batch`

### Verdict

KEEP. The lever fuses assembly for regular compressed extents into the parallel
read/decompress job: decompress into the existing temporary `Vec`, copy the
requested decompressed slice into the final disjoint output window, then drop the
temporary immediately. This keeps the rejected zstd direct-to-final idea out of
the decoder, but removes the old live-set shape where every regular compressed
extent's decompressed `Vec` stayed resident until the serial assembly loop.

The single-file compressed read improved materially and RSS dropped. The whole
tree walk was neutral-positive and does not get extra keep credit. Kernel btrfs
still wins both direct rows, so this is a gap reduction, not a kernel-domination
claim.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | 4 accepted rows: primary 15-run read/walk plus final-source 10-run read/walk, all with mounted kernel comparators |
| Direct ext4/btrfs-kernel ratios | Final-source read candidate `35.9 ms` vs kernel `6.7 ms` (`5.38x` slower); final-source walk candidate `31.9 ms` vs kernel `11.2 ms` (`2.85x` slower) |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Internal A/B win/loss/neutral | `1 / 0 / 1`: single-file read win, walk neutral |
| Direct kernel win/loss/neutral | `0 / 2 / 0` |
| Memory signal | Single-file max RSS `83,620 KiB -> 50,868 KiB`; minor faults `22,932 -> 14,478` |
| Behavior proof | Candidate read SHA-256 matched mounted kernel file: `2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`; focused btrfs decompression tests passed `10/10`; harness conformance passed `100 / 0 / 2 ignored` |
| Build/check guard | RCH `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`, but artifact retrieval left `/data/projects/.rch-targets/frankenfs-cod-a/release-perf/ffs-cli` at the clean baseline hash. Accepted timings use a local release-perf final-source build. Local `cargo fmt -p ffs-core --check` and `cargo check -p ffs-core --all-targets` passed. |
| Clippy | `cargo clippy -p ffs-core --all-targets --no-deps -- -D warnings` remains blocked by pre-existing pedantic debt outside this lever: `vfs.rs` derivable default, old `BTRFS_CHUNK_BLOCKS` local static, statfs too-many-lines, later local `use`/const placement, indirect-pointer casts, and redundant closures. The candidate-caused local-enum lint was fixed. |
| Release-readiness score for perf-superiority claims | 61 / 100: a real measured keep with byte/conformance proof and lower RSS, but direct kernel btrfs still leads by `2.85-5.38x`. |
| Release-readiness score for this row's hygiene | 95 / 100: clean worktree, explicit baseline/candidate binaries, primary and final-source A/B rows, direct kernel ratios, byte proof, conformance, and clippy blocker attribution are recorded. The only deduction is RCH artifact retrieval failing to provide the measured binary. |

### Measured Rows

| Phase | Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Primary A/B, 15 runs | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `56.1 ms` | `36.8 ms` | `7.4 ms` | `1.52x` old/new | candidate `5.00x` slower than kernel | KEEP |
| Primary A/B, 15 runs | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `36.6 ms` | `34.0 ms` | `11.9 ms` | `1.08x` old/new | candidate `2.85x` slower than kernel | Neutral |
| Final-source confirmation, 10 runs | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `53.2 ms` | `35.9 ms` | `6.7 ms` | `1.48x` old/new | candidate `5.38x` slower than kernel | KEEP confirmation |
| Final-source confirmation, 10 runs | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `32.4 ms` | `31.9 ms` | `11.2 ms` | `1.015x` old/new | candidate `2.85x` slower than kernel | Neutral |

### Isomorphism

Ordering preserved: yes. Extents are still validated and consumed in extent
order; regular compressed extent copies moved earlier only after carving
disjoint final output windows.

Tie-breaking unchanged: yes. Per-idx first error is retained, and the serial
assembly loop still consumes results in extent order.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: candidate stdout for `/compressible.bin` matches the
mounted kernel file SHA-256. Harness conformance passed.

### Commands

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --profile release-perf -p ffs-cli

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo build --profile release-perf -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /data/projects/.scratch/batch-fused-ab-single-20260620.json \
  --command-name frankenfs-baseline-read \
  '/data/projects/.scratch/ffs-cli-547be7a3-cod-a-batch-baseline-20260620T2107 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-fused-copy-read \
  '/data/projects/.scratch/ffs-cli-547be7a3-cod-a-batch-fused-copy-candidate-local-20260620T2125 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null'

hyperfine --warmup 3 --runs 10 \
  --export-json /data/projects/.scratch/batch-fused-final-single-20260620.json \
  --command-name frankenfs-baseline-read \
  '/data/projects/.scratch/ffs-cli-547be7a3-cod-a-batch-baseline-20260620T2107 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-fused-copy-final-read \
  '/data/projects/.scratch/ffs-cli-547be7a3-cod-a-batch-fused-copy-final-20260620T2137 --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null'

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-xmh5g` cod-a Guard-Fold Rejection

Date: 2026-06-20
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs streamed-read dir/symlink guard fold in
`btrfs_read_file_into_impl`
Commit under measurement: `4e9e9c1b`
Revert commit: `37b7e8b`
RCH workers: `vmi1149989` clean-current release-perf build and post-revert
`ffs-core` check, `vmi1153651` parent release-perf build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

REJECT. The idea was a metadata-elision lever: reuse the already-fetched btrfs
inode item in the streamed-read path instead of doing another
`btrfs_read_inode_attr` style guard before regular-file reads. It was plausible
because the remaining compressed-read gap has repeatedly pointed at btrfs
metadata fan-out and per-call overhead.

The first local A/B appeared spectacular, but it was invalid: the shared
worktree had a concurrent peer edit in `crates/ffs-cli/src/main.rs` that changed
the CLI single-file read tile from 64 MiB to 1 MiB. The contaminated binary
therefore measured two levers at once. Detached clean worktrees for parent
`5d77712a` and current `4e9e9c1b` removed that contamination and showed the
guard fold alone was neutral on single-file read and neutral/slightly negative
on walk. Production source was reverted.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this closeout | 1 |
| Direct mounted btrfs rows completed | 4 clean rows plus 4 invalid/contaminated diagnostic rows |
| Same-host evidence | Local A/B against `/data/tmp/btrdiff2_1340519.img` and mounted reference `/data/tmp/btrdiff2mnt_1340519`; clean acceptance runs used 15 iterations |
| Direct ext4/btrfs-kernel ratios | Clean current single-file read `56.5 ms` vs kernel `7.1 ms` (`8.01x` slower); clean current walk `34.9 ms` vs kernel `12.4 ms` (`2.82x` slower) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal A/B win/loss/neutral | `0 / 1 / 1`: single-file neutral below keep threshold, walk slight loss/noise |
| Direct kernel win/loss/neutral | `0 / 2 / 0` |
| Conformance/build guard | RCH clean-current `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`; RCH parent build passed on `vmi1153651`; local clean parent/current release-perf builds passed for runnable binaries; `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1149989`; local fallback `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored` after RCH reported no admissible worker for that test. |
| Release-readiness score for perf-superiority claims | 42 / 100: direct mounted-kernel evidence and conformance are green, but this lever keeps no production win and btrfs-kernel still leads by `2.82-8.01x` on clean rows. |
| Release-readiness score for this row's hygiene | 97 / 100: exact parent/current commits were rebuilt, contamination was detected and corrected with detached clean worktrees, direct kernel ratios and invalid rows are recorded, and the no-gain source was reverted. |

### Measured Rows

| Phase | Workload | Parent | Current | Kernel btrfs | Ratio vs parent | Ratio vs kernel | Verdict |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Invalid contaminated, parent first | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `59.5 ms` | `23.3 ms` | `7.2 ms` | `2.55x` old/new | current `3.25x` slower than kernel | Invalid: current binary included peer CLI tile edit |
| Invalid contaminated, current first | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `58.4 ms` | `22.7 ms` | `7.0 ms` | `2.57x` old/new | current `3.23x` slower than kernel | Invalid: confirms contamination, not guard-fold keep |
| Invalid contaminated, parent first | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `35.1 ms` | `36.0 ms` | `11.7 ms` | `0.974x` old/new | current `3.07x` slower than kernel | Invalid diagnostic; walk did not improve |
| Invalid contaminated, current first | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `34.4 ms` | `34.3 ms` | `10.9 ms` | `1.003x` old/new | current `3.15x` slower than kernel | Invalid diagnostic; neutral |
| Clean acceptance | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `57.1 ms` | `56.5 ms` | `7.1 ms` | `1.011x` old/new | current `8.01x` slower than kernel | Reject: neutral/no-ship |
| Clean acceptance | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `34.4 ms` | `34.9 ms` | `12.4 ms` | `0.986x` old/new | current `2.82x` slower than kernel | Reject: slight loss/noise |

### Kernel Reference Coverage

This row used the same mounted read-only btrfs image as the direct kernel
reference. The clean candidate never beat kernel btrfs and did not move the
FrankenFS side enough to justify keeping code. The false contaminated win is a
useful guardrail: do not attribute future 64 MiB -> 1 MiB CLI tile results to
core btrfs metadata changes unless the binary is built from a clean worktree.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --profile release-perf -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /data/projects/.scratch/guardfold-clean-btrfs-zstd-single-20260620.json \
  --command-name parent-5d77712a \
  '/data/projects/.scratch/ffs-cli-5d77712a-guardfold-parent --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name clean-current-4e9e9c1b \
  '/data/projects/.scratch/ffs-cli-4e9e9c1b-guardfold-clean-current --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null'

hyperfine --warmup 3 --runs 15 \
  --export-json /data/projects/.scratch/guardfold-clean-btrfs-zstd-walk-20260620.json \
  --command-name parent-5d77712a \
  '/data/projects/.scratch/ffs-cli-5d77712a-guardfold-parent --log-format json walk /data/tmp/btrdiff2_1340519.img --read-data --no-stat >/dev/null 2>&1' \
  --command-name clean-current-4e9e9c1b \
  '/data/projects/.scratch/ffs-cli-4e9e9c1b-guardfold-clean-current --log-format json walk /data/tmp/btrdiff2_1340519.img --read-data --no-stat >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/* >/dev/null'

cargo fmt -p ffs-core --check

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo check -p ffs-core --all-targets

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-xmh5g.408` cod-b Btrfs Metadata-Descent Rejection

Date: 2026-06-21
Agent: BlackThrush (`cod-b`)
Scope: `ffs-core` btrfs read/read_into dir/symlink guard descent plus
`ffs-cli read` final lookup/getattr reuse
Commit under measurement: detached-worktree candidate at `d5ebffea`, source
reverted before commit
RCH worker: `vmi1227854` clean-source release-perf build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

REJECT. The combined lever removed the redundant btrfs pre-read
`btrfs_read_inode_attr` guard from `read`/`read_into` by using the inode item
already fetched in `btrfs_read_file_into`, while preserving symlink payload
reads for `readlink`. It also reused the final `lookup` attr in `ffs-cli read`
instead of immediately calling `getattr` on the same inode for file size.

The direct mounted-kernel A/B did not justify keeping source. Single-file read
was only `1.03x` old/new, below the keep threshold, and whole-tree walk was
slightly slower/noise. A `pread64` diagnostic showed the same syscall count on
the target (`332` baseline, `332` candidate), so the suspected duplicate
metadata descents are already hidden by the current cache/read shape for this
image. Production source was manually reverted; this section is evidence only.

### Scorecard

| Gate | Result |
| --- | --- |
| Direct mounted btrfs rows completed | 4 rows: single-file read and whole-tree walk, each with baseline, candidate, and mounted-kernel comparator |
| Same-host evidence | Local detached-worktree A/B at `d5ebffea` against `/data/tmp/btrdiff2_1340519.img` and mounted reference `/data/tmp/btrdiff2mnt_1340519`; accepted runs used 15 iterations |
| Direct ext4/btrfs-kernel ratios | Candidate single-file read `37.6 ms` vs kernel `7.5 ms` (`5.01x` slower); candidate walk `34.1 ms` vs kernel `12.2 ms` (`2.79x` slower) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 combined metadata-elision lever |
| Internal A/B win/loss/neutral | `0 / 1 / 1`: single-file neutral-positive below keep threshold; walk slight loss/noise |
| Direct kernel win/loss/neutral | `0 / 2 / 0` |
| Syscall diagnostic | `strace -f -c -e pread64` single-file read: baseline `332` preads, candidate `332` preads |
| Build/check guard | RCH clean-source `cargo build --profile release-perf -p ffs-cli` passed on `vmi1227854`; isolated local release-perf baseline and candidate builds passed; `cargo check -p ffs-core --all-targets` and `cargo check -p ffs-cli --all-targets` passed; post-revert `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored` |
| Behavior proof | Focused `cargo test -p ffs-core btrfs_read -- --nocapture` passed `21 / 0 / 1 ignored`; `cargo test -p ffs-core readlink -- --nocapture` passed `4 / 0`; `cargo test -p ffs-core btrfs_symlink_target_passes_btrfs_check -- --nocapture` passed `1 / 0` |
| Formatting | `rustfmt --edition 2024 --check --config skip_children=true crates/ffs-core/src/lib.rs crates/ffs-cli/src/main.rs` passed. Full `cargo fmt -p ffs-cli --check` remains blocked by pre-existing `crates/ffs-cli/src/cmd_repair.rs` formatting drift unrelated to this candidate. |
| Release-readiness score for perf-superiority claims | 35 / 100: direct mounted-kernel evidence is real, but no production code was kept and kernel still leads by `2.79-5.01x` on the accepted candidate rows. |
| Release-readiness score for this row's hygiene | 96 / 100: isolated detached worktree, current HEAD baseline/candidate binaries copied aside, direct kernel ratios, pread diagnostic, focused behavior tests, conformance, and source revert are recorded. Remaining deductions are lack of full clippy because of pre-existing workspace pedantic debt and the known package fmt drift outside the edited files. |

### Measured Rows

| Phase | Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Acceptance, 15 runs | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `38.7 ms` | `37.6 ms` | `7.5 ms` | `1.03x` old/new | candidate `5.01x` slower than kernel | Reject: below keep threshold |
| Acceptance, 15 runs | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `33.9 ms` | `34.1 ms` | `12.2 ms` | `0.994x` old/new | candidate `2.79x` slower than kernel | Reject: slight loss/noise |
| Diagnostic | single-file `strace -f -c -e pread64` | `332` preads | `332` preads | N/A | no syscall-count change | N/A | Confirms no real metadata I/O reduction on this fixture |

### Isomorphism

Ordering preserved: yes. The candidate only moved regular-file type checks to
the inode item already fetched by the read helper and reused the final CLI
lookup attr for file size.

Tie-breaking unchanged: yes. Btrfs symlink payload reads stayed allowed only
for `readlink`; public regular reads still rejected symlink inodes.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Goldens/bytes verified: focused btrfs read and symlink tests passed; post-revert
harness conformance passed `100 / 0 / 2 ignored`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --profile release-perf -p ffs-cli

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  cargo build --profile release-perf -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /data/projects/.scratch/bd-xmh5g-408-d5ebffea-read-20260621.json \
  --command-name frankenfs-baseline-read \
  '/data/projects/.scratch/ffs-cli-d5ebffea-bd-xmh5g-408-baseline --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name frankenfs-candidate-read \
  '/data/projects/.scratch/ffs-cli-d5ebffea-bd-xmh5g-408-candidate --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null'

hyperfine --warmup 3 --runs 15 \
  --export-json /data/projects/.scratch/bd-xmh5g-408-d5ebffea-walk-20260621.json \
  --command-name frankenfs-baseline-walk \
  '/data/projects/.scratch/ffs-cli-d5ebffea-bd-xmh5g-408-baseline --log-format json walk --read-data --no-stat /data/tmp/btrdiff2_1340519.img >/dev/null 2>&1' \
  --command-name frankenfs-candidate-walk \
  '/data/projects/.scratch/ffs-cli-d5ebffea-bd-xmh5g-408-candidate --log-format json walk --read-data --no-stat /data/tmp/btrdiff2_1340519.img >/dev/null 2>&1' \
  --command-name btrfs-kernel-cat-all \
  'sh -c "cat /data/tmp/btrdiff2mnt_1340519/* >/dev/null"'
```

## `bd-xmh5g.407` cod-b CLI Read-Tile Rejection

Date: 2026-06-20
Agent: BlackThrush (`cod-b`)
Scope: `ffs-cli read` single-file stream tile for btrfs compressed reads,
64 MiB -> 1 MiB
Commit under measurement: rejected local candidate, source reverted before
commit
RCH workers: `vmi1227854` clean-source release-perf build, `vmi1149989`
candidate release-perf build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

REJECT. The profile hypothesis was that the single-file `ffs read` command was
making the btrfs compressed-read gap worse by requesting a 64 MiB chunk, forcing
the core read path to hold the output chunk plus every decompressed extent in
that chunk. The `walk --read-data` path already uses a 1 MiB buffer and showed
much lower one-shot RSS, so this was a plausible cache/working-set tile lever.

The real direct comparator rejected it. A one-shot smoke looked faster
(`33.2 ms` -> `29.8 ms` CLI duration), but the 15-run hyperfine acceptance pass
regressed the target read from `35.266 ms` to `36.367 ms` (`0.970x` old/new).
RSS did not materially improve (`47,844 KiB` baseline vs `47,812 KiB`
candidate), so the working-set story did not hold. The production source was
reverted; only this evidence remains.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this closeout | 1 |
| Direct mounted btrfs rows completed | 4 rows: current/candidate `ffs read` and current/candidate `walk --read-data`, each compared to the mounted kernel image |
| Same-host evidence | Local A/B against `/data/tmp/btrdiff2_1340519.img` and mounted reference `/data/tmp/btrdiff2mnt_1340519`; acceptance runs used 15 iterations |
| Direct ext4/btrfs-kernel ratios | Candidate single-file read `36.367 ms` vs kernel `6.268 ms` (`5.80x` slower); candidate walk `31.486 ms` vs kernel `11.888 ms` (`2.65x` slower) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal A/B win/loss/neutral | `0 / 1 / 1`: target read loss; untouched walk path treated as collateral/no-ship evidence |
| Direct kernel win/loss/neutral | `0 / 2 / 0` |
| Conformance/build guard | RCH clean-source `cargo build --profile release-perf -p ffs-cli` passed on `vmi1227854`; RCH candidate build passed on `vmi1149989`; source reverted; `git diff --exit-code -- crates/ffs-cli/src/main.rs` passed; RCH conformance `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `hz2` (100 passed / 0 failed / 2 ignored). `cargo fmt -p ffs-cli --check` is blocked by pre-existing formatting drift in `crates/ffs-cli/src/cmd_repair.rs`, not by this reverted candidate. |
| Release-readiness score for perf-superiority claims | 35 / 100: direct mounted-kernel evidence is real, but no production code was kept and kernel still leads by `2.65-5.80x` on the accepted candidate rows. |
| Release-readiness score for this row's hygiene | 92 / 100: baseline/candidate direct rows, RSS smoke, kernel ratios, RCH build evidence, and manual source revert are recorded; remaining risk is that no allocator profiler was available to pinpoint the underlying allocation site. |

### Measured Rows

| Phase | Workload | Baseline | Candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| One-shot RSS smoke | `ffs-cli read --discard /compressible.bin` | `33.228 ms`, `47,844 KiB`, `11,577` minor faults | `29.814 ms`, `47,812 KiB`, `11,561` minor faults | N/A | `1.11x` old/new smoke | N/A | Routing-only smoke; RSS unchanged |
| Acceptance, 15 runs | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `35.266 ms` | `36.367 ms` | `6.268 ms` | `0.970x` old/new | candidate `5.80x` slower than kernel | Reject: regression |
| Acceptance, 15 runs | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `29.108 ms` | `31.486 ms` | `11.888 ms` | `0.925x` old/new | candidate `2.65x` slower than kernel | Reject: no collateral win |

### Kernel Reference Coverage

This row used the same mounted read-only btrfs image as the direct kernel
reference. The candidate never beat kernel btrfs. The failed RSS movement says
the remaining compressed-read gap is not solved by shrinking the CLI request
tile alone; another pass needs allocator attribution inside `btrfs_read_file`
or a structural I/O/decode design that actually reduces live decompressed
extent/output overlap.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --profile release-perf -p ffs-cli

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs_cod_b_current_btrdiff2_read_walk.json \
  '/data/projects/.rch-targets/frankenfs-cod-b/release-perf/ffs-cli --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null' \
  '/data/projects/.rch-targets/frankenfs-cod-b/release-perf/ffs-cli --log-format json walk --read-data --no-stat /data/tmp/btrdiff2_1340519.img >/dev/null 2>&1' \
  'cat /data/tmp/btrdiff2mnt_1340519/* >/dev/null'

hyperfine --warmup 3 --runs 15 \
  --export-json /tmp/frankenfs_cod_b_candidate_btrdiff2_read_walk.json \
  '/data/projects/.rch-targets/frankenfs-cod-b/release-perf/ffs-cli --log-format json read /data/tmp/btrdiff2_1340519.img /compressible.bin --discard >/dev/null 2>&1' \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin >/dev/null' \
  '/data/projects/.rch-targets/frankenfs-cod-b/release-perf/ffs-cli --log-format json walk --read-data --no-stat /data/tmp/btrdiff2_1340519.img >/dev/null 2>&1' \
  'cat /data/tmp/btrdiff2mnt_1340519/* >/dev/null'
```

## `bd-xmh5g` cod-b Scratch-Buffer Rejection

Date: 2026-06-20
Agent: BlackThrush (`cod-b`)
Scope: btrfs zstd compressed-read input-buffer scratch reuse, retaining one
compressed input `Vec` per Rayon worker for sub-1 MiB compressed extents.
Commit under measurement: rejected local candidate, source reverted before
commit
RCH workers: `vmi1153651` release build after revert, `vmi1149989`
conformance after revert
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

REJECT. The lever was a plausible allocator-pressure attack from the btrfs
compressed-read gap: reuse the compressed input staging buffer per worker while
leaving output assembly and decompressor semantics unchanged. A 7-run smoke
looked mildly positive, but the 25-run acceptance pass flipped the single-file
read into a regression and left the whole-tree walk in neutral/no-ship
territory. The source change was reverted; only this evidence remains.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this closeout | 1 |
| Direct mounted btrfs rows completed | 4 rows: 2 smoke rows plus 2 acceptance rows |
| Same-worker evidence | Local same-host A/B against clean `59466af0` baseline and mounted kernel btrfs image `/data/tmp/btrdiff2_1340519.img`; acceptance runs used 25 iterations |
| Direct ext4/btrfs-kernel ratios | 0 / 2 acceptance rows beat kernel; candidate was `8.53x` slower on single-file read and `2.77x` slower on whole-tree walk |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal A/B win/loss/neutral | `0 / 1 / 1` on acceptance: read loss, walk neutral |
| Direct kernel win/loss/neutral | `0 / 2 / 0` |
| Conformance/build guard | Local `cargo check -p ffs-core --all-targets` passed while the scratch candidate was present; source reverted; RCH `cargo build --release -p ffs-cli` passed on `vmi1153651`; RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1149989` (100 passed / 0 failed / 2 ignored). |
| Release-readiness score for perf-superiority claims | 58 / 100: direct mounted kernel evidence is real and conformance is green, but this lever did not reduce the remaining btrfs compressed-read gap enough to ship. |
| Release-readiness score for this row's hygiene | 96 / 100: candidate measured, higher-confidence rerun performed after smoke ambiguity, regression reverted, direct kernel ratios recorded, and conformance/build gates are green. |

### Measured Rows

| Phase | Workload | Baseline | Scratch candidate | Kernel btrfs | Ratio vs baseline | Ratio vs kernel | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Smoke, 7 runs | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `58.5 ms` | `56.2 ms` | `6.5 ms` | `1.041x` old/new | candidate `8.68x` slower than kernel | Routing-only smoke win |
| Smoke, 7 runs | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `43.3 ms` | `39.3 ms` | `12.4 ms` | `1.102x` old/new | candidate `3.18x` slower than kernel | Routing-only smoke win |
| Acceptance, 25 runs | `ffs-cli read --discard /compressible.bin` vs kernel `cat` | `56.7 ms` | `58.6 ms` | `6.9 ms` | `0.968x` old/new | candidate `8.53x` slower than kernel | Reject: regression |
| Acceptance, 25 runs | `ffs-cli walk --read-data --no-stat` vs kernel `cat *` | `36.3 ms` | `35.0 ms` | `12.6 ms` | `1.037x` old/new | candidate `2.77x` slower than kernel | Reject: neutral/no-ship |

### Kernel Reference Coverage

This row used a mounted read-only btrfs image as the direct kernel reference.
The candidate never beats kernel btrfs on either accepted row. The remaining
gap is not allocator scratch-buffer churn; the next attack should move deeper
into decode-output placement, logical-to-physical extent lookup fan-out, or a
structural I/O backend change that can reduce userspace copy/syscall overhead
without violating the repository's no-unsafe policy.

### Commands

```bash
hyperfine --warmup 3 --runs 25 \
  '/data/projects/.rch-targets/frankenfs-cod-b-baseline/release-perf/ffs-cli read --discard /data/tmp/btrdiff2_1340519.img /compressible.bin' \
  '/data/projects/.rch-targets/frankenfs-cod-b-scratch/release-perf/ffs-cli read --discard /data/tmp/btrdiff2_1340519.img /compressible.bin' \
  'cat /data/tmp/btrdiff2mnt_1340519/compressible.bin > /dev/null'

hyperfine --warmup 3 --runs 25 \
  '/data/projects/.rch-targets/frankenfs-cod-b-baseline/release-perf/ffs-cli walk --read-data --no-stat /data/tmp/btrdiff2_1340519.img' \
  '/data/projects/.rch-targets/frankenfs-cod-b-scratch/release-perf/ffs-cli walk --read-data --no-stat /data/tmp/btrdiff2_1340519.img' \
  'sh -c "cat /data/tmp/btrdiff2mnt_1340519/* > /dev/null"'

AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --release -p ffs-cli

AGENT_NAME=cod-b CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-w3hol` cod-a Fresh Verification

Date: 2026-06-20
Agent: BlackThrush (`cod-a`)
Scope: fresh verification of the already-landed `ffs-fuse` per-file-handle
writeback batching lever for `bd-w3hol`
Commit under measurement: `5170de3e` (`perf(fuse): batch writeback commits`)
RCH workers: `hz1` benchmark/build, `vmi1152480` focused tests,
`vmi1153651` conformance
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

KEEP. The fresh cod-a same-worker run still shows the deferred flush path
beating per-write commit on the FUSE writeback-cache batching benchmark. The
win is smaller than the earlier `vmi1227854` row, but remains outside a
neutral/no-ship range for this targeted primitive.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this verification | 1 |
| RCH Criterion rows completed | 2 / 2 FUSE A/B rows plus 3 / 3 core request-scope rows |
| Same-worker evidence | Yes, `hz1` for each A/B group |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no valid kernel comparator isolates FrankenFS's per-FH `RequestScope` batching table |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Internal A/B win/loss/neutral | 1 / 0 / 0 |
| Direct kernel win/loss/neutral | 0 / 0 / 1 |
| Conformance/build guard | RCH `cargo build --release -p ffs-fuse` passed on `hz1`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `vmi1152480` (12/12); RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1153651` (100 passed / 0 failed / 2 ignored). |
| Release-readiness score for perf-superiority claims | 67 / 100: fresh same-worker keep on the writeback amortization primitive and conformance green, but still no direct mounted ext4/btrfs-kernel write+fsync ratio. |
| Release-readiness score for this row's hygiene | 95 / 100: fresh bench, focused behavior tests, release build, conformance gate, and canonical negative-evidence row are recorded; remaining risk is only the absent direct mounted kernel comparator. |

### Measured Rows

| Bead | Workload | Old | New | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-w3hol` | `mount_runtime_writeback/per_write_commit_32x32k` vs `deferred_flush_32x32k`, 32 x 32 KiB writes plus flush | `75.412 us` median | `64.716 us` median | `1.165x` old/new; production latency `0.858x` | Keep: `14.2%` lower latency on the isolated commit-amortization primitive |
| `bd-xmh5g.401` | `mvcc_commit_batching_2000`, core per-write vs request-scope batched commit | `8.7549 ms` median | `6.7427 ms` median | `1.299x` per-write/request-scope; request-scope is `1.7%` slower than raw batched (`6.6308 ms`) | Keep as enabling primitive, not a direct kernel claim |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever changes
FrankenFS's in-process FUSE dispatch strategy: multiple write requests against
one file handle share a deferred `RequestScope` until a durability boundary.
Linux ext4/btrfs do not expose an equivalent timed primitive. A mounted
write+fsync benchmark is still required for whole-filesystem superiority
claims.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release-perf -p ffs-fuse \
  --bench mount_runtime -- mount_runtime_writeback

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release-perf -p ffs-core \
  --bench mvcc_commit_batching -- mvcc_commit_batching_2000

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --release -p ffs-fuse

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-fuse writeback_cache -- --nocapture

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-w3hol` Addendum

Date: 2026-06-20
Agent: BlackThrush (`cod-b`)
Scope: `ffs-fuse` per-file-handle writeback batching for `bd-w3hol`
Commit under measurement: this commit
RCH workers: `vmi1227854` bench, `vmi1153651` release build, `ovh-a` focused tests, `hz1` clippy, `hz2` broad harness/conformance probe
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

KEEP. The production FUSE write path now keeps one deferred write
`RequestScope` per `(ino, fh)` while writeback-cache writes are buffered by the
kernel, then commits that scope on `flush`, `fsync`, `release`, or `destroy`.
Synchronous and NOWAIT writes explicitly drain or bypass the deferred scope, so
the optimization only amortizes commit overhead where the FUSE writeback-cache
contract permits delayed visibility to stable storage.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 2 / 2 |
| Same-worker evidence | Yes, `vmi1227854` for both A/B rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator isolates FrankenFS's per-FH `RequestScope` batching table |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Internal A/B win/loss/neutral | 1 / 0 / 0 |
| Direct kernel win/loss/neutral | 0 / 0 / 1 |
| Conformance/build guard | RCH `cargo build --release -p ffs-fuse` passed on `vmi1153651`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `ovh-a` (12/12); RCH `cargo clippy -p ffs-fuse --all-targets --no-deps -- -D warnings` passed on `hz1`; RCH `cargo test -p ffs-harness -- --nocapture` on `hz2` cleared lib `2056/2056`, `tests/btrfs_kernel_reference.rs` `7/7`, and `tests/conformance.rs` `100 passed / 0 failed / 2 ignored` before unrelated mounted `fuse_e2e` failures; RCH focused post-patch `cargo test -p ffs-harness --test fuse_e2e ext4_fuse_inline_data_reads -- --nocapture` passed on `ovh-a` (2/2). |
| Format/lint guard | `cargo fmt -p ffs-fuse --check`, `cargo fmt -p ffs-harness --check`, and `git diff --check` passed; focused local `cargo clippy -p ffs-harness --test conformance --test fuse_e2e --no-deps -- -D warnings` passed. Full workspace `cargo fmt --check` remains blocked by pre-existing unrelated formatting drift. |
| Release-readiness score for perf-superiority claims | 65 / 100: real same-worker keep on the writeback amortization primitive, but no direct kernel ratio yet and broad mounted `fuse_e2e` still has unrelated red rows. |
| Release-readiness score for this row's hygiene | 90 / 100: measured keep, focused behavior tests, conformance green, stale mounted-suite failures documented; remaining work is a direct mounted write+fsync kernel comparator after unrelated `fuse_e2e` debt is isolated. |

### Measured Rows

| Bead | Workload | Old per-write commit | New deferred flush | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-w3hol` | `mount_runtime_writeback/per_write_commit_32x32k` vs `deferred_flush_32x32k`, 32 x 32 KiB writes plus flush | `43.353 us` median | `30.213 us` median | `1.435x` old/new; production latency `0.697x` | Keep: `30.3%` lower latency on the isolated commit-amortization primitive |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever changes
FrankenFS's in-process FUSE dispatch strategy: multiple write requests against
one file handle share a deferred `RequestScope` until a durability boundary.
Linux ext4/btrfs do not expose an equivalent timed primitive. A mounted kernel
write+fsync benchmark is still required for a whole-filesystem superiority
claim because it includes syscall, VFS, page-cache, FUSE transport, allocator,
journal, and block-layer behavior.

### Residual Mounted-Suite Risk

A stale RCH full-harness run on `hz2` started before the final
`fuse_e2e` fixture patch and was interrupted after printing unrelated mounted
`fuse_e2e` failures: btrfs cross-parent directory nlink accounting,
security-xattr privilege enforcement, btrfs `RENAME_EXCHANGE`, and a read-only
ext4 ioctl fast-fail assertion. The duplicated inline-data fixture issue from
that run was fixed in both `conformance.rs` and `fuse_e2e.rs`; the focused
post-patch RCH inline-data mounted check passed on `ovh-a`.

### Commands

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-fuse \
  --bench mount_runtime -- mount_runtime_writeback --sample-size 10

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-fuse writeback_cache -- --nocapture

AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test fuse_e2e \
  ext4_fuse_inline_data_reads -- --nocapture
```

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-journal` code-first backlog rows `bd-xmh5g.406` and `bd-xmh5g.404`
Commit under measurement: `01872c46`
RCH worker: `ovh-a`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH: `.rch-target-ovh-a-pool-2beeb9204616d289df744a9cc897c5df`

## Verdict

This cluster is release-ready only as a measured rejection. Both production
optimizations were benchmarked with same-worker Criterion runs and reverted
because the realistic rows lost. The A/B benchmark rows remain as guards so the
same levers are not rediscovered and retried without new evidence.

## Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined | 2 |
| RCH Criterion rows completed | 2 / 2 |
| Same-worker evidence | Yes, `ovh-a` for both runs |
| Direct ext4/btrfs-kernel ratios | 0 / 2 direct; no kernel comparator exists for these internal JBD2/Rust materialization microprimitives |
| Production levers kept | 0 |
| Production levers rejected/reverted | 2 |
| Conformance/build guard after revert | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-journal` passed |
| Release-readiness score for perf-superiority claims | 35 / 100: honest local evidence, but no direct kernel ratio for these primitives and both tested levers lost on realistic rows |
| Release-readiness score for this cluster's hygiene | 95 / 100: measurements recorded, dead ends ledgered, production paths reverted, crate check passed |

## Measured Rows

| Bead | Workload | Old | New | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.406` | Commit checksum, 1024 B block | `220.86 ns` | `158.52 ns` | `1.393x` old/new | Win, but not the normal block size |
| `bd-xmh5g.406` | Commit checksum, 4096 B block | `595.89 ns` | `742.02 ns` | `0.803x` old/new | Reject: segmented path is `24.5%` slower |
| `bd-xmh5g.406` | Commit checksum, 16384 B block | `2.8403 us` | `2.2867 us` | `1.242x` old/new | Win, but outweighed by the 4 KiB row |
| `bd-xmh5g.404` | Replay materialize, 16 blocks | `3.9888 us` | `4.2087 us` | `0.948x` old/new | Reject: `into_inner` is `5.5%` slower |
| `bd-xmh5g.404` | Replay materialize, 64 blocks | `21.282 us` | `22.110 us` | `0.963x` old/new | Reject: `3.9%` slower |
| `bd-xmh5g.404` | Replay materialize, 256 blocks | `71.482 us` | `77.324 us` | `0.924x` old/new | Reject: `8.2%` slower |

## Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator was available for these two internals:

- `bd-xmh5g.406` changes the Rust implementation strategy for verifying a JBD2
  commit-block checksum. The repository has kernel conformance tests for
  on-disk behavior, but no timed kernel JBD2 checksum microharness.
- `bd-xmh5g.404` changes a Rust `BlockBuf` materialization detail after journal
  block reads. There is no kernel-equivalent primitive to time.

The existing broad mount reference artifact
`benchmarks/baselines/history/20260503-bd-rchk5-3-mount-sudo-comparison.json`
is non-isolating for these commits and remains worse than the 2026-02-18
reference: cold-mount p99 `171096 us` vs `36029 us` (`4.75x` slower),
warm-mount p99 `300114 us` vs `58275 us` (`5.15x` slower), and recovery p99
`74217 us` vs `35020 us` (`2.12x` slower). Those rows must not be used as
evidence for or against either micro-optimization.

## Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-journal \
  --bench journal_replay_apply_io_overlap -- \
  journal_commit_checksum_zero_field_clone_vs_segmented

RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-journal \
  --bench journal_replay_apply_io_overlap -- \
  journal_replay_blockbuf_materialize

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  cargo check -p ffs-journal
```

## `bd-xmh5g.403` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-mvcc` code-first backlog row `bd-xmh5g.403`
Commit under measurement: `1cd8de6f`
RCH worker: `vmi1227854`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH:
`.rch-target-vmi1227854-pool-cbd309d7d1ec6129ad21bdb51108009f`

### Verdict

This row is release-ready only as a measured rejection. The fused SSI write-key
log construction lost every tested write-count row against the old prebuilt
`BTreeSet` path, so the production optimization was reverted. The Criterion A/B
rows remain in `wal_throughput` as negative-evidence guards.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 |
| Same-worker evidence | Yes, `vmi1227854` for all rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator exists for this internal SSI `CommittedTxnRecord.write_set` construction primitive |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/build guard after revert | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-mvcc --bench wal_throughput` passed on `vmi1227854`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-mvcc ssi -- --nocapture` passed on `hz2` with 70 filtered SSI lib tests, 1 evidence integration test, and 2 stress tests passing |
| Format guard | `cargo fmt -p ffs-mvcc --check` failed on existing formatting drift in unrelated `ffs-mvcc` benches/tests and distant test blocks; the `.403` revert hunk was not listed in the rustfmt diff and this commit does not broaden into a format cleanup |
| Release-readiness score for perf-superiority claims | 20 / 100: decisive negative Rust-internal evidence, no valid kernel comparator, no keep claim |
| Release-readiness score for this row's hygiene | 90 / 100: same-worker A/B completed, ratios ledgered, production reverted, retry predicate written, focused post-revert gates passed; package fmt drift remains pre-existing follow-up work |

### Measured Rows

| Bead | Workload | Old prebuild | New fused | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.403` | SSI write-key log, 64 writes | `437.77 ns` | `790.80 ns` | `0.554x` old/new | Reject: fused is `80.6%` slower |
| `bd-xmh5g.403` | SSI write-key log, 256 writes | `1.8957 us` | `4.1605 us` | `0.456x` old/new | Reject: fused is `119.5%` slower |
| `bd-xmh5g.403` | SSI write-key log, 1024 writes | `8.0965 us` | `24.173 us` | `0.335x` old/new | Reject: fused is `198.6%` slower |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes how FrankenFS constructs the in-memory SSI `CommittedTxnRecord.write_set`
for `commit_ssi_internal`; ext4/btrfs-kernel does not expose an equivalent
timed primitive. A whole-filesystem kernel write benchmark would include syscall,
VFS, journal, allocator, and page-cache behavior, and would still not isolate
this lever because FrankenFS's current write path uses plain `commit`, not
`commit_ssi`.

### Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-mvcc \
  --bench wal_throughput -- \
  mvcc_commit_ssi_writekey_log_ab

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-mvcc --bench wal_throughput

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-mvcc ssi -- --nocapture

cargo fmt -p ffs-mvcc --check
```

## `bd-xmh5g.400` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-btrfs` code-first backlog row `bd-xmh5g.400`
Commit under measurement: `e55bb16e`
RCH Criterion worker: `ovh-a`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH:
`.rch-target-ovh-a-pool-42ea7743fa151ef0fd4b694270dc5239`

### Verdict

This row is release-ready only as a measured rejection. Moving the owned
`BtrfsCowNode` child vector into the production `DagNode` was slower than the
old double-clone construction on the existing realistic btrfs writeback DAG
benchmark, so the production lever was reverted. The same A/B benchmark remains
as a guard against rediscovering the moved-child shape.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 |
| Same-worker evidence | Yes, `ovh-a` for all benchmark rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator exists for this Rust-internal `WriteDependencyDag` child-vector materialization primitive |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/build guard after revert | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` passed on `hz1`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` passed on `hz2` with 37 passed / 0 failed; local `cargo fmt -p ffs-btrfs --check` passed |
| Release-readiness score for perf-superiority claims | 20 / 100: decisive negative Rust-internal evidence, no valid kernel comparator, no keep claim |
| Release-readiness score for this row's hygiene | 95 / 100: same-worker A/B completed, ratios ledgered, production reverted, retry predicate written, focused post-revert gates and formatting passed |

### Measured Rows

| Bead | Workload | Old double-clone | New moved-child | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.400` | DAG build, old double-clone model vs single-clone model | `89.928 us` | `112.58 us` | `0.799x` old/new | Reject: single-clone model is `25.2%` slower |
| `bd-xmh5g.400` | DAG build, old double-clone model vs production moved-child path | `89.928 us` | `110.91 us` | `0.811x` old/new | Reject: production moved-child path is `23.3%` slower |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes how FrankenFS builds an in-memory btrfs metadata writeback DAG from the
safe Rust `InMemoryCowBtrfsTree` snapshot. Linux btrfs does not expose an
equivalent timed primitive, and a whole-filesystem btrfs writeback benchmark
would include VFS, page-cache, allocator, checksum, and device latency without
isolating `WriteDependencyDag::collect_nodes`.

The prior broad vs-kernel attempt on this branch captured a kernel ext4 read
baseline but could not FUSE-mount FrankenFS in the execution environment. That
artifact is useful as environment context only; it is not evidence for this
in-memory btrfs DAG construction lever.

### Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-btrfs \
  --bench writeback_dag_order -- \
  writeback_dag_build_child_vector_ab

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture

cargo fmt -p ffs-btrfs --check
```

## `bd-r9c10` Addendum

Date: 2026-06-20
Agent: BlackThrush (`cod-b`)
Scope: `ffs-core` ext4 indirect read gap and `ext4_indirect_read_overlap`
Production status: incumbent serial-plan / parallel-owned-buffer / serial-assemble path restored
RCH baseline worker: `vmi1149989`
RCH candidate worker: `vmi1167313` (RCH did not honor requested worker pin)
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

This row is release-ready only as a measured rejection of the direct-output
copy-elision follow-up. The incumbent `read_ext4_indirect` parallel read path
already wins strongly against the serial synthetic oracle, but removing
per-segment owned buffers and filling disjoint output windows directly regressed
the 64-run row and was neutral at 256 runs. Production code was reverted; the
benchmark A/B arm remains as a negative-evidence guard.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 2 / 2 |
| Same-worker evidence | Partial: baseline on `vmi1149989`; candidate same-binary A/B on `vmi1167313` because RCH selected a different worker despite `RCH_WORKER`/`RCH_WORKERS` |
| Direct ext4/btrfs-kernel ratios | 0 / 1 new direct; prior direct ext4 indirect gap remains `211-224 ms` FrankenFS vs `45 ms` kernel (`~4.7-5.0x` slower) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/behavior guard after revert | `ext4_indirect_read_overlap` asserts serial, incumbent parallel, and in-place candidate byte equality before measuring; both RCH bench runs passed. RCH `cargo check -p ffs-core --bench ext4_indirect_read_overlap` passed on `vmi1152480`; RCH-wrapper local fallback `cargo test -p ffs-core read_ext4_indirect -- --nocapture` passed 1 focused test; RCH-wrapper local fallback `cargo test -p ffs-harness --test conformance -- --nocapture` passed 100 / 0 / 2 ignored |
| Release-readiness score for perf-superiority claims | 20 / 100: honest negative evidence against one candidate; the direct ext4-kernel indirect-read gap remains open |
| Release-readiness score for this row's hygiene | 88 / 100: baseline measured, candidate measured, production reverted, ratios ledgered, focused behavior/conformance green; worker pinning drift, RCH local fallback for tests, and pre-existing `ffs-core` clippy/rustfmt drift prevent a cleaner score |

### Measured Rows

| Bead | Workload | Incumbent | Candidate | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-r9c10` | 16 non-contiguous runs, same-binary A/B on `vmi1167313` | `2.7308 ms` | `2.5461 ms` | `1.073x` incumbent/candidate | Small win, below keep threshold alone |
| `bd-r9c10` | 64 non-contiguous runs, same-binary A/B on `vmi1167313` | `7.7753 ms` | `8.6526 ms` | `0.899x` incumbent/candidate | Reject: candidate is `11.3%` slower |
| `bd-r9c10` | 256 non-contiguous runs, same-binary A/B on `vmi1167313` | `25.508 ms` | `25.452 ms` | `1.002x` incumbent/candidate | Neutral |

Baseline incumbent-vs-serial evidence on `vmi1149989`:

| Workload | Serial | Incumbent parallel | Ratio |
| --- | --- | --- | --- |
| 16 non-contiguous runs | `5.7337 ms` | `970.27 us` | `5.91x` serial/incumbent |
| 64 non-contiguous runs | `23.414 ms` | `2.7872 ms` | `8.40x` serial/incumbent |
| 256 non-contiguous runs | `92.482 ms` | `13.491 ms` | `6.85x` serial/incumbent |

### Kernel Reference Coverage

The direct kernel comparator for this surface remains the existing 32 MiB ext4
`^extent` image probe, where FrankenFS indirect reads measured `211-224 ms`
against kernel ext4 `45 ms`. Today's RCH benchmark is an isolated Rust A/B for
one proposed internal lever against that gap. It does not create a new direct
kernel win and should not be reported as whole-filesystem domination.

### Commands

```bash
AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-core \
  --bench ext4_indirect_read_overlap -- \
  ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3

AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 RCH_WORKERS=vmi1149989 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-core \
  --bench ext4_indirect_read_overlap -- \
  ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3

AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-core --bench ext4_indirect_read_overlap

AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-core read_ext4_indirect -- --nocapture

AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-xmh5g` Addendum

Date: 2026-06-20
Agent: BlackThrush (`cod-b`)
Scope: `ffs-core` ext4 indirect near-contiguous large-run reads
Production status: kept; `read_ext4_indirect` now splits large coalesced runs into ordered chunks before the existing parallel owned-buffer read phase
RCH proof worker: `vmi1227854` for Criterion A/B
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

Keep the 128-block default. The internal 32 MiB large-run model improves from
`25.523 ms` single-run median to `15.729 ms` at 128-block chunks (`1.623x`
old/new). The 16-block candidate lost and the 32-block row was too small/noisy
to use as the default. Fresh mounted ext4-kernel comparison was attempted but
blocked by loop-device policy, so the prior direct ext4-kernel loss remains the
release-readiness limiter.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 7 / 7 large-run rows |
| Same-worker evidence | Yes: chunk-size sweep on `vmi1227854` |
| Direct ext4/btrfs-kernel ratios | Existing direct loss remains `211-224 ms` FrankenFS vs `45 ms` kernel (`~4.7-5.0x` slower); fresh rerun blocked by loop-device setup failure |
| Production levers kept | 1 (`read_ext4_indirect` large-run chunking, default `128` blocks) |
| Production levers rejected/reverted | 1 rejected setting family (`16` blocks); `32` blocks treated neutral/noisy |
| Internal win/loss/neutral | `4/1/1` |
| Direct kernel win/loss/neutral | `0/1/0` existing direct loss; fresh run blocked |
| Conformance/behavior guard | RCH focused test `ext4_indirect_large_run_chunks_default_bd_xmh5g` passed on `vmi1167313`; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1152480`; RCH-wrapper local fallback `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored`; `git diff --check` passed. |
| Release-readiness score for perf-superiority claims | 45 / 100: real same-worker keep for the targeted internal gap, but no fresh mounted kernel ratio and the old direct ext4-kernel loss is still open |
| Release-readiness score for this row's hygiene | 90 / 100: same-worker sweep, focused behavior proof, check, conformance, and ledgers are recorded; remaining gaps are loop-device policy and unrelated pre-existing clippy/rustfmt debt |

### Measured Rows

| Workload | Single-run | Candidate | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `large_run_chunked_16blocks/8192` | `25.523 ms` | `31.397 ms` | `0.813x` old/new | Reject |
| `large_run_chunked_32blocks/8192` | `25.523 ms` | `23.067 ms` | `1.106x` old/new | Neutral/noisy |
| `large_run_chunked_64blocks/8192` | `25.523 ms` | `17.267 ms` | `1.478x` old/new | Win |
| `large_run_chunked_128blocks/8192` | `25.523 ms` | `15.729 ms` | `1.623x` old/new | KEEP |
| `large_run_chunked_256blocks/8192` | `25.523 ms` | `16.591 ms` | `1.539x` old/new | Win |
| `large_run_chunked_512blocks/8192` | `25.523 ms` | `17.475 ms` | `1.461x` old/new | Win |

### Kernel Reference Coverage

The direct comparator built `ffs-cli` release-perf, generated a 32 MiB ext4
`^extents` file, and `debugfs stat` confirmed indirect/double-indirect block
mappings. The worker then failed `mount -o loop,ro` with `failed to setup loop
device` (`/tmp/ffs_indirect_cmp.0g2lsq`). This addendum must not be reported as
whole-filesystem ext4 domination until that mounted comparator reruns.

### Commands

```bash
AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-core \
  --bench ext4_indirect_read_overlap -- \
  ext4_indirect_read_overlap/large_run --warm-up-time 1 \
  --measurement-time 1 --sample-size 20

AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-core \
  ext4_indirect_large_run_chunks_default_bd_xmh5g -- --nocapture

AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-core --all-targets

AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture
```

## `bd-xmh5g.389` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-a`)
Scope: `ffs-inode` code-first backlog row `bd-xmh5g.389`
Base commit under closeout: `f064ef29`
RCH Criterion worker: `vmi1227854`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`
Remote target dir used by RCH:
`.rch-target-vmi1227854-pool-cbd309d7d1ec6129ad21bdb51108009f`

### Verdict

This row is release-ready only as a measured rejection. `BlockBuf::into_inner()`
showed a small 4 KiB win but regressed the wider 16 KiB and 64 KiB rows that the
same owned-buffer materialization primitive claims to cover. The three
production `ffs-inode` RMW sites are back on `as_slice().to_vec()`; the
Criterion A/B benchmark remains as a guard.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 |
| Same-worker evidence | Yes, `vmi1227854` for all benchmark rows |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no kernel comparator exists for this Rust-internal owned-buffer materialization primitive |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Conformance/build guard after revert | `cargo fmt -p ffs-inode --check` passed locally; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo check -p ffs-inode --all-targets` passed on `hz1`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo test -p ffs-inode --lib -- --nocapture` passed on `ovh-a` with 129 passed / 0 failed; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings` passed on `hz2`; focused post-clippy test `inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes` passed on `ovh-a` |
| Known adjacent gate limitation | Full dependency-lint clippy without `--no-deps` is blocked by an unrelated existing `ffs-extent` `clippy::significant_drop_tightening` lint at `crates/ffs-extent/src/lib.rs:1487`; this addendum does not take ownership of that crate |
| Release-readiness score for perf-superiority claims | 20 / 100: decisive negative Rust-internal evidence, no valid kernel comparator, no keep claim |
| Release-readiness score for this row's hygiene | 95 / 100: same-worker A/B completed, ratios ledgered, production reverted, retry predicate written, focused post-revert gates and formatting passed |

### Measured Rows

| Bead | Workload | Old copy | New move | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-xmh5g.389` | Owned `BlockBuf` materialization, 4096 B | `576.96 ns` | `534.36 ns` | `1.080x` old/new | Small 4 KiB win, not enough to carry the wider rows |
| `bd-xmh5g.389` | Owned `BlockBuf` materialization, 16384 B | `1.3722 us` | `1.5633 us` | `0.878x` old/new | Reject: move is `13.9%` slower |
| `bd-xmh5g.389` | Owned `BlockBuf` materialization, 65536 B | `3.7725 us` | `4.2885 us` | `0.880x` old/new | Reject: move is `13.7%` slower |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes how FrankenFS materializes an owned Rust `BlockBuf` into a mutable `Vec`
inside three inode read-modify-write helpers. Linux ext4/btrfs does not expose
an equivalent timed primitive, and a whole-filesystem inode update benchmark
would include syscall, VFS, journal, allocator, page-cache, and block-layer
latency without isolating the `into_inner()` vs `to_vec()` choice.

### Commands

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release-perf -p ffs-mvcc \
  --bench blockbuf_into_inner -- \
  blockbuf_into_inner_vs_to_vec

cargo fmt -p ffs-inode --check

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo check -p ffs-inode --all-targets

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-inode --lib -- --nocapture

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings

RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo test -p ffs-inode --lib \
  inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes -- --nocapture
```

## `bd-f759f` Addendum

Date: 2026-06-19
Agent: BlackThrush (`cod-b`)
Scope: `ffs-btrfs` code-first backlog row `bd-f759f`
Code-first implementation commit: `c7b28426`
Commit under measurement: `44e41db2`
RCH Criterion worker: `ovh-a`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`
Remote target dir used by RCH:
`.rch-target-ovh-a-pool-42ea7743fa151ef0fd4b694270dc5239`

### Verdict

This row is release-ready as a measured Rust-internal keep. The production
capacity-sized `HashSet` visited set is materially faster than the old
`BTreeSet` visited membership model on the existing btrfs metadata writeback DAG
scheduler benchmark, while the old-model oracle and WB-I1 prefix checks preserve
the deterministic flush-order contract. No revert was applied.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 1 / 1 |
| Same-worker evidence | Yes, `ovh-a` for both A/B arms in one Criterion run |
| Direct ext4/btrfs-kernel ratios | 0 / 1 direct; no valid kernel comparator exists for this Rust-internal `WriteDependencyDag` visited-set membership primitive |
| Production levers kept | 1 |
| Production levers rejected/reverted | 0 |
| Conformance/build guard after keep | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` passed on `hz1`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` passed on `hz2` with 37 passed / 0 failed; local `cargo fmt -p ffs-btrfs --check` passed |
| Release-readiness score for perf-superiority claims | 60 / 100: decisive same-worker Rust-internal keep, exact old-model order guard, but no valid direct ext4/btrfs-kernel comparator for the primitive |
| Release-readiness score for this row's hygiene | 98 / 100: A/B benchmark completed, ratio ledgered, conformance/check/fmt passed, production kept without broadening the change |

### Measured Rows

| Bead | Workload | Old `BTreeSet` | New `HashSet` | Ratio | Verdict |
| --- | --- | --- | --- | --- | --- |
| `bd-f759f` | Reverse-topological writeback DAG scheduling | `18.969 us` | `13.220 us` | `1.435x` old/new; `0.697x` new/old latency | Keep: production `HashSet` is `30.3%` lower latency |

### Kernel Reference Coverage

No direct ext4/btrfs-kernel comparator is valid for this row. The lever only
changes the in-memory membership set used by FrankenFS
`WriteDependencyDag::reverse_topological_order`; Linux btrfs does not expose an
equivalent timed primitive. A whole-filesystem btrfs writeback benchmark would
include VFS, page-cache, allocator, checksum, journal, and device latency, and
would not isolate the visited-set membership choice.

The prior broad vs-kernel mount/read artifacts remain environment context only
for this row. They are not evidence for or against this isolated scheduler
membership lever.

### Commands

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench --profile release-perf -p ffs-btrfs \
  --bench writeback_dag_order -- \
  writeback_dag_order_hashset_ab

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture

cargo fmt -p ffs-btrfs --check
```

---

## WIN — parallel-read chunk default 256 -> 32 blocks on real many-core hw (cc 2026-06-19, bd-vffrx / 3671522c)

The `FFS_READ_CHUNK_BLOCKS` default splits a large contiguous run into block-aligned chunks read concurrently
on the rayon pool. c110c39b cut it 16 MiB -> 1 MiB (256 blocks) after the 4096 default was found tuned for a
~2-core box; the same under-fill bug survived one level down. On a real **64-core** box (rayon pool ~62
threads), 256 blocks yields only ~32 chunks for a 32 MiB read — about half the pool — leaving most of the
I/O-overlap on the table. Dropped the default to **32 blocks = 128 KiB** at BOTH parallel-read sites (ext4
`read_file_data`, btrfs `btrfs_read_file`).

Measured (engine `duration_us`, A/B via `FFS_READ_CHUNK_BLOCKS` on one fresh release binary, min of N,
default-32 vs forced-256):

| Workload | warm 32 vs 256 | cold 32 vs 256 |
|---|---|---|
| ext4 128 MiB extent read   | **1.41x** (32.9 -> 23.3 ms) | **1.31x** (53.9 -> 41.2 ms) |
| btrfs 100 MiB uncompressed  | **3.17x** (106 -> 33.5 ms)  | **1.69x** (117 -> 69.1 ms)  |

Byte-identical output (md5 of a 128 MiB ext4 read matches the source for chunk 1/32/256/4096). ffs-core
release tests green. Output is invariant in chunk size — only parallel-read granularity changes; the env
override is preserved. Narrows the warm-seq kernel gap (ext4 warm ~2.4x -> read-only ~19.6ms vs kernel ~8ms).
Residual gap root-caused to `FileByteDevice` pread-per-chunk syscall + page-cache copy (perf: sys 0.277s >>
user 0.108s, IPC 0.35) — see bd-jgbam (mmap-backed ByteDevice deep swing). Adaptive (core-count-scaled) chunk
sizing evaluated and rejected as overfit — see perf-negative-results.md.

cod-b 2026-06-20 `bd-27x9a` verification on a real btrfs image with one 100 MiB uncompressed extent
(`/data/tmp/btrperf_1231197.img:/m.bin`) keeps the direction but not the domination claim. Local hyperfine,
warm/shared-cache, release-perf CLI: kernel btrfs `dd` mean `48.7 ms`; current ffs default-32 mean `76.3 ms`;
forced old 256-block chunk mean `91.1 ms`. So current ffs is still `1.57x` slower than kernel on this comparator,
while remaining `1.19x` faster than forced old chunking. RCH primitive proof is stronger but Rust-internal:
`btrfs_uncompressed_read_overlap_16extents` on `ovh-a` measured serial `5.0966 ms` vs parallel `405.27 us`
median (`12.58x`) with byte-identical output asserted by the bench. A follow-up direct-overwrite `FileByteDevice`
fast path was measured and reverted (`76.3 -> 75.7 ms`, `0.8%`, inside noise; forced 256 flipped faster under the
same noisy run). Release-readiness verdict: chunking is a real keep versus the old setting, but btrfs-kernel
domination remains open and should route to file-device/syscall/copy work, not more chunk retuning.

---

## REJECT — btrfs read scratch/direct-into-dst candidates did not transfer (cod-b 2026-06-20, bd-2emlm)

Commit under measurement: uncommitted candidate, reverted before commit
RCH build/bench worker: `hz1` for `ffs-block` Criterion and `ffs-cli` release build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

This row is release-ready as negative evidence, not a production keep. The `FileByteDevice` reusable scratch
primitive won dramatically in isolation, but the combined real-read candidate stayed neutral versus the prior
FrankenFS btrfs timing and still lost to kernel streaming. Source candidates were reverted.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 1 / 1 |
| Same-worker primitive evidence | Yes, `hz1` for both A/B arms in one Criterion run |
| Direct ext4/btrfs-kernel ratios | `1/2/0`: candidate beat kernel btrfs `dd bs=128M` (`74.949 ms` vs `127.923 ms`, `1.71x` faster), lost to kernel `dd bs=8M` (`77.580 ms` vs `51.407 ms`, `1.51x` slower), and lost to kernel `cat` (`77.580 ms` vs `11.710 ms`, `6.63x` slower) |
| Internal win/loss/neutral | `1/0/1`: `FileByteDevice` scratch A/B was `11.15x` faster in the primitive; whole btrfs read was neutral versus prior `76.3 ms` FrankenFS context (`74.949 ms` / `77.580 ms`) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 2 (`FileByteDevice` reusable staging scratch; btrfs `read_into` direct-to-dst candidate) |
| Conformance/build guard after revert | RCH `cargo check -p ffs-block --all-targets` passed on `hz1`; RCH `cargo test -p ffs-block file_byte_device -- --nocapture` passed on `vmi1149989`; RCH `cargo clippy -p ffs-block --all-targets -- -D warnings` passed on `vmi1152480`; RCH `cargo build --release -p ffs-cli` passed on `hz1`; RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1152480` (100 passed / 0 failed / 2 ignored); source reverted to no production code delta |
| Release-readiness score for perf-superiority claims | 45 / 100: useful real-image evidence and fresh kernel comparators, but no shippable speedup and kernel streaming still dominates |
| Release-readiness score for this row's hygiene | 93 / 100: measured before rejecting, logged win/loss/neutral ratios, reverted no-gain source, and left retry predicate; whole-workspace fmt remains blocked by unrelated pre-existing `ffs-core` formatting dirt |

### Measured Rows

| Workload | Candidate | Comparator | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| `file_byte_device_read_1mib` primitive | `96.908 us` reusable scratch | `1.0804 ms` fresh-temp shape | `11.15x` old/new | Reject at production surface; primitive win did not transfer |
| btrfs `/m.bin` real read | `74.949 ms` candidate | prior FrankenFS default-32 `76.3 ms` | `1.02x` | Neutral |
| btrfs `/m.bin` real read, streaming run | `77.580 ms` candidate | prior FrankenFS default-32 `76.3 ms` | `0.98x` | Neutral |
| btrfs `/m.bin` vs kernel materialising read | `74.949 ms` candidate | kernel `dd bs=128M` `127.923 ms` | `1.71x` FrankenFS faster | Win |
| btrfs `/m.bin` vs kernel buffered read | `77.580 ms` candidate | kernel `dd bs=8M` `51.407 ms` | `1.51x` FrankenFS slower | Loss |
| btrfs `/m.bin` vs kernel page-cache streaming | `77.580 ms` candidate | kernel `cat` `11.710 ms` | `6.63x` FrankenFS slower | Loss |

### Retry Predicate

Do not retry reusable staging scratch or btrfs direct-to-dst as blind standalone levers. The next credible
`bd-2emlm` pass needs heap allocation attribution for the btrfs read pipeline and must prove RSS drops below the
current ~133-138 MiB profile before measuring throughput again.

---

## KEEP — sharded MVCC chain-head Cow move verification (cod-b 2026-06-20, bd-xmh5g.395)

Commit under verification: `8d610785` (`make_chain_head_full` moves the resolved `Cow` with
`into_owned`) plus invariant guard `6fed9db6`.
RCH bench worker: `vmi1152480`
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

Keep the existing production change. The sharded compaction path now matches the single-store
`make_chain_head_full` implementation and avoids cloning an already-owned decompressed buffer. The fresh
same-worker Cow-owned A/B shows this is decisively positive for the primitive that the compaction path uses.

This is not a whole-filesystem ext4/btrfs-kernel domination row. The direct kernel ratio is N/A because the
operation is internal MVCC version materialization; the parent direct ext4 indirect-read loss remains open until
the mounted comparator can rerun.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 3 / 3 Cow-owned A/B sizes |
| Same-worker evidence | Yes: `to_vec_clone` and `into_owned_move` measured in one Criterion run on `vmi1152480` |
| Direct ext4/btrfs-kernel ratios | N/A for this internal MVCC primitive; parent direct ext4 indirect-read loss remains `~4.7-5.0x` slower than kernel from prior mounted evidence |
| Internal win/loss/neutral | `3/0/0` |
| Direct kernel win/loss/neutral | `0/0/1` |
| Production levers kept | 1 already-retained lever (`resolve_data_with(...).into_owned()` in sharded chain-head compaction) |
| Production levers rejected/reverted | 0 |
| Conformance/behavior guard | RCH focused test `prune_preserves_read_visible_data_after_chain_head_compaction` passed on `vmi1152480`; RCH `cargo check -p ffs-mvcc --all-targets` passed on `vmi1293453`; RCH `cargo clippy -p ffs-mvcc --all-targets --no-deps -- -D warnings` passed on `vmi1152480`; RCH harness conformance passed on `vmi1153651` (100 passed / 0 failed / 2 ignored); local `cargo fmt -p ffs-mvcc --check` passed. |
| Known gate caveat | Plain `cargo clippy -p ffs-mvcc --all-targets -- -D warnings` still enters path dependency linting and fails on pre-existing `ffs-repair/src/storage.rs` pedantic debt outside this MVCC closeout. |
| Release-readiness score for perf-superiority claims | 60 / 100: decisive same-worker internal keep with conformance green, but no direct kernel comparator applies and the parent direct read gap stays open |
| Release-readiness score for this row's hygiene | 95 / 100: measured A/B, invariant test, check, scoped clippy, fmt, conformance, and canonical ledger row are complete; residual risk is only the unrelated dependency clippy debt |

### Measured Rows

| Workload | Old clone path | Kept move path | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| `mvcc_read_block_cow_owned/to_vec_clone/4096` vs `into_owned_move/4096` | `214.82 ns` | `13.523 ns` | `15.89x` old/new | KEEP |
| `mvcc_read_block_cow_owned/to_vec_clone/16384` vs `into_owned_move/16384` | `1.0014 us` | `12.372 ns` | `80.94x` old/new | KEEP |
| `mvcc_read_block_cow_owned/to_vec_clone/65536` vs `into_owned_move/65536` | `5.9061 us` | `10.004 ns` | `590.37x` old/new | KEEP |

### Isomorphism

Ordering preserved: yes. `make_chain_head_full` rewrites only the retained chain head from `Identical` to
`Full`; version order and commit sequences are unchanged.

Tie-breaking unchanged: yes. Snapshot visibility uses the same retained `BlockVersion` and commit sequence.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Bytes verified: yes. The focused compaction test proves the retained snapshot still reads the same bytes after
the older full version is drained, and the A/B benchmark constructs byte-identical buffers for the old and kept
materialization paths.

### Retry Predicate

Do not reopen the `to_vec` materialization path for `Cow::Owned`. Future work should target an actual remaining
direct-kernel gap, such as mounted ext4/btrfs streaming read syscall/copy overhead, unless a new profile shows
compressed MVCC GC compaction itself dominating a realistic write+GC workload.

## KEEP — sharded MVCC conflict-merge Cow borrow verification (cod-b 2026-06-20, bd-xmh5g.402)

Commit under measurement: uncommitted cod-b candidate for sharded conflict-merge base/latest materialization.
RCH proof workers: `vmi1227854` for primary same-worker Criterion/check, `vmi1153651` for focused test and
targeted conformance, `hz1` for scoped clippy and secondary benchmark sanity.
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-b`

### Verdict

Keep the production change. The sharded SafeMerge conflict path used to materialize base/latest visible version
bytes as owned `Vec`s even though `merge_bytes` only reads them. The new helper preserves the existing owned
public read API while allowing conflict merge to borrow uncompressed `Full` version bytes through `Cow`; compressed
or identical-chain versions still allocate only when decompression or resolution requires ownership.

This is not a whole-filesystem ext4/btrfs-kernel domination row. The direct kernel ratio is N/A because the measured
surface is an internal MVCC merge materialization primitive, not a kernel-visible mounted read/write syscall path.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 6 / 6 (`3` primary same-worker acceptance rows, `3` secondary sanity rows) |
| Same-worker evidence | Yes: old clone and borrowed `Cow` arms measured in one Criterion run on `vmi1227854` |
| Direct ext4/btrfs-kernel ratios | N/A for this internal MVCC primitive; recorded as direct-kernel neutral (`0/0/1`) |
| Internal win/loss/neutral | `3/0/0` acceptance (`3/0/0` secondary sanity, not used as acceptance proof) |
| Direct kernel win/loss/neutral | `0/0/1` |
| Production levers kept | 1 (`resolve_version_bytes_cow_at_or_before` plus sharded conflict-merge borrow path) |
| Production levers rejected/reverted | 0 |
| Conformance/behavior guard | RCH `cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- conflict_merge_materialization_ab --warm-up-time 1 --measurement-time 3` passed on `vmi1227854`; RCH `cargo check -p ffs-mvcc --bench wal_throughput` passed on `vmi1227854`; RCH focused test `sharded::tests::fcw_append_only_merge_proof_allows_same_block_commit` passed on `vmi1153651`; RCH `cargo clippy -p ffs-mvcc --all-targets --no-deps -- -D warnings` passed on `hz1`; RCH conformance passed on `vmi1153651` (100 passed / 0 failed / 2 ignored); local `cargo fmt --check --package ffs-mvcc` passed. |
| Known gate caveat | RCH `cargo build --release -p ffs-mvcc` compiled successfully on `vmi1153651`, then artifact retrieval failed with `RCH-E309`/exit 102. Full `cargo test -p ffs-harness -- --nocapture` exposed unrelated mounted FUSE failures before interruption; the targeted conformance test passed cleanly. |
| Release-readiness score for perf-superiority claims | 55 / 100: decisive same-worker internal win and conformance green, but no direct kernel comparator applies and the parent mounted read gaps remain open |
| Release-readiness score for this row's hygiene | 91 / 100: measured A/B, focused invariant test, check, scoped clippy, fmt, targeted conformance, and canonical ledger row are complete; residual caveats are unrelated full-harness FUSE failures and the RCH artifact-retrieval failure after successful remote release build |

### Measured Rows

| Workload | Old clone path | Kept borrow path | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| `conflict_merge_materialization_ab/old_vec_clone_base_latest/4096` vs `cow_borrow_base_latest/4096` | `127.52 ns` | `4.4895 ns` | `28.40x` old/new | KEEP |
| `conflict_merge_materialization_ab/old_vec_clone_base_latest/16384` vs `cow_borrow_base_latest/16384` | `478.34 ns` | `4.3897 ns` | `108.97x` old/new | KEEP |
| `conflict_merge_materialization_ab/old_vec_clone_base_latest/65536` vs `cow_borrow_base_latest/65536` | `1.5497 us` | `4.4659 ns` | `347.0x` old/new | KEEP |
| secondary `hz1` sanity, 4 KiB | `159.77 ns` | `7.1521 ns` | `22.34x` old/new | Sanity only |
| secondary `hz1` sanity, 16 KiB | `692.12 ns` | `7.2868 ns` | `94.98x` old/new | Sanity only |
| secondary `hz1` sanity, 64 KiB | `2.8152 us` | `7.4608 ns` | `377.3x` old/new | Sanity only |

### Isomorphism

Ordering preserved: yes. The sharded path still selects the same newest visible version with the same
`newest_visible_index` helper.

Tie-breaking unchanged: yes. Commit sequence visibility and SafeMerge conflict resolution are unchanged; only
base/latest byte ownership changes.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Bytes verified: yes. The focused sharded SafeMerge test passed, public visible reads still return owned `Vec`s,
and the new borrow path passes the same byte slices to read-only `merge_bytes`. Compressed versions still use owned
decompressed bytes via `Cow::Owned`.

### Retry Predicate

Do not reopen clone-vs-borrow materialization for read-only conflict-merge inputs unless a future profile shows
compressed or identical-chain resolution dominates and needs a different specialization. Next `bd-xmh5g` work should
target a remaining direct kernel loss rather than another internal MVCC byte-ownership micro-lever.

## `bd-xmh5g` Addendum (cod-a btrfs zstd decoder reuse)

Date: 2026-06-20
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs zstd transparent decompression for compressed extents
Production status: kept; `btrfs_decompress` reuses one zstd decompressor context per worker thread
RCH proof workers: `vmi1167313` for bench/check/focused test, `ovh-a` for conformance, `vmi1227854` for release build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

Keep the thread-local zstd decoder reuse because the real mounted-image target
improved twice: single-file read improved `76.1 ms -> 54.9 ms` (`1.39x`) and
whole-tree walk improved `53.2 ms -> 32.8 ms` (`1.62x`). This is not kernel
domination: current kernel btrfs still wins by `8.51x` on the single-file
surface and `2.99x` on the walk surface.

The internal synthetic decompressor-context bench is negative evidence, not a
keep proof: fresh decompressor median `5.9330 ms` vs thread-reused median
`7.2849 ms` (`0.814x` old/new). The direct workload outweighed the synthetic
loss, but future zstd-context-only microbenches should not be treated as
decisive unless they match the mounted-image path.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| RCH Criterion rows completed | 2 / 2 tiny zstd rows after adding a targeted bench-filter guard |
| Direct ext4/btrfs-kernel ratios | Single-file candidate `54.9 ms` vs kernel `6.5 ms` (`8.51x` slower); walk candidate `32.8 ms` vs kernel `11.0 ms` (`2.99x` slower) |
| Production levers kept | 1 (`BTRFS_ZSTD_DECOMPRESSOR` thread-local decoder reuse) |
| Production levers rejected/reverted | 0 production; synthetic mechanism row is recorded as a loss |
| Internal win/loss/neutral | `0/1/0` |
| Direct kernel win/loss/neutral | `0/2/0` |
| Conformance/behavior guard | Local `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --all-targets` passed; RCH `cargo test -p ffs-core btrfs_decompress -- --nocapture` passed 10/10; RCH conformance passed 100/0/2 ignored; RCH `cargo build --release -p ffs-cli` passed. |
| Known gate caveat | RCH `cargo clippy -p ffs-core --all-targets --no-deps -- -D warnings` is blocked by pre-existing `ffs-core` pedantic debt in `vfs.rs`, old indirect-pointer casts, xattr const placement, and redundant closures outside this lever. |
| Release-readiness score for perf-superiority claims | 58 / 100: real direct-image improvement on the largest btrfs compressed-read gap, conformance green, but kernel still leads by `2.99-8.51x` |
| Release-readiness score for this row's hygiene | 88 / 100: direct baseline/candidate confirmation, RCH bench/check/test/build, conformance, and ledgers are complete; residual risk is the contradictory synthetic row and pre-existing clippy debt |

### Measured Rows

| Workload | Baseline | Candidate confirmation | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| FrankenFS `read --discard /compressible.bin` | `76.1 ms` | `54.9 ms` | `1.39x` old/new | KEEP |
| Kernel `cat /compressible.bin` vs candidate | `6.5 ms` kernel | `54.9 ms` FrankenFS | kernel `8.51x` faster | Direct loss remains |
| FrankenFS `walk --read-data --no-stat` | `53.2 ms` | `32.8 ms` | `1.62x` old/new | KEEP |
| Kernel `cat *` vs candidate walk | `11.0 ms` kernel | `32.8 ms` FrankenFS | kernel `2.99x` faster | Direct loss remains |
| RCH synthetic `fresh_decompressor_per_frame` vs `thread_reused_decompressor` | `5.9330 ms` | `7.2849 ms` | `0.814x` old/new | Synthetic loss |

### Isomorphism

Ordering preserved: yes. Each compressed extent still decodes independently,
then the existing read assembly copies slices in the same file-offset order.

Tie-breaking unchanged: yes. Extent lookup, checksum handling, and compression
type dispatch are unchanged.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Bytes verified: yes. The existing btrfs decompression tests passed, including
zstd short-frame zero-fill and oversized-frame rejection. Harness conformance
also passed `btrfs_transparent_decompression_zstd_regular_extent_conforms`.

### Retry Predicate

Do not retry dedicated pools, `with_min_len`, or zstd decoder-context-only
microbenches without a new direct-image signal. Next work should attack a
different remaining cost center: output-buffer reuse or decode-direct-to-final
buffer, btrfs metadata/extent lookup fan-out, or a larger multi-file compressed
kernel image that reproduces the remaining `2.99-8.51x` loss.

## `bd-xmh5g` Addendum (cod-a btrfs zstd direct-output rejection)

Date: 2026-06-20
Agent: BlackThrush (`cod-a`)
Scope: `ffs-core` btrfs zstd transparent decompression for full-overlap regular
compressed extents
Production status: rejected/reverted; no source retained
RCH proof workers: `vmi1152480` for candidate check/build, `vmi1153651` for
clean-source check, `vmi1227854` for clean-source conformance, `vmi1149989`
for clean-source release-perf build
Requested target dir: `/data/projects/.rch-targets/frankenfs-cod-a`

### Verdict

Reject. Direct-to-final zstd decode did not transfer into the mounted-image
read path. Single-file read worsened from `55.931 ms` to `57.961 ms`
(`0.965x` old/new); whole-tree walk was neutral at `34.8826 ms` to
`34.8828 ms` (`1.000x`). The candidate still lost to kernel btrfs by `8.27x`
on the single-file read and `3.02x` on the walk.

### Scorecard

| Gate | Result |
| --- | --- |
| Code-first backlog rows examined in this addendum | 1 |
| Direct ext4/btrfs-kernel ratios | Single-file candidate `57.961 ms` vs kernel `7.011 ms` (`8.27x` slower); walk candidate `34.883 ms` vs kernel `11.537 ms` (`3.02x` slower) |
| Production levers kept | 0 |
| Production levers rejected/reverted | 1 |
| Internal win/loss/neutral | `0/1/1` |
| Direct kernel win/loss/neutral | `0/2/0` |
| Conformance/behavior guard | Candidate RCH `cargo check -p ffs-core` and RCH `cargo build --profile release-perf -p ffs-cli` passed on `vmi1152480`; production code was reverted; clean-source RCH `cargo check -p ffs-core` passed on `vmi1153651`; clean-source RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1227854` (100 passed / 0 failed / 2 ignored); clean-source RCH `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`. |
| Release-readiness score for perf-superiority claims | 35 / 100: honest direct-kernel measurement and green conformance, but no kept lever and kernel still leads by `3.02-8.27x` |
| Release-readiness score for this row's hygiene | 94 / 100: baseline/candidate direct rows, kernel ratios, production revert, clean-source check, conformance, and negative-evidence ledger are complete; remaining risk is lack of allocator/flamegraph attribution for the next route. |

### Measured Rows

| Workload | Baseline | Candidate | Ratio | Verdict |
| --- | ---: | ---: | ---: | --- |
| FrankenFS `read --discard /compressible.bin` | `55.931 ms` | `57.961 ms` | `0.965x` old/new | Reject |
| Kernel `cat /compressible.bin` vs candidate | `7.011 ms` kernel | `57.961 ms` FrankenFS | kernel `8.27x` faster | Direct loss |
| FrankenFS `walk --read-data --no-stat` | `34.8826 ms` | `34.8828 ms` | `1.000x` old/new | Neutral/reject |
| Kernel `cat *` vs candidate walk | `11.537 ms` kernel | `34.883 ms` FrankenFS | kernel `3.02x` faster | Direct loss |

### Isomorphism

Ordering preserved: yes. The candidate preserved extent-order assembly and only
changed the destination buffer for full-overlap zstd regular extents.

Tie-breaking unchanged: yes. Extent lookup, compression-type dispatch, checksum
handling, and partial-extent fallback were unchanged.

Floating-point identical: N/A.

RNG seeds unchanged: N/A.

Bytes verified: yes by the existing btrfs decompression/conformance gates after
the revert; no production byte path from this candidate remains.

### Retry Predicate

Do not retry direct-to-final zstd decoding without allocation attribution showing
the decompressed output allocation and final copy dominate the mounted-image
path. Next work should profile or specialize btrfs extent lookup/metadata
fan-out, compressed scratch reuse, or CLI/open/read overhead for the remaining
compressed-read kernel gap.
