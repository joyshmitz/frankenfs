# Upgrade Log

## 2026-04-21 / 2026-04-22: library-updater session (Clawdstein-libupdater-frankenfs)

Workspace-level dependency bumps in `Cargo.toml [workspace.dependencies]`,
one commit per dependency. Every check/test was offloaded via
`rch exec -- cargo <cmd>`. `fuser` is intentionally pinned because of the
`[patch.crates-io] fuser = { path = "vendor/fuser" }` override that forwards
unrestricted ioctls for FIEMAP / EXT4_IOC_* parity.

### Session summary

- **Updated:**  25 (1 preflight + 24 main loop — anyhow, arc-swap, bitflags,
  blake3, clap, ctrlc, criterion, insta, libc, memchr, parking_lot, proptest,
  rayon, serde, serde_json, sha2, smallvec, tempfile, thiserror, toml,
  tracing, tracing-subscriber, zstd, brotli, flate2, ftui)
- **Skipped:**  fuser (pinned to `vendor/fuser` via `[patch.crates-io]`),
  crc32c, crossbeam-epoch, hex, xxhash-rust, lzokay-native (already latest)
- **Failed:**   0
- **Needs attention:** 4 pre-existing conformance test failures
  (fixture_checksum_manifest_is_complete, ext4_e2compr_write_readback_*,
  btrfs_tree_block_checksum_tamper_detection_*, full_conformance_gate_pass)
  — these fail identically before and after this session, i.e. they are
  unrelated to the dep bumps. Fixture drift owned by other ongoing work.
- **Circuit breaker:** not hit. Clean finish.

### Preflight: asupersync 0.3.0 → 0.3.1

- **Why:** 0.3.1 published ~3h before session start (2026-04-21T23:58:52Z).
- **Lockstep bumps (via `cargo update -p asupersync`):** asupersync-macros,
  franken-decision, franken-evidence, franken-kernel → 0.3.1.
- **Checks:** workspace check clean; `cargo test -p ffs-harness --lib`
  312 passed / 0 failed.
- **Commit:** `eacbc42`

### Per-dependency updates (this session)

#### anyhow: 1.0.97 → 1.0.102
- Patch bump. No API changes. Lockfile already floated to 1.0.102 via
  transitive dep; manifest pin now matches. Commit: `915793b`

#### arc-swap: 1.7.1 → 1.9.1
- Minor bump (additive). Commit: `6a1be90`

#### bitflags: 2.9.0 → 2.11.1
- Minor bump (adds `from_bits_retain` const fns, no changes used here).
  Commit: `f7228e8`

#### blake3: 1.6.0 → 1.8.4
- Minor bumps within 1.x; new AVX-512/NEON perf work, hash output
  byte-identical (critical for any persisted digests). Commit: `0ca7087`

#### clap: 4.5.0 → 4.6.1
- Minor bump within 4.x; derive-based CLIs in ffs-cli/ffs-tui compile
  unchanged. Commit: `05e47f9`

#### ctrlc: 3.4 → 3.5.2
- Minor bump; Unix path unchanged. Commit: `78f3ca5`

#### criterion: 0.5.1 → 0.8.2 (MAJOR, two major bumps)
- Breaking: criterion 0.6 deprecated `criterion::black_box` in favor of
  `std::hint::black_box`. Migrated 8 bench files:
  ffs-alloc/benches/{batch_alloc,bitmap_ops}.rs,
  ffs-block/benches/arc_cache.rs,
  ffs-extent/benches/extent_resolve.rs,
  ffs-fuse/benches/{degraded_pressure,mount_runtime}.rs,
  ffs-harness/benches/{metadata_parse,ondisk_parse}.rs.
  Imports split between `criterion::{Criterion, criterion_group,
  criterion_main}` and `std::hint::black_box`.
- MSRV 1.80 from criterion 0.6 is a non-issue (workspace rust-version 1.85).
- Commit: `3627fbb`. Tests: ffs-harness --lib 312/0.

#### insta: 1.42.1 → 1.47.2
- Declared but not consumed by any crate; manifest pin updated, no lockfile
  entry exists so `cargo update -p insta` N/A. Commit: `04ac32b`

#### libc: 0.2.180 → 0.2.185
- Patch bump, additive FFI bindings only. Commit: `379939e`

#### memchr: 2.7.4 → 2.8.0
- Minor bump, additive SIMD backends. Commit: `5ce886e`

#### parking_lot: 0.12.3 → 0.12.5
- Patch bump, internal perf. Commit: `8608aa7`

#### proptest: 1.6.0 → 1.11.0
- Minor bumps, additive. Commit: `e549128`

#### rayon: 1.11.0 → 1.12.0
- Minor bump, additive `ParallelIterator` combinators. Commit: `f67944e`

#### serde: 1.0.218 → 1.0.228
- Patch bumps, bugfix only, derive output unchanged. Commit: `35d544e`

#### serde_json: 1.0.140 → 1.0.149
- Patch bumps, internal parser tweaks. Commit: `020b5da`

#### sha2: 0.10.8 → 0.11.0 (MAJOR, digest 0.10 -> 0.11)
- Breaking per changelog: type aliases replaced with newtypes, compression
  internals moved to `block_api` module. The single consumer
  (ffs-harness/tests/conformance.rs) uses the stable Digest-trait surface
  (`Sha256::new`, `update`, `finalize`), unchanged. Hash output is
  byte-identical.
- Transitive sha2 0.10.9 purged from lockfile; only 0.11 + digest 0.11
  remain.
- Commit: `15dcd85`. Tests: ffs-harness --lib 312/0.

#### smallvec: 1.14.0 → 1.15.1
- Minor bump, additive. Commit: `21c7a01`

#### tempfile: 3.17.1 → 3.27.0
- Many minor bumps within 3.x; core `tempfile()` / `tempdir()` /
  `NamedTempFile::new()` APIs unchanged. Commit: `91c29aa`

#### thiserror: 2.0.11 → 2.0.18
- Patch bumps within 2.x, bugfix only. Commit: `1bfa762`

#### toml: 0.8 → 1.1.2 (MAJOR, first 1.x)
- Breaking per changelog: serde/std are opt-in (still default here);
  `Deserializer::new`/`ValueDeserializer::new` deprecated in favor of
  `Deserializer::parse`; serializer now takes `&mut Buffer` instead of
  `&mut String`; order preservation requires `preserve_order` feature;
  `toml_edit` absorbed, `toml_write` renamed `toml_writer`, new
  `toml_parser` helper crate.
- The one consumer (ffs-harness/benchmark_taxonomy.rs) uses stable
  `toml::from_str(&text)` + `toml::de::Error`, untouched.
- Lockfile churn: serde_spanned/toml_datetime/winnow bumped.
- Commit: `769eed9`. Tests: ffs-harness --lib 312/0.

#### tracing: 0.1.41 → 0.1.44
- Patch bump, additive. Commit: `dcff33d`

#### tracing-subscriber: 0.3.19 → 0.3.23
- Patch bumps, additive. Commit: `4123707`

#### zstd: 0.13 → 0.13.3 (hot-path)
- Patch bump, vendored libzstd 1.5.x C-source patches, decompression
  byte-identical per zstd spec. Tests: ffs-btrfs --lib 163/0.
  Commit: `30dfc24`

#### brotli: 6.0 → 8.0.2 (MAJOR × 2, hot-path)
- Two major bumps to Dropbox pure-Rust brotli. Stable surface used here
  (`Decompressor::new`, `BrotliCompress`, `BrotliEncoderParams`) is
  unchanged. Decoder still accepts any RFC-7932 stream produced by the
  old encoder.
- Transitive brotli-decompressor 4.0.3 -> 5.0.0.
- Tests: ffs-mvcc --lib 398/0. Commit: `2b0f644`

#### flate2: 1.0 → 1.1.9 (hot-path)
- Minor bumps within 1.x (zlib-rs / miniz-oxide backend improvements).
  DEFLATE / zlib output remain bit-exact per RFC 1950/1951.
  Tests: ffs-mvcc --lib 398/0. Commit: `2379d3c`

#### ftui: 0.2.1 → 0.3.1 (MAJOR for 0.x)
- Minor-for-SemVer but major-for-0.x. All 10 ftui-* subcrates bumped in
  lockstep. Stable re-exports used by ffs-tui/src/lib.rs
  (Cmd/Event/Model/PackedRgba/Style/KeyEvent + layout/render/text/widgets
  modules) still resolve under 0.3.1. Tests: ffs-tui --lib 56/0.
  Commit: `417bb79`

---

## 2026-04-22: Full Review Session (cc-fs)

Agent: cc-fs | Mode: FULL REVIEW

### Test/Clippy Status

- **Clippy:** PASS (0 errors, 6 warnings in vendored fuser)
- **Workspace tests:** 4 conformance failures (pre-existing, tracked in bd-uyjcz)

### Bugs Fixed

| Bead | Description | Fix |
|------|-------------|-----|
| bd-5o3i6 | 6 btrfs readdir tests failing (CRC32C mismatch) | Added checksum stamping to `build_btrfs_readdir_image` in ffs-core/src/lib.rs |
| bd-tnmo2 | 2 degraded_pressure tests failing (threshold mismatch) | Updated headroom values for asupersync 0.3 (0.75 Warning, 0.15 Critical) |
| - | 2 cross_crate_integration tests failing | Added checksum stamping to `build_btrfs_fsops_image` in cross_crate_integration.rs |
| - | Clippy too_many_lines error | Added `#[allow(clippy::too_many_lines)]` to `create_btrfs_image_with_subvolumes` |
| - | Missing fuzz corpus directory | Created `fuzz/corpus/fuzz_ioctl_dispatch/` |

### Fuzz Coverage Audit (/testing-fuzzing)

**Existing coverage:** 23 fuzz targets covering all critical parsing paths.

**Gaps identified and beads filed (17 total):**

| ID | Target | Priority |
|----|--------|----------|
| bd-gznge | fuzz_btrfs_xattr_items | P2 |
| bd-ik16s | fuzz_detect_filesystem | P2 |
| bd-i1vkz | fuzz_native_cow_recovery | P2 |
| bd-eiae2 | fuzz_repair_evidence_ledger | P2 |
| bd-6ut5x | fuzz_repair_codec_roundtrip | P2 |
| bd-37w4o | fuzz_verify_ext4_integrity | P2 |
| bd-i820d | fuzz_ffs_inspect | P2 |
| bd-uqfhd | fuzz_por_authenticator | P2 |
| bd-11yv0 | fuzz_lrc_repair | P2 |
| bd-snm7k | btrfs checksum verification | P2 |
| bd-atkc6 | Ext4ImageReader | P2 |
| bd-w1nsv | ffs-dir operations | P2 |
| bd-1dkja | ffs-xattr parsing | P2 |
| bd-e6rh8 | ffs-cli btrfs parsers | P2 |
| bd-9zg6j | ffs-inode roundtrip | P2 |
| bd-cz3rv | parse_dx_root large_dir=true | P3 |
| bd-qk6am | fuzz_alloc_bitmap | P3 |

### Known Issues (Pre-existing)

| Bead | Issue |
|------|-------|
| bd-uyjcz | 4 conformance tests failing (btrfs checksum, fixture manifest, e2compr) |
| bd-scqdb | dispatch_ioctl_move_ext_rejection_logs flaky (tracing isolation) |

### Crates Audited

All 19 crates in workspace audited for fuzz coverage gaps:
ffs-core, ffs-ondisk, ffs-btrfs, ffs-journal, ffs-mvcc, ffs-repair,
ffs-dir, ffs-xattr, ffs-inode, ffs-alloc, ffs-cli, ffs-block, ffs-btree,
ffs-extent, ffs-error, ffs-types, ffs-tui, ffs-harness, ffs

### Saturation Check (cod-fs)

- Final `/testing-fuzzing` re-scan focused on `ffs-core` open/recovery/journal/path/ioctl surfaces.
- No new fuzz-target findings surfaced beyond the already-filed backlog.
- Existing dedicated coverage remains in place for `OpenFs::from_device`, journal replay, MVCC WAL recovery, path-component validation, ioctl dispatch, path-encoding mount behavior, and repair-symbol mutation.
- The only obvious remaining parser-style gap in `ffs-core` is still `verify_ext4_integrity(image: &[u8], ...)`, which is already tracked as `bd-37w4o`.
- Repeated `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenfs_cod cargo test --workspace --all-targets` passes converged on the same 4 `ffs-harness` conformance failures already tracked by `bd-uyjcz`, `bd-efc2j`, `bd-r8c8r`, and `bd-ew490`; no new failure class surfaced.
- Status: **DONE** for additional `cod-fs` review/fuzz discovery on this frontier; idle until the code surface changes or one of the filed beads lands.

### Final Report (cod-fs)

- FrankenFS `cod-fs` work complete for this frontier.
- Closed or reconciled 36 beads across parity coverage, stale-tracker cleanup, fuzz-harness implementation, and blocked syscall-boundary closeouts.
- Filed 17+ review/fuzz follow-up beads covering workspace gate failures, conformance regressions, and remaining `ffs-core` / `ffs-fuse` fuzz targets.
- Current remote workspace status: `cargo test --workspace --all-targets` is green until `ffs-harness` conformance and then fails only the 4 known tests tracked by `bd-uyjcz`, `bd-efc2j`, `bd-r8c8r`, and `bd-ew490`; no new failure class surfaced in repeated `rch` passes.
- Current dependency status: `asupersync` is consistently pinned to `0.3.1` across the workspace, `ffs-*` crates, and `Cargo.lock`.
- Final state: **DONE** and idle pending new code-surface changes or prioritization of the remaining open review beads.

### Session Complete

**Final verification (2026-04-22T13:xx):**
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS (6 warnings in vendored fuser only)
- `cargo test --workspace --all-targets`: 4 conformance failures (pre-existing bd-uyjcz)
- Fuzz audit: Saturated after 5+ passes — no new gaps beyond 17 filed beads

**Session outcome:**
- 5 bugs fixed (CRC32C checksums, asupersync thresholds, clippy, corpus dir)
- 17 fuzz beads filed (P2/P3)
- 2 pre-existing issues remain (bd-uyjcz conformance, bd-scqdb flaky)
- All 19 workspace crates audited

### FINAL REPORT (cc-fs) — 2026-04-22

| Metric | Value |
|--------|-------|
| Clippy | PASS |
| Tests | 4 failures (pre-existing) |
| Fuzz audit | Saturated |
| Bugs fixed | 5 |
| Beads filed | 17 |
| Crates audited | 19/19 |

**cc-fs: IDLE** — no actionable work.

---

## 2026-04-21: asupersync 0.2.5 → 0.3.0

**Commits:**
- `83907c2` chore(deps): bump asupersync 0.2.5 → 0.3.0 (crates.io v0.3.0)
- `a6bb60d` fix(ffs-core): update tests for asupersync 0.3 threshold changes

**Breaking changes in asupersync 0.3:**

The `SystemPressure::degradation_level()` thresholds changed:

| Level | Old threshold | New threshold | Old label  | New label  |
|-------|--------------|---------------|------------|------------|
| 0     | >= 0.50      | >= 0.90       | normal     | normal     |
| 1     | >= 0.30      | >= 0.65       | warning    | light      |
| 2     | >= 0.15      | >= 0.35       | degraded   | moderate   |
| 3     | >= 0.05      | >= 0.10       | critical   | heavy      |
| 4     | < 0.05       | < 0.10        | emergency  | emergency  |

**Migration:**
- All test assertions using headroom values were updated
- `DegradationLevel` doc comments updated to reflect new boundaries
- Internal FrankenFS level names (Warning, Degraded, Critical) kept unchanged
