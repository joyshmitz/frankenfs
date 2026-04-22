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
