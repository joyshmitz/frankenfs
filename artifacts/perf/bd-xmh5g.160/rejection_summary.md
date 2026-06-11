# bd-xmh5g.160 rejection summary

Target: `ffs-repair` RaptorQ direct-decode selected-row validation.

Profile evidence:
- RCH profile selected `ovh-a` despite a `vmi1227854` preference, so that run was
  treated as profile/routing evidence.
- RCH `ovh-a` profile rows:
  - `raptorq_encode_group_16blocks` `[250.15 us,251.62 us,252.49 us]`
  - `raptorq_decode_group_16blocks` `[261.49 us,263.75 us,266.16 us]`
  - `raptorq_decode_group_owned_symbols_16blocks` `[263.90 us,264.99 us,266.51 us]`
  - `lrc_encode_global_64blocks_8parity` `[211.04 us,219.35 us,226.04 us]`

Comparable baseline:
- Same-worker RCH `vmi1227854` restored-code baseline from `bd-xmh5g.159`:
  - borrowed decode `[249.69 us,265.16 us,278.92 us]`
  - owned decode `[251.75 us,291.60 us,319.61 us]`
  - no-corruption decode `[195.86 ns,199.44 ns,203.05 ns]`

Candidate:
- Skipped redundant expected-byte recomputation for selected pivot repair rows
  after one/two-erasure direct solve.
- Kept all row length checks and all non-selected repair-row validation.

Behavior proof before rejection:
- RCH `vmi1227854` `cargo check -j 1 -p ffs-repair --all-targets`
- RCH `vmi1227854` `cargo test -j 1 -p ffs-repair direct -- --nocapture`
- RCH `vmi1227854` `cargo test -j 1 -p ffs-repair raptorq -- --nocapture`
- RCH `vmi1227854` `cargo clippy -j 1 -p ffs-repair --all-targets -- -D warnings`
- Normalized golden hashes matched prior artifacts:
  - decode `5e11bf11a354338c346ceffaa88d681e03a0cd794bd4ffb280f31a14dc58608f`
  - encode `7b53276f2759953be509118ba260c659ed8c55eec7f8f6a2537c80dcbe2e033a`

Rebench:
- Same-worker RCH `vmi1227854` candidate:
  - borrowed decode `[366.80 us,417.31 us,494.07 us]`
  - owned decode `[341.33 us,361.07 us,383.19 us]`
  - no-corruption decode `[209.68 ns,216.63 ns,231.05 ns]`

Decision:
- Rejected. Borrowed decode regressed `0.64x` by midpoint, owned decode
  regressed `0.81x`, and no-corruption decode also regressed.
- Score `0.0`; no runtime code kept.
- `crates/ffs-repair/src/codec.rs` restored to pre-lever source.
