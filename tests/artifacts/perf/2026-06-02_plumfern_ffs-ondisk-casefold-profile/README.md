# bd-m7adx - ffs-ondisk casefold profile

## Target

Profile-backed target: `ffs_ondisk::ext4_casefold_key` on valid long UTF-8
names from `crates/ffs-ondisk/benches/casefold_key.rs`.

Baseline command:

```bash
RCH_FORCE_REMOTE=true TMPDIR=/data/tmp timeout 1400 rch exec -- \
  cargo bench --profile release-perf -p ffs-ondisk --bench casefold_key -- --noplot
```

Baseline worker: `vmi1293453`.

## Baseline

| Benchmark | Mean | Interval |
|---|---:|---:|
| `ext4_casefold_key_long_utf8` | 6.0021 us | [5.8735, 6.1375] us |
| `ext4_casefold_key_mixed_utf8` | 727.33 ns | [719.56, 737.77] ns |
| `ext4_casefold_key_ascii` | 146.63 ns | [144.49, 149.14] ns |
| `ext4_casefold_key_invalid_utf8` | 79.332 ns | [78.537, 80.151] ns |

Hotspot ranking: valid long UTF-8 names are the slowest casefold profile by a
wide margin.

## Attempted Lever

Candidate: route valid UTF-8 names without special ext4 sharp-s expansion
through `str::to_lowercase().into_bytes()` instead of the existing per-char
loop.

Opportunity score before implementation: Impact 3 x Confidence 3 / Effort 1 =
9.0.

## After Benchmark

After command: same Criterion bench through `rch`.

After worker: `vmi1153651`.

| Benchmark | Mean | Interval |
|---|---:|---:|
| `ext4_casefold_key_long_utf8` | 10.825 us | [10.627, 11.059] us |
| `ext4_casefold_key_mixed_utf8` | 1.1827 us | [1.1458, 1.2256] us |
| `ext4_casefold_key_ascii` | 239.50 ns | [235.74, 243.72] ns |
| `ext4_casefold_key_invalid_utf8` | 143.12 ns | [140.15, 146.35] ns |

Verdict: rejected. The after run selected a different worker and all rows
worsened, including rows not expected to benefit from the valid-UTF8 branch. The
candidate failed the Score >= 2.0 keep rule and no optimization code was kept.

## Behavior Finding

The attempted fast path exposed a semantic trap: Rust `str::to_lowercase`
applies the Unicode final-sigma context rule for capital sigma, while the
current per-char loop does not. A valid-UTF8 fast path through
`str::to_lowercase` would make `"ΑΣ"` fold differently from `"ασ"` and break
current casefold collision semantics.

The source diff keeps only the regression guard:
`ext4_casefold_key_capital_sigma_folds_like_lowercase_sigma`.

## Isomorphism Proof

- Ordering preserved: yes. The kept source change is test-only and does not
  alter lookup, iteration, or parser ordering.
- Tie-breaking unchanged: yes. No runtime tie-break logic changed.
- Floating-point: N/A.
- RNG seeds: N/A.
- Golden outputs: checked-in manifests passed:
  - `conformance/fixtures/checksums.sha256`
  - `conformance/golden/checksums.sha256`
  - `tests/fixtures/golden/checksums.txt`

## Validation

- `cargo fmt --package ffs-ondisk --check`: pass.
- `rch exec -- cargo test -p ffs-ondisk ext4_casefold -- --nocapture`: pass
  on `vmi1293453`, 5/5 focused casefold tests.
- `rch exec -- cargo check -p ffs-ondisk --all-targets`: pass on
  `vmi1293453`.
- `rch exec -- cargo clippy -p ffs-ondisk --all-targets -- -D warnings`: pass
  on `vmi1156319`.
- `git diff --check`: pass.
