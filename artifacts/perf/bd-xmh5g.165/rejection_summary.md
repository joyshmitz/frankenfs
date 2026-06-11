# bd-xmh5g.165 rejection summary

## Target
- Crate: `ffs-repair`
- Benchmark row: `raptorq_decode_group_16blocks`
- Lever tested: stream borrowed direct-decode known-source projection from the block device into repair-row residuals, instead of first collecting a `Vec<KnownSourceSymbol>`.

## Baseline
Fresh full-suite RCH profile on remote `vmi1152480`:

| Row | Criterion time |
| --- | --- |
| `raptorq_encode_group_16blocks` | `[283.36 us, 307.15 us, 324.77 us]` |
| `raptorq_decode_group_16blocks` | `[311.28 us, 341.56 us, 371.19 us]` |
| `raptorq_decode_group_owned_symbols_16blocks` | `[313.55 us, 325.14 us, 341.98 us]` |
| `raptorq_decode_group_no_corruption_16blocks` | `[32.050 ns, 33.677 ns, 34.622 ns]` |
| `lrc_encode_global_64blocks_8parity` | `[397.87 us, 488.34 us, 565.08 us]` |

The LRC row was out of scope because SnowyHeron held the active LRC reservation.

## Candidate
The candidate preserved the direct small-erasure algorithm:
- repair row scan order unchanged
- full-rank pair selection unchanged
- all repair-row validation unchanged
- owned-symbol path left unchanged to preserve fallback restoration semantics

RCH behavior proof before rejection:
- `cargo check -j 1 -p ffs-repair --lib` passed on remote `vmi1153651`.
- `cargo test -j 1 -p ffs-repair --lib -- --nocapture --test-threads=1` passed on remote `vmi1152480`: 444 passed, 0 failed.
- `decode_direct_source_major_residuals_match_row_major_reference` passed.
- Marker-bounded `RAPTORQ_DECODE_GOLDEN` stdout SHA256 stayed `f751dab0a92e1476c2b57a94884162005cdf5fc1cdffc99f260c1aefad60f5c5`.
- Marker-bounded `RAPTORQ_ENCODE_GOLDEN` stdout SHA256 stayed `9bd71cee3bf4770d2b25495dc3f19c59bf995db3b5595d7ccdccd340116bed47`.

## Rebench
Same-worker RCH remote `vmi1152480` focused rebench:

| Row | Baseline midpoint | Candidate midpoint | Result |
| --- | ---: | ---: | ---: |
| `raptorq_decode_group_16blocks` | `341.56 us` | `397.48 us` | `0.86x` |
| `raptorq_decode_group_owned_symbols_16blocks` | `325.14 us` | `349.48 us` | `0.93x` |
| `raptorq_decode_group_no_corruption_16blocks` | `33.677 ns` | `31.415 ns` | `1.07x` |

Conservative lower/upper for target row was `311.28 / 452.72 = 0.69x`.

## Decision
Rejected. The profile-backed target row regressed on the same worker, and the owned-symbol decode row also regressed. Score `0.0`; no runtime code kept.

`crates/ffs-repair/src/codec.rs` was restored to the pre-lever source. The next RaptorQ pass should avoid streamed borrowed projection, pair projection, placeholder-skip, row-cache, decoder-construction deferral, ESI-validation shortcuts, determinant-scaling, selected-row validation pruning, and output-buffer materialization. Route deeper, likely toward a different RaptorQ primitive or layout that avoids the current per-row residual projection shape entirely.
