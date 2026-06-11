# bd-xmh5g.161 RaptorQ Compact Known-Source Projection

Status: KEPT

Artifact path note: this directory retains the initial local `bd-xmh5g.160`
name because the baseline/proof files were captured before upstream claimed and
rejected that ID; the live tracker closeout for this kept lever is
`bd-xmh5g.161`.

Target: `ffs-repair` direct small-erasure known-source projection for
`raptorq_decode_group_16blocks` and
`raptorq_decode_group_owned_symbols_16blocks`.

Profile-backed baseline, RCH remote `vmi1227854`:

- `raptorq_decode_group_16blocks`: `[277.19 us,307.67 us,347.26 us]`
- `raptorq_decode_group_owned_symbols_16blocks`: `[269.93 us,285.61 us,300.02 us]`
- `raptorq_decode_group_no_corruption_16blocks`: `[191.62 ns,195.39 ns,200.09 ns]`

One lever:

- `read_known_source_symbols` returns compact intact source symbols with their
  source indices instead of allocating corrupt zero-placeholder blocks.
- Projection keeps total `source_count` explicit and walks only intact symbols.

Rebench, same-worker RCH remote `vmi1227854`:

- `raptorq_decode_group_16blocks`: `[263.11 us,269.96 us,277.69 us]`
- `raptorq_decode_group_owned_symbols_16blocks`: `[246.01 us,256.55 us,276.10 us]`
- `raptorq_decode_group_no_corruption_16blocks`: `[186.76 ns,192.94 ns,198.31 ns]`

Score: Impact 4.0 x Confidence 4.0 / Effort 2.0 = 8.0.

Isomorphism proof:

- Ordering preserved: intact source symbols are read in ascending source index
  order; recovered corrupt output ordering and duplicates remain in the
  unchanged `recover_from_direct_solution` path.
- Tie-breaking unchanged: repair row scan order, full-rank selection, and
  fallback order are unchanged.
- Floating-point identical: N/A.
- RNG seeds unchanged: `repair_seed`, ESI order, and coefficient generation are
  unchanged.
- Golden verified: marker-bounded `RAPTORQ_DECODE_GOLDEN` SHA256
  `f751dab0a92e1476c2b57a94884162005cdf5fc1cdffc99f260c1aefad60f5c5`.

Gates:

- `cargo fmt --package ffs-repair --check`
- RCH remote `vmi1227854`: `decode_direct_source_major_residuals_match_row_major_reference`
- RCH remote `vmi1227854`: `raptorq_decode_golden_report`
- RCH remote `vmi1227854`: focused Criterion baseline/rebench
- RCH remote `vmi1227854`: `cargo check -j 1 -p ffs-repair --all-targets`
- RCH remote `vmi1227854`: `cargo clippy -j 1 -p ffs-repair --all-targets -- -D warnings`
