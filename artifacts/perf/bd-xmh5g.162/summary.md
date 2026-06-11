# bd-xmh5g.162 LRC Small-Parity Scheduler

Status: REJECTED, no runtime code kept.

Target: `ffs-repair` `lrc_encode_global_64blocks_8parity`, selected from the
fresh post-`bd-xmh5g.161` RCH profile on `vmi1227854`.

Focused baseline, RCH remote `vmi1227854`:

- `lrc_encode_global_64blocks_8parity`: `[278.80 us,296.23 us,318.83 us]`

One lever:

- Route small LRC global parity cases (`p <= 8`, `block_size <= 4096`) through
  a sequential scheduler while preserving the existing parity-major block body.

Behavior proof before rejection:

- RCH remote `vmi1227854`: `cargo test -j 1 -p ffs-repair global -- --nocapture --test-threads=1`
- 15 focused global/LRC tests passed.
- Marker-bounded `LRC_GLOBAL_PARITY_GOLDEN` SHA256:
  `84e1fd0632220fbbba4154b19448e06ade4c648c724171b5e41c131242a2df8b`

Candidate rebench, same-worker RCH remote `vmi1227854`:

- `lrc_encode_global_64blocks_8parity`: `[630.69 us,661.68 us,693.66 us]`

Decision:

- Rejected. Midpoint ratio was `0.45x`; conservative lower/upper ratio was
  `0.40x`. Score `0.0`.

Isomorphism:

- Ordering preserved: global parity output order remained `j=0..p-1`.
- Tie-breaking unchanged: N/A.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- GF recurrence unchanged: same `alpha^((i+1)*(j+1))` coefficient recurrence
  and data-block contribution order.

Shipped state:

- `crates/ffs-repair/src/lrc.rs` restored exactly to pre-lever source.
