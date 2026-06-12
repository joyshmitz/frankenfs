# bd-xmh5g.169 pass 33 rejection

## Target

- Crate: `ffs-repair`
- Benchmark row: `lrc_encode_global_64blocks_8parity`
- Lever: seed the zero-initialized global parity row with assignment
  microkernels for the first source block or source pair before continuing the
  existing parity-major XOR loop.

## Evidence

| Run | Worker | Source | Time |
| --- | --- | --- | --- |
| Clean `HEAD` baseline | `vmi1152480` | `clean_head_lrc_rch.txt` | `[553.08 us,636.80 us,691.71 us]` |
| Candidate route | `vmi1149989` | `candidate_seed_microkernel_rch.txt` | `[208.20 us,225.52 us,242.60 us]` |
| Same-path old baseline | `ovh-a` | `main_old_baseline_rch.txt` | `[193.84 us,196.57 us,199.79 us]` |
| Same-path candidate | `ovh-a` | `main_candidate_seed_microkernel_rch.txt` | `[228.05 us,246.63 us,268.45 us]` |

`baseline_lrc_vmi1152480_rch.txt` captured an intermediate row-pair candidate
that was overwritten before final scoring; it is retained only as scratch
routing context and is not part of the decision.

## Decision

Rejected. The same-worker `ovh-a` midpoint regressed from `196.57 us` to
`246.63 us` (`0.80x`), with non-overlapping intervals. Score: `0.0`; no
runtime code kept.

## Isomorphism

- Ordering preserved: yes; parity order `j=0..p-1`, data-block order
  `i=0..k-1`, and byte order were unchanged.
- Tie-breaking unchanged: N/A.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- GF arithmetic identical: not promoted. A late targeted RCH test matched zero
  tests because the runtime source had already been restored, so it is not
  counted as behavior proof.
- Golden SHA256:
  `84e1fd0632220fbbba4154b19448e06ade4c648c724171b5e41c131242a2df8b`.

## Shipped State

`crates/ffs-repair/src/lrc.rs` was restored to the pre-lever source before
closeout. The next route should avoid seed-assignment microkernels and move to a
different LRC primitive: coefficient schedule/table reuse or a GF(256)
matrix-vector layout with a same-binary old/new microkernel gate.
