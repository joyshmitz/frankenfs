# bd-xmh5g.44 - streaming batch allocation bitmap scan

Date: 2026-06-04
Crate: `ffs-alloc`
Outcome: kept

## Lever

`try_alloc_batch_in_group` previously called `bitmap_find_free` once per
single-block allocation. The kept lever streams the bitmap once in cyclic
allocation order, sets free bits in place, and emits the same one-block
`BlockAlloc` sequence.

## Isomorphism

- Ordering preserved: yes. The scan records the same cyclic first-free order as
  repeated `bitmap_find_free` calls from the previous search position.
- Tie-breaking unchanged: yes. Equal candidates are still selected by lowest bit
  in cyclic order from the goal.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- Golden verified:
  `tests/artifacts/perf/2026-06-04_batch_alloc_stream/golden_batch_take_rows.sha256`.

Remote proof:

- `RCH_FORCE_REMOTE=true rch exec -- cargo check -p ffs-alloc --all-targets`
- `RCH_FORCE_REMOTE=true rch exec -- cargo test -p ffs-alloc batch -- --nocapture`
  passed 15 batch allocation tests, including batch-vs-single proptest.
- `RCH_FORCE_REMOTE=true rch exec -- cargo test -p ffs-alloc bitmap_take_free_bits_cyclic_golden_report -- --nocapture`
  produced the hashed golden rows.

## Performance

Same worker (`ts2`), same command:
`RCH_FORCE_REMOTE=true rch exec -- cargo bench -p ffs-alloc --profile release-perf --bench batch_alloc -- --noplot`.

| Row | Baseline mean | After mean | Delta |
| --- | ---: | ---: | ---: |
| `alloc_20_blocks/batch_20` | 2.6632 us | 2.5220 us | 1.06x |
| `alloc_100_blocks/batch_100` | 4.0969 us | 2.9094 us | 1.41x |

Campaign score: kept as Score >= 2.0 because the profile target was
`batch_100`, the confidence is high from same-worker interval separation, and
the implementation effort/blast radius is low.
