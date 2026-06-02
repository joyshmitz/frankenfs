# bd-p7555 - LRC global parity indexed hot-loop lever rejected

Date: 2026-06-02
Agent: PlumFern
Crate: ffs-repair
Target: `lrc_encode_global_64blocks_8parity`

## Profile-backed target

`bd-p7555` was filed from an rch Criterion profile on worker `vmi1149989`:

- `lrc_encode_global_64blocks_8parity`: 532.77 us [513.11, 550.23]
- `raptorq_decode_group_16blocks`: 491.81 us [460.05, 521.48]
- `raptorq_encode_group_16blocks`: 219.61 us [198.69, 233.87]

The target is `encode_global` in `crates/ffs-repair/src/lrc.rs`, a GF(256)
dense matrix-vector style encoder over 64 data blocks, 8 global parity blocks,
and 4096-byte shards.

## Alien primitive card

Symptom: GF(256) erasure-code parity encoding row remains a top `ffs-repair`
profile row after earlier repair/scrub wins.

Matched sources:

- `alien_cs_graveyard.md` section 1.4: LRC encoding is GF(256)
  matrix-vector multiply; shard ops are memory-bandwidth bound.
- Graveyard appendix: record the incumbent baseline because asymptotic or SIMD
  ideas often lose to cache constants.

Candidate primitive: replace iterator zip in the private GF table XOR helper
with a length-stable indexed loop. This keeps the same 64 KiB static GF
multiply table, same row-major parity traversal, and same coefficient map while
giving LLVM a simpler hot loop.

Fallback: keep the incumbent row-major iterator loop, because the previous
source-block-major loop fusion and portable-SIMD nibble-split GF multiply also
regressed.

EV/score before trying: Impact 2 x Confidence 2 / Effort 1 = 4.0.

## Benchmark

Command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 900 rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_codec -- lrc_encode_global_64blocks_8parity --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Both runs used rch worker `vmi1227854`.

| Arm | Mean | Interval | Decision |
| --- | ---: | --- | --- |
| baseline row-major iterator | 593.67 us | [578.61, 614.20] | incumbent |
| indexed helper loop | 725.14 us | [699.95, 738.71] | rejected |

Delta: indexed loop is 22.8% slower by mean, with non-overlapping intervals.

Score after measurement: Impact 0 x Confidence 4 / Effort 1 = 0.0. Production
code was restored to the baseline helper.

## Isomorphism proof

- Ordering preserved: yes in the candidate, because `encode_global` still
  iterated parity rows `j`, then data blocks `i`, then bytes in ascending index.
- Tie-breaking unchanged: N/A.
- Floating point: N/A.
- RNG seeds: N/A.
- Error classes: candidate did not change public validation; `encode_global`
  still asserted data block count and block-size equality before calling the
  private helper.
- Golden output sha256: `sha256sum -c
  tests/artifacts/perf/2026-06-02_lrc_simd_gf/lrc_global_parity_golden.sha256`
  passed after restoring the incumbent code.

## Conclusion

No production code change is kept for `bd-p7555`. Three profile-backed levers
have now failed the keep gate:

- source-block-major loop fusion: regressed to 1.3801 ms from a 716.81 us
  baseline in earlier `bd-kaiam` evidence;
- portable-SIMD nibble-split GF multiply: 3.097 ms vs 1.581 ms same-binary
  scalar A/B in `tests/artifacts/perf/2026-06-02_lrc_simd_gf/`;
- indexed helper loop: 725.14 us vs 593.67 us on `vmi1227854`.

The next `ffs-repair` no-gap pass should re-profile and move to the shifted
hotspot, likely RaptorQ decode, rather than retrying this L1-resident GF table
loop without a new profile-backed primitive.
