# bd-xmh5g.166 - LRC Pair-Kernel Chunked XOR Reject

## Baseline

- Worker: `vmi1152480`
- Command:
  `RCH_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- cargo bench -j 1 -p ffs-repair --bench scrub_codec lrc_encode_global_64blocks_8parity -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2`
- `lrc_encode_global_64blocks_8parity`: `[817.26 us,887.32 us,973.85 us]`

## Candidate

- Lever: safe-Rust 8-byte chunked XOR/table kernel inside `gf256_mul_xor_pair_into`.
- Behavior proof:
  `RCH_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- cargo test -j 1 -p ffs-repair gf256_mul_xor_pair_matches_separate_passes -- --nocapture --test-threads=1`
- Result: passed, 1 focused test.
- Candidate command:
  `RCH_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- cargo bench -j 1 -p ffs-repair --bench scrub_codec lrc_encode_global_64blocks_8parity -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2`
- `lrc_encode_global_64blocks_8parity`: `[993.84 us,1.0890 ms,1.1738 ms]`

## Decision

- Score: `0.0`
- Decision: rejected; runtime code reverted before closeout.
- Candidate isomorphism: parity/source/byte ordering preserved, LRC tie-breaking N/A, floating point N/A, RNG N/A, GF arithmetic proven by focused equivalence test.
- Shipped-state isomorphism: exact revert to pre-lever `lrc.rs`.
- Next route: avoid LRC pair-body byte chunking; attack a different coefficient-layout or regenerating-code/LRC encode primitive with a target ratio of at least `1.20x`.
