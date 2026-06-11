# bd-xmh5g.164 - RaptorQ Pair-Fused Direct Projection Reject

## Baseline

- Worker: `vmi1152480`
- Command:
  `RCH_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- cargo bench -j 1 -p ffs-repair --bench scrub_codec -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2`
- `raptorq_decode_group_16blocks`: `[345.04 us,381.31 us,418.63 us]`
- `raptorq_decode_group_owned_symbols_16blocks`: `[338.42 us,364.50 us,383.21 us]`
- `raptorq_decode_group_no_corruption_16blocks`: `[31.279 ns,31.818 ns,32.789 ns]`

## Candidate

- Lever: pair-fused direct known-source projection with a local safe RFC6330 GF(256) multiplication table.
- Behavior proof:
  `RCH_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- cargo test -j 1 -p ffs-repair direct_projection_pair_kernel_matches_sequential_addmul -- --nocapture --test-threads=1`
- Result: passed, 1 focused test.
- Candidate command:
  `RCH_WORKER=vmi1152480 RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- cargo bench -j 1 -p ffs-repair --bench scrub_codec raptorq_decode_group -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2`
- `raptorq_decode_group_16blocks`: `[361.67 us,392.87 us,426.04 us]`
- `raptorq_decode_group_owned_symbols_16blocks`: `[425.85 us,493.22 us,564.92 us]`
- `raptorq_decode_group_no_corruption_16blocks`: `[64.045 ns,93.936 ns,136.33 ns]`

## Decision

- Score: `0.0`
- Decision: rejected; runtime code reverted before closeout.
- Shipped-state isomorphism: exact revert to pre-lever `codec.rs`.
- Next route: avoid pair-fused same-source projection; attack a different structural RaptorQ encode/decode layout or regenerating-code/LRC coefficient-layout primitive.
