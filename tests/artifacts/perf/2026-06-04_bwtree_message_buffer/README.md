# Bw-tree message-buffer delta

Accepted `bd-xmh5g.48` pass 14: add a B-epsilon-tree style message-buffer
delta above Bw-tree pages so insert/delete mutations coalesce by key before
forcing a full-base consolidation.

## Profile target

Fresh rch reprofile after pass 13 showed the residual write-path gap:

```text
write_heavy/bwtree/8 mean: 436.65 ms
write_heavy/locked_btree/8 mean: 26.134 ms
mixed/bwtree/8 mean: 283.48 ms
mixed/locked_btree/8 mean: 26.146 ms
```

The symptom was that default-threshold preconsolidation still materialized and
cloned the full 10k-entry base at every small delta-chain window.

## Same-binary A/B

Command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1800 rch exec -- cargo bench --profile release-perf -p ffs-btree --bench bwtree_vs_locked -- write_heavy_message_buffer_ab --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

Worker: `vmi1149989`

```text
old_individual_preconsolidation_8: [512.15 ms 541.55 ms 571.45 ms]
new_message_buffer_8: [142.16 ms 149.65 ms 156.83 ms]
```

Mean ratio: `541.55 / 149.65 = 3.62x`.

Keep score: `Impact 3.62 * Confidence 0.90 / Effort 1.50 = 2.17`, so the
lever clears the `Score >= 2.0` gate.

## Proof

Remote gates:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1200 rch exec -- cargo check -p ffs-btree --all-targets
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1400 rch exec -- cargo test -p ffs-btree message_buffer_matches_individual_preconsolidation_golden_report -- --nocapture --test-threads=1
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1400 rch exec -- cargo test -p ffs-btree -- --nocapture
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1400 rch exec -- cargo clippy -p ffs-btree --all-targets -- -D warnings
```

Workers: `ts1` for check, focused golden, and full tests; `ts2` for clippy.

Local format gate:

```text
cargo fmt --package ffs-btree --check
git diff --check -- crates/ffs-btree/src/bw_tree.rs crates/ffs-btree/benches/bwtree_vs_locked.rs
```

Golden marker hash:

```text
4f2958281a766531e9a890d31147aa1f7102c136cab39f85207ed35e09a2f9f6  bwtree_message_buffer_golden.tsv
```

## Isomorphism

- Ordering preserved: yes. Insert/delete mutations still linearize at the CAS
  that publishes the new page head; the buffer is one head delta over the same
  successor chain.
- Tie-breaking unchanged: yes. For the same key, the newest buffered mutation
  replaces the older one exactly as the newest delta shadows older deltas. For
  different keys, insert/delete effects commute because the materialized state
  is a `BTreeMap` keyed by `BwKey`.
- Floating-point: N/A.
- RNG seeds: unchanged. The benchmark and golden proof use the same
  deterministic xorshift/probe sequences as the unbuffered comparator.
- Golden outputs: `sha256sum` verified for `bwtree_message_buffer_golden.tsv`.
