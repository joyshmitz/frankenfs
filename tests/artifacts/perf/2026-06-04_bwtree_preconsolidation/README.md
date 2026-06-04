# Bw-tree append preconsolidation

Accepted `bd-xmh5g.47` pass 13: make the default consolidation threshold active
in `MappingTable::append_delta` instead of waiting for the runaway guard.

## Profile target

Prior profile-backed residual from `bwtree_vs_locked`:

```text
mixed/bwtree/8 mean: 1.0349 s
```

The long delta-chain mixed workload remained the next non-overlapping
profile-backed target after `ffs-repair` LRC and `ffs-mvcc` flush were owned by
other agents.

## Same-binary A/B

Command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1800 rch exec -- cargo bench --profile release-perf -p ffs-btree --bench bwtree_vs_locked -- mixed_auto_consolidation_ab --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

Worker: `vmi1264463`

```text
old_deferred_consolidation_8: [4.6494 s 4.9455 s 5.2365 s]
new_default_preconsolidation_8: [1.6495 s 2.1811 s 2.7749 s]
```

Mean ratio: `4.9455 / 2.1811 = 2.27x`.

Post-commit same-worker confirmation on `ts2`:

```text
old_deferred_consolidation_8: [1.8629 s 1.9152 s 1.9695 s]
new_default_preconsolidation_8: [349.77 ms 376.24 ms 403.68 ms]
```

Confirmation mean ratio: `1.9152 / 0.37624 = 5.09x`.

## Proof

Remote gates:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1200 rch exec -- cargo check -p ffs-btree --all-targets
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1400 rch exec -- cargo clippy -p ffs-btree --all-targets -- -D warnings
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1400 rch exec -- cargo test -p ffs-btree append_preconsolidation_matches_deferred_golden_report -- --nocapture --test-threads=1
```

Local format gate:

```text
cargo fmt -p ffs-btree --check
```

Golden marker hash:

```text
354ce4886e5de4ef335c9826d11f11db4d5a7d57d47ec62886d04f6e49a210fb  bwtree_preconsolidation_golden.tsv
```

## Isomorphism

- Ordering preserved: yes. Insert/delete linearization still occurs at the CAS
  that appends the mutation; consolidation CAS only replaces an equivalent base
  state before retrying the pending mutation.
- Tie-breaking unchanged: yes. Latest delta still shadows older entries by CAS
  order; materialized key order remains `BTreeMap` order.
- Floating-point: N/A.
- RNG seeds: unchanged. The benchmark and golden test keep the existing
  deterministic xorshift/probe sequences.
- Golden outputs: `sha256sum` verified for `bwtree_preconsolidation_golden.tsv`.
