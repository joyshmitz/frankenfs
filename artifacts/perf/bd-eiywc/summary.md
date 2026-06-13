# bd-eiywc Evidence Summary

## Change

Finish the in-progress zero-copy Btrfs leaf-entry primitive that was folded into
`2a9c228f` as concurrent work: `BtrfsLeafEntryBatch` stores item payloads as
ranges into the shared verified leaf block, and
`walk_tree_range_borrowed_with_nodes` exposes those batches for parsed-node
walks. This pass adds the focused Criterion row and a unit isomorphism test.

## Profile / Baseline

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1149989 rch exec -- cargo bench -j 1 -p ffs-btrfs --bench parsed_node_cache -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Baseline artifact: `baseline_parsed_node_cache_rch.txt`.

Baseline rows on `vmi1149989`:

- `btrfs_parsed_node_walk_full/byte_reparse`: [283.23 us, 297.13 us, 313.17 us]
- `btrfs_parsed_node_walk_full/parsed_cached`: [193.43 us, 197.25 us, 203.97 us]
- `btrfs_parsed_node_walk_narrow/byte_reparse`: [13.483 us, 13.835 us, 14.106 us]
- `btrfs_parsed_node_walk_narrow/parsed_cached`: [1.4115 us, 1.4573 us, 1.5047 us]

## Rebench

Candidate command:

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1149989 rch exec -- cargo bench -j 1 -p ffs-btrfs --bench parsed_node_cache -- btrfs_parsed_node_walk_full --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Candidate rows on `vmi1149989`:

- `btrfs_parsed_node_walk_full/byte_reparse`: [285.90 us, 320.85 us, 357.81 us]
- `btrfs_parsed_node_walk_full/parsed_cached`: [312.95 us, 331.26 us, 362.33 us]
- `btrfs_parsed_node_walk_full/parsed_cached_borrowed`: [53.754 us, 57.278 us, 60.683 us]

Speedup:

- Versus same-worker old `parsed_cached` baseline midpoint: 197.25 / 57.278 = 3.44x.
- Versus same-run current owned `parsed_cached` midpoint: 331.26 / 57.278 = 5.78x.
- Conservative old-baseline lower/candidate upper: 193.43 / 60.683 = 3.19x.

Score: kept. Impact 4.5 x Confidence 4.0 / Effort 1.0 = 18.0.

## Isomorphism Proof

- Ordering preserved: yes. The borrowed walker uses the same internal-node
  pruning and leaf item iteration order as `walk_tree_range_with_nodes`.
- Tie-breaking unchanged: yes. There is no new choice point; range boundaries
  and duplicate-node rejection are unchanged.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- Golden/output verification: `walk_tree_range_borrowed_with_nodes_matches_owned_entries_bd_eiywc`
  converts borrowed batches back to owned entries and asserts exact `(key, data)`
  equality against the byte walker over empty, point, partial, and full ranges
  across two warm-cache passes.

## Alien Primitive Contract

Change: Arc-backed zero-copy leaf payload batches for Btrfs parsed-node walks.

Hotspot evidence: full-range `parsed_cached` walk was materialization-bound
after parsed-node caching; borrowed batches remove per-item `Vec<u8>` allocation
and payload copy.

Mapped graveyard sections: FrankenFS profile queue (cache/metadata contention),
cache-oblivious / data-layout primitives, and zero-copy I/O/data movement.

Fallback trigger: if a downstream consumer requires owned entry lifetime, convert
the batch with `BtrfsLeafEntryBatch::to_owned_entries`, which is byte-identical
to the previous API.

Rollback: revert the `bd-eiywc` evidence/test/bench commit; the primitive itself
is included in `2a9c228f`.

## Next Route

Do not repeat RaptorQ/LRC microkernel families for this pass. The next ready
perf bead is `bd-dy41g`: zero-copy ranged reads directly into the caller output
slice, a separate data-movement primitive already filed in Beads.
