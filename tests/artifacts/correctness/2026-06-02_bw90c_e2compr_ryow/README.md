# bd-bw90c — sequential e2compr write corruption: FIXED

**Crate:** `ffs-core` · **Type:** data-corruption fix (production-reachable)

## Symptom
Writing a compressed (`EXT4_COMPR_FL`) file in sequential chunks (how the FUSE
kernel layer splits a large userspace write — FrankenFS does not raise
`max_write`) corrupted a cluster on readback:
`Corruption { detail: "e2compr: compressed cluster too small for header" }`.
A single `fs.write` of the same data roundtripped fine.

## Root cause
The e2compr write path runs with **no transaction** (`with_latest_scope` →
`RequestScope::with_snapshot(begin)`, `scope.tx = None`). `write_block_ptr`
writes the indirect block via `block_device_adapter()` — an `MvccBlockDevice`
at the **current** snapshot, committing new MVCC versions at increasing seqs.
But `read_block_with_scope` step 2 read `read_visible` at the **fixed begin
snapshot**, so in-scope writes (seq > begin) were invisible. Once an indirect
block already existed at scope begin (a prior chunk's committed block), each
per-slot read-modify-write read the stale begin-version and overwrote it,
**losing intermediate pointer-slot writes** → the cluster's data pointer read
back as 0. (A single write worked only because the indirect block didn't exist
at begin, so reads fell through to the current-snapshot device adapter.)

The entire MvccStore layer was exonerated first by three passing regression
tests (`disjoint_proof_*` 2-RMW / 40-RMW / cluster-pattern+prune) — the defect
was purely the ffs-core fixed-snapshot vs current-snapshot read/write split.

## Fix
In `read_block_with_scope` / `read_block_arc_with_scope`, do the fixed-snapshot
MVCC read (step 2) **only for transaction-backed scopes** (which need
isolation). No-tx scopes fall through to the current-snapshot device adapter
(step 3), making their reads consistent with their writes → read-your-writes.

## Proof
- `compressed_write_reaching_double_indirect_roundtrips_ext4` (chunked >4 MiB
  compressed write, reaching `i_block[13]` double-indirect) now **passes**
  byte-for-byte — was the failing repro; also satisfies bd-1c9h7's
  double-indirect coverage.
- **Full ffs-core lib suite: 890 passed, 0 failed** — no isolation/behavior
  regression from the read-primitive change.
- ffs-mvcc + ffs-fuse suites green; clippy clean; `#![forbid(unsafe_code)]`.
