# Repair Writeback Serialization Contract

**Status:** Accepted fail-closed V1.x contract
**Bead:** `bd-rchk0.1.1`
**Executable contract:** `docs/repair-writeback-serialization-contract.json`

## Current Policy

Read-only mounted automatic repair may mutate only when the operator explicitly
starts `ffs mount --background-repair --background-scrub-ledger <jsonl>`.
Read-write mounted automatic repair remains disabled. If read-write mounted
traffic and repair writeback overlap before a unified serializer exists,
FrankenFS must reject repair mutation with
`rw_repair_serialization_missing` and preserve reproduction artifacts.

The failure is intentional. A repair writeback can replace a source block and
refresh repair symbols. If a client write has newer data in flight, stale
repair data would be indistinguishable from a correct repair unless both paths
share the same serialization point.

## State Machine

The checked JSON contract defines the states and transition guards. The V1.x
safe path is:

```text
detection_only_scrub -> repair_planning -> repair_lease_held
```

That path can inspect, plan, and log. It cannot mutate a read-write mounted
image. The current read-write mounted mutation request is:

```text
client_write_in_flight + repair_writeback_requested
  -> repair_writeback_blocked_rw
  error_class = rw_repair_serialization_missing
```

Future mutating read-write repair must first introduce the single serializer
that admits both client writes and repair writeback. Only then can a repair
advance into `repair_writeback_staged` and, after verified durable source-block
writeback, `repair_symbol_refresh`.

## Invariants

The contract freezes eight invariants:

| ID | Requirement |
|----|-------------|
| I1 | Repair observes a named MVCC snapshot epoch and refuses stale epochs |
| I2 | Client writes and repair writeback use one writer serializer |
| I3 | Dirty or merely flushed client data cannot authorize repair mutation |
| I4 | `fsync`/`fsyncdir` are the durability boundaries; `flush` is not |
| I5 | Mutating repair holds an active per-image ownership lease |
| I6 | Repair symbols match the current block generation |
| I7 | Cancellation leaves no hidden partial mutation |
| I8 | Failed source-block writeback refuses repair-symbol refresh |

These invariants are validated by:

```bash
cargo run -p ffs-harness -- validate-repair-writeback-serialization \
  --contract docs/repair-writeback-serialization-contract.json
```

## Evidence Events

Every rejection or future mutation proof must log:

```text
operation_id
scenario_id
snapshot_epoch
lease_id
repair_symbol_version
expected_state
observed_state
error_class
artifact_paths
cleanup_status
reproduction_command
follow_up_bead
```

Those fields are required because a user must be able to answer what was
corrupt, which client-write epoch was visible, which repair symbol generation
was considered, why mutation was refused or allowed, and how to reproduce the
decision.

## Risk Decision

The accepted expected-loss decision is `fail_closed_until_unified_serializer`.
The rejected decision is `enable_rw_repair_without_serializer`.

The fail-closed path has operator friction, but it preserves user data. The
unserialized mutating path risks replacing newer client data with decoded stale
data and then refreshing repair symbols around the stale state. That is a
silent corruption failure, so the contract rejects it even if the repair engine
itself can decode a block correctly.

## Follow-Up Requirements

No public claim may upgrade `repair.rw.writeback` until follow-up beads provide:

- executable trace/state tests for this contract;
- a real unified serializer for client writes and repair writeback;
- repair-symbol freshness proof against mounted write epochs;
- interrupted writeback proof that refuses symbol refresh and preserves repro
  artifacts.
