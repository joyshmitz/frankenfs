# Repair Writeback Serialization Contract

**Status:** Enabled V1.x read-write repair gate after route/race evidence
**Beads:** `bd-rchk0.1.1` through `bd-rchk0.1.4`
**Executable contracts:** `docs/repair-writeback-serialization-contract.json` (historical fail-closed gate) and `scripts/e2e/ffs_repair_writeback_route_e2e.sh` (current enablement gate)

## Current Policy

Mounted automatic repair may mutate only when the operator explicitly starts
`ffs mount --background-repair --background-scrub-ledger <jsonl>`. Read-write
mounts keep background scrub disabled by default, so read-write repair requires
the same explicit flag pair plus `--rw`.

Read-write mounted repair is enabled only through the mounted MVCC request-scope
authority. The scrub daemon captures the bytes observed at repair-planning time;
the mounted writeback path compares those bytes against the current mounted view
before staging recovered source blocks. If client writes changed the block after
scrub planned the repair, the repair writeback fails closed and repair-symbol
refresh is suppressed.

The original `bd-rchk0.1.1` JSON contract remains as a regression artifact for
the pre-serializer fail-closed policy. The current release gate is the route and
race smoke, which proves the serializer exists, stale snapshots reject, kernel
FUSE `writeback_cache` stays disabled, and the CLI enables read-write repair only
with durable ledger evidence.

## State Machine

The checked JSON contract defines the historical fail-closed states and
transition guards. The current V1.x enabled path is:

```text
detection_only_scrub -> repair_planning -> repair_lease_held
  -> repair_writeback_staged -> repair_symbol_refresh
```

That path can inspect, plan, log, stage recovered source blocks through the
mounted MVCC serializer, flush durable bytes, and refresh repair symbols. The
stale read-write rejection path is:

```text
mounted_view != scrub_time_expected_current
  -> repair_writeback_blocked_rw
  error_class = stale_repair_writeback_rejected
```

The historical missing-serializer rejection remains valuable because any future
refactor that bypasses the mounted authority should fall back to refusal rather
than direct-device mutation on a read-write mount.

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

The accepted expected-loss decision is now
`enable_with_mounted_mvcc_serializer`. The rejected decision remains
`enable_rw_repair_without_serializer`.

The enabled path has implementation cost and a small latency cost, but it keeps
repair writeback and client writes behind the same mounted mutation authority.
The unserialized mutating path risks replacing newer client data with decoded
stale data and then refreshing repair symbols around the stale state. That is a
silent corruption failure, so any path without the mounted serializer must still
reject even if the repair engine itself can decode a block correctly.

## Follow-Up Requirements

`repair.rw.writeback` may remain enabled only while these proofs stay green:

- executable trace/state tests for the historical fail-closed contract;
- mounted MVCC serializer routing for recovered source blocks;
- repair-symbol freshness proof against mounted write epochs;
- interrupted writeback proof that refuses symbol refresh and preserves repro
  artifacts;
- CLI/E2E evidence that missing ledgers, stale snapshots, and unsafe
  writeback-cache state fail before user data can be overwritten.
