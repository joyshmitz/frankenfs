# RCH Proof Ledger Runbook

The RCH proof ledger turns a captured `rch` transcript into a machine-readable
record of what happened on the worker. Use it whenever a validation claim relies
on remote cargo output, especially when artifact retrieval warns, stalls, or
falls back locally.

## Generate A Ledger

Capture the raw `rch` output first, then parse it:

```bash
ffs-harness rch-proof-ledger \
  --transcript artifacts/e2e/run/cargo_check.raw \
  --command-arg cargo \
  --command-arg check \
  --command-arg -p \
  --command-arg ffs-harness \
  --command-arg --all-targets \
  --cwd /data/projects/frankenfs \
  --env CARGO_TARGET_DIR \
  --format json \
  --out artifacts/e2e/run/rch_proof_ledger.json \
  --summary-out artifacts/e2e/run/rch_proof_ledger.md
```

The JSON ledger is the contract. The Markdown summary is the operator handoff
surface. Preserve the raw transcript beside both outputs.

## Capacity Preflight

Use the capacity preflight before starting expensive remote-only proof lanes
when `rch status --json` reports degraded posture, no admissible workers,
critical pressure, stale telemetry, or repeated local fallback refusals. The
preflight is not validation proof. It is an infrastructure-blocker artifact
that explains why proof cannot be collected yet.

Default status-only capture:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 ./scripts/e2e/ffs_rch_capacity_preflight_e2e.sh
```

Remote-required probe capture:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_RCH_CAPACITY_PREFLIGHT_RUN_PROBE=1 \
./scripts/e2e/ffs_rch_capacity_preflight_e2e.sh
```

The probe runs:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check -p ffs-error --lib
```

If RCH refuses local fallback, the run still passes as a capacity diagnostic
and records `RCH_LOCAL_FALLBACK_REJECTED` in `result.json`. If the probe
produces neither an RCH remote summary nor a local-fallback refusal, the
preflight fails because the result is ambiguous.

Preserve these artifacts in handoffs:

- `run.log`
- `result.json`
- `rch_status.json`
- `rch_capacity_preflight_report.json`
- `rch_capacity_preflight_summary.md`
- `rch_capacity_probe.raw` when the probe is enabled

Use this wording when RCH capacity blocks validation:

```text
Remote proof is unavailable because the RCH capacity preflight reported
`no_admissible_workers`. This is not product validation proof; rerun the
remote cargo gate after RCH capacity recovers. See
artifacts/e2e/<run>/rch_capacity_preflight_report.json and result.json.
```

## Decision Rules

| Transcript state | Ledger verdict | Operator action |
|---|---|---|
| Worker-side exit=0, worker identity present, no artifact warning | `remote_success` | Treat as sufficient validation proof for the exact command and cwd. |
| Worker-side exit=0 with target retrieval, rsync, or artifact warning | `remote_success_artifact_warning` | Accept the worker-side success only with a degraded-proof note naming the warning and raw transcript path. |
| `[RCH] local (remote execution failed)` | `invalid_local_fallback` | Local fallback is not remote validation proof. Rerun on RCH or report the remote-execution blocker. |
| Remote exit is nonzero | `remote_failure` | Treat as a failed validation or product/tooling failure according to the command. |
| Worker or exit evidence is missing | `missing_remote_evidence` | Do not claim validation; capture a complete transcript first. |
| Capacity preflight reports `no_admissible_workers` or local-fallback refusal | not a proof-ledger verdict | Report an infrastructure blocker and rerun after RCH capacity recovers. |

Worker-side exit=0 is sufficient evidence only when the command, cwd, worker,
and transcript match the claimed gate. A local shell exit code is not enough if
the transcript does not prove remote execution.

## Degraded-Proof Notes

When a target artifact retrieval warning appears after worker success, keep the
remote proof but mark the claim as degraded. The closeout note must name:

- the worker id
- the remote exit code
- the command and cwd
- the raw transcript path
- the retrieval status from `artifact_retrieval_status`
- each warning in `warnings`

Use this wording in handoffs:

```text
Remote worker exit=0 is accepted as validation proof. Target artifact retrieval
reported a warning, so this is a degraded-proof closeout; see
artifacts/e2e/run/cargo_check.raw and rch_proof_ledger.json.
```

## Fixture Gate

The no-worker fixture gate writes synthetic transcript ledgers and validates the
proof boundaries without invoking cargo or a live RCH worker:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 ./scripts/e2e/ffs_rch_proof_ledger_e2e.sh
```

The gate writes JSON and Markdown artifacts under its `artifacts/e2e/...`
directory. It covers clean remote success, degraded artifact warning, and local
fallback rejection.
