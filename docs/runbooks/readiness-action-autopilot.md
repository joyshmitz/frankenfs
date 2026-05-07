# Readiness Action Autopilot Runbook

The readiness action autopilot turns existing evidence into operator-reviewed
next actions. It is a dry-run planning surface only: it writes reports and logs,
but it never runs xfstests, mutates mounts, installs packages, or launches
large-host campaigns.

## Generate The Report Pack

Use the harness entrypoint with explicit output paths:

```bash
ffs-harness recommend-readiness-actions \
  --out-json artifacts/readiness/actions/report.json \
  --out-md artifacts/readiness/actions/report.md \
  --stdout-log artifacts/readiness/actions/stdout.log \
  --stderr-log artifacts/readiness/actions/stderr.log \
  --report-id readiness_action_operator_handoff \
  --generated-at 2026-05-07T00:00:00Z \
  --invocation "ffs-harness recommend-readiness-actions --out-json artifacts/readiness/actions/report.json --out-md artifacts/readiness/actions/report.md --stdout-log artifacts/readiness/actions/stdout.log --stderr-log artifacts/readiness/actions/stderr.log"
```

The JSON report is the machine contract. The Markdown report is the operator
handoff view. The stdout and stderr logs are deterministic dry-run evidence for
E2E artifact bundles.

## Agent Handoff

Each recommendation carries a controlling bead, exact reproduction command,
safety class, evidence tier, diagnostics, and public-claim effect. Use the
controlling bead as the Agent Mail thread id and Beads traceability anchor.

Local-safe actions may be claimed and executed by an agent after normal file
reservation checks. Permissioned, destructive, or stale-evidence actions require
explicit operator authorization before the reproduction command is run.

Do not treat a dry-run recommendation as product evidence. A dry-run report can
justify opening or prioritizing work, but public readiness claims must remain
tied to real proof bundles, operational readiness reports, host capability
artifacts, or xfstests result artifacts.

## Permission Boundaries

The following action families stay blocked until the operator provides the
matching authorization and artifact root:

| Action family | Required operator signal | Required artifact evidence |
|---|---|---|
| xfstests baseline | `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` plus explicit TEST_DIR, SCRATCH_MNT, and RESULT_BASE | xfstests logs, pass/fail/not-run counts, command transcript, cleanup status |
| mounted mutation | explicit scratch mount/device authorization | mount logs, before/after state, cleanup status |
| large-host swarm campaign | `FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1`, `FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host`, and a configured permissioned runner | host capability proof, worker identity, raw logs, p99 attribution ledger |
| public readiness upgrade | proof-bundle or authoritative operational evidence newer than the configured freshness TTL | generated report plus source artifact paths |

Smoke evidence can support a blocker or downgrade note, but it must not upgrade
README, FEATURE_PARITY, or release-gate readiness wording.

## Golden Coverage

The pinned readiness-action snapshots cover the four representative planner
states:

| Scenario | Safety outcome | Public claim effect |
|---|---|---|
| local schema work | local-safe | no change |
| xfstests baseline | permissioned and ack-required | block upgrade |
| large-host swarm evidence | permissioned and ack-required | downgrade required |
| contradictory release gate evidence | impossible | block upgrade |

When intentional planner behavior changes, update the snapshots only after
reviewing the JSON and Markdown diff. The snapshot diff is the approval surface;
do not accept it just to make tests pass.
