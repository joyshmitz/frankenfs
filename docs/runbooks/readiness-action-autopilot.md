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
safety class, evidence tier, diagnostics, public-claim effect, and, when known,
Agent Mail thread ids plus reservation/proof artifact paths. Use the controlling
bead as the Beads traceability anchor and the supplied mail thread as the
coordination thread.

Local-safe actions may be claimed and executed by an agent after normal file
reservation checks. Permissioned, destructive, or stale-evidence actions require
explicit operator authorization before the reproduction command is run.

Do not treat a dry-run recommendation as product evidence. A dry-run report can
justify opening or prioritizing work, but public readiness claims must remain
tied to real proof bundles, operational readiness reports, host capability
artifacts, or xfstests result artifacts.

## Claimability And RCH Advisory Inputs

The dry-run planner may consume claimability-plan reports and RCH proof ledgers
as advisory operator evidence. These inputs are intentionally weaker than
product proof:

| Advisory input | Allowed use | Forbidden claim effect |
|---|---|---|
| claimability plan | choose the next safe bead, carry the Agent Mail thread id, preserve reservation artifact paths, and copy exact safe-next commands | claim a raw bv parent epic, mutate foreign tracker rows, or improve a readiness percentage |
| permission-gated claimability row | block the action until the exact ACK is present | satisfy xfstests, mount, or large-host evidence requirements |
| degraded RCH proof ledger | preserve worker id, remote exit status, transcript path, and artifact retrieval warning for operator review | treat `[RCH] local` fallback as proof or upgrade public readiness from proof capture alone |

When a claimability plan reports zero safe claims and raw bv recommends a parent
epic, the readiness action output must stay handoff-only: it may explain that
the parent-epic suggestion was suppressed, but it must not recommend claiming
the parent epic. Every claimability/RCH recommendation must keep
`public_claim_effect` at `no_change`, `block_upgrade`, or `downgrade_required`;
`upgrade_eligible` is reserved for authoritative product evidence.

## Advisory Readiness Lab Handoff

Use the non-permissioned readiness lab when operators or agents need fresh
advisory context before a destructive xfstests run or a permissioned large-host
swarm campaign is approved:

```bash
AGENT_NAME="${AGENT_NAME:-operator}" ./scripts/e2e/ffs_readiness_lab_e2e.sh
```

The generated package lives under
`artifacts/e2e/<timestamp>_ffs_readiness_lab/readiness_lab/` and includes
`readiness_lab_combined_manifest.json`, `command_transcript.tsv`, `logs/`, and
per-lane directories for contracts, host simulation, RCH scheduling, truth
graphs, permissioned-campaign handoff packets, NUMA/p99 replay, and dashboard
rendering. These reports are advisory only: each claim must remain tied to
`product_evidence_claim=none` and
`advisory_only_no_public_readiness_change`.

| Advisory artifact type | Allowed use | Forbidden claim effect |
|---|---|---|
| readiness-lab contract bundle | verify schema, freshness, and claim-effect fields | mark any proof-bundle lane as `pass` |
| host capability simulation | preview CPU, RAM, NUMA, storage, runner, and ACK blockers | upgrade `swarm.responsiveness` |
| RCH lane dry-run schedule | plan command order, target dirs, env allowlist, and artifact destinations | claim cargo check, test, or clippy execution occurred |
| truth graph | connect advisory reports, blockers, beads, and source paths | override authoritative proof-bundle, release-gate, or operational-evidence decisions |
| xfstests rehearsal packet | prepare the exact ACK, command plan, cleanup plan, and raw artifact roots | satisfy `xfstests.baseline` |
| NUMA/p99 replay fixture report | rehearse contention-shape parsing and p99 attribution | satisfy performance or swarm responsiveness readiness |
| readiness dashboard advisory rows | expose source-linked `advisory_only`, `handoff_only`, or blocked states | set `release_ready=true` |

Transitioning from advisory to authoritative evidence requires a new
permissioned run, not wording changes. For xfstests, the operator must provide
`XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` plus
scoped `XFSTESTS_DIR`, `TEST_DIR`, `SCRATCH_MNT`, and `RESULT_BASE`. For the
large-host swarm lane, the operator must provide
`FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1`,
`FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host`,
`FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER`, and
`FFS_SWARM_WORKLOAD_ARTIFACT_ROOT`. Preserve raw logs, cleanup status, command
transcripts, and proof-bundle lane candidates, then let the release gate decide
whether public readiness wording can change.

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
