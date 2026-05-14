# Tracker Hygiene Runbook

FrankenFS uses Beads as the source of truth for work selection, but the
JSONL store can occasionally contain rows that clearly belong to another
project. Treat those rows as triage pollution first, not as data to delete or
close.

This runbook covers source-scoped diagnosis, safe handoff, and the criteria
for enabling strict tracker hygiene gates.

## Current Classifier

FrankenFS-local tracker rows use IDs beginning with:

- `bd-`
- `frankenfs-`

Rows with other prefixes are reported as foreign-looking by
`scripts/e2e/ffs_tracker_source_hygiene_e2e.sh`. The classifier is deliberately
prefix-based because historical foreign rows may still have `source_repo: "."`
after JSONL import or cross-repo copy mistakes.

## Diagnosis

Use no-db or direct JSONL commands when SQLite state, `bv`, or `br ready`
appears polluted.

List foreign-looking open rows:

```bash
jq -s '[.[] | select(((.id // "") | test("^(bd|frankenfs)-") | not) and ((.status // "open") == "open")) | {id,title,status,priority,source_repo}]' .beads/issues.jsonl
```

List FrankenFS-local open rows:

```bash
jq -s '[.[] | select(((.id // "") | test("^(bd|frankenfs)-")) and ((.status // "open") == "open")) | {id,title,status,priority,issue_type,assignee,owner}] | sort_by(.priority, .id)' .beads/issues.jsonl
```

Emit the structured report:

```bash
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Run the reusable Rust classifier directly when a tool wants the queue-state JSON
without the E2E wrapper artifacts:

```bash
ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl
```

The report writes `tracker_source_hygiene_report.json` under
`artifacts/e2e/<run>_ffs_tracker_source_hygiene/` and includes:

- `local_open_rows`
- `source_aware_ready_rows`
- `source_aware_queue_state`
- `local_graph_exports`
- `permission_gated_rows`
- `blocked_local_rows`
- `local_in_progress_rows`
- `stale_in_progress_rows`
- `excluded_foreign_open_count`
- `excluded_foreign_by_prefix`
- `foreign_group_summaries`
- `foreign_open_samples`
- `reproduction_commands`

`source_aware_ready_rows` excludes local rows that require an explicit
permission ACK until the ACK is present in the environment. Permission-gated
rows are still reported under `permission_gated_rows` with the required env
name and value so agents can distinguish "ready after operator authorization"
from ordinary ready work. Current gates are:

| Gate | Required environment |
|---|---|
| real xfstests execution | `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` |
| permissioned large-host swarm execution | `FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1` and `FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host` |

`source_aware_queue_state` is the one-field queue verdict for agents. It
includes `claimable_count`, `local_epic_count`, `blocked_local_count`,
`permission_gated_count`, `local_in_progress_count`,
`stale_in_progress_count`, `excluded_foreign_open_count`, the matching ID
lists, and `next_safe_actions`. If `verdict` is not `ready`, do not claim
ordinary work from raw `br` or `bv` output until you have checked this field.

`local_in_progress_rows` reports FrankenFS-local rows already claimed by an
agent. `stale_in_progress_rows` is the subset whose `updated_at` or `created_at`
timestamp is older than `TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS`
(default: 21600 seconds). Missing or unparsable activity timestamps are treated
as stale. A stale row is only a reclaim candidate after checking Agent Mail and
the worktree; the report does not reopen or mutate it.

Ordinary non-strict live runs also spawn the deterministic fixture/golden
self-check by default, so the standard agent queue probe catches report-shape
drift without extra environment variables. Set
`TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0` only when debugging the
live tracker report in isolation.

For direct deterministic fixture runs,
`TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN` compares a canonicalized report against a
checked-in JSON golden. Canonicalization scrubs the run ID, timestamp, input
path, and generated artifact paths, but keeps queue state, local rows, stale
rows, permission gates, foreign summaries, export metadata, and reproduction
commands exact. Set `TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH=1` with the
same golden to run a negative self-test that intentionally corrupts an
artifact-local golden copy and passes only if the diff rejects it.

The same run writes local-only JSONL graph inputs next to the report:

- `tracker_source_hygiene_local_open.jsonl`
- `tracker_source_hygiene_source_aware_ready.jsonl`
- matching `.sha256` checksum files

Use these exports when a graph or ready-work tool reads the contaminated full
JSONL store. `local_open` contains full original FrankenFS-local open rows,
including dependencies. `source_aware_ready` contains only claimable local rows:
it excludes epics, blocked rows, foreign-looking rows, and permission-gated
rows until the required ACK is present. These artifacts are copies; generating
them does not close, rewrite, delete, or rename any tracker row.

## Serialized Report Coverage Gate

When source-aware triage produces another missing JSON/report-shape bead, run
the report schema inventory gate before filing an ad hoc follow-up:

```bash
ffs-harness validate-report-schema-inventory \
  --out artifacts/report-schema-inventory/report.json \
  --summary-out artifacts/report-schema-inventory/report.md
```

The E2E wrapper is:

```bash
./scripts/e2e/ffs_report_schema_inventory_e2e.sh
```

This gate is non-permissioned and read-only. It emits
`product_evidence_claim=none`, `uncovered_required_report_ids`, deterministic
row results, row-scoped missing-evidence tokens, and a reproduction command.
Use uncovered required rows as the source for narrow report-coverage beads; do
not treat the report as a proof-bundle pass, xfstests result, mounted mutation
result, or large-host swarm campaign result.

## Reconciliation Rules

Do not delete, rewrite, close, or rename foreign-looking rows merely because
they pollute local triage. Those rows may be the only audit record for another
project.

Before any mutation is proposed:

1. Capture the source-scoped report artifact.
2. Group foreign rows by prefix and likely owner project.
3. Search Agent Mail for related threads if the owner is not obvious.
4. Contact the current or likely owner using Agent Mail.
5. Record the exact proposed mutation and wait for explicit authorization.

If authorization is absent, leave the rows intact. Work around the pollution
with the source-aware report or no-db JSONL filters.

## Agent Mail Handoff

Use a dedicated thread when foreign rows need owner review:

```text
thread_id: tracker-hygiene
subject: [tracker-hygiene] Foreign row ownership check: <prefix>
```

Include:

- Report artifact path
- Foreign prefix and sample IDs
- Why the rows appear non-FrankenFS
- Proposed action, if any
- Confirmation that no mutation has happened yet

Use `cc` sparingly. Message only agents likely to own the source project or the
current tracker operation. If a file reservation exists for `.beads/issues.jsonl`,
do not bypass it.

## Strict Mode

`TRACKER_SOURCE_HYGIENE_STRICT=1` fails when foreign-looking open rows exist.
Strict mode is suitable only after all of these are true:

- `excluded_foreign_open_count` is zero in a fresh report.
- Any previous foreign row group has an Agent Mail handoff or owner decision.
- `.beads/issues.jsonl` has no active peer reservation.
- `br dep cycles --no-db --json` reports zero cycles.
- A default non-strict report still emits valid `local_open_rows` and
  `source_aware_ready_rows`, a valid `source_aware_queue_state`, plus
  checksum-validated local graph exports.

Run strict mode as:

```bash
TRACKER_SOURCE_HYGIENE_STRICT=1 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

If strict mode fails, do not weaken the gate or delete rows to make it pass.
Return to diagnosis and owner handoff.

## Fixture Validation

The deterministic classifier fixture lives at
`tests/fixtures/tracker_source_hygiene.jsonl`.

Validate the fixture contract:

```bash
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=5 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN=tests/fixtures/tracker_source_hygiene_report.golden.json \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=4 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Strict fixture validation should fail closed while the fixture contains foreign
open rows:

```bash
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_STRICT=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=5 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=4 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

The strict command returning nonzero is expected for this fixture.
