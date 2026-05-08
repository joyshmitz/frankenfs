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

The report writes `tracker_source_hygiene_report.json` under
`artifacts/e2e/<run>_ffs_tracker_source_hygiene/` and includes:

- `local_open_rows`
- `source_aware_ready_rows`
- `excluded_foreign_open_count`
- `excluded_foreign_by_prefix`
- `foreign_open_samples`
- `reproduction_commands`

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
  `source_aware_ready_rows`.

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
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=4 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=22 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Strict fixture validation should fail closed while the fixture contains foreign
open rows:

```bash
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_STRICT=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=4 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=22 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

The strict command returning nonzero is expected for this fixture.
