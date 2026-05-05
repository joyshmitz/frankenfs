#!/usr/bin/env bash
# validate_br_dotted_id_roundtrip.sh - regression guard for bd-suf84.
#
# This smoke copies the live tracker into an isolated fixture workspace, then
# proves current br handles dotted parent/child IDs without losing records.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

PARENT_ID="${BR_DOTTED_PARENT_ID:-bd-rchk0.5.6}"
CHILD_ID="${BR_DOTTED_CHILD_ID:-bd-rchk0.5.6.1}"
RELATED_TARGET_ID="${BR_DOTTED_RELATED_TARGET_ID:-bd-rchk0.4.1}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

require_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        e2e_fail "required tool missing: $tool"
    fi
}

e2e_init "validate_br_dotted_id_roundtrip"
# Preserve the temp workspace as part of the proof artifact. This repo forbids
# automated file deletion, including cleanup of directories created by a smoke.
E2E_CLEANUP_ITEMS=()

require_tool br
require_tool jq
require_tool python3
require_tool sha256sum

FIXTURE_ROOT="$E2E_LOG_DIR/fixture_repo"
FIXTURE_BEADS="$FIXTURE_ROOT/.beads"
COMMAND_DIR="$E2E_LOG_DIR/commands"
COMMAND_TRANSCRIPT="$E2E_LOG_DIR/command_transcript.tsv"
REPORT_JSON="$E2E_LOG_DIR/br_dotted_id_roundtrip_report.json"
FIXTURE_DB="$FIXTURE_BEADS/br-dotted-roundtrip.db"

mkdir -p "$FIXTURE_BEADS" "$COMMAND_DIR"
cp "$REPO_ROOT/.beads/issues.jsonl" "$FIXTURE_BEADS/issues.jsonl"

printf 'id\tworkdir\texit_code\tstdout\tstderr\targv\n' >"$COMMAND_TRANSCRIPT"

run_fixture_cmd() {
    local id="$1"
    shift
    local stdout_path="$COMMAND_DIR/${id}.stdout"
    local stderr_path="$COMMAND_DIR/${id}.stderr"
    local rc=0

    (
        cd "$FIXTURE_ROOT"
        "$@"
    ) >"$stdout_path" 2>"$stderr_path" || rc=$?

    {
        printf '%s\t%s\t%s\t%s\t%s' "$id" "$FIXTURE_ROOT" "$rc" "$stdout_path" "$stderr_path"
        for arg in "$@"; do
            printf '\t%s' "$arg"
        done
        printf '\n'
    } >>"$COMMAND_TRANSCRIPT"

    if [[ "$rc" -ne 0 ]]; then
        e2e_log "Command failed: $id exit=$rc"
        e2e_log "stderr:"
        sed -n '1,120p' "$stderr_path" | while IFS= read -r line; do
            e2e_log "  $line"
        done
        return "$rc"
    fi
}

jsonl_count() {
    jq -s 'length' "$1"
}

assert_json_field() {
    local path="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$path" >/dev/null; then
        e2e_log "JSON assertion failed in $path: $message"
        return 1
    fi
}

INITIAL_COUNT="$(jsonl_count "$FIXTURE_BEADS/issues.jsonl")"
INITIAL_HASH="$(sha256sum "$FIXTURE_BEADS/issues.jsonl" | awk '{print $1}')"
BR_VERSION="$(br --version)"

e2e_step "Scenario 1: exact no-db lookup preserves dotted parent and child"
run_fixture_cmd "no_db_show_parent_initial" br show "$PARENT_ID" --no-db --json
run_fixture_cmd "no_db_show_child_initial" br show "$CHILD_ID" --no-db --json
if assert_json_field "$COMMAND_DIR/no_db_show_parent_initial.stdout" ".[0].id == \"$PARENT_ID\"" "parent id mismatch" \
    && assert_json_field "$COMMAND_DIR/no_db_show_child_initial.stdout" ".[0].id == \"$CHILD_ID\"" "child id mismatch"; then
    scenario_result "br_dotted_no_db_exact_lookup" "PASS" "parent and child IDs are exact"
else
    scenario_result "br_dotted_no_db_exact_lookup" "FAIL" "exact lookup failed"
fi

e2e_step "Scenario 2: no-db update targets parent without dropping child"
run_fixture_cmd "no_db_update_parent_notes" br update "$PARENT_ID" \
    --notes "bd-suf84 fixture exact parent update proof" \
    --no-db --json
run_fixture_cmd "no_db_show_parent_after_update" br show "$PARENT_ID" --no-db --json
run_fixture_cmd "no_db_show_child_after_update" br show "$CHILD_ID" --no-db --json
AFTER_UPDATE_COUNT="$(jsonl_count "$FIXTURE_BEADS/issues.jsonl")"
if [[ "$AFTER_UPDATE_COUNT" == "$INITIAL_COUNT" ]] \
    && assert_json_field "$COMMAND_DIR/no_db_show_parent_after_update.stdout" ".[0].notes == \"bd-suf84 fixture exact parent update proof\"" "parent notes not updated" \
    && assert_json_field "$COMMAND_DIR/no_db_show_child_after_update.stdout" ".[0].id == \"$CHILD_ID\"" "child missing after update"; then
    scenario_result "br_dotted_no_db_parent_update" "PASS" "count preserved at $AFTER_UPDATE_COUNT"
else
    scenario_result "br_dotted_no_db_parent_update" "FAIL" "no-db update changed count or lost child"
fi

e2e_step "Scenario 3: no-db dependency add keeps graph acyclic"
run_fixture_cmd "no_db_dep_add_parent_related" br dep add "$PARENT_ID" "$RELATED_TARGET_ID" \
    --type related --no-db --json
run_fixture_cmd "no_db_dep_add_child_parent" br dep add "$CHILD_ID" "$PARENT_ID" \
    --type related --no-db --json
run_fixture_cmd "no_db_dep_cycles" br dep cycles --no-db --json
AFTER_DEP_COUNT="$(jsonl_count "$FIXTURE_BEADS/issues.jsonl")"
if [[ "$AFTER_DEP_COUNT" == "$INITIAL_COUNT" ]] \
    && assert_json_field "$COMMAND_DIR/no_db_dep_add_parent_related.stdout" ".issue_id == \"$PARENT_ID\" and .depends_on_id == \"$RELATED_TARGET_ID\" and (.action == \"added\" or .action == \"already_exists\")" "parent dependency add mismatch" \
    && assert_json_field "$COMMAND_DIR/no_db_dep_add_child_parent.stdout" ".issue_id == \"$CHILD_ID\" and .depends_on_id == \"$PARENT_ID\" and (.action == \"added\" or .action == \"already_exists\")" "child dependency add mismatch" \
    && assert_json_field "$COMMAND_DIR/no_db_dep_cycles.stdout" ".count == 0" "dependency cycle detected"; then
    scenario_result "br_dotted_no_db_dependency_add" "PASS" "dependency operations preserved count and cycles=0"
else
    scenario_result "br_dotted_no_db_dependency_add" "FAIL" "dependency operation failed"
fi

e2e_step "Scenario 4: fresh DB import preserves exact dotted IDs"
run_fixture_cmd "db_import_only" br sync --import-only --db "$FIXTURE_DB" --no-auto-flush --json
run_fixture_cmd "db_show_parent_after_import" br show "$PARENT_ID" \
    --db "$FIXTURE_DB" --no-auto-flush --no-auto-import --json
run_fixture_cmd "db_show_child_after_import" br show "$CHILD_ID" \
    --db "$FIXTURE_DB" --no-auto-flush --no-auto-import --json
run_fixture_cmd "db_list_all_after_import" br list --all --limit 0 \
    --db "$FIXTURE_DB" --no-auto-flush --no-auto-import --json
DB_IMPORT_COUNT="$(jq '.issues | length' "$COMMAND_DIR/db_list_all_after_import.stdout")"
if [[ "$DB_IMPORT_COUNT" == "$INITIAL_COUNT" ]] \
    && assert_json_field "$COMMAND_DIR/db_show_parent_after_import.stdout" ".[0].id == \"$PARENT_ID\"" "DB parent missing after import" \
    && assert_json_field "$COMMAND_DIR/db_show_child_after_import.stdout" ".[0].id == \"$CHILD_ID\"" "DB child missing after import"; then
    scenario_result "br_dotted_db_import_exact_lookup" "PASS" "fresh DB count=$DB_IMPORT_COUNT"
else
    scenario_result "br_dotted_db_import_exact_lookup" "FAIL" "fresh DB import lost dotted IDs"
fi

e2e_step "Scenario 5: DB update and flush preserve issue count"
run_fixture_cmd "db_update_parent_priority" br update "$PARENT_ID" --priority 1 \
    --db "$FIXTURE_DB" --no-auto-flush --no-auto-import --json
run_fixture_cmd "db_dep_add_parent_related" br dep add "$PARENT_ID" "$RELATED_TARGET_ID" \
    --type related --db "$FIXTURE_DB" --no-auto-flush --no-auto-import --json
run_fixture_cmd "db_sync_flush_only" br sync --flush-only --db "$FIXTURE_DB" --no-auto-import --json
AFTER_FLUSH_COUNT="$(jsonl_count "$FIXTURE_BEADS/issues.jsonl")"
AFTER_FLUSH_HASH="$(sha256sum "$FIXTURE_BEADS/issues.jsonl" | awk '{print $1}')"
run_fixture_cmd "no_db_show_parent_after_flush" br show "$PARENT_ID" --no-db --json
run_fixture_cmd "no_db_show_child_after_flush" br show "$CHILD_ID" --no-db --json
if [[ "$AFTER_FLUSH_COUNT" == "$INITIAL_COUNT" ]] \
    && assert_json_field "$COMMAND_DIR/no_db_show_parent_after_flush.stdout" ".[0].id == \"$PARENT_ID\"" "parent missing after flush" \
    && assert_json_field "$COMMAND_DIR/no_db_show_child_after_flush.stdout" ".[0].id == \"$CHILD_ID\"" "child missing after flush"; then
    scenario_result "br_dotted_db_flush_preserves_count" "PASS" "flush count=$AFTER_FLUSH_COUNT hash=$AFTER_FLUSH_HASH"
else
    scenario_result "br_dotted_db_flush_preserves_count" "FAIL" "flush lost records"
fi

e2e_step "Scenario 6: log contract and report fields"
python3 - "$REPORT_JSON" "$COMMAND_TRANSCRIPT" "$FIXTURE_ROOT" "$FIXTURE_DB" \
    "$INITIAL_COUNT" "$AFTER_UPDATE_COUNT" "$AFTER_DEP_COUNT" "$DB_IMPORT_COUNT" \
    "$AFTER_FLUSH_COUNT" "$INITIAL_HASH" "$AFTER_FLUSH_HASH" "$BR_VERSION" \
    "$PARENT_ID" "$CHILD_ID" "$RELATED_TARGET_ID" "$REPO_ROOT" <<'PY'
import csv
import json
import pathlib
import sys
from datetime import datetime, timezone

(
    report_path,
    transcript_path,
    fixture_root,
    db_path,
    initial_count,
    after_update_count,
    after_dep_count,
    db_import_count,
    after_flush_count,
    initial_hash,
    after_flush_hash,
    br_version,
    parent_id,
    child_id,
    related_target_id,
    repo_root,
) = sys.argv[1:]

commands = []
with open(transcript_path, encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    for row in reader:
        argv = [row.get("argv", "")]
        argv.extend(row.get(None) or [])
        commands.append(
            {
                "id": row["id"],
                "workdir": row["workdir"],
                "exit_code": int(row["exit_code"]),
                "stdout_path": row["stdout"],
                "stderr_path": row["stderr"],
                "argv": argv,
            }
        )

required_command_ids = {
    "no_db_show_parent_initial",
    "no_db_show_child_initial",
    "no_db_update_parent_notes",
    "no_db_dep_add_parent_related",
    "no_db_dep_add_child_parent",
    "db_import_only",
    "db_show_parent_after_import",
    "db_show_child_after_import",
    "db_update_parent_priority",
    "db_dep_add_parent_related",
    "db_sync_flush_only",
    "no_db_show_parent_after_flush",
    "no_db_show_child_after_flush",
}
observed_ids = {command["id"] for command in commands}
missing_ids = sorted(required_command_ids - observed_ids)
if missing_ids:
    raise SystemExit(f"missing commands: {missing_ids}")
if any(command["exit_code"] != 0 for command in commands):
    failed = [command["id"] for command in commands if command["exit_code"] != 0]
    raise SystemExit(f"failed commands: {failed}")

report = {
    "schema_version": 1,
    "scenario_id": "br_dotted_roundtrip_log_contract",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "br_version": br_version,
    "source_jsonl_path": f"{repo_root}/.beads/issues.jsonl",
    "fixture_root": fixture_root,
    "fixture_jsonl_path": f"{fixture_root}/.beads/issues.jsonl",
    "db_path": db_path,
    "parent_id": parent_id,
    "child_id": child_id,
    "related_target_id": related_target_id,
    "counts": {
        "initial": int(initial_count),
        "after_no_db_update": int(after_update_count),
        "after_no_db_dependency_add": int(after_dep_count),
        "after_db_import": int(db_import_count),
        "after_flush": int(after_flush_count),
    },
    "hashes": {
        "initial_jsonl_sha256": initial_hash,
        "after_flush_jsonl_sha256": after_flush_hash,
    },
    "command_transcript": transcript_path,
    "commands": commands,
    "required_proof": [
        "exact no-db lookup for dotted parent",
        "exact no-db lookup for dotted child",
        "no-db update of dotted parent",
        "no-db dependency add involving dotted parent and child",
        "fresh DB import from fixture JSONL",
        "DB exact lookup for dotted parent and child",
        "DB update and flush-only export",
        "post-flush no-db exact lookup",
    ],
    "reproduction_command": "scripts/e2e/validate_br_dotted_id_roundtrip.sh",
    "outcome": "PASS",
}
pathlib.Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if [[ -f "$REPORT_JSON" ]] \
    && grep -q '"source_jsonl_path"' "$REPORT_JSON" \
    && grep -q '"db_path"' "$REPORT_JSON" \
    && grep -q '"command_transcript"' "$REPORT_JSON" \
    && grep -q '"reproduction_command"' "$REPORT_JSON"; then
    scenario_result "br_dotted_roundtrip_log_contract" "PASS" "report=$REPORT_JSON"
else
    scenario_result "br_dotted_roundtrip_log_contract" "FAIL" "report missing required fields"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_fail "br dotted-id roundtrip validation failed: pass=$PASS_COUNT fail=$FAIL_COUNT total=$TOTAL"
fi

e2e_log "Report: $REPORT_JSON"
e2e_log "Fixture workspace: $FIXTURE_ROOT"
e2e_log "Command transcript: $COMMAND_TRANSCRIPT"
e2e_pass
