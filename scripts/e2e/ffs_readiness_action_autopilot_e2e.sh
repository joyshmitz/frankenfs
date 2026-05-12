#!/usr/bin/env bash
# ffs_readiness_action_autopilot_e2e.sh - non-permissioned readiness action gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_readiness_action_autopilot}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-6}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

extract_report_json() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "dry_run" in obj and "planner_result" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("readiness action dry-run JSON report not found")
PY
}

e2e_init "ffs_readiness_action_autopilot"

RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/readiness-action-autopilot"
REPORT_JSON="$E2E_LOG_DIR/readiness_action_autopilot_report.json"
DRY_RUN_RAW="$E2E_LOG_DIR/readiness_action_autopilot_dry_run.raw"
BAD_INPUT_JSON="$RCH_INPUT_DIR/readiness_action_bad_input.json"
BAD_INPUT_RAW="$E2E_LOG_DIR/readiness_action_autopilot_bad_input.raw"
UNIT_LOG="$E2E_LOG_DIR/readiness_action_autopilot_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: readiness action autopilot CLI is wired"
if grep -q "recommend-readiness-actions" crates/ffs-harness/src/main.rs \
    && grep -q "ReadinessActionDryRunReport" crates/ffs-harness/src/readiness_action_autopilot.rs \
    && grep -q "ffs_readiness_action_autopilot" scripts/e2e/scenario_catalog.json; then
    scenario_result "readiness_action_autopilot_cli_wired" "PASS" "CLI command, report schema, and catalog suite are exported"
else
    scenario_result "readiness_action_autopilot_cli_wired" "FAIL" "missing CLI command, report schema, or catalog suite"
fi

e2e_step "Scenario 2: dry-run report pack is emitted"
if e2e_rch_capture "$DRY_RUN_RAW" cargo run --quiet -p ffs-harness -- \
    recommend-readiness-actions \
    --out-json /dev/stdout \
    --out-md /dev/stdout \
    --stdout-log /dev/stdout \
    --stderr-log /dev/stdout \
    --report-id "readiness_action_autopilot_e2e" \
    --generated-at "2026-05-12T00:00:00Z" \
    --invocation "scripts/e2e/ffs_readiness_action_autopilot_e2e.sh" \
    && extract_report_json "$DRY_RUN_RAW" "$REPORT_JSON" \
    && grep -q "# Readiness Action Dry-Run Report" "$DRY_RUN_RAW" \
    && grep -q "readiness-action-dry-run" "$DRY_RUN_RAW" \
    && grep -q "no reproduction commands executed" "$DRY_RUN_RAW"; then
    scenario_result "readiness_action_autopilot_report_pack" "PASS" "JSON, Markdown, stdout, and stderr dry-run outputs were emitted"
else
    cat "$DRY_RUN_RAW"
    scenario_result "readiness_action_autopilot_report_pack" "FAIL" "dry-run command failed"
fi

e2e_step "Scenario 3: dry-run report keeps safety classifications explicit"
if python3 - "$REPORT_JSON" "$DRY_RUN_RAW" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
raw_output = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["dry_run"]:
    raise SystemExit("report must be dry_run")
if report["report_id"] != "readiness_action_autopilot_e2e":
    raise SystemExit("report_id drifted")
if report["generated_at"] != "2026-05-12T00:00:00Z":
    raise SystemExit("generated_at drifted")
metadata = report["command_metadata"]
if metadata["cleanup_status"] != "not_required_dry_run":
    raise SystemExit(f"unexpected cleanup status: {metadata['cleanup_status']}")
output_kinds = {row["kind"] for row in metadata["output_paths"]}
if output_kinds != {"json_report", "markdown_report", "stdout_log", "stderr_log"}:
    raise SystemExit(f"unexpected output paths: {output_kinds}")
scenarios = report["scenarios"]
if len(scenarios) != 4:
    raise SystemExit(f"expected 4 dry-run scenarios, got {len(scenarios)}")
action_ids = {row["action_id"] for row in scenarios}
required_actions = {
    "define-readiness-action-schema",
    "run-permissioned-xfstests-baseline",
    "refresh-large-host-swarm-campaign",
}
if not required_actions <= action_ids:
    raise SystemExit(f"missing required actions: {required_actions - action_ids}")
safety_classes = {row["safety_class"] for row in scenarios}
if not {"local_safe", "permissioned", "impossible"} <= safety_classes:
    raise SystemExit(f"missing safety classes: {safety_classes}")
claim_effects = {row["public_claim_effect"] for row in scenarios}
if "downgrade_required" not in claim_effects and "block_upgrade" not in claim_effects:
    raise SystemExit(f"missing conservative claim effects: {claim_effects}")
if any("no reproduction command was executed" not in row["dry_run_note"] for row in scenarios):
    raise SystemExit("every scenario must carry a dry-run note")
if report["planner_result"]["report"]["recommendations"][0]["safety_class"] != "local_safe":
    raise SystemExit("local-safe recommendation should rank first")
if "# Readiness Action Dry-Run Report" not in raw_output:
    raise SystemExit("markdown heading missing")
for marker in ("LocalSafe", "Permissioned", "DowngradeRequired"):
    if marker not in raw_output:
        raise SystemExit(f"markdown missing {marker}")
PY
then
    scenario_result "readiness_action_autopilot_report_contract" "PASS" "dry-run classifications and conservative claim states verified"
else
    scenario_result "readiness_action_autopilot_report_contract" "FAIL" "dry-run report contract failed"
fi

e2e_step "Scenario 4: deterministic logs prove no commands executed"
if grep -q "readiness-action-dry-run" "$DRY_RUN_RAW" \
    && grep -q "recommendations=4" "$DRY_RUN_RAW" \
    && grep -q "scenarios=4" "$DRY_RUN_RAW" \
    && grep -q "cleanup_status=not_required_dry_run" "$DRY_RUN_RAW" \
    && grep -q "no reproduction commands executed" "$DRY_RUN_RAW" \
    && grep -q "permissioned, destructive, and stale-evidence commands stayed dry-run only" "$DRY_RUN_RAW"; then
    scenario_result "readiness_action_autopilot_dry_run_logs" "PASS" "stdout/stderr logs preserve dry-run safety evidence"
else
    cat "$DRY_RUN_RAW"
    scenario_result "readiness_action_autopilot_dry_run_logs" "FAIL" "dry-run logs missing safety evidence"
fi

e2e_step "Scenario 5: invalid input fails closed"
printf '{"report_id":42}\n' >"$BAD_INPUT_JSON"
if e2e_rch_capture "$BAD_INPUT_RAW" cargo run --quiet -p ffs-harness -- \
    recommend-readiness-actions \
    --input "$BAD_INPUT_JSON" \
    --out-json /dev/stdout \
    --out-md /dev/stdout \
    --stdout-log /dev/stdout \
    --stderr-log /dev/stdout; then
    scenario_result "readiness_action_autopilot_rejects_bad_input" "FAIL" "invalid input unexpectedly passed"
elif grep -q "failed to parse readiness action input" "$BAD_INPUT_RAW" \
    || grep -q "missing field" "$BAD_INPUT_RAW" \
    || grep -q "invalid type" "$BAD_INPUT_RAW"; then
    scenario_result "readiness_action_autopilot_rejects_bad_input" "PASS" "invalid input rejected"
else
    cat "$BAD_INPUT_RAW"
    scenario_result "readiness_action_autopilot_rejects_bad_input" "FAIL" "invalid input failed without actionable diagnostics"
fi

e2e_step "Scenario 6: docs contract is wired"
if grep -q "Readiness Action Autopilot Contract" scripts/e2e/README.md \
    && grep -q "recommend-readiness-actions" docs/runbooks/readiness-action-autopilot.md \
    && grep -q "readiness_action_autopilot_report_pack" scripts/e2e/scenario_catalog.json; then
    scenario_result "readiness_action_autopilot_docs_contract" "PASS" "E2E README, runbook, and catalog references are present"
else
    scenario_result "readiness_action_autopilot_docs_contract" "FAIL" "docs or catalog contract missing"
fi

e2e_step "Scenario 7: readiness action autopilot tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness readiness_action -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_fixture_set_covers_required_schema_surface" \
        "recommend_readiness_actions_cmd_writes_dry_run_report_pack" \
        "dry_run_json_report_matches_golden"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "readiness_action_autopilot_unit_tests" "PASS" "focused readiness action tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "readiness_action_autopilot_unit_tests" "FAIL" "focused readiness action tests failed"
fi

e2e_log "Readiness action report: $REPORT_JSON"
e2e_log "Readiness action raw output: $DRY_RUN_RAW"

if ((FAIL_COUNT == 0)); then
    e2e_log "Readiness action autopilot scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Readiness action autopilot scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
