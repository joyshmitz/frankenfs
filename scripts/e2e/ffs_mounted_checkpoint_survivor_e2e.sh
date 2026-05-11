#!/usr/bin/env bash
# ffs_mounted_checkpoint_survivor_e2e.sh - non-permissioned mounted checkpoint survivor gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_mounted_checkpoint_survivor}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"

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
    if isinstance(obj, dict) and "matrix_id" in obj and "scenario_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("mounted checkpoint survivor report JSON object not found")
PY
}

e2e_init "ffs_mounted_checkpoint_survivor"

MATRIX_JSON="$REPO_ROOT/tests/mounted-checkpoint-survivor/mounted_checkpoint_survivor.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/mounted_checkpoint_survivor"
REPORT_JSON="$E2E_LOG_DIR/mounted_checkpoint_survivor_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/mounted_checkpoint_survivor_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/mounted_checkpoint_survivor_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/mounted_checkpoint_survivor_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/mounted_checkpoint_survivor_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/mounted_checkpoint_survivor_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: mounted checkpoint survivor CLI is wired"
if grep -q "pub mod mounted_checkpoint_survivor" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-mounted-checkpoint-survivor" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_mounted_checkpoint_survivor" scripts/e2e/scenario_catalog.json; then
    scenario_result "mounted_checkpoint_survivor_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "mounted_checkpoint_survivor_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in mounted checkpoint survivor matrix validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-mounted-checkpoint-survivor \
    --matrix "$MATRIX_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "mounted_checkpoint_survivor_validates" "PASS" "checked-in matrix accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "mounted_checkpoint_survivor_validates" "FAIL" "checked-in matrix rejected"
fi

e2e_step "Scenario 3: lifecycle and preservation coverage are explicit"
if python3 - "$REPORT_JSON" "$MATRIX_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matrix = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_kinds = {
    "clean_unmount",
    "process_termination_pre_fsync",
    "process_termination_post_fsync",
    "reopen_after_write",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["scenario_count"] < 6:
    raise SystemExit("expected at least six mounted checkpoint scenarios")
missing_kinds = required_kinds - set(report["kinds_seen"])
if missing_kinds:
    raise SystemExit(f"missing lifecycle kinds: {sorted(missing_kinds)}")
policies = {scenario["partial_artifact_policy"] for scenario in matrix["scenarios"]}
if not {"preserve_on_failure", "preserve_always"}.issubset(policies):
    raise SystemExit(f"missing partial artifact preservation policies: {sorted(policies)}")
process_controls = {scenario["process_control"] for scenario in matrix["scenarios"]}
if "kill_minus_nine_refused" not in process_controls:
    raise SystemExit("unsafe kill -9 refusal row is not visible")
PY
then
    scenario_result "mounted_checkpoint_survivor_coverage" "PASS" "lifecycle, preservation, and refusal coverage verified"
else
    scenario_result "mounted_checkpoint_survivor_coverage" "FAIL" "mounted checkpoint survivor coverage contract failed"
fi

e2e_step "Scenario 4: invalid mounted checkpoint survivor matrix fails closed"
jq '.scenarios[0].artifact_paths = []' "$MATRIX_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-mounted-checkpoint-survivor \
    --matrix "$INVALID_JSON"; then
    scenario_result "mounted_checkpoint_survivor_invalid_rejected" "FAIL" "invalid matrix unexpectedly passed"
elif grep -q "artifact_path" "$INVALID_RAW"; then
    scenario_result "mounted_checkpoint_survivor_invalid_rejected" "PASS" "missing artifact path is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "mounted_checkpoint_survivor_invalid_rejected" "FAIL" "invalid matrix failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-mounted-checkpoint-survivor \
    --matrix "$MATRIX_JSON" \
    --format markdown \
    && grep -q "# Mounted Checkpoint Survivor" "$MARKDOWN_RAW" \
    && grep -q "process_termination_post_fsync" "$MARKDOWN_RAW" \
    && grep -q "Mounted Checkpoint Survivor Contract" scripts/e2e/README.md; then
    scenario_result "mounted_checkpoint_survivor_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "mounted_checkpoint_survivor_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: mounted checkpoint survivor unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib mounted_checkpoint_survivor -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_matrix_report_snapshot" \
        "render_mounted_checkpoint_survivor_markdown_default_matrix" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "mounted_checkpoint_survivor_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "mounted_checkpoint_survivor_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Mounted checkpoint survivor matrix: $MATRIX_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Mounted checkpoint survivor scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Mounted checkpoint survivor scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
