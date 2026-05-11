#!/usr/bin/env bash
# ffs_remediation_severity_gate_e2e.sh - non-permissioned remediation severity gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_remediation_severity_gate}"
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
    if isinstance(obj, dict) and "gate_id" in obj and "entry_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("remediation severity gate report JSON object not found")
PY
}

e2e_init "ffs_remediation_severity_gate"

GATE_JSON="$REPO_ROOT/tests/remediation-severity-gate/remediation_severity_gate.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/remediation_severity_gate"
REPORT_JSON="$E2E_LOG_DIR/remediation_severity_gate_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/remediation_severity_gate_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/remediation_severity_gate_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/remediation_severity_gate_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/remediation_severity_gate_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/remediation_severity_gate_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: remediation severity gate CLI is wired"
if grep -q "pub mod remediation_severity_gate" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-remediation-severity-gate" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_remediation_severity_gate" scripts/e2e/scenario_catalog.json; then
    scenario_result "remediation_severity_gate_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "remediation_severity_gate_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in remediation severity gate validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-severity-gate \
    --gate "$GATE_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "remediation_severity_gate_validates" "PASS" "checked-in gate accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "remediation_severity_gate_validates" "FAIL" "checked-in gate rejected"
fi

e2e_step "Scenario 3: outcome coverage and release blockers are explicit"
if python3 - "$REPORT_JSON" "$GATE_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
gate = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_classes = {
    "product_failure",
    "host_capability_skip",
    "unsafe_repair_refusal",
    "low_confidence_repair",
    "missing_proof_lane",
    "inconclusive_oracle_conflict",
    "pass_with_experimental_caveat",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["entry_count"] < 11:
    raise SystemExit("expected at least eleven remediation entries")
if report["block_release_count"] < 4:
    raise SystemExit("expected at least four block_release entries")
missing = required_classes - set(report["outcome_classes_covered"])
if missing:
    raise SystemExit(f"missing outcome classes: {sorted(missing)}")
for entry in gate["entries"]:
    if not entry["docs_target"]:
        raise SystemExit(f"missing docs_target: {entry['remediation_id']}")
    if not entry["artifact_requirements"]:
        raise SystemExit(f"missing artifact requirements: {entry['remediation_id']}")
    has_action = bool(entry["immediate_action_command"].strip())
    has_non_goal = bool(entry.get("explicit_non_goal_rationale", "").strip())
    if has_action == has_non_goal:
        raise SystemExit(f"entry must have exactly one action or non-goal rationale: {entry['remediation_id']}")
PY
then
    scenario_result "remediation_severity_gate_coverage" "PASS" "outcome coverage, blockers, docs, artifacts, and actions verified"
else
    scenario_result "remediation_severity_gate_coverage" "FAIL" "remediation severity coverage contract failed"
fi

e2e_step "Scenario 4: invalid remediation severity gate fails closed"
jq '.entries[0].release_gate_effect = "annotate_caveat"' "$GATE_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-severity-gate \
    --gate "$INVALID_JSON"; then
    scenario_result "remediation_severity_gate_invalid_rejected" "FAIL" "invalid gate unexpectedly passed"
elif grep -q "data_loss_unrecoverable" "$INVALID_RAW"; then
    scenario_result "remediation_severity_gate_invalid_rejected" "PASS" "unrecoverable-loss downgrade is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "remediation_severity_gate_invalid_rejected" "FAIL" "invalid gate failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-severity-gate \
    --gate "$GATE_JSON" \
    --format markdown \
    && grep -q "# Remediation Severity Gate" "$MARKDOWN_RAW" \
    && grep -q "block-release entries" "$MARKDOWN_RAW" \
    && grep -q "Remediation Severity Gate Contract" scripts/e2e/README.md; then
    scenario_result "remediation_severity_gate_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "remediation_severity_gate_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: remediation severity gate unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib remediation_severity_gate -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_gate_validates_required_classes" \
        "render_remediation_severity_gate_markdown_default_gate" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "remediation_severity_gate_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "remediation_severity_gate_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Remediation severity gate: $GATE_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Remediation severity gate scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Remediation severity gate scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
