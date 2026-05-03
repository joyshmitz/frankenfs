#!/usr/bin/env bash
# ffs_ambition_evidence_matrix_e2e.sh - smoke gate for bd-rchk0.5.10.1.
#
# Validates that the ambition evidence matrix is exported, renders a report,
# groups rows by acceptance dimensions, exposes required log tokens, and keeps
# its unit/schema tests green.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_ambition_evidence_matrix}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

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

e2e_init "ffs_ambition_evidence_matrix"

REPORT_JSON="${E2E_LOG_DIR}/ambition_evidence_matrix_report.json"
REPORT_RAW="${E2E_LOG_DIR}/ambition_evidence_matrix_report.raw"
ISSUES_JSONL="${E2E_LOG_DIR}/issues.jsonl"
UNIT_LOG="$(mktemp)"
cp .beads/issues.jsonl "$ISSUES_JSONL"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod ambition_evidence_matrix" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-ambition-evidence-matrix" crates/ffs-harness/src/main.rs; then
    scenario_result "ambition_matrix_wired" "PASS" "module and CLI command exported"
else
    scenario_result "ambition_matrix_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: CLI renders report"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-ambition-evidence-matrix \
    --issues "$ISSUES_JSONL" >"$REPORT_RAW" 2>&1; then
    if python3 - "$REPORT_RAW" "$REPORT_JSON" <<'PY'
import json
import sys

raw_path, report_path = sys.argv[1], sys.argv[2]
text = open(raw_path, encoding="utf-8", errors="replace").read()
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "matrix_version" in obj:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("matrix JSON object not found in rch output")
PY
    then
        scenario_result "ambition_matrix_report_renders" "PASS" "report JSON rendered"
    else
        scenario_result "ambition_matrix_report_renders" "FAIL" "report JSON missing or invalid"
    fi
else
    scenario_result "ambition_matrix_report_renders" "FAIL" "CLI command failed"
fi

e2e_step "Scenario 3: report groups acceptance dimensions"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
required = [
    "grouped_by_user_risk",
    "grouped_by_security_coverage",
    "grouped_by_remediation_coverage",
    "grouped_by_demo_coverage",
    "grouped_by_budget_status",
    "grouped_by_release_gate_consumer",
]
missing = [key for key in required if not data.get(key)]
if missing:
    raise SystemExit(f"missing groups: {missing}")
if "bd-rchk0.5.14" not in data["grouped_by_budget_status"].get("applicable", []):
    raise SystemExit("budget bead not grouped as applicable")
PY
then
    scenario_result "ambition_matrix_grouping" "PASS" "all grouping dimensions populated"
else
    scenario_result "ambition_matrix_grouping" "FAIL" "grouping validation failed"
fi

e2e_step "Scenario 4: required log contract tokens"
TOKENS_FOUND=0
for token in \
    "matrix_version" \
    "source_bead_ids" \
    "stale_reference_checks" \
    "missing_field_diagnostics" \
    "generated_artifact_paths" \
    "reproduction_command"; do
    if grep -q "\"${token}\"" "$REPORT_JSON"; then
        TOKENS_FOUND=$((TOKENS_FOUND + 1))
    fi
done

if [[ $TOKENS_FOUND -eq 6 ]]; then
    scenario_result "ambition_matrix_log_tokens" "PASS" "all log tokens present"
else
    scenario_result "ambition_matrix_log_tokens" "FAIL" "only ${TOKENS_FOUND}/6 log tokens present"
fi

e2e_step "Scenario 5: unit/schema tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib -- ambition_evidence_matrix \
    2>"$UNIT_LOG" | tee -a "$UNIT_LOG"; then
    TESTS_RUN=$(grep -c "test ambition_evidence_matrix::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 5 ]]; then
        scenario_result "ambition_matrix_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "ambition_matrix_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "ambition_matrix_unit_tests" "FAIL" "unit tests failed"
fi

rm -f "$UNIT_LOG"

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_ambition_evidence_matrix completed"
else
    e2e_fail "ffs_ambition_evidence_matrix failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
