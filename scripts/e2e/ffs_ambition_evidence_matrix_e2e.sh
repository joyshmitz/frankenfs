#!/usr/bin/env bash
# ffs_ambition_evidence_matrix_e2e.sh - smoke gate for bd-rchk0.5.10.1 / bd-vp5v7.
#
# Validates that the ambition evidence matrix is exported, renders a report,
# groups rows by acceptance dimensions, exposes required log tokens, checks
# consumer contracts, proves stale/missing links fail closed, and keeps tests green.

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
STALE_ISSUES_JSONL="${E2E_LOG_DIR}/issues_stale_reference.jsonl"
MISSING_ARTIFACT_JSONL="${E2E_LOG_DIR}/issues_missing_artifact.jsonl"
STALE_RAW="${E2E_LOG_DIR}/stale_reference.raw"
MISSING_ARTIFACT_RAW="${E2E_LOG_DIR}/missing_artifact.raw"
UNIT_LOG="${E2E_LOG_DIR}/ambition_evidence_matrix_unit_tests.log"
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
    "grouped_by_matrix_status",
]
missing = [key for key in required if not data.get(key)]
if missing:
    raise SystemExit(f"missing groups: {missing}")
if "bd-rchk0.5.14" not in data["grouped_by_budget_status"].get("validated", []):
    raise SystemExit("budget bead not grouped as validated")
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
    "consumer_versions" \
    "stale_reference_checks" \
    "missing_field_diagnostics" \
    "downgrade_decisions" \
    "generated_artifact_paths" \
    "reproduction_command"; do
    if grep -q "\"${token}\"" "$REPORT_JSON"; then
        TOKENS_FOUND=$((TOKENS_FOUND + 1))
    fi
done

if [[ $TOKENS_FOUND -eq 8 ]]; then
    scenario_result "ambition_matrix_log_tokens" "PASS" "all log tokens present"
else
    scenario_result "ambition_matrix_log_tokens" "FAIL" "only ${TOKENS_FOUND}/8 log tokens present"
fi

e2e_step "Scenario 5: required downstream outputs are represented"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
coverage = {
    row["source_bead_id"]: row
    for row in data.get("required_output_coverage", [])
}
required = [
    "bd-rchk0.5.11",
    "bd-rchk0.5.12",
    "bd-rchk0.5.13",
    "bd-rchk0.5.14",
]
missing = [bead for bead in required if bead not in coverage]
unrepresented = [
    bead
    for bead in required
    if bead in coverage and not coverage[bead].get("represented")
]
if missing or unrepresented:
    raise SystemExit(
        f"missing={missing} unrepresented={unrepresented}"
    )
for bead in required:
    if not coverage[bead].get("matrix_fields"):
        raise SystemExit(f"{bead} has no matrix field mapping")
PY
then
    scenario_result "ambition_matrix_required_outputs" "PASS" "required output coverage represented"
else
    scenario_result "ambition_matrix_required_outputs" "FAIL" "required output coverage missing"
fi

e2e_step "Scenario 6: consumer contracts and downgrade decisions are emitted"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
required_consumers = {
    "proof-bundle",
    "release-gates",
    "remediation-catalog",
    "README/FEATURE_PARITY",
    "follow-up-bead",
}
summary_consumers = {
    row["consumer_name"]
    for row in data.get("consumer_summaries", [])
}
contract_consumers = {
    row["consumer_name"]
    for row in data.get("consumer_contracts", [])
}
missing_summaries = required_consumers - summary_consumers
missing_contracts = required_consumers - contract_consumers
if missing_summaries or missing_contracts:
    raise SystemExit(
        f"missing_summaries={sorted(missing_summaries)} "
        f"missing_contracts={sorted(missing_contracts)}"
    )
if not data.get("downgrade_decisions"):
    raise SystemExit("missing downgrade decisions")
for summary in data.get("consumer_summaries", []):
    if not summary.get("consumer_version"):
        raise SystemExit(f"missing consumer version: {summary}")
PY
then
    scenario_result "ambition_matrix_consumer_contracts" "PASS" "consumer summaries and downgrade decisions emitted"
else
    scenario_result "ambition_matrix_consumer_contracts" "FAIL" "consumer contract validation failed"
fi

e2e_step "Scenario 7: stale reference injection fails closed"
python3 - "$ISSUES_JSONL" "$STALE_ISSUES_JSONL" <<'PY'
import json
import sys

source, dest = sys.argv[1], sys.argv[2]
with open(source, encoding="utf-8") as src, open(dest, "w", encoding="utf-8") as out:
    for line in src:
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("id") == "bd-rchk0.5.14":
            continue
        out.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-ambition-evidence-matrix \
    --issues "$STALE_ISSUES_JSONL" >"$STALE_RAW" 2>&1; then
    scenario_result "ambition_matrix_stale_reference_fails" "FAIL" "stale reference unexpectedly passed"
elif grep -q "bd-rchk0.5.14" "$STALE_RAW"; then
    scenario_result "ambition_matrix_stale_reference_fails" "PASS" "stale reference failed closed"
else
    scenario_result "ambition_matrix_stale_reference_fails" "FAIL" "expected stale reference diagnostic missing"
fi

e2e_step "Scenario 8: missing artifact injection fails closed"
python3 - "$ISSUES_JSONL" "$MISSING_ARTIFACT_JSONL" <<'PY'
import json
import sys

source, dest = sys.argv[1], sys.argv[2]
with open(source, encoding="utf-8") as src, open(dest, "w", encoding="utf-8") as out:
    for line in src:
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("id") == "bd-rchk0.5.10.1":
            row["artifact_path"] = ""
        out.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-ambition-evidence-matrix \
    --issues "$MISSING_ARTIFACT_JSONL" >"$MISSING_ARTIFACT_RAW" 2>&1; then
    scenario_result "ambition_matrix_missing_artifact_fails" "FAIL" "missing artifact unexpectedly passed"
elif grep -q "artifact_path" "$MISSING_ARTIFACT_RAW"; then
    scenario_result "ambition_matrix_missing_artifact_fails" "PASS" "missing artifact failed closed"
else
    scenario_result "ambition_matrix_missing_artifact_fails" "FAIL" "expected missing artifact diagnostic missing"
fi

e2e_step "Scenario 9: unit/schema tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib -- ambition_evidence_matrix \
    2>"$UNIT_LOG" | tee -a "$UNIT_LOG"; then
    TESTS_RUN=$(grep -c "test ambition_evidence_matrix::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "ambition_matrix_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "ambition_matrix_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "ambition_matrix_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_ambition_evidence_matrix completed"
else
    e2e_fail "ffs_ambition_evidence_matrix failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
