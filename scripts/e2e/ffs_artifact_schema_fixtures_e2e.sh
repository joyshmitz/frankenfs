#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

e2e_init "ffs_artifact_schema_fixtures"
e2e_print_env

FIXTURE_DIR="$REPO_ROOT/tests/artifact-schema-fixtures"
REPORT_JSON="$E2E_LOG_DIR/artifact_schema_fixture_report.json"
REPORT_MD="$E2E_LOG_DIR/artifact_schema_fixture_report.md"
VALIDATION_LOG="$E2E_LOG_DIR/artifact_schema_fixture_validator.log"
REPRO_COMMAND="scripts/e2e/ffs_artifact_schema_fixtures_e2e.sh"

HARNESS_CMD=()
if [[ -n "${FFS_HARNESS_BIN:-}" ]]; then
    HARNESS_CMD=("$FFS_HARNESS_BIN")
else
    HARNESS_CMD=(cargo run -p ffs-harness --)
fi

e2e_step "Scenario 1: fixture directory and files are present"
e2e_assert_dir "$FIXTURE_DIR"
e2e_assert_file "$FIXTURE_DIR/positive/positive_matrix.fixture.json"
e2e_assert_file "$FIXTURE_DIR/negative/negative_matrix.fixture.json"
e2e_assert_file "$FIXTURE_DIR/artifacts/shared/run.log"
scenario_result "artifact_schema_fixture_files_present" "PASS" "positive, negative, and shared artifact files exist"

e2e_step "Scenario 2: validator accepts positives and rejects negatives exactly"
if "${HARNESS_CMD[@]}" validate-artifact-schema-fixtures \
    --fixtures "$FIXTURE_DIR" \
    --out "$REPORT_JSON" \
    --summary-out "$REPORT_MD" \
    --reproduction-command "$REPRO_COMMAND" >"$VALIDATION_LOG" 2>&1; then
    e2e_log "Artifact schema fixture validator succeeded"
    sed -n '1,120p' "$VALIDATION_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "artifact_schema_fixture_validator_exact" "PASS" "validator emitted exact positive/negative fixture verdicts"
else
    e2e_log "Artifact schema fixture validator failed"
    sed -n '1,160p' "$VALIDATION_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "artifact_schema_fixture_validator_exact" "FAIL" "validator rejected the fixture suite"
    e2e_fail "artifact schema fixture validator failed"
fi

e2e_step "Scenario 3: machine-readable report covers required diagnostics"
python3 - "$REPORT_JSON" "$FIXTURE_DIR" "$REPRO_COMMAND" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
fixture_dir = pathlib.Path(sys.argv[2])
expected_repro = sys.argv[3]

if not report["valid"]:
    raise SystemExit("fixture report should be valid")
if report["validator_version"] != 1:
    raise SystemExit("validator_version must be 1")
if report["reproduction_command"] != expected_repro:
    raise SystemExit("reproduction command was not preserved")
if report["positive_count"] < 1 or report["negative_count"] < 1:
    raise SystemExit("expected both positive and negative fixtures")

positive = next(row for row in report["fixtures"] if row["fixture_id"] == "positive_matrix")
negative = next(row for row in report["fixtures"] if row["fixture_id"] == "negative_matrix")
if positive["observed_result"] != "accept" or not positive["valid"]:
    raise SystemExit("positive fixture did not accept cleanly")
if negative["observed_result"] != "reject" or not negative["valid"]:
    raise SystemExit("negative fixture did not reject exactly")
if not positive["fixture_sha256"] or not negative["fixture_sha256"]:
    raise SystemExit("fixture hashes must be recorded")

required_positive_classes = {
    "pass",
    "product_failure",
    "host_capability_skip",
    "authoritative_lane_unavailable",
    "harness_failure",
    "unsupported_scope",
    "stale_artifact",
    "missing_artifact",
    "noisy_measurement",
    "security_refusal",
    "unsafe_repair_refusal",
    "inconclusive_oracle_conflict",
    "pass_with_experimental_caveat",
}
positive_classes = set(positive["classification"].split(","))
missing_classes = sorted(required_positive_classes - positive_classes)
if missing_classes:
    raise SystemExit(f"positive fixture missing classifications: {missing_classes}")

required_codes = {
    "missing_run_id",
    "missing_lane_id",
    "duplicate_scenario_id",
    "stale_schema_version",
    "missing_raw_log_path",
    "artifact_sha256_mismatch",
    "ambiguous_skip_reason",
    "missing_cleanup_status",
    "missing_artifact",
    "missing_remediation_id",
    "invalid_classification",
    "missing_reproduction_command",
    "redacted_reproduction_command",
}
observed_codes = {diag["code"] for diag in negative["observed_diagnostics"]}
missing_codes = sorted(required_codes - observed_codes)
if missing_codes:
    raise SystemExit(f"negative fixture missing diagnostic codes: {missing_codes}")

negative_fixture = json.loads((fixture_dir / "negative/negative_matrix.fixture.json").read_text())
expected_pairs = {
    (diag["code"], diag["path"]) for diag in negative_fixture["expected_diagnostics"]
}
observed_pairs = {
    (diag["code"], diag["path"]) for diag in negative["observed_diagnostics"]
}
if expected_pairs != observed_pairs:
    raise SystemExit("negative fixture diagnostics did not match exact code/path pairs")
PY
scenario_result "artifact_schema_fixture_report_contract" "PASS" "report preserves fixture hashes, diagnostic codes, paths, validator version, and reproduction command"

e2e_step "Scenario 4: human-readable diagnostics are suitable for readiness reports"
e2e_assert_file "$REPORT_MD"
if grep -q "Artifact Schema Fixture Suite" "$REPORT_MD" \
    && grep -q "negative_matrix" "$REPORT_MD" \
    && grep -q "artifact_sha256_mismatch" "$REPORT_MD" \
    && grep -q "$REPRO_COMMAND" "$REPORT_MD"; then
    scenario_result "artifact_schema_fixture_markdown_summary" "PASS" "markdown summary includes fixture ids, diagnostics, and reproduction command"
else
    scenario_result "artifact_schema_fixture_markdown_summary" "FAIL" "markdown summary missing required diagnostics"
    e2e_fail "artifact schema fixture markdown summary is incomplete"
fi

e2e_pass
