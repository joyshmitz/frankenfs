#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_artifact_schema_fixtures}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-2}"
RCH_CAPTURE_VISIBILITY="${FFS_ARTIFACT_SCHEMA_FIXTURES_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_ARTIFACT_SCHEMA_FIXTURES_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_ARTIFACT_SCHEMA_FIXTURES_SKIP_SELF_CHECK:-0}"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

run_rch_capture() {
    local output_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$output_path" "$@"
}

write_artifact_schema_fixture_rch_stub() {
    local stub_path="$1"

    e2e_write_fixture_rch_stub "$stub_path" \
        --mode-env FFS_ARTIFACT_SCHEMA_FIXTURES_FIXTURE_CASE \
        --unknown-case-message "unknown artifact schema fixtures fixture case" \
        --complete-body-stdin <<'SH'
case "$command_text" in
    *"cargo run --quiet -p ffs-harness -- validate-artifact-schema-fixtures "*)
        python3 - <<'PY'
import json
import pathlib

reproduction_command = "scripts/e2e/ffs_artifact_schema_fixtures_e2e.sh"
negative_fixture = json.loads(
    pathlib.Path("tests/artifact-schema-fixtures/negative/negative_matrix.fixture.json").read_text()
)
positive_classes = ",".join(
    [
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
    ]
)
report = {
    "validator_version": 1,
    "valid": True,
    "reproduction_command": reproduction_command,
    "positive_count": 1,
    "negative_count": 1,
    "fixtures": [
        {
            "fixture_id": "positive_matrix",
            "observed_result": "accept",
            "valid": True,
            "fixture_sha256": "fixture-positive-sha256",
            "classification": positive_classes,
            "observed_diagnostics": [],
        },
        {
            "fixture_id": "negative_matrix",
            "observed_result": "reject",
            "valid": True,
            "fixture_sha256": "fixture-negative-sha256",
            "classification": "invalid_fixture_matrix",
            "observed_diagnostics": negative_fixture["expected_diagnostics"],
        },
    ],
}
print(json.dumps(report, sort_keys=True))
print()
print("# Artifact Schema Fixture Suite")
print()
print("Fixture negative_matrix rejected exactly.")
print("Diagnostic: artifact_sha256_mismatch")
print(f"Reproduction: {reproduction_command}")
PY
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/artifact_schema_fixtures_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_ARTIFACT_SCHEMA_FIXTURES_SELF_CHECK=0 \
        FFS_ARTIFACT_SCHEMA_FIXTURES_SKIP_SELF_CHECK=1 \
        FFS_ARTIFACT_SCHEMA_FIXTURES_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_artifact_schema_fixtures_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic artifact schema fixtures wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir report_json report_md validation_log
    stub_path="$E2E_LOG_DIR/rch-artifact-schema-fixtures-fixture"
    write_artifact_schema_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    report_json="$result_dir/artifact_schema_fixture_report.json"
    report_md="$result_dir/artifact_schema_fixture_report.md"
    validation_log="$result_dir/artifact_schema_fixture_validator.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$validation_log" ]] \
        && [[ -f "$report_json" ]] \
        && [[ -f "$report_md" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "artifact_schema_fixture_files_present" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "artifact_schema_fixture_validator_exact" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "artifact_schema_fixture_report_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "artifact_schema_fixture_markdown_summary" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .validator_version == 1
            and .positive_count == 1
            and .negative_count == 1
            and .reproduction_command == "scripts/e2e/ffs_artifact_schema_fixtures_e2e.sh"
        ' "$report_json" >/dev/null \
        && grep -q "negative_matrix" "$report_md" \
        && grep -q "artifact_sha256_mismatch" "$report_md"; then
        scenario_result "artifact_schema_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "artifact_schema_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Artifact schema fixtures complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "artifact_schema_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "artifact_schema_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Artifact schema fixtures local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "artifact_schema_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "artifact_schema_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Artifact schema fixtures missing remote evidence fixture self-check failed"
    fi
}

extract_validator_report_json() {
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
    if (
        isinstance(obj, dict)
        and obj.get("validator_version") == 1
        and "fixtures" in obj
        and "reproduction_command" in obj
    ):
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("artifact schema fixture JSON report not found")
PY
}

extract_validator_summary_markdown() {
    local raw_path="$1"
    local summary_path="$2"

    python3 - "$raw_path" "$summary_path" <<'PY'
import pathlib
import re
import sys

raw_path, summary_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Artifact Schema Fixture Suite")
if start < 0:
    raise SystemExit("artifact schema fixture Markdown summary not found")
end = len(text)
for marker in ("\nartifact schema fixture summary written:", "\n  20"):
    found = text.find(marker, start)
    if found >= 0:
        end = min(end, found)
pathlib.Path(summary_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_artifact_schema_fixtures"
e2e_print_env

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

FIXTURE_DIR="$REPO_ROOT/tests/artifact-schema-fixtures"
REPORT_JSON="$E2E_LOG_DIR/artifact_schema_fixture_report.json"
REPORT_MD="$E2E_LOG_DIR/artifact_schema_fixture_report.md"
VALIDATION_LOG="$E2E_LOG_DIR/artifact_schema_fixture_validator.log"
REPRO_COMMAND="scripts/e2e/ffs_artifact_schema_fixtures_e2e.sh"

run_harness_validator() {
    if [[ -n "${FFS_HARNESS_BIN:-}" ]]; then
        "$FFS_HARNESS_BIN" validate-artifact-schema-fixtures \
            --fixtures "$FIXTURE_DIR" \
            --out "$REPORT_JSON" \
            --summary-out "$REPORT_MD" \
            --reproduction-command "$REPRO_COMMAND" >"$VALIDATION_LOG" 2>&1
        return
    fi

    run_rch_capture "$VALIDATION_LOG" cargo run --quiet -p ffs-harness -- \
        validate-artifact-schema-fixtures \
        --fixtures "$FIXTURE_DIR" \
        --summary-out /dev/stdout \
        --reproduction-command "$REPRO_COMMAND" \
        && extract_validator_report_json "$VALIDATION_LOG" "$REPORT_JSON" \
        && extract_validator_summary_markdown "$VALIDATION_LOG" "$REPORT_MD"
}

e2e_step "Scenario 1: fixture directory and files are present"
e2e_assert_dir "$FIXTURE_DIR"
e2e_assert_file "$FIXTURE_DIR/positive/positive_matrix.fixture.json"
e2e_assert_file "$FIXTURE_DIR/negative/negative_matrix.fixture.json"
e2e_assert_file "$FIXTURE_DIR/artifacts/shared/run.log"
scenario_result "artifact_schema_fixture_files_present" "PASS" "positive, negative, and shared artifact files exist"

e2e_step "Scenario 2: validator accepts positives and rejects negatives exactly"
if run_harness_validator; then
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
