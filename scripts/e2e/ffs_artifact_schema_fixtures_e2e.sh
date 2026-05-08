#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_artifact_schema_fixtures}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-2}"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

run_rch_capture() {
    local output_path="$1"
    shift
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local required_artifact="${RCH_REQUIRED_ARTIFACT:-}"
    local required_artifact_deadline=0
    local wait_status
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        RCH_VISIBILITY=none \
        "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" && -n "$required_artifact" && -e "$required_artifact" ]]; then
            e2e_log "RCH_REQUIRED_ARTIFACT_READY|artifact=${required_artifact}|output=${output_path}"
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REQUIRED_ARTIFACT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
            fi
            break
        fi
        if [[ -n "$remote_exit" && -n "$required_artifact" && "$required_artifact_deadline" -eq 0 ]]; then
            required_artifact_deadline=$((SECONDS + RCH_ARTIFACT_RETRIEVAL_GRACE_SECS))
        fi
        if [[ -n "$remote_exit" && -n "$required_artifact" && "$required_artifact_deadline" -gt 0 ]] \
            && ((SECONDS >= required_artifact_deadline)); then
            e2e_log "RCH_REQUIRED_ARTIFACT_MISSING|artifact=${required_artifact}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            status=99
            break
        fi
        if [[ -n "$remote_exit" && -z "$required_artifact" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
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
