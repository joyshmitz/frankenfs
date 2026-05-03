#!/usr/bin/env bash
# ffs_repair_confidence_lab_e2e.sh - mutation-safety threshold smoke for bd-rchk0.5.3.1.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_confidence_lab}"
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

run_rch_capture() {
    local log_path="$1"
    shift
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-240}"
    if command -v timeout >/dev/null 2>&1; then
        timeout "${timeout_secs}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1
    else
        "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1
    fi
}

e2e_init "ffs_repair_confidence_lab"

SPEC_JSON="$REPO_ROOT/docs/repair-confidence-mutation-safety.json"
REPORT_JSON="$E2E_LOG_DIR/repair_confidence_lab_report.json"
SUMMARY_MD="$E2E_LOG_DIR/repair_confidence_lab_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/repair_confidence_lab_validate.raw"
BAD_MISSING_LOG="$E2E_LOG_DIR/bad_missing_log.json"
BAD_UNSAFE_MUTATION="$E2E_LOG_DIR/bad_unsafe_mutation.json"
BAD_EXPERIMENTAL_NO_FOLLOWUP="$E2E_LOG_DIR/bad_experimental_no_followup.json"
BAD_MISSING_ARTIFACTS="$E2E_LOG_DIR/bad_missing_artifacts.json"
BAD_RAW="$E2E_LOG_DIR/repair_confidence_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/repair_confidence_lab_unit_tests.log"

e2e_step "Scenario 1: repair confidence lab module and CLI are wired"
if grep -q "pub mod repair_confidence_lab" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-repair-confidence-lab" crates/ffs-harness/src/main.rs; then
    scenario_result "repair_confidence_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "repair_confidence_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in repair confidence lab validates"
if cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab \
    --spec "$SPEC_JSON" \
    --out "$REPORT_JSON" \
    --summary-out "$SUMMARY_MD" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "repair_confidence_lab_validates" "PASS" "checked-in lab accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "repair_confidence_lab_validates" "FAIL" "checked-in lab rejected"
fi

e2e_step "Scenario 3: report covers mutation, refusal, dry-run, detect-only, and verification failure"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["bead_id"] != "bd-rchk0.5.3.1":
    raise SystemExit("wrong bead id")
required = {
    "detect_only",
    "dry_run_success",
    "mutating_repair_verified",
    "unsafe_to_repair",
    "failed_verification",
}
if set(report["by_outcome"]) != required:
    raise SystemExit(f"unexpected outcome coverage: {report['by_outcome']}")
if report["mutation_allowed_count"] != 1:
    raise SystemExit("exactly one scenario should allow mutation")
if report["mutation_refused_count"] < 2:
    raise SystemExit("expected at least two explicit mutation refusals")

decisions = {row["scenario_id"]: row for row in report["scenario_reports"]}
mutating = decisions["repair_mutate_verified_single_block"]
if not mutating["mutation_allowed"] or mutating["threshold_decision"] != "mutate_allowed":
    raise SystemExit("verified mutating scenario was not allowed")
unsafe = decisions["repair_refuse_low_confidence_multi_block"]
if unsafe["mutation_allowed"] or unsafe["threshold_decision"] != "unsafe_refused":
    raise SystemExit("unsafe scenario did not refuse mutation")
failed = decisions["repair_failed_verification_hash_mismatch"]
if failed["mutation_allowed"] or failed["threshold_decision"] != "verification_failed_refused":
    raise SystemExit("failed verification scenario did not refuse mutation")
dry_run = decisions["repair_dry_run_single_block_recoverable"]
if dry_run["mutation_allowed"] or dry_run["threshold_decision"] != "dry_run_ready":
    raise SystemExit("dry-run scenario lost dry-run-only classification")
detect = decisions["repair_detect_only_metadata_mismatch"]
if detect["mutation_allowed"] or detect["threshold_decision"] != "detection_only":
    raise SystemExit("detect-only scenario lost detection-only classification")

for row in decisions.values():
    if "REPAIR_CONFIDENCE_DECISION" not in row["log_line"]:
        raise SystemExit(f"missing structured log marker for {row['scenario_id']}")
    if "reproduction_command=" not in row["log_line"]:
        raise SystemExit(f"missing reproduction command in log for {row['scenario_id']}")
if "verification_failed_refused" not in summary:
    raise SystemExit("summary missing verification refusal")
PY
then
    scenario_result "repair_confidence_decision_coverage" "PASS" "decision report covers all safety outcomes"
else
    scenario_result "repair_confidence_decision_coverage" "FAIL" "decision report contract failed"
fi

e2e_step "Scenario 4: invalid repair confidence variants fail closed"
python3 - "$SPEC_JSON" "$BAD_MISSING_LOG" "$BAD_UNSAFE_MUTATION" "$BAD_EXPERIMENTAL_NO_FOLLOWUP" "$BAD_MISSING_ARTIFACTS" <<'PY'
import json
import pathlib
import sys

source, missing_log, unsafe_mutation, no_followup, missing_artifacts = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

variant = json.loads(json.dumps(base))
variant["required_log_fields"] = [
    field for field in variant["required_log_fields"]
    if field != "verification_verdict"
]
missing_log.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for scenario in variant["scenarios"]:
    if scenario["scenario_id"] == "repair_refuse_low_confidence_multi_block":
        scenario["expected_outcome"] = "mutating_repair_verified"
unsafe_mutation.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for threshold in variant["thresholds"]:
    if threshold["threshold_id"] == "experimental_refusal_calibration_gate":
        threshold.pop("follow_up_bead", None)
no_followup.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
variant["scenarios"][0]["expected_artifacts"] = []
missing_artifacts.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_MISSING_LOG" "$BAD_UNSAFE_MUTATION" "$BAD_EXPERIMENTAL_NO_FOLLOWUP" "$BAD_MISSING_ARTIFACTS"; do
    if cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab \
        --spec "$bad" \
        --out "$E2E_LOG_DIR/$(basename "$bad" .json).report.json" >"$BAD_RAW" 2>&1; then
        e2e_log "Unexpectedly accepted invalid repair confidence lab: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "repair confidence lab validation failed\\|invalid repair confidence lab JSON" "$BAD_RAW"; then
        e2e_log "Invalid repair confidence lab failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "repair_confidence_invalid_variants_rejected" "PASS" "bad log/outcome/follow-up/artifact variants rejected"
else
    scenario_result "repair_confidence_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: docs contract distinguishes mutating repair, detection-only scrub, and unsupported classes"
if grep -q "Repair Confidence Lab Contract" scripts/e2e/README.md \
    && grep -q "automatic mutating repair" scripts/e2e/README.md \
    && grep -q "detection-only scrub" scripts/e2e/README.md \
    && grep -q "unsupported corruption classes" scripts/e2e/README.md; then
    scenario_result "repair_confidence_docs_contract" "PASS" "docs distinguish repair support states"
else
    scenario_result "repair_confidence_docs_contract" "FAIL" "missing repair confidence docs wording"
fi

e2e_step "Scenario 6: repair confidence lab unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib repair_confidence_lab -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "repair_confidence_unit_tests" "PASS" "repair confidence unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "repair_confidence_unit_tests" "FAIL" "repair confidence unit tests failed"
fi

e2e_log "Repair confidence lab spec: $SPEC_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Repair confidence lab scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Repair confidence lab scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
