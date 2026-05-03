#!/usr/bin/env bash
# ffs_operator_recovery_drill_e2e.sh - operator recovery drill gate for bd-rchk0.5.8.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_operator_recovery_drill}"
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

e2e_init "ffs_operator_recovery_drill"

SPEC_JSON="$REPO_ROOT/docs/operator-recovery-drill.json"
REPORT_JSON="$E2E_LOG_DIR/operator_recovery_drill_report.json"
SUMMARY_MD="$E2E_LOG_DIR/operator_recovery_drill_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/operator_recovery_drill_validate.raw"
BAD_MISSING_LOG="$E2E_LOG_DIR/bad_missing_log.json"
BAD_MUTATE_PREFLIGHT="$E2E_LOG_DIR/bad_mutate_preflight.json"
BAD_NO_PROOF_BUNDLE="$E2E_LOG_DIR/bad_no_proof_bundle.json"
BAD_NO_ROLLBACK="$E2E_LOG_DIR/bad_no_rollback.json"
BAD_RAW="$E2E_LOG_DIR/operator_recovery_drill_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/operator_recovery_drill_unit_tests.log"

e2e_step "Scenario 1: operator recovery drill module and CLI are wired"
if grep -q "pub mod operator_recovery_drill" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-operator-recovery-drill" crates/ffs-harness/src/main.rs; then
    scenario_result "operator_recovery_drill_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "operator_recovery_drill_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in operator recovery drill validates"
if cargo run --quiet -p ffs-harness -- validate-operator-recovery-drill \
    --spec "$SPEC_JSON" \
    --out "$REPORT_JSON" \
    --summary-out "$SUMMARY_MD" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "operator_recovery_drill_validates" "PASS" "checked-in drill accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "operator_recovery_drill_validates" "FAIL" "checked-in drill rejected"
fi

e2e_step "Scenario 3: report covers detect, dry-run, mutate, refusal, logs, and proof bundle lane"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["bead_id"] != "bd-rchk0.5.8":
    raise SystemExit("wrong bead id")
if report["proof_bundle_lane"] != "operator_recovery_drill":
    raise SystemExit("operator drill did not expose its proof bundle lane")
required = {
    "detection_only",
    "dry_run_success",
    "mutating_repair_verified",
    "unsafe_refused",
}
if set(report["by_outcome"]) != required:
    raise SystemExit(f"unexpected outcome coverage: {report['by_outcome']}")
if report["mutation_allowed_count"] != 1:
    raise SystemExit("exactly one drill scenario should allow mutation")
if report["mutation_refused_count"] < 1:
    raise SystemExit("expected at least one explicit mutation refusal")

decisions = {row["scenario_id"]: row for row in report["scenario_reports"]}
if decisions["operator_detect_only_metadata_mismatch"]["drill_decision"] != "detection_only":
    raise SystemExit("detect-only drill lost detection-only decision")
if decisions["operator_dry_run_single_block_recoverable"]["drill_decision"] != "dry_run_ready":
    raise SystemExit("dry-run drill lost dry-run-only decision")
mutating = decisions["operator_mutate_verified_single_block"]
if not mutating["mutation_allowed"] or mutating["drill_decision"] != "mutate_allowed":
    raise SystemExit("verified mutation was not allowed")
refused = decisions["operator_refuse_low_confidence_multi_block"]
if refused["mutation_allowed"] or refused["drill_decision"] != "preflight_failed_refused":
    raise SystemExit("unsafe mutation was not refused by preflight")
for row in decisions.values():
    if "OPERATOR_RECOVERY_DRILL" not in row["log_line"]:
        raise SystemExit(f"missing structured marker for {row['scenario_id']}")
    for token in [
        "exact_commands=",
        "image_hashes=",
        "corruption_manifest=",
        "confidence_threshold=",
        "repair_plan=",
        "operator_warnings=",
        "post_repair_verification=",
        "rollback_or_refusal_outcome=",
        "cleanup_status=",
        "reproduction_command=",
    ]:
        if token not in row["log_line"]:
            raise SystemExit(f"missing {token} in {row['scenario_id']}")
    if row["proof_bundle_lane"] != "operator_recovery_drill":
        raise SystemExit(f"missing proof bundle lane in {row['scenario_id']}")
if "preflight_failed_refused" not in summary:
    raise SystemExit("summary missing refusal decision")
PY
then
    scenario_result "operator_recovery_drill_decision_coverage" "PASS" "decision report covers all drill outcomes"
else
    scenario_result "operator_recovery_drill_decision_coverage" "FAIL" "decision report contract failed"
fi

e2e_step "Scenario 4: invalid operator recovery drill variants fail closed"
python3 - "$SPEC_JSON" "$BAD_MISSING_LOG" "$BAD_MUTATE_PREFLIGHT" "$BAD_NO_PROOF_BUNDLE" "$BAD_NO_ROLLBACK" <<'PY'
import json
import pathlib
import sys

source, missing_log, mutate_preflight, no_proof_bundle, no_rollback = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

variant = json.loads(json.dumps(base))
variant["required_log_fields"] = [
    field for field in variant["required_log_fields"]
    if field != "rollback_or_refusal_outcome"
]
missing_log.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for scenario in variant["scenarios"]:
    if scenario["scenario_id"] == "operator_mutate_verified_single_block":
        scenario["preflight_checks"][0]["passed"] = False
mutate_preflight.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for artifact in variant["scenarios"][0]["expected_artifacts"]:
    artifact["consumers"] = [consumer for consumer in artifact["consumers"] if consumer != "proof_bundle"]
no_proof_bundle.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for scenario in variant["scenarios"]:
    if scenario["scenario_id"] == "operator_mutate_verified_single_block":
        scenario["repair_plan"]["rollback_available"] = False
no_rollback.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_MISSING_LOG" "$BAD_MUTATE_PREFLIGHT" "$BAD_NO_PROOF_BUNDLE" "$BAD_NO_ROLLBACK"; do
    if cargo run --quiet -p ffs-harness -- validate-operator-recovery-drill \
        --spec "$bad" \
        --out "$E2E_LOG_DIR/$(basename "$bad" .json).report.json" >"$BAD_RAW" 2>&1; then
        e2e_log "Unexpectedly accepted invalid operator recovery drill: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "operator recovery drill validation failed\\|invalid operator recovery drill JSON" "$BAD_RAW"; then
        e2e_log "Invalid operator recovery drill failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "operator_recovery_drill_invalid_variants_rejected" "PASS" "bad log/preflight/proof-bundle/rollback variants rejected"
else
    scenario_result "operator_recovery_drill_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: operator docs describe detection-only, dry-run, mutating, and refused drills"
if grep -q "Operator Recovery Drill Contract" scripts/e2e/README.md \
    && grep -q "detection-only drill" docs/runbooks/corruption-recovery.md \
    && grep -q "dry-run drill" docs/runbooks/corruption-recovery.md \
    && grep -q "verified mutating drill" docs/runbooks/corruption-recovery.md \
    && grep -q "refused unsafe drill" docs/runbooks/corruption-recovery.md; then
    scenario_result "operator_recovery_drill_docs_contract" "PASS" "docs distinguish drill support states"
else
    scenario_result "operator_recovery_drill_docs_contract" "FAIL" "missing operator recovery drill docs wording"
fi

e2e_step "Scenario 6: operator recovery drill unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib operator_recovery_drill -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "operator_recovery_drill_unit_tests" "PASS" "operator recovery drill unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "operator_recovery_drill_unit_tests" "FAIL" "operator recovery drill unit tests failed"
fi

e2e_log "Operator recovery drill spec: $SPEC_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Operator recovery drill scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Operator recovery drill scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
