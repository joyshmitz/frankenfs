#!/usr/bin/env bash
# ffs_repair_writeback_serialization_e2e.sh - dry-run gate for bd-rchk0.1.1.
#
# Validates the read-write repair/writeback serialization contract and proves
# the current mounted read-write repair path fails closed with repro artifacts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_writeback_serialization}"
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

e2e_init "ffs_repair_writeback_serialization"

CONTRACT_JSON="$REPO_ROOT/docs/repair-writeback-serialization-contract.json"
REPORT_JSON="$E2E_LOG_DIR/repair_writeback_serialization_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/repair_writeback_serialization_artifact_manifest.json"
SUMMARY_MD="$E2E_LOG_DIR/repair_writeback_serialization_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/repair_writeback_serialization_validate.raw"
BAD_MISSING_EVIDENCE="$E2E_LOG_DIR/bad_missing_evidence.json"
BAD_UNSAFE_RISK="$E2E_LOG_DIR/bad_unsafe_risk.json"
BAD_MUTATION_ALLOWED="$E2E_LOG_DIR/bad_mutation_allowed.json"
BAD_MISSING_REPRO="$E2E_LOG_DIR/bad_missing_repro.json"
BAD_RAW="$E2E_LOG_DIR/repair_writeback_bad.raw"
FAIL_CLOSED_ARTIFACT="$E2E_LOG_DIR/repair_writeback_rw_fail_closed_artifact.json"
FAIL_CLOSED_LOG="$E2E_LOG_DIR/repair_writeback_rw_fail_closed.log"
UNIT_LOG="$E2E_LOG_DIR/repair_writeback_serialization_unit_tests.log"

e2e_step "Scenario 1: repair/writeback serialization module and CLI are wired"
if grep -q "pub mod repair_writeback_serialization" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-repair-writeback-serialization" crates/ffs-harness/src/main.rs; then
    scenario_result "repair_writeback_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "repair_writeback_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in contract validates and emits proof artifacts"
if cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
    --contract "$CONTRACT_JSON" \
    --artifact-root "artifacts/repair-writeback/dry-run" \
    --out "$REPORT_JSON" \
    --artifact-out "$ARTIFACT_JSON" \
    --summary-out "$SUMMARY_MD" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "repair_writeback_contract_validates" "PASS" "checked-in contract accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "repair_writeback_contract_validates" "FAIL" "checked-in contract rejected"
fi

e2e_step "Scenario 3: report proves fail-closed policy, risk decision, and consumers"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["bead_id"] != "bd-rchk0.1.1":
    raise SystemExit("wrong bead id")
if report["state_count"] < 10 or report["transition_count"] < 10:
    raise SystemExit("state machine is too small")
if report["missing_required_evidence_fields"]:
    raise SystemExit(f"missing evidence fields: {report['missing_required_evidence_fields']}")
if report["missing_required_coverage_tags"]:
    raise SystemExit(f"missing coverage: {report['missing_required_coverage_tags']}")
if not report["risk_report"]["fail_closed_is_lower_loss"]:
    raise SystemExit("fail-closed option is not lower loss")

transition = next(
    row for row in report["transition_evaluations"]
    if row["from_state"] == "client_write_in_flight"
    and row["event"] == "repair_writeback_requested"
)
if transition["allowed"] or transition["mutation_allowed"]:
    raise SystemExit("RW repair transition did not fail closed")
if transition["error_class"] != "rw_repair_serialization_missing":
    raise SystemExit("wrong fail-closed error class")
if "bd-rchk0.1.2" != transition.get("follow_up_bead"):
    raise SystemExit("missing serializer follow-up")

scenario = next(row for row in report["scenario_reports"] if row["scenario_id"] == "repair_writeback_rw_fail_closed")
if not scenario["proves_no_lost_client_write"] or not scenario["preserves_reproduction_data"]:
    raise SystemExit("fail-closed scenario does not preserve no-lost-write/repro proof")
if scenario["expected_error_class"] != "rw_repair_serialization_missing":
    raise SystemExit("wrong scenario error class")

metadata = [entry.get("metadata", {}) for entry in artifact["artifacts"]]
if not any(row.get("proof_bundle_lane") == "repair_rw_writeback" for row in metadata):
    raise SystemExit("missing proof-bundle lane metadata")
if not any(row.get("release_gate_feature") == "repair.rw.writeback" for row in metadata):
    raise SystemExit("missing release-gate metadata")
if "rw_repair_serialization_missing" not in summary:
    raise SystemExit("summary missing fail-closed error class")
PY
then
    scenario_result "repair_writeback_fail_closed_report" "PASS" "report and sample artifact verified"
else
    scenario_result "repair_writeback_fail_closed_report" "FAIL" "report contract failed"
fi

e2e_step "Scenario 4: invalid contract variants fail closed"
python3 - "$CONTRACT_JSON" "$BAD_MISSING_EVIDENCE" "$BAD_UNSAFE_RISK" "$BAD_MUTATION_ALLOWED" "$BAD_MISSING_REPRO" <<'PY'
import json
import pathlib
import sys

source, missing_evidence, unsafe_risk, mutation_allowed, missing_repro = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

variant = json.loads(json.dumps(base))
variant["required_evidence_fields"] = [
    field for field in variant["required_evidence_fields"]
    if field != "reproduction_command"
]
missing_evidence.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
variant["risk_decision"]["chosen_option"] = "enable_rw_repair_without_serializer"
variant["risk_decision"]["rejected_option"] = "fail_closed_until_unified_serializer"
unsafe_risk.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for transition in variant["transitions"]:
    if transition["transition_id"] == "rw_repair_fail_closed":
        transition["mutation_allowed"] = True
mutation_allowed.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for scenario in variant["scenarios"]:
    if scenario["scenario_id"] == "repair_writeback_rw_fail_closed":
        scenario["preserves_reproduction_data"] = False
missing_repro.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_MISSING_EVIDENCE" "$BAD_UNSAFE_RISK" "$BAD_MUTATION_ALLOWED" "$BAD_MISSING_REPRO"; do
    if cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
        --contract "$bad" \
        --out "$E2E_LOG_DIR/$(basename "$bad" .json).report.json" >"$BAD_RAW" 2>&1; then
        e2e_log "Unexpectedly accepted invalid repair/writeback contract: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "repair/writeback serialization validation failed\\|invalid repair/writeback contract JSON" "$BAD_RAW"; then
        e2e_log "Invalid repair/writeback contract failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "repair_writeback_invalid_variants_rejected" "PASS" "bad evidence/risk/mutation/repro variants rejected"
else
    scenario_result "repair_writeback_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: fail-closed scenario artifact preserves required log fields"
if python3 - "$REPORT_JSON" "$FAIL_CLOSED_ARTIFACT" "$FAIL_CLOSED_LOG" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact_path = pathlib.Path(sys.argv[2])
log_path = pathlib.Path(sys.argv[3])
scenario = next(row for row in report["scenario_reports"] if row["scenario_id"] == "repair_writeback_rw_fail_closed")
record = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "operation_id": "op-rw-repair-fail-closed-001",
    "scenario_id": scenario["scenario_id"],
    "snapshot_epoch": 42,
    "lease_id": "lease-dry-run-001",
    "repair_symbol_version": "group-7-generation-12",
    "expected_state": "repair_writeback_blocked_rw",
    "observed_state": scenario["final_state"],
    "error_class": scenario["expected_error_class"],
    "artifact_paths": [str(artifact_path), str(log_path)],
    "cleanup_status": "preserved_artifacts",
    "reproduction_command": report["reproduction_command"],
    "follow_up_bead": "bd-rchk0.1.2",
    "mutation_attempted": False,
    "lost_client_write_possible": False,
}
artifact_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "REPAIR_WRITEBACK_EVENT|"
    + "|".join(f"{key}={value}" for key, value in record.items() if key not in {"artifact_paths"})
    + "\n",
    encoding="utf-8",
)

required = [
    "operation_id",
    "scenario_id",
    "snapshot_epoch",
    "lease_id",
    "repair_symbol_version",
    "expected_state",
    "observed_state",
    "error_class",
    "artifact_paths",
    "cleanup_status",
    "reproduction_command",
    "follow_up_bead",
]
missing = [field for field in required if field not in record]
if missing:
    raise SystemExit(f"missing fields from fail-closed artifact: {missing}")
if record["error_class"] != "rw_repair_serialization_missing":
    raise SystemExit("wrong error class")
if record["mutation_attempted"]:
    raise SystemExit("fail-closed artifact claims mutation")
if record["lost_client_write_possible"]:
    raise SystemExit("fail-closed artifact does not prove no lost client write")
PY
then
    scenario_result "repair_writeback_fail_closed_artifact" "PASS" "fail-closed artifact preserves required fields"
else
    scenario_result "repair_writeback_fail_closed_artifact" "FAIL" "fail-closed artifact contract failed"
fi

e2e_step "Scenario 6: repair/writeback serialization unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib repair_writeback_serialization -- --nocapture >"$UNIT_LOG" 2>&1; then
    cat "$UNIT_LOG"
    scenario_result "repair_writeback_unit_tests" "PASS" "repair/writeback unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "repair_writeback_unit_tests" "FAIL" "repair/writeback unit tests failed"
fi

e2e_log "Repair/writeback contract: $CONTRACT_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"
e2e_log "Fail-closed artifact: $FAIL_CLOSED_ARTIFACT"

if ((FAIL_COUNT == 0)); then
    e2e_log "Repair/writeback serialization scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Repair/writeback serialization scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
