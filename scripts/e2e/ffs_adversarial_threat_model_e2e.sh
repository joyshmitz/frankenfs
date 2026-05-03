#!/usr/bin/env bash
# ffs_adversarial_threat_model_e2e.sh - dry-run security gate for bd-rchk0.5.11/bd-0qx9b.
#
# Validates the adversarial-image threat model without mounting hostile images
# or running long fuzz campaigns.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_adversarial_threat_model}"
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

    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-180}"
    set +e
    timeout "${timeout_secs}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1
    local status=$?
    set -e

    if [[ $status -eq 124 ]] && rg -q "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|log=${log_path}|timeout_secs=${timeout_secs}"
        return 0
    fi
    return "$status"
}

e2e_init "ffs_adversarial_threat_model"

MODEL_JSON="$REPO_ROOT/security/adversarial_image_threat_model.json"
REPORT_JSON="$E2E_LOG_DIR/adversarial_threat_model_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/adversarial_threat_model_artifact_manifest.json"
WORDING_TSV="$E2E_LOG_DIR/adversarial_threat_model_wording.tsv"
VALIDATE_RAW="$E2E_LOG_DIR/adversarial_threat_model_validate.raw"
BAD_TRAVERSAL_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_traversal.json"
BAD_REVIEW_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_review.json"
BAD_LOG_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_log.json"
BAD_LIMIT_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_limit.json"
BAD_OPERATOR_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_operator.json"
BAD_CONTROL_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_control.json"
BAD_COUNTER_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_counter.json"
BAD_CLEANUP_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_cleanup.json"
BAD_RAW="$E2E_LOG_DIR/adversarial_threat_model_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/adversarial_threat_model_unit_tests.log"

e2e_step "Scenario 1: adversarial threat model module and CLI are wired"
if grep -q "pub mod adversarial_threat_model" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-adversarial-threat-model" crates/ffs-harness/src/main.rs; then
    scenario_result "adversarial_threat_model_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "adversarial_threat_model_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in threat model validates and emits artifacts"
if cargo run --quiet -p ffs-harness -- validate-adversarial-threat-model \
    --model "$MODEL_JSON" \
    --artifact-root "artifacts/security/dry-run" \
    --out "$REPORT_JSON" \
    --artifact-out "$ARTIFACT_JSON" \
    --wording-out "$WORDING_TSV" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "adversarial_threat_model_validates" "PASS" "checked-in threat model accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "adversarial_threat_model_validates" "FAIL" "checked-in threat model rejected"
fi

e2e_step "Scenario 3: dry-run coverage, logs, artifact mapping, and wording are present"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" "$WORDING_TSV" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
wording = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit("threat model report invalid")
required = {
    "malformed_image",
    "hostile_artifact_path",
    "missing_host_capability",
    "resource_exhaustion",
    "repair_ledger_tamper",
    "unsupported_mount_option",
    "unsafe_operator_command",
}
covered = {row["threat_class"] for row in report["evaluated_scenarios"]}
missing = required - covered
if missing:
    raise SystemExit(f"missing threat classes: {sorted(missing)}")
log_fields = set(report["required_log_fields"])
for field in [
    "threat_scenario_id",
    "input_hash",
    "parser_capability",
    "mount_capability",
    "repair_capability",
    "resource_controls",
    "expected_safe_behavior",
    "expected_classification",
    "observed_classification",
    "resource_limits",
    "observed_input_bytes",
    "observed_cpu_ms",
    "observed_wall_ms",
    "observed_memory_mib",
    "observed_disk_bytes",
    "enforcement_point",
    "cleanup_status",
    "artifact_paths",
    "remediation_id",
    "reproduction_command",
]:
    if field not in log_fields:
        raise SystemExit(f"missing log field: {field}")
if artifact["gate_id"] != "adversarial_threat_model":
    raise SystemExit("wrong artifact gate_id")
if artifact.get("bead_id") != "bd-0qx9b":
    raise SystemExit("missing bead id")
categories = {entry["category"] for entry in artifact["artifacts"]}
if "raw_log" not in categories or "repro_pack" not in categories or "summary_report" not in categories:
    raise SystemExit(f"missing security artifact categories: {categories}")
if "docs alone cannot promote" not in wording:
    raise SystemExit("wording does not preserve docs-gated security status")
required_scenarios = {
    "oversized_metadata_seed_capped",
    "cyclic_metadata_reference_quarantined",
    "deeply_nested_directory_capped",
    "huge_xattr_payload_capped",
    "truncated_repair_ledger_quarantined",
    "corrupt_repair_ledger_quarantined",
    "hostile_proof_bundle_traversal_refused",
    "hostile_proof_bundle_symlink_refused",
    "excessive_log_output_capped",
    "excessive_artifact_count_capped",
    "timeout_capped",
    "file_descriptor_exhaustion_capped",
}
scenarios = {row["scenario_id"]: row for row in report["evaluated_scenarios"]}
missing_scenarios = required_scenarios - set(scenarios)
if missing_scenarios:
    raise SystemExit(f"missing bounded hostile scenarios: {sorted(missing_scenarios)}")
safe_classifications = {"rejected", "unsupported", "capped", "quarantined", "mutation_refused", "host_path_refused"}
for scenario_id in required_scenarios:
    row = scenarios[scenario_id]
    if row["observed_classification"] not in safe_classifications:
        raise SystemExit(f"unsafe classification for {scenario_id}: {row['observed_classification']}")
    if not row.get("resource_controls"):
        raise SystemExit(f"missing resource controls for {scenario_id}")
    if not row.get("artifact_paths"):
        raise SystemExit(f"missing artifact paths for {scenario_id}")
    counters = row.get("observed_resource_counters") or {}
    for key in ("input_bytes", "wall_ms"):
        if key not in counters:
            raise SystemExit(f"missing observed counter {key} for {scenario_id}")
    if row.get("primary_enforcement_point") in {None, "", "missing"}:
        raise SystemExit(f"missing enforcement point for {scenario_id}")
PY
then
    scenario_result "adversarial_threat_model_dry_run_expands" "PASS" "coverage, logs, artifacts, containment, and wording verified"
else
    scenario_result "adversarial_threat_model_dry_run_expands" "FAIL" "dry-run threat model contract failed"
fi

e2e_step "Scenario 4: malformed threat model variants fail closed"
python3 - "$MODEL_JSON" "$BAD_TRAVERSAL_JSON" "$BAD_REVIEW_JSON" "$BAD_LOG_JSON" "$BAD_LIMIT_JSON" "$BAD_OPERATOR_JSON" "$BAD_CONTROL_JSON" "$BAD_COUNTER_JSON" "$BAD_CLEANUP_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

source, bad_traversal, bad_review, bad_log, bad_limit, bad_operator, bad_control, bad_counter, bad_cleanup = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

traversal = json.loads(json.dumps(base))
traversal["scenarios"][1]["expected_path_decision"] = "accept_confined"
bad_traversal.write_text(json.dumps(traversal, indent=2, sort_keys=True) + "\n", encoding="utf-8")

review = json.loads(json.dumps(base))
review["scenarios"][0]["review_status"] = "unreviewed"
bad_review.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log = json.loads(json.dumps(base))
log["required_log_fields"] = [field for field in log["required_log_fields"] if field != "input_hash"]
bad_log.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")

limit = json.loads(json.dumps(base))
limit["scenarios"][4]["resource_limits"]["max_wall_ms"] = 0
bad_limit.write_text(json.dumps(limit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

operator = json.loads(json.dumps(base))
operator["scenarios"][-1]["release_gate_effect"] = "follow_up_only"
bad_operator.write_text(json.dumps(operator, indent=2, sort_keys=True) + "\n", encoding="utf-8")

control = json.loads(json.dumps(base))
del control["scenarios"][4]["resource_controls"][0]["resource_class"]
bad_control.write_text(json.dumps(control, indent=2, sort_keys=True) + "\n", encoding="utf-8")

counter = json.loads(json.dumps(base))
counter["scenarios"][4]["observed_resource_counters"]["wall_ms"] = counter["scenarios"][4]["resource_limits"]["max_wall_ms"] + 1
bad_counter.write_text(json.dumps(counter, indent=2, sort_keys=True) + "\n", encoding="utf-8")

cleanup = json.loads(json.dumps(base))
cleanup["scenarios"][5]["cleanup_status"] = "failed"
bad_cleanup.write_text(json.dumps(cleanup, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_TRAVERSAL_JSON" "$BAD_REVIEW_JSON" "$BAD_LOG_JSON" "$BAD_LIMIT_JSON" "$BAD_OPERATOR_JSON" "$BAD_CONTROL_JSON" "$BAD_COUNTER_JSON" "$BAD_CLEANUP_JSON"; do
    if cargo run --quiet -p ffs-harness -- validate-adversarial-threat-model \
        --model "$bad" \
        --out "$E2E_LOG_DIR/$(basename "$bad" .json).report.json" >"$BAD_RAW" 2>&1; then
        e2e_log "Unexpectedly accepted invalid threat model: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "adversarial threat model validation failed\\|invalid adversarial threat model JSON" "$BAD_RAW"; then
        e2e_log "Invalid threat model failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "adversarial_threat_model_invalid_variants_rejected" "PASS" "bad traversal/review/log/limit/operator/control/counter/cleanup variants rejected"
else
    scenario_result "adversarial_threat_model_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: adversarial threat model unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib adversarial_threat_model -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "adversarial_threat_model_unit_tests" "PASS" "adversarial threat model unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "adversarial_threat_model_unit_tests" "FAIL" "adversarial threat model unit tests failed"
fi

e2e_log "Adversarial threat model: $MODEL_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"
e2e_log "Generated wording: $WORDING_TSV"

if ((FAIL_COUNT == 0)); then
    e2e_log "Adversarial threat model scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Adversarial threat model scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
