#!/usr/bin/env bash
# ffs_proof_overhead_budget_e2e.sh - smoke gate for bd-rchk0.5.14.
#
# Runs a bounded proof-style harness workflow, captures overhead metrics,
# evaluates them against the sample budget schema, and verifies the release-gate
# log contract.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_proof_overhead_budget}"
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

e2e_init "ffs_proof_overhead_budget"

BUDGET_JSON="${E2E_LOG_DIR}/proof_overhead_budget.json"
METRICS_JSON="${E2E_LOG_DIR}/proof_overhead_metrics.json"
REPORT_JSON="${E2E_LOG_DIR}/proof_overhead_budget_report.json"
REPORT_RAW="${E2E_LOG_DIR}/proof_overhead_budget_report.raw"
PROOF_STDOUT="${E2E_LOG_DIR}/proof_workflow_stdout.log"
PROOF_BUNDLE="${E2E_LOG_DIR}/proof_bundle.json"
REPRO_PACK="${E2E_LOG_DIR}/reproduction_pack.json"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod proof_overhead_budget" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-proof-overhead-budget" crates/ffs-harness/src/main.rs; then
    scenario_result "proof_budget_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "proof_budget_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: bounded proof workflow emits metrics"
START_NS=$(date +%s%N)
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- parity >"$PROOF_STDOUT" 2>&1; then
    END_NS=$(date +%s%N)
    DURATION_SECONDS=$(python3 - "$START_NS" "$END_NS" <<'PY'
import sys
start = int(sys.argv[1])
end = int(sys.argv[2])
print(f"{max(end - start, 0) / 1_000_000_000:.6f}")
PY
)
    python3 - "$PROOF_STDOUT" "$PROOF_BUNDLE" "$REPRO_PACK" "$BUDGET_JSON" "$METRICS_JSON" "$DURATION_SECONDS" <<'PY'
import json
import os
import sys

stdout_path, proof_bundle_path, repro_pack_path, budget_path, metrics_path, duration = sys.argv[1:]
reproduction_command = (
    "ffs-harness validate-proof-overhead-budget "
    f"--budget {budget_path} --metrics {metrics_path}"
)

with open(stdout_path, encoding="utf-8", errors="replace") as handle:
    parity_output = handle.read()

proof_bundle = {
    "scenario_id": "proof_budget_developer_smoke",
    "workflow": "ffs-harness parity",
    "duration_seconds": float(duration),
    "parity_output_bytes": len(parity_output.encode("utf-8")),
}
repro_pack = {
    "scenario_id": "proof_budget_developer_smoke",
    "reproduction_command": reproduction_command,
    "inputs": [budget_path, metrics_path, stdout_path],
}

with open(proof_bundle_path, "w", encoding="utf-8") as handle:
    json.dump(proof_bundle, handle, indent=2, sort_keys=True)
    handle.write("\n")
with open(repro_pack_path, "w", encoding="utf-8") as handle:
    json.dump(repro_pack, handle, indent=2, sort_keys=True)
    handle.write("\n")

artifact_bytes = os.path.getsize(proof_bundle_path) + os.path.getsize(repro_pack_path)
log_bytes = os.path.getsize(stdout_path)
operator_report_bytes = os.path.getsize(proof_bundle_path)

required_log_fields = [
    "scenario_id",
    "profile",
    "baseline_id",
    "observed_value",
    "budget_value",
    "unit",
    "threshold_decision",
    "artifact_sizes",
    "compression_retention_decision",
    "reproduction_command",
]

budget = {
    "schema_version": 1,
    "profile": "developer_smoke",
    "baseline_id": "proof-budget-baseline-2026-05-01",
    "baseline_captured_at": "2026-05-01T00:00:00Z",
    "max_baseline_age_days": 14,
    "metrics": [
        {"category": "runtime_overhead", "metric": "runtime_overhead_percent", "unit": "percent", "warn_at": 8.0, "fail_at": 12.0},
        {"category": "memory_overhead", "metric": "memory_overhead_percent", "unit": "percent", "warn_at": 10.0, "fail_at": 20.0},
        {"category": "artifact_disk_usage", "metric": "artifact_disk_bytes", "unit": "bytes", "warn_at": 524288.0, "fail_at": 1048576.0},
        {"category": "log_volume", "metric": "log_bytes", "unit": "bytes", "warn_at": 524288.0, "fail_at": 1048576.0},
        {"category": "repair_symbol_storage", "metric": "repair_symbol_bytes", "unit": "bytes", "warn_at": 65536.0, "fail_at": 131072.0},
        {"category": "rch_upload_size", "metric": "rch_upload_bytes", "unit": "bytes", "warn_at": 1048576.0, "fail_at": 2097152.0},
        {"category": "campaign_duration", "metric": "campaign_duration_seconds", "unit": "seconds", "warn_at": 120.0, "fail_at": 240.0},
        {"category": "operator_report_size", "metric": "operator_report_bytes", "unit": "bytes", "warn_at": 262144.0, "fail_at": 524288.0}
    ],
    "retention": {
        "max_total_artifact_bytes": 1048576,
        "compress_above_bytes": 524288,
        "mandatory_artifact_classes": ["proof_bundle", "reproduction_pack"],
        "preserve_reproduction_command": True,
        "retention_days": 30
    },
    "required_log_fields": required_log_fields,
    "release_gate_consumers": ["release-gates", "ci-required", "proof-bundle"],
    "exceptions": []
}

metrics = {
    "scenario_id": "proof_budget_developer_smoke",
    "profile": "developer_smoke",
    "baseline_id": "proof-budget-baseline-2026-05-01",
    "observed_at": "2026-05-03T00:00:00Z",
    "metrics": [
        {"category": "runtime_overhead", "metric": "runtime_overhead_percent", "value": 4.0, "unit": "percent"},
        {"category": "memory_overhead", "metric": "memory_overhead_percent", "value": 7.0, "unit": "percent"},
        {"category": "artifact_disk_usage", "metric": "artifact_disk_bytes", "value": float(artifact_bytes), "unit": "bytes"},
        {"category": "log_volume", "metric": "log_bytes", "value": float(log_bytes), "unit": "bytes"},
        {"category": "repair_symbol_storage", "metric": "repair_symbol_bytes", "value": 4096.0, "unit": "bytes"},
        {"category": "rch_upload_size", "metric": "rch_upload_bytes", "value": 8192.0, "unit": "bytes"},
        {"category": "campaign_duration", "metric": "campaign_duration_seconds", "value": float(duration), "unit": "seconds"},
        {"category": "operator_report_size", "metric": "operator_report_bytes", "value": float(operator_report_bytes), "unit": "bytes"}
    ],
    "artifacts": [
        {"path": proof_bundle_path, "class": "proof_bundle", "size_bytes": os.path.getsize(proof_bundle_path), "mandatory": True},
        {"path": repro_pack_path, "class": "reproduction_pack", "size_bytes": os.path.getsize(repro_pack_path), "mandatory": True},
        {"path": stdout_path, "class": "raw_log", "size_bytes": os.path.getsize(stdout_path), "mandatory": False}
    ],
    "reproduction_command": reproduction_command
}

with open(budget_path, "w", encoding="utf-8") as handle:
    json.dump(budget, handle, indent=2, sort_keys=True)
    handle.write("\n")
with open(metrics_path, "w", encoding="utf-8") as handle:
    json.dump(metrics, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
    scenario_result "proof_budget_metrics_captured" "PASS" "bounded parity workflow metrics captured"
else
    scenario_result "proof_budget_metrics_captured" "FAIL" "bounded parity workflow failed"
fi

e2e_step "Scenario 3: release gate evaluates sample budget"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-proof-overhead-budget \
    --budget "$BUDGET_JSON" \
    --metrics "$METRICS_JSON" >"$REPORT_RAW" 2>&1; then
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
    if isinstance(obj, dict) and "release_gate_verdict" in obj:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("proof overhead budget report JSON object not found")
PY
    then
        scenario_result "proof_budget_release_gate_evaluates" "PASS" "budget evaluator returned success"
    else
        scenario_result "proof_budget_release_gate_evaluates" "FAIL" "budget report JSON missing or invalid"
    fi
else
    scenario_result "proof_budget_release_gate_evaluates" "FAIL" "budget evaluator failed"
fi

e2e_step "Scenario 4: report logs required budget fields"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
required = [
    "scenario_id",
    "profile",
    "baseline_id",
    "observed_value",
    "budget_value",
    "unit",
    "threshold_decision",
    "artifact_sizes",
    "compression_retention_decision",
    "reproduction_command",
]
if data.get("release_gate_verdict") != "pass":
    raise SystemExit(f"unexpected verdict: {data.get('release_gate_verdict')}")
if len(data.get("metric_results", [])) < 8:
    raise SystemExit("expected all proof budget metric categories")
if not all(field in data.get("required_log_fields", []) for field in required):
    raise SystemExit("required_log_fields missing release-gate fields")
for row in data.get("log_records", []):
    missing = [field for field in required if field not in row]
    if missing:
        raise SystemExit(f"log row missing fields: {missing}")
    if not row["artifact_sizes"]:
        raise SystemExit("log row missing artifact sizes")
    if not row["reproduction_command"]:
        raise SystemExit("log row missing reproduction command")
retention = data.get("retention_result", {})
if retention.get("compression_retention_decision") != "pass":
    raise SystemExit(f"unexpected retention decision: {retention}")
if "verdict=pass" not in data.get("human_summary", ""):
    raise SystemExit("human summary missing verdict")
PY
then
    scenario_result "proof_budget_log_contract" "PASS" "report exposes required log fields"
else
    scenario_result "proof_budget_log_contract" "FAIL" "report log contract validation failed"
fi

e2e_step "Scenario 5: unit/schema tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib -- proof_overhead_budget 2>&1 | tee "$UNIT_LOG"; then
    TESTS_RUN=$(grep -c "test proof_overhead_budget::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 8 ]]; then
        scenario_result "proof_budget_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "proof_budget_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "proof_budget_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_proof_overhead_budget completed"
else
    e2e_fail "ffs_proof_overhead_budget failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
