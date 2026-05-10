#!/usr/bin/env bash
# ffs_readiness_lab_e2e.sh - non-permissioned readiness-lab orchestrator.
#
# Runs the readiness-lab contract gate, permissioned campaign rehearsal packet
# gate, and readiness dashboard gate as one advisory evidence package. This
# script never exports permissioned ACK variables or executes xfstests/swarm
# workloads.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd -P)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

AGENT_NAME_FOR_TARGET="${AGENT_NAME:-CobaltPike}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/.cargo-target-frankenfs-${AGENT_NAME_FOR_TARGET}-bd-wt1rq}"
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

assert_no_permissioned_ack() {
    local phase="$1"
    local forbidden=(
        "XFSTESTS_REAL_RUN_ACK"
        "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD"
        "FFS_SWARM_WORKLOAD_REAL_RUN_ACK"
        "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER"
    )
    local present=()
    local name
    for name in "${forbidden[@]}"; do
        if [[ -n "${!name:-}" ]]; then
            present+=("$name")
        fi
    done
    if ((${#present[@]} > 0)); then
        e2e_log "PERMISSIONED_ACK_ENV_PRESENT|phase=${phase}|vars=${present[*]}"
        return 1
    fi
    return 0
}

record_child_result() {
    local child_id="$1"
    local script_path="$2"
    local status="$3"
    local log_dir="$4"
    local result_json="$5"
    local detail="$6"
    jq -cn \
        --arg child_id "$child_id" \
        --arg script_path "$script_path" \
        --arg status "$status" \
        --arg log_dir "$log_dir" \
        --arg result_json "$result_json" \
        --arg detail "$detail" \
        '{
          child_id: $child_id,
          script_path: $script_path,
          status: $status,
          log_dir: $log_dir,
          result_json: $result_json,
          detail: $detail
        }' >>"$CHILD_RESULTS_JSONL"
}

run_or_reuse_child_gate() {
    local scenario_id="$1"
    local script_path="$2"
    local expected_gate_id="$3"
    local reuse_env_name="$4"
    local reuse_log_dir="${!reuse_env_name:-}"
    local result_json

    if [[ -n "$reuse_log_dir" ]]; then
        e2e_step "Reuse child gate artifacts: ${script_path}"
        result_json="${reuse_log_dir}/result.json"
        if [[ -f "$result_json" ]] \
            && jq -e --arg gate_id "$expected_gate_id" '.gate_id == $gate_id and .verdict == "PASS"' "$result_json" >/dev/null \
            && assert_no_permissioned_ack "reuse-${scenario_id}"; then
            record_child_result "$scenario_id" "$script_path" "PASS" "$reuse_log_dir" "$result_json" "reused passing child gate artifacts"
            scenario_result "$scenario_id" "PASS" "reused child gate artifacts: ${reuse_log_dir}"
        else
            record_child_result "$scenario_id" "$script_path" "FAIL" "$reuse_log_dir" "$result_json" "reused child gate artifacts failed validation"
            scenario_result "$scenario_id" "FAIL" "reused child gate artifacts failed validation: ${reuse_log_dir}"
        fi
        return
    fi

    run_child_gate "$scenario_id" "$script_path" "$expected_gate_id"
}

run_child_gate() {
    local scenario_id="$1"
    local script_path="$2"
    local expected_gate_id="$3"
    local stdout_path="$REPORT_DIR/${scenario_id}.stdout"
    local stderr_path="$REPORT_DIR/${scenario_id}.stderr"
    local status
    local child_log_dir
    local result_json

    e2e_step "Child gate: ${script_path}"
    if ! assert_no_permissioned_ack "before-${scenario_id}"; then
        record_child_result "$scenario_id" "$script_path" "FAIL" "" "" "permissioned ACK env present before child"
        scenario_result "$scenario_id" "FAIL" "permissioned ACK env present before child"
        return
    fi

    set +e
    bash "$script_path" >"$stdout_path" 2>"$stderr_path"
    status=$?
    set -e

    child_log_dir="$(sed -n 's/^Log directory: //p' "$stdout_path" | tail -n 1)"
    result_json="${child_log_dir}/result.json"
    if [[ $status -eq 0 ]] \
        && [[ -f "$result_json" ]] \
        && jq -e --arg gate_id "$expected_gate_id" '.gate_id == $gate_id and .verdict == "PASS"' "$result_json" >/dev/null \
        && assert_no_permissioned_ack "after-${scenario_id}"; then
        record_child_result "$scenario_id" "$script_path" "PASS" "$child_log_dir" "$result_json" "child gate passed"
        scenario_result "$scenario_id" "PASS" "child gate passed: ${child_log_dir}"
    else
        record_child_result "$scenario_id" "$script_path" "FAIL" "${child_log_dir:-}" "${result_json:-}" "child gate failed"
        scenario_result "$scenario_id" "FAIL" "child gate failed; stdout=${stdout_path}; stderr=${stderr_path}"
    fi
}

validate_json_artifact() {
    local scenario_id="$1"
    local artifact_path="$2"
    local jq_filter="$3"
    local detail="$4"

    e2e_step "Validate artifact: ${scenario_id}"
    if [[ -f "$artifact_path" ]] && jq -e "$jq_filter" "$artifact_path" >/dev/null; then
        scenario_result "$scenario_id" "PASS" "$detail"
    else
        scenario_result "$scenario_id" "FAIL" "artifact validation failed: ${artifact_path}"
    fi
}

write_orchestrator_manifest() {
    python3 - "$E2E_LOG_FILE" "$CHILD_RESULTS_JSONL" "$MANIFEST_JSON" "$MANIFEST_MD" <<'PY'
import json
import pathlib
import re
import sys

log_path, child_path, manifest_path, markdown_path = map(pathlib.Path, sys.argv[1:])
scenario_re = re.compile(r"SCENARIO_RESULT\|scenario_id=([^|]+)\|outcome=([^|]+)(?:\|detail=(.*))?")
scenarios = []
for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
    match = scenario_re.search(line)
    if match:
        scenarios.append(
            {
                "scenario_id": match.group(1),
                "outcome": match.group(2),
                "detail": match.group(3) or "",
            }
        )

child_runs = []
if child_path.exists():
    for line in child_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            child_runs.append(json.loads(line))

scenario_pass_count = sum(1 for row in scenarios if row["outcome"] == "PASS")
scenario_fail_count = sum(1 for row in scenarios if row["outcome"] != "PASS")
manifest = {
    "schema_version": 1,
    "orchestrator_id": "frankenfs-readiness-lab:e2e:v1",
    "source_bead": "bd-wt1rq",
    "valid": scenario_fail_count == 0,
    "product_evidence_claim": "none",
    "permissioned_ack_consumed": False,
    "release_gate_effect": "advisory_only_no_public_readiness_change",
    "scenario_count": len(scenarios),
    "scenario_pass_count": scenario_pass_count,
    "scenario_fail_count": scenario_fail_count,
    "child_runs": child_runs,
    "scenarios": scenarios,
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    "# FrankenFS Readiness Lab E2E Orchestrator",
    "",
    f"- Valid: `{str(manifest['valid']).lower()}`",
    "- Product evidence claim: `none`",
    "- Permissioned ACK consumed: `false`",
    "- Release gate effect: `advisory_only_no_public_readiness_change`",
    f"- Scenarios: `{scenario_pass_count}/{len(scenarios)}` passed",
    "",
    "## Child Gates",
]
for child in child_runs:
    lines.append(f"- `{child['child_id']}`: `{child['status']}` -> `{child['log_dir']}`")
lines.extend(["", "## Scenarios"])
for scenario in scenarios:
    lines.append(f"- `{scenario['scenario_id']}`: `{scenario['outcome']}` - {scenario['detail']}")
markdown_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_readiness_lab"

REPORT_DIR="$E2E_LOG_DIR/readiness_lab_orchestrator"
CHILD_RESULTS_JSONL="$REPORT_DIR/child_results.jsonl"
MANIFEST_JSON="$REPORT_DIR/readiness_lab_orchestrator_manifest.json"
MANIFEST_MD="$REPORT_DIR/readiness_lab_orchestrator_manifest.md"
mkdir -p "$REPORT_DIR"
: >"$CHILD_RESULTS_JSONL"

e2e_step "Scenario 1: permissioned ACK boundary is absent"
if assert_no_permissioned_ack "start"; then
    scenario_result "readiness_lab_permission_boundary" "PASS" "no permissioned ACK env vars present"
else
    scenario_result "readiness_lab_permission_boundary" "FAIL" "permissioned ACK env var present"
fi

run_or_reuse_child_gate "readiness_lab_contracts_child" \
    "scripts/e2e/ffs_readiness_lab_contracts_e2e.sh" \
    "ffs_readiness_lab_contracts" \
    "FFS_READINESS_LAB_CONTRACTS_LOG_DIR"
run_or_reuse_child_gate "readiness_lab_permissioned_broker_child" \
    "scripts/e2e/ffs_permissioned_campaign_broker_e2e.sh" \
    "ffs_permissioned_campaign_broker" \
    "FFS_READINESS_LAB_PERMISSIONED_BROKER_LOG_DIR"
run_or_reuse_child_gate "readiness_lab_dashboard_child" \
    "scripts/e2e/ffs_readiness_dashboard_e2e.sh" \
    "ffs_readiness_dashboard" \
    "FFS_READINESS_LAB_DASHBOARD_LOG_DIR"

CONTRACTS_LOG_DIR="$(jq -r 'select(.child_id == "readiness_lab_contracts_child") | .log_dir' "$CHILD_RESULTS_JSONL" | tail -n 1)"
BROKER_LOG_DIR="$(jq -r 'select(.child_id == "readiness_lab_permissioned_broker_child") | .log_dir' "$CHILD_RESULTS_JSONL" | tail -n 1)"
DASHBOARD_LOG_DIR="$(jq -r 'select(.child_id == "readiness_lab_dashboard_child") | .log_dir' "$CHILD_RESULTS_JSONL" | tail -n 1)"

CONTRACT_REPORT_DIR="$CONTRACTS_LOG_DIR/readiness_lab_contracts"
BROKER_REPORT_DIR="$BROKER_LOG_DIR/permissioned_campaign_broker"
DASHBOARD_REPORT_DIR="$DASHBOARD_LOG_DIR/readiness_dashboard_reports"

validate_json_artifact "readiness_lab_contract_bundle" \
    "$CONTRACT_REPORT_DIR/report.json" \
    '.valid == true and .product_claim_violation_count == 0 and .advisory_artifact_count == .artifact_count' \
    "contract bundle remains advisory-only"

validate_json_artifact "readiness_lab_host_simulator" \
    "$CONTRACT_REPORT_DIR/host_simulation_report.json" \
    '.valid == true and .product_evidence_claim == "none" and (.release_gate_effect | test("swarm.responsiveness remains hidden"))' \
    "host simulator classifies advisory candidates without product evidence"

validate_json_artifact "readiness_lab_rch_scheduler" \
    "$CONTRACT_REPORT_DIR/rch_lane_schedule_report.json" \
    '.valid == true and .dry_run_only == true and .product_evidence_claim == "none" and .planned_lane_count > 0' \
    "RCH lane scheduler emits dry-run-only plan"

validate_json_artifact "readiness_lab_truth_graph" \
    "$CONTRACT_REPORT_DIR/truth_graph_report.json" \
    '.valid == true and .dry_run_only == true and .product_evidence_claim == "none" and .blocker_edge_count >= 1' \
    "truth graph links advisory evidence and blockers"

validate_json_artifact "readiness_lab_xfstests_rehearsal" \
    "$BROKER_REPORT_DIR/packets/xfstests_handoff_packet.json" \
    '.lane_kind == "xfstests_real_baseline" and .product_evidence_claim == "none" and .required_ack.env_var == "XFSTESTS_REAL_RUN_ACK" and (.authorization_notice | test("not executed evidence"))' \
    "xfstests rehearsal packet exists without executed product evidence"

validate_json_artifact "readiness_lab_numa_p99_replay" \
    "$CONTRACT_REPORT_DIR/numa_p99_replay_report.json" \
    '.valid == true and .replay_only == true and .product_evidence_claim == "none" and .fixture_count == 6 and .missing_shape_count == 0' \
    "NUMA/p99 replay fixtures cover advisory shapes"

validate_json_artifact "readiness_lab_dashboard_integration" \
    "$DASHBOARD_REPORT_DIR/dashboard.json" \
    '.valid == true and .source_report_count >= 8 and ([.claims[] | select(.source_kind | startswith("readiness_lab")) | .claim_state] | length >= 4)' \
    "dashboard consumes readiness-lab advisory reports"

validate_json_artifact "readiness_lab_advisory_release_gate" \
    "$DASHBOARD_REPORT_DIR/dashboard.json" \
    '.valid == true and ([.claims[] | select(.source_kind | startswith("readiness_lab")) | .claim_state] | all(. == "advisory_only" or . == "detection_only" or . == "dry_run_only" or . == "handoff_only" or . == "blocked"))' \
    "readiness-lab claims stay advisory or blocked in release-gate view"

e2e_step "Scenario 10: orchestrator manifest is written"
write_orchestrator_manifest
if jq -e '.valid == true and .product_evidence_claim == "none" and .permissioned_ack_consumed == false and .scenario_fail_count == 0' "$MANIFEST_JSON" >/dev/null \
    && grep -q "Product evidence claim: \`none\`" "$MANIFEST_MD"; then
    scenario_result "readiness_lab_orchestrator_manifest" "PASS" "combined JSON and Markdown manifest written"
else
    scenario_result "readiness_lab_orchestrator_manifest" "FAIL" "combined manifest validation failed"
fi

write_orchestrator_manifest

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass "ffs_readiness_lab completed (${PASS_COUNT}/${TOTAL})"
else
    e2e_fail "ffs_readiness_lab failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
