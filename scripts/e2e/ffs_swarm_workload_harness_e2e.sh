#!/usr/bin/env bash
# ffs_swarm_workload_harness_e2e.sh - smoke gate for bd-p2j3e.2.
#
# Validates the NUMA-aware swarm workload harness contract. The suite is
# dry-run-only: it checks command plans, host fingerprints, resource caps, and
# downgrade semantics without running destructive filesystem workloads.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export CARGO_TARGET_DIR="${FFS_SWARM_WORKLOAD_CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_workload_harness}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
E2E_START_TIME="$(date +%s)"
E2E_LOG_DIR="${REPO_ROOT}/artifacts/e2e/$(date +%Y%m%d_%H%M%S)_ffs_swarm_workload_harness"
E2E_LOG_FILE="${E2E_LOG_DIR}/run.log"

mkdir -p "$E2E_LOG_DIR"

e2e_log() {
    local message="$*"
    echo "$message"
    echo "$message" >>"$E2E_LOG_FILE"
}

e2e_step() {
    local step="$1"
    e2e_log ""
    e2e_log "=== ${step} ==="
    e2e_log "Time: $(date -Iseconds)"
}

e2e_finish() {
    local verdict="$1"
    local summary="$2"
    local duration
    duration=$(($(date +%s) - E2E_START_TIME))

    cat >"${E2E_LOG_DIR}/result.json" <<JSON
{
  "schema_version": 1,
  "runner_contract_version": 1,
  "gate_id": "ffs_swarm_workload_harness",
  "created_at": "$(date -Iseconds)",
  "verdict": "${verdict}",
  "summary": "${summary}",
  "pass_count": ${PASS_COUNT},
  "fail_count": ${FAIL_COUNT},
  "total": ${TOTAL},
  "duration_secs": ${duration},
  "log_file": "${E2E_LOG_FILE}"
}
JSON

    e2e_log ""
    e2e_log "=============================================="
    e2e_log "${verdict}: ${summary}"
    e2e_log "=============================================="
    e2e_log "Log file: ${E2E_LOG_FILE}"
    e2e_log "JSON summary written: ${E2E_LOG_DIR}/result.json"
}

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
    local output_path="$1"
    shift
    local status

    set +e
    RCH_VISIBILITY=none timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1
    status=$?
    set -e

    if [[ $status -eq 0 ]]; then
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

run_local_capture() {
    local output_path="$1"
    shift

    timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "$@" >"$output_path" 2>&1
}

e2e_log "=============================================="
e2e_log "E2E Test: ffs_swarm_workload_harness"
e2e_log "=============================================="
e2e_log "Started: $(date -Iseconds)"
e2e_log "Log directory: ${E2E_LOG_DIR}"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

MANIFEST_JSON="benchmarks/swarm_workload_harness_manifest.json"
REPORT_RAW="${E2E_LOG_DIR}/swarm_workload_harness_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/swarm_workload_harness_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/swarm_workload_harness_report_md.raw"
MUTATED_HOST_JSON="${E2E_LOG_DIR}/swarm_workload_bad_small_host.json"
MUTATED_HOST_RAW="${E2E_LOG_DIR}/swarm_workload_bad_small_host.raw"
MUTATED_NUMA_JSON="${E2E_LOG_DIR}/swarm_workload_bad_numa.json"
MUTATED_NUMA_RAW="${E2E_LOG_DIR}/swarm_workload_bad_numa.raw"
MUTATED_COMMAND_JSON="${E2E_LOG_DIR}/swarm_workload_bad_command.json"
MUTATED_COMMAND_RAW="${E2E_LOG_DIR}/swarm_workload_bad_command.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod swarm_workload_harness" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-workload-harness" crates/ffs-harness/src/main.rs \
    && [[ -f "$MANIFEST_JSON" ]]; then
    scenario_result "swarm_workload_cli_wired" "PASS" "module, CLI command, and default manifest present"
else
    scenario_result "swarm_workload_cli_wired" "FAIL" "missing module export, CLI command, or default manifest"
fi

e2e_step "Scenario 2: unit tests cover harness invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness swarm_workload_harness; then
    scenario_result "swarm_workload_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "swarm_workload_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default manifest validates with all required workload profiles"
if run_local_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MANIFEST_JSON"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true and .profile_count == 5 and .missing_workload_classes == [] and .large_host_plan_count == 1 and .host_downgrade_count == 1 and (.release_claim_counts.plan_ready == 1) and (.release_claim_counts.small_host_smoke == 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "swarm_workload_default_manifest" "PASS" "default manifest preserves plan-ready and downgraded rows"
    else
        scenario_result "swarm_workload_default_manifest" "FAIL" "manifest report missing workload or downgrade accounting"
    fi
else
    scenario_result "swarm_workload_default_manifest" "FAIL" "validator failed for default manifest; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering includes host downgrade and workload matrix"
if run_local_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MANIFEST_JSON" --format markdown; then
    if grep -q "Host downgrades" "$REPORT_MD_RAW" && grep -q "metadata_storm" "$REPORT_MD_RAW" && grep -q "cache_pressure" "$REPORT_MD_RAW"; then
        scenario_result "swarm_workload_markdown" "PASS" "markdown summary includes downgrade and workload matrix"
    else
        scenario_result "swarm_workload_markdown" "FAIL" "markdown summary missing downgrade or workload matrix"
    fi
else
    scenario_result "swarm_workload_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: small-host 64-core claim fails closed"
jq '.scenarios[1].classification = "pass" | .scenarios[1].release_claim_state = "measured_authoritative"' \
    "$MANIFEST_JSON" >"$MUTATED_HOST_JSON"
set +e
run_local_capture "$MUTATED_HOST_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MUTATED_HOST_JSON"
MUTATED_HOST_STATUS=$?
set -e
if [[ $MUTATED_HOST_STATUS -ne 0 ]] && grep -q "below the 64-core/256GB target" "$MUTATED_HOST_RAW"; then
    scenario_result "swarm_workload_small_host_fail_closed" "PASS" "small-host measured_authoritative mutation rejected"
else
    scenario_result "swarm_workload_small_host_fail_closed" "FAIL" "small-host measured_authoritative mutation was not rejected"
fi

e2e_step "Scenario 6: missing NUMA visibility rationale fails closed"
jq 'del(.scenarios[1].host.numa.missing_reason)' \
    "$MANIFEST_JSON" >"$MUTATED_NUMA_JSON"
set +e
run_local_capture "$MUTATED_NUMA_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MUTATED_NUMA_JSON"
MUTATED_NUMA_STATUS=$?
set -e
if [[ $MUTATED_NUMA_STATUS -ne 0 ]] && grep -q "missing_reason" "$MUTATED_NUMA_RAW"; then
    scenario_result "swarm_workload_numa_reason_fail_closed" "PASS" "missing NUMA visibility reason rejected"
else
    scenario_result "swarm_workload_numa_reason_fail_closed" "FAIL" "missing NUMA visibility reason was not rejected"
fi

e2e_step "Scenario 7: mutating host command plan fails closed"
jq '.workload_profiles[0].command_plan.mutates_host_filesystems = true' \
    "$MANIFEST_JSON" >"$MUTATED_COMMAND_JSON"
set +e
run_local_capture "$MUTATED_COMMAND_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MUTATED_COMMAND_JSON"
MUTATED_COMMAND_STATUS=$?
set -e
if [[ $MUTATED_COMMAND_STATUS -ne 0 ]] && grep -q "mutates host filesystems" "$MUTATED_COMMAND_RAW"; then
    scenario_result "swarm_workload_mutating_command_fail_closed" "PASS" "mutating host command plan rejected"
else
    scenario_result "swarm_workload_mutating_command_fail_closed" "FAIL" "mutating host command plan was not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
