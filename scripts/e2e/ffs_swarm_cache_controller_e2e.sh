#!/usr/bin/env bash
# ffs_swarm_cache_controller_e2e.sh - smoke gate for bd-p2j3e.5.
#
# Validates the swarm cache controller contract, including the rule that
# small-host fixture evidence must downgrade release claims instead of becoming
# a 64-core/256GB performance proof.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export CARGO_TARGET_DIR="${FFS_SWARM_CACHE_CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_cache_controller}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
E2E_START_TIME="$(date +%s)"
E2E_LOG_DIR="${REPO_ROOT}/artifacts/e2e/$(date +%Y%m%d_%H%M%S)_ffs_swarm_cache_controller"
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
  "gate_id": "ffs_swarm_cache_controller",
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
e2e_log "E2E Test: ffs_swarm_cache_controller"
e2e_log "=============================================="
e2e_log "Started: $(date -Iseconds)"
e2e_log "Log directory: ${E2E_LOG_DIR}"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

CONTRACT_JSON="benchmarks/swarm_cache_controller_contract.json"
REPORT_RAW="${E2E_LOG_DIR}/swarm_cache_controller_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/swarm_cache_controller_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/swarm_cache_controller_report_md.raw"
MUTATED_JSON="${E2E_LOG_DIR}/swarm_cache_controller_bad_small_host.json"
MUTATED_RAW="${E2E_LOG_DIR}/swarm_cache_controller_bad_small_host.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod swarm_cache_controller" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-cache-controller" crates/ffs-harness/src/main.rs \
    && [[ -f "$CONTRACT_JSON" ]]; then
    scenario_result "swarm_cache_cli_wired" "PASS" "module, CLI command, and default contract present"
else
    scenario_result "swarm_cache_cli_wired" "FAIL" "missing module export, CLI command, or default contract"
fi

e2e_step "Scenario 2: unit tests cover contract invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness swarm_cache_controller; then
    scenario_result "swarm_cache_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "swarm_cache_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default contract validates and preserves small-host downgrade"
if run_local_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-cache-controller --contract "$CONTRACT_JSON"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true and .small_host_downgrade_count == 1 and .authoritative_claim_count == 1 and (.claim_state_counts.small_host_smoke >= 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "swarm_cache_default_contract" "PASS" "valid contract includes one small-host downgrade and one authoritative reference fixture"
    else
        scenario_result "swarm_cache_default_contract" "FAIL" "contract report missing expected claim-state accounting"
    fi
else
    scenario_result "swarm_cache_default_contract" "FAIL" "validator failed for default contract; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering is generated from validation report"
if run_local_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-cache-controller --contract "$CONTRACT_JSON" --format markdown; then
    if grep -q "Small-host downgrades" "$REPORT_MD_RAW" && grep -q "small_host_smoke" "$REPORT_MD_RAW"; then
        scenario_result "swarm_cache_markdown" "PASS" "markdown summary includes downgrade accounting"
    else
        scenario_result "swarm_cache_markdown" "FAIL" "markdown summary missing downgrade accounting"
    fi
else
    scenario_result "swarm_cache_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: small-host authoritative claims fail closed"
jq '.scenarios[1].release_claim_state = "measured_authoritative" | .scenarios[1].measurements[0].release_claim_state = "measured_authoritative"' \
    "$CONTRACT_JSON" >"$MUTATED_JSON"
set +e
run_local_capture "$MUTATED_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-cache-controller --contract "$MUTATED_JSON"
MUTATED_STATUS=$?
set -e
if [[ $MUTATED_STATUS -ne 0 ]] && grep -q "below the 64-core/256GB target" "$MUTATED_RAW"; then
    scenario_result "swarm_cache_small_host_fail_closed" "PASS" "small-host measured_authoritative mutation rejected"
else
    scenario_result "swarm_cache_small_host_fail_closed" "FAIL" "small-host measured_authoritative mutation was not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
