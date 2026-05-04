#!/usr/bin/env bash
# ffs_swarm_tail_latency_e2e.sh - smoke gate for bd-p2j3e.1.
#
# Validates the swarm tail-latency decomposition ledger. This suite is
# dry-run-only: it verifies component attribution, reference downgrade rules,
# and release-claim fail-closed behavior without running destructive mounted
# workloads.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export CARGO_TARGET_DIR="${FFS_SWARM_TAIL_CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_tail_latency}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
E2E_START_TIME="$(date +%s)"
E2E_LOG_DIR="${REPO_ROOT}/artifacts/e2e/$(date +%Y%m%d_%H%M%S)_ffs_swarm_tail_latency"
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
  "gate_id": "ffs_swarm_tail_latency",
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
e2e_log "E2E Test: ffs_swarm_tail_latency"
e2e_log "=============================================="
e2e_log "Started: $(date -Iseconds)"
e2e_log "Log directory: ${E2E_LOG_DIR}"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

LEDGER_JSON="benchmarks/swarm_tail_latency_ledger.json"
REPORT_RAW="${E2E_LOG_DIR}/swarm_tail_latency_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/swarm_tail_latency_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/swarm_tail_latency_report_md.raw"
MUTATED_COMPONENT_JSON="${E2E_LOG_DIR}/swarm_tail_bad_component.json"
MUTATED_COMPONENT_RAW="${E2E_LOG_DIR}/swarm_tail_bad_component.raw"
MUTATED_REFERENCE_JSON="${E2E_LOG_DIR}/swarm_tail_bad_reference.json"
MUTATED_REFERENCE_RAW="${E2E_LOG_DIR}/swarm_tail_bad_reference.raw"
MUTATED_HOST_JSON="${E2E_LOG_DIR}/swarm_tail_bad_host.json"
MUTATED_HOST_RAW="${E2E_LOG_DIR}/swarm_tail_bad_host.raw"
MUTATED_BUCKET_JSON="${E2E_LOG_DIR}/swarm_tail_bad_bucket.json"
MUTATED_BUCKET_RAW="${E2E_LOG_DIR}/swarm_tail_bad_bucket.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod swarm_tail_latency" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-tail-latency" crates/ffs-harness/src/main.rs \
    && [[ -f "$LEDGER_JSON" ]]; then
    scenario_result "swarm_tail_cli_wired" "PASS" "module, CLI command, and default ledger present"
else
    scenario_result "swarm_tail_cli_wired" "FAIL" "missing module export, CLI command, or default ledger"
fi

e2e_step "Scenario 2: unit tests cover ledger invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness swarm_tail_latency; then
    scenario_result "swarm_tail_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "swarm_tail_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default ledger validates with all classifications and dominance alerts"
if run_local_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$LEDGER_JSON"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true and .row_count == 5 and .missing_reference_count == 1 and .component_dominance_alert_count >= 3 and (.classification_counts.pass == 1) and (.classification_counts.warn == 1) and (.classification_counts.fail == 1) and (.classification_counts.noisy == 1) and (.classification_counts.missing_reference == 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "swarm_tail_default_ledger" "PASS" "default ledger preserves classifications, missing-reference downgrade, and dominance alerts"
    else
        scenario_result "swarm_tail_default_ledger" "FAIL" "default ledger report missing classification or dominance accounting"
    fi
else
    scenario_result "swarm_tail_default_ledger" "FAIL" "validator failed for default ledger; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering includes tail attribution and watched alerts"
if run_local_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$LEDGER_JSON" --format markdown; then
    if grep -q "Tail Attribution" "$REPORT_MD_RAW" && grep -q "wal_fsync" "$REPORT_MD_RAW" && grep -q "fuse_wrapper" "$REPORT_MD_RAW" && grep -q "missing_reference" "$REPORT_MD_RAW"; then
        scenario_result "swarm_tail_markdown" "PASS" "markdown summary includes tail attribution and watched dominant components"
    else
        scenario_result "swarm_tail_markdown" "FAIL" "markdown summary missing tail attribution, watched alert, or missing-reference row"
    fi
else
    scenario_result "swarm_tail_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: missing required component fails closed"
jq '.rows[0].latency.components |= map(select(.component != "wal_fsync"))' \
    "$LEDGER_JSON" >"$MUTATED_COMPONENT_JSON"
set +e
run_local_capture "$MUTATED_COMPONENT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$MUTATED_COMPONENT_JSON"
MUTATED_COMPONENT_STATUS=$?
set -e
if [[ $MUTATED_COMPONENT_STATUS -ne 0 ]] && grep -q "missing required component wal_fsync" "$MUTATED_COMPONENT_RAW"; then
    scenario_result "swarm_tail_missing_component_fail_closed" "PASS" "missing component attribution rejected"
else
    scenario_result "swarm_tail_missing_component_fail_closed" "FAIL" "missing component attribution was not rejected"
fi

e2e_step "Scenario 6: missing reference cannot become measured claim"
jq '.rows[4].release_claim_state = "measured_authoritative"' \
    "$LEDGER_JSON" >"$MUTATED_REFERENCE_JSON"
set +e
run_local_capture "$MUTATED_REFERENCE_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$MUTATED_REFERENCE_JSON"
MUTATED_REFERENCE_STATUS=$?
set -e
if [[ $MUTATED_REFERENCE_STATUS -ne 0 ]] && grep -q "public performance wording must remain experimental" "$MUTATED_REFERENCE_RAW"; then
    scenario_result "swarm_tail_missing_reference_fail_closed" "PASS" "missing reference measured claim rejected"
else
    scenario_result "swarm_tail_missing_reference_fail_closed" "FAIL" "missing reference measured claim was not rejected"
fi

e2e_step "Scenario 7: missing host fingerprint fails closed"
jq '.rows[0].host.host_fingerprint = ""' \
    "$LEDGER_JSON" >"$MUTATED_HOST_JSON"
set +e
run_local_capture "$MUTATED_HOST_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$MUTATED_HOST_JSON"
MUTATED_HOST_STATUS=$?
set -e
if [[ $MUTATED_HOST_STATUS -ne 0 ]] && grep -q "host.host_fingerprint" "$MUTATED_HOST_RAW"; then
    scenario_result "swarm_tail_missing_host_fail_closed" "PASS" "missing host fingerprint rejected"
else
    scenario_result "swarm_tail_missing_host_fail_closed" "FAIL" "missing host fingerprint was not rejected"
fi

e2e_step "Scenario 8: nonmonotonic p99 buckets fail closed"
jq '.rows[0].latency.p95_latency_us = 12000.0' \
    "$LEDGER_JSON" >"$MUTATED_BUCKET_JSON"
set +e
run_local_capture "$MUTATED_BUCKET_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$MUTATED_BUCKET_JSON"
MUTATED_BUCKET_STATUS=$?
set -e
if [[ $MUTATED_BUCKET_STATUS -ne 0 ]] && grep -q "p50 <= p95 <= p99" "$MUTATED_BUCKET_RAW"; then
    scenario_result "swarm_tail_nonmonotonic_bucket_fail_closed" "PASS" "nonmonotonic latency buckets rejected"
else
    scenario_result "swarm_tail_nonmonotonic_bucket_fail_closed" "FAIL" "nonmonotonic latency buckets were not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
