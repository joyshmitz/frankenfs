#!/usr/bin/env bash
# ffs_scrub_repair_scheduler_e2e.sh - smoke gate for bd-p2j3e.6.
#
# Validates the morsel-driven scrub/repair scheduler proof plan, including
# fail-closed behavior for repair writeback bypass and foreground p99 budget
# overclaims.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export CARGO_TARGET_DIR="${FFS_SCRUB_REPAIR_SCHEDULER_CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_scrub_repair_scheduler}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
E2E_START_TIME="$(date +%s)"
E2E_LOG_DIR="${REPO_ROOT}/artifacts/e2e/$(date +%Y%m%d_%H%M%S)_ffs_scrub_repair_scheduler"
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
  "gate_id": "ffs_scrub_repair_scheduler",
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
e2e_log "E2E Test: ffs_scrub_repair_scheduler"
e2e_log "=============================================="
e2e_log "Started: $(date -Iseconds)"
e2e_log "Log directory: ${E2E_LOG_DIR}"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

MANIFEST_JSON="benchmarks/scrub_repair_scheduler_manifest.json"
REPORT_RAW="${E2E_LOG_DIR}/scrub_repair_scheduler_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/scrub_repair_scheduler_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/scrub_repair_scheduler_report_md.raw"
MUTATED_ROUTE_JSON="${E2E_LOG_DIR}/scrub_repair_scheduler_bad_route.json"
MUTATED_ROUTE_RAW="${E2E_LOG_DIR}/scrub_repair_scheduler_bad_route.raw"
MUTATED_P99_JSON="${E2E_LOG_DIR}/scrub_repair_scheduler_bad_p99.json"
MUTATED_P99_RAW="${E2E_LOG_DIR}/scrub_repair_scheduler_bad_p99.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod scrub_repair_scheduler" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-scrub-repair-scheduler" crates/ffs-harness/src/main.rs \
    && [[ -f "$MANIFEST_JSON" ]]; then
    scenario_result "scrub_repair_scheduler_cli_wired" "PASS" "module, CLI command, and default manifest present"
else
    scenario_result "scrub_repair_scheduler_cli_wired" "FAIL" "missing module export, CLI command, or default manifest"
fi

e2e_step "Scenario 2: unit tests cover scheduler invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness scrub_repair_scheduler; then
    scenario_result "scrub_repair_scheduler_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "scrub_repair_scheduler_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default manifest validates and feeds proof-bundle artifacts"
if run_local_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-scrub-repair-scheduler --manifest "$MANIFEST_JSON"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true and .scenario_count == 2 and .authoritative_claim_count == 1 and .conservative_claim_count == 1 and (.classification_counts.pass == 1) and (.classification_counts.skip == 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "scrub_repair_scheduler_default_manifest" "PASS" "valid manifest has authoritative plus conservative rows"
    else
        scenario_result "scrub_repair_scheduler_default_manifest" "FAIL" "manifest report missing expected claim or classification accounting"
    fi
else
    scenario_result "scrub_repair_scheduler_default_manifest" "FAIL" "validator failed for default manifest; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering exposes expected-loss accounting"
if run_local_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-scrub-repair-scheduler --manifest "$MANIFEST_JSON" --format markdown; then
    if grep -q "Freshness loss" "$REPORT_MD_RAW" && grep -q "Foreground loss" "$REPORT_MD_RAW"; then
        scenario_result "scrub_repair_scheduler_markdown" "PASS" "markdown summary includes loss accounting"
    else
        scenario_result "scrub_repair_scheduler_markdown" "FAIL" "markdown summary missing loss accounting"
    fi
else
    scenario_result "scrub_repair_scheduler_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: direct repair writeback bypass fails closed"
jq '.scenarios[0].ledger.mutation_route = "direct_block_write"' \
    "$MANIFEST_JSON" >"$MUTATED_ROUTE_JSON"
set +e
run_local_capture "$MUTATED_ROUTE_RAW" cargo run --quiet -p ffs-harness -- validate-scrub-repair-scheduler --manifest "$MUTATED_ROUTE_JSON"
MUTATED_ROUTE_STATUS=$?
set -e
if [[ $MUTATED_ROUTE_STATUS -ne 0 ]] && grep -q "bypasses the mounted mutation authority" "$MUTATED_ROUTE_RAW"; then
    scenario_result "scrub_repair_scheduler_bypass_fail_closed" "PASS" "direct repair writeback route rejected"
else
    scenario_result "scrub_repair_scheduler_bypass_fail_closed" "FAIL" "direct repair writeback route was not rejected"
fi

e2e_step "Scenario 6: foreground p99 over-budget pass fails closed"
jq '.scenarios[0].observed_foreground_p99_us = 7500.0' \
    "$MANIFEST_JSON" >"$MUTATED_P99_JSON"
set +e
run_local_capture "$MUTATED_P99_RAW" cargo run --quiet -p ffs-harness -- validate-scrub-repair-scheduler --manifest "$MUTATED_P99_JSON"
MUTATED_P99_STATUS=$?
set -e
if [[ $MUTATED_P99_STATUS -ne 0 ]] && grep -q "foreground p99 regression" "$MUTATED_P99_RAW"; then
    scenario_result "scrub_repair_scheduler_p99_fail_closed" "PASS" "over-budget pass row rejected"
else
    scenario_result "scrub_repair_scheduler_p99_fail_closed" "FAIL" "over-budget pass row was not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
