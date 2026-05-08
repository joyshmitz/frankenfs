#!/usr/bin/env bash
# ffs_writeback_e2e.sh - Deterministic write-back durability E2E suite

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_writeback}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"

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
    local status
    shift

    e2e_log "RCH command: $*"
    status=0
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
        timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 || status=$?
    if [[ $status -eq 0 ]]; then
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|log=${log_path}|status=${status}|timeout_secs=${RCH_COMMAND_TIMEOUT_SECS}"
        return 0
    fi
    return "$status"
}

e2e_init "ffs_writeback_e2e"
e2e_print_env

e2e_step "Write-back cache durability scenarios"
e2e_log "Running deterministic scenarios from crates/ffs-block/tests/writeback_e2e.rs"
TEST_LOG="$E2E_LOG_DIR/writeback_e2e_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-block --test writeback_e2e -- --nocapture; then
    scenario_result "writeback_durability_unit_tests" "PASS" "writeback_e2e cargo test passed"
else
    scenario_result "writeback_durability_unit_tests" "FAIL" "writeback_e2e cargo test failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
    e2e_fail "Write-back durability unit tests failed"
fi

e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

e2e_pass
