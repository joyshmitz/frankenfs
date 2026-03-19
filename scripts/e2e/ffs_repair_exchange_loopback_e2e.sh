#!/usr/bin/env bash
# ffs_repair_exchange_loopback_e2e.sh - Loopback verification for repair symbol exchange
#
# Usage: ./scripts/e2e/ffs_repair_exchange_loopback_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

e2e_init "ffs_repair_exchange_loopback"

e2e_step "Scenario 1: Unit framing and retry tests"
if rch exec -- cargo test -p ffs-repair exchange::tests:: -- --nocapture; then
    scenario_result "repair_exchange_unit_tests" "PASS" "Framing and retry tests passed"
else
    scenario_result "repair_exchange_unit_tests" "FAIL" "Framing and retry tests failed"
fi

e2e_step "Scenario 2: Loopback symbol exchange"
if rch exec -- cargo test -p ffs-repair exchange::tests::loopback_exchange_e2e -- --nocapture --test-threads=1; then
    scenario_result "repair_exchange_loopback" "PASS" "Loopback get/put exchange passed"
else
    scenario_result "repair_exchange_loopback" "FAIL" "Loopback get/put exchange failed"
fi

e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
fi

e2e_log "OVERALL: PASS"
