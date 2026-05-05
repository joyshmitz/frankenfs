#!/usr/bin/env bash
# ffs_mvcc_replay_gate_e2e.sh - Verification gate for durable MVCC replay path (bd-h6nz.1.7)
#
# Final acceptance gate proving MVCC replay correctness, observability, and crash resilience.
#
# Validates:
# 1. ffs-mvcc full test suite passes (358+ tests)
# 2. WAL replay engine tests pass (happy path + corruption + torn records)
# 3. Crash matrix tests pass (deterministic crash/restart scenarios)
# 4. Persist layer tests pass (checkpoint + WAL round-trips)
# 5. CLI WAL telemetry tests pass
# 6. ffs-core WAL recovery integration tests pass
# 7. Structured logging: WAL replay lifecycle markers present
# 8. Structured logging: crash matrix markers present
# 9. E2E scripts for WAL/crash-matrix exist and are well-formed
#
# Usage: ./scripts/e2e/ffs_mvcc_replay_gate_e2e.sh
#
# Exit codes:
#   0 - All scenarios passed
#   1 - One or more scenarios failed

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Source shared helpers
source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:-CARGO_TARGET_DIR,RUST_LOG,RUST_BACKTRACE}"
RCH_AGENT_TARGET_SUFFIX="${AGENT_NAME:-${USER:-agent}}"
RCH_CARGO_TARGET_DIR="${RCH_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_frankenfs_mvcc_replay_gate_$RCH_AGENT_TARGET_SUFFIX}"

rch_allow_env() {
    local name="$1"
    if [[ ",$RCH_ENV_ALLOWLIST," != *",$name,"* ]]; then
        RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST},$name"
    fi
}

rch_allow_env CARGO_TARGET_DIR
rch_allow_env RUST_LOG
rch_allow_env RUST_BACKTRACE

run_rch_cargo() {
    CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
        RCH_ENV_ALLOWLIST="$RCH_ENV_ALLOWLIST" \
        RCH_VISIBILITY="$RCH_VISIBILITY" \
        "$RCH_BIN" exec -- cargo "$@"
}

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

e2e_init "ffs_mvcc_replay_gate"

WAL_REPLAY_SRC="crates/ffs-mvcc/src/wal_replay.rs"
CRASH_MATRIX_SRC="crates/ffs-mvcc/src/crash_matrix.rs"
PERSIST_SRC="crates/ffs-mvcc/src/persist.rs"

#######################################
# Scenario 1: Full ffs-mvcc test suite
#######################################
e2e_step "Scenario 1: Full ffs-mvcc test suite"

TEST_LOG=$(mktemp)
if run_rch_cargo test -p ffs-mvcc --lib 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test .*::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 300 ]]; then
        scenario_result "mvcc_full_suite" "PASS" "Full suite passed (${TESTS_RUN} tests)"
    else
        scenario_result "mvcc_full_suite" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 300)"
    fi
else
    scenario_result "mvcc_full_suite" "FAIL" "ffs-mvcc test suite failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 2: WAL replay tests
#######################################
e2e_step "Scenario 2: WAL replay engine tests"

TEST_LOG=$(mktemp)
if run_rch_cargo test -p ffs-mvcc --lib -- wal_replay::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test wal_replay::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "wal_replay_tests" "PASS" "WAL replay tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "wal_replay_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "wal_replay_tests" "FAIL" "WAL replay tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 3: Crash matrix tests
#######################################
e2e_step "Scenario 3: Crash matrix deterministic scenarios"

TEST_LOG=$(mktemp)
if run_rch_cargo test -p ffs-mvcc --lib -- crash_matrix 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test crash_matrix::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "crash_matrix_tests" "PASS" "Crash matrix tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "crash_matrix_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "crash_matrix_tests" "FAIL" "Crash matrix tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 4: Persist layer tests
#######################################
e2e_step "Scenario 4: Persist layer (checkpoint + WAL)"

TEST_LOG=$(mktemp)
if run_rch_cargo test -p ffs-mvcc --lib -- persist::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test persist::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 25 ]]; then
        scenario_result "persist_layer_tests" "PASS" "Persist tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "persist_layer_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 25)"
    fi
else
    scenario_result "persist_layer_tests" "FAIL" "Persist tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 5: CLI WAL telemetry tests
#######################################
e2e_step "Scenario 5: CLI WAL telemetry tests"

TEST_LOG=$(mktemp)
if run_rch_cargo test -p ffs-cli -- wal_replay 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test tests::wal_replay" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "cli_wal_telemetry_tests" "PASS" "CLI WAL tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "cli_wal_telemetry_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "cli_wal_telemetry_tests" "FAIL" "CLI WAL tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 6: ffs-core WAL recovery integration
#######################################
e2e_step "Scenario 6: ffs-core WAL recovery integration"

TEST_LOG=$(mktemp)
if run_rch_cargo test -p ffs-core -- mvcc_wal_recovery 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "core_wal_recovery" "PASS" "ffs-core WAL recovery tests passed"
else
    scenario_result "core_wal_recovery" "FAIL" "ffs-core WAL recovery tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 7: WAL replay structured logging
#######################################
e2e_step "Scenario 7: WAL replay structured logging markers"

REPLAY_MARKERS=0
for marker in "wal_replay_start" "wal_replay_done" "wal_replay_apply" "wal_replay_empty" "wal_replay_corrupt" "wal_replay_truncated"; do
    if grep -q "\"${marker}" "$WAL_REPLAY_SRC"; then
        REPLAY_MARKERS=$((REPLAY_MARKERS + 1))
    fi
done

if [[ $REPLAY_MARKERS -ge 5 ]]; then
    scenario_result "wal_replay_logging" "PASS" "${REPLAY_MARKERS}/6 WAL replay log markers present"
else
    scenario_result "wal_replay_logging" "FAIL" "Only ${REPLAY_MARKERS}/6 replay markers found"
fi

#######################################
# Scenario 8: Crash matrix structured logging
#######################################
e2e_step "Scenario 8: Crash matrix structured logging"

MATRIX_MARKERS=0
for marker in "crash_matrix_start" "crash_matrix_done" "crash_matrix_scenario"; do
    if grep -q "\"${marker}" "$CRASH_MATRIX_SRC"; then
        MATRIX_MARKERS=$((MATRIX_MARKERS + 1))
    fi
done

if [[ $MATRIX_MARKERS -ge 3 ]]; then
    scenario_result "crash_matrix_logging" "PASS" "${MATRIX_MARKERS}/3 crash matrix markers present"
else
    scenario_result "crash_matrix_logging" "FAIL" "Only ${MATRIX_MARKERS}/3 matrix markers found"
fi

#######################################
# Scenario 9: E2E scripts exist
#######################################
e2e_step "Scenario 9: MVCC E2E scripts present"

E2E_SCRIPTS_FOUND=0
for script in "ffs_wal_replay_e2e.sh" "ffs_wal_writer_e2e.sh" "ffs_crash_matrix_e2e.sh" "ffs_mvcc_lifecycle_e2e.sh" "ffs_cli_wal_telemetry_e2e.sh"; do
    if [[ -f "$REPO_ROOT/scripts/e2e/$script" ]]; then
        E2E_SCRIPTS_FOUND=$((E2E_SCRIPTS_FOUND + 1))
    fi
done

if [[ $E2E_SCRIPTS_FOUND -eq 5 ]]; then
    scenario_result "mvcc_e2e_scripts" "PASS" "All 5 MVCC E2E scripts present"
else
    scenario_result "mvcc_e2e_scripts" "FAIL" "Only ${E2E_SCRIPTS_FOUND}/5 E2E scripts found"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
else
    e2e_log "OVERALL: PASS"
    exit 0
fi
