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
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

rch_allow_env() {
    local name="$1"
    if [[ ",$RCH_ENV_ALLOWLIST," != *",$name,"* ]]; then
        RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST},$name"
    fi
}

rch_allow_env CARGO_TARGET_DIR
rch_allow_env RUST_LOG
rch_allow_env RUST_BACKTRACE

terminate_rch_capture() {
    local pid="$1"
    kill -TERM "-$pid" >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
}

run_rch_cargo_capture() {
    local log_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    shift

    : >"$log_path"
    set +e
    setsid env \
        CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
        RCH_ENV_ALLOWLIST="$RCH_ENV_ALLOWLIST" \
        RCH_VISIBILITY="$RCH_VISIBILITY" \
        "$RCH_BIN" exec -- cargo "$@" >"$log_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}"
                terminate_rch_capture "$pid"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}"
            terminate_rch_capture "$pid"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
            return 99
        fi
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|log=${log_path}|status=${status}"
        return 0
    fi
    return "$status"
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

TEST_LOG="${E2E_LOG_DIR}/mvcc_full_suite.log"
if run_rch_cargo_capture "$TEST_LOG" test -p ffs-mvcc --lib; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    TESTS_RUN=$(grep -c "test .*::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 300 ]]; then
        scenario_result "mvcc_full_suite" "PASS" "Full suite passed (${TESTS_RUN} tests)"
    else
        scenario_result "mvcc_full_suite" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 300)"
    fi
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "mvcc_full_suite" "FAIL" "ffs-mvcc test suite failed"
fi

#######################################
# Scenario 2: WAL replay tests
#######################################
e2e_step "Scenario 2: WAL replay engine tests"

TEST_LOG="${E2E_LOG_DIR}/wal_replay_tests.log"
if run_rch_cargo_capture "$TEST_LOG" test -p ffs-mvcc --lib -- wal_replay::tests; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    TESTS_RUN=$(grep -c "test wal_replay::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "wal_replay_tests" "PASS" "WAL replay tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "wal_replay_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "wal_replay_tests" "FAIL" "WAL replay tests failed"
fi

#######################################
# Scenario 3: Crash matrix tests
#######################################
e2e_step "Scenario 3: Crash matrix deterministic scenarios"

TEST_LOG="${E2E_LOG_DIR}/crash_matrix_tests.log"
if run_rch_cargo_capture "$TEST_LOG" test -p ffs-mvcc --lib -- crash_matrix; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    TESTS_RUN=$(grep -c "test crash_matrix::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "crash_matrix_tests" "PASS" "Crash matrix tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "crash_matrix_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "crash_matrix_tests" "FAIL" "Crash matrix tests failed"
fi

#######################################
# Scenario 4: Persist layer tests
#######################################
e2e_step "Scenario 4: Persist layer (checkpoint + WAL)"

TEST_LOG="${E2E_LOG_DIR}/persist_layer_tests.log"
if run_rch_cargo_capture "$TEST_LOG" test -p ffs-mvcc --lib -- persist::tests; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    TESTS_RUN=$(grep -c "test persist::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 25 ]]; then
        scenario_result "persist_layer_tests" "PASS" "Persist tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "persist_layer_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 25)"
    fi
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "persist_layer_tests" "FAIL" "Persist tests failed"
fi

#######################################
# Scenario 5: CLI WAL telemetry tests
#######################################
e2e_step "Scenario 5: CLI WAL telemetry tests"

TEST_LOG="${E2E_LOG_DIR}/cli_wal_telemetry_tests.log"
if run_rch_cargo_capture "$TEST_LOG" test -p ffs-cli -- wal_replay; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    TESTS_RUN=$(grep -c "^test .* \.\.\. ok$" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "cli_wal_telemetry_tests" "PASS" "CLI WAL tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "cli_wal_telemetry_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "cli_wal_telemetry_tests" "FAIL" "CLI WAL tests failed"
fi

#######################################
# Scenario 6: ffs-core WAL recovery integration
#######################################
e2e_step "Scenario 6: ffs-core WAL recovery integration"

TEST_LOG="${E2E_LOG_DIR}/core_wal_recovery.log"
if run_rch_cargo_capture "$TEST_LOG" test -p ffs-core -- mvcc_wal_recovery; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "core_wal_recovery" "PASS" "ffs-core WAL recovery tests passed"
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >>"$E2E_LOG_FILE"
    scenario_result "core_wal_recovery" "FAIL" "ffs-core WAL recovery tests failed"
fi

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
