#!/usr/bin/env bash
# ffs_wal_writer_e2e.sh - E2E verification for append-only WAL writer (bd-h6nz.1.2)
#
# Validates that:
# 1. WalWriter type exists and is public
# 2. WalWriter unit tests pass (append, monotonicity, backpressure, etc.)
# 3. PersistentMvccStore integration tests pass (commit, replay, rollback)
# 4. Property tests pass (monotonic ordering preservation)
# 5. Structured logging events are emitted
# 6. Error classification is correct (retryable vs fatal)
# 7. Sync policy variants work correctly
#
# Usage: ./scripts/e2e/ffs_wal_writer_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_wal_writer}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

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
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    shift

    e2e_log "RCH command: $*"
    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$log_path"
    set +e
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}|command=$*"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    return "$status"
}

log_test_tail() {
    local log_path="$1"

    if [[ -f "$log_path" ]]; then
        tail -40 "$log_path" | while IFS= read -r line; do e2e_log "  $line"; done
    fi
}

e2e_init "ffs_wal_writer"
e2e_print_env

#######################################
# Scenario 1: WalWriter type exists and is public
#######################################
e2e_step "Scenario 1: WalWriter type existence"

TYPES_FOUND=0
for item in "pub struct WalWriter" "pub enum WalWriteError" "pub enum SyncPolicy" "pub struct WalWriterConfig" "pub struct AppendResult"; do
    if grep -q "$item" crates/ffs-mvcc/src/wal_writer.rs; then
        TYPES_FOUND=$((TYPES_FOUND + 1))
    fi
done

if [[ $TYPES_FOUND -eq 5 ]]; then
    scenario_result "wal_writer_types" "PASS" "All 5 public types present"
else
    scenario_result "wal_writer_types" "FAIL" "Only ${TYPES_FOUND}/5 public types found"
fi

#######################################
# Scenario 2: WalWriter unit tests pass
#######################################
e2e_step "Scenario 2: WalWriter unit tests"

TEST_LOG="$E2E_LOG_DIR/wal_writer_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests; then
    TESTS_RUN=$(grep -Ec "^test wal_writer::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "wal_writer_unit" "PASS" "WalWriter unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "wal_writer_unit" "FAIL" "Too few WalWriter tests: ${TESTS_RUN} (expected >= 15)"
        log_test_tail "$TEST_LOG"
    fi
else
    scenario_result "wal_writer_unit" "FAIL" "WalWriter unit tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 3: Monotonicity enforcement tests
#######################################
e2e_step "Scenario 3: Monotonicity enforcement"

TEST_LOG="$E2E_LOG_DIR/wal_writer_monotonicity.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::rejects_non_monotonic; then
    scenario_result "wal_writer_monotonic" "PASS" "Monotonicity enforcement tests passed"
else
    scenario_result "wal_writer_monotonic" "FAIL" "Monotonicity enforcement tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 4: Sentinel rejection tests (D8)
#######################################
e2e_step "Scenario 4: Sentinel rejection (D8)"

TEST_LOG="$E2E_LOG_DIR/wal_writer_sentinel.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::rejects_sentinel; then
    scenario_result "wal_writer_sentinel" "PASS" "Sentinel rejection tests passed"
else
    scenario_result "wal_writer_sentinel" "FAIL" "Sentinel rejection tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 5: Backpressure threshold
#######################################
e2e_step "Scenario 5: Backpressure threshold"

TEST_LOG="$E2E_LOG_DIR/wal_writer_backpressure.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::backpressure; then
    scenario_result "wal_writer_backpressure" "PASS" "Backpressure threshold tests passed"
else
    scenario_result "wal_writer_backpressure" "FAIL" "Backpressure threshold tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 6: Sync policy variants
#######################################
e2e_step "Scenario 6: Sync policy variants"

TEST_LOG="$E2E_LOG_DIR/wal_writer_sync_policy.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::sync_policy; then
    SYNC_TESTS=$(grep -Ec "^test wal_writer::tests::sync_policy" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "wal_writer_sync_policy" "PASS" "Sync policy tests passed (${SYNC_TESTS} variants)"
else
    scenario_result "wal_writer_sync_policy" "FAIL" "Sync policy tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 7: Error classification
#######################################
e2e_step "Scenario 7: Error classification"

TEST_LOG="$E2E_LOG_DIR/wal_writer_error_classification.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::error_classification; then
    scenario_result "wal_writer_error_class" "PASS" "Error classification tests passed"
else
    scenario_result "wal_writer_error_class" "FAIL" "Error classification tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 8: Property test — monotonic ordering
#######################################
e2e_step "Scenario 8: Property test — monotonic ordering"

TEST_LOG="$E2E_LOG_DIR/wal_writer_proptest_monotonic.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::proptest_monotonic; then
    scenario_result "wal_writer_proptest_monotonic" "PASS" "Monotonic ordering property test passed"
else
    scenario_result "wal_writer_proptest_monotonic" "FAIL" "Monotonic ordering property test failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 9: PersistentMvccStore integration (uses WalWriter)
#######################################
e2e_step "Scenario 9: PersistentMvccStore integration"

TEST_LOG="$E2E_LOG_DIR/wal_writer_persist_integration.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- persist::tests; then
    PERSIST_TESTS=$(grep -Ec "^test persist::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "wal_writer_persist_integration" "PASS" "PersistentMvccStore tests passed (${PERSIST_TESTS} tests)"
else
    scenario_result "wal_writer_persist_integration" "FAIL" "PersistentMvccStore tests failed"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 10: Structured logging markers present
#######################################
e2e_step "Scenario 10: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "wal_append_start" "wal_append_ok" "wal_sync_ok" "wal_append_err" "wal_sync_err" "wal_backpressure" "wal_verify_ok" "wal_verify_err" "wal_flush_ok"; do
    if grep -q "\"${marker}\"" crates/ffs-mvcc/src/wal_writer.rs; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 7 ]]; then
    scenario_result "wal_writer_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/9 markers present"
else
    scenario_result "wal_writer_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/9 structured log markers found"
fi

#######################################
# Scenario 11: Write verification (read-back) capability
#######################################
e2e_step "Scenario 11: Write verification"

TEST_LOG="$E2E_LOG_DIR/wal_writer_verify_writes.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_writer::tests::verify_writes; then
    scenario_result "wal_writer_verify" "PASS" "Write verification test passed"
else
    scenario_result "wal_writer_verify" "FAIL" "Write verification test failed"
    log_test_tail "$TEST_LOG"
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
