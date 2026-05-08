#!/usr/bin/env bash
# ffs_crash_matrix_e2e.sh - E2E verification for deterministic crash/restart matrix (bd-h6nz.1.5)
#
# Validates that:
# 1. crash_matrix module exists and is publicly accessible
# 2. All 5 crash point classes are tested
# 3. Unit tests pass (crash_matrix::tests)
# 4. Structured logging markers are present
# 5. CrashMatrixReport is serializable to JSON
# 6. Existing WAL replay and persist tests still pass
# 7. No silent divergence across seeds
#
# Usage: ./scripts/e2e/ffs_crash_matrix_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_crash_matrix}"
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
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
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

e2e_init "ffs_crash_matrix"
e2e_print_env

#######################################
# Scenario 1: crash_matrix module exists
#######################################
e2e_step "Scenario 1: crash_matrix module exists"

if [[ -f "crates/ffs-mvcc/src/crash_matrix.rs" ]]; then
    scenario_result "crash_matrix_module_exists" "PASS" "crash_matrix.rs present"
else
    scenario_result "crash_matrix_module_exists" "FAIL" "crash_matrix.rs missing"
fi

#######################################
# Scenario 2: All 5 crash point classes
#######################################
e2e_step "Scenario 2: All crash point classes present"

CLASSES_FOUND=0
for class in "CrashBeforeRecordVisible" "CrashAfterRecordBeforeChecksum" "CrashAfterChecksumBeforeSync" "CrashAfterSyncBeforeCommitSeqPublish" "RepeatedCrashReplay"; do
    if grep -q "$class" crates/ffs-mvcc/src/crash_matrix.rs; then
        CLASSES_FOUND=$((CLASSES_FOUND + 1))
    fi
done

if [[ $CLASSES_FOUND -eq 5 ]]; then
    scenario_result "crash_point_classes" "PASS" "All 5 crash point classes present"
else
    scenario_result "crash_point_classes" "FAIL" "Only ${CLASSES_FOUND}/5 classes found"
fi

#######################################
# Scenario 3: CrashMatrixReport structure
#######################################
e2e_step "Scenario 3: CrashMatrixReport structure"

FIELDS_FOUND=0
for field in "pub seed" "pub total_scenarios" "pub passed" "pub failed" "pub scenarios"; do
    if grep -q "$field" crates/ffs-mvcc/src/crash_matrix.rs; then
        FIELDS_FOUND=$((FIELDS_FOUND + 1))
    fi
done

if [[ $FIELDS_FOUND -ge 5 ]]; then
    scenario_result "matrix_report_fields" "PASS" "CrashMatrixReport has all fields"
else
    scenario_result "matrix_report_fields" "FAIL" "Only ${FIELDS_FOUND}/5 report fields found"
fi

#######################################
# Scenario 4: Crash matrix unit tests pass
#######################################
e2e_step "Scenario 4: Crash matrix unit tests"

TEST_LOG="$E2E_LOG_DIR/crash_matrix_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- crash_matrix; then
    TESTS_RUN=$(grep -c "test crash_matrix::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "crash_matrix_tests" "PASS" "Unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "crash_matrix_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "crash_matrix_tests" "FAIL" "Unit tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 5: Structured logging markers
#######################################
e2e_step "Scenario 5: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "crash_matrix_start" "crash_matrix_done" "crash_matrix_scenario_start" "crash_matrix_scenario_pass" "crash_matrix_scenario_fail" "crash_matrix_cycle" "fail_fast_matrix_start" "fail_fast_matrix_done"; do
    if grep -q "\"${marker}\"" crates/ffs-mvcc/src/crash_matrix.rs; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 6 ]]; then
    scenario_result "structured_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/8 markers present"
else
    scenario_result "structured_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/8 structured log markers found"
fi

#######################################
# Scenario 6: Oracle validation present
#######################################
e2e_step "Scenario 6: Oracle validation"

ORACLE_FOUND=0
for pattern in "fn build_oracle_store" "fn verify_oracle" "fn generate_commits" "pub fn run_crash_matrix" "pub fn run_fail_fast_matrix"; do
    if grep -q "$pattern" crates/ffs-mvcc/src/crash_matrix.rs; then
        ORACLE_FOUND=$((ORACLE_FOUND + 1))
    fi
done

if [[ $ORACLE_FOUND -ge 5 ]]; then
    scenario_result "oracle_validation" "PASS" "Oracle and matrix API present (${ORACLE_FOUND}/5)"
else
    scenario_result "oracle_validation" "FAIL" "Only ${ORACLE_FOUND}/5 oracle/API functions found"
fi

#######################################
# Scenario 7: WAL replay tests still pass
#######################################
e2e_step "Scenario 7: WAL replay + persist tests"

TEST_LOG="$E2E_LOG_DIR/wal_replay_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests; then
    scenario_result "wal_replay_tests" "PASS" "WAL replay tests passed"
else
    scenario_result "wal_replay_tests" "FAIL" "WAL replay tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

TEST_LOG="$E2E_LOG_DIR/persist_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- persist::tests; then
    scenario_result "persist_tests" "PASS" "Persist tests passed"
else
    scenario_result "persist_tests" "FAIL" "Persist tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 8: Serializable report (JSON)
#######################################
e2e_step "Scenario 8: Report serialization"

if grep -q "Serialize, Deserialize" crates/ffs-mvcc/src/crash_matrix.rs; then
    scenario_result "report_serializable" "PASS" "CrashMatrixReport derives Serialize/Deserialize"
else
    scenario_result "report_serializable" "FAIL" "Missing Serialize/Deserialize on report types"
fi

#######################################
# Scenario 9: Deterministic by seed
#######################################
e2e_step "Scenario 9: Deterministic reproduction"

if grep -q "fn generate_commits_is_deterministic" crates/ffs-mvcc/src/crash_matrix.rs; then
    scenario_result "deterministic_seed" "PASS" "Deterministic seed test present"
else
    scenario_result "deterministic_seed" "FAIL" "Missing deterministic seed test"
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
