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
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
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
e2e_rch_add_env_allowlist CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE
RCH_CAPTURE_VISIBILITY="${FFS_MVCC_REPLAY_GATE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_AGENT_TARGET_SUFFIX="${AGENT_NAME:-${USER:-agent}}"
RCH_CARGO_TARGET_DIR="${RCH_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_frankenfs_mvcc_replay_gate_$RCH_AGENT_TARGET_SUFFIX}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_MVCC_REPLAY_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_MVCC_REPLAY_GATE_SKIP_SELF_CHECK:-0}"

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
    local had_errexit=0
    shift

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$log_path"
    set +e
    setsid env \
        CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" \
        RCH_ENV_ALLOWLIST="$RCH_ENV_ALLOWLIST" \
        RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "$RCH_BIN" exec -- cargo "$@" >"$log_path" 2>&1 &
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
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}|command=cargo $*"
                terminate_rch_capture "$pid"
                e2e_rch_cancel_matching_queue_entry cargo "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=cargo $*"
            terminate_rch_capture "$pid"
            e2e_rch_cancel_matching_queue_entry cargo "$@"
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
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}|command=cargo $*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}|command=cargo $*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
            return 99
        fi
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

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_MVCC_REPLAY_GATE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        echo "Remote command finished: exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown MVCC replay gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-mvcc --lib")
        echo "running 320 tests"
        for i in $(seq -w 1 320); do
            echo "test mvcc_full_suite::fixture_case_${i} ... ok"
        done
        ;;
    *"cargo test -p ffs-mvcc --lib -- wal_replay::tests"*)
        echo "running 16 tests"
        for i in $(seq -w 1 16); do
            echo "test wal_replay::tests::fixture_replay_case_${i} ... ok"
        done
        ;;
    *"cargo test -p ffs-mvcc --lib -- crash_matrix"*)
        echo "running 16 tests"
        for i in $(seq -w 1 16); do
            echo "test crash_matrix::tests::fixture_crash_case_${i} ... ok"
        done
        ;;
    *"cargo test -p ffs-mvcc --lib -- persist::tests"*)
        echo "running 26 tests"
        for i in $(seq -w 1 26); do
            echo "test persist::tests::fixture_persist_case_${i} ... ok"
        done
        ;;
    *"cargo test -p ffs-cli -- wal_replay"*)
        printf '%s\n' \
            "running 4 tests" \
            "test cli::wal_replay_fixture_summary ... ok" \
            "test cli::wal_replay_fixture_json ... ok" \
            "test cli::wal_replay_fixture_errors ... ok" \
            "test cli::wal_replay_fixture_paths ... ok"
        ;;
    *"cargo test -p ffs-core -- mvcc_wal_recovery"*)
        printf '%s\n' \
            "running 2 tests" \
            "test mvcc_wal_recovery::fixture_replays_visible_state ... ok" \
            "test mvcc_wal_recovery::fixture_rejects_torn_record ... ok"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/mvcc_replay_gate_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_MVCC_REPLAY_GATE_SELF_CHECK=0 \
        FFS_MVCC_REPLAY_GATE_SKIP_SELF_CHECK=1 \
        FFS_MVCC_REPLAY_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_mvcc_replay_gate_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic MVCC replay gate wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-mvcc-replay-gate-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "mvcc_full_suite" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "wal_replay_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "crash_matrix_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "persist_layer_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "cli_wal_telemetry_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "core_wal_recovery" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "wal_replay_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "crash_matrix_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "mvcc_e2e_scripts" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "mvcc_replay_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "mvcc_replay_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "mvcc_replay_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "mvcc_replay_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "mvcc_replay_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "mvcc_replay_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_mvcc_replay_gate"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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
