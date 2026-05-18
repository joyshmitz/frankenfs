#!/usr/bin/env bash
# ffs_wal_replay_e2e.sh - E2E verification for durable MVCC replay engine (bd-h6nz.1.3)
#
# Validates that:
# 1. WalReplayEngine type exists and is public
# 2. TailPolicy and ReplayOutcome enums exist
# 3. Replay engine unit tests pass (clean, truncated, corrupt, FailFast, etc.)
# 4. Persist integration tests pass (replay through PersistentMvccStore)
# 5. Structured logging events are emitted
# 6. Replay outcome classification is correct
# 7. Idempotent replay produces identical results
#
# Usage: ./scripts/e2e/ffs_wal_replay_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_wal_replay}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_WAL_REPLAY_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_WAL_REPLAY_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_WAL_REPLAY_SKIP_SELF_CHECK:-0}"

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
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_WAL_REPLAY_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected WAL replay fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown WAL replay fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"wal_replay::tests::replay_truncated"*)
        echo "test wal_replay::tests::replay_truncated_fixture ... ok"
        ;;
    *"wal_replay::tests::replay_corrupt_crc_fail_fast"*)
        echo "test wal_replay::tests::replay_corrupt_crc_fail_fast_fixture ... ok"
        ;;
    *"wal_replay::tests::replay_rejects"*)
        echo "test wal_replay::tests::replay_rejects_monotonicity_fixture ... ok"
        ;;
    *"wal_replay::tests::replay_is_idempotent"*)
        echo "test wal_replay::tests::replay_is_idempotent_fixture ... ok"
        ;;
    *"wal_replay::tests"*)
        for i in $(seq 1 15); do
            echo "test wal_replay::tests::fixture_replay_case_${i} ... ok"
        done
        ;;
    *"persist::tests"*)
        for i in $(seq 1 6); do
            echo "test persist::tests::fixture_persist_case_${i} ... ok"
        done
        ;;
    *)
        echo "unexpected WAL replay fixture command: $command_text" >&2
        exit 64
        ;;
esac

echo "test result: ok. fixture passed"
if [[ "$fixture_case" == "complete" ]]; then
    echo "Remote command finished: exit=0"
fi
exit 0
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
    local child_log="$E2E_LOG_DIR/wal_replay_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_WAL_REPLAY_SELF_CHECK=0 \
        FFS_WAL_REPLAY_SKIP_SELF_CHECK=1 \
        FFS_WAL_REPLAY_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_wal_replay_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic WAL replay wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-wal-replay-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .invalid_scenario_marker_count == 0
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "replay_engine_types" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "replay_engine_unit" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "wal_replay_monotonicity" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "wal_replay_idempotent" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "replay_persist_integration" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "wal_replay_logging_markers" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "replay_outcome_in_report" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "wal_replay_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "wal_replay_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "wal_replay_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "wal_replay_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "wal_replay_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "wal_replay_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_wal_replay"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

#######################################
# Scenario 1: Replay engine types exist and are public
#######################################
e2e_step "Scenario 1: Replay engine type existence"

TYPES_FOUND=0
for item in "pub enum TailPolicy" "pub enum ReplayOutcome" "pub struct ReplayReport" "pub struct WalReplayEngine"; do
    if grep -q "$item" crates/ffs-mvcc/src/wal_replay.rs; then
        TYPES_FOUND=$((TYPES_FOUND + 1))
    fi
done

if [[ $TYPES_FOUND -eq 4 ]]; then
    scenario_result "replay_engine_types" "PASS" "All 4 public types present"
else
    scenario_result "replay_engine_types" "FAIL" "Only ${TYPES_FOUND}/4 public types found"
fi

#######################################
# Scenario 2: TailPolicy variants
#######################################
e2e_step "Scenario 2: TailPolicy variants"

VARIANTS_FOUND=0
for variant in "TruncateToLastGood" "FailFast"; do
    if grep -q "$variant" crates/ffs-mvcc/src/wal_replay.rs; then
        VARIANTS_FOUND=$((VARIANTS_FOUND + 1))
    fi
done

if [[ $VARIANTS_FOUND -eq 2 ]]; then
    scenario_result "replay_tail_policy" "PASS" "Both TailPolicy variants present"
else
    scenario_result "replay_tail_policy" "FAIL" "Only ${VARIANTS_FOUND}/2 TailPolicy variants found"
fi

#######################################
# Scenario 3: ReplayOutcome variants
#######################################
e2e_step "Scenario 3: ReplayOutcome variants"

OUTCOME_FOUND=0
for variant in "Clean" "EmptyLog" "TruncatedTail" "CorruptTail" "MonotonicityViolation"; do
    if grep -q "$variant" crates/ffs-mvcc/src/wal_replay.rs; then
        OUTCOME_FOUND=$((OUTCOME_FOUND + 1))
    fi
done

if [[ $OUTCOME_FOUND -eq 5 ]]; then
    scenario_result "replay_outcome_variants" "PASS" "All 5 ReplayOutcome variants present"
else
    scenario_result "replay_outcome_variants" "FAIL" "Only ${OUTCOME_FOUND}/5 ReplayOutcome variants found"
fi

#######################################
# Scenario 4: Replay engine unit tests pass
#######################################
e2e_step "Scenario 4: Replay engine unit tests"

TEST_LOG="$E2E_LOG_DIR/wal_replay_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests; then
    TESTS_RUN=$(grep -c "test wal_replay::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "replay_engine_unit" "PASS" "Replay engine unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "replay_engine_unit" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "replay_engine_unit" "FAIL" "Replay engine unit tests failed"
fi

#######################################
# Scenario 5: Truncated tail handling tests
#######################################
e2e_step "Scenario 5: Truncated tail handling"

TEST_LOG="$E2E_LOG_DIR/wal_replay_truncated_tail.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_truncated; then
    scenario_result "replay_truncated_tail" "PASS" "Truncated tail tests passed"
else
    scenario_result "replay_truncated_tail" "FAIL" "Truncated tail tests failed"
fi

#######################################
# Scenario 6: FailFast policy tests
#######################################
e2e_step "Scenario 6: FailFast policy"

TEST_LOG="$E2E_LOG_DIR/wal_replay_fail_fast.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_corrupt_crc_fail_fast; then
    scenario_result "replay_fail_fast" "PASS" "FailFast policy tests passed"
else
    scenario_result "replay_fail_fast" "FAIL" "FailFast policy tests failed"
fi

#######################################
# Scenario 7: Monotonicity enforcement
#######################################
e2e_step "Scenario 7: Monotonicity enforcement"

TEST_LOG="$E2E_LOG_DIR/wal_replay_monotonicity.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_rejects; then
    scenario_result "wal_replay_monotonicity" "PASS" "Monotonicity enforcement tests passed"
else
    scenario_result "wal_replay_monotonicity" "FAIL" "Monotonicity enforcement tests failed"
fi

#######################################
# Scenario 8: Idempotent replay
#######################################
e2e_step "Scenario 8: Idempotent replay"

TEST_LOG="$E2E_LOG_DIR/wal_replay_idempotent.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_is_idempotent; then
    scenario_result "wal_replay_idempotent" "PASS" "Idempotent replay test passed"
else
    scenario_result "wal_replay_idempotent" "FAIL" "Idempotent replay test failed"
fi

#######################################
# Scenario 9: PersistentMvccStore integration (uses replay engine)
#######################################
e2e_step "Scenario 9: PersistentMvccStore integration"

TEST_LOG="$E2E_LOG_DIR/wal_replay_persist_integration.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- persist::tests; then
    PERSIST_TESTS=$(grep -c "test persist::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "replay_persist_integration" "PASS" "PersistentMvccStore tests passed (${PERSIST_TESTS} tests)"
else
    scenario_result "replay_persist_integration" "FAIL" "PersistentMvccStore tests failed"
fi

#######################################
# Scenario 10: Structured logging markers present
#######################################
e2e_step "Scenario 10: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "wal_replay_start" "wal_replay_done" "wal_replay_apply" "wal_replay_empty" "wal_replay_end_of_data" "wal_replay_truncated_tail" "wal_replay_corrupt_tail" "wal_replay_monotonicity_violation" "wal_replay_sentinel_rejected"; do
    if grep -q "\"${marker}\"" crates/ffs-mvcc/src/wal_replay.rs; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 7 ]]; then
    scenario_result "wal_replay_logging_markers" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/9 markers present"
else
    scenario_result "wal_replay_logging_markers" "FAIL" "Only ${LOG_MARKERS_FOUND}/9 structured log markers found"
fi

#######################################
# Scenario 11: ReplayOutcome integrated into WalRecoveryReport
#######################################
e2e_step "Scenario 11: ReplayOutcome in WalRecoveryReport"

if grep -q "pub outcome: ReplayOutcome" crates/ffs-mvcc/src/persist.rs; then
    scenario_result "replay_outcome_in_report" "PASS" "ReplayOutcome field present in WalRecoveryReport"
else
    scenario_result "replay_outcome_in_report" "FAIL" "ReplayOutcome field missing from WalRecoveryReport"
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
