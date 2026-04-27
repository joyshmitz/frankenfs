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

e2e_init "ffs_wal_replay"

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

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- wal_replay::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test wal_replay::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "replay_engine_unit" "PASS" "Replay engine unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "replay_engine_unit" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "replay_engine_unit" "FAIL" "Replay engine unit tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 5: Truncated tail handling tests
#######################################
e2e_step "Scenario 5: Truncated tail handling"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_truncated 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "replay_truncated_tail" "PASS" "Truncated tail tests passed"
else
    scenario_result "replay_truncated_tail" "FAIL" "Truncated tail tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 6: FailFast policy tests
#######################################
e2e_step "Scenario 6: FailFast policy"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_corrupt_crc_fail_fast 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "replay_fail_fast" "PASS" "FailFast policy tests passed"
else
    scenario_result "replay_fail_fast" "FAIL" "FailFast policy tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 7: Monotonicity enforcement
#######################################
e2e_step "Scenario 7: Monotonicity enforcement"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_rejects 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "replay_monotonicity" "PASS" "Monotonicity enforcement tests passed"
else
    scenario_result "replay_monotonicity" "FAIL" "Monotonicity enforcement tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 8: Idempotent replay
#######################################
e2e_step "Scenario 8: Idempotent replay"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- wal_replay::tests::replay_is_idempotent 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "replay_idempotent" "PASS" "Idempotent replay test passed"
else
    scenario_result "replay_idempotent" "FAIL" "Idempotent replay test failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 9: PersistentMvccStore integration (uses replay engine)
#######################################
e2e_step "Scenario 9: PersistentMvccStore integration"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- persist::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    PERSIST_TESTS=$(grep -c "test persist::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "replay_persist_integration" "PASS" "PersistentMvccStore tests passed (${PERSIST_TESTS} tests)"
else
    scenario_result "replay_persist_integration" "FAIL" "PersistentMvccStore tests failed"
fi
rm -f "$TEST_LOG"

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
    scenario_result "replay_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/9 markers present"
else
    scenario_result "replay_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/9 structured log markers found"
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
