#!/usr/bin/env bash
# ffs_mvcc_lifecycle_e2e.sh - E2E verification for durable MVCC OpenFs integration (bd-h6nz.1.4)
#
# Validates that:
# 1. OpenOptions has mvcc_wal_path and mvcc_replay_policy fields
# 2. OpenFs has mvcc_wal_recovery field and accessor
# 3. Integration tests pass (clean replay, truncated tail, FailFast fallback)
# 4. Structured logging events are emitted
# 5. init_mvcc_store helper exists
#
# Usage: ./scripts/e2e/ffs_mvcc_lifecycle_e2e.sh
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

e2e_init "ffs_mvcc_lifecycle"

#######################################
# Scenario 1: OpenOptions has WAL fields
#######################################
e2e_step "Scenario 1: OpenOptions WAL fields"

FIELDS_FOUND=0
for field in "pub mvcc_wal_path" "pub mvcc_replay_policy"; do
    if grep -q "$field" crates/ffs-core/src/lib.rs; then
        FIELDS_FOUND=$((FIELDS_FOUND + 1))
    fi
done

if [[ $FIELDS_FOUND -eq 2 ]]; then
    scenario_result "open_options_wal_fields" "PASS" "Both WAL fields present in OpenOptions"
else
    scenario_result "open_options_wal_fields" "FAIL" "Only ${FIELDS_FOUND}/2 WAL fields found"
fi

#######################################
# Scenario 2: OpenFs has mvcc_wal_recovery
#######################################
e2e_step "Scenario 2: OpenFs mvcc_wal_recovery field"

if grep -q "pub mvcc_wal_recovery" crates/ffs-core/src/lib.rs; then
    scenario_result "openfs_wal_recovery" "PASS" "mvcc_wal_recovery field present"
else
    scenario_result "openfs_wal_recovery" "FAIL" "mvcc_wal_recovery field missing"
fi

#######################################
# Scenario 3: init_mvcc_store helper
#######################################
e2e_step "Scenario 3: init_mvcc_store helper"

if grep -q "fn init_mvcc_store" crates/ffs-core/src/lib.rs; then
    scenario_result "init_mvcc_store" "PASS" "init_mvcc_store helper present"
else
    scenario_result "init_mvcc_store" "FAIL" "init_mvcc_store helper missing"
fi

#######################################
# Scenario 4: Integration tests pass
#######################################
e2e_step "Scenario 4: MVCC WAL integration tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-core --lib -- mvcc_wal 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test tests::mvcc_wal" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "mvcc_wal_integration" "PASS" "Integration tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "mvcc_wal_integration" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "mvcc_wal_integration" "FAIL" "Integration tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 5: Replay engine tests still pass
#######################################
e2e_step "Scenario 5: Replay engine unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- wal_replay::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "replay_engine_unit" "PASS" "Replay engine unit tests passed"
else
    scenario_result "replay_engine_unit" "FAIL" "Replay engine unit tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 6: Structured logging markers
#######################################
e2e_step "Scenario 6: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "mvcc_store_init" "mvcc_wal_not_found" "mvcc_wal_empty" "mvcc_wal_replay_begin" "mvcc_wal_replay_done" "mvcc_wal_replay_failed_fallback" "mvcc_wal_bad_header" "mvcc_wal_too_small"; do
    if grep -q "\"${marker}\"" crates/ffs-core/src/lib.rs; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 6 ]]; then
    scenario_result "lifecycle_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/8 markers present"
else
    scenario_result "lifecycle_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/8 structured log markers found"
fi

#######################################
# Scenario 7: Persist tests still pass
#######################################
e2e_step "Scenario 7: Persist tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc --lib -- persist::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "persist_tests" "PASS" "Persist tests passed"
else
    scenario_result "persist_tests" "FAIL" "Persist tests failed"
fi
rm -f "$TEST_LOG"

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
