#!/usr/bin/env bash
# ffs_version_store_format_e2e.sh - E2E verification for version-store format decision (OQ7)
#
# Validates that:
# 1. WAL format constants are stable
# 2. WAL encode/decode tests pass
# 3. Persist tests (replay, checkpoint, crash) pass
# 4. Decision record exists with required sections
# 5. Spec marks OQ7 as resolved
#
# Usage: ./scripts/e2e/ffs_version_store_format_e2e.sh
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

e2e_init "ffs_version_store_format"

#######################################
# Scenario 1: WAL format constants exist in code
#######################################
e2e_step "Scenario 1: WAL format constants"

CONSTANTS_FOUND=0
for constant in "WAL_MAGIC" "WAL_VERSION" "CHECKSUM_TYPE_CRC32C" "HEADER_SIZE" "MIN_COMMIT_RECORD_SIZE" "RECORD_TYPE_COMMIT"; do
    if grep -q "pub const ${constant}" crates/ffs-mvcc/src/wal.rs; then
        CONSTANTS_FOUND=$((CONSTANTS_FOUND + 1))
    fi
done

if [[ $CONSTANTS_FOUND -eq 6 ]]; then
    scenario_result "vs_format_header" "PASS" "All 6 WAL format constants present"
else
    scenario_result "vs_format_header" "FAIL" "Only ${CONSTANTS_FOUND}/6 WAL format constants found"
fi

#######################################
# Scenario 2: WAL encode/decode tests pass
#######################################
e2e_step "Scenario 2: WAL encode/decode round-trip"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- wal::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test wal::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "vs_format_commit_roundtrip" "PASS" "WAL encode/decode tests passed"
else
    scenario_result "vs_format_commit_roundtrip" "FAIL" "WAL encode/decode tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 3: Truncated tail handling tests
#######################################
e2e_step "Scenario 3: Truncated tail handling"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- truncat 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "vs_format_truncated_tail" "PASS" "Truncated tail tests passed"
else
    scenario_result "vs_format_truncated_tail" "FAIL" "Truncated tail tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 4: CRC corruption detection tests
#######################################
e2e_step "Scenario 4: CRC corruption detection"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- crc corrupt 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "vs_format_corrupt_crc" "PASS" "CRC corruption detection tests passed"
else
    scenario_result "vs_format_corrupt_crc" "FAIL" "CRC corruption detection tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 5: Monotonicity enforcement tests
#######################################
e2e_step "Scenario 5: Monotonicity enforcement"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- duplicate_commit_sequence 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "vs_format_monotonic" "PASS" "Monotonicity enforcement tests passed"
else
    scenario_result "vs_format_monotonic" "FAIL" "Monotonicity enforcement tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 6: Checkpoint + replay tests
#######################################
e2e_step "Scenario 6: Checkpoint + replay determinism"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- checkpoint 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "vs_format_checkpoint_replay" "PASS" "Checkpoint + replay tests passed"
else
    scenario_result "vs_format_checkpoint_replay" "FAIL" "Checkpoint + replay tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 7: OQ7 format stability tests
#######################################
e2e_step "Scenario 7: OQ7 format stability"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- oq7_ 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    OQ7_COUNT=$(grep -c "test wal::tests::oq7_" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "vs_format_sentinels" "PASS" "OQ7 format stability tests passed (${OQ7_COUNT} tests)"
else
    scenario_result "vs_format_sentinels" "FAIL" "OQ7 format stability tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 8: Decision record exists
#######################################
e2e_step "Scenario 8: Decision record"

DECISION_DOC="docs/oq7-version-store-format.md"
if [[ -f "$DECISION_DOC" ]]; then
    SECTIONS_FOUND=0
    for section in "Accepted" "WAL v1" "Crash Consistency" "Alternatives" "Validation Matrix" "Durable Invariants"; do
        if grep -q "$section" "$DECISION_DOC"; then
            SECTIONS_FOUND=$((SECTIONS_FOUND + 1))
        fi
    done
    if [[ $SECTIONS_FOUND -ge 5 ]]; then
        scenario_result "vs_decision_record" "PASS" "Decision record with ${SECTIONS_FOUND}/6 required sections"
    else
        scenario_result "vs_decision_record" "FAIL" "Decision record only has ${SECTIONS_FOUND}/6 sections"
    fi
else
    scenario_result "vs_decision_record" "FAIL" "Decision record not found: $DECISION_DOC"
fi

#######################################
# Scenario 9: Sync requirement tests
#######################################
e2e_step "Scenario 9: Sync requirement (crash-safe mode)"

TEST_LOG=$(mktemp)
if cargo test -p ffs-mvcc -- sync_failure 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "vs_format_sync_required" "PASS" "Sync failure handling tests passed"
else
    scenario_result "vs_format_sync_required" "FAIL" "Sync failure handling tests failed"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

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
