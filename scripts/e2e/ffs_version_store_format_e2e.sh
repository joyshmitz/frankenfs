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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_version_store_format}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"

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
    local status
    shift

    e2e_log "RCH command: $*"
    status=0
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
        timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 || status=$?
    if [[ $status -eq 0 ]]; then
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|log=${log_path}|status=${status}|timeout_secs=${RCH_COMMAND_TIMEOUT_SECS}"
        return 0
    fi
    return "$status"
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

TEST_LOG="$E2E_LOG_DIR/version_store_wal_roundtrip.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- wal::tests; then
    TESTS_RUN=$(grep -c "test wal::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "vs_format_commit_roundtrip" "PASS" "WAL encode/decode tests passed"
else
    scenario_result "vs_format_commit_roundtrip" "FAIL" "WAL encode/decode tests failed"
fi

#######################################
# Scenario 3: Truncated tail handling tests
#######################################
e2e_step "Scenario 3: Truncated tail handling"

TEST_LOG="$E2E_LOG_DIR/version_store_truncated_tail.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- truncat; then
    scenario_result "vs_format_truncated_tail" "PASS" "Truncated tail tests passed"
else
    scenario_result "vs_format_truncated_tail" "FAIL" "Truncated tail tests failed"
fi

#######################################
# Scenario 4: CRC corruption detection tests
#######################################
e2e_step "Scenario 4: CRC corruption detection"

TEST_LOG="$E2E_LOG_DIR/version_store_corrupt_crc.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- crc corrupt; then
    scenario_result "vs_format_corrupt_crc" "PASS" "CRC corruption detection tests passed"
else
    scenario_result "vs_format_corrupt_crc" "FAIL" "CRC corruption detection tests failed"
fi

#######################################
# Scenario 5: Monotonicity enforcement tests
#######################################
e2e_step "Scenario 5: Monotonicity enforcement"

TEST_LOG="$E2E_LOG_DIR/version_store_monotonicity.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- duplicate_commit_sequence; then
    scenario_result "vs_format_monotonic" "PASS" "Monotonicity enforcement tests passed"
else
    scenario_result "vs_format_monotonic" "FAIL" "Monotonicity enforcement tests failed"
fi

#######################################
# Scenario 6: Checkpoint + replay tests
#######################################
e2e_step "Scenario 6: Checkpoint + replay determinism"

TEST_LOG="$E2E_LOG_DIR/version_store_checkpoint_replay.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- checkpoint; then
    scenario_result "vs_format_checkpoint_replay" "PASS" "Checkpoint + replay tests passed"
else
    scenario_result "vs_format_checkpoint_replay" "FAIL" "Checkpoint + replay tests failed"
fi

#######################################
# Scenario 7: OQ7 format stability tests
#######################################
e2e_step "Scenario 7: OQ7 format stability"

TEST_LOG="$E2E_LOG_DIR/version_store_oq7_format.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- oq7_; then
    OQ7_COUNT=$(grep -c "test wal::tests::oq7_" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "vs_format_sentinels" "PASS" "OQ7 format stability tests passed (${OQ7_COUNT} tests)"
else
    scenario_result "vs_format_sentinels" "FAIL" "OQ7 format stability tests failed"
fi

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

TEST_LOG="$E2E_LOG_DIR/version_store_sync_failure.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- sync_failure; then
    scenario_result "vs_format_sync_required" "PASS" "Sync failure handling tests passed"
else
    scenario_result "vs_format_sync_required" "FAIL" "Sync failure handling tests failed"
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
