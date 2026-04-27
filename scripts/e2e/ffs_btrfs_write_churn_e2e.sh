#!/usr/bin/env bash
# ffs_btrfs_write_churn_e2e.sh - E2E verification for btrfs scrub/repair under write churn (bd-h6nz.3.4)
#
# Validates that:
# 1. Write-churn stress tests exist and cover corruption detection
# 2. No-false-clean invariant test exists
# 3. Recovery with fresh symbols under churn works
# 4. Evidence ledger captures churn context
# 5. Staleness timeout recovery path tested
# 6. Structured logging markers for scrub/repair events present
# 7. All pipeline tests pass
# 8. Btrfs validators still pass
# 9. Btrfs repair CLI tests still pass
#
# Usage: ./scripts/e2e/ffs_btrfs_write_churn_e2e.sh
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

e2e_init "ffs_btrfs_write_churn"

PIPELINE_SRC="crates/ffs-repair/src/pipeline.rs"

#######################################
# Scenario 1: Write-churn stress tests exist
#######################################
e2e_step "Scenario 1: Write-churn stress tests present"

TESTS_FOUND=0
for test_name in "scrub_detects_corruption_after_write_churn" "no_false_clean_when_corruption_exists_under_heavy_churn" "recovery_succeeds_with_fresh_symbols_under_write_churn" "evidence_ledger_captures_churn_context" "write_churn_with_staleness_timeout_still_recovers"; do
    if grep -q "fn ${test_name}" "$PIPELINE_SRC"; then
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
done

if [[ $TESTS_FOUND -eq 5 ]]; then
    scenario_result "churn_tests_exist" "PASS" "All 5 write-churn stress tests present"
else
    scenario_result "churn_tests_exist" "FAIL" "Only ${TESTS_FOUND}/5 write-churn tests found"
fi

#######################################
# Scenario 2: No-false-clean invariant
#######################################
e2e_step "Scenario 2: No-false-clean invariant test"

if grep -q 'scrub must NEVER report 0 corruption' "$PIPELINE_SRC"; then
    scenario_result "no_false_clean_invariant" "PASS" "No-false-clean invariant test documented"
else
    scenario_result "no_false_clean_invariant" "FAIL" "Missing no-false-clean invariant documentation"
fi

#######################################
# Scenario 3: Evidence churn context
#######################################
e2e_step "Scenario 3: Evidence ledger churn context"

if grep -q 'evidence must record corruption detection' "$PIPELINE_SRC" && grep -q 'evidence must record repair attempt' "$PIPELINE_SRC"; then
    scenario_result "evidence_churn_context" "PASS" "Evidence churn context assertions present"
else
    scenario_result "evidence_churn_context" "FAIL" "Missing evidence churn context assertions"
fi

#######################################
# Scenario 4: Structured logging markers
#######################################
e2e_step "Scenario 4: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "scrub_and_recover" "scrub complete" "refresh_staleness_timeout_triggered" "refresh_group_marked_dirty" "symbol_refresh_complete"; do
    if grep -q "$marker" "$PIPELINE_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 4 ]]; then
    scenario_result "logging_markers" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/5 markers present"
else
    scenario_result "logging_markers" "FAIL" "Only ${LOG_MARKERS_FOUND}/5 markers found"
fi

#######################################
# Scenario 5: Write-churn tests pass
#######################################
e2e_step "Scenario 5: Write-churn tests pass"

TEST_LOG=$(mktemp)
if cargo test -p ffs-repair --lib -- scrub_detects_corruption_after_write_churn no_false_clean recovery_succeeds_with_fresh evidence_ledger_captures_churn write_churn_with_staleness 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 5 ]]; then
        scenario_result "churn_tests_pass" "PASS" "Write-churn tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "churn_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 5)"
    fi
else
    scenario_result "churn_tests_pass" "FAIL" "Write-churn tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 6: Btrfs validator tests pass
#######################################
e2e_step "Scenario 6: Btrfs validator tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-repair --lib -- btrfs 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test scrub::tests::btrfs" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "btrfs_validators" "PASS" "Btrfs validator tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "btrfs_validators" "FAIL" "Too few btrfs tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "btrfs_validators" "FAIL" "Btrfs validator tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 7: Full pipeline test suite
#######################################
e2e_step "Scenario 7: Full pipeline test suite"

TEST_LOG=$(mktemp)
if cargo test -p ffs-repair --lib -- pipeline::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 50 ]]; then
        scenario_result "pipeline_suite" "PASS" "Full pipeline suite passed (${TESTS_RUN} tests)"
    else
        scenario_result "pipeline_suite" "FAIL" "Too few pipeline tests: ${TESTS_RUN} (expected >= 50)"
    fi
else
    scenario_result "pipeline_suite" "FAIL" "Pipeline suite failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 8: Btrfs CLI repair tests pass
#######################################
e2e_step "Scenario 8: Btrfs CLI repair tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-cli -- btrfs_repair 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    scenario_result "btrfs_cli_repair" "PASS" "Btrfs CLI repair tests passed"
else
    scenario_result "btrfs_cli_repair" "FAIL" "Btrfs CLI repair tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 9: RefreshTelemetry supports churn observability
#######################################
e2e_step "Scenario 9: Refresh telemetry for churn observability"

TELEMETRY_FIELDS=0
for field in "dirty_groups" "max_dirty_age_ms" "tracked_groups" "dirty_age_ms" "since_last_refresh_ms"; do
    if grep -q "pub ${field}" "$PIPELINE_SRC"; then
        TELEMETRY_FIELDS=$((TELEMETRY_FIELDS + 1))
    fi
done

if [[ $TELEMETRY_FIELDS -ge 5 ]]; then
    scenario_result "churn_telemetry" "PASS" "All ${TELEMETRY_FIELDS}/5 telemetry fields present"
else
    scenario_result "churn_telemetry" "FAIL" "Only ${TELEMETRY_FIELDS}/5 telemetry fields found"
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
