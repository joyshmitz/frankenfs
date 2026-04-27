#!/usr/bin/env bash
# ffs_refresh_policy_e2e.sh - E2E verification for OQ3 symbol freshness policy (bd-h6nz.6.3)
#
# Validates that:
# 1. RefreshPolicy enum has all 3 variants (Eager, Lazy, Adaptive)
# 2. RefreshMode enum has all 6 trigger modes
# 3. GroupRefreshState state machine fields exist
# 4. RefreshTelemetry and GroupRefreshSummary types exist
# 5. Staleness timeout logic is present
# 6. Structured logging markers for refresh events exist
# 7. Pipeline refresh tests pass
# 8. Evidence SymbolRefreshDetail alignment
# 9. Churn/staleness budget tests pass
#
# Usage: ./scripts/e2e/ffs_refresh_policy_e2e.sh
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

e2e_init "ffs_refresh_policy"

PIPELINE_SRC="crates/ffs-repair/src/pipeline.rs"

#######################################
# Scenario 1: RefreshPolicy variants
#######################################
e2e_step "Scenario 1: RefreshPolicy variants"

VARIANTS_FOUND=0
for variant in "Eager" "Lazy" "Adaptive"; do
    if grep -q "^\s*${variant}" "$PIPELINE_SRC"; then
        VARIANTS_FOUND=$((VARIANTS_FOUND + 1))
    fi
done

if [[ $VARIANTS_FOUND -eq 3 ]]; then
    scenario_result "refresh_policy_variants" "PASS" "All 3 RefreshPolicy variants present"
else
    scenario_result "refresh_policy_variants" "FAIL" "Only ${VARIANTS_FOUND}/3 variants found"
fi

#######################################
# Scenario 2: RefreshMode trigger modes
#######################################
e2e_step "Scenario 2: RefreshMode trigger modes"

MODES_FOUND=0
for mode in "Recovery" "EagerWrite" "LazyScrub" "AdaptiveEagerWrite" "AdaptiveLazyScrub" "StalenessTimeout"; do
    if grep -q "${mode}" "$PIPELINE_SRC"; then
        MODES_FOUND=$((MODES_FOUND + 1))
    fi
done

if [[ $MODES_FOUND -eq 6 ]]; then
    scenario_result "refresh_modes" "PASS" "All 6 RefreshMode trigger modes present"
else
    scenario_result "refresh_modes" "FAIL" "Only ${MODES_FOUND}/6 modes found"
fi

#######################################
# Scenario 3: GroupRefreshState fields
#######################################
e2e_step "Scenario 3: GroupRefreshState state machine"

STATE_FIELDS=0
for field in "dirty: bool" "dirty_since: Option<Instant>" "policy: RefreshPolicy" "last_refresh: Instant"; do
    if grep -q "$field" "$PIPELINE_SRC"; then
        STATE_FIELDS=$((STATE_FIELDS + 1))
    fi
done

if [[ $STATE_FIELDS -eq 4 ]]; then
    scenario_result "group_refresh_state" "PASS" "All 4 state machine fields present"
else
    scenario_result "group_refresh_state" "FAIL" "Only ${STATE_FIELDS}/4 state fields found"
fi

#######################################
# Scenario 4: Telemetry types exist
#######################################
e2e_step "Scenario 4: Telemetry types"

TELEMETRY_FOUND=0
for pattern in "pub struct RefreshTelemetry" "pub struct GroupRefreshSummary" "pub fn refresh_telemetry"; do
    if grep -q "$pattern" "$PIPELINE_SRC"; then
        TELEMETRY_FOUND=$((TELEMETRY_FOUND + 1))
    fi
done

if [[ $TELEMETRY_FOUND -eq 3 ]]; then
    scenario_result "telemetry_types" "PASS" "RefreshTelemetry, GroupRefreshSummary, and accessor present"
else
    scenario_result "telemetry_types" "FAIL" "Only ${TELEMETRY_FOUND}/3 telemetry components found"
fi

#######################################
# Scenario 5: Staleness timeout logic
#######################################
e2e_step "Scenario 5: Staleness timeout logic"

TIMEOUT_FOUND=0
for pattern in "dirty_age >= max_staleness" "StalenessTimeout" "refresh_staleness_timeout_triggered"; do
    if grep -q "$pattern" "$PIPELINE_SRC"; then
        TIMEOUT_FOUND=$((TIMEOUT_FOUND + 1))
    fi
done

if [[ $TIMEOUT_FOUND -ge 3 ]]; then
    scenario_result "staleness_timeout" "PASS" "Staleness timeout detection logic present"
else
    scenario_result "staleness_timeout" "FAIL" "Only ${TIMEOUT_FOUND}/3 timeout patterns found"
fi

#######################################
# Scenario 6: Structured logging markers
#######################################
e2e_step "Scenario 6: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "refresh_policy_evaluated" "refresh_staleness_timeout_triggered" "refresh_group_marked_dirty" "adaptive_refresh_policy_resolved" "symbol_refresh_queued" "symbol_refresh_complete" "symbol_refresh_deferred"; do
    if grep -q "\"${marker}\"" "$PIPELINE_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 6 ]]; then
    scenario_result "structured_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/7 markers present"
else
    scenario_result "structured_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/7 structured log markers found"
fi

#######################################
# Scenario 7: Pipeline unit tests pass
#######################################
e2e_step "Scenario 7: Pipeline refresh tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-repair --lib -- pipeline::tests 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 45 ]]; then
        scenario_result "pipeline_tests" "PASS" "Pipeline tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "pipeline_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 45)"
    fi
else
    scenario_result "pipeline_tests" "FAIL" "Pipeline tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 8: Evidence SymbolRefreshDetail alignment
#######################################
e2e_step "Scenario 8: Evidence SymbolRefreshDetail alignment"

EVIDENCE_SRC="crates/ffs-repair/src/evidence.rs"
ALIGNED=0
for field in "previous_generation" "new_generation" "symbols_generated"; do
    if grep -q "$field" "$EVIDENCE_SRC"; then
        ALIGNED=$((ALIGNED + 1))
    fi
done

if [[ $ALIGNED -eq 3 ]]; then
    scenario_result "evidence_alignment" "PASS" "All 3 SymbolRefreshDetail fields present"
else
    scenario_result "evidence_alignment" "FAIL" "Only ${ALIGNED}/3 fields found"
fi

#######################################
# Scenario 9: Churn and policy tests pass
#######################################
e2e_step "Scenario 9: Churn and policy-specific tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-repair --lib -- churn_writes eager_policy lazy_policy staleness_timeout 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "churn_policy_tests" "PASS" "Churn/policy tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "churn_policy_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "churn_policy_tests" "FAIL" "Churn/policy tests failed"
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
