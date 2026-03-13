#!/usr/bin/env bash
# ffs_health_consistency_e2e.sh - Verification gate for cross-surface health consistency (bd-h6nz.7.3)
#
# Validates that runtime health state is reported consistently across CLI, TUI,
# and structured log surfaces.
#
# Scenarios:
# 1. Health consistency module exists in ffs-harness
# 2. All 5 canonical health dimensions defined
# 3. Degradation level has 5 variants in ffs-core
# 4. TUI handles all degradation levels
# 5. Pressure counters exist in ffs-fuse
# 6. Runtime mode variants present in CLI
# 7. WAL replay markers present in ffs-mvcc
# 8. Source-of-truth documentation covers all dimensions
# 9. Health consistency unit tests pass
#
# Usage: ./scripts/e2e/ffs_health_consistency_e2e.sh
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

e2e_init "ffs_health_consistency"

HC_SRC="crates/ffs-harness/src/health_consistency.rs"

#######################################
# Scenario 1: Module exists
#######################################
e2e_step "Scenario 1: Health consistency module exists"

if [[ -f "$HC_SRC" ]] && grep -q "pub mod health_consistency" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "health_consistency_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "health_consistency_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All 5 dimensions defined
#######################################
e2e_step "Scenario 2: All 5 canonical health dimensions"

DIMS_FOUND=0
for dim in "DEGRADATION_LEVEL" "RUNTIME_MODE" "REPLAY_STATUS" "REPAIR_STALENESS" "PRESSURE_COUNTERS"; do
    if grep -q "pub const ${dim}" "$HC_SRC"; then
        DIMS_FOUND=$((DIMS_FOUND + 1))
    fi
done

if [[ $DIMS_FOUND -eq 5 ]]; then
    scenario_result "health_canonical_dimensions_defined" "PASS" "All 5 dimensions defined"
else
    scenario_result "health_canonical_dimensions_defined" "FAIL" "Only ${DIMS_FOUND}/5 dimensions"
fi

#######################################
# Scenario 3: Degradation 5 variants in core
#######################################
e2e_step "Scenario 3: Degradation level variants in ffs-core"

DEG_VARIANTS=0
for variant in "Normal" "Warning" "Degraded" "Critical" "Emergency"; do
    if grep -q "$variant" "crates/ffs-core/src/degradation.rs"; then
        DEG_VARIANTS=$((DEG_VARIANTS + 1))
    fi
done

if [[ $DEG_VARIANTS -eq 5 ]]; then
    scenario_result "health_degradation_five_variants" "PASS" "All 5 degradation levels in core"
else
    scenario_result "health_degradation_five_variants" "FAIL" "Only ${DEG_VARIANTS}/5 variants"
fi

#######################################
# Scenario 4: TUI handles all degradation levels
#######################################
e2e_step "Scenario 4: TUI handles all degradation levels"

TUI_LEVELS=0
for variant in "Normal" "Warning" "Degraded" "Critical" "Emergency"; do
    if grep -q "DegradationLevel::${variant}" "crates/ffs-tui/src/lib.rs"; then
        TUI_LEVELS=$((TUI_LEVELS + 1))
    fi
done

if [[ $TUI_LEVELS -eq 5 ]]; then
    scenario_result "health_tui_degradation_coverage" "PASS" "TUI handles all 5 levels"
else
    scenario_result "health_tui_degradation_coverage" "FAIL" "Only ${TUI_LEVELS}/5 levels in TUI"
fi

#######################################
# Scenario 5: Pressure counters in ffs-fuse
#######################################
e2e_step "Scenario 5: Pressure counters in ffs-fuse"

COUNTERS=0
for counter in "requests_throttled" "requests_shed"; do
    if grep -q "$counter" "crates/ffs-fuse/src/lib.rs"; then
        COUNTERS=$((COUNTERS + 1))
    fi
done

if [[ $COUNTERS -eq 2 ]]; then
    scenario_result "health_pressure_counters_in_fuse" "PASS" "Both pressure counters present"
else
    scenario_result "health_pressure_counters_in_fuse" "FAIL" "Only ${COUNTERS}/2 counters"
fi

#######################################
# Scenario 6: Runtime mode variants in CLI
#######################################
e2e_step "Scenario 6: Runtime mode variants in CLI"

MODES=0
for mode in "Standard" "Managed" "PerCore"; do
    if grep -q "$mode" "crates/ffs-cli/src/main.rs"; then
        MODES=$((MODES + 1))
    fi
done

if [[ $MODES -eq 3 ]]; then
    scenario_result "health_runtime_modes_in_cli" "PASS" "All 3 runtime modes in CLI"
else
    scenario_result "health_runtime_modes_in_cli" "FAIL" "Only ${MODES}/3 modes"
fi

#######################################
# Scenario 7: WAL replay markers in ffs-mvcc
#######################################
e2e_step "Scenario 7: WAL replay markers in ffs-mvcc"

MARKERS=0
for marker in "wal_replay_start" "wal_replay_done"; do
    if grep -q "$marker" "crates/ffs-mvcc/src/wal_replay.rs"; then
        MARKERS=$((MARKERS + 1))
    fi
done

if [[ $MARKERS -eq 2 ]]; then
    scenario_result "health_wal_replay_markers" "PASS" "Both WAL replay markers present"
else
    scenario_result "health_wal_replay_markers" "FAIL" "Only ${MARKERS}/2 markers"
fi

#######################################
# Scenario 8: Source-of-truth documentation
#######################################
e2e_step "Scenario 8: Source-of-truth documentation"

SOT_DIMS=0
for phrase in "Degradation level" "Runtime mode" "WAL replay status" "Repair staleness" "Pressure counters"; do
    if grep -q "$phrase" "$HC_SRC"; then
        SOT_DIMS=$((SOT_DIMS + 1))
    fi
done

if [[ $SOT_DIMS -eq 5 ]]; then
    scenario_result "health_source_of_truth_documented" "PASS" "All 5 dimensions documented"
else
    scenario_result "health_source_of_truth_documented" "FAIL" "Only ${SOT_DIMS}/5 documented"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Health consistency unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- health_consistency 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test health_consistency::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 8 ]]; then
        scenario_result "health_consistency_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "health_consistency_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 8)"
    fi
else
    scenario_result "health_consistency_unit_tests_pass" "FAIL" "Health consistency tests failed"
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
