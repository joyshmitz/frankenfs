#!/usr/bin/env bash
# ffs_btrfs_capability_drift_e2e.sh - Verification gate for btrfs capability drift detection (bd-h6nz.3.5)
#
# Validates that the FEATURE_PARITY.md btrfs capability contract table stays
# synchronized with actual unit test and E2E scenario coverage.
#
# Scenarios:
# 1. Drift detection module exists in ffs-harness
# 2. FEATURE_PARITY.md contains parseable unit:: contract rows
# 3. FEATURE_PARITY.md contains parseable e2e:: contract rows
# 4. check_unit_contract verifies fn existence in ffs-core
# 5. check_e2e_contract verifies scenario names in E2E scripts
# 6. parse_capability_table ignores non-contract rows
# 7. All unit contracts have corresponding test functions
# 8. All e2e contracts have corresponding scenario references
# 9. Btrfs capability drift unit tests pass
#
# Usage: ./scripts/e2e/ffs_btrfs_capability_drift_e2e.sh
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

e2e_init "ffs_btrfs_capability_drift"

DRIFT_SRC="crates/ffs-harness/src/btrfs_capability_drift.rs"
PARITY_MD="FEATURE_PARITY.md"

#######################################
# Scenario 1: Module exists
#######################################
e2e_step "Scenario 1: Drift detection module exists"

if [[ -f "$DRIFT_SRC" ]] && grep -q "pub mod btrfs_capability_drift" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "btrfs_drift_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "btrfs_drift_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: Unit contract rows parseable
#######################################
e2e_step "Scenario 2: FEATURE_PARITY.md has unit:: contract rows"

UNIT_COUNT=$(grep -c '`unit::' "$PARITY_MD" || echo "0")
if [[ $UNIT_COUNT -ge 15 ]]; then
    scenario_result "btrfs_drift_unit_contracts_parseable" "PASS" "${UNIT_COUNT} unit contracts found"
else
    scenario_result "btrfs_drift_unit_contracts_parseable" "FAIL" "Only ${UNIT_COUNT} unit contracts (expected >= 15)"
fi

#######################################
# Scenario 3: E2E contract rows parseable
#######################################
e2e_step "Scenario 3: FEATURE_PARITY.md has e2e:: contract rows"

E2E_COUNT=$(grep -c '`e2e::' "$PARITY_MD" || echo "0")
if [[ $E2E_COUNT -ge 10 ]]; then
    scenario_result "btrfs_drift_e2e_contracts_parseable" "PASS" "${E2E_COUNT} e2e contracts found"
else
    scenario_result "btrfs_drift_e2e_contracts_parseable" "FAIL" "Only ${E2E_COUNT} e2e contracts (expected >= 10)"
fi

#######################################
# Scenario 4: Unit contract checker uses fn pattern
#######################################
e2e_step "Scenario 4: check_unit_contract verifies fn existence"

if grep -q 'fn check_unit_contract' "$DRIFT_SRC" && grep -q 'fn {bare_name}(' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_unit_checker_pattern" "PASS" "Unit checker uses fn pattern"
else
    scenario_result "btrfs_drift_unit_checker_pattern" "FAIL" "Unit checker pattern not found"
fi

#######################################
# Scenario 5: E2E contract checker with progressive stripping
#######################################
e2e_step "Scenario 5: check_e2e_contract verifies scenario names"

if grep -q 'fn check_e2e_contract' "$DRIFT_SRC" && grep -q 'strip_prefix.*btrfs_rw_' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_e2e_checker_stripping" "PASS" "E2E checker uses progressive stripping"
else
    scenario_result "btrfs_drift_e2e_checker_stripping" "FAIL" "E2E checker stripping logic not found"
fi

#######################################
# Scenario 6: Parser ignores non-contract rows
#######################################
e2e_step "Scenario 6: Parser ignores non-contract rows"

if grep -q 'parse_ignores_non_contract_rows' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_parser_selectivity" "PASS" "Selectivity test present"
else
    scenario_result "btrfs_drift_parser_selectivity" "FAIL" "No selectivity test"
fi

#######################################
# Scenario 7: Unit contracts have test functions
#######################################
e2e_step "Scenario 7: All unit contracts have test functions in ffs-core"

if grep -q 'all_documented_unit_contracts_have_test_functions' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_unit_coverage_test" "PASS" "Unit coverage assertion test present"
else
    scenario_result "btrfs_drift_unit_coverage_test" "FAIL" "Unit coverage assertion test missing"
fi

#######################################
# Scenario 8: E2E contracts have scenario references
#######################################
e2e_step "Scenario 8: All e2e contracts have scenario references"

if grep -q 'all_documented_e2e_contracts_have_scenario_references' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_e2e_coverage_test" "PASS" "E2E coverage assertion test present"
else
    scenario_result "btrfs_drift_e2e_coverage_test" "FAIL" "E2E coverage assertion test missing"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Btrfs capability drift unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- btrfs_capability_drift 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test btrfs_capability_drift::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 5 ]]; then
        scenario_result "btrfs_drift_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "btrfs_drift_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 5)"
    fi
else
    scenario_result "btrfs_drift_unit_tests_pass" "FAIL" "Drift detection tests failed"
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
