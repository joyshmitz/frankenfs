#!/usr/bin/env bash
# ffs_verification_gate_e2e.sh - Final acceptance gate for verification contract (bd-h6nz.9.5)
#
# Validates that:
# 1. All verification toolchain unit tests pass (artifact_manifest, log_contract, verification_runner)
# 2. Scenario catalog validation passes
# 3. Cross-epic E2E scripts follow runner conventions (conformance check)
# 4. Structured logging markers include correlation fields
# 5. Result schema is machine-parseable across representative scripts
# 6. Scenario IDs conform to the canonical regex
# 7. Runner contract and manifest schema versions are consistent
# 8. Log contract and E2E marker format are synchronized
# 9. Full ffs-harness test suite passes
#
# Usage: ./scripts/e2e/ffs_verification_gate_e2e.sh
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

e2e_init "ffs_verification_gate"

#######################################
# Scenario 1: artifact_manifest unit tests pass
#######################################
e2e_step "Scenario 1: artifact_manifest unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- artifact_manifest 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test artifact_manifest::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 20 ]]; then
        scenario_result "artifact_manifest_unit_tests" "PASS" "artifact_manifest tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "artifact_manifest_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 20)"
    fi
else
    scenario_result "artifact_manifest_unit_tests" "FAIL" "artifact_manifest tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 2: log_contract unit tests pass
#######################################
e2e_step "Scenario 2: log_contract unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- log_contract 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test log_contract::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "log_contract_unit_tests" "PASS" "log_contract tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "log_contract_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "log_contract_unit_tests" "FAIL" "log_contract tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 3: verification_runner unit tests pass
#######################################
e2e_step "Scenario 3: verification_runner unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- verification_runner 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test verification_runner::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 20 ]]; then
        scenario_result "verification_runner_unit_tests" "PASS" "verification_runner tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "verification_runner_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 20)"
    fi
else
    scenario_result "verification_runner_unit_tests" "FAIL" "verification_runner tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 4: Scenario catalog validates
#######################################
e2e_step "Scenario 4: Scenario catalog validation"

CATALOG="$REPO_ROOT/scripts/e2e/scenario_catalog.json"
if [[ -f "$CATALOG" ]]; then
    # Check for required fields
    CATALOG_FIELDS=0
    if jq -e '.catalog_version' "$CATALOG" >/dev/null 2>&1; then
        CATALOG_FIELDS=$((CATALOG_FIELDS + 1))
    fi
    if jq -e '.scenario_id_regex' "$CATALOG" >/dev/null 2>&1; then
        CATALOG_FIELDS=$((CATALOG_FIELDS + 1))
    fi
    if jq -e '.taxonomy' "$CATALOG" >/dev/null 2>&1; then
        CATALOG_FIELDS=$((CATALOG_FIELDS + 1))
    fi
    if jq -e '.suites' "$CATALOG" >/dev/null 2>&1; then
        CATALOG_FIELDS=$((CATALOG_FIELDS + 1))
    fi

    if [[ $CATALOG_FIELDS -eq 4 ]]; then
        # Check for duplicate active IDs
        DUPS=$(jq -r '.suites[].scenarios[] | select((.status // "active") == "active" and has("id")) | .id' "$CATALOG" | sort | uniq -d)
        if [[ -z "$DUPS" ]]; then
            scenario_result "scenario_catalog_valid" "PASS" "Catalog valid with all required fields"
        else
            scenario_result "scenario_catalog_valid" "FAIL" "Duplicate IDs found: $DUPS"
        fi
    else
        scenario_result "scenario_catalog_valid" "FAIL" "Only ${CATALOG_FIELDS}/4 required fields present"
    fi
else
    scenario_result "scenario_catalog_valid" "FAIL" "Catalog file missing"
fi

#######################################
# Scenario 5: Cross-epic script conformance
#######################################
e2e_step "Scenario 5: Cross-epic script conformance"

CONFORMANCE_FAILURES=0
SCRIPTS_CHECKED=0
for script in "$REPO_ROOT"/scripts/e2e/ffs_*_e2e.sh; do
    [[ -f "$script" ]] || continue
    SCRIPTS_CHECKED=$((SCRIPTS_CHECKED + 1))
    script_content=$(<"$script")

    # Check essential conventions
    if ! echo "$script_content" | grep -q 'set -euo pipefail'; then
        e2e_log "  CONFORMANCE FAIL: $(basename "$script") missing strict mode"
        CONFORMANCE_FAILURES=$((CONFORMANCE_FAILURES + 1))
        continue
    fi
    if ! echo "$script_content" | grep -q 'e2e_init'; then
        e2e_log "  CONFORMANCE FAIL: $(basename "$script") missing e2e_init"
        CONFORMANCE_FAILURES=$((CONFORMANCE_FAILURES + 1))
        continue
    fi
    if ! echo "$script_content" | grep -q 'SCENARIO_RESULT\|scenario_result'; then
        e2e_log "  CONFORMANCE FAIL: $(basename "$script") no scenario markers"
        CONFORMANCE_FAILURES=$((CONFORMANCE_FAILURES + 1))
    fi
done

if [[ $CONFORMANCE_FAILURES -eq 0 && $SCRIPTS_CHECKED -ge 5 ]]; then
    scenario_result "cross_epic_conformance" "PASS" "All ${SCRIPTS_CHECKED} E2E scripts conform"
else
    scenario_result "cross_epic_conformance" "FAIL" "${CONFORMANCE_FAILURES}/${SCRIPTS_CHECKED} scripts have violations"
fi

#######################################
# Scenario 6: Structured logging correlation fields
#######################################
e2e_step "Scenario 6: Structured logging correlation fields"

RUNNER_SRC="crates/ffs-harness/src/verification_runner.rs"
CORR_FIELDS=0
for field in "operation_id" "scenario_id" "outcome"; do
    if grep -q "$field = " "$RUNNER_SRC"; then
        CORR_FIELDS=$((CORR_FIELDS + 1))
    fi
done

if [[ $CORR_FIELDS -eq 3 ]]; then
    scenario_result "structured_logging_fields" "PASS" "All 3 correlation fields present"
else
    scenario_result "structured_logging_fields" "FAIL" "Only ${CORR_FIELDS}/3 correlation fields"
fi

#######################################
# Scenario 7: Schema version consistency
#######################################
e2e_step "Scenario 7: Schema version consistency"

MANIFEST_SRC="crates/ffs-harness/src/artifact_manifest.rs"
LOG_SRC="crates/ffs-harness/src/log_contract.rs"

# All schema versions should be >= 1
VERSIONS_OK=0
if grep -q 'pub const SCHEMA_VERSION: u32 = 1' "$MANIFEST_SRC"; then
    VERSIONS_OK=$((VERSIONS_OK + 1))
fi
if grep -q 'pub const CONTRACT_VERSION: u32 = 1' "$LOG_SRC"; then
    VERSIONS_OK=$((VERSIONS_OK + 1))
fi
if grep -q 'pub const RUNNER_CONTRACT_VERSION: u32 = 1' "$RUNNER_SRC"; then
    VERSIONS_OK=$((VERSIONS_OK + 1))
fi

if [[ $VERSIONS_OK -eq 3 ]]; then
    scenario_result "schema_version_consistency" "PASS" "All 3 contract versions set"
else
    scenario_result "schema_version_consistency" "FAIL" "Only ${VERSIONS_OK}/3 versions found"
fi

#######################################
# Scenario 8: E2E marker format synchronized
#######################################
e2e_step "Scenario 8: E2E marker format synchronized"

# Check that log_contract defines the marker format constants
# and that lib.sh uses the same format
SYNC_OK=0
if grep -q 'pub const PREFIX: &str = "SCENARIO_RESULT"' "$LOG_SRC"; then
    SYNC_OK=$((SYNC_OK + 1))
fi
if grep -q 'pub const PASS: &str = "PASS"' "$LOG_SRC"; then
    SYNC_OK=$((SYNC_OK + 1))
fi
if grep -q 'pub const FAIL: &str = "FAIL"' "$LOG_SRC"; then
    SYNC_OK=$((SYNC_OK + 1))
fi
if grep -q 'SCENARIO_RESULT|scenario_id=' "$REPO_ROOT/scripts/e2e/lib.sh"; then
    SYNC_OK=$((SYNC_OK + 1))
fi

if [[ $SYNC_OK -eq 4 ]]; then
    scenario_result "e2e_marker_format_sync" "PASS" "Rust and shell marker formats synchronized"
else
    scenario_result "e2e_marker_format_sync" "FAIL" "Only ${SYNC_OK}/4 format checks passed"
fi

#######################################
# Scenario 9: Full ffs-harness test suite
#######################################
e2e_step "Scenario 9: Full ffs-harness test suite"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test .*::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 180 ]]; then
        scenario_result "full_harness_suite" "PASS" "Full suite passed (${TESTS_RUN} tests)"
    else
        scenario_result "full_harness_suite" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 180)"
    fi
else
    scenario_result "full_harness_suite" "FAIL" "Harness test suite failed"
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
