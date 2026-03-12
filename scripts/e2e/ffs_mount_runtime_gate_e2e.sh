#!/usr/bin/env bash
# ffs_mount_runtime_gate_e2e.sh - Verification gate for mount runtime modes (bd-h6nz.2.6)
#
# Final acceptance gate proving runtime-mode wiring is correct, observable, and user-safe.
#
# Validates:
# 1. CLI mount tests pass (runtime mode parsing, validation, routing)
# 2. ffs-fuse unit tests pass (managed mount, per-core dispatch)
# 3. ffs-core degradation/backpressure tests pass
# 4. MountMode boundary enforcement tests pass
# 5. Structured logging: mode selection marker present with correlation fields
# 6. Structured logging: mode rejection marker present with error classification
# 7. Structured logging: boundary violation marker with required fields
# 8. Runtime mode tests cover all 3 modes (standard, managed, per-core)
# 9. Observability surfaces: CLI error messages and structured logs both present
#
# Usage: ./scripts/e2e/ffs_mount_runtime_gate_e2e.sh
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

e2e_init "ffs_mount_runtime_gate"

CLI_SRC="crates/ffs-cli/src/main.rs"
CORE_SRC="crates/ffs-core/src/lib.rs"

#######################################
# Scenario 1: CLI mount tests pass
#######################################
e2e_step "Scenario 1: CLI mount unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-cli -- mount 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test tests::mount" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "cli_mount_unit_tests" "PASS" "CLI mount tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "cli_mount_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 10)"
    fi
else
    scenario_result "cli_mount_unit_tests" "FAIL" "CLI mount tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 2: ffs-fuse unit tests pass
#######################################
e2e_step "Scenario 2: ffs-fuse unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-fuse --lib 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test .*::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 100 ]]; then
        scenario_result "fuse_unit_tests" "PASS" "ffs-fuse tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "fuse_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 100)"
    fi
else
    scenario_result "fuse_unit_tests" "FAIL" "ffs-fuse tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 3: Degradation/backpressure tests
#######################################
e2e_step "Scenario 3: Degradation and backpressure tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-core --lib -- degradation backpressure 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test .*::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 20 ]]; then
        scenario_result "degradation_backpressure_tests" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "degradation_backpressure_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 20)"
    fi
else
    scenario_result "degradation_backpressure_tests" "FAIL" "Degradation tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 4: Mode boundary enforcement
#######################################
e2e_step "Scenario 4: Mode boundary enforcement"

GUARDS_FOUND=0
for guard in "require_native_mode" "require_repair_write_access" "require_version_store_access" "require_blake3_write_access"; do
    if grep -q "fn ${guard}" "$CORE_SRC"; then
        GUARDS_FOUND=$((GUARDS_FOUND + 1))
    fi
done

TEST_LOG=$(mktemp)
if cargo test -p ffs-core --lib -- mode_violation 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    if [[ $GUARDS_FOUND -eq 4 ]]; then
        scenario_result "mode_boundary_enforcement" "PASS" "All 4 guards present and tests pass"
    else
        scenario_result "mode_boundary_enforcement" "FAIL" "Only ${GUARDS_FOUND}/4 guards found"
    fi
else
    scenario_result "mode_boundary_enforcement" "FAIL" "Mode violation tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 5: Mode selection structured logging
#######################################
e2e_step "Scenario 5: Mode selection structured logging"

SELECTION_FIELDS=0
for field in "mount_runtime_mode_selected" "operation_id" "scenario_id" "outcome" "runtime_mode"; do
    if grep -q "$field" "$CLI_SRC"; then
        SELECTION_FIELDS=$((SELECTION_FIELDS + 1))
    fi
done

if [[ $SELECTION_FIELDS -ge 5 ]]; then
    scenario_result "mode_selection_logging" "PASS" "Mode selection log has ${SELECTION_FIELDS}/5 fields"
else
    scenario_result "mode_selection_logging" "FAIL" "Only ${SELECTION_FIELDS}/5 selection log fields"
fi

#######################################
# Scenario 6: Mode rejection structured logging
#######################################
e2e_step "Scenario 6: Mode rejection structured logging"

REJECTION_FIELDS=0
for field in "mount_runtime_mode_rejected" "error_class" "reason"; do
    if grep -q "$field" "$CLI_SRC"; then
        REJECTION_FIELDS=$((REJECTION_FIELDS + 1))
    fi
done

if [[ $REJECTION_FIELDS -ge 3 ]]; then
    scenario_result "mode_rejection_logging" "PASS" "Mode rejection log has ${REJECTION_FIELDS}/3 fields"
else
    scenario_result "mode_rejection_logging" "FAIL" "Only ${REJECTION_FIELDS}/3 rejection log fields"
fi

#######################################
# Scenario 7: Boundary violation logging
#######################################
e2e_step "Scenario 7: Boundary violation logging"

if grep -q "native_mode_boundary_violation" "$CORE_SRC"; then
    VIOLATION_FIELDS=0
    for field in "mount_mode" "rejected_operation" "operation_id"; do
        if grep -A5 "native_mode_boundary_violation" "$CORE_SRC" | grep -q "$field"; then
            VIOLATION_FIELDS=$((VIOLATION_FIELDS + 1))
        fi
    done
    if [[ $VIOLATION_FIELDS -ge 3 ]]; then
        scenario_result "boundary_violation_logging" "PASS" "Violation log has ${VIOLATION_FIELDS}/3 fields"
    else
        scenario_result "boundary_violation_logging" "FAIL" "Only ${VIOLATION_FIELDS}/3 violation log fields"
    fi
else
    scenario_result "boundary_violation_logging" "FAIL" "native_mode_boundary_violation log not found"
fi

#######################################
# Scenario 8: All 3 runtime modes covered
#######################################
e2e_step "Scenario 8: All 3 runtime modes covered"

MODES_FOUND=0
for mode in "Standard" "Managed" "PerCore"; do
    if grep -q "$mode" "$CLI_SRC"; then
        MODES_FOUND=$((MODES_FOUND + 1))
    fi
done

if [[ $MODES_FOUND -eq 3 ]]; then
    scenario_result "all_runtime_modes_covered" "PASS" "All 3 runtime modes present in CLI"
else
    scenario_result "all_runtime_modes_covered" "FAIL" "Only ${MODES_FOUND}/3 modes found"
fi

#######################################
# Scenario 9: Two observability surfaces
#######################################
e2e_step "Scenario 9: Dual observability surfaces"

SURFACES=0
# Surface 1: Structured tracing logs
if grep -q "mount_runtime_mode_selected" "$CLI_SRC"; then
    SURFACES=$((SURFACES + 1))
fi
# Surface 2: CLI error messages (actionable user-facing text)
if grep -q "managed-unmount-timeout-secs requires" "$CLI_SRC"; then
    SURFACES=$((SURFACES + 1))
fi

if [[ $SURFACES -eq 2 ]]; then
    scenario_result "dual_observability_surfaces" "PASS" "Both tracing logs and CLI messages present"
else
    scenario_result "dual_observability_surfaces" "FAIL" "Only ${SURFACES}/2 observability surfaces"
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
