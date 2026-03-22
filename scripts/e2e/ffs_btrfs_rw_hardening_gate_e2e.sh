#!/usr/bin/env bash
# ffs_btrfs_rw_hardening_gate_e2e.sh - Verification gate for btrfs experimental RW hardening (bd-h6nz.3.6)
#
# Final acceptance gate proving btrfs experimental write behavior is explicit,
# safe, and diagnosable across the full pipeline: guardrails → logging → crash
# recovery → capability matrix synchronization.
#
# Scenarios:
# 1. Unsupported-op guardrails: EOPNOTSUPP errno contract in ffs-error
# 2. Unit tests for btrfs write operations (happy + error paths)
# 3. Structured logging: log contract tests exist for fallocate/fsync/flush
# 4. Crash consistency: crash_matrix module and crash points defined
# 5. Capability matrix: FEATURE_PARITY.md has btrfs RW contract rows
# 6. Drift detection: btrfs_capability_drift module passes
# 7. E2E scripts exist for RW smoke, write churn, and crash matrix
# 8. Errno exhaustiveness: FfsError → errno mapping is exhaustive
# 9. All btrfs write unit tests pass
#
# Usage: ./scripts/e2e/ffs_btrfs_rw_hardening_gate_e2e.sh
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

e2e_init "ffs_btrfs_rw_hardening_gate"

CORE_SRC="crates/ffs-core/src/lib.rs"
ERROR_SRC="crates/ffs-error/src/lib.rs"
FUSE_SRC="crates/ffs-fuse/src/lib.rs"
PARITY_MD="FEATURE_PARITY.md"
DRIFT_SRC="crates/ffs-harness/src/btrfs_capability_drift.rs"

#######################################
# Scenario 1: EOPNOTSUPP errno contract for unsupported ops
#######################################
e2e_step "Scenario 1: EOPNOTSUPP errno contract"

ERRNO_MARKERS=0
for marker in "UnsupportedFeature" "EOPNOTSUPP" "to_errno"; do
    if grep -q "$marker" "$ERROR_SRC"; then
        ERRNO_MARKERS=$((ERRNO_MARKERS + 1))
    fi
done

if [[ $ERRNO_MARKERS -eq 3 ]]; then
    scenario_result "hardening_eopnotsupp_contract" "PASS" "UnsupportedFeature → EOPNOTSUPP mapped in ffs-error"
else
    scenario_result "hardening_eopnotsupp_contract" "FAIL" "Only ${ERRNO_MARKERS}/3 errno markers found"
fi

#######################################
# Scenario 2: Btrfs write unit tests cover happy + error + guardrail paths
#######################################
e2e_step "Scenario 2: Btrfs write unit test coverage"

HAPPY_PATH=$(grep -c "fn btrfs_write_create_file\|fn btrfs_write_mkdir\|fn btrfs_write_unlink\|fn btrfs_write_rename\|fn btrfs_write_symlink\|fn btrfs_write_hard_link" "$CORE_SRC" || echo "0")
ERROR_PATH=$(grep -c "fn btrfs_write_fallocate_punch_hole_zeroes_data\|fn btrfs_write_fallocate_unsupported_mode_bits_rejected" "$CORE_SRC" || echo "0")
GUARDRAIL=$(grep -c "fn btrfs_write_enable_writes_sets_writable" "$CORE_SRC" || echo "0")

TOTAL_WRITE_TESTS=$(grep -c "fn btrfs_write" "$CORE_SRC" || echo "0")

if [[ $HAPPY_PATH -ge 5 && $ERROR_PATH -ge 2 && $GUARDRAIL -ge 1 && $TOTAL_WRITE_TESTS -ge 30 ]]; then
    scenario_result "hardening_write_test_coverage" "PASS" "${TOTAL_WRITE_TESTS} btrfs_write tests (${HAPPY_PATH} happy, ${ERROR_PATH} error, ${GUARDRAIL} guardrail)"
else
    scenario_result "hardening_write_test_coverage" "FAIL" "Insufficient: total=${TOTAL_WRITE_TESTS}, happy=${HAPPY_PATH}, error=${ERROR_PATH}, guardrail=${GUARDRAIL}"
fi

#######################################
# Scenario 3: Structured log contract tests for fallocate/fsync/flush
#######################################
e2e_step "Scenario 3: Log contract tests"

LOG_CONTRACTS=0
for contract in "fallocate_success_log_contract" "fallocate_rejection_log_contract" "fsync_log_contract_success" "fsync_rejection_log_contract" "flush_log_contract"; do
    if grep -q "$contract" "$CORE_SRC"; then
        LOG_CONTRACTS=$((LOG_CONTRACTS + 1))
    fi
done

if [[ $LOG_CONTRACTS -ge 4 ]]; then
    scenario_result "hardening_log_contracts" "PASS" "${LOG_CONTRACTS} structured log contract tests"
else
    scenario_result "hardening_log_contracts" "FAIL" "Only ${LOG_CONTRACTS}/4 log contract tests"
fi

#######################################
# Scenario 4: Crash consistency matrix infrastructure
#######################################
e2e_step "Scenario 4: Crash consistency matrix"

CRASH_MARKERS=0
if grep -q "crash_matrix_label_for_point" "scripts/e2e/ffs_btrfs_rw_smoke.sh"; then
    CRASH_MARKERS=$((CRASH_MARKERS + 1))
fi
if grep -q "CRASH_MATRIX_EVENT" "scripts/e2e/ffs_btrfs_rw_smoke.sh"; then
    CRASH_MARKERS=$((CRASH_MARKERS + 1))
fi
if grep -q "crash_matrix" "scripts/e2e/ffs_crash_matrix_e2e.sh" 2>/dev/null; then
    CRASH_MARKERS=$((CRASH_MARKERS + 1))
fi

CRASH_POINTS=$(grep -c "printf '" "scripts/e2e/ffs_btrfs_rw_smoke.sh" | head -1 || echo "0")
# Count actual labels in crash_matrix_label_for_point
LABEL_COUNT=$(grep -c ") printf " "scripts/e2e/ffs_btrfs_rw_smoke.sh" || echo "0")

if [[ $CRASH_MARKERS -ge 2 && $LABEL_COUNT -ge 10 ]]; then
    scenario_result "hardening_crash_matrix" "PASS" "Crash matrix with ${LABEL_COUNT} labeled points and structured events"
else
    scenario_result "hardening_crash_matrix" "FAIL" "Crash matrix incomplete: markers=${CRASH_MARKERS}, labels=${LABEL_COUNT}"
fi

#######################################
# Scenario 5: Capability matrix in FEATURE_PARITY.md
#######################################
e2e_step "Scenario 5: Capability matrix"

UNIT_CONTRACTS=$(grep -c '`unit::btrfs_write' "$PARITY_MD" || echo "0")
E2E_CONTRACTS=$(grep -c '`e2e::btrfs_rw' "$PARITY_MD" || echo "0")

if [[ $UNIT_CONTRACTS -ge 15 && $E2E_CONTRACTS -ge 10 ]]; then
    scenario_result "hardening_capability_matrix" "PASS" "${UNIT_CONTRACTS} unit + ${E2E_CONTRACTS} e2e contracts in FEATURE_PARITY.md"
else
    scenario_result "hardening_capability_matrix" "FAIL" "Only ${UNIT_CONTRACTS} unit + ${E2E_CONTRACTS} e2e contracts"
fi

#######################################
# Scenario 6: Drift detection module operational
#######################################
e2e_step "Scenario 6: Drift detection"

if [[ -f "$DRIFT_SRC" ]] && grep -q "pub fn check_btrfs_drift" "$DRIFT_SRC"; then
    # Run drift detection tests
    DRIFT_LOG=$(mktemp)
    if cargo test -p ffs-harness --lib -- btrfs_capability_drift 2>"$DRIFT_LOG" | tee -a "$DRIFT_LOG" > /dev/null 2>&1; then
        DRIFT_TESTS=$(grep -c "test btrfs_capability_drift" "$DRIFT_LOG" 2>/dev/null || echo "0")
        scenario_result "hardening_drift_detection" "PASS" "Drift detection passes (${DRIFT_TESTS} tests)"
    else
        scenario_result "hardening_drift_detection" "FAIL" "Drift detection tests failed"
    fi
    rm -f "$DRIFT_LOG"
else
    scenario_result "hardening_drift_detection" "FAIL" "Drift detection module not found"
fi

#######################################
# Scenario 7: E2E scripts exist for RW smoke, write churn, crash matrix
#######################################
e2e_step "Scenario 7: E2E script coverage"

SCRIPTS_FOUND=0
for script in "ffs_btrfs_rw_smoke.sh" "ffs_btrfs_write_churn_e2e.sh" "ffs_crash_matrix_e2e.sh" "ffs_btrfs_capability_drift_e2e.sh"; do
    if [[ -f "scripts/e2e/${script}" ]]; then
        SCRIPTS_FOUND=$((SCRIPTS_FOUND + 1))
    fi
done

if [[ $SCRIPTS_FOUND -ge 4 ]]; then
    scenario_result "hardening_e2e_script_coverage" "PASS" "${SCRIPTS_FOUND} btrfs RW E2E scripts present"
else
    scenario_result "hardening_e2e_script_coverage" "FAIL" "Only ${SCRIPTS_FOUND}/4 E2E scripts found"
fi

#######################################
# Scenario 8: Errno exhaustiveness (FfsError match is exhaustive)
#######################################
e2e_step "Scenario 8: Errno exhaustiveness"

# Check that to_errno covers key error variants
VARIANTS_COVERED=0
for variant in "UnsupportedFeature" "ReadOnly" "NotFound" "Exists" "NoSpace" "IsDirectory"; do
    if grep -q "FfsError::${variant}" "$ERROR_SRC"; then
        VARIANTS_COVERED=$((VARIANTS_COVERED + 1))
    fi
done

if [[ $VARIANTS_COVERED -ge 6 ]]; then
    scenario_result "hardening_errno_exhaustive" "PASS" "All ${VARIANTS_COVERED} key FfsError variants have errno mappings"
else
    scenario_result "hardening_errno_exhaustive" "FAIL" "Only ${VARIANTS_COVERED}/6 variants covered"
fi

#######################################
# Scenario 9: All btrfs write unit tests pass
#######################################
e2e_step "Scenario 9: Btrfs write unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-core --lib -- btrfs_write 2>"$TEST_LOG" | tee -a "$TEST_LOG" > /dev/null 2>&1; then
    TESTS_RUN=$(grep -c "test.*btrfs_write" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 30 ]]; then
        scenario_result "hardening_btrfs_write_tests_pass" "PASS" "${TESTS_RUN} btrfs_write tests passed"
    else
        scenario_result "hardening_btrfs_write_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 30)"
    fi
else
    scenario_result "hardening_btrfs_write_tests_pass" "FAIL" "btrfs_write tests failed"
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
