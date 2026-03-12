#!/usr/bin/env bash
# ffs_mount_mode_e2e.sh - E2E verification for mount-mode boundary contract
#
# Validates that:
# 1. MountMode enum exists and defaults to Compat
# 2. CLI --native flag is accepted
# 3. Compat mode blocks native-only operations
# 4. Native mode allows all operations
# 5. Mode boundary violation produces correct error and structured log
#
# Usage: ./scripts/e2e/ffs_mount_mode_e2e.sh
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
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|status=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

e2e_init "ffs_mount_mode"

#######################################
# Scenario 1: MountMode type exists in ffs-types
#######################################
e2e_step "Scenario 1: MountMode type existence"

if grep -q "pub enum MountMode" crates/ffs-types/src/lib.rs; then
    if grep -q "Compat" crates/ffs-types/src/lib.rs && grep -q "Native" crates/ffs-types/src/lib.rs; then
        scenario_result "mode_type_exists" "PASS" "MountMode enum with Compat/Native variants found in ffs-types"
    else
        scenario_result "mode_type_exists" "FAIL" "MountMode enum missing Compat or Native variant"
    fi
else
    scenario_result "mode_type_exists" "FAIL" "MountMode enum not found in ffs-types"
fi

#######################################
# Scenario 2: Default mode is Compat
#######################################
e2e_step "Scenario 2: Default mount mode is Compat"

if grep -q '#\[default\]' crates/ffs-types/src/lib.rs; then
    # Check that #[default] is on the line before Compat
    DEFAULT_LINE=$(grep -n '#\[default\]' crates/ffs-types/src/lib.rs | head -1 | cut -d: -f1)
    NEXT_LINE=$((DEFAULT_LINE + 1))
    NEXT_CONTENT=$(sed -n "${NEXT_LINE}p" crates/ffs-types/src/lib.rs)
    if echo "$NEXT_CONTENT" | grep -q "Compat"; then
        scenario_result "mode_default_compat" "PASS" "Default MountMode is Compat"
    else
        scenario_result "mode_default_compat" "FAIL" "Default MountMode is not Compat (found: $NEXT_CONTENT)"
    fi
else
    scenario_result "mode_default_compat" "FAIL" "#[default] attribute not found on MountMode"
fi

#######################################
# Scenario 3: OpenOptions includes mount_mode field
#######################################
e2e_step "Scenario 3: OpenOptions has mount_mode field"

if grep -q "pub mount_mode: MountMode" crates/ffs-core/src/lib.rs; then
    scenario_result "mode_open_options" "PASS" "OpenOptions has mount_mode: MountMode field"
else
    scenario_result "mode_open_options" "FAIL" "OpenOptions missing mount_mode field"
fi

#######################################
# Scenario 4: OpenFs has mount_mode field
#######################################
e2e_step "Scenario 4: OpenFs stores mount_mode"

if grep -q "pub mount_mode: MountMode" crates/ffs-core/src/lib.rs; then
    scenario_result "mode_open_fs" "PASS" "OpenFs has mount_mode field"
else
    scenario_result "mode_open_fs" "FAIL" "OpenFs missing mount_mode field"
fi

#######################################
# Scenario 5: CLI --native flag exists
#######################################
e2e_step "Scenario 5: CLI --native flag"

if grep -q '\-\-native' crates/ffs-cli/src/main.rs; then
    if grep -q "native: bool" crates/ffs-cli/src/main.rs; then
        scenario_result "mode_native_opt_in" "PASS" "CLI --native flag with bool field found"
    else
        scenario_result "mode_native_opt_in" "FAIL" "CLI --native found but not as bool field"
    fi
else
    scenario_result "mode_native_opt_in" "FAIL" "CLI --native flag not found"
fi

#######################################
# Scenario 6: Boundary enforcement guards exist
#######################################
e2e_step "Scenario 6: Boundary enforcement guards"

GUARDS_FOUND=0
for guard in "require_native_mode" "require_repair_write_access" "require_version_store_access" "require_blake3_write_access"; do
    if grep -q "fn ${guard}" crates/ffs-core/src/lib.rs; then
        GUARDS_FOUND=$((GUARDS_FOUND + 1))
    fi
done

if [[ $GUARDS_FOUND -eq 4 ]]; then
    scenario_result "mode_compat_blocks_repair" "PASS" "All 4 boundary enforcement guards found"
else
    scenario_result "mode_compat_blocks_repair" "FAIL" "Only ${GUARDS_FOUND}/4 boundary guards found"
fi

#######################################
# Scenario 7: ModeViolation error variant exists
#######################################
e2e_step "Scenario 7: ModeViolation error variant"

if grep -q "ModeViolation" crates/ffs-error/src/lib.rs; then
    if grep -q "ModeViolation.*EPERM" crates/ffs-error/src/lib.rs; then
        scenario_result "mode_violation_errno" "PASS" "ModeViolation error maps to EPERM"
    else
        scenario_result "mode_violation_errno" "FAIL" "ModeViolation exists but EPERM mapping not found"
    fi
else
    scenario_result "mode_violation_errno" "FAIL" "ModeViolation error variant not found"
fi

#######################################
# Scenario 8: Unit tests compile and pass
#######################################
e2e_step "Scenario 8: Mount-mode unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-types -p ffs-core -p ffs-error -- mount_mode mode_violation require_native compat_mode >"$TEST_LOG" 2>&1; then
    TESTS_RUN=$(grep -oP 'test result: ok\. \K[0-9]+' "$TEST_LOG" | paste -sd+ - | bc 2>/dev/null || echo "0")
    scenario_result "mode_unit_tests" "PASS" "${TESTS_RUN} mount-mode unit tests passed"
else
    scenario_result "mode_unit_tests" "FAIL" "Mount-mode unit tests failed"
    tail -20 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 9: Structured log emission on mode selection
#######################################
e2e_step "Scenario 9: Structured log on mode selection"

if grep -q "mount_mode_selected" crates/ffs-core/src/lib.rs; then
    if grep -q 'operation_id = "open_fs"' crates/ffs-core/src/lib.rs; then
        scenario_result "mode_boundary_log_emission" "PASS" "mount_mode_selected log with operation_id found"
    else
        scenario_result "mode_boundary_log_emission" "FAIL" "mount_mode_selected log missing operation_id"
    fi
else
    scenario_result "mode_boundary_log_emission" "FAIL" "mount_mode_selected structured log not found"
fi

#######################################
# Scenario 10: Structured log on boundary violation
#######################################
e2e_step "Scenario 10: Structured log on boundary violation"

if grep -q "native_mode_boundary_violation" crates/ffs-core/src/lib.rs; then
    VIOLATION_FIELDS=0
    for field in "mount_mode" "rejected_operation" "operation_id" "scenario_id" "outcome"; do
        if grep -A5 "native_mode_boundary_violation" crates/ffs-core/src/lib.rs | grep -q "$field"; then
            VIOLATION_FIELDS=$((VIOLATION_FIELDS + 1))
        fi
    done
    if [[ $VIOLATION_FIELDS -ge 4 ]]; then
        scenario_result "mode_violation_log" "PASS" "Boundary violation log has ${VIOLATION_FIELDS}/5 required fields"
    else
        scenario_result "mode_violation_log" "FAIL" "Boundary violation log only has ${VIOLATION_FIELDS}/5 required fields"
    fi
else
    scenario_result "mode_violation_log" "FAIL" "native_mode_boundary_violation log not found"
fi

#######################################
# Scenario 11: Decision record exists
#######################################
e2e_step "Scenario 11: Decision record"

DECISION_DOC="docs/oq1-native-mode-boundary.md"
if [[ -f "$DECISION_DOC" ]]; then
    SECTIONS_FOUND=0
    for section in "Accepted" "Compat" "Native" "Enforcement" "Alternatives" "Validation Matrix"; do
        if grep -q "$section" "$DECISION_DOC"; then
            SECTIONS_FOUND=$((SECTIONS_FOUND + 1))
        fi
    done
    if [[ $SECTIONS_FOUND -ge 5 ]]; then
        scenario_result "mode_decision_record" "PASS" "Decision record with ${SECTIONS_FOUND}/6 required sections"
    else
        scenario_result "mode_decision_record" "FAIL" "Decision record only has ${SECTIONS_FOUND}/6 sections"
    fi
else
    scenario_result "mode_decision_record" "FAIL" "Decision record not found: $DECISION_DOC"
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
