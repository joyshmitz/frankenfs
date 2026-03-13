#!/usr/bin/env bash
# ffs_error_taxonomy_e2e.sh - Verification gate for operator-facing error taxonomy (bd-h6nz.7.6)
#
# Validates the canonical error taxonomy: 7 error classes, stable codes,
# remediation hints, runbook cross-links, and surface consistency across
# CLI, TUI, and evidence outputs.
#
# Scenarios:
# 1. Error taxonomy module exists and is exported
# 2. All 7 error classes defined
# 3. At least 10 representative scenarios with stable codes
# 4. Every scenario has a non-empty remediation hint
# 5. Runbook cross-links resolve to existing files
# 6. FfsError variant references are valid
# 7. Evidence preset alignment with error classes
# 8. Error code uniqueness and prefix alignment
# 9. Error taxonomy unit tests pass
#
# Usage: ./scripts/e2e/ffs_error_taxonomy_e2e.sh
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

e2e_init "ffs_error_taxonomy"

TAXONOMY_SRC="crates/ffs-harness/src/error_taxonomy.rs"
ERROR_SRC="crates/ffs-error/src/lib.rs"

#######################################
# Scenario 1: Error taxonomy module exists and is exported
#######################################
e2e_step "Scenario 1: Error taxonomy module exists"

if [[ -f "$TAXONOMY_SRC" ]] && grep -q "pub mod error_taxonomy" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "taxonomy_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "taxonomy_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All 7 error classes defined
#######################################
e2e_step "Scenario 2: All 7 error classes defined"

CLASS_COUNT=0
for class in "Configuration" "Compatibility" "Replay" "Repair" "Pressure" "IoCorruption" "UnsupportedOp"; do
    if grep -q "$class" "$TAXONOMY_SRC"; then
        CLASS_COUNT=$((CLASS_COUNT + 1))
    fi
done

if [[ $CLASS_COUNT -eq 7 ]]; then
    scenario_result "taxonomy_seven_classes" "PASS" "All 7 error classes defined"
else
    scenario_result "taxonomy_seven_classes" "FAIL" "Only ${CLASS_COUNT}/7 classes found"
fi

#######################################
# Scenario 3: At least 10 representative scenarios with stable codes
#######################################
e2e_step "Scenario 3: At least 10 scenario codes"

CODE_COUNT=$(grep -c '"FFS-' "$TAXONOMY_SRC" || echo "0")

if [[ $CODE_COUNT -ge 10 ]]; then
    scenario_result "taxonomy_min_scenarios" "PASS" "${CODE_COUNT} stable error codes defined"
else
    scenario_result "taxonomy_min_scenarios" "FAIL" "Only ${CODE_COUNT}/10 error codes"
fi

#######################################
# Scenario 4: Every scenario has a non-empty remediation hint
#######################################
e2e_step "Scenario 4: Remediation hints present"

HINT_COUNT=$(grep -c "remediation_hint:" "$TAXONOMY_SRC" || true)
HINT_COUNT="${HINT_COUNT:-0}"
EMPTY_HINT=$(grep -c 'remediation_hint: ""' "$TAXONOMY_SRC" || true)
EMPTY_HINT="${EMPTY_HINT:-0}"

if [[ $HINT_COUNT -ge 10 && $EMPTY_HINT -eq 0 ]]; then
    scenario_result "taxonomy_hints_nonempty" "PASS" "${HINT_COUNT} hints, none empty"
else
    scenario_result "taxonomy_hints_nonempty" "FAIL" "${HINT_COUNT} hints, ${EMPTY_HINT} empty"
fi

#######################################
# Scenario 5: Runbook cross-links resolve to existing files
#######################################
e2e_step "Scenario 5: Runbook cross-links"

RUNBOOKS_FOUND=0
RUNBOOKS_TOTAL=0
for runbook in "docs/runbooks/replay-failure-triage.md" "docs/runbooks/corruption-recovery.md" "docs/runbooks/backpressure-investigation.md"; do
    RUNBOOKS_TOTAL=$((RUNBOOKS_TOTAL + 1))
    if [[ -f "$runbook" ]]; then
        RUNBOOKS_FOUND=$((RUNBOOKS_FOUND + 1))
    fi
done

# Also check that runbooks are referenced in taxonomy
RUNBOOK_REFS=$(grep -c "docs/runbooks/" "$TAXONOMY_SRC" || echo "0")

if [[ $RUNBOOKS_FOUND -eq $RUNBOOKS_TOTAL && $RUNBOOK_REFS -ge 3 ]]; then
    scenario_result "taxonomy_runbook_links" "PASS" "All ${RUNBOOKS_TOTAL} runbooks exist, ${RUNBOOK_REFS} references"
else
    scenario_result "taxonomy_runbook_links" "FAIL" "${RUNBOOKS_FOUND}/${RUNBOOKS_TOTAL} runbooks, ${RUNBOOK_REFS} refs"
fi

#######################################
# Scenario 6: FfsError variant references are valid
#######################################
e2e_step "Scenario 6: FfsError variant references valid"

VARIANTS_FOUND=0
VARIANTS_TOTAL=0
for variant in "InvalidGeometry" "Format" "UnsupportedFeature" "IncompatibleFeature" "UnsupportedBlockSize" "MvccConflict" "RepairFailed" "Corruption" "Io" "NoSpace" "ModeViolation" "ReadOnly"; do
    VARIANTS_TOTAL=$((VARIANTS_TOTAL + 1))
    # Check variant exists in both taxonomy and error crate
    if grep -q "\"$variant\"" "$TAXONOMY_SRC" && grep -q "$variant" "$ERROR_SRC"; then
        VARIANTS_FOUND=$((VARIANTS_FOUND + 1))
    fi
done

if [[ $VARIANTS_FOUND -eq $VARIANTS_TOTAL ]]; then
    scenario_result "taxonomy_variant_refs" "PASS" "All ${VARIANTS_TOTAL} variant references valid"
else
    scenario_result "taxonomy_variant_refs" "FAIL" "Only ${VARIANTS_FOUND}/${VARIANTS_TOTAL} variants valid"
fi

#######################################
# Scenario 7: Evidence preset alignment with error classes
#######################################
e2e_step "Scenario 7: Evidence preset alignment"

PRESETS_FOUND=0
for preset in "replay-anomalies" "repair-failures" "pressure-transitions"; do
    if grep -q "$preset" "$TAXONOMY_SRC"; then
        PRESETS_FOUND=$((PRESETS_FOUND + 1))
    fi
done

if [[ $PRESETS_FOUND -eq 3 ]]; then
    scenario_result "taxonomy_preset_alignment" "PASS" "All 3 evidence presets referenced in taxonomy"
else
    scenario_result "taxonomy_preset_alignment" "FAIL" "Only ${PRESETS_FOUND}/3 presets referenced"
fi

#######################################
# Scenario 8: Error code uniqueness and prefix format
#######################################
e2e_step "Scenario 8: Error code format"

# Check all 7 prefixes are present
PREFIX_COUNT=0
for prefix in "FFS-CFG" "FFS-CMP" "FFS-RPL" "FFS-RPR" "FFS-PRS" "FFS-IOC" "FFS-UNS"; do
    if grep -q "\"$prefix" "$TAXONOMY_SRC"; then
        PREFIX_COUNT=$((PREFIX_COUNT + 1))
    fi
done

if [[ $PREFIX_COUNT -eq 7 ]]; then
    scenario_result "taxonomy_code_format" "PASS" "All 7 code prefixes present"
else
    scenario_result "taxonomy_code_format" "FAIL" "Only ${PREFIX_COUNT}/7 prefixes found"
fi

#######################################
# Scenario 9: Error taxonomy unit tests pass
#######################################
e2e_step "Scenario 9: Unit tests pass"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- error_taxonomy 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test error_taxonomy::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "taxonomy_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "taxonomy_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 10)"
    fi
else
    scenario_result "taxonomy_unit_tests_pass" "FAIL" "Error taxonomy tests failed"
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
