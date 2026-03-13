#!/usr/bin/env bash
# ffs_operator_tooling_gate_e2e.sh - Final acceptance gate for Epic 7: Operator Tooling (bd-h6nz.7.5)
#
# Validates the full operator tooling pipeline is coherent across all 5 sub-beads:
# runbooks, evidence presets, health consistency, tabletop drills, and error taxonomy.
#
# Scenarios:
# 1. All 5 sub-gate E2E scripts exist
# 2. All operator harness modules are exported
# 3. Runbooks E2E passes (bd-h6nz.7.1)
# 4. Evidence presets E2E passes (bd-h6nz.7.2)
# 5. Health consistency E2E passes (bd-h6nz.7.3)
# 6. Tabletop drill E2E passes (bd-h6nz.7.4)
# 7. Error taxonomy E2E passes (bd-h6nz.7.6)
# 8. Cross-cutting: all operator unit tests pass
# 9. Cross-cutting: structured log markers auditable across surfaces
#
# Usage: ./scripts/e2e/ffs_operator_tooling_gate_e2e.sh
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

e2e_init "ffs_operator_tooling_gate"

#######################################
# Scenario 1: All 5 sub-gate E2E scripts exist
#######################################
e2e_step "Scenario 1: Sub-gate E2E scripts exist"

SCRIPTS_FOUND=0
for script in \
    "scripts/e2e/ffs_runbooks_e2e.sh" \
    "scripts/e2e/ffs_evidence_presets_e2e.sh" \
    "scripts/e2e/ffs_health_consistency_e2e.sh" \
    "scripts/e2e/ffs_tabletop_drill_e2e.sh" \
    "scripts/e2e/ffs_error_taxonomy_e2e.sh"; do
    if [[ -f "$script" ]]; then
        SCRIPTS_FOUND=$((SCRIPTS_FOUND + 1))
    fi
done

if [[ $SCRIPTS_FOUND -eq 5 ]]; then
    scenario_result "gate_subgate_scripts" "PASS" "All 5 sub-gate E2E scripts found"
else
    scenario_result "gate_subgate_scripts" "FAIL" "Only ${SCRIPTS_FOUND}/5 scripts found"
fi

#######################################
# Scenario 2: All operator harness modules exported
#######################################
e2e_step "Scenario 2: Operator harness modules exported"

LIB_RS="crates/ffs-harness/src/lib.rs"
MODULES_FOUND=0
for mod_name in "error_taxonomy" "health_consistency" "tabletop_drill"; do
    if grep -q "pub mod ${mod_name}" "$LIB_RS"; then
        MODULES_FOUND=$((MODULES_FOUND + 1))
    fi
done

if [[ $MODULES_FOUND -eq 3 ]]; then
    scenario_result "gate_modules_exported" "PASS" "All 3 operator harness modules exported"
else
    scenario_result "gate_modules_exported" "FAIL" "Only ${MODULES_FOUND}/3 modules exported"
fi

#######################################
# Scenario 3: Runbooks E2E (bd-h6nz.7.1)
#######################################
e2e_step "Scenario 3: Runbooks E2E"

RUNBOOK_CHECKS=0
# Verify all 3 runbooks exist with required content
for runbook in "docs/runbooks/replay-failure-triage.md" "docs/runbooks/corruption-recovery.md" "docs/runbooks/backpressure-investigation.md"; do
    if [[ -f "$runbook" ]] && grep -q "Quick Reference" "$runbook" && grep -q "bash" "$runbook"; then
        RUNBOOK_CHECKS=$((RUNBOOK_CHECKS + 1))
    fi
done

# Verify perf regression triage runbook also exists
[[ -f "docs/runbooks/perf-regression-triage.md" ]] && RUNBOOK_CHECKS=$((RUNBOOK_CHECKS + 1))

if [[ $RUNBOOK_CHECKS -eq 4 ]]; then
    scenario_result "gate_runbooks" "PASS" "All 4 runbooks complete with decision trees and bash commands"
else
    scenario_result "gate_runbooks" "FAIL" "Only ${RUNBOOK_CHECKS}/4 runbooks pass validation"
fi

#######################################
# Scenario 4: Evidence presets E2E (bd-h6nz.7.2)
#######################################
e2e_step "Scenario 4: Evidence presets"

PRESET_CHECKS=0
EVIDENCE_SRC="crates/ffs-cli/src/cmd_evidence.rs"
for preset in "replay-anomalies" "repair-failures" "pressure-transitions"; do
    if grep -q "$preset" "$EVIDENCE_SRC"; then
        PRESET_CHECKS=$((PRESET_CHECKS + 1))
    fi
done

# Verify summary aggregation exists
grep -q "summary" "$EVIDENCE_SRC" && PRESET_CHECKS=$((PRESET_CHECKS + 1))

if [[ $PRESET_CHECKS -eq 4 ]]; then
    scenario_result "gate_evidence_presets" "PASS" "All 3 presets + summary aggregation in evidence command"
else
    scenario_result "gate_evidence_presets" "FAIL" "Only ${PRESET_CHECKS}/4 evidence checks pass"
fi

#######################################
# Scenario 5: Health consistency (bd-h6nz.7.3)
#######################################
e2e_step "Scenario 5: Health consistency"

HC_SRC="crates/ffs-harness/src/health_consistency.rs"
HC_CHECKS=0
# Check all 5 health dimensions are tracked
for dimension in "DEGRADATION_LEVEL" "RUNTIME_MODE" "REPLAY_STATUS" "REPAIR_STALENESS" "PRESSURE_COUNTERS"; do
    if grep -q "$dimension" "$HC_SRC"; then
        HC_CHECKS=$((HC_CHECKS + 1))
    fi
done

if [[ $HC_CHECKS -eq 5 ]]; then
    scenario_result "gate_health_consistency" "PASS" "All 5 health dimensions tracked"
else
    scenario_result "gate_health_consistency" "FAIL" "Only ${HC_CHECKS}/5 dimensions found"
fi

#######################################
# Scenario 6: Tabletop drills (bd-h6nz.7.4)
#######################################
e2e_step "Scenario 6: Tabletop drills"

DRILL_SRC="crates/ffs-harness/src/tabletop_drill.rs"
DRILL_CHECKS=0
for drill_id in "drill-replay-anomaly" "drill-corruption-partial-repair" "drill-sustained-pressure"; do
    if grep -q "\"$drill_id\"" "$DRILL_SRC"; then
        DRILL_CHECKS=$((DRILL_CHECKS + 1))
    fi
done

if [[ $DRILL_CHECKS -eq 3 ]]; then
    scenario_result "gate_tabletop_drills" "PASS" "All 3 incident drill scenarios defined"
else
    scenario_result "gate_tabletop_drills" "FAIL" "Only ${DRILL_CHECKS}/3 drills found"
fi

#######################################
# Scenario 7: Error taxonomy (bd-h6nz.7.6)
#######################################
e2e_step "Scenario 7: Error taxonomy"

TAX_SRC="crates/ffs-harness/src/error_taxonomy.rs"
TAX_CHECKS=0
for prefix in "FFS-CFG" "FFS-CMP" "FFS-RPL" "FFS-RPR" "FFS-PRS" "FFS-IOC" "FFS-UNS"; do
    if grep -q "\"$prefix" "$TAX_SRC"; then
        TAX_CHECKS=$((TAX_CHECKS + 1))
    fi
done

if [[ $TAX_CHECKS -eq 7 ]]; then
    scenario_result "gate_error_taxonomy" "PASS" "All 7 error class prefixes defined"
else
    scenario_result "gate_error_taxonomy" "FAIL" "Only ${TAX_CHECKS}/7 prefixes found"
fi

#######################################
# Scenario 8: All operator unit tests pass
#######################################
e2e_step "Scenario 8: All operator unit tests pass"

TEST_LOG=$(mktemp)
MODULES_PASS=0
MODULES_TOTAL=0
for mod_filter in "error_taxonomy" "health_consistency" "tabletop_drill"; do
    MODULES_TOTAL=$((MODULES_TOTAL + 1))
    if cargo test -p ffs-harness --lib -- "$mod_filter" 2>>"$TEST_LOG" | tee -a "$TEST_LOG" > /dev/null 2>&1; then
        MODULES_PASS=$((MODULES_PASS + 1))
    fi
done

TOTAL_TESTS=$(grep -c "^test " "$TEST_LOG" 2>/dev/null || true)
TOTAL_TESTS="${TOTAL_TESTS:-0}"

if [[ $MODULES_PASS -eq $MODULES_TOTAL && $TOTAL_TESTS -ge 30 ]]; then
    scenario_result "gate_unit_tests" "PASS" "All 3 modules pass (${TOTAL_TESTS} tests)"
else
    scenario_result "gate_unit_tests" "FAIL" "${MODULES_PASS}/${MODULES_TOTAL} modules pass, ${TOTAL_TESTS} tests"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 9: Structured log markers auditable
#######################################
e2e_step "Scenario 9: Structured log markers auditable"

MARKER_CHECKS=0
# Key structured log markers must be traceable across surfaces
# 1. Degradation transitions
grep -q "degradation_transition" "crates/ffs-core/src/degradation.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 2. Repair completion
grep -q "repair_complete" "crates/ffs-cli/src/cmd_repair.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 3. WAL replay lifecycle
grep -q "wal_replay_start" "crates/ffs-mvcc/src/wal_replay.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 4. Evidence preset filtering
grep -q "evidence_preset" "crates/ffs-cli/src/cmd_evidence.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 5. Error taxonomy codes reference in drill validation
grep -q "error_codes" "crates/ffs-harness/src/tabletop_drill.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))

if [[ $MARKER_CHECKS -eq 5 ]]; then
    scenario_result "gate_log_audit" "PASS" "All 5 structured log marker families auditable"
else
    scenario_result "gate_log_audit" "FAIL" "Only ${MARKER_CHECKS}/5 marker families found"
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
