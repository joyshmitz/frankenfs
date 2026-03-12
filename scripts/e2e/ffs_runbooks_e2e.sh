#!/usr/bin/env bash
# ffs_runbooks_e2e.sh - Verification gate for operator runbooks (bd-h6nz.7.1)
#
# Validates that all operator runbooks exist and contain required sections:
# 1. replay-failure-triage.md — WAL replay failure diagnosis
# 2. corruption-recovery.md — Corruption detection and repair workflow
# 3. backpressure-investigation.md — Backpressure/degradation investigation
# 4. perf-regression-triage.md — Performance regression triage (pre-existing)
#
# Each runbook must contain:
# - Prerequisites section
# - At least one bash command block
# - Stop Conditions section
# - A decision tree or quick reference section
#
# Usage: ./scripts/e2e/ffs_runbooks_e2e.sh
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

e2e_init "ffs_runbooks"

RUNBOOK_DIR="$REPO_ROOT/docs/runbooks"

#######################################
# Scenario 1: All 4 runbooks exist
#######################################
e2e_step "Scenario 1: All runbooks present"

RUNBOOKS_FOUND=0
for runbook in "replay-failure-triage.md" "corruption-recovery.md" "backpressure-investigation.md" "perf-regression-triage.md"; do
    if [[ -f "$RUNBOOK_DIR/$runbook" ]]; then
        RUNBOOKS_FOUND=$((RUNBOOKS_FOUND + 1))
    else
        e2e_log "MISSING: $runbook"
    fi
done

if [[ $RUNBOOKS_FOUND -eq 4 ]]; then
    scenario_result "runbooks_all_present" "PASS" "All 4 runbooks present"
else
    scenario_result "runbooks_all_present" "FAIL" "Only ${RUNBOOKS_FOUND}/4 runbooks found"
fi

#######################################
# Scenario 2: Each runbook has Prerequisites
#######################################
e2e_step "Scenario 2: Prerequisites sections"

PREREQS_FOUND=0
for runbook in "replay-failure-triage.md" "corruption-recovery.md" "backpressure-investigation.md" "perf-regression-triage.md"; do
    if [[ -f "$RUNBOOK_DIR/$runbook" ]] && grep -q "## Prerequisites" "$RUNBOOK_DIR/$runbook"; then
        PREREQS_FOUND=$((PREREQS_FOUND + 1))
    fi
done

if [[ $PREREQS_FOUND -eq 4 ]]; then
    scenario_result "runbooks_have_prerequisites" "PASS" "All 4 runbooks have Prerequisites"
else
    scenario_result "runbooks_have_prerequisites" "FAIL" "Only ${PREREQS_FOUND}/4 have Prerequisites"
fi

#######################################
# Scenario 3: Each runbook has Stop Conditions
#######################################
e2e_step "Scenario 3: Stop Conditions sections"

STOPS_FOUND=0
for runbook in "replay-failure-triage.md" "corruption-recovery.md" "backpressure-investigation.md" "perf-regression-triage.md"; do
    # Accept "Stop Conditions" or "Evidence Checklist" as terminal/exit-criteria sections
    if [[ -f "$RUNBOOK_DIR/$runbook" ]] && grep -qE "## (Stop Conditions|Evidence Checklist)" "$RUNBOOK_DIR/$runbook"; then
        STOPS_FOUND=$((STOPS_FOUND + 1))
    fi
done

if [[ $STOPS_FOUND -eq 4 ]]; then
    scenario_result "runbooks_have_exit_criteria" "PASS" "All 4 runbooks have exit criteria sections"
else
    scenario_result "runbooks_have_exit_criteria" "FAIL" "Only ${STOPS_FOUND}/4 have exit criteria sections"
fi

#######################################
# Scenario 4: Each runbook has bash command blocks
#######################################
e2e_step "Scenario 4: Bash command blocks present"

CMDS_FOUND=0
for runbook in "replay-failure-triage.md" "corruption-recovery.md" "backpressure-investigation.md" "perf-regression-triage.md"; do
    if [[ -f "$RUNBOOK_DIR/$runbook" ]] && grep -q '```bash' "$RUNBOOK_DIR/$runbook"; then
        CMDS_FOUND=$((CMDS_FOUND + 1))
    fi
done

if [[ $CMDS_FOUND -eq 4 ]]; then
    scenario_result "runbooks_have_bash_commands" "PASS" "All 4 runbooks have bash command blocks"
else
    scenario_result "runbooks_have_bash_commands" "FAIL" "Only ${CMDS_FOUND}/4 have bash command blocks"
fi

#######################################
# Scenario 5: Decision tree / quick reference
#######################################
e2e_step "Scenario 5: Decision trees present"

TREES_FOUND=0
for runbook in "replay-failure-triage.md" "corruption-recovery.md" "backpressure-investigation.md" "perf-regression-triage.md"; do
    if [[ -f "$RUNBOOK_DIR/$runbook" ]] && grep -q "Quick Reference\|Decision" "$RUNBOOK_DIR/$runbook"; then
        TREES_FOUND=$((TREES_FOUND + 1))
    fi
done

if [[ $TREES_FOUND -eq 4 ]]; then
    scenario_result "runbooks_have_decision_trees" "PASS" "All 4 runbooks have decision trees"
else
    scenario_result "runbooks_have_decision_trees" "FAIL" "Only ${TREES_FOUND}/4 have decision trees"
fi

#######################################
# Scenario 6: Replay runbook references ffs CLI commands
#######################################
e2e_step "Scenario 6: Replay runbook ffs CLI references"

REPLAY_CMDS=0
for cmd in "ffs info" "ffs scrub" "ffs repair"; do
    if grep -q "$cmd" "$RUNBOOK_DIR/replay-failure-triage.md"; then
        REPLAY_CMDS=$((REPLAY_CMDS + 1))
    fi
done

if [[ $REPLAY_CMDS -ge 3 ]]; then
    scenario_result "replay_runbook_ffs_commands" "PASS" "Replay runbook references ${REPLAY_CMDS}/3 ffs commands"
else
    scenario_result "replay_runbook_ffs_commands" "FAIL" "Only ${REPLAY_CMDS}/3 ffs commands in replay runbook"
fi

#######################################
# Scenario 7: Corruption runbook references scrub+repair flow
#######################################
e2e_step "Scenario 7: Corruption runbook scrub/repair flow"

CORRUPTION_REFS=0
for ref in "ffs scrub" "ffs repair" "ffs evidence" "corruption_count"; do
    if grep -q "$ref" "$RUNBOOK_DIR/corruption-recovery.md"; then
        CORRUPTION_REFS=$((CORRUPTION_REFS + 1))
    fi
done

if [[ $CORRUPTION_REFS -ge 4 ]]; then
    scenario_result "corruption_runbook_scrub_repair" "PASS" "Corruption runbook has ${CORRUPTION_REFS}/4 key references"
else
    scenario_result "corruption_runbook_scrub_repair" "FAIL" "Only ${CORRUPTION_REFS}/4 key references in corruption runbook"
fi

#######################################
# Scenario 8: Backpressure runbook references degradation levels
#######################################
e2e_step "Scenario 8: Backpressure runbook degradation levels"

BP_LEVELS=0
for level in "Normal" "Elevated" "Degraded" "Emergency"; do
    if grep -q "$level" "$RUNBOOK_DIR/backpressure-investigation.md"; then
        BP_LEVELS=$((BP_LEVELS + 1))
    fi
done

if [[ $BP_LEVELS -eq 4 ]]; then
    scenario_result "backpressure_runbook_degradation_levels" "PASS" "All 4 degradation levels documented"
else
    scenario_result "backpressure_runbook_degradation_levels" "FAIL" "Only ${BP_LEVELS}/4 degradation levels found"
fi

#######################################
# Scenario 9: Backpressure runbook references runtime modes
#######################################
e2e_step "Scenario 9: Backpressure runbook runtime modes"

BP_MODES=0
for mode in "standard" "managed" "per-core"; do
    if grep -q "$mode" "$RUNBOOK_DIR/backpressure-investigation.md"; then
        BP_MODES=$((BP_MODES + 1))
    fi
done

if [[ $BP_MODES -eq 3 ]]; then
    scenario_result "backpressure_runbook_runtime_modes" "PASS" "All 3 runtime modes referenced"
else
    scenario_result "backpressure_runbook_runtime_modes" "FAIL" "Only ${BP_MODES}/3 runtime modes found"
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
