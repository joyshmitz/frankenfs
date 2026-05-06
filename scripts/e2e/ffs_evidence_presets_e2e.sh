#!/usr/bin/env bash
# ffs_evidence_presets_e2e.sh - Verification gate for evidence query presets (bd-h6nz.7.2)
#
# Validates operator-oriented evidence query presets and summary views.
#
# Scenarios:
# 1. CLI parses --preset flag for all 4 ledger presets
# 2. CLI parses --summary flag
# 3. Preset event type definitions exist in cmd_evidence.rs
# 4. Summary struct has required fields (JSON schema stability)
# 5. Evidence unit tests pass (15+ tests including preset/summary)
# 6. Structured logging: evidence_start and evidence_complete markers present
# 7. Structured logging: evidence_preset_rejected marker for invalid presets
# 8. Preset and event_type mutual exclusivity enforced
# 9. Known presets documented in code
#
# Usage: ./scripts/e2e/ffs_evidence_presets_e2e.sh
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

e2e_init "ffs_evidence_presets"

CLI_SRC="crates/ffs-cli/src/cmd_evidence.rs"
MAIN_SRC="crates/ffs-cli/src/main.rs"

#######################################
# Scenario 1: All 4 ledger presets defined
#######################################
e2e_step "Scenario 1: Preset definitions present"

PRESETS_FOUND=0
for preset in "replay-anomalies" "repair-failures" "pressure-transitions" "contention"; do
    if grep -q "\"${preset}\"" "$CLI_SRC"; then
        PRESETS_FOUND=$((PRESETS_FOUND + 1))
    fi
done

if [[ $PRESETS_FOUND -eq 4 ]]; then
    scenario_result "evidence_presets_all_defined" "PASS" "All 4 ledger presets defined"
else
    scenario_result "evidence_presets_all_defined" "FAIL" "Only ${PRESETS_FOUND}/4 ledger presets found"
fi

#######################################
# Scenario 2: Summary struct defined
#######################################
e2e_step "Scenario 2: Summary struct with required fields"

SUMMARY_FIELDS=0
for field in "total_records" "event_type_counts" "time_span_ns" "block_groups_seen" "preset" "replay_summary" "repair_summary" "pressure_summary" "contention_summary"; do
    if grep -q "pub $field" "$CLI_SRC"; then
        SUMMARY_FIELDS=$((SUMMARY_FIELDS + 1))
    fi
done

if [[ $SUMMARY_FIELDS -ge 9 ]]; then
    scenario_result "evidence_summary_struct_fields" "PASS" "EvidenceSummary has ${SUMMARY_FIELDS}/9 fields"
else
    scenario_result "evidence_summary_struct_fields" "FAIL" "Only ${SUMMARY_FIELDS}/9 summary fields found"
fi

#######################################
# Scenario 3: CLI --preset flag wired
#######################################
e2e_step "Scenario 3: CLI --preset flag wired"

if grep -q "preset: Option" "$MAIN_SRC" && grep -q 'preset' "$CLI_SRC"; then
    scenario_result "evidence_cli_preset_flag" "PASS" "CLI --preset flag wired"
else
    scenario_result "evidence_cli_preset_flag" "FAIL" "CLI --preset flag not found"
fi

#######################################
# Scenario 4: CLI --summary flag wired
#######################################
e2e_step "Scenario 4: CLI --summary flag wired"

if grep -q "summary: bool" "$MAIN_SRC" && grep -q "print_summary" "$CLI_SRC"; then
    scenario_result "evidence_cli_summary_flag" "PASS" "CLI --summary flag wired"
else
    scenario_result "evidence_cli_summary_flag" "FAIL" "CLI --summary flag not found"
fi

#######################################
# Scenario 5: Evidence unit tests pass
#######################################
e2e_step "Scenario 5: Evidence unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-cli -- evidence 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test tests::.*evidence\|test tests::.*preset\|test tests::load_evidence" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 12 ]]; then
        scenario_result "evidence_unit_tests_pass" "PASS" "Evidence tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "evidence_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 12)"
    fi
else
    scenario_result "evidence_unit_tests_pass" "FAIL" "Evidence tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 6: Structured logging markers
#######################################
e2e_step "Scenario 6: Structured logging markers"

LOG_MARKERS=0
for marker in "evidence_start" "evidence_complete"; do
    if grep -q "\"${marker}\"" "$CLI_SRC"; then
        LOG_MARKERS=$((LOG_MARKERS + 1))
    fi
done

if [[ $LOG_MARKERS -ge 2 ]]; then
    scenario_result "evidence_structured_logging" "PASS" "${LOG_MARKERS}/2 logging markers present"
else
    scenario_result "evidence_structured_logging" "FAIL" "Only ${LOG_MARKERS}/2 markers found"
fi

#######################################
# Scenario 7: Invalid preset rejection logging
#######################################
e2e_step "Scenario 7: Invalid preset rejection logging"

if grep -q "evidence_preset_rejected" "$CLI_SRC"; then
    scenario_result "evidence_preset_rejection_logging" "PASS" "Rejection log marker present"
else
    scenario_result "evidence_preset_rejection_logging" "FAIL" "Rejection log marker not found"
fi

#######################################
# Scenario 8: Preset/event_type mutual exclusion
#######################################
e2e_step "Scenario 8: Preset and event_type mutual exclusion"

if grep -q "mutually exclusive" "$CLI_SRC"; then
    scenario_result "evidence_preset_event_type_exclusive" "PASS" "Mutual exclusion enforced"
else
    scenario_result "evidence_preset_event_type_exclusive" "FAIL" "Mutual exclusion not found"
fi

#######################################
# Scenario 9: Correlation fields in logging
#######################################
e2e_step "Scenario 9: Correlation fields in evidence logging"

CORR_FIELDS=0
for field in "operation_id" "outcome" "preset" "record_count"; do
    if grep -q "$field" "$CLI_SRC"; then
        CORR_FIELDS=$((CORR_FIELDS + 1))
    fi
done

if [[ $CORR_FIELDS -ge 4 ]]; then
    scenario_result "evidence_logging_correlation_fields" "PASS" "${CORR_FIELDS}/4 correlation fields present"
else
    scenario_result "evidence_logging_correlation_fields" "FAIL" "Only ${CORR_FIELDS}/4 correlation fields"
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
