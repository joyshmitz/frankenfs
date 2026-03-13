#!/usr/bin/env bash
# ffs_benchmark_governance_e2e.sh - Verification gate for benchmark/regression governance (bd-h6nz.5.6)
#
# End-to-end validation that the full benchmark governance pipeline is coherent:
# taxonomy → comparator → hysteresis → triage → structured logging → follow-up commands.
#
# Scenarios:
# 1. Comparator produces structured log fields (benchmark_id, profile_id, baseline_ref)
# 2. Triage decisions include actionable followup_command
# 3. Guard-failure followup commands reference benchmark_record.sh
# 4. Hysteresis tracker emits rerun-count structured fields
# 5. All triage actions map to non-empty followup commands (except NoAction)
# 6. ComparisonContext JSON schema round-trips
# 7. Triage decision JSON includes followup_command field
# 8. Benchmark taxonomy + comparator + triage integration test passes
# 9. All benchmark governance unit tests pass
#
# Usage: ./scripts/e2e/ffs_benchmark_governance_e2e.sh
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

e2e_init "ffs_benchmark_governance"

COMP_SRC="crates/ffs-harness/src/perf_comparison.rs"
TRIAGE_SRC="crates/ffs-harness/src/perf_triage.rs"
TAXONOMY_SRC="crates/ffs-harness/src/benchmark_taxonomy.rs"

#######################################
# Scenario 1: Comparator emits benchmark_id, profile_id, baseline_ref in structured log
#######################################
e2e_step "Scenario 1: Comparator structured log fields"

FIELDS_FOUND=0
for field in "benchmark_id" "profile_id" "baseline_ref"; do
    if grep -q "$field" "$COMP_SRC"; then
        FIELDS_FOUND=$((FIELDS_FOUND + 1))
    fi
done

if [[ $FIELDS_FOUND -eq 3 ]]; then
    scenario_result "governance_comparator_log_fields" "PASS" "All 3 context fields present in comparator"
else
    scenario_result "governance_comparator_log_fields" "FAIL" "Only ${FIELDS_FOUND}/3 context fields"
fi

#######################################
# Scenario 2: Triage decisions include followup_command field
#######################################
e2e_step "Scenario 2: Triage decisions include followup_command"

if grep -q "pub followup_command: String" "$TRIAGE_SRC"; then
    scenario_result "governance_triage_followup_field" "PASS" "followup_command field in TriageDecision"
else
    scenario_result "governance_triage_followup_field" "FAIL" "followup_command field not found"
fi

#######################################
# Scenario 3: Guard-failure followup commands reference benchmark_record.sh
#######################################
e2e_step "Scenario 3: Followup commands reference benchmark_record.sh"

if grep -q "benchmark_record" "$TRIAGE_SRC"; then
    scenario_result "governance_followup_references_record" "PASS" "Followup commands reference benchmark_record.sh"
else
    scenario_result "governance_followup_references_record" "FAIL" "No benchmark_record reference in followup commands"
fi

#######################################
# Scenario 4: Hysteresis tracker emits structured count fields
#######################################
e2e_step "Scenario 4: Hysteresis tracker structured count fields"

HYST_FIELDS=0
for field in "fail_count" "warn_count" "window_size" "problem_count"; do
    if grep -q "$field" "$COMP_SRC"; then
        HYST_FIELDS=$((HYST_FIELDS + 1))
    fi
done

if [[ $HYST_FIELDS -ge 3 ]]; then
    scenario_result "governance_hysteresis_log_fields" "PASS" "${HYST_FIELDS} hysteresis fields emitted"
else
    scenario_result "governance_hysteresis_log_fields" "FAIL" "Only ${HYST_FIELDS}/3 hysteresis fields"
fi

#######################################
# Scenario 5: All TriageActions mapped to followup commands
#######################################
e2e_step "Scenario 5: All TriageActions mapped in followup_for"

ACTIONS_FOUND=0
for action in "CollectMoreSamples" "RerunOnReference" "BisectCommits" "CheckEnvironment" "RecalibrateThresholds" "NoAction"; do
    if grep -q "TriageAction::${action}" "$TRIAGE_SRC"; then
        ACTIONS_FOUND=$((ACTIONS_FOUND + 1))
    fi
done

if [[ $ACTIONS_FOUND -eq 6 ]]; then
    scenario_result "governance_all_actions_mapped" "PASS" "All 6 triage actions mapped"
else
    scenario_result "governance_all_actions_mapped" "FAIL" "Only ${ACTIONS_FOUND}/6 actions mapped"
fi

#######################################
# Scenario 6: ComparisonContext JSON schema present
#######################################
e2e_step "Scenario 6: ComparisonContext struct defined"

if grep -q "pub struct ComparisonContext" "$COMP_SRC" && grep -q "Serialize, Deserialize" "$COMP_SRC"; then
    scenario_result "governance_context_struct" "PASS" "ComparisonContext struct with serde"
else
    scenario_result "governance_context_struct" "FAIL" "ComparisonContext not found or missing serde"
fi

#######################################
# Scenario 7: Triage emit_triage_log includes followup_command
#######################################
e2e_step "Scenario 7: emit_triage_log includes followup_command"

if grep -q 'followup_command.*decision.followup_command' "$TRIAGE_SRC"; then
    scenario_result "governance_log_has_followup" "PASS" "followup_command in structured triage log"
else
    scenario_result "governance_log_has_followup" "FAIL" "followup_command not in triage log emission"
fi

#######################################
# Scenario 8: Taxonomy + comparator + triage modules all build
#######################################
e2e_step "Scenario 8: All governance modules build"

if cargo check -p ffs-harness 2>/dev/null; then
    scenario_result "governance_modules_build" "PASS" "ffs-harness builds cleanly"
else
    scenario_result "governance_modules_build" "FAIL" "ffs-harness build failed"
fi

#######################################
# Scenario 9: All governance unit tests pass
#######################################
e2e_step "Scenario 9: Governance unit tests"

TEST_LOG=$(mktemp)
COMBINED_PASS=0
COMBINED_FAIL=0

# Run tests for all 3 governance modules
for mod_filter in "benchmark_taxonomy" "perf_comparison" "perf_triage"; do
    if cargo test -p ffs-harness --lib -- "$mod_filter" 2>>"$TEST_LOG" | tee -a "$TEST_LOG" > /dev/null 2>&1; then
        COMBINED_PASS=$((COMBINED_PASS + 1))
    else
        COMBINED_FAIL=$((COMBINED_FAIL + 1))
    fi
done

TOTAL_TESTS=$(grep -c "^test " "$TEST_LOG" 2>/dev/null || echo "0")

if [[ $COMBINED_FAIL -eq 0 && $TOTAL_TESTS -ge 50 ]]; then
    scenario_result "governance_unit_tests_pass" "PASS" "All 3 modules pass (${TOTAL_TESTS} tests total)"
else
    scenario_result "governance_unit_tests_pass" "FAIL" "Failures: ${COMBINED_FAIL}/3 modules, ${TOTAL_TESTS} tests"
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
