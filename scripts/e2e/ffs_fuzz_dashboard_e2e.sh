#!/usr/bin/env bash
# ffs_fuzz_dashboard_e2e.sh - Verification gate for fuzz coverage/reporting dashboard (bd-h6nz.4.5)
#
# Validates the fuzz dashboard module: campaign summary parsing, health
# assessment, regression detection, schema validation, and nightly script
# integration.
#
# Scenarios:
# 1. Fuzz dashboard module exists and is exported
# 2. CampaignSummary struct matches nightly_fuzz.sh JSON schema
# 3. TargetHealth enum covers all 4 states
# 4. assess_campaign_health returns per-target reports
# 5. detect_regressions compares campaigns with thresholds
# 6. Nightly fuzz script exists with JSON output
# 7. Campaign schema validation covers required fields
# 8. Regression alert severity levels (Warning/Critical)
# 9. Fuzz dashboard unit tests pass
#
# Usage: ./scripts/e2e/ffs_fuzz_dashboard_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fuzz_dashboard}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

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

e2e_init "ffs_fuzz_dashboard"

#######################################
# Scenario 1: Fuzz dashboard module exists and is exported
#######################################
e2e_step "Scenario 1: Fuzz dashboard module exists"

if [[ -f "crates/ffs-harness/src/fuzz_dashboard.rs" ]] && grep -q "pub mod fuzz_dashboard" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "dashboard_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "dashboard_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: CampaignSummary struct matches nightly schema
#######################################
e2e_step "Scenario 2: CampaignSummary struct fields"

FIELDS_OK=0
for field in campaign_id commit_sha timestamp config totals targets; do
    grep -q "pub ${field}:" "crates/ffs-harness/src/fuzz_dashboard.rs" && FIELDS_OK=$((FIELDS_OK + 1))
done

if [[ $FIELDS_OK -eq 6 ]]; then
    scenario_result "dashboard_campaign_schema" "PASS" "All 6 CampaignSummary fields present"
else
    scenario_result "dashboard_campaign_schema" "FAIL" "Only ${FIELDS_OK}/6 fields found"
fi

#######################################
# Scenario 3: TargetHealth enum covers all states
#######################################
e2e_step "Scenario 3: TargetHealth enum states"

STATES_OK=0
for state in Healthy Stagnant CrashesFound Error; do
    grep -q "$state" "crates/ffs-harness/src/fuzz_dashboard.rs" && STATES_OK=$((STATES_OK + 1))
done

if [[ $STATES_OK -eq 4 ]]; then
    scenario_result "dashboard_health_states" "PASS" "All 4 TargetHealth states defined"
else
    scenario_result "dashboard_health_states" "FAIL" "Only ${STATES_OK}/4 states found"
fi

#######################################
# Scenario 4: assess_campaign_health function exists
#######################################
e2e_step "Scenario 4: Health assessment function"

if grep -q "pub fn assess_campaign_health" "crates/ffs-harness/src/fuzz_dashboard.rs" && \
   grep -q "TargetHealthReport" "crates/ffs-harness/src/fuzz_dashboard.rs"; then
    scenario_result "dashboard_health_assessment" "PASS" "assess_campaign_health exists with TargetHealthReport"
else
    scenario_result "dashboard_health_assessment" "FAIL" "Health assessment function missing"
fi

#######################################
# Scenario 5: Regression detection with thresholds
#######################################
e2e_step "Scenario 5: Regression detection"

if grep -q "pub fn detect_regressions" "crates/ffs-harness/src/fuzz_dashboard.rs" && \
   grep -q "THROUGHPUT_REGRESSION_THRESHOLD" "crates/ffs-harness/src/fuzz_dashboard.rs" && \
   grep -q "COVERAGE_REGRESSION_THRESHOLD" "crates/ffs-harness/src/fuzz_dashboard.rs"; then
    scenario_result "dashboard_regression_detection" "PASS" "detect_regressions with throughput/coverage thresholds"
else
    scenario_result "dashboard_regression_detection" "FAIL" "Regression detection missing or incomplete"
fi

#######################################
# Scenario 6: Nightly fuzz script exists with JSON output
#######################################
e2e_step "Scenario 6: Nightly fuzz script"

if [[ -x "fuzz/scripts/nightly_fuzz.sh" ]] && \
   grep -q "campaign_id" "fuzz/scripts/nightly_fuzz.sh" && \
   grep -q "target_count" "fuzz/scripts/nightly_fuzz.sh" && \
   grep -q "total_runs" "fuzz/scripts/nightly_fuzz.sh" && \
   grep -q "crash_count" "fuzz/scripts/nightly_fuzz.sh" && \
   grep -q "campaign_summary" "fuzz/scripts/nightly_fuzz.sh"; then
    scenario_result "dashboard_nightly_script" "PASS" "nightly_fuzz.sh exists with dashboard-compatible JSON output"
else
    scenario_result "dashboard_nightly_script" "FAIL" "Nightly fuzz script missing or incomplete"
fi

#######################################
# Scenario 7: Campaign schema validation
#######################################
e2e_step "Scenario 7: Schema validation function"

if grep -q "pub fn validate_campaign_schema" "crates/ffs-harness/src/fuzz_dashboard.rs" && \
   grep -q "SchemaCheck" "crates/ffs-harness/src/fuzz_dashboard.rs"; then
    scenario_result "dashboard_schema_validation" "PASS" "validate_campaign_schema with SchemaCheck results"
else
    scenario_result "dashboard_schema_validation" "FAIL" "Schema validation function missing"
fi

#######################################
# Scenario 8: Alert severity levels
#######################################
e2e_step "Scenario 8: Alert severity levels"

if grep -q "AlertSeverity" "crates/ffs-harness/src/fuzz_dashboard.rs" && \
   grep -q "Warning" "crates/ffs-harness/src/fuzz_dashboard.rs" && \
   grep -q "Critical" "crates/ffs-harness/src/fuzz_dashboard.rs"; then
    scenario_result "dashboard_alert_severity" "PASS" "Warning and Critical severity levels defined"
else
    scenario_result "dashboard_alert_severity" "FAIL" "Alert severity levels missing"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Unit tests pass"

TEST_LOG=$(mktemp)
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib -- fuzz_dashboard >"$TEST_LOG" 2>&1; then
    cat "$TEST_LOG"
    cat "$TEST_LOG" >> "$E2E_LOG_FILE"
    TESTS_RUN=$(grep -c "test fuzz_dashboard::tests::" "$TEST_LOG" 2>/dev/null || true)
    TESTS_RUN="${TESTS_RUN:-0}"
    if [[ $TESTS_RUN -ge 14 ]]; then
        scenario_result "dashboard_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "dashboard_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 14)"
    fi
else
    cat "$TEST_LOG"
    cat "$TEST_LOG" >> "$E2E_LOG_FILE"
    scenario_result "dashboard_unit_tests_pass" "FAIL" "Fuzz dashboard tests failed"
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
