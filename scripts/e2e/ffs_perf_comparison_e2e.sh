#!/usr/bin/env bash
# ffs_perf_comparison_e2e.sh - E2E validation for statistically robust regression comparator
#
# Validates that:
#   1. The perf_comparison module builds and all unit tests pass
#   2. Statistical primitives (mean, std, CI, effect size) compute correctly
#   3. Welch's t-test p-value approximation is accurate for known distributions
#   4. Hysteresis tracker correctly gates flaky verdicts
#   5. Integration with AcceptanceEnvelope produces expected verdicts
#
# Scenario IDs:
#   perf_comparison_builds_clean       - cargo check + test pass for perf_comparison
#   perf_comparison_stats_accuracy     - statistical primitives produce known results
#   perf_comparison_ttest_accuracy     - t-test distinguishes significant vs. non-significant
#   perf_comparison_hysteresis_gates   - hysteresis suppresses single-run flakes
#   perf_comparison_envelope_integration - comparator + envelope produces correct verdicts
#
# Usage:
#   scripts/e2e/ffs_perf_comparison_e2e.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Source shared helpers
source "$(dirname "$0")/lib.sh"

SCENARIO_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

log_scenario() {
    local scenario_id="$1"
    local outcome="$2"  # PASS or FAIL
    local detail="${3:-}"

    local marker="SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}"
    if [ -n "$detail" ]; then
        marker="${marker}|detail=${detail}"
    fi
    echo "$marker"
    SCENARIO_RESULTS+=("$marker")

    if [ "$outcome" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ── Scenario: perf_comparison_builds_clean ────────────────────────────

echo "=== Scenario: perf_comparison_builds_clean ==="
if rch exec -- cargo test -p ffs-harness --lib perf_comparison 2>&1; then
    log_scenario "perf_comparison_builds_clean" "PASS"
else
    log_scenario "perf_comparison_builds_clean" "FAIL" "cargo test perf_comparison failed"
fi

# ── Scenario: perf_comparison_stats_accuracy ──────────────────────────

echo "=== Scenario: perf_comparison_stats_accuracy ==="
# Verify the stats tests cover known values: mean, std, CV, median
STATS_TESTS="stats_known_values stats_single_value stats_even_count_median stats_cv_percent_is_correct"
STATS_FAIL=""
for test_name in $STATS_TESTS; do
    if ! rch exec -- cargo test -p ffs-harness --lib "perf_comparison::tests::${test_name}" 2>&1 | grep -q "test result: ok"; then
        STATS_FAIL="${STATS_FAIL}${test_name} "
    fi
done

if [ -z "$STATS_FAIL" ]; then
    log_scenario "perf_comparison_stats_accuracy" "PASS"
else
    log_scenario "perf_comparison_stats_accuracy" "FAIL" "failed=${STATS_FAIL}"
fi

# ── Scenario: perf_comparison_ttest_accuracy ──────────────────────────

echo "=== Scenario: perf_comparison_ttest_accuracy ==="
TTEST_TESTS="t_test_identical_samples_high_p t_test_clearly_different_samples_low_p t_test_symmetry t_test_too_small_samples"
TTEST_FAIL=""
for test_name in $TTEST_TESTS; do
    if ! rch exec -- cargo test -p ffs-harness --lib "perf_comparison::tests::${test_name}" 2>&1 | grep -q "test result: ok"; then
        TTEST_FAIL="${TTEST_FAIL}${test_name} "
    fi
done

if [ -z "$TTEST_FAIL" ]; then
    log_scenario "perf_comparison_ttest_accuracy" "PASS"
else
    log_scenario "perf_comparison_ttest_accuracy" "FAIL" "failed=${TTEST_FAIL}"
fi

# ── Scenario: perf_comparison_hysteresis_gates ────────────────────────

echo "=== Scenario: perf_comparison_hysteresis_gates ==="
HYST_TESTS="hysteresis_single_fail_is_early_warning hysteresis_two_fails_in_window_confirmed hysteresis_pass_clears_signal hysteresis_reset_clears_history hysteresis_window_evicts_old"
HYST_FAIL=""
for test_name in $HYST_TESTS; do
    if ! rch exec -- cargo test -p ffs-harness --lib "perf_comparison::tests::${test_name}" 2>&1 | grep -q "test result: ok"; then
        HYST_FAIL="${HYST_FAIL}${test_name} "
    fi
done

if [ -z "$HYST_FAIL" ]; then
    log_scenario "perf_comparison_hysteresis_gates" "PASS"
else
    log_scenario "perf_comparison_hysteresis_gates" "FAIL" "failed=${HYST_FAIL}"
fi

# ── Scenario: perf_comparison_envelope_integration ────────────────────

echo "=== Scenario: perf_comparison_envelope_integration ==="
INTEG_TESTS="comparator_noise_floor_passes comparator_significant_large_regression_fails comparator_not_significant_passes_despite_delta comparator_warn_zone_with_significance improvement_is_not_regression"
INTEG_FAIL=""
for test_name in $INTEG_TESTS; do
    if ! rch exec -- cargo test -p ffs-harness --lib "perf_comparison::tests::${test_name}" 2>&1 | grep -q "test result: ok"; then
        INTEG_FAIL="${INTEG_FAIL}${test_name} "
    fi
done

if [ -z "$INTEG_FAIL" ]; then
    log_scenario "perf_comparison_envelope_integration" "PASS"
else
    log_scenario "perf_comparison_envelope_integration" "FAIL" "failed=${INTEG_FAIL}"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Perf Comparison E2E Summary"
echo "============================================"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  TOTAL: $((PASS_COUNT + FAIL_COUNT))"
echo "============================================"

for result in "${SCENARIO_RESULTS[@]}"; do
    echo "  $result"
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "PERF_COMPARISON_E2E: FAILED"
    exit 1
fi

echo ""
echo "PERF_COMPARISON_E2E: PASSED"
exit 0
