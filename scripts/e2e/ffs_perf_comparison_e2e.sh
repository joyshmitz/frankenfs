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

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_perf_comparison}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_PERF_COMPARISON_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_PERF_COMPARISON_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_PERF_COMPARISON_SKIP_SELF_CHECK:-0}"

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    e2e_rch_add_env_allowlist "$rch_env_var"
done

SCENARIO_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
PERF_LOG=""

run_rch_capture() {
    local output_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$output_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_PERF_COMPARISON_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown perf comparison fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib perf_comparison -- --nocapture"*)
        printf '%s\n' \
            "running 18 tests" \
            "test perf_comparison::tests::stats_known_values ... ok" \
            "test perf_comparison::tests::stats_single_value ... ok" \
            "test perf_comparison::tests::stats_even_count_median ... ok" \
            "test perf_comparison::tests::stats_cv_percent_is_correct ... ok" \
            "test perf_comparison::tests::t_test_identical_samples_high_p ... ok" \
            "test perf_comparison::tests::t_test_clearly_different_samples_low_p ... ok" \
            "test perf_comparison::tests::t_test_symmetry ... ok" \
            "test perf_comparison::tests::t_test_too_small_samples ... ok" \
            "test perf_comparison::tests::hysteresis_single_fail_is_early_warning ... ok" \
            "test perf_comparison::tests::hysteresis_two_fails_in_window_confirmed ... ok" \
            "test perf_comparison::tests::hysteresis_pass_clears_signal ... ok" \
            "test perf_comparison::tests::hysteresis_reset_clears_history ... ok" \
            "test perf_comparison::tests::hysteresis_window_evicts_old ... ok" \
            "test perf_comparison::tests::comparator_noise_floor_passes ... ok" \
            "test perf_comparison::tests::comparator_significant_large_regression_fails ... ok" \
            "test perf_comparison::tests::comparator_not_significant_passes_despite_delta ... ok" \
            "test perf_comparison::tests::comparator_warn_zone_with_significance ... ok" \
            "test perf_comparison::tests::improvement_is_not_regression ... ok"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/perf_comparison_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_PERF_COMPARISON_SELF_CHECK=0 \
        FFS_PERF_COMPARISON_SKIP_SELF_CHECK=1 \
        FFS_PERF_COMPARISON_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_perf_comparison_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic perf comparison wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir test_log
    stub_path="$E2E_LOG_DIR/rch-perf-comparison-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    test_log="$result_dir/perf_comparison_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$test_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "perf_comparison_builds_clean" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "perf_comparison_stats_accuracy" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "perf_comparison_ttest_accuracy" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "perf_comparison_hysteresis_gates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "perf_comparison_envelope_integration" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "stats_known_values" "$test_log" \
        && grep -q "t_test_clearly_different_samples_low_p" "$test_log" \
        && grep -q "hysteresis_two_fails_in_window_confirmed" "$test_log" \
        && grep -q "comparator_significant_large_regression_fails" "$test_log"; then
        log_scenario "perf_comparison_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        log_scenario "perf_comparison_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Perf comparison complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        log_scenario "perf_comparison_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        log_scenario "perf_comparison_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Perf comparison local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        log_scenario "perf_comparison_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        log_scenario "perf_comparison_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Perf comparison missing remote evidence fixture self-check failed"
    fi
}

print_rch_log() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
}

log_scenario() {
    local scenario_id="$1"
    local outcome="$2"  # PASS or FAIL
    local detail="${3:-}"

    local marker="SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}"
    if [ -n "$detail" ]; then
        marker="${marker}|detail=${detail}"
    fi
    e2e_log "$marker"
    SCENARIO_RESULTS+=("$marker")

    if [ "$outcome" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

require_tests_in_log() {
    local scenario_id="$1"
    local pass_detail="$2"
    local missing=""
    local test_name
    shift 2

    for test_name in "$@"; do
        if ! grep -Eq "test .*${test_name} .*\\.\\.\\. ok" "$PERF_LOG"; then
            missing="${missing}${test_name} "
        fi
    done

    if [ -z "$missing" ]; then
        log_scenario "$scenario_id" "PASS" "$pass_detail"
    else
        log_scenario "$scenario_id" "FAIL" "missing_or_failed=${missing}log=${PERF_LOG}"
    fi
}

e2e_init "ffs_perf_comparison"
PERF_LOG="$E2E_LOG_DIR/perf_comparison_tests.log"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

# ── Scenario: perf_comparison_builds_clean ────────────────────────────

e2e_step "Scenario: perf_comparison_builds_clean"
if run_rch_capture "$PERF_LOG" cargo test -p ffs-harness --lib perf_comparison -- --nocapture; then
    log_scenario "perf_comparison_builds_clean" "PASS" "cargo test perf_comparison passed; log=${PERF_LOG}"
else
    print_rch_log "$PERF_LOG"
    log_scenario "perf_comparison_builds_clean" "FAIL" "cargo test perf_comparison failed; log=${PERF_LOG}"
fi

# ── Scenario: perf_comparison_stats_accuracy ──────────────────────────

e2e_step "Scenario: perf_comparison_stats_accuracy"
require_tests_in_log \
    "perf_comparison_stats_accuracy" \
    "statistical primitive tests passed" \
    "stats_known_values" \
    "stats_single_value" \
    "stats_even_count_median" \
    "stats_cv_percent_is_correct"

# ── Scenario: perf_comparison_ttest_accuracy ──────────────────────────

e2e_step "Scenario: perf_comparison_ttest_accuracy"
require_tests_in_log \
    "perf_comparison_ttest_accuracy" \
    "Welch t-test accuracy tests passed" \
    "t_test_identical_samples_high_p" \
    "t_test_clearly_different_samples_low_p" \
    "t_test_symmetry" \
    "t_test_too_small_samples"

# ── Scenario: perf_comparison_hysteresis_gates ────────────────────────

e2e_step "Scenario: perf_comparison_hysteresis_gates"
require_tests_in_log \
    "perf_comparison_hysteresis_gates" \
    "hysteresis tracker tests passed" \
    "hysteresis_single_fail_is_early_warning" \
    "hysteresis_two_fails_in_window_confirmed" \
    "hysteresis_pass_clears_signal" \
    "hysteresis_reset_clears_history" \
    "hysteresis_window_evicts_old"

# ── Scenario: perf_comparison_envelope_integration ────────────────────

e2e_step "Scenario: perf_comparison_envelope_integration"
require_tests_in_log \
    "perf_comparison_envelope_integration" \
    "acceptance-envelope integration tests passed" \
    "comparator_noise_floor_passes" \
    "comparator_significant_large_regression_fails" \
    "comparator_not_significant_passes_despite_delta" \
    "comparator_warn_zone_with_significance" \
    "improvement_is_not_regression"

# ── Summary ───────────────────────────────────────────────────────────

e2e_log ""
e2e_log "============================================"
e2e_log "  Perf Comparison E2E Summary"
e2e_log "============================================"
e2e_log "  PASS: $PASS_COUNT"
e2e_log "  FAIL: $FAIL_COUNT"
e2e_log "  TOTAL: $((PASS_COUNT + FAIL_COUNT))"
e2e_log "============================================"

for result in "${SCENARIO_RESULTS[@]}"; do
    e2e_log "  ${result/SCENARIO_RESULT/SCENARIO_SUMMARY}"
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    e2e_log ""
    e2e_log "PERF_COMPARISON_E2E: FAILED"
    exit 1
fi

e2e_log ""
e2e_log "PERF_COMPARISON_E2E: PASSED"
e2e_pass
exit 0
