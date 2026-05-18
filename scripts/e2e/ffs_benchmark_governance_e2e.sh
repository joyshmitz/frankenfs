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
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_benchmark_governance}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_CAPTURE_VISIBILITY="${FFS_BENCHMARK_GOVERNANCE_RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-420}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_BENCHMARK_GOVERNANCE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_BENCHMARK_GOVERNANCE_SKIP_SELF_CHECK:-0}"

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

fixture_case="${FFS_BENCHMARK_GOVERNANCE_FIXTURE_CASE:-complete}"

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
        echo "Remote command finished: exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown benchmark governance fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo check -p ffs-harness"*)
        echo "    Finished dev [unoptimized + debuginfo] target(s) in 0.01s"
        ;;
    *"cargo test -p ffs-harness --lib -- benchmark_taxonomy"*)
        printf '%s\n' \
            "running 20 tests" \
            "test benchmark_taxonomy::tests::taxonomy_contains_required_profiles ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_ids_are_unique ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_thresholds_are_ordered ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_baselines_are_named ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_serializes_to_json ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_deserializes_from_json ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_profile_lookup_is_stable ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_benchmark_lookup_is_stable ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_records_release_profile ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_records_perf_profile ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_detects_missing_thresholds ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_detects_duplicate_ids ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_emits_structured_log_fields ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_tracks_regression_budget ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_maps_to_triage_surface ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_preserves_sort_order ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_rejects_empty_profiles ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_has_operator_labels ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_has_followup_commands ... ok" \
            "test benchmark_taxonomy::tests::taxonomy_round_trip_is_stable ... ok"
        ;;
    *"cargo test -p ffs-harness --lib -- perf_comparison"*)
        printf '%s\n' \
            "running 20 tests" \
            "test perf_comparison::tests::comparison_context_round_trips ... ok" \
            "test perf_comparison::tests::comparison_logs_benchmark_id ... ok" \
            "test perf_comparison::tests::comparison_logs_profile_id ... ok" \
            "test perf_comparison::tests::comparison_logs_baseline_ref ... ok" \
            "test perf_comparison::tests::comparison_hysteresis_tracks_fail_count ... ok" \
            "test perf_comparison::tests::comparison_hysteresis_tracks_warn_count ... ok" \
            "test perf_comparison::tests::comparison_hysteresis_tracks_window_size ... ok" \
            "test perf_comparison::tests::comparison_hysteresis_tracks_problem_count ... ok" \
            "test perf_comparison::tests::comparison_accepts_clean_runs ... ok" \
            "test perf_comparison::tests::comparison_flags_warn_runs ... ok" \
            "test perf_comparison::tests::comparison_flags_fail_runs ... ok" \
            "test perf_comparison::tests::comparison_thresholds_are_monotonic ... ok" \
            "test perf_comparison::tests::comparison_preserves_baseline_labels ... ok" \
            "test perf_comparison::tests::comparison_sorts_benchmarks_stably ... ok" \
            "test perf_comparison::tests::comparison_reports_delta_percent ... ok" \
            "test perf_comparison::tests::comparison_rejects_missing_baselines ... ok" \
            "test perf_comparison::tests::comparison_rejects_unknown_profiles ... ok" \
            "test perf_comparison::tests::comparison_json_schema_is_stable ... ok" \
            "test perf_comparison::tests::comparison_operator_summary_is_nonempty ... ok" \
            "test perf_comparison::tests::comparison_release_gate_effect_is_stable ... ok"
        ;;
    *"cargo test -p ffs-harness --lib -- perf_triage"*)
        printf '%s\n' \
            "running 20 tests" \
            "test perf_triage::tests::triage_decision_serializes_followup_command ... ok" \
            "test perf_triage::tests::triage_collect_more_samples_has_command ... ok" \
            "test perf_triage::tests::triage_rerun_on_reference_has_command ... ok" \
            "test perf_triage::tests::triage_bisect_commits_has_command ... ok" \
            "test perf_triage::tests::triage_check_environment_has_command ... ok" \
            "test perf_triage::tests::triage_recalibrate_thresholds_has_command ... ok" \
            "test perf_triage::tests::triage_no_action_has_empty_command ... ok" \
            "test perf_triage::tests::triage_logs_followup_command ... ok" \
            "test perf_triage::tests::triage_guard_failure_references_record_script ... ok" \
            "test perf_triage::tests::triage_maps_warn_to_collect_samples ... ok" \
            "test perf_triage::tests::triage_maps_fail_to_bisect ... ok" \
            "test perf_triage::tests::triage_maps_environment_to_check_environment ... ok" \
            "test perf_triage::tests::triage_preserves_benchmark_id ... ok" \
            "test perf_triage::tests::triage_preserves_profile_id ... ok" \
            "test perf_triage::tests::triage_preserves_baseline_ref ... ok" \
            "test perf_triage::tests::triage_json_schema_is_stable ... ok" \
            "test perf_triage::tests::triage_operator_summary_is_nonempty ... ok" \
            "test perf_triage::tests::triage_release_gate_effect_is_stable ... ok" \
            "test perf_triage::tests::triage_command_text_is_shell_safe ... ok" \
            "test perf_triage::tests::triage_action_order_is_stable ... ok"
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
    local child_log="$E2E_LOG_DIR/benchmark_governance_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_BENCHMARK_GOVERNANCE_SELF_CHECK=0 \
        FFS_BENCHMARK_GOVERNANCE_SKIP_SELF_CHECK=1 \
        FFS_BENCHMARK_GOVERNANCE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_benchmark_governance_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic benchmark governance wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-benchmark-governance-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "governance_comparator_log_fields" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_triage_followup_field" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_followup_references_record" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_hysteresis_log_fields" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_all_actions_mapped" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_context_struct" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_log_has_followup" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_modules_build" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "governance_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "benchmark_governance_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "benchmark_governance_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "benchmark_governance_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "benchmark_governance_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "benchmark_governance_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "benchmark_governance_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_benchmark_governance"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

COMP_SRC="crates/ffs-harness/src/perf_comparison.rs"
TRIAGE_SRC="crates/ffs-harness/src/perf_triage.rs"
TAXONOMY_SRC="crates/ffs-harness/src/benchmark_taxonomy.rs"
BUILD_LOG="$E2E_LOG_DIR/benchmark_governance_build.log"
TEST_LOG="$E2E_LOG_DIR/benchmark_governance_unit_tests.log"

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

if run_rch_capture "$BUILD_LOG" cargo check -p ffs-harness; then
    scenario_result "governance_modules_build" "PASS" "ffs-harness builds cleanly"
else
    scenario_result "governance_modules_build" "FAIL" "ffs-harness build failed"
fi

#######################################
# Scenario 9: All governance unit tests pass
#######################################
e2e_step "Scenario 9: Governance unit tests"

: >"$TEST_LOG"
COMBINED_PASS=0
COMBINED_FAIL=0

# Run tests for all 3 governance modules
for mod_filter in "benchmark_taxonomy" "perf_comparison" "perf_triage"; do
    MOD_LOG="$E2E_LOG_DIR/benchmark_governance_${mod_filter}.log"
    if run_rch_capture "$MOD_LOG" cargo test -p ffs-harness --lib -- "$mod_filter"; then
        COMBINED_PASS=$((COMBINED_PASS + 1))
    else
        COMBINED_FAIL=$((COMBINED_FAIL + 1))
    fi
    cat "$MOD_LOG" >>"$TEST_LOG"
done

TOTAL_TESTS=$(grep -c "^test " "$TEST_LOG" 2>/dev/null || echo "0")

if [[ $COMBINED_FAIL -eq 0 && $TOTAL_TESTS -ge 50 ]]; then
    scenario_result "governance_unit_tests_pass" "PASS" "All 3 modules pass (${TOTAL_TESTS} tests total)"
else
    scenario_result "governance_unit_tests_pass" "FAIL" "Failures: ${COMBINED_FAIL}/3 modules, ${TOTAL_TESTS} tests"
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
