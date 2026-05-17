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
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_FUZZ_DASHBOARD_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_FUZZ_DASHBOARD_SKIP_SELF_CHECK:-0}"

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
    local log_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    shift

    e2e_log "RCH command: $*"
    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$log_path"
    set +e
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}|command=$*"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_FUZZ_DASHBOARD_FIXTURE_CASE:-complete}"

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
        echo "unknown fuzz dashboard fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- fuzz_dashboard"*)
        printf '%s\n' \
            "test fuzz_dashboard::tests::parse_campaign_summary_accepts_nightly_schema ... ok" \
            "test fuzz_dashboard::tests::parse_campaign_summary_rejects_malformed_json ... ok" \
            "test fuzz_dashboard::tests::validate_campaign_schema_reports_required_fields ... ok" \
            "test fuzz_dashboard::tests::validate_campaign_schema_rejects_string_false_positives ... ok" \
            "test fuzz_dashboard::tests::assess_campaign_health_reports_healthy_targets ... ok" \
            "test fuzz_dashboard::tests::assess_campaign_health_reports_stagnant_targets ... ok" \
            "test fuzz_dashboard::tests::assess_campaign_health_reports_crashes ... ok" \
            "test fuzz_dashboard::tests::assess_campaign_health_reports_errors ... ok" \
            "test fuzz_dashboard::tests::detect_regressions_flags_throughput_drops ... ok" \
            "test fuzz_dashboard::tests::detect_regressions_flags_coverage_drops ... ok" \
            "test fuzz_dashboard::tests::regression_alert_json_shape_is_stable ... ok" \
            "test fuzz_dashboard::tests::campaign_summary_json_shape_is_stable ... ok" \
            "test fuzz_dashboard::tests::nightly_summary_round_trips ... ok" \
            "test fuzz_dashboard::tests::schema_validation_is_deterministic ... ok"
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
    local child_log="$E2E_LOG_DIR/fuzz_dashboard_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_FUZZ_DASHBOARD_SELF_CHECK=0 \
        FFS_FUZZ_DASHBOARD_SKIP_SELF_CHECK=1 \
        FFS_FUZZ_DASHBOARD_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_fuzz_dashboard_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic fuzz dashboard wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir test_log
    stub_path="$E2E_LOG_DIR/rch-fuzz-dashboard-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    test_log="$result_dir/fuzz_dashboard_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$test_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "dashboard_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_campaign_schema" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_health_states" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_health_assessment" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_regression_detection" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_nightly_script" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_schema_validation" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_alert_severity" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "dashboard_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && [[ "$(grep -c "test fuzz_dashboard::tests::" "$test_log" 2>/dev/null || echo 0)" -ge 14 ]]; then
        scenario_result "dashboard_fixture_complete_self_check" "PASS" "result=${result_path} unit_log=${test_log}"
    else
        scenario_result "dashboard_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Fuzz dashboard complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "dashboard_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "dashboard_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Fuzz dashboard local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "dashboard_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "dashboard_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Fuzz dashboard missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_fuzz_dashboard"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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

TEST_LOG="${E2E_LOG_DIR}/fuzz_dashboard_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- fuzz_dashboard; then
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
