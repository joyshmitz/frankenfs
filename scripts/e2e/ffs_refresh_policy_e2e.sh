#!/usr/bin/env bash
# ffs_refresh_policy_e2e.sh - E2E verification for OQ3 symbol freshness policy (bd-h6nz.6.3)
#
# Validates that:
# 1. RefreshPolicy enum has all 3 variants (Eager, Lazy, Adaptive)
# 2. RefreshMode enum has all 6 trigger modes
# 3. GroupRefreshState state machine fields exist
# 4. RefreshTelemetry and GroupRefreshSummary types exist
# 5. Staleness timeout logic is present
# 6. Structured logging markers for refresh events exist
# 7. Pipeline refresh tests pass
# 8. Evidence SymbolRefreshDetail alignment
# 9. Churn/staleness budget tests pass
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_refresh_policy_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_refresh_policy}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_REFRESH_POLICY_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REFRESH_POLICY_SKIP_SELF_CHECK:-0}"

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

fixture_case="${FFS_REFRESH_POLICY_FIXTURE_CASE:-complete}"

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
        echo "unknown refresh policy fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-repair --lib -- pipeline::tests"*)
        echo "running 45 tests"
        for i in $(seq -w 1 45); do
            echo "test pipeline::tests::refresh_policy_fixture_case_${i} ... ok"
        done
        ;;
    *"cargo test -p ffs-repair --lib -- churn_writes eager_policy lazy_policy staleness_timeout"*)
        printf '%s\n' \
            "running 4 tests" \
            "test pipeline::tests::churn_writes_refresh_budget ... ok" \
            "test pipeline::tests::eager_policy_refreshes_immediately ... ok" \
            "test pipeline::tests::lazy_policy_defers_refresh ... ok" \
            "test pipeline::tests::staleness_timeout_triggers_refresh ... ok"
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
    local child_log="$E2E_LOG_DIR/refresh_policy_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REFRESH_POLICY_SELF_CHECK=0 \
        FFS_REFRESH_POLICY_SKIP_SELF_CHECK=1 \
        FFS_REFRESH_POLICY_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_refresh_policy_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic refresh policy wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-refresh-policy-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_variants" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_modes" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_group_state" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_telemetry_types" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_staleness_timeout" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_structured_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_pipeline_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_evidence_alignment" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "refresh_policy_churn_policy_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "refresh_policy_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "refresh_policy_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "refresh_policy_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "refresh_policy_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "refresh_policy_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "refresh_policy_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_refresh_policy"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_print_env

PIPELINE_SRC="crates/ffs-repair/src/pipeline.rs"

#######################################
# Scenario 1: RefreshPolicy variants
#######################################
e2e_step "Scenario 1: RefreshPolicy variants"

VARIANTS_FOUND=0
for variant in "Eager" "Lazy" "Adaptive"; do
    if grep -q "^\s*${variant}" "$PIPELINE_SRC"; then
        VARIANTS_FOUND=$((VARIANTS_FOUND + 1))
    fi
done

if [[ $VARIANTS_FOUND -eq 3 ]]; then
    scenario_result "refresh_policy_variants" "PASS" "All 3 RefreshPolicy variants present"
else
    scenario_result "refresh_policy_variants" "FAIL" "Only ${VARIANTS_FOUND}/3 variants found"
fi

#######################################
# Scenario 2: RefreshMode trigger modes
#######################################
e2e_step "Scenario 2: RefreshMode trigger modes"

MODES_FOUND=0
for mode in "Recovery" "EagerWrite" "LazyScrub" "AdaptiveEagerWrite" "AdaptiveLazyScrub" "StalenessTimeout"; do
    if grep -q "${mode}" "$PIPELINE_SRC"; then
        MODES_FOUND=$((MODES_FOUND + 1))
    fi
done

if [[ $MODES_FOUND -eq 6 ]]; then
    scenario_result "refresh_policy_modes" "PASS" "All 6 RefreshMode trigger modes present"
else
    scenario_result "refresh_policy_modes" "FAIL" "Only ${MODES_FOUND}/6 modes found"
fi

#######################################
# Scenario 3: GroupRefreshState fields
#######################################
e2e_step "Scenario 3: GroupRefreshState state machine"

STATE_FIELDS=0
for field in "dirty: bool" "dirty_since: Option<Instant>" "policy: RefreshPolicy" "last_refresh: Instant"; do
    if grep -q "$field" "$PIPELINE_SRC"; then
        STATE_FIELDS=$((STATE_FIELDS + 1))
    fi
done

if [[ $STATE_FIELDS -eq 4 ]]; then
    scenario_result "refresh_policy_group_state" "PASS" "All 4 state machine fields present"
else
    scenario_result "refresh_policy_group_state" "FAIL" "Only ${STATE_FIELDS}/4 state fields found"
fi

#######################################
# Scenario 4: Telemetry types exist
#######################################
e2e_step "Scenario 4: Telemetry types"

TELEMETRY_FOUND=0
for pattern in "pub struct RefreshTelemetry" "pub struct GroupRefreshSummary" "pub fn refresh_telemetry"; do
    if grep -q "$pattern" "$PIPELINE_SRC"; then
        TELEMETRY_FOUND=$((TELEMETRY_FOUND + 1))
    fi
done

if [[ $TELEMETRY_FOUND -eq 3 ]]; then
    scenario_result "refresh_policy_telemetry_types" "PASS" "RefreshTelemetry, GroupRefreshSummary, and accessor present"
else
    scenario_result "refresh_policy_telemetry_types" "FAIL" "Only ${TELEMETRY_FOUND}/3 telemetry components found"
fi

#######################################
# Scenario 5: Staleness timeout logic
#######################################
e2e_step "Scenario 5: Staleness timeout logic"

TIMEOUT_FOUND=0
for pattern in "dirty_age >= max_staleness" "StalenessTimeout" "refresh_staleness_timeout_triggered"; do
    if grep -q "$pattern" "$PIPELINE_SRC"; then
        TIMEOUT_FOUND=$((TIMEOUT_FOUND + 1))
    fi
done

if [[ $TIMEOUT_FOUND -ge 3 ]]; then
    scenario_result "refresh_policy_staleness_timeout" "PASS" "Staleness timeout detection logic present"
else
    scenario_result "refresh_policy_staleness_timeout" "FAIL" "Only ${TIMEOUT_FOUND}/3 timeout patterns found"
fi

#######################################
# Scenario 6: Structured logging markers
#######################################
e2e_step "Scenario 6: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "refresh_policy_evaluated" "refresh_staleness_timeout_triggered" "refresh_group_marked_dirty" "adaptive_refresh_policy_resolved" "symbol_refresh_queued" "symbol_refresh_complete" "symbol_refresh_deferred"; do
    if grep -q "\"${marker}\"" "$PIPELINE_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 6 ]]; then
    scenario_result "refresh_policy_structured_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/7 markers present"
else
    scenario_result "refresh_policy_structured_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/7 structured log markers found"
fi

#######################################
# Scenario 7: Pipeline unit tests pass
#######################################
e2e_step "Scenario 7: Pipeline refresh tests"

TEST_LOG="$E2E_LOG_DIR/pipeline_refresh_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair --lib -- pipeline::tests; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 45 ]]; then
        scenario_result "refresh_policy_pipeline_tests" "PASS" "Pipeline tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "refresh_policy_pipeline_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 45)"
    fi
else
    scenario_result "refresh_policy_pipeline_tests" "FAIL" "Pipeline tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 8: Evidence SymbolRefreshDetail alignment
#######################################
e2e_step "Scenario 8: Evidence SymbolRefreshDetail alignment"

EVIDENCE_SRC="crates/ffs-repair/src/evidence.rs"
ALIGNED=0
for field in "previous_generation" "new_generation" "symbols_generated"; do
    if grep -q "$field" "$EVIDENCE_SRC"; then
        ALIGNED=$((ALIGNED + 1))
    fi
done

if [[ $ALIGNED -eq 3 ]]; then
    scenario_result "refresh_policy_evidence_alignment" "PASS" "All 3 SymbolRefreshDetail fields present"
else
    scenario_result "refresh_policy_evidence_alignment" "FAIL" "Only ${ALIGNED}/3 fields found"
fi

#######################################
# Scenario 9: Churn and policy tests pass
#######################################
e2e_step "Scenario 9: Churn and policy-specific tests"

TEST_LOG="$E2E_LOG_DIR/churn_policy_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair --lib -- churn_writes eager_policy lazy_policy staleness_timeout; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "refresh_policy_churn_policy_tests" "PASS" "Churn/policy tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "refresh_policy_churn_policy_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "refresh_policy_churn_policy_tests" "FAIL" "Churn/policy tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
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
