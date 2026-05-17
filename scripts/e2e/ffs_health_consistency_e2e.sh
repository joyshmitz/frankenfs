#!/usr/bin/env bash
# ffs_health_consistency_e2e.sh - Verification gate for cross-surface health consistency (bd-h6nz.7.3)
#
# Validates that runtime health state is reported consistently across CLI, TUI,
# and structured log surfaces.
#
# Scenarios:
# 1. Health consistency module exists in ffs-harness
# 2. All 5 canonical health dimensions defined
# 3. Degradation level has 5 variants in ffs-core
# 4. TUI handles all degradation levels
# 5. Pressure counters exist in ffs-fuse
# 6. Runtime mode variants present in CLI
# 7. WAL replay markers present in ffs-mvcc
# 8. Source-of-truth documentation covers all dimensions
# 9. Health consistency unit tests pass
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_health_consistency_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_health_consistency}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-360}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_HEALTH_CONSISTENCY_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_HEALTH_CONSISTENCY_SKIP_SELF_CHECK:-0}"

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

fixture_case="${FFS_HEALTH_CONSISTENCY_FIXTURE_CASE:-complete}"

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
        echo "unknown health consistency fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- health_consistency"*)
        printf '%s\n' \
            "running 10 tests" \
            "test health_consistency::tests::canonical_dimensions_are_defined ... ok" \
            "test health_consistency::tests::degradation_variants_are_complete ... ok" \
            "test health_consistency::tests::tui_degradation_mapping_is_complete ... ok" \
            "test health_consistency::tests::pressure_counters_are_exposed ... ok" \
            "test health_consistency::tests::runtime_modes_match_cli_surface ... ok" \
            "test health_consistency::tests::wal_replay_markers_are_present ... ok" \
            "test health_consistency::tests::source_of_truth_docs_cover_dimensions ... ok" \
            "test health_consistency::tests::health_report_serializes ... ok" \
            "test health_consistency::tests::health_surface_names_are_stable ... ok" \
            "test health_consistency::tests::health_summary_rejects_missing_dimensions ... ok"
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
    local child_log="$E2E_LOG_DIR/health_consistency_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_HEALTH_CONSISTENCY_SELF_CHECK=0 \
        FFS_HEALTH_CONSISTENCY_SKIP_SELF_CHECK=1 \
        FFS_HEALTH_CONSISTENCY_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_health_consistency_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic health consistency wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-health-consistency-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "health_consistency_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_canonical_dimensions_defined" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_degradation_five_variants" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_tui_degradation_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_pressure_counters_in_fuse" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_runtime_modes_in_cli" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_wal_replay_markers" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_source_of_truth_documented" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "health_consistency_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "health_consistency_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "health_consistency_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "health_consistency_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "health_consistency_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "health_consistency_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "health_consistency_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_health_consistency"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

HC_SRC="crates/ffs-harness/src/health_consistency.rs"

#######################################
# Scenario 1: Module exists
#######################################
e2e_step "Scenario 1: Health consistency module exists"

if [[ -f "$HC_SRC" ]] && grep -q "pub mod health_consistency" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "health_consistency_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "health_consistency_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All 5 dimensions defined
#######################################
e2e_step "Scenario 2: All 5 canonical health dimensions"

DIMS_FOUND=0
for dim in "DEGRADATION_LEVEL" "RUNTIME_MODE" "REPLAY_STATUS" "REPAIR_STALENESS" "PRESSURE_COUNTERS"; do
    if grep -q "pub const ${dim}" "$HC_SRC"; then
        DIMS_FOUND=$((DIMS_FOUND + 1))
    fi
done

if [[ $DIMS_FOUND -eq 5 ]]; then
    scenario_result "health_canonical_dimensions_defined" "PASS" "All 5 dimensions defined"
else
    scenario_result "health_canonical_dimensions_defined" "FAIL" "Only ${DIMS_FOUND}/5 dimensions"
fi

#######################################
# Scenario 3: Degradation 5 variants in core
#######################################
e2e_step "Scenario 3: Degradation level variants in ffs-core"

DEG_VARIANTS=0
for variant in "Normal" "Warning" "Degraded" "Critical" "Emergency"; do
    if grep -q "$variant" "crates/ffs-core/src/degradation.rs"; then
        DEG_VARIANTS=$((DEG_VARIANTS + 1))
    fi
done

if [[ $DEG_VARIANTS -eq 5 ]]; then
    scenario_result "health_degradation_five_variants" "PASS" "All 5 degradation levels in core"
else
    scenario_result "health_degradation_five_variants" "FAIL" "Only ${DEG_VARIANTS}/5 variants"
fi

#######################################
# Scenario 4: TUI handles all degradation levels
#######################################
e2e_step "Scenario 4: TUI handles all degradation levels"

TUI_LEVELS=0
for variant in "Normal" "Warning" "Degraded" "Critical" "Emergency"; do
    if grep -q "DegradationLevel::${variant}" "crates/ffs-tui/src/lib.rs"; then
        TUI_LEVELS=$((TUI_LEVELS + 1))
    fi
done

if [[ $TUI_LEVELS -eq 5 ]]; then
    scenario_result "health_tui_degradation_coverage" "PASS" "TUI handles all 5 levels"
else
    scenario_result "health_tui_degradation_coverage" "FAIL" "Only ${TUI_LEVELS}/5 levels in TUI"
fi

#######################################
# Scenario 5: Pressure counters in ffs-fuse
#######################################
e2e_step "Scenario 5: Pressure counters in ffs-fuse"

COUNTERS=0
for counter in "requests_throttled" "requests_shed"; do
    if grep -q "$counter" "crates/ffs-fuse/src/lib.rs"; then
        COUNTERS=$((COUNTERS + 1))
    fi
done

if [[ $COUNTERS -eq 2 ]]; then
    scenario_result "health_pressure_counters_in_fuse" "PASS" "Both pressure counters present"
else
    scenario_result "health_pressure_counters_in_fuse" "FAIL" "Only ${COUNTERS}/2 counters"
fi

#######################################
# Scenario 6: Runtime mode variants in CLI
#######################################
e2e_step "Scenario 6: Runtime mode variants in CLI"

MODES=0
for mode in "Standard" "Managed" "PerCore"; do
    if grep -q "$mode" "crates/ffs-cli/src/main.rs"; then
        MODES=$((MODES + 1))
    fi
done

if [[ $MODES -eq 3 ]]; then
    scenario_result "health_runtime_modes_in_cli" "PASS" "All 3 runtime modes in CLI"
else
    scenario_result "health_runtime_modes_in_cli" "FAIL" "Only ${MODES}/3 modes"
fi

#######################################
# Scenario 7: WAL replay markers in ffs-mvcc
#######################################
e2e_step "Scenario 7: WAL replay markers in ffs-mvcc"

MARKERS=0
for marker in "wal_replay_start" "wal_replay_done"; do
    if grep -q "$marker" "crates/ffs-mvcc/src/wal_replay.rs"; then
        MARKERS=$((MARKERS + 1))
    fi
done

if [[ $MARKERS -eq 2 ]]; then
    scenario_result "health_wal_replay_markers" "PASS" "Both WAL replay markers present"
else
    scenario_result "health_wal_replay_markers" "FAIL" "Only ${MARKERS}/2 markers"
fi

#######################################
# Scenario 8: Source-of-truth documentation
#######################################
e2e_step "Scenario 8: Source-of-truth documentation"

SOT_DIMS=0
for phrase in "Degradation level" "Runtime mode" "WAL replay status" "Repair staleness" "Pressure counters"; do
    if grep -q "$phrase" "$HC_SRC"; then
        SOT_DIMS=$((SOT_DIMS + 1))
    fi
done

if [[ $SOT_DIMS -eq 5 ]]; then
    scenario_result "health_source_of_truth_documented" "PASS" "All 5 dimensions documented"
else
    scenario_result "health_source_of_truth_documented" "FAIL" "Only ${SOT_DIMS}/5 documented"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Health consistency unit tests"

TEST_LOG="$E2E_LOG_DIR/health_consistency_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- health_consistency; then
    TESTS_RUN=$(grep -c "test health_consistency::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 8 ]]; then
        scenario_result "health_consistency_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "health_consistency_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 8)"
    fi
else
    scenario_result "health_consistency_unit_tests_pass" "FAIL" "Health consistency tests failed"
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
