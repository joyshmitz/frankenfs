#!/usr/bin/env bash
# ffs_btrfs_write_churn_e2e.sh - E2E verification for btrfs scrub/repair under write churn (bd-h6nz.3.4)
#
# Validates that:
# 1. Write-churn stress tests exist and cover corruption detection
# 2. No-false-clean invariant test exists
# 3. Recovery with fresh symbols under churn works
# 4. Evidence ledger captures churn context
# 5. Staleness timeout recovery path tested
# 6. Structured logging markers for scrub/repair events present
# 7. All pipeline tests pass
# 8. Btrfs validators still pass
# 9. Btrfs repair CLI tests still pass
#
# Usage: ./scripts/e2e/ffs_btrfs_write_churn_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_btrfs_write_churn}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_WRITE_CHURN_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_BTRFS_WRITE_CHURN_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_BTRFS_WRITE_CHURN_SKIP_SELF_CHECK:-0}"

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
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
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

fixture_case="${FFS_BTRFS_WRITE_CHURN_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected btrfs write-churn fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown btrfs write-churn fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"scrub_detects_corruption_after_write_churn"*)
        for name in \
            scrub_detects_corruption_after_write_churn \
            no_false_clean_when_corruption_exists_under_heavy_churn \
            recovery_succeeds_with_fresh_symbols_under_write_churn \
            evidence_ledger_captures_churn_context \
            write_churn_with_staleness_timeout_still_recovers; do
            echo "test pipeline::tests::${name} ... ok"
        done
        ;;
    *"btrfs_repair"*)
        echo "test btrfs_repair_fixture_accepts_report ... ok"
        ;;
    *" -- btrfs"*)
        for name in \
            btrfs_extent_checksum_detects_corruption \
            btrfs_scrub_reports_bad_mirror \
            btrfs_repair_rewrites_missing_block \
            btrfs_validator_tracks_generation; do
            echo "test scrub::tests::${name} ... ok"
        done
        ;;
    *"pipeline::tests"*)
        for i in $(seq 1 50); do
            echo "test pipeline::tests::fixture_pipeline_case_${i} ... ok"
        done
        ;;
    *)
        echo "unexpected btrfs write-churn fixture command: $command_text" >&2
        exit 64
        ;;
esac

echo "test result: ok. fixture passed"
if [[ "$fixture_case" == "complete" ]]; then
    echo "Remote command finished: exit=0"
fi
exit 0
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
    local child_log="$E2E_LOG_DIR/btrfs_write_churn_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_BTRFS_WRITE_CHURN_SELF_CHECK=0 \
        FFS_BTRFS_WRITE_CHURN_SKIP_SELF_CHECK=1 \
        FFS_BTRFS_WRITE_CHURN_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_btrfs_write_churn_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic btrfs write-churn wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-btrfs-write-churn-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "churn_tests_exist" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "churn_tests_pass" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_churn_validators" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_churn_pipeline_suite" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_cli_repair" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_churn_telemetry" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "btrfs_write_churn_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "btrfs_write_churn_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "btrfs_write_churn_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "btrfs_write_churn_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "btrfs_write_churn_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "btrfs_write_churn_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_btrfs_write_churn"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_print_env

PIPELINE_SRC="crates/ffs-repair/src/pipeline.rs"

#######################################
# Scenario 1: Write-churn stress tests exist
#######################################
e2e_step "Scenario 1: Write-churn stress tests present"

TESTS_FOUND=0
for test_name in "scrub_detects_corruption_after_write_churn" "no_false_clean_when_corruption_exists_under_heavy_churn" "recovery_succeeds_with_fresh_symbols_under_write_churn" "evidence_ledger_captures_churn_context" "write_churn_with_staleness_timeout_still_recovers"; do
    if grep -q "fn ${test_name}" "$PIPELINE_SRC"; then
        TESTS_FOUND=$((TESTS_FOUND + 1))
    fi
done

if [[ $TESTS_FOUND -eq 5 ]]; then
    scenario_result "churn_tests_exist" "PASS" "All 5 write-churn stress tests present"
else
    scenario_result "churn_tests_exist" "FAIL" "Only ${TESTS_FOUND}/5 write-churn tests found"
fi

#######################################
# Scenario 2: No-false-clean invariant
#######################################
e2e_step "Scenario 2: No-false-clean invariant test"

if grep -q 'scrub must NEVER report 0 corruption' "$PIPELINE_SRC"; then
    scenario_result "no_false_clean_invariant" "PASS" "No-false-clean invariant test documented"
else
    scenario_result "no_false_clean_invariant" "FAIL" "Missing no-false-clean invariant documentation"
fi

#######################################
# Scenario 3: Evidence churn context
#######################################
e2e_step "Scenario 3: Evidence ledger churn context"

if grep -q 'evidence must record corruption detection' "$PIPELINE_SRC" && grep -q 'evidence must record repair attempt' "$PIPELINE_SRC"; then
    scenario_result "evidence_churn_context" "PASS" "Evidence churn context assertions present"
else
    scenario_result "evidence_churn_context" "FAIL" "Missing evidence churn context assertions"
fi

#######################################
# Scenario 4: Structured logging markers
#######################################
e2e_step "Scenario 4: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "scrub_and_recover" "scrub complete" "refresh_staleness_timeout_triggered" "refresh_group_marked_dirty" "symbol_refresh_complete"; do
    if grep -q "$marker" "$PIPELINE_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 4 ]]; then
    scenario_result "btrfs_churn_logging_markers" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/5 markers present"
else
    scenario_result "btrfs_churn_logging_markers" "FAIL" "Only ${LOG_MARKERS_FOUND}/5 markers found"
fi

#######################################
# Scenario 5: Write-churn tests pass
#######################################
e2e_step "Scenario 5: Write-churn tests pass"

TEST_LOG="$E2E_LOG_DIR/write_churn_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair --lib -- scrub_detects_corruption_after_write_churn no_false_clean recovery_succeeds_with_fresh evidence_ledger_captures_churn write_churn_with_staleness; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 5 ]]; then
        scenario_result "churn_tests_pass" "PASS" "Write-churn tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "churn_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 5)"
    fi
else
    scenario_result "churn_tests_pass" "FAIL" "Write-churn tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 6: Btrfs validator tests pass
#######################################
e2e_step "Scenario 6: Btrfs validator tests"

TEST_LOG="$E2E_LOG_DIR/btrfs_validator_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair --lib -- btrfs; then
    TESTS_RUN=$(grep -c "test scrub::tests::btrfs" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "btrfs_churn_validators" "PASS" "Btrfs validator tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "btrfs_churn_validators" "FAIL" "Too few btrfs tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "btrfs_churn_validators" "FAIL" "Btrfs validator tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 7: Full pipeline test suite
#######################################
e2e_step "Scenario 7: Full pipeline test suite"

TEST_LOG="$E2E_LOG_DIR/pipeline_suite_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair --lib -- pipeline::tests; then
    TESTS_RUN=$(grep -c "test pipeline::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 50 ]]; then
        scenario_result "btrfs_churn_pipeline_suite" "PASS" "Full pipeline suite passed (${TESTS_RUN} tests)"
    else
        scenario_result "btrfs_churn_pipeline_suite" "FAIL" "Too few pipeline tests: ${TESTS_RUN} (expected >= 50)"
    fi
else
    scenario_result "btrfs_churn_pipeline_suite" "FAIL" "Pipeline suite failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 8: Btrfs CLI repair tests pass
#######################################
e2e_step "Scenario 8: Btrfs CLI repair tests"

TEST_LOG="$E2E_LOG_DIR/btrfs_cli_repair_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-cli -- btrfs_repair; then
    scenario_result "btrfs_cli_repair" "PASS" "Btrfs CLI repair tests passed"
else
    scenario_result "btrfs_cli_repair" "FAIL" "Btrfs CLI repair tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 9: RefreshTelemetry supports churn observability
#######################################
e2e_step "Scenario 9: Refresh telemetry for churn observability"

TELEMETRY_FIELDS=0
for field in "dirty_groups" "max_dirty_age_ms" "tracked_groups" "dirty_age_ms" "since_last_refresh_ms"; do
    if grep -q "pub ${field}" "$PIPELINE_SRC"; then
        TELEMETRY_FIELDS=$((TELEMETRY_FIELDS + 1))
    fi
done

if [[ $TELEMETRY_FIELDS -ge 5 ]]; then
    scenario_result "btrfs_churn_telemetry" "PASS" "All ${TELEMETRY_FIELDS}/5 telemetry fields present"
else
    scenario_result "btrfs_churn_telemetry" "FAIL" "Only ${TELEMETRY_FIELDS}/5 telemetry fields found"
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
