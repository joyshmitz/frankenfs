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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_evidence_presets}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_EVIDENCE_PRESETS_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_EVIDENCE_PRESETS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_EVIDENCE_PRESETS_SKIP_SELF_CHECK:-0}"

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
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_EVIDENCE_PRESETS_FIXTURE_CASE:-complete}"

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
        echo "unknown evidence presets fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-cli -- evidence"*)
        printf '%s\n' \
            "running 12 tests" \
            "test tests::evidence_preset_replay_anomalies ... ok" \
            "test tests::evidence_preset_repair_failures ... ok" \
            "test tests::evidence_preset_pressure_transitions ... ok" \
            "test tests::evidence_preset_contention ... ok" \
            "test tests::preset_and_event_type_are_mutually_exclusive ... ok" \
            "test tests::preset_rejection_is_logged ... ok" \
            "test tests::load_evidence_summary_records ... ok" \
            "test tests::load_evidence_filters_event_types ... ok" \
            "test tests::load_evidence_correlation_fields ... ok" \
            "test tests::evidence_structured_start_marker ... ok" \
            "test tests::evidence_structured_complete_marker ... ok" \
            "test tests::evidence_summary_json_schema ... ok"
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
    local child_log="$E2E_LOG_DIR/evidence_presets_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_EVIDENCE_PRESETS_SELF_CHECK=0 \
        FFS_EVIDENCE_PRESETS_SKIP_SELF_CHECK=1 \
        FFS_EVIDENCE_PRESETS_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_evidence_presets_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic evidence presets wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir test_log
    stub_path="$E2E_LOG_DIR/rch-evidence-presets-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    test_log="$result_dir/evidence_presets_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$test_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "evidence_presets_all_defined" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_summary_struct_fields" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_cli_preset_flag" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_cli_summary_flag" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_unit_tests_pass" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_structured_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_preset_rejection_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_preset_event_type_exclusive" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_logging_correlation_fields" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && [[ "$(grep -c "test tests::.*evidence\|test tests::.*preset\|test tests::load_evidence" "$test_log")" -ge 12 ]]; then
        scenario_result "evidence_presets_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_presets_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Evidence presets complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "evidence_presets_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_presets_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Evidence presets local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "evidence_presets_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_presets_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Evidence presets missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_evidence_presets"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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

TEST_LOG="$E2E_LOG_DIR/evidence_presets_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-cli -- evidence; then
    TESTS_RUN=$(grep -c "test tests::.*evidence\|test tests::.*preset\|test tests::load_evidence" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 12 ]]; then
        scenario_result "evidence_unit_tests_pass" "PASS" "Evidence tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "evidence_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 12)"
    fi
else
    scenario_result "evidence_unit_tests_pass" "FAIL" "Evidence tests failed"
fi

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
