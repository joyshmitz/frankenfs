#!/usr/bin/env bash
# ffs_mvcc_lifecycle_e2e.sh - E2E verification for durable MVCC OpenFs integration (bd-h6nz.1.4)
#
# Validates that:
# 1. OpenOptions has mvcc_wal_path and mvcc_replay_policy fields
# 2. OpenFs has mvcc_wal_recovery field and accessor
# 3. Integration tests pass (clean replay, truncated tail, FailFast fallback)
# 4. Structured logging events are emitted
# 5. init_mvcc_store helper exists
#
# Usage: ./scripts/e2e/ffs_mvcc_lifecycle_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_mvcc_lifecycle}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_MVCC_LIFECYCLE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_MVCC_LIFECYCLE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_MVCC_LIFECYCLE_SKIP_SELF_CHECK:-0}"

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

fixture_case="${FFS_MVCC_LIFECYCLE_FIXTURE_CASE:-complete}"

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
        echo "unknown MVCC lifecycle fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-core --lib -- mvcc_wal"*)
        printf '%s\n' \
            "test tests::mvcc_wal_clean_replay_records_recovery ... ok" \
            "test tests::mvcc_wal_truncated_tail_tolerant_policy_records_warning ... ok" \
            "test tests::mvcc_wal_fail_fast_policy_returns_error ... ok" \
            "test tests::mvcc_wal_missing_file_is_empty_recovery ... ok" \
            "test tests::mvcc_wal_bad_header_falls_back_read_only ... ok"
        ;;
    *"cargo test -p ffs-mvcc --lib -- wal_replay::tests"*)
        printf '%s\n' \
            "test wal_replay::tests::replay_empty_wal ... ok" \
            "test wal_replay::tests::replay_truncated_tail_reports_warning ... ok" \
            "test wal_replay::tests::replay_bad_header_reports_error ... ok"
        ;;
    *"cargo test -p ffs-mvcc --lib -- persist::tests"*)
        printf '%s\n' \
            "test persist::tests::append_and_read_commit_record ... ok" \
            "test persist::tests::rejects_bad_commit_crc ... ok" \
            "test persist::tests::apply_wal_commit_updates_store ... ok"
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
    local child_log="$E2E_LOG_DIR/mvcc_lifecycle_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_MVCC_LIFECYCLE_SELF_CHECK=0 \
        FFS_MVCC_LIFECYCLE_SKIP_SELF_CHECK=1 \
        FFS_MVCC_LIFECYCLE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_mvcc_lifecycle_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic MVCC lifecycle wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir mvcc_log replay_log persist_log
    stub_path="$E2E_LOG_DIR/rch-mvcc-lifecycle-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    mvcc_log="$result_dir/mvcc_wal_integration_tests.log"
    replay_log="$result_dir/wal_replay_unit_tests.log"
    persist_log="$result_dir/persist_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$mvcc_log" ]] \
        && [[ -f "$replay_log" ]] \
        && [[ -f "$persist_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "open_options_wal_fields" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "openfs_wal_recovery" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "init_mvcc_store" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "mvcc_wal_integration" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "replay_engine_unit" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "mvcc_lifecycle_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "mvcc_lifecycle_persist_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && [[ "$(grep -c "test tests::mvcc_wal" "$mvcc_log" 2>/dev/null || echo 0)" -ge 4 ]] \
        && grep -q "replay_truncated_tail_reports_warning" "$replay_log" \
        && grep -q "apply_wal_commit_updates_store" "$persist_log"; then
        scenario_result "mvcc_lifecycle_fixture_complete_self_check" "PASS" "result=${result_path} mvcc_log=${mvcc_log}"
    else
        scenario_result "mvcc_lifecycle_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "MVCC lifecycle complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "mvcc_lifecycle_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "mvcc_lifecycle_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "MVCC lifecycle local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "mvcc_lifecycle_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "mvcc_lifecycle_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "MVCC lifecycle missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_mvcc_lifecycle"
e2e_print_env

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

#######################################
# Scenario 1: OpenOptions has WAL fields
#######################################
e2e_step "Scenario 1: OpenOptions WAL fields"

FIELDS_FOUND=0
for field in "pub mvcc_wal_path" "pub mvcc_replay_policy"; do
    if grep -q "$field" crates/ffs-core/src/lib.rs; then
        FIELDS_FOUND=$((FIELDS_FOUND + 1))
    fi
done

if [[ $FIELDS_FOUND -eq 2 ]]; then
    scenario_result "open_options_wal_fields" "PASS" "Both WAL fields present in OpenOptions"
else
    scenario_result "open_options_wal_fields" "FAIL" "Only ${FIELDS_FOUND}/2 WAL fields found"
fi

#######################################
# Scenario 2: OpenFs has mvcc_wal_recovery
#######################################
e2e_step "Scenario 2: OpenFs mvcc_wal_recovery field"

if grep -q "pub mvcc_wal_recovery" crates/ffs-core/src/lib.rs; then
    scenario_result "openfs_wal_recovery" "PASS" "mvcc_wal_recovery field present"
else
    scenario_result "openfs_wal_recovery" "FAIL" "mvcc_wal_recovery field missing"
fi

#######################################
# Scenario 3: init_mvcc_store helper
#######################################
e2e_step "Scenario 3: init_mvcc_store helper"

if grep -q "fn init_mvcc_store" crates/ffs-core/src/lib.rs; then
    scenario_result "init_mvcc_store" "PASS" "init_mvcc_store helper present"
else
    scenario_result "init_mvcc_store" "FAIL" "init_mvcc_store helper missing"
fi

#######################################
# Scenario 4: Integration tests pass
#######################################
e2e_step "Scenario 4: MVCC WAL integration tests"

TEST_LOG="$E2E_LOG_DIR/mvcc_wal_integration_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-core --lib -- mvcc_wal; then
    TESTS_RUN=$(grep -c "test tests::mvcc_wal" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "mvcc_wal_integration" "PASS" "Integration tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "mvcc_wal_integration" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "mvcc_wal_integration" "FAIL" "Integration tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 5: Replay engine tests still pass
#######################################
e2e_step "Scenario 5: Replay engine unit tests"

TEST_LOG="$E2E_LOG_DIR/wal_replay_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- wal_replay::tests; then
    scenario_result "replay_engine_unit" "PASS" "Replay engine unit tests passed"
else
    scenario_result "replay_engine_unit" "FAIL" "Replay engine unit tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 6: Structured logging markers
#######################################
e2e_step "Scenario 6: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "mvcc_store_init" "mvcc_wal_not_found" "mvcc_wal_empty" "mvcc_wal_replay_begin" "mvcc_wal_replay_done" "mvcc_wal_replay_failed_fallback" "mvcc_wal_bad_header" "mvcc_wal_too_small"; do
    if grep -q "\"${marker}\"" crates/ffs-core/src/lib.rs; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 6 ]]; then
    scenario_result "mvcc_lifecycle_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/8 markers present"
else
    scenario_result "mvcc_lifecycle_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/8 structured log markers found"
fi

#######################################
# Scenario 7: Persist tests still pass
#######################################
e2e_step "Scenario 7: Persist tests"

TEST_LOG="$E2E_LOG_DIR/persist_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc --lib -- persist::tests; then
    scenario_result "mvcc_lifecycle_persist_tests" "PASS" "Persist tests passed"
else
    scenario_result "mvcc_lifecycle_persist_tests" "FAIL" "Persist tests failed"
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
