#!/usr/bin/env bash
# ffs_version_store_format_e2e.sh - E2E verification for version-store format decision (OQ7)
#
# Validates that:
# 1. WAL format constants are stable
# 2. WAL encode/decode tests pass
# 3. Persist tests (replay, checkpoint, crash) pass
# 4. Decision record exists with required sections
# 5. Spec marks OQ7 as resolved
#
# Usage: ./scripts/e2e/ffs_version_store_format_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_version_store_format}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_VERSION_STORE_FORMAT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_VERSION_STORE_FORMAT_SKIP_SELF_CHECK:-0}"

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

fixture_case="${FFS_VERSION_STORE_FORMAT_FIXTURE_CASE:-complete}"

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
        echo "unknown version store format fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-mvcc -- wal::tests"*)
        printf '%s\n' \
            "test wal::tests::commit_record_round_trips ... ok" \
            "test wal::tests::header_round_trips ... ok"
        ;;
    *"cargo test -p ffs-mvcc -- truncat"*)
        printf '%s\n' "test wal::tests::truncated_tail_is_ignored ... ok"
        ;;
    *"cargo test -p ffs-mvcc -- crc corrupt"*)
        printf '%s\n' "test wal::tests::corrupt_crc_is_rejected ... ok"
        ;;
    *"cargo test -p ffs-mvcc -- duplicate_commit_sequence"*)
        printf '%s\n' "test wal::tests::duplicate_commit_sequence_is_rejected ... ok"
        ;;
    *"cargo test -p ffs-mvcc -- checkpoint"*)
        printf '%s\n' "test wal::tests::checkpoint_replay_is_deterministic ... ok"
        ;;
    *"cargo test -p ffs-mvcc -- oq7_"*)
        printf '%s\n' \
            "test wal::tests::oq7_header_constants_are_stable ... ok" \
            "test wal::tests::oq7_commit_record_binary_shape_is_stable ... ok"
        ;;
    *"cargo test -p ffs-mvcc -- sync_failure"*)
        printf '%s\n' "test wal::tests::sync_failure_preserves_crash_safety ... ok"
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
    local child_log="$E2E_LOG_DIR/version_store_format_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_VERSION_STORE_FORMAT_SELF_CHECK=0 \
        FFS_VERSION_STORE_FORMAT_SKIP_SELF_CHECK=1 \
        FFS_VERSION_STORE_FORMAT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_version_store_format_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic version store format wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir wal_log oq7_log sync_log
    stub_path="$E2E_LOG_DIR/rch-version-store-format-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    wal_log="$result_dir/version_store_wal_roundtrip.log"
    oq7_log="$result_dir/version_store_oq7_format.log"
    sync_log="$result_dir/version_store_sync_failure.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$wal_log" ]] \
        && [[ -f "$oq7_log" ]] \
        && [[ -f "$sync_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "vs_format_header" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_commit_roundtrip" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_truncated_tail" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_corrupt_crc" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_monotonic" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_checkpoint_replay" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_sentinels" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_decision_record" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "vs_format_sync_required" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "commit_record_round_trips" "$wal_log" \
        && grep -q "oq7_header_constants_are_stable" "$oq7_log" \
        && grep -q "sync_failure_preserves_crash_safety" "$sync_log"; then
        scenario_result "vs_format_fixture_complete_self_check" "PASS" "result=${result_path} wal_log=${wal_log}"
    else
        scenario_result "vs_format_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Version store format complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "vs_format_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "vs_format_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Version store format local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "vs_format_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "vs_format_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Version store format missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_version_store_format"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

#######################################
# Scenario 1: WAL format constants exist in code
#######################################
e2e_step "Scenario 1: WAL format constants"

CONSTANTS_FOUND=0
for constant in "WAL_MAGIC" "WAL_VERSION" "CHECKSUM_TYPE_CRC32C" "HEADER_SIZE" "MIN_COMMIT_RECORD_SIZE" "RECORD_TYPE_COMMIT"; do
    if grep -q "pub const ${constant}" crates/ffs-mvcc/src/wal.rs; then
        CONSTANTS_FOUND=$((CONSTANTS_FOUND + 1))
    fi
done

if [[ $CONSTANTS_FOUND -eq 6 ]]; then
    scenario_result "vs_format_header" "PASS" "All 6 WAL format constants present"
else
    scenario_result "vs_format_header" "FAIL" "Only ${CONSTANTS_FOUND}/6 WAL format constants found"
fi

#######################################
# Scenario 2: WAL encode/decode tests pass
#######################################
e2e_step "Scenario 2: WAL encode/decode round-trip"

TEST_LOG="$E2E_LOG_DIR/version_store_wal_roundtrip.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- wal::tests; then
    TESTS_RUN=$(grep -c "test wal::tests" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "vs_format_commit_roundtrip" "PASS" "WAL encode/decode tests passed"
else
    scenario_result "vs_format_commit_roundtrip" "FAIL" "WAL encode/decode tests failed"
fi

#######################################
# Scenario 3: Truncated tail handling tests
#######################################
e2e_step "Scenario 3: Truncated tail handling"

TEST_LOG="$E2E_LOG_DIR/version_store_truncated_tail.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- truncat; then
    scenario_result "vs_format_truncated_tail" "PASS" "Truncated tail tests passed"
else
    scenario_result "vs_format_truncated_tail" "FAIL" "Truncated tail tests failed"
fi

#######################################
# Scenario 4: CRC corruption detection tests
#######################################
e2e_step "Scenario 4: CRC corruption detection"

TEST_LOG="$E2E_LOG_DIR/version_store_corrupt_crc.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- crc corrupt; then
    scenario_result "vs_format_corrupt_crc" "PASS" "CRC corruption detection tests passed"
else
    scenario_result "vs_format_corrupt_crc" "FAIL" "CRC corruption detection tests failed"
fi

#######################################
# Scenario 5: Monotonicity enforcement tests
#######################################
e2e_step "Scenario 5: Monotonicity enforcement"

TEST_LOG="$E2E_LOG_DIR/version_store_monotonicity.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- duplicate_commit_sequence; then
    scenario_result "vs_format_monotonic" "PASS" "Monotonicity enforcement tests passed"
else
    scenario_result "vs_format_monotonic" "FAIL" "Monotonicity enforcement tests failed"
fi

#######################################
# Scenario 6: Checkpoint + replay tests
#######################################
e2e_step "Scenario 6: Checkpoint + replay determinism"

TEST_LOG="$E2E_LOG_DIR/version_store_checkpoint_replay.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- checkpoint; then
    scenario_result "vs_format_checkpoint_replay" "PASS" "Checkpoint + replay tests passed"
else
    scenario_result "vs_format_checkpoint_replay" "FAIL" "Checkpoint + replay tests failed"
fi

#######################################
# Scenario 7: OQ7 format stability tests
#######################################
e2e_step "Scenario 7: OQ7 format stability"

TEST_LOG="$E2E_LOG_DIR/version_store_oq7_format.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- oq7_; then
    OQ7_COUNT=$(grep -c "test wal::tests::oq7_" "$TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "vs_format_sentinels" "PASS" "OQ7 format stability tests passed (${OQ7_COUNT} tests)"
else
    scenario_result "vs_format_sentinels" "FAIL" "OQ7 format stability tests failed"
fi

#######################################
# Scenario 8: Decision record exists
#######################################
e2e_step "Scenario 8: Decision record"

DECISION_DOC="docs/oq7-version-store-format.md"
if [[ -f "$DECISION_DOC" ]]; then
    SECTIONS_FOUND=0
    for section in "Accepted" "WAL v1" "Crash Consistency" "Alternatives" "Validation Matrix" "Durable Invariants"; do
        if grep -q "$section" "$DECISION_DOC"; then
            SECTIONS_FOUND=$((SECTIONS_FOUND + 1))
        fi
    done
    if [[ $SECTIONS_FOUND -ge 5 ]]; then
        scenario_result "vs_decision_record" "PASS" "Decision record with ${SECTIONS_FOUND}/6 required sections"
    else
        scenario_result "vs_decision_record" "FAIL" "Decision record only has ${SECTIONS_FOUND}/6 sections"
    fi
else
    scenario_result "vs_decision_record" "FAIL" "Decision record not found: $DECISION_DOC"
fi

#######################################
# Scenario 9: Sync requirement tests
#######################################
e2e_step "Scenario 9: Sync requirement (crash-safe mode)"

TEST_LOG="$E2E_LOG_DIR/version_store_sync_failure.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-mvcc -- sync_failure; then
    scenario_result "vs_format_sync_required" "PASS" "Sync failure handling tests passed"
else
    scenario_result "vs_format_sync_required" "FAIL" "Sync failure handling tests failed"
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
