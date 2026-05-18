#!/usr/bin/env bash
# ffs_cli_wal_telemetry_e2e.sh - E2E verification for CLI WAL replay telemetry (bd-h6nz.1.6)
#
# Validates that:
# 1. WalReplayInfoOutput struct has all required fields
# 2. MvccStatsOutput includes optional wal_replay field
# 3. MvccInfoOutput includes optional wal_replay field
# 4. build_wal_replay_info helper exists
# 5. print_wal_replay_info helper exists
# 6. log_wal_recovery_telemetry structured log emitter exists
# 7. Unit tests pass for WAL replay telemetry
# 8. Structured logging markers present
# 9. Evidence-compatible fields align with WalRecoveryDetail
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_cli_wal_telemetry_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_cli_wal_telemetry}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_CLI_WAL_TELEMETRY_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_CLI_WAL_TELEMETRY_SKIP_SELF_CHECK:-0}"

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

fixture_case="${FFS_CLI_WAL_TELEMETRY_FIXTURE_CASE:-complete}"

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
        echo "unknown CLI WAL telemetry fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-cli -- wal_replay"*)
        printf '%s\n' \
            "running 5 tests" \
            "test tests::wal_replay_info_output_has_fields ... ok" \
            "test tests::mvcc_stats_output_includes_wal_replay ... ok" \
            "test tests::mvcc_info_output_includes_wal_replay ... ok" \
            "test tests::print_wal_replay_info_json ... ok" \
            "test tests::build_wal_replay_info_records_checkpoint ... ok"
        ;;
    *"cargo test -p ffs-core -- mvcc_wal_recovery"*)
        printf '%s\n' \
            "running 4 tests" \
            "test mvcc::tests::mvcc_wal_recovery_replays_commits ... ok" \
            "test mvcc::tests::mvcc_wal_recovery_discards_partial_records ... ok" \
            "test mvcc::tests::mvcc_wal_recovery_uses_checkpoint ... ok" \
            "test mvcc::tests::mvcc_wal_recovery_reports_clean_state ... ok"
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
    local child_log="$E2E_LOG_DIR/cli_wal_telemetry_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_CLI_WAL_TELEMETRY_SELF_CHECK=0 \
        FFS_CLI_WAL_TELEMETRY_SKIP_SELF_CHECK=1 \
        FFS_CLI_WAL_TELEMETRY_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_cli_wal_telemetry_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic CLI WAL telemetry wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-cli-wal-telemetry-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "wal_replay_info_fields" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "mvcc_stats_wal_replay" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "mvcc_info_wal_replay" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "cli_wal_helpers" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "cli_wal_structured_logging" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "wal_telemetry_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "json_schema_stability" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "cli_wal_evidence_alignment" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "core_wal_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "cli_wal_telemetry_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "cli_wal_telemetry_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "cli_wal_telemetry_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "cli_wal_telemetry_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "cli_wal_telemetry_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "cli_wal_telemetry_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_cli_wal_telemetry"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

CLI_SRC="crates/ffs-cli/src/main.rs"

#######################################
# Scenario 1: WalReplayInfoOutput struct fields
#######################################
e2e_step "Scenario 1: WalReplayInfoOutput struct fields"

FIELDS_FOUND=0
for field in "outcome: String" "is_clean: bool" "commits_replayed: u64" "versions_replayed: u64" "records_discarded: u64" "wal_valid_bytes: u64" "wal_total_bytes: u64" "used_checkpoint: bool" "checkpoint_commit_seq: Option<u64>"; do
    if grep -q "$field" "$CLI_SRC"; then
        FIELDS_FOUND=$((FIELDS_FOUND + 1))
    fi
done

if [[ $FIELDS_FOUND -ge 9 ]]; then
    scenario_result "wal_replay_info_fields" "PASS" "All ${FIELDS_FOUND}/9 WalReplayInfoOutput fields present"
else
    scenario_result "wal_replay_info_fields" "FAIL" "Only ${FIELDS_FOUND}/9 WalReplayInfoOutput fields found"
fi

#######################################
# Scenario 2: MvccStatsOutput includes wal_replay
#######################################
e2e_step "Scenario 2: MvccStatsOutput wal_replay field"

if grep -q 'struct MvccStatsOutput' "$CLI_SRC" && grep -A 10 'struct MvccStatsOutput' "$CLI_SRC" | grep -q 'wal_replay'; then
    scenario_result "mvcc_stats_wal_replay" "PASS" "MvccStatsOutput has wal_replay field"
else
    scenario_result "mvcc_stats_wal_replay" "FAIL" "MvccStatsOutput missing wal_replay field"
fi

#######################################
# Scenario 3: MvccInfoOutput includes wal_replay
#######################################
e2e_step "Scenario 3: MvccInfoOutput wal_replay field"

if grep -q 'struct MvccInfoOutput' "$CLI_SRC" && grep -A 15 'struct MvccInfoOutput' "$CLI_SRC" | grep -q 'wal_replay'; then
    scenario_result "mvcc_info_wal_replay" "PASS" "MvccInfoOutput has wal_replay field"
else
    scenario_result "mvcc_info_wal_replay" "FAIL" "MvccInfoOutput missing wal_replay field"
fi

#######################################
# Scenario 4: Helper functions exist
#######################################
e2e_step "Scenario 4: Helper functions"

HELPERS_FOUND=0
for func in "fn build_wal_replay_info" "fn print_wal_replay_info" "fn log_wal_recovery_telemetry"; do
    if grep -q "$func" "$CLI_SRC"; then
        HELPERS_FOUND=$((HELPERS_FOUND + 1))
    fi
done

if [[ $HELPERS_FOUND -eq 3 ]]; then
    scenario_result "cli_wal_helpers" "PASS" "All 3 WAL replay helpers present"
else
    scenario_result "cli_wal_helpers" "FAIL" "Only ${HELPERS_FOUND}/3 helpers found"
fi

#######################################
# Scenario 5: Structured logging markers
#######################################
e2e_step "Scenario 5: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "wal_recovery_telemetry" "mvcc_stats_start" "mvcc_stats_complete"; do
    if grep -q "\"${marker}\"" "$CLI_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 3 ]]; then
    scenario_result "cli_wal_structured_logging" "PASS" "Structured logging: ${LOG_MARKERS_FOUND}/3 markers present"
else
    scenario_result "cli_wal_structured_logging" "FAIL" "Only ${LOG_MARKERS_FOUND}/3 structured log markers found"
fi

#######################################
# Scenario 6: Unit tests pass
#######################################
e2e_step "Scenario 6: WAL replay telemetry unit tests"

TEST_LOG="$E2E_LOG_DIR/cli_wal_telemetry_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-cli -- wal_replay; then
    TESTS_RUN=$(grep -c "test tests::.*wal_replay\|test tests::mvcc.*wal_replay\|test tests::mvcc_info_output_includes_wal" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "wal_telemetry_tests" "PASS" "Unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "wal_telemetry_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 4)"
    fi
else
    scenario_result "wal_telemetry_tests" "FAIL" "Unit tests failed"
fi

#######################################
# Scenario 7: skip_serializing_if on optional fields
#######################################
e2e_step "Scenario 7: JSON schema stability (skip_serializing_if)"

SKIP_COUNT=0
# Count skip_serializing_if attributes on optional wal_replay and checkpoint fields
for pattern in 'skip_serializing_if.*Option.*is_none.*checkpoint_commit_seq' 'skip_serializing_if.*Option.*is_none.*wal_replay'; do
    # Simpler: just check that skip_serializing_if appears near both fields
    if true; then
        SKIP_COUNT=$((SKIP_COUNT + 1))
    fi
done

# More targeted: check that both checkpoint_commit_seq and wal_replay have skip_serializing_if
SKIPS_FOUND=0
if grep -B 1 'checkpoint_commit_seq' "$CLI_SRC" | grep -q 'skip_serializing_if'; then
    SKIPS_FOUND=$((SKIPS_FOUND + 1))
fi
if grep -B 1 'wal_replay.*Option.*WalReplayInfoOutput' "$CLI_SRC" | grep -q 'skip_serializing_if'; then
    SKIPS_FOUND=$((SKIPS_FOUND + 1))
fi

if [[ $SKIPS_FOUND -ge 2 ]]; then
    scenario_result "json_schema_stability" "PASS" "skip_serializing_if on optional fields (${SKIPS_FOUND}/2)"
else
    scenario_result "json_schema_stability" "FAIL" "Missing skip_serializing_if on ${SKIPS_FOUND}/2 optional fields"
fi

#######################################
# Scenario 8: Evidence field alignment
#######################################
e2e_step "Scenario 8: Evidence field alignment"

EVIDENCE_SRC="crates/ffs-repair/src/evidence.rs"
ALIGNED=0
for field in "commits_replayed" "versions_replayed" "records_discarded" "wal_valid_bytes" "wal_total_bytes" "used_checkpoint" "checkpoint_commit_seq"; do
    CLI_HAS=$(grep -c "$field" "$CLI_SRC" || echo "0")
    EVIDENCE_HAS=$(grep -c "$field" "$EVIDENCE_SRC" || echo "0")
    if [[ $CLI_HAS -gt 0 ]] && [[ $EVIDENCE_HAS -gt 0 ]]; then
        ALIGNED=$((ALIGNED + 1))
    fi
done

if [[ $ALIGNED -eq 7 ]]; then
    scenario_result "cli_wal_evidence_alignment" "PASS" "All 7 fields aligned between CLI and evidence"
else
    scenario_result "cli_wal_evidence_alignment" "FAIL" "Only ${ALIGNED}/7 fields aligned"
fi

#######################################
# Scenario 9: ffs-core WAL recovery tests still pass
#######################################
e2e_step "Scenario 9: ffs-core WAL recovery tests"

TEST_LOG="$E2E_LOG_DIR/core_wal_recovery_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-core -- mvcc_wal_recovery; then
    scenario_result "core_wal_tests" "PASS" "ffs-core WAL recovery tests passed"
else
    scenario_result "core_wal_tests" "FAIL" "ffs-core WAL recovery tests failed"
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
