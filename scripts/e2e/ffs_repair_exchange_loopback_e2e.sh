#!/usr/bin/env bash
# ffs_repair_exchange_loopback_e2e.sh - Loopback verification for repair symbol exchange
#
# Usage: ./scripts/e2e/ffs_repair_exchange_loopback_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_exchange_loopback}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_REPAIR_EXCHANGE_LOOPBACK_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_REPAIR_EXCHANGE_LOOPBACK_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REPAIR_EXCHANGE_LOOPBACK_SKIP_SELF_CHECK:-0}"

for name in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    e2e_rch_add_env_allowlist "$name"
done

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

print_rch_log() {
    local log_path="$1"
    if [[ -s "$log_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$log_path"
    fi
}

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REPAIR_EXCHANGE_LOOPBACK_FIXTURE_CASE:-complete}"

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
        echo "unknown repair exchange loopback fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-repair exchange::tests::loopback_exchange_e2e"*)
        printf '%s\n' \
            "test exchange::tests::loopback_exchange_e2e ... ok"
        ;;
    *"cargo test -p ffs-repair exchange::tests:: -- --nocapture"*)
        printf '%s\n' \
            "test exchange::tests::frame_round_trip ... ok" \
            "test exchange::tests::retry_transient_get_symbol_failure ... ok" \
            "test exchange::tests::retry_transient_put_symbol_failure ... ok"
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
    local child_log="$E2E_LOG_DIR/repair_exchange_loopback_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REPAIR_EXCHANGE_LOOPBACK_SELF_CHECK=0 \
        FFS_REPAIR_EXCHANGE_LOOPBACK_SKIP_SELF_CHECK=1 \
        FFS_REPAIR_EXCHANGE_LOOPBACK_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_repair_exchange_loopback_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic repair exchange loopback wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir unit_log loopback_log
    stub_path="$E2E_LOG_DIR/rch-repair-exchange-loopback-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    unit_log="$result_dir/repair_exchange_unit_tests.log"
    loopback_log="$result_dir/repair_exchange_loopback.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$unit_log" ]] \
        && [[ -f "$loopback_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "repair_exchange_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_exchange_loopback" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "frame_round_trip" "$unit_log" \
        && grep -q "retry_transient_get_symbol_failure" "$unit_log" \
        && grep -q "loopback_exchange_e2e" "$loopback_log"; then
        scenario_result "repair_exchange_loopback_fixture_complete_self_check" "PASS" "result=${result_path} unit_log=${unit_log} loopback_log=${loopback_log}"
    else
        scenario_result "repair_exchange_loopback_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "repair exchange loopback complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "repair_exchange_loopback_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_exchange_loopback_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "repair exchange loopback local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "repair_exchange_loopback_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_exchange_loopback_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "repair exchange loopback missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_repair_exchange_loopback"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Scenario 1: Unit framing and retry tests"
UNIT_LOG="$E2E_LOG_DIR/repair_exchange_unit_tests.log"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-repair exchange::tests:: -- --nocapture; then
    print_rch_log "$UNIT_LOG"
    scenario_result "repair_exchange_unit_tests" "PASS" "Framing and retry tests passed; log=${UNIT_LOG}"
else
    print_rch_log "$UNIT_LOG"
    scenario_result "repair_exchange_unit_tests" "FAIL" "Framing and retry tests failed"
fi

e2e_step "Scenario 2: Loopback symbol exchange"
LOOPBACK_LOG="$E2E_LOG_DIR/repair_exchange_loopback.log"
if run_rch_capture "$LOOPBACK_LOG" cargo test -p ffs-repair exchange::tests::loopback_exchange_e2e -- --nocapture --test-threads=1; then
    print_rch_log "$LOOPBACK_LOG"
    scenario_result "repair_exchange_loopback" "PASS" "Loopback get/put exchange passed; log=${LOOPBACK_LOG}"
else
    print_rch_log "$LOOPBACK_LOG"
    scenario_result "repair_exchange_loopback" "FAIL" "Loopback get/put exchange failed"
fi

e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
fi

e2e_log "OVERALL: PASS"
