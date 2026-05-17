#!/usr/bin/env bash
# ffs_swarm_tail_latency_e2e.sh - smoke gate for bd-p2j3e.1.
#
# Validates the swarm tail-latency decomposition ledger. This suite is
# dry-run-only: it verifies component attribution, reference downgrade rules,
# and release-claim fail-closed behavior without running destructive mounted
# workloads.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${FFS_SWARM_TAIL_CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_tail_latency}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_REMOTE_TMPDIR="${FFS_SWARM_TAIL_RCH_TMPDIR:-/var/tmp}"
RCH_REMOTE_CARGO_HOME="${FFS_SWARM_TAIL_RCH_CARGO_HOME:-/var/tmp/rch_cargo_home_frankenfs_swarm_tail_latency}"
RCH_CAPTURE_VISIBILITY="${FFS_SWARM_TAIL_RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-30}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
E2E_START_TIME="$(date +%s)"
E2E_TEST_NAME="ffs_swarm_tail_latency"
E2E_LOG_ROOT="${REPO_ROOT}/artifacts/e2e"
mkdir -p "$E2E_LOG_ROOT"
E2E_LOG_DIR="$(mktemp -d "$E2E_LOG_ROOT/$(date +%Y%m%d_%H%M%S)_ffs_swarm_tail_latency_XXXXXX")"
E2E_LOG_FILE="${E2E_LOG_DIR}/run.log"

e2e_log() {
    local message="$*"
    echo "$message"
    echo "$message" >>"$E2E_LOG_FILE"
}

e2e_step() {
    local step="$1"
    e2e_log ""
    e2e_log "=== ${step} ==="
    e2e_log "Time: $(date -Iseconds)"
}

e2e_finish() {
    local verdict="$1"
    local summary="$2"
    local duration
    local exit_code=0
    duration=$(($(date +%s) - E2E_START_TIME))

    cat >"${E2E_LOG_DIR}/result.json" <<JSON
{
  "schema_version": 1,
  "runner_contract_version": 1,
  "gate_id": "ffs_swarm_tail_latency",
  "created_at": "$(date -Iseconds)",
  "verdict": "${verdict}",
  "summary": "${summary}",
  "pass_count": ${PASS_COUNT},
  "fail_count": ${FAIL_COUNT},
  "total": ${TOTAL},
  "duration_secs": ${duration},
  "log_file": "${E2E_LOG_FILE}"
}
JSON

    if [[ "$verdict" != "PASS" ]]; then
        exit_code=1
    fi
    e2e_emit_json_summary "$exit_code" >/dev/null 2>&1 || true

    e2e_log ""
    e2e_log "=============================================="
    e2e_log "${verdict}: ${summary}"
    e2e_log "=============================================="
    e2e_log "Log file: ${E2E_LOG_FILE}"
    e2e_log "JSON summary written: ${E2E_LOG_DIR}/result.json"
}

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
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    local command_display
    local -a rch_args=("$@")

    case $- in
        *e*) had_errexit=1 ;;
    esac

    if [[ ${#rch_args[@]} -gt 0 && "${rch_args[0]}" == "cargo" ]]; then
        rch_args=(env "TMPDIR=${RCH_REMOTE_TMPDIR}" "CARGO_HOME=${RCH_REMOTE_CARGO_HOME}" "${rch_args[@]}")
    fi
    command_display="${rch_args[*]}"

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        "${RCH_BIN:-rch}" exec -- "${rch_args[@]}" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=${command_display}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "${rch_args[@]}"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=${command_display}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "${rch_args[@]}"
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
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=${command_display}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=${command_display}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=${command_display}"
        return 0
    fi
    return "$status"
}

run_rch_mutated_validator_capture() {
    local output_path="$1"
    local local_mutated_json="$2"
    local jq_filter="$3"
    local source_json="$4"
    local validator="$5"
    local path_flag="$6"

    jq "$jq_filter" "$source_json" >"$local_mutated_json"
    run_rch_capture "$output_path" cargo run --quiet -p ffs-harness -- "$validator" "$path_flag" "$local_mutated_json"
}

extract_json_object() {
    local input_path="$1"
    local output_path="$2"
    python3 - "$input_path" "$output_path" <<'PY'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
pos = 0
while pos < len(text):
    idx = text.find("{", pos)
    if idx < 0:
        break
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        pos = idx + 1
        continue
    dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
    raise SystemExit(0)
raise SystemExit(f"JSON report not found in {source}")
PY
}

extract_markdown_report() {
    local input_path="$1"
    local output_path="$2"
    python3 - "$input_path" "$output_path" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Swarm Tail-Latency Ledger")
if start < 0:
    raise SystemExit(f"swarm tail-latency markdown report not found in {source}")
end = text.find("\n[RCH]", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
dest.write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_log "=============================================="
e2e_log "E2E Test: ffs_swarm_tail_latency"
e2e_log "=============================================="
e2e_log "Started: $(date -Iseconds)"
e2e_log "Log directory: ${E2E_LOG_DIR}"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

LEDGER_JSON="benchmarks/swarm_tail_latency_ledger.json"
RCH_INPUT_DIR="${REPO_ROOT}/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/swarm_tail_latency"
mkdir -p "$RCH_INPUT_DIR"
REPORT_RAW="${E2E_LOG_DIR}/swarm_tail_latency_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/swarm_tail_latency_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/swarm_tail_latency_report_md.raw"
REPORT_MD="${E2E_LOG_DIR}/swarm_tail_latency_report.md"
MUTATED_COMPONENT_JSON="${RCH_INPUT_DIR}/swarm_tail_bad_component.json"
MUTATED_COMPONENT_RAW="${E2E_LOG_DIR}/swarm_tail_bad_component.raw"
MUTATED_REFERENCE_JSON="${RCH_INPUT_DIR}/swarm_tail_bad_reference.json"
MUTATED_REFERENCE_RAW="${E2E_LOG_DIR}/swarm_tail_bad_reference.raw"
MUTATED_HOST_JSON="${RCH_INPUT_DIR}/swarm_tail_bad_host.json"
MUTATED_HOST_RAW="${E2E_LOG_DIR}/swarm_tail_bad_host.raw"
MUTATED_BUCKET_JSON="${RCH_INPUT_DIR}/swarm_tail_bad_bucket.json"
MUTATED_BUCKET_RAW="${E2E_LOG_DIR}/swarm_tail_bad_bucket.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

if [[ "${FFS_SWARM_TAIL_LATENCY_RESULT_SELF_CHECK_ONLY:-0}" == "1" ]]; then
    e2e_step "Result summary merge self-check"
    scenario_result "swarm_tail_latency_summary_merge" "PASS" "custom and shared result fields merge"
    e2e_log "SCENARIO_RESULT|scenario_id=too_short|outcome=PASS"
    e2e_log "SCENARIO_RESULT|scenario_id=swarm_tail_latency_summary_merge|outcome=PASS|bad_field"
    e2e_log "SCENARIO_RESULT|scenario_id=swarm_tail_latency_summary_merge|outcome=PASS|"
    e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=/tmp/rch-local.log|command=cargo test"
    e2e_finish "PASS" "self-check custom summary merge"
    if jq -e '
        .gate_id == "ffs_swarm_tail_latency"
        and .verdict == "PASS"
        and .summary == "self-check custom summary merge"
        and .pass_count == 1
        and .fail_count == 0
        and .total == 1
        and .invalid_scenario_marker_count == 3
        and (.invalid_scenario_markers | length == 3)
        and ([.invalid_scenario_markers[].reason] | sort == [
            "invalid_scenario_id",
            "malformed_extension",
            "malformed_extension"
        ])
        and .rch_local_fallback_rejected_count == 1
        and (.rch_local_fallback_rejections[0].marker | contains("RCH_LOCAL_FALLBACK_REJECTED"))
    ' "$E2E_LOG_DIR/result.json" >/dev/null; then
        e2e_log "Swarm tail-latency result summary merge self-check passed"
        exit 0
    fi
    jq . "$E2E_LOG_DIR/result.json" || true
    e2e_log "Swarm tail-latency result summary merge self-check failed"
    exit 1
fi

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod swarm_tail_latency" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-tail-latency" crates/ffs-harness/src/main.rs \
    && [[ -f "$LEDGER_JSON" ]]; then
    scenario_result "swarm_tail_cli_wired" "PASS" "module, CLI command, and default ledger present"
else
    scenario_result "swarm_tail_cli_wired" "FAIL" "missing module export, CLI command, or default ledger"
fi

e2e_step "Scenario 2: unit tests cover ledger invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness swarm_tail_latency; then
    scenario_result "swarm_tail_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "swarm_tail_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default ledger validates with all classifications and dominance alerts"
if run_rch_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$LEDGER_JSON" \
    && extract_json_object "$REPORT_RAW" "$REPORT_JSON"; then
    if jq -e '.valid == true and .row_count == 5 and .missing_reference_count == 1 and .component_dominance_alert_count >= 3 and (.classification_counts.pass == 1) and (.classification_counts.warn == 1) and (.classification_counts.fail == 1) and (.classification_counts.noisy == 1) and (.classification_counts.missing_reference == 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "swarm_tail_default_ledger" "PASS" "default ledger preserves classifications, missing-reference downgrade, and dominance alerts"
    else
        scenario_result "swarm_tail_default_ledger" "FAIL" "default ledger report missing classification or dominance accounting"
    fi
else
    scenario_result "swarm_tail_default_ledger" "FAIL" "validator failed for default ledger; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering includes tail attribution and watched alerts"
if run_rch_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-tail-latency --ledger "$LEDGER_JSON" --format markdown \
    && extract_markdown_report "$REPORT_MD_RAW" "$REPORT_MD"; then
    if grep -q "Tail Attribution" "$REPORT_MD" && grep -q "wal_fsync" "$REPORT_MD" && grep -q "fuse_wrapper" "$REPORT_MD" && grep -q "missing_reference" "$REPORT_MD"; then
        scenario_result "swarm_tail_markdown" "PASS" "markdown summary includes tail attribution and watched dominant components"
    else
        scenario_result "swarm_tail_markdown" "FAIL" "markdown summary missing tail attribution, watched alert, or missing-reference row"
    fi
else
    scenario_result "swarm_tail_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: missing required component fails closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_COMPONENT_RAW" \
    "$MUTATED_COMPONENT_JSON" \
    '.rows[0].latency.components |= map(select(.component != "wal_fsync"))' \
    "$LEDGER_JSON" \
    validate-swarm-tail-latency \
    --ledger
MUTATED_COMPONENT_STATUS=$?
set -e
if [[ $MUTATED_COMPONENT_STATUS -ne 0 ]] && grep -q "missing required component wal_fsync" "$MUTATED_COMPONENT_RAW"; then
    scenario_result "swarm_tail_missing_component_fail_closed" "PASS" "missing component attribution rejected"
else
    scenario_result "swarm_tail_missing_component_fail_closed" "FAIL" "missing component attribution was not rejected"
fi

e2e_step "Scenario 6: missing reference cannot become measured claim"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_REFERENCE_RAW" \
    "$MUTATED_REFERENCE_JSON" \
    '.rows[4].release_claim_state = "measured_authoritative"' \
    "$LEDGER_JSON" \
    validate-swarm-tail-latency \
    --ledger
MUTATED_REFERENCE_STATUS=$?
set -e
if [[ $MUTATED_REFERENCE_STATUS -ne 0 ]] && grep -q "public performance wording must remain experimental" "$MUTATED_REFERENCE_RAW"; then
    scenario_result "swarm_tail_missing_reference_fail_closed" "PASS" "missing reference measured claim rejected"
else
    scenario_result "swarm_tail_missing_reference_fail_closed" "FAIL" "missing reference measured claim was not rejected"
fi

e2e_step "Scenario 7: missing host fingerprint fails closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_HOST_RAW" \
    "$MUTATED_HOST_JSON" \
    '.rows[0].host.host_fingerprint = ""' \
    "$LEDGER_JSON" \
    validate-swarm-tail-latency \
    --ledger
MUTATED_HOST_STATUS=$?
set -e
if [[ $MUTATED_HOST_STATUS -ne 0 ]] && grep -q "host.host_fingerprint" "$MUTATED_HOST_RAW"; then
    scenario_result "swarm_tail_missing_host_fail_closed" "PASS" "missing host fingerprint rejected"
else
    scenario_result "swarm_tail_missing_host_fail_closed" "FAIL" "missing host fingerprint was not rejected"
fi

e2e_step "Scenario 8: nonmonotonic p99 buckets fail closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_BUCKET_RAW" \
    "$MUTATED_BUCKET_JSON" \
    '.rows[0].latency.p95_latency_us = 12000.0' \
    "$LEDGER_JSON" \
    validate-swarm-tail-latency \
    --ledger
MUTATED_BUCKET_STATUS=$?
set -e
if [[ $MUTATED_BUCKET_STATUS -ne 0 ]] && grep -q "p50 <= p95 <= p99" "$MUTATED_BUCKET_RAW"; then
    scenario_result "swarm_tail_nonmonotonic_bucket_fail_closed" "PASS" "nonmonotonic latency buckets rejected"
else
    scenario_result "swarm_tail_nonmonotonic_bucket_fail_closed" "FAIL" "nonmonotonic latency buckets were not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
