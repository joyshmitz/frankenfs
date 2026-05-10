#!/usr/bin/env bash
# ffs_swarm_cache_controller_e2e.sh - smoke gate for bd-p2j3e.5.
#
# Validates the swarm cache controller contract, including the rule that
# small-host fixture evidence must downgrade release claims instead of becoming
# a 64-core/256GB performance proof.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${FFS_SWARM_CACHE_CARGO_TARGET_DIR:-${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_cache_controller}}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-2}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

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
    duration=$(($(date +%s) - E2E_START_TIME))

    cat >"${E2E_LOG_DIR}/result.json" <<JSON
{
  "schema_version": 1,
  "runner_contract_version": 1,
  "gate_id": "ffs_swarm_cache_controller",
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

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        RCH_VISIBILITY=none \
        "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
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
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
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
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

extract_report_json() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "small_host_downgrade_count" in obj and "authoritative_claim_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("swarm cache-controller JSON report not found")
PY
}

extract_report_markdown() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Swarm Cache Controller Contract")
if start < 0:
    raise SystemExit("swarm cache-controller markdown report not found")
end = text.find("\n[RCH]", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
pathlib.Path(report_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

run_rch_stdout_capture() {
    local output_path="$1"
    shift
    local rch_log_path="${output_path}.rch.log"
    local status=0

    run_rch_capture "$rch_log_path" "$@" || status=$?
    if [[ $status -ne 0 ]]; then
        return "$status"
    fi
    if extract_report_json "$rch_log_path" "$output_path" 2>/dev/null; then
        return 0
    fi
    if extract_report_markdown "$rch_log_path" "$output_path"; then
        return 0
    fi
    return 1
}

run_rch_mutated_validator_capture() {
    local output_path="$1"
    local local_mutated_json="$2"
    local jq_filter="$3"
    local source_json="$4"
    local validator="$5"
    local path_flag="$6"
    local scenario_dir
    local remote_mutated_json
    local status=0

    jq "$jq_filter" "$source_json" >"$local_mutated_json"
    scenario_dir="${RCH_INPUT_ROOT}/$(basename "$local_mutated_json" .json)"
    mkdir -p "$scenario_dir"
    remote_mutated_json="${scenario_dir}/manifest.json"
    cp "$local_mutated_json" "$remote_mutated_json"

    run_rch_capture "$output_path" cargo run --quiet -p ffs-harness -- "$validator" "$path_flag" "$remote_mutated_json" || status=$?
    if [[ $status -eq 0 ]] && grep -q '^error:' "$output_path"; then
        return 1
    fi
    return "$status"
}

e2e_init "ffs_swarm_cache_controller"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

CONTRACT_JSON="benchmarks/swarm_cache_controller_contract.json"
RCH_INPUT_ROOT="${REPO_ROOT}/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/swarm_cache_controller"
mkdir -p "$RCH_INPUT_ROOT"
REPORT_RAW="${E2E_LOG_DIR}/swarm_cache_controller_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/swarm_cache_controller_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/swarm_cache_controller_report_md.raw"
MUTATED_JSON="${E2E_LOG_DIR}/swarm_cache_controller_bad_small_host.json"
MUTATED_RAW="${E2E_LOG_DIR}/swarm_cache_controller_bad_small_host.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod swarm_cache_controller" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-cache-controller" crates/ffs-harness/src/main.rs \
    && [[ -f "$CONTRACT_JSON" ]]; then
    scenario_result "swarm_cache_cli_wired" "PASS" "module, CLI command, and default contract present"
else
    scenario_result "swarm_cache_cli_wired" "FAIL" "missing module export, CLI command, or default contract"
fi

e2e_step "Scenario 2: unit tests cover contract invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness swarm_cache_controller; then
    scenario_result "swarm_cache_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "swarm_cache_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default contract validates and preserves small-host downgrade"
if run_rch_stdout_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-cache-controller --contract "$CONTRACT_JSON"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true and .small_host_downgrade_count == 1 and .authoritative_claim_count == 1 and (.claim_state_counts.small_host_smoke >= 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "swarm_cache_default_contract" "PASS" "valid contract includes one small-host downgrade and one authoritative reference fixture"
    else
        scenario_result "swarm_cache_default_contract" "FAIL" "contract report missing expected claim-state accounting"
    fi
else
    scenario_result "swarm_cache_default_contract" "FAIL" "validator failed for default contract; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering is generated from validation report"
if run_rch_stdout_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-cache-controller --contract "$CONTRACT_JSON" --format markdown; then
    if grep -q "Small-host downgrades" "$REPORT_MD_RAW" && grep -q "small_host_smoke" "$REPORT_MD_RAW"; then
        scenario_result "swarm_cache_markdown" "PASS" "markdown summary includes downgrade accounting"
    else
        scenario_result "swarm_cache_markdown" "FAIL" "markdown summary missing downgrade accounting"
    fi
else
    scenario_result "swarm_cache_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: small-host authoritative claims fail closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_RAW" \
    "$MUTATED_JSON" \
    '.scenarios[1].release_claim_state = "measured_authoritative" | .scenarios[1].measurements[0].release_claim_state = "measured_authoritative"' \
    "$CONTRACT_JSON" \
    validate-swarm-cache-controller \
    --contract
MUTATED_STATUS=$?
set -e
if [[ $MUTATED_STATUS -ne 0 ]] && grep -q "below the 64-core/256GB target" "$MUTATED_RAW"; then
    scenario_result "swarm_cache_small_host_fail_closed" "PASS" "small-host measured_authoritative mutation rejected"
else
    scenario_result "swarm_cache_small_host_fail_closed" "FAIL" "small-host measured_authoritative mutation was not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
