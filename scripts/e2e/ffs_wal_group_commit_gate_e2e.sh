#!/usr/bin/env bash
# ffs_wal_group_commit_gate_e2e.sh - dry-run evidence gate for bd-p2j3e.4.
#
# Validates that WAL/group-commit performance claims stay blocked until replay
# proof and comparable fsync-tail evidence both pass.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${FFS_WAL_GROUP_COMMIT_CARGO_TARGET_DIR:-${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_wal_group_commit_gate}}"
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
  "gate_id": "ffs_wal_group_commit_gate",
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
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
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
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}|command=$*"
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
text = "\n".join(
    line
    for line in text.splitlines()
    if not line.startswith(
        (
            "WAL group-commit gate report written:",
            "WAL group-commit gate summary written:",
        )
    )
) + "\n"
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "classification_counts" in obj and "expected_loss_selected_candidate_id" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("WAL group-commit JSON report not found")
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
start = text.find("# WAL Group-Commit Gate")
if start < 0:
    raise SystemExit("WAL group-commit Markdown report not found")
tail = text[start:]
match = re.search(r"\n\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*\brch::", tail)
end = start + match.start() if match else len(text)
remote_end = text.find("\nRemote command finished:", start)
if remote_end >= 0:
    end = min(end, remote_end)
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
    local raw_output="${output_path}.rch.log"
    local status=0

    jq "$jq_filter" "$source_json" >"$local_mutated_json"
    scenario_dir="${RCH_INPUT_ROOT}/$(basename "$local_mutated_json" .json)"
    mkdir -p "$scenario_dir"
    remote_mutated_json="${scenario_dir}/manifest.json"
    cp "$local_mutated_json" "$remote_mutated_json"

    run_rch_capture "$raw_output" cargo run --quiet -p ffs-harness -- "$validator" "$path_flag" "$remote_mutated_json" || status=$?
    if ! extract_report_json "$raw_output" "$output_path" 2>/dev/null; then
        cp "$raw_output" "$output_path"
    fi
    if [[ $status -eq 0 ]] && grep -q '^error:' "$output_path"; then
        return 1
    fi
    return "$status"
}

e2e_init "ffs_wal_group_commit_gate"
RCH_INPUT_ROOT="${REPO_ROOT}/artifacts/rch_e2e/$(basename "$E2E_LOG_DIR")/wal_group_commit_gate"
mkdir -p "$RCH_INPUT_ROOT"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"

MANIFEST_JSON="benchmarks/wal_group_commit_gate_manifest.json"
REPORT_RAW="${E2E_LOG_DIR}/wal_group_commit_gate_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/wal_group_commit_gate_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/wal_group_commit_gate_report_md.raw"
MISSING_RAW_JSON="${E2E_LOG_DIR}/wal_group_commit_missing_raw_log.json"
MISSING_RAW_REPORT="${E2E_LOG_DIR}/wal_group_commit_missing_raw_log.raw"
MISSING_REF_JSON="${E2E_LOG_DIR}/wal_group_commit_missing_reference_claim.json"
MISSING_REF_REPORT="${E2E_LOG_DIR}/wal_group_commit_missing_reference_claim.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod wal_group_commit_gate" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-wal-group-commit-gate" crates/ffs-harness/src/main.rs \
    && [[ -f "$MANIFEST_JSON" ]]; then
    scenario_result "wal_group_commit_cli_wired" "PASS" "module, CLI command, and default manifest present"
else
    scenario_result "wal_group_commit_cli_wired" "FAIL" "missing module export, CLI command, or default manifest"
fi

e2e_step "Scenario 2: unit tests cover WAL gate invariants"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness wal_group_commit_gate; then
    scenario_result "wal_group_commit_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "wal_group_commit_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default manifest validates all dry-run classifications"
if run_rch_stdout_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-wal-group-commit-gate --manifest "$MANIFEST_JSON"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true
        and .classification_counts.pass == 1
        and .classification_counts.warn == 1
        and .classification_counts.fail == 2
        and .classification_counts.noisy == 1
        and .classification_counts.missing_reference == 1
        and .missing_reference_count == 1
        and .expected_loss_selected_candidate_id == .expected_loss_best_candidate_id
        and .public_claim_authoritative_count == 1' "$REPORT_JSON" >/dev/null; then
        scenario_result "wal_group_commit_default_manifest" "PASS" "default manifest emits pass/warn/fail/noisy/missing-reference classes"
    else
        scenario_result "wal_group_commit_default_manifest" "FAIL" "default manifest report missing expected classification accounting"
    fi
else
    scenario_result "wal_group_commit_default_manifest" "FAIL" "validator failed for default manifest; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown summary includes expected-loss and missing-reference evidence"
if run_rch_stdout_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-wal-group-commit-gate --manifest "$MANIFEST_JSON" --format markdown; then
    if grep -q "Expected-Loss Controller" "$REPORT_MD_RAW" && grep -q "missing_reference" "$REPORT_MD_RAW"; then
        scenario_result "wal_group_commit_markdown" "PASS" "markdown exposes expected-loss and missing-reference rows"
    else
        scenario_result "wal_group_commit_markdown" "FAIL" "markdown summary missing expected-loss or missing-reference content"
    fi
else
    scenario_result "wal_group_commit_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: missing raw WAL logs fail closed"
set +e
run_rch_mutated_validator_capture \
    "$MISSING_RAW_REPORT" \
    "$MISSING_RAW_JSON" \
    '.scenarios[0].raw_logs = [] | .replay_proofs[0].raw_log_path = ""' \
    "$MANIFEST_JSON" \
    validate-wal-group-commit-gate \
    --manifest
MISSING_RAW_STATUS=$?
set -e
if [[ $MISSING_RAW_STATUS -ne 0 ]] \
    && grep -q "raw_logs must not be empty" "$MISSING_RAW_REPORT" \
    && grep -q "raw_log_path must not be empty" "$MISSING_RAW_REPORT"; then
    scenario_result "wal_group_commit_missing_raw_logs" "PASS" "missing raw WAL logs rejected"
else
    scenario_result "wal_group_commit_missing_raw_logs" "FAIL" "missing raw WAL logs were not rejected"
fi

e2e_step "Scenario 6: missing comparable reference blocks authoritative claims"
set +e
run_rch_mutated_validator_capture \
    "$MISSING_REF_REPORT" \
    "$MISSING_REF_JSON" \
    'del(.scenarios[0].reference)' \
    "$MANIFEST_JSON" \
    validate-wal-group-commit-gate \
    --manifest
MISSING_REF_STATUS=$?
set -e
if [[ $MISSING_REF_STATUS -ne 0 ]] \
    && grep -q "missing comparable reference" "$MISSING_REF_REPORT"; then
    scenario_result "wal_group_commit_missing_reference_claim" "PASS" "authoritative claim without comparable reference rejected"
else
    scenario_result "wal_group_commit_missing_reference_claim" "FAIL" "authoritative missing-reference mutation was not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
