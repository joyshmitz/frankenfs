#!/usr/bin/env bash
# ffs_verification_runner_e2e.sh - E2E verification for runner conventions (bd-h6nz.9.4)
#
# Validates that:
# 1. verification_runner module exists and builds clean
# 2. E2E script conformance checker catches known violations
# 3. JSON result emission from lib.sh works
# 4. run_gate.sh runner wrapper exists and has correct structure
# 5. Scenario marker parsing is consistent between shell and Rust
# 6. Unit tests pass for verification_runner module
# 7. Structured logging markers are present
# 8. Retry semantics function is available in lib.sh
# 9. Existing E2E scripts pass conformance check
# 10. Permissioned FUSE lane artifacts and docs are wired
# 11. Mounted write error-class RCH probes use direct cargo commands
# 12. Mounted ext4/btrfs scenario matrix artifacts are wired
# 13. Shared E2E artifact directories are unique under concurrent starts
# 14. Scenario catalog id_pattern sample validation fails closed
# 15. Verification gate scenario_catalog_valid uses the full catalog validator
# 16. Scenario catalog rejects uncataloged static scenario_result IDs
#
# Usage: ./scripts/e2e/ffs_verification_runner_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_verification_runner}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

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
    e2e_rch_capture "$@"
}

verify_lib_summary_preserves_suite_fields() {
    if ! command -v jq >/dev/null 2>&1; then
        return 1
    fi

    local saved_log_dir="$E2E_LOG_DIR"
    local saved_log_file="$E2E_LOG_FILE"
    local saved_start_time="$E2E_START_TIME"
    local saved_test_name="$E2E_TEST_NAME"

    local probe_dir expected_command expected_artifact status
    probe_dir="$E2E_TEMP_DIR/result_summary_merge_probe"
    expected_command="$probe_dir/command_transcript.tsv"
    expected_artifact="$probe_dir/artifact.json"
    status=1

    mkdir -p "$probe_dir"
    E2E_LOG_DIR="$probe_dir"
    E2E_LOG_FILE="$probe_dir/run.log"
    E2E_START_TIME="$(date +%s)"
    E2E_TEST_NAME="summary_merge_probe"

    printf 'SCENARIO_RESULT|scenario_id=summary_merge_probe|outcome=PASS|detail=merge ok\n' \
        >"$E2E_LOG_FILE"
    cat >"$probe_dir/result.json" <<JSON
{
  "verdict": "STALE",
  "exit_code": 99,
  "command_transcript": "$expected_command",
  "worker_identity": "summary-worker",
  "cleanup_status": "partial_artifacts_preserved",
  "artifact_paths": ["$expected_artifact"],
  "scenarios": [
    {
      "scenario_id": "stale_scenario",
      "outcome": "FAIL"
    }
  ]
}
JSON

    if e2e_emit_json_summary 0 >/dev/null 2>&1 \
        && jq -e \
            --arg command_transcript "$expected_command" \
            --arg artifact_path "$expected_artifact" '
                .verdict == "PASS"
                and .exit_code == 0
                and .gate_id == "summary_merge_probe"
                and .command_transcript == $command_transcript
                and .worker_identity == "summary-worker"
                and .cleanup_status == "partial_artifacts_preserved"
                and .artifact_paths == [$artifact_path]
                and (.scenarios | length == 1)
                and .scenarios[0].scenario_id == "summary_merge_probe"
                and .scenarios[0].outcome == "PASS"
            ' "$probe_dir/result.json" >/dev/null; then
        status=0
    fi

    E2E_LOG_DIR="$saved_log_dir"
    E2E_LOG_FILE="$saved_log_file"
    E2E_START_TIME="$saved_start_time"
    E2E_TEST_NAME="$saved_test_name"

    return "$status"
}

verify_run_gate_marker_contract() {
    if ! command -v jq >/dev/null 2>&1; then
        return 1
    fi

    local probe_dir probe_script relative_script probe_log manifest_path gate_status
    local retry_probe_script retry_relative_script retry_log retry_state retry_manifest_path retry_gate_status
    local json_probe_script json_relative_script json_log json_manifest_path json_gate_status json_gate_id
    local missing_relative_script missing_log missing_manifest_path missing_gate_status
    local missing_gate_id_log missing_gate_id_status missing_retries_log missing_retries_status
    local bad_retries_log bad_retries_status
    local fail_marker_script fail_marker_relative_script fail_marker_log fail_marker_manifest_path
    local fail_marker_gate_status
    local bad_catalog_repo bad_catalog_log bad_catalog_status
    local empty_catalog_repo empty_catalog_log empty_catalog_status
    local path_escape_script path_escape_relative_script path_escape_log path_escape_manifest_path
    local path_escape_gate_status path_escape_executed
    local absolute_script absolute_script_log absolute_script_manifest_path absolute_script_gate_status
    local absolute_script_executed
    local conformance_probe_script conformance_relative_script conformance_log conformance_manifest_path
    local conformance_gate_status
    local expected_git_clean
    probe_dir="$E2E_LOG_DIR/run_gate_marker_contract_probe"
    probe_script="$probe_dir/probe_marker_script.sh"
    probe_log="$probe_dir/run_gate.log"

    mkdir -p "$probe_dir"
    cat >"$probe_script" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_valid_marker|outcome=PASS|detail=quote_"probe"\path'
printf '%s\n' 'SCENARIO_RESULT|scenario_id=Upper_case_bad|outcome=PASS'
printf '%s\n' 'SCENARIO_RESULT|scenario_id=too_short|outcome=PASS'
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_invalid_outcome|outcome=SKIP'
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_status_only|status=PASS'
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_duplicate_outcome|outcome=PASS|outcome=FAIL'
printf '%s\n' 'SCENARIO_RESULT_EXTRA|scenario_id=gate_extra_prefix|outcome=PASS'
printf '%s\n' 'RCH_LOCAL_FALLBACK_REJECTED|log=/tmp/rch-local.log|command=cargo test'
PROBE

    relative_script="${probe_script#$REPO_ROOT/}"
    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    gate_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_marker_contract "$relative_script" \
        >"$probe_log" 2>&1 || gate_status=$?
    [[ "$gate_status" -eq 1 ]] || return 1

    manifest_path=$(sed -n 's/^Manifest: //p' "$probe_log" | tail -n 1)
    [[ -n "$manifest_path" && -f "$manifest_path" ]] || return 1

    jq -e --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_marker_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].verdict == "FAIL"
        and (.script_results[0].scenarios | length == 1)
        and .script_results[0].scenarios[0].scenario_id == "gate_valid_marker"
        and .script_results[0].scenarios[0].outcome == "PASS"
        and .script_results[0].scenarios[0].detail == "quote_\"probe\"\\path"
        and .script_results[0].rch_local_fallback_rejected_count == 1
        and .script_results[0].rch_local_fallback_rejections[0].marker == "RCH_LOCAL_FALLBACK_REJECTED|log=/tmp/rch-local.log|command=cargo test"
    ' "$manifest_path" >/dev/null

    retry_probe_script="$probe_dir/retry_marker_script.sh"
    retry_log="$probe_dir/run_gate_retry.log"
    retry_state="$probe_dir/retry_state"

    cat >"$retry_probe_script" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
state_file="${RUN_GATE_RETRY_PROBE_STATE:?state file required}"
if [[ ! -f "$state_file" ]]; then
    printf 'seen\n' >"$state_file"
    printf '%s\n' 'RCH_LOCAL_FALLBACK_REJECTED|log=/tmp/rch-first.log|command=cargo test'
    exit 1
fi
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_retry_clean_second_attempt|outcome=PASS'
PROBE

    retry_relative_script="${retry_probe_script#$REPO_ROOT/}"
    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    retry_gate_status=0
    RUN_GATE_RETRY_PROBE_STATE="$retry_state" \
        scripts/e2e/run_gate.sh --gate-id run_gate_retry_marker_contract --retries 1 "$retry_relative_script" \
        >"$retry_log" 2>&1 || retry_gate_status=$?
    [[ "$retry_gate_status" -eq 1 ]] || return 1

    retry_manifest_path=$(sed -n 's/^Manifest: //p' "$retry_log" | tail -n 1)
    [[ -n "$retry_manifest_path" && -f "$retry_manifest_path" ]] || return 1

    jq -e --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_retry_marker_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].verdict == "FAIL"
        and .script_results[0].attempts == 2
        and (.script_results[0].scenarios | length == 1)
        and .script_results[0].scenarios[0].scenario_id == "gate_retry_clean_second_attempt"
        and .script_results[0].scenarios[0].outcome == "PASS"
        and .script_results[0].rch_local_fallback_rejected_count == 1
        and .script_results[0].rch_local_fallback_rejections[0].marker == "RCH_LOCAL_FALLBACK_REJECTED|log=/tmp/rch-first.log|command=cargo test"
    ' "$retry_manifest_path" >/dev/null

    json_probe_script="$probe_dir/json_escape_script.sh"
    json_log="$probe_dir/run_gate_json_escape.log"
    json_gate_id='run_gate_json_"/slash_contract'

    cat >"$json_probe_script" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_json_escape_probe|outcome=PASS'
PROBE

    json_relative_script="${json_probe_script#$REPO_ROOT/}"
    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    json_gate_status=0
    scripts/e2e/run_gate.sh --gate-id "$json_gate_id" "$json_relative_script" \
        >"$json_log" 2>&1 || json_gate_status=$?
    [[ "$json_gate_status" -eq 0 ]] || return 1

    json_manifest_path=$(sed -n 's/^Manifest: //p' "$json_log" | tail -n 1)
    [[ -n "$json_manifest_path" && -f "$json_manifest_path" ]] || return 1

    jq -e --arg gate_id "$json_gate_id" --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == $gate_id
        and (.run_id | type == "string")
        and (.run_id | length > 0)
        and .git_context.clean == $expected_git_clean
        and .verdict == "PASS"
        and .scripts_failed == 0
        and (.script_results | length == 1)
        and .script_results[0].scenarios[0].scenario_id == "gate_json_escape_probe"
    ' "$json_manifest_path" >/dev/null

    fail_marker_script="$probe_dir/fail_marker_exit_zero_script.sh"
    fail_marker_log="$probe_dir/run_gate_fail_marker_exit_zero.log"

    cat >"$fail_marker_script" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_fail_marker_exit_zero|outcome=FAIL|detail=marker says fail'
PROBE

    fail_marker_relative_script="${fail_marker_script#$REPO_ROOT/}"
    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    fail_marker_gate_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_fail_marker_exit_zero_contract "$fail_marker_relative_script" \
        >"$fail_marker_log" 2>&1 || fail_marker_gate_status=$?
    [[ "$fail_marker_gate_status" -eq 1 ]] || return 1

    fail_marker_manifest_path=$(sed -n 's/^Manifest: //p' "$fail_marker_log" | tail -n 1)
    [[ -n "$fail_marker_manifest_path" && -f "$fail_marker_manifest_path" ]] || return 1

    jq -e --arg fail_marker_script "$fail_marker_relative_script" --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_fail_marker_exit_zero_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_total == 1
        and .scripts_passed == 0
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].script == $fail_marker_script
        and .script_results[0].verdict == "FAIL"
        and .script_results[0].attempts == 1
        and (.script_results[0].scenarios | length == 1)
        and .script_results[0].scenarios[0].scenario_id == "gate_fail_marker_exit_zero"
        and .script_results[0].scenarios[0].outcome == "FAIL"
        and .script_results[0].scenarios[0].detail == "marker says fail"
        and .script_results[0].rch_local_fallback_rejected_count == 0
        and .script_results[0].rch_local_fallback_rejections == []
    ' "$fail_marker_manifest_path" >/dev/null

    missing_gate_id_log="$probe_dir/run_gate_missing_gate_id_arg.log"
    missing_gate_id_status=0
    scripts/e2e/run_gate.sh --gate-id >"$missing_gate_id_log" 2>&1 || missing_gate_id_status=$?
    [[ "$missing_gate_id_status" -eq 1 ]] || return 1
    grep -Fq "ERROR: --gate-id requires a non-empty value" "$missing_gate_id_log" || return 1
    ! grep -Eq "unbound variable|syntax error|^Output: |^Manifest: " "$missing_gate_id_log" || return 1

    missing_retries_log="$probe_dir/run_gate_missing_retries_arg.log"
    missing_retries_status=0
    scripts/e2e/run_gate.sh --retries >"$missing_retries_log" 2>&1 || missing_retries_status=$?
    [[ "$missing_retries_status" -eq 1 ]] || return 1
    grep -Fq "ERROR: --retries requires a non-negative integer" "$missing_retries_log" || return 1
    ! grep -Eq "unbound variable|syntax error|^Output: |^Manifest: " "$missing_retries_log" || return 1

    bad_retries_log="$probe_dir/run_gate_bad_retries_arg.log"
    bad_retries_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_bad_retries_contract --retries nope "$json_relative_script" \
        >"$bad_retries_log" 2>&1 || bad_retries_status=$?
    [[ "$bad_retries_status" -eq 1 ]] || return 1
    grep -Fq "ERROR: --retries requires a non-negative integer" "$bad_retries_log" || return 1
    ! grep -Eq "unbound variable|syntax error|^Output: |^Manifest: " "$bad_retries_log" || return 1

    bad_catalog_repo="$probe_dir/bad_catalog_repo"
    bad_catalog_log="$probe_dir/run_gate_bad_catalog.log"
    mkdir -p "$bad_catalog_repo/scripts/e2e"
    cp scripts/e2e/run_gate.sh "$bad_catalog_repo/scripts/e2e/run_gate.sh"
    printf '{ bad catalog\n' >"$bad_catalog_repo/scripts/e2e/scenario_catalog.json"
    bad_catalog_status=0
    "$bad_catalog_repo/scripts/e2e/run_gate.sh" --gate-id run_gate_bad_catalog_contract --catalog \
        >"$bad_catalog_log" 2>&1 || bad_catalog_status=$?
    [[ "$bad_catalog_status" -eq 1 ]] || return 1
    grep -Fq "ERROR: failed to parse scenario catalog at " "$bad_catalog_log" || return 1
    ! grep -Eq "^No scripts to run\\.|^Output: |^Manifest: " "$bad_catalog_log" || return 1

    empty_catalog_repo="$probe_dir/empty_catalog_repo"
    empty_catalog_log="$probe_dir/run_gate_empty_catalog.log"
    mkdir -p "$empty_catalog_repo/scripts/e2e"
    cp scripts/e2e/run_gate.sh "$empty_catalog_repo/scripts/e2e/run_gate.sh"
    printf '{"suites":[]}\n' >"$empty_catalog_repo/scripts/e2e/scenario_catalog.json"
    empty_catalog_status=0
    "$empty_catalog_repo/scripts/e2e/run_gate.sh" --gate-id run_gate_empty_catalog_contract --catalog \
        >"$empty_catalog_log" 2>&1 || empty_catalog_status=$?
    [[ "$empty_catalog_status" -eq 1 ]] || return 1
    grep -Fq "ERROR: no scripts resolved for gate" "$empty_catalog_log" || return 1
    ! grep -Eq "^No scripts to run\\.|^Output: |^Manifest: " "$empty_catalog_log" || return 1

    path_escape_script="$probe_dir/../run_gate_path_escape_probe.sh"
    path_escape_relative_script="${path_escape_script#$REPO_ROOT/}"
    path_escape_log="$probe_dir/run_gate_path_escape.log"
    path_escape_executed="$probe_dir/path_escape_probe.executed"

    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -euo pipefail'
        printf 'printf executed >%q\n' "$path_escape_executed"
        printf '%s\n' "printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_path_escape_probe|outcome=PASS'"
    } >"$path_escape_script"

    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    path_escape_gate_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_path_escape_contract "$path_escape_relative_script" \
        >"$path_escape_log" 2>&1 || path_escape_gate_status=$?
    [[ "$path_escape_gate_status" -eq 1 ]] || return 1
    [[ ! -e "$path_escape_executed" ]] || return 1

    path_escape_manifest_path=$(sed -n 's/^Manifest: //p' "$path_escape_log" | tail -n 1)
    [[ -n "$path_escape_manifest_path" && -f "$path_escape_manifest_path" ]] || return 1

    jq -e --arg path_escape_script "$path_escape_relative_script" --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_path_escape_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_total == 1
        and .scripts_passed == 0
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].script == $path_escape_script
        and .script_results[0].verdict == "FAIL"
        and .script_results[0].attempts == 0
        and .script_results[0].scenarios == []
        and .script_results[0].rch_local_fallback_rejected_count == 0
        and .script_results[0].rch_local_fallback_rejections == []
        and (.script_results[0].error | contains("invalid script path"))
    ' "$path_escape_manifest_path" >/dev/null

    absolute_script="$probe_dir/run_gate_absolute_path_probe.sh"
    absolute_script_log="$probe_dir/run_gate_absolute_path.log"
    absolute_script_executed="$probe_dir/absolute_path_probe.executed"

    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -euo pipefail'
        printf 'printf executed >%q\n' "$absolute_script_executed"
        printf '%s\n' "printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_absolute_path_probe|outcome=PASS'"
    } >"$absolute_script"

    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    absolute_script_gate_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_absolute_path_contract "$absolute_script" \
        >"$absolute_script_log" 2>&1 || absolute_script_gate_status=$?
    [[ "$absolute_script_gate_status" -eq 1 ]] || return 1
    [[ ! -e "$absolute_script_executed" ]] || return 1

    absolute_script_manifest_path=$(sed -n 's/^Manifest: //p' "$absolute_script_log" | tail -n 1)
    [[ -n "$absolute_script_manifest_path" && -f "$absolute_script_manifest_path" ]] || return 1

    jq -e --arg absolute_script "$absolute_script" --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_absolute_path_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_total == 1
        and .scripts_passed == 0
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].script == $absolute_script
        and .script_results[0].verdict == "FAIL"
        and .script_results[0].attempts == 0
        and .script_results[0].scenarios == []
        and .script_results[0].rch_local_fallback_rejected_count == 0
        and .script_results[0].rch_local_fallback_rejections == []
        and (.script_results[0].error | contains("invalid script path"))
    ' "$absolute_script_manifest_path" >/dev/null

    missing_relative_script="artifacts/e2e/run_gate_marker_contract_missing_script.sh"
    missing_log="$probe_dir/run_gate_missing_script.log"
    missing_gate_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_missing_script_contract "$missing_relative_script" \
        >"$missing_log" 2>&1 || missing_gate_status=$?
    [[ "$missing_gate_status" -eq 1 ]] || return 1

    missing_manifest_path=$(sed -n 's/^Manifest: //p' "$missing_log" | tail -n 1)
    [[ -n "$missing_manifest_path" && -f "$missing_manifest_path" ]] || return 1

    jq -e --arg missing_script "$missing_relative_script" --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_missing_script_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_total == 1
        and .scripts_passed == 0
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].script == $missing_script
        and .script_results[0].verdict == "FAIL"
        and .script_results[0].attempts == 0
        and .script_results[0].scenarios == []
        and .script_results[0].rch_local_fallback_rejected_count == 0
        and .script_results[0].rch_local_fallback_rejections == []
        and (.script_results[0].error | contains("script not found:"))
    ' "$missing_manifest_path" >/dev/null

    conformance_probe_script="$probe_dir/bad_conformance_script.sh"
    conformance_log="$probe_dir/run_gate_conformance_failure.log"

    cat >"$conformance_probe_script" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'SCENARIO_RESULT|scenario_id=gate_conformance_probe|outcome=PASS'
PROBE

    conformance_relative_script="${conformance_probe_script#$REPO_ROOT/}"
    if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ]]; then
        expected_git_clean="true"
    else
        expected_git_clean="false"
    fi
    conformance_gate_status=0
    scripts/e2e/run_gate.sh --gate-id run_gate_conformance_failure_contract --conformance "$conformance_relative_script" \
        >"$conformance_log" 2>&1 || conformance_gate_status=$?
    [[ "$conformance_gate_status" -eq 1 ]] || return 1

    conformance_manifest_path=$(sed -n 's/^Manifest: //p' "$conformance_log" | tail -n 1)
    [[ -n "$conformance_manifest_path" && -f "$conformance_manifest_path" ]] || return 1

    jq -e --arg conformance_script "$conformance_relative_script" --argjson expected_git_clean "$expected_git_clean" '
        .gate_id == "run_gate_conformance_failure_contract"
        and .git_context.clean == $expected_git_clean
        and .verdict == "FAIL"
        and .scripts_total == 1
        and .scripts_passed == 0
        and .scripts_failed == 1
        and (.script_results | length == 1)
        and .script_results[0].script == $conformance_script
        and .script_results[0].verdict == "FAIL"
        and .script_results[0].attempts == 0
        and .script_results[0].scenarios == []
        and .script_results[0].rch_local_fallback_rejected_count == 0
        and .script_results[0].rch_local_fallback_rejections == []
        and (.script_results[0].error | contains("conformance violations"))
        and (.script_results[0].error | contains("missing e2e_init call"))
    ' "$conformance_manifest_path" >/dev/null
}

init_git_clean_probe_repo() {
    local repo_dir="$1"

    mkdir -p "$repo_dir"
    git -C "$repo_dir" init -q
    printf 'tracked\n' >"$repo_dir/tracked.txt"
    git -C "$repo_dir" add tracked.txt
    git -C "$repo_dir" \
        -c user.email=ffs-e2e@example.invalid \
        -c user.name=ffs-e2e \
        commit -q -m "initial"
}

verify_git_context_clean_dirty_states() {
    if ! command -v git >/dev/null 2>&1; then
        return 1
    fi

    local probe_root clean_repo staged_repo untracked_repo
    probe_root="$E2E_TEMP_DIR/git_context_clean_probe"
    clean_repo="$probe_root/clean"
    staged_repo="$probe_root/staged"
    untracked_repo="$probe_root/untracked"

    init_git_clean_probe_repo "$clean_repo" || return 1
    init_git_clean_probe_repo "$staged_repo" || return 1
    init_git_clean_probe_repo "$untracked_repo" || return 1

    printf 'changed\n' >>"$staged_repo/tracked.txt"
    git -C "$staged_repo" add tracked.txt
    printf 'untracked\n' >"$untracked_repo/new-file.txt"

    [[ "$(e2e_git_context_clean "$clean_repo")" == "true" ]] \
        && [[ "$(e2e_git_context_clean "$staged_repo")" == "false" ]] \
        && [[ "$(e2e_git_context_clean "$untracked_repo")" == "false" ]]
}

verify_e2e_init_artifact_dirs_unique() {
    local probe_name probe_root attempt
    probe_name="artifact_dir_unique_probe"
    probe_root="$E2E_TEMP_DIR/e2e_init_artifact_dir_probe"
    mkdir -p "$probe_root"

    for attempt in 1 2 3; do
        local first_out second_out first_pid second_pid first_dir second_dir
        local first_base second_base first_prefix second_prefix
        first_out="$probe_root/first_${attempt}.out"
        second_out="$probe_root/second_${attempt}.out"

        (
            set -euo pipefail
            cd "$REPO_ROOT"
            export REPO_ROOT
            export FFS_E2E_DISABLE_TEMP_CLEANUP=1
            source "$REPO_ROOT/scripts/e2e/lib.sh"
            e2e_init "$probe_name"
            printf 'E2E_PROBE_LOG_DIR=%s\n' "$E2E_LOG_DIR"
        ) >"$first_out" 2>&1 &
        first_pid=$!

        (
            set -euo pipefail
            cd "$REPO_ROOT"
            export REPO_ROOT
            export FFS_E2E_DISABLE_TEMP_CLEANUP=1
            source "$REPO_ROOT/scripts/e2e/lib.sh"
            e2e_init "$probe_name"
            printf 'E2E_PROBE_LOG_DIR=%s\n' "$E2E_LOG_DIR"
        ) >"$second_out" 2>&1 &
        second_pid=$!

        if ! wait "$first_pid"; then
            return 1
        fi
        if ! wait "$second_pid"; then
            return 1
        fi

        first_dir=$(sed -n 's/^E2E_PROBE_LOG_DIR=//p' "$first_out" | tail -n 1)
        second_dir=$(sed -n 's/^E2E_PROBE_LOG_DIR=//p' "$second_out" | tail -n 1)
        [[ -n "$first_dir" && -n "$second_dir" ]] || return 1
        [[ "$first_dir" != "$second_dir" ]] || return 1
        [[ -d "$first_dir" && -d "$second_dir" ]] || return 1

        first_base=$(basename "$first_dir")
        second_base=$(basename "$second_dir")
        first_prefix="${first_base%_*}"
        second_prefix="${second_base%_*}"

        if [[ "$first_prefix" == "$second_prefix" ]] \
            && [[ "$first_base" == *"${probe_name}_"* ]] \
            && [[ "$second_base" == *"${probe_name}_"* ]]; then
            return 0
        fi
    done

    return 1
}

verify_e2e_artifact_roots_are_collision_resistant() {
    local offenders
    offenders="$(
        grep -R -n -F \
            --include='*.sh' \
            --exclude='ffs_verification_runner_e2e.sh' \
            'artifacts/e2e/$(date +%Y%m%d_%H%M%S)' \
            "$REPO_ROOT/scripts/e2e" \
            2>/dev/null || true
    )"

    if [[ -n "$offenders" ]]; then
        printf '%s\n' "$offenders"
        return 1
    fi

    offenders="$(
        grep -R -n -E \
            --include='*.sh' \
            --exclude='ffs_verification_runner_e2e.sh' \
            'RUN_ID="\$\(date \+%Y%m%d_%H%M%S\)_' \
            "$REPO_ROOT/scripts/e2e" \
            2>/dev/null || true
    )"

    if [[ -n "$offenders" ]]; then
        printf '%s\n' "$offenders"
        return 1
    fi

    for required in \
        'mktemp -d "$LOG_ROOT/$(date +%Y%m%d_%H%M%S)_ffs_log_contract_XXXXXX"' \
        'mktemp -d "$E2E_LOG_ROOT/$(date +%Y%m%d_%H%M%S)_ffs_swarm_tail_latency_XXXXXX"' \
        'mktemp -d "$LOG_ROOT/$(date +%Y%m%d_%H%M%S)_ffs_writeback_cache_audit_XXXXXX"' \
        'mktemp -d "$artifact_root/${timestamp}_xfstests_preflight_XXXXXX"'; do
        if ! grep -R -Fq "$required" "$REPO_ROOT/scripts/e2e"; then
            printf 'missing required unique artifact allocation: %s\n' "$required"
            return 1
        fi
    done
}

verify_rch_required_artifact_missing_fails_fast() {
    local probe_dir fake_rch output_path missing_artifact status start elapsed
    probe_dir="$E2E_TEMP_DIR/rch_required_artifact_missing_probe"
    fake_rch="$probe_dir/rch"
    output_path="$probe_dir/capture.log"
    missing_artifact="$probe_dir/missing-required-artifact"

    mkdir -p "$probe_dir"
    cat >"$fake_rch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "exec" && "${2:-}" == "--" ]]; then
    printf '[RCH] remote worker=fake-required-artifact\n'
    printf 'Remote command finished: exit=0\n'
    while :; do
        sleep 1
    done
fi

if [[ "${1:-}" == "queue" && "${2:-}" == "--json" ]]; then
    printf '{"data":{"active_builds":[]}}\n'
    exit 0
fi

if [[ "${1:-}" == "cancel" ]]; then
    exit 0
fi

printf 'unsupported fake rch invocation\n' >&2
exit 2
SH
    chmod +x "$fake_rch"

    start=$SECONDS
    set +e
    RCH_BIN="$fake_rch" \
        RCH_COMMAND_TIMEOUT_SECS=20 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        RCH_REQUIRED_ARTIFACT="$missing_artifact" \
        e2e_rch_capture "$output_path" cargo build -p fake-required-artifact
    status=$?
    set -e
    elapsed=$((SECONDS - start))

    [[ "$status" -eq 99 ]] \
        && ((elapsed < 20)) \
        && grep -Fq "RCH_REQUIRED_ARTIFACT_MISSING" "$output_path"
}

verify_catalog_id_pattern_sample_rejects_bad_patterns() {
    local probe_dir bad_catalog probe_log status
    probe_dir="$E2E_TEMP_DIR/catalog_id_pattern_sample_probe"
    bad_catalog="$probe_dir/bad_scenario_catalog.json"
    probe_log="$probe_dir/catalog_validation.log"

    mkdir -p "$probe_dir"
    cat >"$bad_catalog" <<'JSON'
{
  "catalog_version": "probe",
  "scenario_id_regex": "^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$",
  "taxonomy": ["error"],
  "suites": [
    {
      "suite_id": "bad_catalog_probe",
      "script": "scripts/e2e/bad_catalog_probe.sh",
      "required_categories": ["error"],
      "scenarios": [
        {
          "id_pattern": "^bad_[A-Z]+$",
          "category": "error",
          "status": "active",
          "evidence": "bad_catalog_probe"
        }
      ]
    }
  ]
}
JSON

    set +e
    (
        cd "$REPO_ROOT"
        export REPO_ROOT
        E2E_LOG_FILE="$probe_log" e2e_validate_scenario_catalog "$bad_catalog"
    ) >"$probe_dir/stdout.log" 2>"$probe_dir/stderr.log"
    status=$?
    set -e

    [[ "$status" -ne 0 ]] \
        && grep -Fq "generated id_pattern sample does not match scenario_id_regex" "$probe_log"
}

verify_catalog_rejects_uncataloged_static_scenario_result() {
    local probe_dir bad_catalog probe_script probe_log status
    probe_dir="$E2E_TEMP_DIR/catalog_uncataloged_static_probe"
    bad_catalog="$probe_dir/scenario_catalog.json"
    probe_script="$probe_dir/scripts/e2e/bad_catalog_probe_e2e.sh"
    probe_log="$probe_dir/catalog_validation.log"

    mkdir -p "$(dirname "$probe_script")"
    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'scenario_result "cataloged_probe_case" "PASS" "cataloged"'
        printf '%s\n' 'scenario_result "uncataloged_probe_case" "PASS" "uncataloged"'
    } >"$probe_script"

    cat >"$bad_catalog" <<'JSON'
{
  "catalog_version": "probe",
  "scenario_id_regex": "^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$",
  "taxonomy": ["happy"],
  "suites": [
    {
      "suite_id": "bad_catalog_probe",
      "script": "scripts/e2e/bad_catalog_probe_e2e.sh",
      "required_categories": ["happy"],
      "scenarios": [
        {
          "id": "cataloged_probe_case",
          "category": "happy",
          "status": "active",
          "evidence": "SCENARIO_RESULT|scenario_id=cataloged_probe_case|outcome=PASS"
        }
      ]
    }
  ]
}
JSON

    set +e
    (
        cd "$probe_dir"
        REPO_ROOT="$probe_dir" E2E_LOG_FILE="$probe_log" e2e_validate_scenario_catalog "$bad_catalog"
    ) >"$probe_dir/stdout.log" 2>"$probe_dir/stderr.log"
    status=$?
    set -e

    [[ "$status" -ne 0 ]] \
        && grep -Fq "script emits uncataloged static scenario IDs: uncataloged_probe_case" "$probe_log"
}

verify_verification_gate_catalog_valid_uses_full_validator() {
    local gate_path block_path
    gate_path="$REPO_ROOT/scripts/e2e/ffs_verification_gate_e2e.sh"
    block_path="$E2E_TEMP_DIR/verification_gate_catalog_validation_block.txt"

    awk '
        /^# Scenario 4: Scenario catalog validates/ { in_block = 1 }
        in_block { print }
        /^# Scenario 5: Cross-epic script conformance/ { exit }
    ' "$gate_path" >"$block_path"

    grep -Fq 'e2e_validate_scenario_catalog "$CATALOG"' "$block_path" \
        && grep -Fq 'scenario_result "scenario_catalog_valid" "PASS"' "$block_path" \
        && grep -Fq 'scenario_result "scenario_catalog_valid" "FAIL"' "$block_path" \
        && grep -Fq 'scenario_catalog_validation.log' "$block_path" \
        && ! grep -Fq 'CATALOG_FIELDS=0' "$block_path" \
        && ! grep -Fq 'Duplicate IDs found' "$block_path"
}

e2e_init "ffs_verification_runner"

RUNNER_SRC="crates/ffs-harness/src/verification_runner.rs"
LIB_SH="scripts/e2e/lib.sh"
GATE_SH="scripts/e2e/run_gate.sh"
FUSE_PROD_SH="scripts/e2e/ffs_fuse_production.sh"
MOUNTED_WRITE_ERROR_CLASSES_SH="scripts/e2e/ffs_mounted_write_error_classes_e2e.sh"
E2E_README="scripts/e2e/README.md"

#######################################
# Scenario 1: verification_runner module exists
#######################################
e2e_step "Scenario 1: verification_runner module exists"

if [[ -f "$RUNNER_SRC" ]]; then
    scenario_result "runner_module_exists" "PASS" "verification_runner.rs present"
else
    scenario_result "runner_module_exists" "FAIL" "verification_runner.rs missing"
fi

#######################################
# Scenario 2: Core types present
#######################################
e2e_step "Scenario 2: Core runner types present"

TYPES_FOUND=0
for pattern in "pub struct ParsedScenario" "pub struct RunnerConfig" "pub struct ScriptRunResult" "pub struct ManifestParams" "pub const RUNNER_CONTRACT_VERSION"; do
    if grep -q "$pattern" "$RUNNER_SRC"; then
        TYPES_FOUND=$((TYPES_FOUND + 1))
    fi
done

if [[ $TYPES_FOUND -eq 5 ]]; then
    scenario_result "runner_core_types" "PASS" "All 5 core types/constants present"
else
    scenario_result "runner_core_types" "FAIL" "Only ${TYPES_FOUND}/5 core types found"
fi

#######################################
# Scenario 3: API functions present
#######################################
e2e_step "Scenario 3: API functions present"

FUNCS_FOUND=0
for func in "pub fn parse_e2e_output" "pub fn build_manifest_from_parsed" "pub fn check_script_conformance" "pub fn aggregate_verdict" "pub fn merge_scenarios"; do
    if grep -q "$func" "$RUNNER_SRC"; then
        FUNCS_FOUND=$((FUNCS_FOUND + 1))
    fi
done

if [[ $FUNCS_FOUND -eq 5 ]]; then
    scenario_result "runner_api_functions" "PASS" "All 5 API functions present"
else
    scenario_result "runner_api_functions" "FAIL" "Only ${FUNCS_FOUND}/5 API functions found"
fi

#######################################
# Scenario 4: lib.sh JSON emission
#######################################
e2e_step "Scenario 4: lib.sh JSON emission support"

LIB_FEATURES=0
for feature in "e2e_emit_json_summary" "e2e_retry" "E2E_TEST_NAME" "result.json"; do
    if grep -q "$feature" "$LIB_SH"; then
        LIB_FEATURES=$((LIB_FEATURES + 1))
    fi
done

if [[ $LIB_FEATURES -eq 4 ]]; then
    scenario_result "lib_json_emission" "PASS" "All 4 lib.sh features present"
else
    scenario_result "lib_json_emission" "FAIL" "Only ${LIB_FEATURES}/4 features found"
fi

#######################################
# Scenario 4b: lib.sh preserves suite result fields
#######################################
e2e_step "Scenario 4b: lib.sh JSON summary preserves suite fields"

if verify_lib_summary_preserves_suite_fields; then
    scenario_result "lib_json_summary_preserves_suite_fields" "PASS" "Suite-specific result fields preserved"
else
    scenario_result "lib_json_summary_preserves_suite_fields" "FAIL" "Suite-specific result fields were not preserved"
fi

#######################################
# Scenario 4c: lib.sh git cleanliness catches dirty states
#######################################
e2e_step "Scenario 4c: lib.sh git cleanliness dirty-state detection"

if verify_git_context_clean_dirty_states; then
    scenario_result "lib_git_context_clean_dirty_states" "PASS" "Clean, staged, and untracked states classified correctly"
else
    scenario_result "lib_git_context_clean_dirty_states" "FAIL" "Git cleanliness dirty-state classification failed"
fi

#######################################
# Scenario 4d: lib.sh E2E artifact directories are collision-resistant
#######################################
e2e_step "Scenario 4d: lib.sh E2E artifact directory uniqueness"

if verify_e2e_init_artifact_dirs_unique; then
    scenario_result "lib_e2e_artifact_dirs_unique" "PASS" "Concurrent E2E starts received distinct log directories"
else
    scenario_result "lib_e2e_artifact_dirs_unique" "FAIL" "Concurrent E2E starts shared or malformed log directories"
fi

#######################################
# Scenario 4e: standalone E2E artifact roots are collision-resistant
#######################################
e2e_step "Scenario 4e: standalone E2E artifact root uniqueness"

if verify_e2e_artifact_roots_are_collision_resistant; then
    scenario_result "standalone_e2e_artifact_roots_unique" "PASS" "Standalone E2E scripts use unique artifact roots"
else
    scenario_result "standalone_e2e_artifact_roots_unique" "FAIL" "Standalone E2E scripts still use collision-prone artifact roots"
fi

#######################################
# Scenario 4f: lib.sh RCH required artifacts fail closed
#######################################
e2e_step "Scenario 4f: lib.sh RCH required artifact missing fail-closed"

if e2e_rch_capture_fixture_matrix_self_test >/dev/null \
    && verify_rch_required_artifact_missing_fails_fast; then
    scenario_result "lib_rch_required_artifact_missing_fails_fast" "PASS" "Missing required artifact returned 99 before command timeout"
else
    scenario_result "lib_rch_required_artifact_missing_fails_fast" "FAIL" "Missing required artifact did not fail closed promptly"
fi

#######################################
# Scenario 4g: scenario catalog id_pattern samples fail closed
#######################################
e2e_step "Scenario 4g: scenario catalog id_pattern sample fail-closed check"

if verify_catalog_id_pattern_sample_rejects_bad_patterns; then
    scenario_result "catalog_id_pattern_sample_rejects_bad_patterns" "PASS" "Invalid id_pattern sample rejected by scenario_id_regex"
else
    scenario_result "catalog_id_pattern_sample_rejects_bad_patterns" "FAIL" "Invalid id_pattern sample was not rejected"
fi

#######################################
# Scenario 4h: scenario catalog rejects uncataloged static scenario IDs
#######################################
e2e_step "Scenario 4h: scenario catalog uncataloged static scenario-result fail-closed check"

if verify_catalog_rejects_uncataloged_static_scenario_result; then
    scenario_result "catalog_rejects_uncataloged_static_scenario_result" "PASS" "Static scenario_result IDs absent from the catalog are rejected"
else
    scenario_result "catalog_rejects_uncataloged_static_scenario_result" "FAIL" "Uncataloged static scenario_result ID was not rejected"
fi

#######################################
# Scenario 4i: verification gate catalog-valid marker uses full validator
#######################################
e2e_step "Scenario 4i: verification gate scenario_catalog_valid uses full validator"

if verify_verification_gate_catalog_valid_uses_full_validator; then
    scenario_result "verification_gate_catalog_valid_full_validator" "PASS" "scenario_catalog_valid is backed by e2e_validate_scenario_catalog"
else
    scenario_result "verification_gate_catalog_valid_full_validator" "FAIL" "scenario_catalog_valid still has a shallow catalog check"
fi

#######################################
# Scenario 5: run_gate.sh runner exists
#######################################
e2e_step "Scenario 5: run_gate.sh runner wrapper"

GATE_FEATURES=0
for feature in "--gate-id" "--ci" "--retries" "--catalog" "--conformance" "gate_manifest.json"; do
    if grep -q -- "$feature" "$GATE_SH"; then
        GATE_FEATURES=$((GATE_FEATURES + 1))
    fi
done

if [[ $GATE_FEATURES -eq 6 ]] && verify_run_gate_marker_contract; then
    scenario_result "gate_runner_features" "PASS" "All 6 runner features present; marker contract probe passed"
else
    scenario_result "gate_runner_features" "FAIL" "Feature count ${GATE_FEATURES}/6 or marker contract probe failed"
fi

#######################################
# Scenario 6: Unit tests pass
#######################################
e2e_step "Scenario 6: verification_runner unit tests"

TEST_LOG="$E2E_LOG_DIR/verification_runner_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- verification_runner; then
    TESTS_RUN=$(grep -c "test verification_runner::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "runner_unit_tests" "PASS" "Unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "runner_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "runner_unit_tests" "FAIL" "Unit tests failed"
fi

#######################################
# Scenario 7: Structured logging markers
#######################################
e2e_step "Scenario 7: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "verification_runner_manifest_built"; do
    if grep -q "\"${marker}\"" "$RUNNER_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 1 ]]; then
    scenario_result "runner_logging_markers" "PASS" "Structured logging markers present"
else
    scenario_result "runner_logging_markers" "FAIL" "Missing structured logging markers"
fi

#######################################
# Scenario 8: Conformance checker detects violations
#######################################
e2e_step "Scenario 8: Conformance violation detection"

# The Rust tests cover violation detection; verify the test names exist
VIOLATION_TESTS=0
for test_name in "conformant_script_has_no_violations" "script_missing_lib_source_detected" "script_missing_strict_mode_detected" "conformance_missing_everything_reports_all_violations"; do
    if grep -q "fn ${test_name}" "$RUNNER_SRC"; then
        VIOLATION_TESTS=$((VIOLATION_TESTS + 1))
    fi
done

if [[ $VIOLATION_TESTS -eq 4 ]]; then
    scenario_result "conformance_violation_tests" "PASS" "All 4 conformance tests present"
else
    scenario_result "conformance_violation_tests" "FAIL" "Only ${VIOLATION_TESTS}/4 conformance tests found"
fi

#######################################
# Scenario 9: Exit code conventions documented
#######################################
e2e_step "Scenario 9: Exit code conventions"

EXIT_CODE_PATTERNS=0
for pattern in "pub const PASS: i32 = 0" "pub const FAIL: i32 = 1"; do
    if grep -q "$pattern" "$RUNNER_SRC"; then
        EXIT_CODE_PATTERNS=$((EXIT_CODE_PATTERNS + 1))
    fi
done

if [[ $EXIT_CODE_PATTERNS -eq 2 ]]; then
    scenario_result "exit_code_conventions" "PASS" "Exit code constants defined"
else
    scenario_result "exit_code_conventions" "FAIL" "Only ${EXIT_CODE_PATTERNS}/2 exit code constants found"
fi

#######################################
# Scenario 10: Permissioned FUSE lane artifacts
#######################################
e2e_step "Scenario 10: Permissioned FUSE lane artifacts"

FUSE_LANE_FEATURES=0
for feature in \
    "FUSE_CAPABILITY_JSON" \
    "fuse_permissioned_lane.json" \
    "e2e_probe_fuse_capability" \
    "--require-mount-probe" \
    "--mount-probe-exit" \
    "--unmount-probe-exit" \
    "emit_permissioned_lane_summary" \
    "fusermount_version" \
    "qa_artifacts"; do
    if grep -q -- "$feature" "$FUSE_PROD_SH"; then
        FUSE_LANE_FEATURES=$((FUSE_LANE_FEATURES + 1))
    fi
done

if [[ $FUSE_LANE_FEATURES -eq 9 ]]; then
    scenario_result "permissioned_fuse_lane_artifacts" "PASS" "All 9 FUSE lane artifact hooks present"
else
    scenario_result "permissioned_fuse_lane_artifacts" "FAIL" "Only ${FUSE_LANE_FEATURES}/9 FUSE lane hooks found"
fi

if grep -Eq 'cargo run( --quiet)? -p ffs-harness|cargo run .* -p ffs-harness' scripts/e2e/lib.sh; then
    scenario_result "permissioned_fuse_lane_rch_harness_binary" "FAIL" "shared FUSE capability helper still has a local cargo fallback"
else
    scenario_result "permissioned_fuse_lane_rch_harness_binary" "PASS" "shared FUSE capability helper requires a prebuilt FFS_HARNESS_BIN"
fi

#######################################
# Scenario 11: Permissioned btrfs lane controls
#######################################
e2e_step "Scenario 11: Permissioned btrfs lane controls"

BTRFS_LANE_FEATURES=0
for feature in \
    "FFS_RUN_BTRFS_LANE_PROBE" \
    "FFS_REQUIRE_BTRFS_LANE_PROBE" \
    "fuse_lane_btrfs_mount_unmount_probe"; do
    if grep -q "$feature" "$FUSE_PROD_SH"; then
        BTRFS_LANE_FEATURES=$((BTRFS_LANE_FEATURES + 1))
    fi
done

if [[ $BTRFS_LANE_FEATURES -eq 3 ]]; then
    scenario_result "permissioned_btrfs_lane_controls" "PASS" "Btrfs lane controls present"
else
    scenario_result "permissioned_btrfs_lane_controls" "FAIL" "Only ${BTRFS_LANE_FEATURES}/3 btrfs lane controls found"
fi

#######################################
# Scenario 12: Mounted write error-class RCH guardrails
#######################################
e2e_step "Scenario 12: Mounted write error-class RCH guardrails"

if grep -Eq 'exec[[:space:]]+--[[:space:]]+bash|bash[[:space:]]+-c' "$MOUNTED_WRITE_ERROR_CLASSES_SH"; then
    scenario_result "mounted_write_error_classes_direct_rch_cargo" "FAIL" "mounted write suite still wraps cargo in rch exec -- bash"
elif grep -q "e2e_rch_capture" "$MOUNTED_WRITE_ERROR_CLASSES_SH" \
    && grep -q "validate-mounted-write-error-classes" "$MOUNTED_WRITE_ERROR_CLASSES_SH"; then
    scenario_result "mounted_write_error_classes_direct_rch_cargo" "PASS" "mounted write suite uses shared RCH capture with direct cargo commands"
else
    scenario_result "mounted_write_error_classes_direct_rch_cargo" "FAIL" "mounted write suite is missing shared RCH capture markers"
fi

#######################################
# Scenario 13: Permissioned lane documentation
#######################################
e2e_step "Scenario 13: Permissioned lane documentation"

FUSE_LANE_DOCS=0
for feature in \
    "Permissioned FUSE Lane" \
    "FFS_RUN_BTRFS_LANE_PROBE=1" \
    "FFS_REQUIRE_BTRFS_LANE_PROBE=1" \
    "FUSE-capable worker shell command" \
    "fuse_capability.json" \
    "fuse_permissioned_lane.json"; do
    if grep -q "$feature" "$E2E_README"; then
        FUSE_LANE_DOCS=$((FUSE_LANE_DOCS + 1))
    fi
done

if grep -Eq 'rch[[:space:]]+exec[[:space:]]+--[[:space:]]+bash|bash[[:space:]]+-lc.*ffs_fuse_production' "$E2E_README"; then
    scenario_result "permissioned_fuse_lane_docs" "FAIL" "permissioned FUSE docs still wrap the mounted lane in a shell command"
elif [[ $FUSE_LANE_DOCS -eq 6 ]]; then
    scenario_result "permissioned_fuse_lane_docs" "PASS" "Permissioned lane docs present"
else
    scenario_result "permissioned_fuse_lane_docs" "FAIL" "Only ${FUSE_LANE_DOCS}/6 documentation markers found"
fi

#######################################
# Scenario 14: Mounted scenario matrix artifacts
#######################################
e2e_step "Scenario 14: Mounted scenario matrix artifacts"

MOUNTED_MATRIX_FEATURES=0
for feature in \
    "MOUNTED_MATRIX_JSON" \
    "mounted_scenario_matrix.json" \
    "emit_mounted_matrix" \
    "record_matrix_result" \
    'SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}' \
    "bd-rchk4.3" \
    "operation_sequence" \
    "expected_outcome" \
    "artifact_paths"; do
    if grep -q -- "$feature" "$FUSE_PROD_SH"; then
        MOUNTED_MATRIX_FEATURES=$((MOUNTED_MATRIX_FEATURES + 1))
    fi
done

if [[ $MOUNTED_MATRIX_FEATURES -eq 9 ]]; then
    scenario_result "mounted_scenario_matrix_artifacts" "PASS" "All 9 mounted matrix hooks present"
else
    scenario_result "mounted_scenario_matrix_artifacts" "FAIL" "Only ${MOUNTED_MATRIX_FEATURES}/9 mounted matrix hooks found"
fi

#######################################
# Scenario 15: Btrfs mounted production rows
#######################################
e2e_step "Scenario 15: Btrfs mounted production rows"

BTRFS_MOUNTED_ROWS=0
for feature in \
    "Phase 7: btrfs mounted read-only smoke" \
    "btrfs_ro_mount_start" \
    "btrfs_ro_stat_root" \
    "btrfs_ro_list_root" \
    "btrfs_ro_mount_stop" \
    'FFS_RUN_BTRFS_LANE_PROBE="${FFS_RUN_BTRFS_LANE_PROBE:-1}"'; do
    if grep -q -- "$feature" "$FUSE_PROD_SH"; then
        BTRFS_MOUNTED_ROWS=$((BTRFS_MOUNTED_ROWS + 1))
    fi
done

if [[ $BTRFS_MOUNTED_ROWS -eq 6 ]]; then
    scenario_result "mounted_btrfs_production_rows" "PASS" "Btrfs mounted smoke rows present"
else
    scenario_result "mounted_btrfs_production_rows" "FAIL" "Only ${BTRFS_MOUNTED_ROWS}/6 btrfs mounted rows found"
fi

#######################################
# Scenario 16: Scenario catalog covers production FUSE matrix
#######################################
e2e_step "Scenario 16: Scenario catalog covers production FUSE matrix"

CATALOG_MATRIX_ROWS=0
for feature in \
    "ffs_fuse_production" \
    "fuse_prod_fuse_lane_ext4_mount_unmount_probe" \
    "fuse_prod_fuse_lane_btrfs_mount_unmount_probe" \
    "fuse_prod_btrfs_ro_mount_start" \
    "fuse_prod_btrfs_ro_stat_root" \
    "fuse_prod_btrfs_ro_list_root" \
    "fuse_prod_btrfs_fixture_missing" \
    "fuse_prod_xattr_tools_unavailable"; do
    if grep -q -- "$feature" "scripts/e2e/scenario_catalog.json"; then
        CATALOG_MATRIX_ROWS=$((CATALOG_MATRIX_ROWS + 1))
    fi
done

if [[ $CATALOG_MATRIX_ROWS -eq 8 ]]; then
    scenario_result "catalog_production_fuse_matrix" "PASS" "Production FUSE matrix catalog rows present"
else
    scenario_result "catalog_production_fuse_matrix" "FAIL" "Only ${CATALOG_MATRIX_ROWS}/8 catalog rows found"
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
