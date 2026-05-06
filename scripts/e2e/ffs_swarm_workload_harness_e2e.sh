#!/usr/bin/env bash
# ffs_swarm_workload_harness_e2e.sh - smoke gate for bd-p2j3e.2 / bd-rchk0.53.3.
#
# Validates the NUMA-aware swarm workload harness contract and the
# permission-aware E2E runner contract. The default lane is safe: it emits
# dry-run/smoke artifacts and permissioned-run blockers without starting
# destructive or high-load filesystem workloads.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export CARGO_TARGET_DIR="${FFS_SWARM_WORKLOAD_CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_workload_harness}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"
REFERENCE_TIMESTAMP="${FFS_SWARM_WORKLOAD_REFERENCE_TIMESTAMP:-2026-05-06T00:00:00Z}"
PERMISSIONED_ACK_TOKEN="swarm-workload-may-use-permissioned-large-host"
ENABLE_PERMISSIONED="${FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD:-0}"
PERMISSIONED_REAL_RUN_ACK="${FFS_SWARM_WORKLOAD_REAL_RUN_ACK:-}"
PERMISSIONED_RUNNER="${FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER:-}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
E2E_START_TIME="$(date +%s)"
E2E_LOG_DIR="${REPO_ROOT}/artifacts/e2e/$(date +%Y%m%d_%H%M%S)_ffs_swarm_workload_harness"
E2E_LOG_FILE="${E2E_LOG_DIR}/run.log"
COMMAND_TRANSCRIPT="${E2E_LOG_DIR}/command_transcript.tsv"
WORKER_IDENTITY="${RCH_WORKER_IDENTITY:-${RCH_WORKER:-local:$(hostname -s 2>/dev/null || printf unknown)}}"
RUNNER_CLEANUP_STATUS="partial_artifacts_preserved"
CURRENT_SCENARIO_ID="startup"

mkdir -p "$E2E_LOG_DIR"
printf 'created_at\tscenario_id\texit_status\tcommand\tstdout_path\tstderr_path\tworker_identity\n' >"$COMMAND_TRANSCRIPT"

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
  "gate_id": "ffs_swarm_workload_harness",
  "created_at": "$(date -Iseconds)",
  "verdict": "${verdict}",
  "summary": "${summary}",
  "pass_count": ${PASS_COUNT},
  "fail_count": ${FAIL_COUNT},
  "total": ${TOTAL},
  "duration_secs": ${duration},
  "log_file": "${E2E_LOG_FILE}",
  "command_transcript": "${COMMAND_TRANSCRIPT}",
  "worker_identity": "${WORKER_IDENTITY}",
  "cleanup_status": "${RUNNER_CLEANUP_STATUS}",
  "manifest_path": "${LOCAL_SMOKE_MANIFEST:-}",
  "report_path": "${LOCAL_SMOKE_REPORT_JSON:-}",
  "permissioned_blocker_path": "${PERMISSIONED_BLOCKER_JSON:-}",
  "artifact_paths": [
    "${REPORT_JSON:-}",
    "${REPORT_MD_RAW:-}",
    "${LOCAL_SMOKE_MANIFEST:-}",
    "${LOCAL_SMOKE_REPORT_JSON:-}",
    "${PERMISSIONED_BLOCKER_JSON:-}",
    "${COMMAND_TRANSCRIPT}"
  ]
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

record_command() {
    local scenario_id="$1"
    local exit_status="$2"
    local command_text="$3"
    local stdout_path="$4"
    local stderr_path="$5"
    command_text="${command_text//$'\t'/ }"
    command_text="${command_text//$'\n'/ }"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Iseconds)" \
        "$scenario_id" \
        "$exit_status" \
        "$command_text" \
        "$stdout_path" \
        "$stderr_path" \
        "$WORKER_IDENTITY" >>"$COMMAND_TRANSCRIPT"
}

run_rch_capture() {
    local output_path="$1"
    shift
    local status
    local command_text="$*"

    set +e
    RCH_VISIBILITY=none timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1
    status=$?
    set -e
    record_command "${CURRENT_SCENARIO_ID:-unknown}" "$status" "$command_text" "$output_path" "$output_path"

    if [[ $status -eq 0 ]]; then
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

run_rch_stdout_capture() {
    local output_path="$1"
    shift
    local status
    local rch_log_path="${output_path}.rch.log"
    local command_text="$*"

    set +e
    RCH_VISIBILITY=none timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "${RCH_BIN:-rch}" exec -- bash -lc '
        set -euo pipefail
        stdout_path="${CARGO_TARGET_DIR}/e2e_stdout/stdout.$$"
        mkdir -p "$(dirname "$stdout_path")"
        set +e
        "$@" >"$stdout_path"
        status=$?
        set -e
        printf "%s\n" "__FFS_REMOTE_STDOUT_BEGIN__"
        cat "$stdout_path"
        printf "%s\n" "__FFS_REMOTE_STDOUT_END__"
        exit "$status"
    ' _ "$@" >"$rch_log_path" 2>&1
    status=$?
    set -e
    record_command "${CURRENT_SCENARIO_ID:-unknown}" "$status" "$command_text" "$output_path" "$rch_log_path"

    if [[ $status -eq 0 ]] || { [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$rch_log_path"; }; then
        awk '
            $0 == "__FFS_REMOTE_STDOUT_BEGIN__" { capture = 1; next }
            $0 == "__FFS_REMOTE_STDOUT_END__" { found = 1; capture = 0; next }
            capture { print }
            END { exit found ? 0 : 1 }
        ' "$rch_log_path" >"$output_path"
        if [[ $status -eq 124 ]]; then
            e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}|rch_log=${rch_log_path}|command=$*"
        fi
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
    local reference_timestamp="${7:-$REFERENCE_TIMESTAMP}"

    jq "$jq_filter" "$source_json" >"$local_mutated_json"
    if run_rch_capture "$output_path" bash -lc '
        set -euo pipefail
        jq_filter="$1"
        source_json="$2"
        local_mutated_json="$3"
        validator="$4"
        path_flag="$5"
        reference_timestamp="$6"
        remote_mutated_json="${CARGO_TARGET_DIR}/e2e_mutations/$(basename "$local_mutated_json")"
        mkdir -p "$(dirname "$remote_mutated_json")"
        jq "$jq_filter" "$source_json" >"$remote_mutated_json"
        cargo run --quiet -p ffs-harness -- "$validator" "$path_flag" "$remote_mutated_json" --reference-timestamp "$reference_timestamp"
    ' _ "$jq_filter" "$source_json" "$local_mutated_json" "$validator" "$path_flag" "$reference_timestamp"; then
        if grep -q '^error:' "$output_path"; then
            set +e
            return 1
        fi
        return 0
    else
        local rch_status=$?
        set +e
        return "$rch_status"
    fi
}

permissioned_missing_prerequisites() {
    if [[ "$ENABLE_PERMISSIONED" != "1" ]]; then
        printf '%s\n' "missing_FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD"
    fi
    if [[ "$PERMISSIONED_REAL_RUN_ACK" != "$PERMISSIONED_ACK_TOKEN" ]]; then
        printf '%s\n' "missing_FFS_SWARM_WORKLOAD_REAL_RUN_ACK"
    fi
    if [[ -z "$PERMISSIONED_RUNNER" ]]; then
        printf '%s\n' "missing_FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER"
    elif [[ "$PERMISSIONED_RUNNER" == */* && ! -x "$PERMISSIONED_RUNNER" ]]; then
        printf '%s\n' "non_executable_FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER"
    elif [[ "$PERMISSIONED_RUNNER" != */* ]] && ! command -v "$PERMISSIONED_RUNNER" >/dev/null 2>&1; then
        printf '%s\n' "unresolved_FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER"
    fi
}

permissioned_blocker_reason() {
    local missing=("$@")
    if ((${#missing[@]} == 1)) && [[ "${missing[0]}" == "missing_FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD" ]]; then
        printf '%s\n' "permissioned large-host swarm workload execution is disabled by default"
    elif ((${#missing[@]} == 1)) && [[ "${missing[0]}" == "missing_FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER" ]]; then
        printf '%s\n' "permissioned large-host swarm workload runner is not configured on this host"
    else
        printf '%s\n' "permissioned large-host swarm workload prerequisites are not satisfied on this host"
    fi
}

permissioned_rerun_command() {
    printf 'FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=%s FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER=/path/to/runner %s\n' \
        "$PERMISSIONED_ACK_TOKEN" \
        "./scripts/e2e/ffs_swarm_workload_harness_e2e.sh"
}

write_permissioned_blocker() {
    local missing=("$@")
    local reason joined_missing rerun_command
    reason="$(permissioned_blocker_reason "${missing[@]}")"
    joined_missing="$(IFS='|'; printf '%s' "${missing[*]}")"
    rerun_command="$(permissioned_rerun_command)"

    printf 'permissioned large-host swarm workload was not started: %s\n' "$reason" >"$PERMISSIONED_STDOUT"
    : >"$PERMISSIONED_STDERR"

    jq -n \
        --arg created_at "$(date -Iseconds)" \
        --arg reason "$reason" \
        --arg missing "$joined_missing" \
        --arg ack_env "FFS_SWARM_WORKLOAD_REAL_RUN_ACK" \
        --arg ack_value "$PERMISSIONED_ACK_TOKEN" \
        --arg rerun_command "$rerun_command" \
        --arg stdout_path "$PERMISSIONED_STDOUT" \
        --arg stderr_path "$PERMISSIONED_STDERR" \
        --arg command_transcript "$COMMAND_TRANSCRIPT" \
        --arg worker_identity "$WORKER_IDENTITY" \
        --arg manifest_path "$LOCAL_SMOKE_MANIFEST" \
        --arg report_path "$LOCAL_SMOKE_REPORT_JSON" \
        '{
          schema_version: 1,
          runner_contract_version: 1,
          gate_id: "ffs_swarm_workload_harness",
          scenario_id: "swarm_workload_permissioned_large_host_blocked",
          created_at: $created_at,
          verdict: "skip",
          classification: "capability_skip",
          release_claim_state: "blocked",
          permissioned_execution_attempted: false,
          cleanup_status: "not_started_dry_run",
          skip_reason: $reason,
          missing_prerequisites: ($missing | split("|") | map(select(length > 0))),
          required_ack: { env: $ack_env, value: $ack_value },
          rerun_command: $rerun_command,
          stdout_path: $stdout_path,
          stderr_path: $stderr_path,
          command_transcript: $command_transcript,
          worker_identity: $worker_identity,
          artifact_paths: [$manifest_path, $report_path, $stdout_path, $stderr_path, $command_transcript]
        }' >"$PERMISSIONED_BLOCKER_JSON"
}

validate_permissioned_blocker() {
    jq -e \
        --arg ack_value "$PERMISSIONED_ACK_TOKEN" \
        '.permissioned_execution_attempted == false
         and .cleanup_status == "not_started_dry_run"
         and .release_claim_state == "blocked"
         and .classification == "capability_skip"
         and (.missing_prerequisites | length) >= 1
         and .required_ack.env == "FFS_SWARM_WORKLOAD_REAL_RUN_ACK"
         and .required_ack.value == $ack_value
         and (.rerun_command | contains("FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1"))
         and (.stdout_path | length > 0)
         and (.stderr_path | length > 0)
         and (.command_transcript | length > 0)' \
        "$PERMISSIONED_BLOCKER_JSON" >/dev/null
}

write_local_smoke_manifest() {
    local generated_at host_name host_fingerprint cpu_cores ram_total_gb ram_available_gb node_count
    local numa_observable numa_missing_reason permissioned_reason rerun_command
    generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    host_name="$(hostname -s 2>/dev/null || printf unknown)"
    host_fingerprint="local-smoke-${host_name}-$(date -u +%Y%m%d%H%M%S)"
    cpu_cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)"
    ram_total_gb="$(awk '/MemTotal:/ { printf "%.1f", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || printf 1.0)"
    ram_available_gb="$(awk '/MemAvailable:/ { printf "%.1f", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || printf 0.0)"
    node_count="$(find /sys/devices/system/node -maxdepth 1 -type d -name 'node[0-9]*' 2>/dev/null | wc -l | tr -d ' ')"
    if [[ -n "$node_count" && "$node_count" -gt 0 ]]; then
        numa_observable="true"
        numa_missing_reason=""
    else
        node_count="0"
        numa_observable="false"
        numa_missing_reason="NUMA topology not visible in local E2E lane"
    fi
    mapfile -t local_missing < <(permissioned_missing_prerequisites)
    permissioned_reason="$(permissioned_blocker_reason "${local_missing[@]}")"
    rerun_command="$(permissioned_rerun_command)"

    jq \
        --arg generated_at "$generated_at" \
        --arg host_fingerprint "$host_fingerprint" \
        --arg cpu_cores "$cpu_cores" \
        --arg ram_total_gb "$ram_total_gb" \
        --arg ram_available_gb "$ram_available_gb" \
        --arg node_count "$node_count" \
        --arg numa_observable "$numa_observable" \
        --arg numa_missing_reason "$numa_missing_reason" \
        --arg run_log "$E2E_LOG_FILE" \
        --arg command_transcript "$COMMAND_TRANSCRIPT" \
        --arg worker_identity "$WORKER_IDENTITY" \
        --arg permissioned_reason "$permissioned_reason" \
        --arg rerun_command "$rerun_command" \
        --arg permissioned_stdout "$PERMISSIONED_STDOUT" \
        --arg permissioned_stderr "$PERMISSIONED_STDERR" \
        --arg permissioned_blocker "$PERMISSIONED_BLOCKER_JSON" \
        --arg local_report "$LOCAL_SMOKE_REPORT_JSON" \
        '
        .manifest_id = "bd-rchk0.53.3-local-smoke-e2e-v1"
        | .generated_at = $generated_at
        | .scenarios[0].scenario_id = "swarm_workload_permissioned_large_host_blocked"
        | .scenarios[0].classification = "capability_skip"
        | .scenarios[0].release_claim_state = "blocked"
        | .scenarios[0].cleanup_status = "partial_artifacts_preserved"
        | .scenarios[0].host.host_fingerprint = ("permissioned-large-host-blocked-" + $generated_at)
        | .scenarios[0].host.fuse_capability.state = "unknown"
        | .scenarios[0].host.fuse_capability.detail = ("permissioned run not attempted: " + $permissioned_reason)
        | .scenarios[0].host.worker_isolation_notes = "external permissioned runner required; no large-host workload was started"
        | .scenarios[0].reproduction_command = $rerun_command
        | .scenarios[0].raw_logs = [$permissioned_stdout, $permissioned_stderr, $run_log]
        | .scenarios[0].artifact_paths = [$permissioned_blocker, $command_transcript]
        | .scenarios[1].scenario_id = "swarm_workload_local_smoke_dry_run"
        | .scenarios[1].host.host_fingerprint = $host_fingerprint
        | .scenarios[1].host.cpu_cores_logical = ($cpu_cores | tonumber)
        | .scenarios[1].host.ram_total_gb = ($ram_total_gb | tonumber)
        | .scenarios[1].host.ram_available_gb = ($ram_available_gb | tonumber)
        | .scenarios[1].host.kernel = $worker_identity
        | .scenarios[1].host.worker_isolation_notes = "local dry-run smoke only; no large-host readiness claim"
        | .scenarios[1].host.numa = if $numa_observable == "true" then
            { observable: true, node_count: ($node_count | tonumber), placement_intent: "observed local topology; not authoritative for large-host claim" }
          else
            { observable: false, placement_intent: "local smoke; no NUMA placement claim", missing_reason: $numa_missing_reason }
          end
        | .scenarios[1].cleanup_status = "partial_artifacts_preserved"
        | .scenarios[1].classification = "capability_skip"
        | .scenarios[1].release_claim_state = "small_host_smoke"
        | .scenarios[1].reproduction_command = "./scripts/e2e/ffs_swarm_workload_harness_e2e.sh"
        | .scenarios[1].raw_logs = [$run_log]
        | .scenarios[1].artifact_paths = [$local_report, $command_transcript]
        ' "$MANIFEST_JSON" >"$LOCAL_SMOKE_MANIFEST"
}

run_permissioned_runner_if_configured() {
    mapfile -t missing < <(permissioned_missing_prerequisites)
    if ((${#missing[@]} > 0)); then
        return 2
    fi

    local runner_command="$PERMISSIONED_RUNNER $PERMISSIONED_MANIFEST_JSON $PERMISSIONED_REPORT_JSON"
    set +e
    "$PERMISSIONED_RUNNER" "$PERMISSIONED_MANIFEST_JSON" "$PERMISSIONED_REPORT_JSON" >"$PERMISSIONED_STDOUT" 2>"$PERMISSIONED_STDERR"
    local status=$?
    set -e
    record_command "swarm_workload_permissioned_gate" "$status" "$runner_command" "$PERMISSIONED_STDOUT" "$PERMISSIONED_STDERR"
    if [[ $status -ne 0 ]]; then
        return "$status"
    fi
    [[ -s "$PERMISSIONED_MANIFEST_JSON" ]] || return 1
    if ! run_rch_stdout_capture "$PERMISSIONED_REPORT_RAW" \
        cargo run --quiet -p ffs-harness -- \
        validate-swarm-workload-harness \
        --manifest "$PERMISSIONED_MANIFEST_JSON" \
        --reference-timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; then
        return 1
    fi
    cp "$PERMISSIONED_REPORT_RAW" "$PERMISSIONED_REPORT_JSON"
    jq -e '
        .valid == true
        and ((.release_claim_counts.measured_authoritative // 0) >= 1)
        and ((.verdict_counts.pass // 0) >= 1)
        and (.scenario_verdicts | any(.release_claim_state == "measured_authoritative" and .host_lane == "permissioned_large_host" and .verdict == "pass"))
    ' "$PERMISSIONED_REPORT_JSON" >/dev/null
}

e2e_log "=============================================="
e2e_log "E2E Test: ffs_swarm_workload_harness"
e2e_log "=============================================="
e2e_log "Started: $(date -Iseconds)"
e2e_log "Log directory: ${E2E_LOG_DIR}"
e2e_log "Cargo target dir: ${CARGO_TARGET_DIR}"
e2e_log ""

MANIFEST_JSON="benchmarks/swarm_workload_harness_manifest.json"
REPORT_RAW="${E2E_LOG_DIR}/swarm_workload_harness_report.raw"
REPORT_JSON="${E2E_LOG_DIR}/swarm_workload_harness_report.json"
REPORT_MD_RAW="${E2E_LOG_DIR}/swarm_workload_harness_report_md.raw"
LOCAL_SMOKE_MANIFEST="${E2E_LOG_DIR}/swarm_workload_local_smoke_manifest.json"
LOCAL_SMOKE_REPORT_RAW="${E2E_LOG_DIR}/swarm_workload_local_smoke_report.raw"
LOCAL_SMOKE_REPORT_JSON="${E2E_LOG_DIR}/swarm_workload_local_smoke_report.json"
PERMISSIONED_BLOCKER_JSON="${E2E_LOG_DIR}/swarm_workload_permissioned_blocker.json"
PERMISSIONED_STDOUT="${E2E_LOG_DIR}/swarm_workload_permissioned.stdout"
PERMISSIONED_STDERR="${E2E_LOG_DIR}/swarm_workload_permissioned.stderr"
PERMISSIONED_MANIFEST_JSON="${E2E_LOG_DIR}/swarm_workload_permissioned_manifest.json"
PERMISSIONED_REPORT_RAW="${E2E_LOG_DIR}/swarm_workload_permissioned_report.raw"
PERMISSIONED_REPORT_JSON="${E2E_LOG_DIR}/swarm_workload_permissioned_report.json"
MUTATED_HOST_JSON="${E2E_LOG_DIR}/swarm_workload_bad_small_host.json"
MUTATED_HOST_RAW="${E2E_LOG_DIR}/swarm_workload_bad_small_host.raw"
MUTATED_NUMA_JSON="${E2E_LOG_DIR}/swarm_workload_bad_numa.json"
MUTATED_NUMA_RAW="${E2E_LOG_DIR}/swarm_workload_bad_numa.raw"
MUTATED_COMMAND_JSON="${E2E_LOG_DIR}/swarm_workload_bad_command.json"
MUTATED_COMMAND_RAW="${E2E_LOG_DIR}/swarm_workload_bad_command.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"

e2e_step "Scenario 1: module and CLI are wired"
CURRENT_SCENARIO_ID="swarm_workload_cli_wired"
if grep -q "pub mod swarm_workload_harness" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-workload-harness" crates/ffs-harness/src/main.rs \
    && [[ -f "$MANIFEST_JSON" ]]; then
    scenario_result "swarm_workload_cli_wired" "PASS" "module, CLI command, and default manifest present"
else
    scenario_result "swarm_workload_cli_wired" "FAIL" "missing module export, CLI command, or default manifest"
fi

e2e_step "Scenario 2: unit tests cover harness invariants"
CURRENT_SCENARIO_ID="swarm_workload_unit_tests"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness swarm_workload_harness; then
    scenario_result "swarm_workload_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "swarm_workload_unit_tests" "FAIL" "focused unit tests failed; see ${UNIT_LOG}"
fi

e2e_step "Scenario 3: default manifest validates with all required workload profiles"
CURRENT_SCENARIO_ID="swarm_workload_default_manifest"
if run_rch_stdout_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MANIFEST_JSON" --reference-timestamp "$REFERENCE_TIMESTAMP"; then
    cp "$REPORT_RAW" "$REPORT_JSON"
    if jq -e '.valid == true and .profile_count == 5 and .missing_workload_classes == [] and .large_host_plan_count == 1 and .host_downgrade_count == 1 and (.release_claim_counts.plan_ready == 1) and (.release_claim_counts.small_host_smoke == 1)' "$REPORT_JSON" >/dev/null; then
        scenario_result "swarm_workload_default_manifest" "PASS" "default manifest preserves plan-ready and downgraded rows"
    else
        scenario_result "swarm_workload_default_manifest" "FAIL" "manifest report missing workload or downgrade accounting"
    fi
else
    scenario_result "swarm_workload_default_manifest" "FAIL" "validator failed for default manifest; see ${REPORT_RAW}"
fi

e2e_step "Scenario 4: markdown rendering includes host downgrade and workload matrix"
CURRENT_SCENARIO_ID="swarm_workload_markdown"
if run_rch_stdout_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$MANIFEST_JSON" --reference-timestamp "$REFERENCE_TIMESTAMP" --format markdown; then
    if grep -q "Host downgrades" "$REPORT_MD_RAW" && grep -q "metadata_storm" "$REPORT_MD_RAW" && grep -q "cache_pressure" "$REPORT_MD_RAW"; then
        scenario_result "swarm_workload_markdown" "PASS" "markdown summary includes downgrade and workload matrix"
    else
        scenario_result "swarm_workload_markdown" "FAIL" "markdown summary missing downgrade or workload matrix"
    fi
else
    scenario_result "swarm_workload_markdown" "FAIL" "markdown command failed; see ${REPORT_MD_RAW}"
fi

e2e_step "Scenario 5: local runner emits downgraded dry-run artifacts"
CURRENT_SCENARIO_ID="swarm_workload_local_smoke_artifacts"
mapfile -t PERMISSIONED_MISSING < <(permissioned_missing_prerequisites)
write_permissioned_blocker "${PERMISSIONED_MISSING[@]}"
write_local_smoke_manifest
if run_rch_stdout_capture "$LOCAL_SMOKE_REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-swarm-workload-harness --manifest "$LOCAL_SMOKE_MANIFEST" --reference-timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; then
    cp "$LOCAL_SMOKE_REPORT_RAW" "$LOCAL_SMOKE_REPORT_JSON"
    if jq -e '
        .valid == true
        and ((.release_claim_counts.measured_authoritative // 0) == 0)
        and ((.verdict_counts.skip // 0) >= 2)
        and (.scenario_verdicts | any(.scenario_id == "swarm_workload_permissioned_large_host_blocked" and .verdict == "skip"))
        and (.scenario_verdicts | any(.scenario_id == "swarm_workload_local_smoke_dry_run" and .verdict == "skip"))
    ' "$LOCAL_SMOKE_REPORT_JSON" >/dev/null \
        && [[ -s "$COMMAND_TRANSCRIPT" ]] \
        && [[ -s "$PERMISSIONED_BLOCKER_JSON" ]]; then
        scenario_result "swarm_workload_local_smoke_artifacts" "PASS" "local smoke manifest/report/transcript prove no large-host pass claim"
    else
        scenario_result "swarm_workload_local_smoke_artifacts" "FAIL" "local smoke artifacts missing downgrade, transcript, or blocker proof"
    fi
else
    scenario_result "swarm_workload_local_smoke_artifacts" "FAIL" "generated local smoke manifest failed validation"
fi

e2e_step "Scenario 6: permissioned blocker records exact rerun contract"
CURRENT_SCENARIO_ID="swarm_workload_permissioned_blocker_contract"
if validate_permissioned_blocker; then
    scenario_result "swarm_workload_permissioned_blocker_contract" "PASS" "permissioned blocker preserves skip reason, ack token, rerun command, and cleanup proof"
else
    scenario_result "swarm_workload_permissioned_blocker_contract" "FAIL" "permissioned blocker artifact failed contract validation"
fi

e2e_step "Scenario 7: permissioned runner cannot pass without explicit ack and capability"
CURRENT_SCENARIO_ID="swarm_workload_permissioned_gate"
set +e
run_permissioned_runner_if_configured
PERMISSIONED_STATUS=$?
set -e
if [[ $PERMISSIONED_STATUS -eq 0 ]]; then
    scenario_result "swarm_workload_permissioned_gate" "PASS" "permissioned runner emitted measured_authoritative large-host pass evidence"
elif [[ $PERMISSIONED_STATUS -eq 2 ]] && validate_permissioned_blocker; then
    scenario_result "swarm_workload_permissioned_gate" "PASS" "permissioned runner was not started without explicit ack/capability"
else
    scenario_result "swarm_workload_permissioned_gate" "FAIL" "permissioned runner failed after prerequisites were configured"
fi

e2e_step "Scenario 8: small-host 64-core claim fails closed"
CURRENT_SCENARIO_ID="swarm_workload_small_host_fail_closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_HOST_RAW" \
    "$MUTATED_HOST_JSON" \
    '.scenarios[1].classification = "pass" | .scenarios[1].release_claim_state = "measured_authoritative"' \
    "$MANIFEST_JSON" \
    validate-swarm-workload-harness \
    --manifest
MUTATED_HOST_STATUS=$?
set -e
if [[ $MUTATED_HOST_STATUS -ne 0 ]] && grep -q "below the 64-core/256GB target" "$MUTATED_HOST_RAW"; then
    scenario_result "swarm_workload_small_host_fail_closed" "PASS" "small-host measured_authoritative mutation rejected"
else
    scenario_result "swarm_workload_small_host_fail_closed" "FAIL" "small-host measured_authoritative mutation was not rejected"
fi

e2e_step "Scenario 9: missing NUMA visibility rationale fails closed"
CURRENT_SCENARIO_ID="swarm_workload_numa_reason_fail_closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_NUMA_RAW" \
    "$MUTATED_NUMA_JSON" \
    'del(.scenarios[1].host.numa.missing_reason)' \
    "$MANIFEST_JSON" \
    validate-swarm-workload-harness \
    --manifest
MUTATED_NUMA_STATUS=$?
set -e
if [[ $MUTATED_NUMA_STATUS -ne 0 ]] && grep -q "missing_reason" "$MUTATED_NUMA_RAW"; then
    scenario_result "swarm_workload_numa_reason_fail_closed" "PASS" "missing NUMA visibility reason rejected"
else
    scenario_result "swarm_workload_numa_reason_fail_closed" "FAIL" "missing NUMA visibility reason was not rejected"
fi

e2e_step "Scenario 10: mutating host command plan fails closed"
CURRENT_SCENARIO_ID="swarm_workload_mutating_command_fail_closed"
set +e
run_rch_mutated_validator_capture \
    "$MUTATED_COMMAND_RAW" \
    "$MUTATED_COMMAND_JSON" \
    '.workload_profiles[0].command_plan.mutates_host_filesystems = true' \
    "$MANIFEST_JSON" \
    validate-swarm-workload-harness \
    --manifest
MUTATED_COMMAND_STATUS=$?
set -e
if [[ $MUTATED_COMMAND_STATUS -ne 0 ]] && grep -q "mutates_host_filesystems" "$MUTATED_COMMAND_RAW"; then
    scenario_result "swarm_workload_mutating_command_fail_closed" "PASS" "mutating host command plan rejected"
else
    scenario_result "swarm_workload_mutating_command_fail_closed" "FAIL" "mutating host command plan was not rejected"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_finish "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    exit 1
fi

e2e_finish "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
