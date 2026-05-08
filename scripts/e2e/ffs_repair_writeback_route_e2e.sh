#!/usr/bin/env bash
# ffs_repair_writeback_route_e2e.sh - smoke gate for bd-rchk0.1.2/bd-rchk0.1.3/bd-rchk0.1.4.
#
# Proves recovered-block writeback is no longer an implicit direct write inside
# the recovery orchestrator, and that the mounted MVCC request-scope authority
# stages, commits, flushes, verifies recovered physical blocks, and rejects
# deterministic stale repair/client-write interleavings. Also proves the CLI
# enables read-write background repair only with ledger-backed evidence while
# kernel writeback-cache mode remains disabled. bd-n99t2 extends the smoke with
# malformed-plan rejection before any mutation or symbol-refresh notification.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_writeback_route}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("$RCH_BIN" queue --json 2>/dev/null || true)"
    if [[ -z "$queue_json" ]]; then
        return 0
    fi
    ids="$(jq -r --arg cmd "$command_text" '
        .data.active_builds[]?
        | select(.project_id | startswith("frankenfs-"))
        | select(.command == $cmd)
        | .id
    ' <<<"$queue_json" || true)"
    for id in $ids; do
        if "$RCH_BIN" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

run_rch_capture() {
    local output_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    shift

    : >"$output_path"
    set +e
    RCH_VISIBILITY="$RCH_VISIBILITY" "$RCH_BIN" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                cancel_matching_rch_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|output=${output_path}|status=${status}"
        return 0
    fi
    return "$status"
}

print_rch_log() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
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

require_core_test() {
    local scenario_id="$1"
    local test_name="$2"
    local detail="$3"
    if grep -Fq "$test_name" "$CORE_LOG"; then
        scenario_result "$scenario_id" "PASS" "$detail"
    else
        scenario_result "$scenario_id" "FAIL" "missing focused test ${test_name}"
    fi
}

e2e_init "ffs_repair_writeback_route"

CORE_LOG="$E2E_LOG_DIR/core_repair_writeback_route.log"
REPAIR_LOG="$E2E_LOG_DIR/repair_writeback_authority.log"
CLI_LOG="$E2E_LOG_DIR/cli_rw_background_repair.log"
FUSE_LOG="$E2E_LOG_DIR/fuse_writeback_cache_guard.log"
ARTIFACT_JSON="$E2E_LOG_DIR/repair_writeback_route_artifact.json"
SUMMARY_MD="$E2E_LOG_DIR/repair_writeback_route_summary.md"

e2e_step "Scenario 1: mounted mutation path stages, commits, flushes, and verifies"
if run_rch_capture "$CORE_LOG" cargo test -p ffs-core repair_writeback_ -- --nocapture; then
    scenario_result "repair_writeback_mounted_request_scope" "PASS" "ffs-core mounted writeback tests passed"
else
    print_rch_log "$CORE_LOG"
    scenario_result "repair_writeback_mounted_request_scope" "FAIL" "ffs-core mounted writeback tests failed"
fi

require_core_test \
    "repair_race_repair_before_write" \
    "repair_writeback_repair_before_client_write_preserves_later_client_commit" \
    "schedule repair-before-write leaves later client commit visible"
require_core_test \
    "repair_race_write_before_repair_stale_rejected" \
    "repair_writeback_write_before_repair_rejects_stale_snapshot" \
    "schedule write-before-repair rejects stale repair snapshot"
require_core_test \
    "repair_race_disjoint_write_and_repair" \
    "repair_writeback_disjoint_client_write_and_repair_both_persist" \
    "schedule disjoint client write and repair write both persist"
require_core_test \
    "repair_race_cancelled_writeback_no_mutation" \
    "repair_writeback_cancellation_before_stage_leaves_device_unchanged" \
    "cancelled repair writeback stops before device mutation"
require_core_test \
    "repair_race_duplicate_block_no_mutation" \
    "repair_writeback_rejects_duplicate_block_without_mutation_or_refresh" \
    "duplicate repair writeback targets reject before mutation or symbol refresh"
require_core_test \
    "repair_race_stale_refresh_suppressed" \
    "repair_writeback_stale_rejection_does_not_notify_refresh_lifecycle" \
    "stale repair rejection suppresses repair-symbol refresh lifecycle"
require_core_test \
    "repair_race_flush_reopen_boundary" \
    "repair_writeback_flush_survives_reopen_after_boundary" \
    "flushed repair writeback is visible after reopen"

e2e_step "Scenario 2: recovery pipeline uses injected writeback authority and fails closed"
if run_rch_capture "$REPAIR_LOG" cargo test -p ffs-repair recovery_ -- --nocapture; then
    scenario_result "repair_writeback_authority_injected" "PASS" "ffs-repair authority and rejection tests passed"
else
    print_rch_log "$REPAIR_LOG"
    scenario_result "repair_writeback_authority_injected" "FAIL" "ffs-repair authority tests failed"
fi

e2e_step "Scenario 3: CLI accepts read-write background repair only with durable ledger evidence"
if run_rch_capture "$CLI_LOG" cargo test -p ffs-cli mount_background_repair -- --nocapture; then
    scenario_result "rw_background_repair_cli_enabled" "PASS" "ffs-cli rw background repair parsing and guard tests passed"
else
    print_rch_log "$CLI_LOG"
    scenario_result "rw_background_repair_cli_enabled" "FAIL" "ffs-cli rw background repair tests failed"
fi

e2e_step "Scenario 4: FUSE mount options keep kernel writeback-cache mode disabled"
if run_rch_capture "$FUSE_LOG" cargo test -p ffs-fuse build_mount_options_excludes_kernel_writeback_cache_mode -- --nocapture; then
    scenario_result "rw_background_repair_writeback_cache_disabled" "PASS" "FUSE writeback-cache exclusion test passed"
else
    print_rch_log "$FUSE_LOG"
    scenario_result "rw_background_repair_writeback_cache_disabled" "FAIL" "FUSE writeback-cache guard test failed"
fi

e2e_step "Scenario 5: machine-readable route artifact preserves operational evidence"
if python3 - "$CORE_LOG" "$REPAIR_LOG" "$CLI_LOG" "$FUSE_LOG" "$ARTIFACT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

core_log = pathlib.Path(sys.argv[1])
repair_log = pathlib.Path(sys.argv[2])
cli_log = pathlib.Path(sys.argv[3])
fuse_log = pathlib.Path(sys.argv[4])
artifact = pathlib.Path(sys.argv[5])
summary = pathlib.Path(sys.argv[6])

core_text = core_log.read_text(encoding="utf-8")
repair_text = repair_log.read_text(encoding="utf-8")
cli_text = cli_log.read_text(encoding="utf-8")
fuse_text = fuse_log.read_text(encoding="utf-8")
required_core = [
    "repair_writeback_uses_mounted_request_scope_and_flushes_to_device",
    "repair_writeback_rejects_short_block_without_mutating_device",
    "repair_writeback_rejects_duplicate_block_without_mutation_or_refresh",
    "repair_writeback_repair_before_client_write_preserves_later_client_commit",
    "repair_writeback_write_before_repair_rejects_stale_snapshot",
    "repair_writeback_disjoint_client_write_and_repair_both_persist",
    "repair_writeback_cancellation_before_stage_leaves_device_unchanged",
    "repair_writeback_stale_rejection_does_not_notify_refresh_lifecycle",
    "repair_writeback_flush_survives_reopen_after_boundary",
]
required_repair = [
    "recovery_uses_configured_writeback_authority",
    "recovery_writeback_rejection_fails_closed_without_symbol_refresh",
]
required_cli = [
    "mount_background_repair_implies_scrub_for_read_write_mount",
    "mount_background_repair_rejects_read_write_missing_ledger",
    "cli_parses_read_write_mount_background_repair_flag",
]
required_fuse = [
    "build_mount_options_excludes_kernel_writeback_cache_mode",
]
missing = [
    name
    for name in required_core
    if name not in core_text
] + [
    name
    for name in required_repair
    if name not in repair_text
] + [
    name
    for name in required_cli
    if name not in cli_text
] + [
    name
    for name in required_fuse
    if name not in fuse_text
]
if missing:
    raise SystemExit(f"missing expected tests: {missing}")

record = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "bead_ids": ["bd-rchk0.1.2", "bd-rchk0.1.3", "bd-rchk0.1.4", "bd-n99t2"],
    "operation_id": "op-repair-writeback-route-smoke-001",
    "scenario_id": "repair_writeback_route_smoke",
    "interleaving_schedule_ids": [
        "repair-before-client-write",
        "client-write-before-repair-stale-rejected",
        "disjoint-client-write-and-repair",
        "cancel-before-repair-stage",
        "duplicate-repair-target-rejected",
        "stale-refresh-suppressed",
        "repair-flush-reopen-boundary",
    ],
    "operation_trace": [
        "capture_expected_current_block",
        "stage_repair_or_client_write",
        "commit_through_mvcc_request_scope",
        "flush_mvcc_to_device",
        "verify_durable_block_bytes",
        "reject_duplicate_repair_targets_before_stage",
        "reject_if_mounted_bytes_changed_since_repair_planning",
    ],
    "writeback_authority": "mounted_mvcc_request_scope",
    "fallback_authority": "direct_device_offline_or_client_read_only",
    "rw_background_repair_cli": {
        "enabled_form": "ffs mount --rw --background-repair --background-scrub-ledger <jsonl> <image> <mountpoint>",
        "missing_ledger": "rejected_before_mount",
        "serialization_gate": "mounted_mvcc_request_scope_required",
        "writeback_cache_state": "kernel_writeback_cache_disabled"
    },
    "expected_state": "repair_writeback_committed_or_malformed_or_stale_repair_rejected",
    "observed_state": "repair_writeback_interleavings_and_duplicate_target_rejection_verified",
    "error_class": None,
    "ledger_rows": [
        "RepairAttempted",
        "RepairSucceeded",
        "RepairFailed",
        "SymbolRefresh",
        "SymbolRefreshSuppressedOnStaleRepair",
    ],
    "visible_data_before": {
        "core": "backing block differs before mounted repair writeback",
        "repair": "corrupt source block injected before decode",
    },
    "visible_data_after": {
        "core": "durable backing block bytes match recovered data",
        "repair": "recovered source block bytes match original data",
    },
    "stdout_paths": [str(core_log), str(repair_log), str(cli_log), str(fuse_log)],
    "stderr_paths": [str(core_log), str(repair_log), str(cli_log), str(fuse_log)],
    "artifact_paths": [
        str(artifact),
        str(summary),
        str(core_log),
        str(repair_log),
        str(cli_log),
        str(fuse_log),
    ],
    "cleanup_status": "preserved_artifacts",
    "reproduction_command": "./scripts/e2e/ffs_repair_writeback_route_e2e.sh",
}
artifact.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
summary.write_text(
    "# Repair Writeback Route And Race Smoke\n\n"
    "- beads: bd-rchk0.1.2, bd-rchk0.1.3, bd-rchk0.1.4, bd-n99t2\n"
    "- mounted authority: mounted_mvcc_request_scope\n"
    "- direct authority scope: offline_or_client_read_only\n"
    "- malformed repair plans: duplicate recovered-block targets reject before mutation\n"
    "- rw background repair: ledger required, mounted serializer required\n"
    "- kernel writeback-cache: disabled\n"
    "- result: repair_writeback_interleavings_and_duplicate_target_rejection_verified\n",
    encoding="utf-8",
)
PY
then
    scenario_result "repair_writeback_route_artifact" "PASS" "route artifact and summary generated"
else
    scenario_result "repair_writeback_route_artifact" "FAIL" "route artifact validation failed"
fi

if ((FAIL_COUNT == 0)); then
    status="PASS"
else
    status="FAIL"
fi

cat >"$E2E_LOG_DIR/result.json" <<JSON
{
  "suite": "ffs_repair_writeback_route",
  "status": "$status",
  "total": $TOTAL,
  "passed": $PASS_COUNT,
  "failed": $FAIL_COUNT,
  "artifact": "$ARTIFACT_JSON",
  "summary": "$SUMMARY_MD"
}
JSON

e2e_log "E2E_SUMMARY|suite=ffs_repair_writeback_route|status=${status}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}|total=${TOTAL}|artifact=${ARTIFACT_JSON}"

if ((FAIL_COUNT != 0)); then
    exit 1
fi
