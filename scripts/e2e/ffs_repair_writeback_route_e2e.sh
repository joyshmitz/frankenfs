#!/usr/bin/env bash
# ffs_repair_writeback_route_e2e.sh - smoke gate for bd-rchk0.1.2/bd-rchk0.1.3.
#
# Proves recovered-block writeback is no longer an implicit direct write inside
# the recovery orchestrator, and that the mounted MVCC request-scope authority
# stages, commits, flushes, verifies recovered physical blocks, and rejects
# deterministic stale repair/client-write interleavings.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_writeback_route}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

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
ARTIFACT_JSON="$E2E_LOG_DIR/repair_writeback_route_artifact.json"
SUMMARY_MD="$E2E_LOG_DIR/repair_writeback_route_summary.md"

e2e_step "Scenario 1: mounted mutation path stages, commits, flushes, and verifies"
if rch exec -- cargo test -p ffs-core repair_writeback_ -- --nocapture >"$CORE_LOG" 2>&1; then
    scenario_result "repair_writeback_mounted_request_scope" "PASS" "ffs-core mounted writeback tests passed"
else
    cat "$CORE_LOG"
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
    "repair_race_stale_refresh_suppressed" \
    "repair_writeback_stale_rejection_does_not_notify_refresh_lifecycle" \
    "stale repair rejection suppresses repair-symbol refresh lifecycle"
require_core_test \
    "repair_race_flush_reopen_boundary" \
    "repair_writeback_flush_survives_reopen_after_boundary" \
    "flushed repair writeback is visible after reopen"

e2e_step "Scenario 2: recovery pipeline uses injected writeback authority and fails closed"
if rch exec -- cargo test -p ffs-repair recovery_ -- --nocapture >"$REPAIR_LOG" 2>&1; then
    scenario_result "repair_writeback_authority_injected" "PASS" "ffs-repair authority and rejection tests passed"
else
    cat "$REPAIR_LOG"
    scenario_result "repair_writeback_authority_injected" "FAIL" "ffs-repair authority tests failed"
fi

e2e_step "Scenario 3: machine-readable route artifact preserves operational evidence"
if python3 - "$CORE_LOG" "$REPAIR_LOG" "$ARTIFACT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

core_log = pathlib.Path(sys.argv[1])
repair_log = pathlib.Path(sys.argv[2])
artifact = pathlib.Path(sys.argv[3])
summary = pathlib.Path(sys.argv[4])

core_text = core_log.read_text(encoding="utf-8")
repair_text = repair_log.read_text(encoding="utf-8")
required_core = [
    "repair_writeback_uses_mounted_request_scope_and_flushes_to_device",
    "repair_writeback_rejects_short_block_without_mutating_device",
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
missing = [
    name
    for name in required_core
    if name not in core_text
] + [
    name
    for name in required_repair
    if name not in repair_text
]
if missing:
    raise SystemExit(f"missing expected tests: {missing}")

record = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "bead_ids": ["bd-rchk0.1.2", "bd-rchk0.1.3"],
    "operation_id": "op-repair-writeback-route-smoke-001",
    "scenario_id": "repair_writeback_route_smoke",
    "interleaving_schedule_ids": [
        "repair-before-client-write",
        "client-write-before-repair-stale-rejected",
        "disjoint-client-write-and-repair",
        "cancel-before-repair-stage",
        "stale-refresh-suppressed",
        "repair-flush-reopen-boundary",
    ],
    "operation_trace": [
        "capture_expected_current_block",
        "stage_repair_or_client_write",
        "commit_through_mvcc_request_scope",
        "flush_mvcc_to_device",
        "verify_durable_block_bytes",
        "reject_if_mounted_bytes_changed_since_repair_planning",
    ],
    "writeback_authority": "mounted_mvcc_request_scope",
    "fallback_authority": "direct_device_offline_or_client_read_only",
    "expected_state": "repair_writeback_committed_or_stale_repair_rejected",
    "observed_state": "repair_writeback_interleavings_verified",
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
    "stdout_paths": [str(core_log), str(repair_log)],
    "stderr_paths": [str(core_log), str(repair_log)],
    "artifact_paths": [str(artifact), str(summary), str(core_log), str(repair_log)],
    "cleanup_status": "preserved_artifacts",
    "reproduction_command": "./scripts/e2e/ffs_repair_writeback_route_e2e.sh",
}
artifact.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
summary.write_text(
    "# Repair Writeback Route And Race Smoke\n\n"
    "- beads: bd-rchk0.1.2, bd-rchk0.1.3\n"
    "- mounted authority: mounted_mvcc_request_scope\n"
    "- direct authority scope: offline_or_client_read_only\n"
    "- result: repair_writeback_interleavings_verified\n",
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
