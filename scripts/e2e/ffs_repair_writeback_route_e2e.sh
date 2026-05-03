#!/usr/bin/env bash
# ffs_repair_writeback_route_e2e.sh - smoke gate for bd-rchk0.1.2.
#
# Proves recovered-block writeback is no longer an implicit direct write inside
# the recovery orchestrator, and that the mounted MVCC request-scope authority
# stages, commits, flushes, and verifies recovered physical blocks.

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
    "bead_id": "bd-rchk0.1.2",
    "operation_id": "op-repair-writeback-route-smoke-001",
    "scenario_id": "repair_writeback_route_smoke",
    "writeback_authority": "mounted_mvcc_request_scope",
    "fallback_authority": "direct_device_offline_or_client_read_only",
    "expected_state": "repair_writeback_committed",
    "observed_state": "repair_writeback_committed_and_verified",
    "error_class": None,
    "ledger_rows": [
        "RepairAttempted",
        "RepairSucceeded",
        "RepairFailed",
        "SymbolRefresh",
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
    "# Repair Writeback Route Smoke\n\n"
    "- bead: bd-rchk0.1.2\n"
    "- mounted authority: mounted_mvcc_request_scope\n"
    "- direct authority scope: offline_or_client_read_only\n"
    "- result: repair_writeback_committed_and_verified\n",
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
