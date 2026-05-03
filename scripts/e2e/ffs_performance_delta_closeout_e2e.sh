#!/usr/bin/env bash
# ffs_performance_delta_closeout_e2e.sh - closeout gate for bd-rchk5.4.
#
# Validates that measured performance artifacts become tracker-backed signal:
# regressions, missing references, and unmeasured claims must all point to
# concrete follow-up beads before the report is accepted.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_performance_delta_closeout}"
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

e2e_init "ffs_performance_delta_closeout"

CONFIG_JSON="$REPO_ROOT/benchmarks/performance_delta_closeout.json"
REPORT_JSON="$E2E_LOG_DIR/performance_delta_closeout.json"
SUMMARY_MD="$E2E_LOG_DIR/performance_delta_closeout.md"
VALIDATE_RAW="$E2E_LOG_DIR/performance_delta_closeout.raw"
BAD_ISSUES_JSONL="$E2E_LOG_DIR/issues_missing_mount_cold_followup.jsonl"
BAD_RAW="$E2E_LOG_DIR/performance_delta_closeout_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/performance_delta_closeout_unit_tests.log"

e2e_step "Scenario 1: performance delta closeout module and CLI are wired"
if grep -q "pub mod performance_delta_closeout" crates/ffs-harness/src/lib.rs \
    && grep -q "performance-delta-closeout" crates/ffs-harness/src/main.rs \
    && [[ -f "$CONFIG_JSON" ]]; then
    scenario_result "performance_delta_closeout_cli_wired" "PASS" "module CLI and config present"
else
    scenario_result "performance_delta_closeout_cli_wired" "FAIL" "missing module CLI or config"
fi

e2e_step "Scenario 2: checked-in closeout config validates artifacts"
if cargo run --quiet -p ffs-harness -- performance-delta-closeout \
    --config "$CONFIG_JSON" \
    --out "$REPORT_JSON" \
    --summary-out "$SUMMARY_MD" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "performance_delta_closeout_validates" "PASS" "closeout report accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "performance_delta_closeout_validates" "FAIL" "closeout report rejected"
fi

e2e_step "Scenario 3: closeout report preserves regressions and follow-ups"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(f"report invalid: {report['errors']}")
if report["row_count"] < 10:
    raise SystemExit("expected core, mounted, pending, and deferred rows")

rows = {(row["operation"], row["classification"], row.get("source_artifact", "")): row for row in report["rows"]}

required_regressions = {
    "mount_cold": "bd-rchk5.5",
    "mount_warm": "bd-rchk5.6",
    "mount_recovery": "bd-rchk5.7",
}
for operation, bead in required_regressions.items():
    matches = [
        row for row in report["rows"]
        if row["operation"] == operation
        and row["classification"] == "regression"
        and row.get("follow_up_bead") == bead
    ]
    if not matches:
        raise SystemExit(f"missing regression row for {operation} -> {bead}")
    if not matches[0]["follow_up_present"]:
        raise SystemExit(f"follow-up bead missing for {operation}")

missing_reference_ops = {
    "cli_metadata_parse_conformance",
    "repair_symbol_refresh_staleness_latency",
    "wal_commit_4k_sync",
}
observed_missing = {
    row["operation"] for row in report["rows"]
    if row["classification"] == "missing_reference"
    and row.get("follow_up_bead") == "bd-rchk5.8"
}
if not missing_reference_ops <= observed_missing:
    raise SystemExit(f"missing reference follow-ups absent: {missing_reference_ops - observed_missing}")

pending = [
    row for row in report["rows"]
    if row["classification"] == "pending_capability"
    and row.get("follow_up_bead") == "bd-9vzzk"
]
if not pending:
    raise SystemExit("missing pending capability row linked to bd-9vzzk")

long_campaign = [
    row for row in report["rows"]
    if row["operation"] == "long_campaign_writeback_cache_smoke"
    and row["classification"] == "unmeasured"
    and row.get("follow_up_bead") == "bd-t21em"
]
if not long_campaign:
    raise SystemExit("missing long-campaign deferred claim row")

if not any(row["classification"] == "improved" for row in report["rows"]):
    raise SystemExit("expected at least one improved core benchmark row")
for bead in ("bd-rchk5.5", "bd-rchk5.6", "bd-rchk5.7", "bd-rchk5.8", "bd-9vzzk", "bd-t21em"):
    if bead not in summary:
        raise SystemExit(f"summary missing {bead}")
PY
then
    scenario_result "performance_delta_closeout_followups" "PASS" "regression and missing-reference rows linked"
else
    scenario_result "performance_delta_closeout_followups" "FAIL" "closeout report lost required follow-up signal"
fi

e2e_step "Scenario 4: missing follow-up bead fails closed"
grep -v '"id":"bd-rchk5.5"' "$REPO_ROOT/.beads/issues.jsonl" >"$BAD_ISSUES_JSONL"
if cargo run --quiet -p ffs-harness -- performance-delta-closeout \
    --config "$CONFIG_JSON" \
    --issues "$BAD_ISSUES_JSONL" >"$BAD_RAW" 2>&1; then
    scenario_result "performance_delta_closeout_missing_followup_rejected" "FAIL" "missing follow-up bead accepted"
elif grep -q "performance delta closeout validation failed" "$BAD_RAW"; then
    scenario_result "performance_delta_closeout_missing_followup_rejected" "PASS" "missing follow-up bead rejected"
else
    cat "$BAD_RAW"
    scenario_result "performance_delta_closeout_missing_followup_rejected" "FAIL" "unexpected failure mode"
fi

e2e_step "Scenario 5: unit tests cover closeout classification and checked-in config"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness performance_delta_closeout -- --nocapture >"$UNIT_LOG" 2>&1; then
    scenario_result "performance_delta_closeout_unit_tests" "PASS" "unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "performance_delta_closeout_unit_tests" "FAIL" "unit tests failed"
fi

e2e_log ""
e2e_log "Scenario totals: total=${TOTAL} pass=${PASS_COUNT} fail=${FAIL_COUNT}"

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    exit 1
fi

e2e_pass
