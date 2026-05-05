#!/usr/bin/env bash
# ffs_crash_replay_refinement_e2e.sh - schedule minimization and dual-lane crash replay smoke for bd-rchk0.5.5.1.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_crash_replay_refinement}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL=0
PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK="permissioned-crash-replay-may-mount-kill-daemon-and-mutate-images"

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [[ "$status" == "SKIP" ]]; then
        SKIP_COUNT=$((SKIP_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

write_host_skip() {
    local scenario_id="$1"
    local lane_type="$2"
    local classification="$3"
    local reason="$4"
    local path="$E2E_LOG_DIR/${scenario_id}.json"
    python3 - "$path" "$scenario_id" "$lane_type" "$classification" "$reason" <<'PY'
import json
import sys
from pathlib import Path

path, scenario_id, lane_type, classification, reason = sys.argv[1:]
payload = {
    "scenario_id": scenario_id,
    "outcome": "SKIP",
    "lane_type": lane_type,
    "classification": classification,
    "reason": reason,
    "hides_product_failure": False,
    "rerun": "FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1 ./scripts/e2e/ffs_crash_replay_refinement_e2e.sh",
}
Path(path).write_text(json.dumps(payload, indent=2) + "\n")
PY
    e2e_log "HOST_CAPABILITY_SKIP|scenario_id=${scenario_id}|lane_type=${lane_type}|classification=${classification}|artifact=${path}|reason=${reason}"
}

permissioned_missing_prerequisites() {
    if [[ ! -e /dev/fuse ]]; then
        printf '%s\n' "missing_/dev/fuse"
    fi
    if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
        printf '%s\n' "missing_fusermount3_or_fusermount"
    fi
    if [[ "${FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK:-}" != "$PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK" ]]; then
        printf '%s\n' "missing_FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK"
    fi
}

write_permissioned_blocker() {
    local scenario_id="$1"
    local lane_type="$2"
    local classification="$3"
    local reason="$4"
    shift 4
    local path="$E2E_LOG_DIR/${scenario_id}.json"
    python3 - "$path" "$scenario_id" "$lane_type" "$classification" "$reason" "$PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK" "$@" <<'PY'
import json
import shutil
import sys
from pathlib import Path

path, scenario_id, lane_type, classification, reason, ack_token, *missing = sys.argv[1:]
payload = {
    "scenario_id": scenario_id,
    "outcome": "SKIP",
    "lane_type": lane_type,
    "classification": classification,
    "blocker_kind": "permissioned_crash_replay_capability_blocker",
    "reason": reason,
    "missing_prerequisites": missing,
    "permissioned_execution_attempted": False,
    "hides_product_failure": False,
    "host_probe": {
        "dev_fuse_present": Path("/dev/fuse").exists(),
        "fusermount3_path": shutil.which("fusermount3"),
        "fusermount_path": shutil.which("fusermount"),
        "mount_attempted": False,
    },
    "required_ack": {
        "env": "FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK",
        "expected": ack_token,
    },
    "rerun": (
        "FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1 "
        f"FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK={ack_token} "
        "./scripts/e2e/ffs_crash_replay_refinement_e2e.sh"
    ),
}
Path(path).write_text(json.dumps(payload, indent=2) + "\n")
PY
    e2e_log "PERMISSIONED_CRASH_REPLAY_BLOCKER|scenario_id=${scenario_id}|lane_type=${lane_type}|classification=${classification}|artifact=${path}|reason=${reason}|missing=$*"
}

permissioned_lane_or_blocker() {
    local scenario_id="$1"
    local lane_type="$2"
    local classification="$3"
    local ready_detail="$4"
    mapfile -t missing < <(permissioned_missing_prerequisites)
    if ((${#missing[@]} > 0)); then
        write_permissioned_blocker \
            "$scenario_id" \
            "$lane_type" \
            "$classification" \
            "permissioned crash replay prerequisites are not satisfied on this host" \
            "${missing[@]}"
        scenario_result "$scenario_id" "SKIP" "structured permissioned capability blocker emitted"
    else
        scenario_result "$scenario_id" "FAIL" "$ready_detail"
    fi
}

run_rch_capture() {
    local log_path="$1"
    shift
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-240}"
    if command -v timeout >/dev/null 2>&1; then
        timeout "${timeout_secs}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1
    else
        "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1
    fi
}

e2e_init "ffs_crash_replay_refinement"

REPORT_JSON="$E2E_LOG_DIR/crash_replay_report.json"
RUN_RAW="$E2E_LOG_DIR/crash_replay_run.raw"
UNIT_LOG="$E2E_LOG_DIR/crash_replay_refinement_unit_tests.log"
ARTIFACT_DIR="$E2E_LOG_DIR/crash_replay_artifacts"

if [[ "${FFS_CRASH_REPLAY_PERMISSIONED_PROBE_ONLY:-0}" == "1" ]]; then
    e2e_step "Permissioned crash replay blocker probe only"
    permissioned_lane_or_blocker \
        "crash_replay_mounted_write_reopen" \
        "mounted_smoke" \
        "mounted_write_reopen" \
        "permissioned mounted crash replay prerequisites are present, but real mounted write/reopen execution remains parent bd-8bg7c work"
    permissioned_lane_or_blocker \
        "crash_replay_repair_interruption" \
        "repair_interruption" \
        "repair_interruption" \
        "permissioned repair interruption prerequisites are present, but real repair-interruption execution remains parent bd-8bg7c work"
    if ((FAIL_COUNT == 0)); then
        e2e_log "Permissioned crash replay blocker probe passed: ${PASS_COUNT}/${TOTAL} (skipped=${SKIP_COUNT})"
        e2e_pass
        exit 0
    else
        e2e_fail "Permissioned crash replay blocker probe failed: ${FAIL_COUNT}/${TOTAL}"
    fi
fi

e2e_step "Scenario 1: crash replay report emits minimization and survivor artifacts"
if cargo run --quiet -p ffs-harness -- run-crash-replay \
    --count 2 \
    --seed 424242 \
    --min-ops 8 \
    --max-ops 8 \
    --out "$ARTIFACT_DIR" >"$RUN_RAW" 2>&1; then
    python3 - "$RUN_RAW" "$REPORT_JSON" "$ARTIFACT_DIR" <<'PY'
import json
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text()
start = raw.find("{")
if start < 0:
    raise SystemExit("no JSON report in crash replay output")
report = json.loads(raw[start:])
Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
artifact_dir = Path(sys.argv[3])
for result in report["results"]:
    schedule_path = artifact_dir / "schedules" / f"schedule_{result['schedule_id']:04}.json"
    if not schedule_path.exists():
        raise SystemExit(f"missing schedule artifact: {schedule_path}")
    schedule_artifact = json.loads(schedule_path.read_text())
    operations = schedule_artifact["schedule"].get("operations", [])
    if not operations:
        raise SystemExit(f"missing operation trace in {schedule_path}")
    for case in result["case_results"]:
        required = [
            "lane_type",
            "classification",
            "expected_survivors",
            "observed_survivors",
            "cleanup_status",
            "raw_log",
            "minimized_reproduction_command",
            "minimized_operation_count",
        ]
        missing = [field for field in required if field not in case]
        if missing:
            raise SystemExit(f"missing case fields: {missing}")
        if case["lane_type"] != "core_deterministic":
            raise SystemExit(f"unexpected lane type: {case['lane_type']}")
        if case["expected_survivors"] != case["observed_survivors"]:
            raise SystemExit("survivor summary mismatch")
        if "run-crash-replay" not in case["minimized_reproduction_command"]:
            raise SystemExit("missing minimized repro command")
        if "CRASH_REPLAY_CASE" not in case["raw_log"]:
            raise SystemExit("missing structured raw log marker")
        if case["cleanup_status"] != "cleaned_up_simulated_state":
            raise SystemExit("missing cleanup status")
print("crash replay report contract ok")
PY
    scenario_result "crash_replay_minimized_artifacts" "PASS" "report includes lane, survivor, cleanup, raw-log, and repro fields"
else
    cat "$RUN_RAW"
    scenario_result "crash_replay_minimized_artifacts" "FAIL" "crash replay command failed"
fi

e2e_step "Scenario 2: crash replay taxonomy covers mounted and repair lanes"
if grep -q "MountedSmoke" crates/ffs-harness/src/e2e.rs \
    && grep -q "RepairInterruption" crates/ffs-harness/src/e2e.rs \
    && grep -q "MountedWriteReopen" crates/ffs-harness/src/e2e.rs \
    && grep -q "HostCapabilitySkip" crates/ffs-harness/src/e2e.rs; then
    scenario_result "crash_replay_dual_lane_taxonomy" "PASS" "mounted/repair/host-skip taxonomy present"
else
    scenario_result "crash_replay_dual_lane_taxonomy" "FAIL" "missing dual-lane taxonomy"
fi

e2e_step "Scenario 3: mounted write/reopen lane is explicit or host-skipped"
if [[ "${FFS_ENABLE_PERMISSIONED_CRASH_REPLAY:-0}" != "1" ]]; then
    write_host_skip \
        "crash_replay_mounted_write_reopen" \
        "mounted_smoke" \
        "mounted_write_reopen" \
        "permissioned mounted crash replay disabled by default"
    scenario_result "crash_replay_mounted_write_reopen" "SKIP" "structured host capability skip emitted"
else
    permissioned_lane_or_blocker \
        "crash_replay_mounted_write_reopen" \
        "mounted_smoke" \
        "mounted_write_reopen" \
        "permissioned mounted crash replay prerequisites are present, but real mounted write/reopen execution remains parent bd-8bg7c work"
fi

e2e_step "Scenario 4: repair-interruption lane is explicit or host-skipped"
if [[ "${FFS_ENABLE_PERMISSIONED_CRASH_REPLAY:-0}" != "1" ]]; then
    write_host_skip \
        "crash_replay_repair_interruption" \
        "repair_interruption" \
        "repair_interruption" \
        "permissioned repair interruption crash replay disabled by default"
    scenario_result "crash_replay_repair_interruption" "SKIP" "structured host capability skip emitted"
else
    permissioned_lane_or_blocker \
        "crash_replay_repair_interruption" \
        "repair_interruption" \
        "repair_interruption" \
        "permissioned repair interruption prerequisites are present, but real repair-interruption execution remains parent bd-8bg7c work"
fi

e2e_step "Scenario 5: crash replay refinement unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib crash_replay -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "crash_replay_refinement_unit_tests" "PASS" "crash replay unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "crash_replay_refinement_unit_tests" "FAIL" "crash replay unit tests failed"
fi

e2e_log "Crash replay report: $REPORT_JSON"
e2e_log "Crash replay artifacts: $ARTIFACT_DIR"

if ((FAIL_COUNT == 0)); then
    e2e_log "Crash replay refinement scenarios passed: ${PASS_COUNT}/${TOTAL} (skipped=${SKIP_COUNT})"
    e2e_pass
else
    e2e_fail "Crash replay refinement scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
