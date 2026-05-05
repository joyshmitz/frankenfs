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
    local runner="${FFS_PERMISSIONED_CRASH_REPLAY_RUNNER:-}"
    if [[ -z "$runner" ]]; then
        printf '%s\n' "missing_FFS_PERMISSIONED_CRASH_REPLAY_RUNNER"
    elif [[ "$runner" == */* && ! -x "$runner" ]]; then
        printf '%s\n' "non_executable_FFS_PERMISSIONED_CRASH_REPLAY_RUNNER"
    elif [[ "$runner" != */* ]] && ! command -v "$runner" >/dev/null 2>&1; then
        printf '%s\n' "unresolved_FFS_PERMISSIONED_CRASH_REPLAY_RUNNER"
    fi
}

permissioned_blocker_reason() {
    local missing=("$@")
    if ((${#missing[@]} == 1)) && [[ "${missing[0]}" == "missing_FFS_PERMISSIONED_CRASH_REPLAY_RUNNER" ]]; then
        printf '%s\n' "permissioned crash replay external runner is not configured on this host"
    elif ((${#missing[@]} == 1)) && [[ "${missing[0]}" == "non_executable_FFS_PERMISSIONED_CRASH_REPLAY_RUNNER" ]]; then
        printf '%s\n' "permissioned crash replay external runner is not executable on this host"
    elif ((${#missing[@]} == 1)) && [[ "${missing[0]}" == "unresolved_FFS_PERMISSIONED_CRASH_REPLAY_RUNNER" ]]; then
        printf '%s\n' "permissioned crash replay external runner command is not on PATH"
    else
        printf '%s\n' "permissioned crash replay prerequisites are not satisfied on this host"
    fi
}

write_permissioned_blocker() {
    local scenario_id="$1"
    local lane_type="$2"
    local classification="$3"
    local reason="$4"
    shift 4
    local path="$E2E_LOG_DIR/${scenario_id}.json"
    local stdout_path="$E2E_LOG_DIR/${scenario_id}.stdout.not_started"
    local stderr_path="$E2E_LOG_DIR/${scenario_id}.stderr.not_started"
    printf 'permissioned crash replay was not started for %s\n' "$scenario_id" >"$stdout_path"
    printf 'missing prerequisites: %s\n' "$*" >"$stderr_path"
    python3 - "$path" "$scenario_id" "$lane_type" "$classification" "$reason" "$PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK" "$stdout_path" "$stderr_path" "$@" <<'PY'
import json
import shutil
import sys
from pathlib import Path

(
    path,
    scenario_id,
    lane_type,
    classification,
    reason,
    ack_token,
    stdout_path,
    stderr_path,
    *missing,
) = sys.argv[1:]
rerun = (
    "FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1 "
    f"FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK={ack_token} "
    "./scripts/e2e/ffs_crash_replay_refinement_e2e.sh"
)
payload = {
    "scenario_id": scenario_id,
    "outcome": "SKIP",
    "lane_type": lane_type,
    "classification": classification,
    "blocker_kind": "permissioned_crash_replay_capability_blocker",
    "reason": reason,
    "missing_prerequisites": missing,
    "permissioned_execution_attempted": False,
    "cleanup_status": "not_mounted_no_image_mutation",
    "hides_product_failure": False,
    "stdout_path": stdout_path,
    "stderr_path": stderr_path,
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
    "rerun": rerun,
    "reproduction_command": rerun,
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
        local reason
        reason="$(permissioned_blocker_reason "${missing[@]}")"
        write_permissioned_blocker \
            "$scenario_id" \
            "$lane_type" \
            "$classification" \
            "$reason" \
            "${missing[@]}"
        scenario_result "$scenario_id" "SKIP" "structured permissioned capability blocker emitted"
    else
        if run_permissioned_runner "$scenario_id" "$lane_type" "$classification"; then
            scenario_result "$scenario_id" "PASS" "permissioned external runner emitted validated artifact"
        else
            scenario_result "$scenario_id" "FAIL" "$ready_detail"
        fi
    fi
}

run_permissioned_runner() {
    local scenario_id="$1"
    local lane_type="$2"
    local classification="$3"
    local runner="${FFS_PERMISSIONED_CRASH_REPLAY_RUNNER:?permissioned runner missing}"
    local artifact_path="$E2E_LOG_DIR/${scenario_id}.json"
    local stdout_path="$E2E_LOG_DIR/${scenario_id}.stdout"
    local stderr_path="$E2E_LOG_DIR/${scenario_id}.stderr"
    FFS_CRASH_REPLAY_SCENARIO_ID="$scenario_id" \
        FFS_CRASH_REPLAY_SCENARIO_LANE="$lane_type" \
        FFS_CRASH_REPLAY_CLASSIFICATION="$classification" \
        FFS_CRASH_REPLAY_ARTIFACT_OUT="$artifact_path" \
        FFS_CRASH_REPLAY_STDOUT_OUT="$stdout_path" \
        FFS_CRASH_REPLAY_STDERR_OUT="$stderr_path" \
        FFS_CRASH_REPLAY_LOG_DIR="$E2E_LOG_DIR" \
        "$runner" >"$stdout_path" 2>"$stderr_path" || return 1
    validate_permissioned_runner_artifact "$artifact_path" "$scenario_id" "$classification"
}

validate_permissioned_runner_artifact() {
    python3 - "$@" <<'PY'
import json
import re
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
scenario_id = sys.argv[2]
classification = sys.argv[3]
if not artifact_path.exists():
    raise SystemExit(f"{scenario_id}: permissioned runner did not emit {artifact_path}")
artifact = json.loads(artifact_path.read_text())
if artifact.get("lane_type") != "mounted_e2e":
    raise SystemExit(f"{scenario_id}: permissioned artifact lane_type must be mounted_e2e")
if artifact.get("crash_taxonomy") != classification:
    raise SystemExit(
        f"{scenario_id}: crash_taxonomy {artifact.get('crash_taxonomy')!r} != {classification!r}"
    )
if artifact.get("oracle_verdict") in {
    "missing_file",
    "unexpected_extra_file",
    "metadata_only_mismatch",
    "replay_failure",
}:
    if not artifact.get("follow_up_bead") and not artifact.get("follow_up_skip_reason"):
        raise SystemExit(f"{scenario_id}: failing permissioned verdict lacks follow-up bead data")
context = artifact.get("permissioned_context")
if not isinstance(context, dict):
    raise SystemExit(f"{scenario_id}: missing permissioned_context")
required_context = [
    "lane_id",
    "host_capability_proof",
    "image_path",
    "image_hash",
    "mountpoint_path",
    "operation_trace_path",
    "expected_survivors_path",
    "observed_survivors_path",
    "stdout_path",
    "stderr_path",
    "cleanup_status",
    "repro_command",
]
missing = [field for field in required_context if not str(context.get(field, "")).strip()]
if missing:
    raise SystemExit(f"{scenario_id}: permissioned_context missing {missing}")
if not re.fullmatch(r"sha256:[0-9A-Fa-f]{64}", context["image_hash"]):
    raise SystemExit(f"{scenario_id}: permissioned_context image_hash must be sha256:<64-hex>")
if context["cleanup_status"] not in {
    "cleaned_up",
    "cleanup_verified",
    "retained_for_debug",
    "host_blocked_before_mount",
}:
    raise SystemExit(f"{scenario_id}: unsupported cleanup_status {context['cleanup_status']!r}")
if context.get("daemon_pid") is not None and not str(context.get("termination_method", "")).strip():
    raise SystemExit(f"{scenario_id}: daemon_pid requires termination_method")
if classification == "repair_interruption" and not str(context.get("repair_ledger_path", "")).strip():
    raise SystemExit(f"{scenario_id}: repair_interruption requires repair_ledger_path")
for path_field in ["stdout_path", "stderr_path"]:
    if not Path(context[path_field]).exists():
        raise SystemExit(f"{scenario_id}: permissioned_context {path_field} artifact missing")
PY
}

validate_permissioned_blocker_artifacts() {
    python3 - "$PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK" "${FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK:-}" "$@" <<'PY'
import json
import sys
from pathlib import Path

ack_token, ack_value, *artifact_paths = sys.argv[1:]
if not artifact_paths:
    raise SystemExit("missing blocker artifact paths")

for artifact_arg in artifact_paths:
    artifact_path = Path(artifact_arg)
    artifact = json.loads(artifact_path.read_text())
    scenario_id = artifact.get("scenario_id", artifact_path.name)
    required_fields = [
        "scenario_id",
        "outcome",
        "lane_type",
        "classification",
        "blocker_kind",
        "reason",
        "missing_prerequisites",
        "permissioned_execution_attempted",
        "cleanup_status",
        "stdout_path",
        "stderr_path",
        "host_probe",
        "required_ack",
        "rerun",
        "reproduction_command",
    ]
    missing_fields = [field for field in required_fields if field not in artifact]
    if missing_fields:
        raise SystemExit(f"{scenario_id}: blocker missing fields {missing_fields}")
    if artifact["outcome"] != "SKIP":
        raise SystemExit(f"{scenario_id}: blocker outcome must be SKIP")
    if artifact["blocker_kind"] != "permissioned_crash_replay_capability_blocker":
        raise SystemExit(f"{scenario_id}: wrong blocker_kind")
    if artifact["permissioned_execution_attempted"] is not False:
        raise SystemExit(f"{scenario_id}: permissioned execution must not be attempted")
    if artifact["cleanup_status"] != "not_mounted_no_image_mutation":
        raise SystemExit(f"{scenario_id}: cleanup_status does not prove non-mutation")
    host_probe = artifact["host_probe"]
    if host_probe.get("mount_attempted") is not False:
        raise SystemExit(f"{scenario_id}: mount_attempted must be false")
    required_ack = artifact["required_ack"]
    if required_ack.get("env") != "FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK":
        raise SystemExit(f"{scenario_id}: required_ack env drifted")
    if required_ack.get("expected") != ack_token:
        raise SystemExit(f"{scenario_id}: required_ack token drifted")
    missing_prereqs = artifact["missing_prerequisites"]
    if not missing_prereqs:
        raise SystemExit(f"{scenario_id}: blocker must record at least one missing prerequisite")
    if (
        ack_value != ack_token
        and "missing_FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK" not in missing_prereqs
    ):
        raise SystemExit(f"{scenario_id}: probe-only blocker must record missing ACK")
    for command_field in ["rerun", "reproduction_command"]:
        command = artifact[command_field]
        if ack_token not in command or "FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1" not in command:
            raise SystemExit(f"{scenario_id}: {command_field} lacks permissioned rerun context")
    for path_field in ["stdout_path", "stderr_path"]:
        if not Path(artifact[path_field]).exists():
            raise SystemExit(f"{scenario_id}: {path_field} artifact missing")

print(f"validated {len(artifact_paths)} permissioned blocker artifacts")
PY
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
if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" == "1" ]]; then
    E2E_CLEANUP_ITEMS=()
    e2e_log "Temp cleanup disabled by FFS_E2E_DISABLE_TEMP_CLEANUP=1"
fi

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
        "permissioned mounted crash replay external runner failed or emitted an invalid artifact"
    permissioned_lane_or_blocker \
        "crash_replay_repair_interruption" \
        "repair_interruption" \
        "repair_interruption" \
        "permissioned repair-interruption external runner failed or emitted an invalid artifact"
    if validate_permissioned_blocker_artifacts \
        "$E2E_LOG_DIR/crash_replay_mounted_write_reopen.json" \
        "$E2E_LOG_DIR/crash_replay_repair_interruption.json"; then
        e2e_log "PERMISSIONED_CRASH_REPLAY_BLOCKER_CONTRACT|outcome=PASS|artifacts=${E2E_LOG_DIR}/crash_replay_mounted_write_reopen.json,${E2E_LOG_DIR}/crash_replay_repair_interruption.json"
        scenario_result "permissioned_crash_replay_blocker_contract" "PASS" "permissioned blocker artifacts preserve cleanup/no-mutation proof"
    else
        scenario_result "permissioned_crash_replay_blocker_contract" "FAIL" "blocker contract validation failed"
    fi
    if ((FAIL_COUNT == 0)); then
        e2e_log "Permissioned crash replay blocker probe passed: ${PASS_COUNT}/${TOTAL} (skipped=${SKIP_COUNT})"
        e2e_pass
        exit 0
    else
        e2e_fail "Permissioned crash replay blocker probe failed: ${FAIL_COUNT}/${TOTAL}"
    fi
fi

e2e_step "Scenario 1: crash replay report emits minimization and survivor artifacts"
if run_rch_capture "$RUN_RAW" cargo run --quiet -p ffs-harness -- run-crash-replay \
    --count 2 \
    --seed 424242 \
    --min-ops 8 \
    --max-ops 8 \
    --out "$ARTIFACT_DIR"; then
    python3 - "$RUN_RAW" "$REPORT_JSON" "$ARTIFACT_DIR" <<'PY'
import json
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text()
start = raw.find("{")
if start < 0:
    raise SystemExit("no JSON report in crash replay output")
report, _ = json.JSONDecoder().raw_decode(raw[start:])
Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
artifact_dir = Path(sys.argv[3])
rch_remote = "[RCH] remote" in raw
missing_remote_schedule_artifacts = 0
for result in report["results"]:
    schedule_path = artifact_dir / "schedules" / f"schedule_{result['schedule_id']:04}.json"
    if schedule_path.exists():
        schedule_artifact = json.loads(schedule_path.read_text())
        operations = schedule_artifact["schedule"].get("operations", [])
        if not operations:
            raise SystemExit(f"missing operation trace in {schedule_path}")
    elif rch_remote:
        missing_remote_schedule_artifacts += 1
    else:
        raise SystemExit(f"missing schedule artifact: {schedule_path}")
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
if missing_remote_schedule_artifacts:
    print(f"schedule artifacts were remote-only for {missing_remote_schedule_artifacts} RCH schedule(s)")
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
        "permissioned mounted crash replay external runner failed or emitted an invalid artifact"
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
        "permissioned repair-interruption external runner failed or emitted an invalid artifact"
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
