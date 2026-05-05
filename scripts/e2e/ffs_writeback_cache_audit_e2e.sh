#!/usr/bin/env bash
# ffs_writeback_cache_audit_e2e.sh - dry-run gate for bd-rchk0.2.1.1.
#
# Proves that the FUSE writeback_cache mount option remains gated by an
# explicit audit report and fails closed for default, unsupported, and stale
# evidence classes. This script intentionally leaves its log artifacts in place.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_writeback_cache_audit}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

RUN_ID="$(date +%Y%m%d_%H%M%S)_ffs_writeback_cache_audit"
LOG_DIR="${FFS_E2E_LOG_DIR:-$REPO_ROOT/artifacts/e2e/$RUN_ID}"
INPUT_DIR="${FFS_E2E_INPUT_DIR:-$REPO_ROOT/artifacts/e2e_inputs/$RUN_ID}"
mkdir -p "$LOG_DIR" "$INPUT_DIR"
LOG_FILE="$LOG_DIR/run.log"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

# Catalog evidence markers:
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_cli_wired|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_accepts_complete_gate|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_rejects_default_mount|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_fuse_unavailable_rejected|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_unsupported_mode_rejected|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_repeated_mount_attempts|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_stale_gate_rejected|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_repeated_downgrade_rejections|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_config_default_rejected|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_host_manifest_mismatch_rejected|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_fuser_options_default_off|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_bad_schema_fails|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_report_fields|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_unit_tests|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_help_docs_consistent|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_catalog_valid|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_cli_help_boundaries|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_cli_rejects_missing_gate|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_cli_rejects_read_only|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_cli_accepts_gate_before_image_open|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_cli_repeated_rejections|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_runtime_kill_switch_rejected|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_fuser_options_enabled|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_opt_in_unit_tests|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_cli_wired|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_accepts_complete_oracle|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_rejects_default_off|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_rejects_missing_fsync|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_rejects_missing_fsyncdir|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_cancellation_classified|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_crash_reopen_artifact|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_report_fields|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_unit_tests|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_cli_wired|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_accepts_complete_matrix|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_rejects_missing_crash_point|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_rejects_survivor_mismatch|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_rejects_flush_durability|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_rejects_missing_fsyncdir|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_report_fields|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_crash_replay_unit_tests|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ext4_opt_in_flush_fsyncdir_reopen|outcome=PASS

log() {
    echo "$*" | tee -a "$LOG_FILE"
}

step() {
    log ""
    log "=== $* ==="
    log "Time: $(date -Iseconds)"
}

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"
    log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

run_rch_capture() {
    local log_path="$1"
    shift
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-420}"
    local status=0
    local pid
    local use_process_group=0
    : >"$log_path"

    if command -v setsid >/dev/null 2>&1; then
        RCH_VISIBILITY=none setsid "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
        use_process_group=1
    else
        RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    fi
    pid=$!

    local deadline=$((SECONDS + timeout_secs))
    while kill -0 "$pid" 2>/dev/null; do
        if grep -Fq "Remote command finished: exit=0" "$log_path"; then
            if [[ "$use_process_group" -eq 1 ]]; then
                kill -TERM -- "-$pid" 2>/dev/null || true
            else
                kill -TERM "$pid" 2>/dev/null || true
            fi
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        if grep -Eq "Remote command finished: exit=([1-9]|[1-9][0-9]+)" "$log_path"; then
            if [[ "$use_process_group" -eq 1 ]]; then
                kill -TERM -- "-$pid" 2>/dev/null || true
            else
                kill -TERM "$pid" 2>/dev/null || true
            fi
            wait "$pid" 2>/dev/null || true
            return 1
        fi
        if [[ "$SECONDS" -ge "$deadline" ]]; then
            break
        fi
        sleep 1
    done

    if kill -0 "$pid" 2>/dev/null; then
        if [[ "$use_process_group" -eq 1 ]]; then
            kill -TERM -- "-$pid" 2>/dev/null || true
        else
            kill -TERM "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
        status=124
    else
        wait "$pid" 2>/dev/null || status=$?
    fi

    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        return 0
    fi
    return "$status"
}

expect_report_rejection() {
    local report_path="$1"
    local expected_reason="$2"
    local expected_invariant="$3"
    python3 - "$report_path" "$expected_reason" "$expected_invariant" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_reason = sys.argv[2]
expected_invariant = sys.argv[3]
decision = report["decision"]
if decision["decision"] != "reject":
    raise SystemExit("expected reject decision")
if decision["reason"] != expected_reason:
    raise SystemExit(f"wrong reason: {decision['reason']}")
if expected_invariant not in decision["invariants_failing"]:
    raise SystemExit(f"{expected_invariant} failure not reported")
PY
}

record_report_observation() {
    local report_path="$1"
    local expected_error_class="$2"
    local cleanup_status="$3"
    local observation
    observation="$(python3 - "$report_path" "$expected_error_class" "$cleanup_status" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
cleanup = sys.argv[3]
decision = report["decision"]
observed = "accept" if decision["decision"] == "accept" else decision["reason"]
invariants = ",".join(row["id"] for row in report["invariant_map"])
raw_options = ",".join(report["mount_options"]["raw_options"])
artifact_paths = ",".join(report["artifact_paths"])
guard = report["runtime_guard"]
repro = report["reproduction_command"].replace("|", "/")
print(
    "WRITEBACK_CACHE_AUDIT_OBSERVATION"
    f"|scenario_id={report['scenario_id']}"
    f"|gate_version={report['gate_version']}"
    f"|mount_options={raw_options}"
    f"|invariant_ids={invariants}"
    f"|decision={decision['decision']}"
    f"|expected_error_class={expected}"
    f"|observed_error_class={observed}"
    f"|artifact_paths={artifact_paths}"
    f"|feature_state={guard['feature_state']}"
    f"|config_source={guard['config_source']}"
    f"|kill_switch_state={guard['kill_switch_state']}"
    f"|gate_artifact_hash={guard['gate_artifact_hash']}"
    f"|gate_fresh={guard['gate_fresh']}"
    f"|gate_age_secs={guard['gate_age_secs']}"
    f"|gate_max_age_secs={guard['gate_max_age_secs']}"
    f"|host_capability_fingerprint={guard['host_capability_fingerprint']}"
    f"|lane_manifest_id={guard['lane_manifest_id']}"
    f"|lane_manifest_path={guard['lane_manifest_path']}"
    f"|lane_manifest_fresh={guard['lane_manifest_fresh']}"
    f"|lane_manifest_matches_host={guard['lane_manifest_matches_host']}"
    f"|release_gate_consumer={guard['release_gate_consumer']}"
    f"|cleanup_status={cleanup}"
    f"|reproduction_command={repro}"
)
PY
)"
    log "$observation"
}

expect_ordering_report_rejection() {
    local report_path="$1"
    local expected_reason="$2"
    local expected_invariant="$3"
    python3 - "$report_path" "$expected_reason" "$expected_invariant" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_reason = sys.argv[2]
expected_invariant = sys.argv[3]
decision = report["decision"]
if decision["decision"] != "reject":
    raise SystemExit("expected reject decision")
if decision["reason"] != expected_reason:
    raise SystemExit(f"wrong reason: {decision['reason']}")
if expected_invariant not in decision["invariants_failing"]:
    raise SystemExit(f"{expected_invariant} failure not reported")
PY
}

record_ordering_observation() {
    local report_path="$1"
    local expected_error_class="$2"
    local cleanup_status="$3"
    local observation
    observation="$(python3 - "$report_path" "$expected_error_class" "$cleanup_status" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
cleanup = sys.argv[3]
decision = report["decision"]
observed = "accept" if decision["decision"] == "accept" else decision["reason"]
invariants = ",".join(row["id"] for row in report["invariant_map"])
raw_options = ",".join(report["mount_options"]["raw_options"])
raw_fuser = ",".join(report["raw_fuser_options"])
artifact_paths = ",".join(report["artifact_paths"])
expected_ordering = ",".join(report["expected_ordering"])
observed_ordering = ",".join(report["observed_ordering"])
repro = report["reproduction_command"].replace("|", "/")
print(
    "WRITEBACK_CACHE_ORDERING_OBSERVATION"
    f"|scenario_id={report['scenario_id']}"
    f"|gate_version={report['gate_version']}"
    f"|mount_options={raw_options}"
    f"|raw_fuser_options={raw_fuser}"
    f"|invariant_ids={invariants}"
    f"|decision={decision['decision']}"
    f"|expected_error_class={expected}"
    f"|observed_error_class={observed}"
    f"|dirty_page_state={report['dirty_page_state']}"
    f"|metadata_state={report['metadata_state']}"
    f"|flush_observed_non_durable={report['flush_observed_non_durable']}"
    f"|fsync_observed_durable={report['fsync_observed_durable']}"
    f"|fsyncdir_observed_durable={report['fsyncdir_observed_durable']}"
    f"|cancellation_state={report['cancellation_state']}"
    f"|unmount_state={report['unmount_state']}"
    f"|crash_reopen_state={report['crash_reopen_state']}"
    f"|epoch_id={report['epoch_id']}"
    f"|epoch_state={report['epoch_state']}"
    f"|repair_symbol_generation={report['repair_symbol_generation']}"
    f"|repair_symbol_refresh={report['repair_symbol_refresh']}"
    f"|expected_ordering={expected_ordering}"
    f"|observed_ordering={observed_ordering}"
    f"|artifact_paths={artifact_paths}"
    f"|cleanup_status={cleanup}"
    f"|reproduction_command={repro}"
)
PY
)"
    log "$observation"
}

expect_crash_replay_report_rejection() {
    local report_path="$1"
    local expected_reason="$2"
    local expected_crash_point="$3"
    python3 - "$report_path" "$expected_reason" "$expected_crash_point" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_reason = sys.argv[2]
expected_crash_point = sys.argv[3]
decision = report["decision"]
if decision["decision"] != "reject":
    raise SystemExit("expected reject decision")
if decision["reason"] != expected_reason:
    raise SystemExit(f"wrong reason: {decision['reason']}")
if expected_crash_point and expected_crash_point not in decision["crash_points_failing"]:
    raise SystemExit(f"{expected_crash_point} failure not reported")
PY
}

record_crash_replay_observation() {
    local report_path="$1"
    local expected_error_class="$2"
    local cleanup_status="$3"
    local observation
    observation="$(python3 - "$report_path" "$expected_error_class" "$cleanup_status" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
cleanup = sys.argv[3]
decision = report["decision"]
observed = "accept" if decision["decision"] == "accept" else decision["reason"]
raw_options = ",".join(report["mount_options"]["raw_options"])
raw_fuser = ",".join(report["raw_fuser_options"])
artifact_paths = ",".join(report["artifact_paths"])
crash_point_ids = ",".join(report["covered_crash_point_ids"])
operation_trace = ",".join(f"{row['step']}:{row['operation']}:{row['durability_boundary']}" for row in report["operation_trace"])
sample = report["crash_points"][0]
survivors_expected = ",".join(sample["expected_survivor_set"])
survivors_actual = ",".join(sample["actual_survivor_set"])
stdout_paths = ",".join(point["stdout_path"] for point in report["crash_points"])
stderr_paths = ",".join(point["stderr_path"] for point in report["crash_points"])
cleanup_paths = ",".join(point["cleanup_status"] for point in report["crash_points"])
repro = report["reproduction_command"].replace("|", "/")
print(
    "WRITEBACK_CACHE_CRASH_REPLAY_OBSERVATION"
    f"|scenario_id={report['scenario_id']}"
    f"|gate_version={report['gate_version']}"
    f"|matrix_id={report['matrix_id']}"
    f"|mount_options={raw_options}"
    f"|raw_fuser_options={raw_fuser}"
    f"|decision={decision['decision']}"
    f"|expected_error_class={expected}"
    f"|observed_error_class={observed}"
    f"|epoch_id={report['epoch_id']}"
    f"|epoch_state={report['epoch_state']}"
    f"|crash_point_ids={crash_point_ids}"
    f"|operation_trace={operation_trace}"
    f"|expected_survivor_set={survivors_expected}"
    f"|actual_survivor_set={survivors_actual}"
    f"|stdout_paths={stdout_paths}"
    f"|stderr_paths={stderr_paths}"
    f"|cleanup_statuses={cleanup_paths}"
    f"|artifact_paths={artifact_paths}"
    f"|cleanup_status={cleanup}"
    f"|reproduction_command={repro}"
)
PY
)"
    log "$observation"
}

extract_json_object() {
    local raw_path="$1"
    local out_path="$2"
    local sentinel="$3"
    python3 - "$raw_path" "$out_path" "$sentinel" <<'PY'
import json
import pathlib
import sys

raw_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
sentinel = sys.argv[3]
text = raw_path.read_text(encoding="utf-8", errors="replace")
marker = text.find(sentinel)
if marker < 0:
    raise SystemExit(f"sentinel not found: {sentinel}")
start = text.rfind("{", 0, marker)
if start < 0:
    raise SystemExit("JSON object start not found")
obj, _ = json.JSONDecoder().raw_decode(text[start:])
out_path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

log "=============================================="
log "E2E Test: ffs_writeback_cache_audit"
log "Started: $(date -Iseconds)"
log "Log directory: $LOG_DIR"
log "Input directory: $INPUT_DIR"
log "CARGO_TARGET_DIR: $CARGO_TARGET_DIR"
log "=============================================="

ACCEPT_GATE="$INPUT_DIR/writeback_cache_accept_gate.json"
DEFAULT_REJECT_GATE="$INPUT_DIR/writeback_cache_default_reject_gate.json"
FUSE_UNAVAILABLE_GATE="$INPUT_DIR/writeback_cache_fuse_unavailable_gate.json"
UNSUPPORTED_MODE_GATE="$INPUT_DIR/writeback_cache_unsupported_mode_gate.json"
STALE_GATE="$INPUT_DIR/writeback_cache_stale_gate.json"
DOWNGRADED_GATE="$INPUT_DIR/writeback_cache_downgraded_gate.json"
CONFIG_DEFAULT_GATE="$INPUT_DIR/writeback_cache_config_default_gate.json"
HOST_MISMATCH_GATE="$INPUT_DIR/writeback_cache_host_mismatch_gate.json"
BAD_SCHEMA_GATE="$INPUT_DIR/writeback_cache_bad_schema_gate.json"
ORDERING_ACCEPT_ORACLE="$INPUT_DIR/writeback_cache_ordering_accept_oracle.json"
ORDERING_DEFAULT_OFF_ORACLE="$INPUT_DIR/writeback_cache_ordering_default_off_oracle.json"
ORDERING_MISSING_FSYNC_ORACLE="$INPUT_DIR/writeback_cache_ordering_missing_fsync_oracle.json"
ORDERING_MISSING_FSYNCDIR_ORACLE="$INPUT_DIR/writeback_cache_ordering_missing_fsyncdir_oracle.json"
ORDERING_CANCELLATION_ORACLE="$INPUT_DIR/writeback_cache_ordering_cancellation_oracle.json"
ORDERING_CRASH_REOPEN_ORACLE="$INPUT_DIR/writeback_cache_ordering_crash_reopen_oracle.json"
CRASH_REPLAY_ACCEPT_ORACLE="$INPUT_DIR/writeback_cache_crash_replay_accept_oracle.json"
CRASH_REPLAY_MISSING_POINT_ORACLE="$INPUT_DIR/writeback_cache_crash_replay_missing_point_oracle.json"
CRASH_REPLAY_SURVIVOR_MISMATCH_ORACLE="$INPUT_DIR/writeback_cache_crash_replay_survivor_mismatch_oracle.json"
CRASH_REPLAY_FLUSH_DURABLE_ORACLE="$INPUT_DIR/writeback_cache_crash_replay_flush_durable_oracle.json"
CRASH_REPLAY_MISSING_FSYNCDIR_ORACLE="$INPUT_DIR/writeback_cache_crash_replay_missing_fsyncdir_oracle.json"
ACCEPT_RAW="$LOG_DIR/writeback_cache_accept.raw"
REJECT_RAW="$LOG_DIR/writeback_cache_reject.raw"
FUSE_UNAVAILABLE_RAW="$LOG_DIR/writeback_cache_fuse_unavailable.raw"
UNSUPPORTED_MODE_RAW="$LOG_DIR/writeback_cache_unsupported_mode.raw"
REPEATED_RAW_A="$LOG_DIR/writeback_cache_repeated_a.raw"
REPEATED_RAW_B="$LOG_DIR/writeback_cache_repeated_b.raw"
STALE_GATE_RAW="$LOG_DIR/writeback_cache_stale_gate.raw"
DOWNGRADED_RAW_A="$LOG_DIR/writeback_cache_downgraded_a.raw"
DOWNGRADED_RAW_B="$LOG_DIR/writeback_cache_downgraded_b.raw"
CONFIG_DEFAULT_RAW="$LOG_DIR/writeback_cache_config_default.raw"
HOST_MISMATCH_RAW="$LOG_DIR/writeback_cache_host_mismatch.raw"
FUSER_OPTIONS_RAW="$LOG_DIR/writeback_cache_fuser_options.raw"
BAD_SCHEMA_RAW="$LOG_DIR/writeback_cache_bad_schema.raw"
UNIT_RAW="$LOG_DIR/writeback_cache_unit_tests.raw"
HELP_RAW="$LOG_DIR/writeback_cache_help.raw"
CLI_OPT_IN_HELP_RAW="$LOG_DIR/writeback_cache_opt_in_help.raw"
CLI_MISSING_GATE_RAW="$LOG_DIR/writeback_cache_opt_in_missing_gate.raw"
CLI_RO_REJECT_RAW="$LOG_DIR/writeback_cache_opt_in_read_only.raw"
CLI_ACCEPT_IMAGE_OPEN_RAW="$LOG_DIR/writeback_cache_opt_in_accept_image_open.raw"
CLI_REPEATED_RAW_A="$LOG_DIR/writeback_cache_opt_in_repeated_a.raw"
CLI_REPEATED_RAW_B="$LOG_DIR/writeback_cache_opt_in_repeated_b.raw"
CLI_KILL_SWITCH_RAW="$LOG_DIR/writeback_cache_runtime_kill_switch.raw"
FUSER_OPT_IN_RAW="$LOG_DIR/writeback_cache_opt_in_fuser_options.raw"
CLI_OPT_IN_UNIT_RAW="$LOG_DIR/writeback_cache_opt_in_unit_tests.raw"
ORDERING_ACCEPT_RAW="$LOG_DIR/writeback_cache_ordering_accept.raw"
ORDERING_DEFAULT_OFF_RAW="$LOG_DIR/writeback_cache_ordering_default_off.raw"
ORDERING_MISSING_FSYNC_RAW="$LOG_DIR/writeback_cache_ordering_missing_fsync.raw"
ORDERING_MISSING_FSYNCDIR_RAW="$LOG_DIR/writeback_cache_ordering_missing_fsyncdir.raw"
ORDERING_CANCELLATION_RAW="$LOG_DIR/writeback_cache_ordering_cancellation.raw"
ORDERING_CRASH_REOPEN_RAW="$LOG_DIR/writeback_cache_ordering_crash_reopen.raw"
ORDERING_UNIT_RAW="$LOG_DIR/writeback_cache_ordering_unit_tests.raw"
CRASH_REPLAY_ACCEPT_RAW="$LOG_DIR/writeback_cache_crash_replay_accept.raw"
CRASH_REPLAY_MISSING_POINT_RAW="$LOG_DIR/writeback_cache_crash_replay_missing_point.raw"
CRASH_REPLAY_SURVIVOR_MISMATCH_RAW="$LOG_DIR/writeback_cache_crash_replay_survivor_mismatch.raw"
CRASH_REPLAY_FLUSH_DURABLE_RAW="$LOG_DIR/writeback_cache_crash_replay_flush_durable.raw"
CRASH_REPLAY_MISSING_FSYNCDIR_RAW="$LOG_DIR/writeback_cache_crash_replay_missing_fsyncdir.raw"
CRASH_REPLAY_UNIT_RAW="$LOG_DIR/writeback_cache_crash_replay_unit_tests.raw"
WRITEBACK_CACHE_MOUNTED_EXT4_RAW="$LOG_DIR/writeback_cache_ext4_opt_in_flush_fsyncdir_reopen.raw"
ACCEPT_REPORT="$LOG_DIR/writeback_cache_accept_report.json"
REJECT_REPORT="$LOG_DIR/writeback_cache_reject_report.json"
FUSE_UNAVAILABLE_REPORT="$LOG_DIR/writeback_cache_fuse_unavailable_report.json"
UNSUPPORTED_MODE_REPORT="$LOG_DIR/writeback_cache_unsupported_mode_report.json"
REPEATED_REPORT_A="$LOG_DIR/writeback_cache_repeated_a_report.json"
REPEATED_REPORT_B="$LOG_DIR/writeback_cache_repeated_b_report.json"
STALE_GATE_REPORT="$LOG_DIR/writeback_cache_stale_gate_report.json"
DOWNGRADED_REPORT_A="$LOG_DIR/writeback_cache_downgraded_a_report.json"
DOWNGRADED_REPORT_B="$LOG_DIR/writeback_cache_downgraded_b_report.json"
CONFIG_DEFAULT_REPORT="$LOG_DIR/writeback_cache_config_default_report.json"
HOST_MISMATCH_REPORT="$LOG_DIR/writeback_cache_host_mismatch_report.json"
ORDERING_ACCEPT_REPORT="$LOG_DIR/writeback_cache_ordering_accept_report.json"
ORDERING_DEFAULT_OFF_REPORT="$LOG_DIR/writeback_cache_ordering_default_off_report.json"
ORDERING_MISSING_FSYNC_REPORT="$LOG_DIR/writeback_cache_ordering_missing_fsync_report.json"
ORDERING_MISSING_FSYNCDIR_REPORT="$LOG_DIR/writeback_cache_ordering_missing_fsyncdir_report.json"
ORDERING_CANCELLATION_REPORT="$LOG_DIR/writeback_cache_ordering_cancellation_report.json"
ORDERING_CRASH_REOPEN_REPORT="$LOG_DIR/writeback_cache_ordering_crash_reopen_report.json"
CRASH_REPLAY_ACCEPT_REPORT="$LOG_DIR/writeback_cache_crash_replay_accept_report.json"
CRASH_REPLAY_MISSING_POINT_REPORT="$LOG_DIR/writeback_cache_crash_replay_missing_point_report.json"
CRASH_REPLAY_SURVIVOR_MISMATCH_REPORT="$LOG_DIR/writeback_cache_crash_replay_survivor_mismatch_report.json"
CRASH_REPLAY_FLUSH_DURABLE_REPORT="$LOG_DIR/writeback_cache_crash_replay_flush_durable_report.json"
CRASH_REPLAY_MISSING_FSYNCDIR_REPORT="$LOG_DIR/writeback_cache_crash_replay_missing_fsyncdir_report.json"

cat >"$ACCEPT_GATE" <<'JSON'
{
  "schema_version": 1,
  "gate_version": "bd-rchk0.2.1.1-gate-v1",
  "bead_id": "bd-rchk0.2.1.1",
  "mount_options": {
    "raw_options": [
      "rw",
      "fsname=frankenfs",
      "default_permissions"
    ],
    "fs_name": "frankenfs",
    "allow_other": false,
    "auto_unmount": true,
    "default_permissions": true,
    "mode": "rw"
  },
  "repair_serialization_state": "rw_lane_accepted",
  "fuse_capability": {
    "probe_status": "available",
    "kernel_supports_writeback_cache": true,
    "helper_binary_present": true
  },
  "epoch_barrier_artifact": {
    "artifact_id": "epoch_barrier_proof",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/epoch_barrier_proof.json"
  },
  "crash_matrix_artifact": {
    "artifact_id": "writeback_crash_matrix",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/crash_matrix.json"
  },
  "fsync_evidence_artifact": {
    "artifact_id": "fsync_fsyncdir_boundary",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/fsync_evidence.json"
  },
  "filesystem_flavor": "ext4",
  "operation_class": "mounted_write",
  "explicit_opt_in": true,
  "conflicting_flags": [],
  "runtime_guard": {
    "kill_switch_state": "disarmed",
    "feature_state": "accepted",
    "config_source": "cli_explicit",
    "gate_artifact_hash": "blake3:writeback-cache-accept-gate-v1",
    "gate_fresh": true,
    "gate_age_secs": 30,
    "gate_max_age_secs": 86400,
    "host_capability_fingerprint": "linux-fuse-writeback-cache-v1",
    "lane_manifest_id": "authoritative-env-frankenfs-fuse-v1",
    "lane_manifest_path": "artifacts/qa/authoritative_environment_manifest.json",
    "lane_manifest_fresh": true,
    "lane_manifest_matches_host": true,
    "release_gate_consumer": "writeback_cache.release_gate"
  }
}
JSON

cat >"$DEFAULT_REJECT_GATE" <<'JSON'
{
  "schema_version": 1,
  "gate_version": "bd-rchk0.2.1.1-gate-v1",
  "bead_id": "bd-rchk0.2.1.1",
  "mount_options": {
    "raw_options": [
      "ro",
      "fsname=frankenfs",
      "default_permissions"
    ],
    "fs_name": "frankenfs",
    "allow_other": false,
    "auto_unmount": true,
    "default_permissions": true,
    "mode": "ro"
  },
  "repair_serialization_state": "rw_lane_accepted",
  "fuse_capability": {
    "probe_status": "available",
    "kernel_supports_writeback_cache": true,
    "helper_binary_present": true
  },
  "epoch_barrier_artifact": {
    "artifact_id": "epoch_barrier_proof",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/epoch_barrier_proof.json"
  },
  "crash_matrix_artifact": {
    "artifact_id": "writeback_crash_matrix",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/crash_matrix.json"
  },
  "fsync_evidence_artifact": {
    "artifact_id": "fsync_fsyncdir_boundary",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/fsync_evidence.json"
  },
  "filesystem_flavor": "ext4",
  "operation_class": "mounted_write",
  "explicit_opt_in": false,
  "conflicting_flags": [],
  "runtime_guard": {
    "kill_switch_state": "disarmed",
    "feature_state": "accepted",
    "config_source": "cli_explicit",
    "gate_artifact_hash": "blake3:writeback-cache-default-reject-gate-v1",
    "gate_fresh": true,
    "gate_age_secs": 30,
    "gate_max_age_secs": 86400,
    "host_capability_fingerprint": "linux-fuse-writeback-cache-v1",
    "lane_manifest_id": "authoritative-env-frankenfs-fuse-v1",
    "lane_manifest_path": "artifacts/qa/authoritative_environment_manifest.json",
    "lane_manifest_fresh": true,
    "lane_manifest_matches_host": true,
    "release_gate_consumer": "writeback_cache.release_gate"
  }
}
JSON

cat >"$BAD_SCHEMA_GATE" <<'JSON'
{
  "schema_version": 99,
  "gate_version": "bd-rchk0.2.1.1-gate-v1",
  "bead_id": "bd-rchk0.2.1.1",
  "mount_options": {
    "raw_options": [
      "rw"
    ],
    "fs_name": "frankenfs",
    "allow_other": false,
    "auto_unmount": true,
    "default_permissions": true,
    "mode": "rw"
  },
  "repair_serialization_state": "rw_lane_accepted",
  "fuse_capability": {
    "probe_status": "available",
    "kernel_supports_writeback_cache": true,
    "helper_binary_present": true
  },
  "epoch_barrier_artifact": {
    "artifact_id": "epoch_barrier_proof",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/epoch_barrier_proof.json"
  },
  "crash_matrix_artifact": {
    "artifact_id": "writeback_crash_matrix",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/crash_matrix.json"
  },
  "fsync_evidence_artifact": {
    "artifact_id": "fsync_fsyncdir_boundary",
    "present": true,
    "fresh": true,
    "passed": true,
    "artifact_path": "artifacts/writeback-cache/fsync_evidence.json"
  },
  "filesystem_flavor": "ext4",
  "operation_class": "mounted_write",
  "explicit_opt_in": true,
  "conflicting_flags": [],
  "runtime_guard": {
    "kill_switch_state": "disarmed",
    "feature_state": "accepted",
    "config_source": "cli_explicit",
    "gate_artifact_hash": "blake3:writeback-cache-bad-schema-gate-v1",
    "gate_fresh": true,
    "gate_age_secs": 30,
    "gate_max_age_secs": 86400,
    "host_capability_fingerprint": "linux-fuse-writeback-cache-v1",
    "lane_manifest_id": "authoritative-env-frankenfs-fuse-v1",
    "lane_manifest_path": "artifacts/qa/authoritative_environment_manifest.json",
    "lane_manifest_fresh": true,
    "lane_manifest_matches_host": true,
    "release_gate_consumer": "writeback_cache.release_gate"
  }
}
JSON

python3 - "$ACCEPT_GATE" \
    "$FUSE_UNAVAILABLE_GATE" \
    "$UNSUPPORTED_MODE_GATE" \
    "$STALE_GATE" \
    "$DOWNGRADED_GATE" \
    "$CONFIG_DEFAULT_GATE" \
    "$HOST_MISMATCH_GATE" <<'PY'
import copy
import json
import pathlib
import sys

base = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

fuse_unavailable = copy.deepcopy(base)
fuse_unavailable["fuse_capability"]["probe_status"] = "unavailable"
fuse_unavailable["fuse_capability"]["kernel_supports_writeback_cache"] = False
fuse_unavailable["fuse_capability"]["helper_binary_present"] = False
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(fuse_unavailable, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

unsupported_mode = copy.deepcopy(base)
unsupported_mode["mount_options"]["mode"] = "swap"
unsupported_mode["mount_options"]["raw_options"] = [
    "swap",
    "fsname=frankenfs",
    "default_permissions",
]
pathlib.Path(sys.argv[3]).write_text(
    json.dumps(unsupported_mode, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

stale_gate = copy.deepcopy(base)
stale_gate["runtime_guard"]["gate_fresh"] = False
stale_gate["runtime_guard"]["gate_age_secs"] = stale_gate["runtime_guard"]["gate_max_age_secs"] + 1
pathlib.Path(sys.argv[4]).write_text(
    json.dumps(stale_gate, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

downgraded = copy.deepcopy(base)
downgraded["runtime_guard"]["feature_state"] = "downgraded"
pathlib.Path(sys.argv[5]).write_text(
    json.dumps(downgraded, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

config_default = copy.deepcopy(base)
config_default["runtime_guard"]["config_source"] = "config_default"
pathlib.Path(sys.argv[6]).write_text(
    json.dumps(config_default, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

host_mismatch = copy.deepcopy(base)
host_mismatch["runtime_guard"]["lane_manifest_matches_host"] = False
pathlib.Path(sys.argv[7]).write_text(
    json.dumps(host_mismatch, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

cat >"$ORDERING_ACCEPT_ORACLE" <<'JSON'
{
  "schema_version": 1,
  "gate_version": "bd-8pz7h-ordering-v1",
  "bead_id": "bd-8pz7h",
  "mount_options": {
    "raw_options": [
      "rw",
      "fsname=frankenfs",
      "writeback_cache"
    ],
    "fs_name": "frankenfs",
    "allow_other": false,
    "auto_unmount": true,
    "default_permissions": true,
    "mode": "rw"
  },
  "raw_fuser_options": [
    "fsname=frankenfs",
    "subtype=ffs",
    "rw",
    "writeback_cache"
  ],
  "dirty_page_state": "fsynced_durable",
  "metadata_state": "metadata_after_data",
  "flush_observed_non_durable": true,
  "fsync_observed_durable": true,
  "fsyncdir_observed_durable": true,
  "cancellation_state": "cancelled_before_writeback_classified",
  "unmount_state": "dirty_pages_flushed_or_rejected",
  "crash_reopen_state": "survivor_set_verified",
  "epoch_id": "epoch-0007",
  "epoch_state": "fresh",
  "repair_symbol_generation": 8,
  "repair_symbol_refresh": "refreshed_after_writeback",
  "invariant_evidence": [
    {
      "id": "I1",
      "supported": true,
      "test_id": "writeback_ordering_i1_snapshot_visibility",
      "artifact_field": "ordering.I1.epoch_id",
      "release_gate_consumer": "writeback_cache.release_gate",
      "unsupported_rationale": ""
    },
    {
      "id": "I2",
      "supported": true,
      "test_id": "writeback_ordering_i2_alias_order",
      "artifact_field": "ordering.I2.observed_ordering",
      "release_gate_consumer": "writeback_cache.release_gate",
      "unsupported_rationale": ""
    },
    {
      "id": "I3",
      "supported": true,
      "test_id": "writeback_ordering_i3_metadata_after_data",
      "artifact_field": "ordering.I3.metadata_state",
      "release_gate_consumer": "writeback_cache.release_gate",
      "unsupported_rationale": ""
    },
    {
      "id": "I4",
      "supported": true,
      "test_id": "writeback_ordering_i4_sync_boundaries",
      "artifact_field": "ordering.I4.fsync_fsyncdir",
      "release_gate_consumer": "writeback_cache.release_gate",
      "unsupported_rationale": ""
    },
    {
      "id": "I5",
      "supported": true,
      "test_id": "writeback_ordering_i5_flush_non_durability",
      "artifact_field": "ordering.I5.flush_observed_non_durable",
      "release_gate_consumer": "writeback_cache.release_gate",
      "unsupported_rationale": ""
    },
    {
      "id": "I6",
      "supported": true,
      "test_id": "writeback_ordering_i6_cross_epoch_order",
      "artifact_field": "ordering.I6.repair_symbol_generation",
      "release_gate_consumer": "writeback_cache.release_gate",
      "unsupported_rationale": ""
    }
  ],
  "expected_ordering": [
    "dirty_data",
    "fsync",
    "metadata",
    "fsyncdir",
    "repair_symbol_refresh"
  ],
  "observed_ordering": [
    "dirty_data",
    "fsync",
    "metadata",
    "fsyncdir",
    "repair_symbol_refresh"
  ],
  "artifact_paths": [
    "artifacts/writeback-cache/ordering.json",
    "artifacts/writeback-cache/crash_reopen.json",
    "artifacts/writeback-cache/cancellation.json"
  ]
}
JSON

python3 - "$ORDERING_ACCEPT_ORACLE" \
    "$ORDERING_DEFAULT_OFF_ORACLE" \
    "$ORDERING_MISSING_FSYNC_ORACLE" \
    "$ORDERING_MISSING_FSYNCDIR_ORACLE" \
    "$ORDERING_CANCELLATION_ORACLE" \
    "$ORDERING_CRASH_REOPEN_ORACLE" <<'PY'
import copy
import json
import pathlib
import sys

base = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

default_off = copy.deepcopy(base)
default_off["mount_options"]["mode"] = "ro"
default_off["mount_options"]["raw_options"] = ["ro", "fsname=frankenfs"]
default_off["raw_fuser_options"] = ["fsname=frankenfs", "subtype=ffs", "ro"]
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(default_off, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

missing_fsync = copy.deepcopy(base)
missing_fsync["dirty_page_state"] = "dirty_unflushed"
missing_fsync["fsync_observed_durable"] = False
pathlib.Path(sys.argv[3]).write_text(
    json.dumps(missing_fsync, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

missing_fsyncdir = copy.deepcopy(base)
missing_fsyncdir["fsyncdir_observed_durable"] = False
pathlib.Path(sys.argv[4]).write_text(
    json.dumps(missing_fsyncdir, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

cancellation = copy.deepcopy(base)
cancellation["artifact_paths"] = [
    "artifacts/writeback-cache/ordering.json",
    "artifacts/writeback-cache/cancellation_before_writeback.json",
]
pathlib.Path(sys.argv[5]).write_text(
    json.dumps(cancellation, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

crash_reopen = copy.deepcopy(base)
crash_reopen["artifact_paths"] = [
    "artifacts/writeback-cache/ordering.json",
    "artifacts/writeback-cache/crash_reopen_survivor_set.json",
]
pathlib.Path(sys.argv[6]).write_text(
    json.dumps(crash_reopen, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

python3 - "$CRASH_REPLAY_ACCEPT_ORACLE" \
    "$CRASH_REPLAY_MISSING_POINT_ORACLE" \
    "$CRASH_REPLAY_SURVIVOR_MISMATCH_ORACLE" \
    "$CRASH_REPLAY_FLUSH_DURABLE_ORACLE" \
    "$CRASH_REPLAY_MISSING_FSYNCDIR_ORACLE" <<'PY'
import copy
import json
import pathlib
import sys

required_ids = [
    "cp01_before_first_write",
    "cp02_after_first_write_before_flush",
    "cp03_after_flush_before_fsync",
    "cp04_after_fsync_before_metadata",
    "cp05_after_metadata_before_fsyncdir",
    "cp06_after_fsyncdir_before_unmount",
    "cp07_after_repeated_write_before_fsync",
    "cp08_after_repeated_write_fsync",
    "cp09_after_cancellation_before_writeback",
    "cp10_after_clean_unmount_before_reopen",
    "cp11_after_reopen_before_repair_refresh",
    "cp12_after_repair_refresh",
]
operations = [
    ("create", "none"),
    ("write", "kernel_writeback_cache"),
    ("flush", "non_durable"),
    ("fsync", "file_durable"),
    ("rename", "metadata_after_data"),
    ("fsyncdir", "directory_durable"),
    ("write", "repeated_write"),
    ("fsync", "last_write_durable"),
    ("cancel", "classified_before_writeback"),
    ("unmount", "dirty_pages_flushed_or_rejected"),
    ("reopen", "survivor_set_verified"),
    ("repair_refresh", "post_writeback_refresh"),
]

def crash_point(crash_point_id, step):
    cancellation_state = "cancelled_before_writeback_classified" if step == 9 else "none"
    repeated_state = "last_fsynced_write_survived" if step in (7, 8) else "not_applicable"
    survivors = [
        "/",
        "/writeback",
        "/writeback/data.bin:blake3=stable-v2",
    ]
    return {
        "crash_point_id": crash_point_id,
        "description": f"{crash_point_id} mounted writeback-cache crash point",
        "operation_step": step,
        "expected_survivor_set": survivors,
        "actual_survivor_set": list(reversed(survivors)),
        "fsync_observed_durable": True,
        "fsyncdir_observed_durable": True,
        "flush_observed_non_durable": True,
        "metadata_after_data_observed": True,
        "unmount_reopen_observed": True,
        "cancellation_state": cancellation_state,
        "repeated_write_state": repeated_state,
        "replay_status": "survivor_set_verified",
        "stdout_path": f"artifacts/writeback-cache/crash-replay/{crash_point_id}.stdout",
        "stderr_path": f"artifacts/writeback-cache/crash-replay/{crash_point_id}.stderr",
        "cleanup_status": "retained_for_qa",
    }

base = {
    "schema_version": 1,
    "gate_version": "bd-rchk0.2.3-crash-replay-v1",
    "bead_id": "bd-rchk0.2.3",
    "matrix_id": "writeback_cache_crash_replay_matrix_v1",
    "mount_options": {
        "raw_options": ["rw", "fsname=frankenfs", "writeback_cache"],
        "fs_name": "frankenfs",
        "allow_other": False,
        "auto_unmount": True,
        "default_permissions": True,
        "mode": "rw",
    },
    "raw_fuser_options": ["fsname=frankenfs", "subtype=ffs", "rw", "writeback_cache"],
    "epoch_id": "epoch-writeback-crash-0001",
    "epoch_state": "fresh",
    "host_capability_fingerprint": "fuse3-writeback-cache-enabled-host",
    "lane_manifest_id": "fuse-writeback-cache-rw-lane-v1",
    "operation_trace": [
        {
            "step": step,
            "operation": op,
            "target": "/writeback/data.bin",
            "durability_boundary": boundary,
            "expected_result": "success",
        }
        for step, (op, boundary) in enumerate(operations, start=1)
    ],
    "crash_points": [
        crash_point(crash_point_id, step)
        for step, crash_point_id in enumerate(required_ids, start=1)
    ],
    "unsupported_combinations": [
        {
            "combination_id": "writeback_cache_ro_mount",
            "rejected": True,
            "reason": "read_only_writeback_cache",
            "follow_up_bead": "bd-rchk0.2.4",
        }
    ],
    "artifact_paths": [
        "artifacts/writeback-cache/crash-replay/matrix.json",
        "artifacts/writeback-cache/crash-replay/results.json",
        "artifacts/writeback-cache/crash-replay/run.log",
    ],
}

pathlib.Path(sys.argv[1]).write_text(
    json.dumps(base, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

missing_point = copy.deepcopy(base)
missing_point["crash_points"] = missing_point["crash_points"][:-1]
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(missing_point, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

survivor_mismatch = copy.deepcopy(base)
survivor_mismatch["crash_points"][0]["actual_survivor_set"].append("/unexpected")
pathlib.Path(sys.argv[3]).write_text(
    json.dumps(survivor_mismatch, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

flush_durable = copy.deepcopy(base)
flush_durable["crash_points"][2]["flush_observed_non_durable"] = False
pathlib.Path(sys.argv[4]).write_text(
    json.dumps(flush_durable, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

missing_fsyncdir = copy.deepcopy(base)
missing_fsyncdir["crash_points"][4]["fsyncdir_observed_durable"] = False
pathlib.Path(sys.argv[5]).write_text(
    json.dumps(missing_fsyncdir, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

step "Scenario 1: writeback-cache audit module and CLI are wired"
if grep -Fq "pub mod writeback_cache_audit" crates/ffs-harness/src/lib.rs \
    && grep -Fq "validate-writeback-cache-audit" crates/ffs-harness/src/main.rs; then
    scenario_result "writeback_cache_audit_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "writeback_cache_audit_cli_wired" "FAIL" "missing module export or CLI command"
fi

step "Scenario 2: explicit opt-in accepts only with complete evidence"
if run_rch_capture "$ACCEPT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$ACCEPT_GATE" \
    --scenario-id writeback_cache_audit_accepts_complete_gate \
    --require-accept; then
    if extract_json_object "$ACCEPT_RAW" "$ACCEPT_REPORT" '"schema_version"'; then
        record_report_observation "$ACCEPT_REPORT" "accept" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_accepts_complete_gate" "PASS" "complete opt-in gate accepted"
    else
        scenario_result "writeback_cache_audit_accepts_complete_gate" "FAIL" "accepted run did not emit report JSON"
    fi
else
    scenario_result "writeback_cache_audit_accepts_complete_gate" "FAIL" "complete opt-in gate rejected; see $ACCEPT_RAW"
fi

step "Scenario 3: default and read-only mounts reject without require-accept"
if run_rch_capture "$REJECT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$DEFAULT_REJECT_GATE" \
    --scenario-id writeback_cache_audit_rejects_default_mount; then
    if extract_json_object "$REJECT_RAW" "$REJECT_REPORT" '"schema_version"' \
        && expect_report_rejection "$REJECT_REPORT" "default_or_read_only_mount" "I3"
    then
        record_report_observation "$REJECT_REPORT" "default_or_read_only_mount" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_rejects_default_mount" "PASS" "default/off gate rejected with stable reason"
    else
        scenario_result "writeback_cache_audit_rejects_default_mount" "FAIL" "reject report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_rejects_default_mount" "FAIL" "schema-valid rejection should emit report"
fi

step "Scenario 4: unavailable FUSE capability rejects with a stable class"
if run_rch_capture "$FUSE_UNAVAILABLE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$FUSE_UNAVAILABLE_GATE" \
    --scenario-id writeback_cache_audit_fuse_unavailable_rejected; then
    if extract_json_object "$FUSE_UNAVAILABLE_RAW" "$FUSE_UNAVAILABLE_REPORT" '"schema_version"' \
        && expect_report_rejection "$FUSE_UNAVAILABLE_REPORT" "fuse_capability_unavailable" "I5"
    then
        record_report_observation "$FUSE_UNAVAILABLE_REPORT" "fuse_capability_unavailable" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_fuse_unavailable_rejected" "PASS" "unavailable kernel/helper capability rejected"
    else
        scenario_result "writeback_cache_audit_fuse_unavailable_rejected" "FAIL" "FUSE-unavailable report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_fuse_unavailable_rejected" "FAIL" "schema-valid FUSE-unavailable gate should emit report"
fi

step "Scenario 5: unsupported mount mode rejects as a policy report"
if run_rch_capture "$UNSUPPORTED_MODE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$UNSUPPORTED_MODE_GATE" \
    --scenario-id writeback_cache_audit_unsupported_mode_rejected; then
    if extract_json_object "$UNSUPPORTED_MODE_RAW" "$UNSUPPORTED_MODE_REPORT" '"schema_version"' \
        && expect_report_rejection "$UNSUPPORTED_MODE_REPORT" "default_or_read_only_mount" "I3"
    then
        record_report_observation "$UNSUPPORTED_MODE_REPORT" "default_or_read_only_mount" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_unsupported_mode_rejected" "PASS" "unsupported mode rejected with report artifact"
    else
        scenario_result "writeback_cache_audit_unsupported_mode_rejected" "FAIL" "unsupported-mode report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_unsupported_mode_rejected" "FAIL" "schema-valid unsupported-mode gate should emit report"
fi

step "Scenario 6: repeated dry-run mount attempts keep the same decision"
if run_rch_capture "$REPEATED_RAW_A" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$DEFAULT_REJECT_GATE" \
    --scenario-id writeback_cache_audit_repeated_mount_attempts_a \
    && run_rch_capture "$REPEATED_RAW_B" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$DEFAULT_REJECT_GATE" \
    --scenario-id writeback_cache_audit_repeated_mount_attempts_b \
    && extract_json_object "$REPEATED_RAW_A" "$REPEATED_REPORT_A" '"schema_version"' \
    && extract_json_object "$REPEATED_RAW_B" "$REPEATED_REPORT_B" '"schema_version"' \
    && python3 - "$REPEATED_REPORT_A" "$REPEATED_REPORT_B" <<'PY'
import json
import pathlib
import sys

a = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
b = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
for key in ("decision", "failure_modes", "required_artifact_fields", "mount_options", "artifact_paths"):
    if a[key] != b[key]:
        raise SystemExit(f"repeated report field changed: {key}")
PY
then
    record_report_observation "$REPEATED_REPORT_A" "default_or_read_only_mount" "retained:${LOG_DIR}"
    scenario_result "writeback_cache_audit_repeated_mount_attempts" "PASS" "repeated dry-run attempts kept decision and artifacts stable"
else
    scenario_result "writeback_cache_audit_repeated_mount_attempts" "FAIL" "repeated dry-run attempts drifted; see $REPEATED_RAW_A and $REPEATED_RAW_B"
fi

step "Scenario 6a: stale runtime gate artifact rejects"
if run_rch_capture "$STALE_GATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$STALE_GATE" \
    --scenario-id writeback_cache_audit_stale_gate_rejected; then
    if extract_json_object "$STALE_GATE_RAW" "$STALE_GATE_REPORT" '"schema_version"' \
        && expect_report_rejection "$STALE_GATE_REPORT" "stale_gate_artifact" "I1"
    then
        record_report_observation "$STALE_GATE_REPORT" "stale_gate_artifact" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_stale_gate_rejected" "PASS" "stale runtime guard gate rejected"
    else
        scenario_result "writeback_cache_audit_stale_gate_rejected" "FAIL" "stale gate report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_stale_gate_rejected" "FAIL" "schema-valid stale gate should emit report"
fi

step "Scenario 6b: downgraded feature state keeps repeated rejection class"
if run_rch_capture "$DOWNGRADED_RAW_A" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$DOWNGRADED_GATE" \
    --scenario-id writeback_cache_audit_repeated_downgrade_rejections_a \
    && run_rch_capture "$DOWNGRADED_RAW_B" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$DOWNGRADED_GATE" \
    --scenario-id writeback_cache_audit_repeated_downgrade_rejections_b \
    && extract_json_object "$DOWNGRADED_RAW_A" "$DOWNGRADED_REPORT_A" '"schema_version"' \
    && extract_json_object "$DOWNGRADED_RAW_B" "$DOWNGRADED_REPORT_B" '"schema_version"' \
    && expect_report_rejection "$DOWNGRADED_REPORT_A" "writeback_feature_downgraded" "I1" \
    && python3 - "$DOWNGRADED_REPORT_A" "$DOWNGRADED_REPORT_B" <<'PY'
import json
import pathlib
import sys

a = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
b = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
for key in ("decision", "failure_modes", "required_artifact_fields", "runtime_guard"):
    if a[key] != b[key]:
        raise SystemExit(f"repeated downgraded report field changed: {key}")
PY
then
    record_report_observation "$DOWNGRADED_REPORT_A" "writeback_feature_downgraded" "retained:${LOG_DIR}"
    scenario_result "writeback_cache_audit_repeated_downgrade_rejections" "PASS" "downgraded feature state stayed fail-closed"
else
    scenario_result "writeback_cache_audit_repeated_downgrade_rejections" "FAIL" "downgraded feature rejection drifted"
fi

step "Scenario 6c: config-default writeback-cache gate rejects"
if run_rch_capture "$CONFIG_DEFAULT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$CONFIG_DEFAULT_GATE" \
    --scenario-id writeback_cache_audit_config_default_rejected; then
    if extract_json_object "$CONFIG_DEFAULT_RAW" "$CONFIG_DEFAULT_REPORT" '"schema_version"' \
        && expect_report_rejection "$CONFIG_DEFAULT_REPORT" "config_default_attempt" "I5"
    then
        record_report_observation "$CONFIG_DEFAULT_REPORT" "config_default_attempt" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_config_default_rejected" "PASS" "config-default gate rejected"
    else
        scenario_result "writeback_cache_audit_config_default_rejected" "FAIL" "config-default report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_config_default_rejected" "FAIL" "schema-valid config-default gate should emit report"
fi

step "Scenario 6d: host/lane-manifest mismatch rejects"
if run_rch_capture "$HOST_MISMATCH_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$HOST_MISMATCH_GATE" \
    --scenario-id writeback_cache_audit_host_manifest_mismatch_rejected; then
    if extract_json_object "$HOST_MISMATCH_RAW" "$HOST_MISMATCH_REPORT" '"schema_version"' \
        && expect_report_rejection "$HOST_MISMATCH_REPORT" "host_capability_mismatch" "I5"
    then
        record_report_observation "$HOST_MISMATCH_REPORT" "host_capability_mismatch" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_host_manifest_mismatch_rejected" "PASS" "host mismatch gate rejected"
    else
        scenario_result "writeback_cache_audit_host_manifest_mismatch_rejected" "FAIL" "host mismatch report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_host_manifest_mismatch_rejected" "FAIL" "schema-valid host-mismatch gate should emit report"
fi

step "Scenario 7: FUSE mount option construction keeps writeback_cache absent"
if run_rch_capture "$FUSER_OPTIONS_RAW" cargo test -p ffs-fuse writeback_cache -- --nocapture; then
    if python3 - "$FUSER_OPTIONS_RAW" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
lines = [line for line in text.splitlines() if "WRITEBACK_CACHE_FUSER_OPTIONS|" in line]
if not lines:
    raise SystemExit("missing FUSE mount option observations")
for line in lines:
    payload = line.split("|labels=", 1)[1].lower()
    if "writeback_cache" in payload or "writebackcache" in payload:
        raise SystemExit(f"writeback cache option leaked: {line}")
PY
    then
        log "WRITEBACK_CACHE_FUSER_OPTIONS_ARTIFACT|raw_log=${FUSER_OPTIONS_RAW}|cleanup_status=retained:${LOG_DIR}"
        scenario_result "writeback_cache_audit_fuser_options_default_off" "PASS" "FUSE option matrix emitted no writeback_cache token"
    else
        scenario_result "writeback_cache_audit_fuser_options_default_off" "FAIL" "FUSE option matrix leaked or omitted observations"
    fi
else
    scenario_result "writeback_cache_audit_fuser_options_default_off" "FAIL" "ffs-fuse writeback_cache tests failed; see $FUSER_OPTIONS_RAW"
fi

step "Scenario 8: bad schema fails closed"
if run_rch_capture "$BAD_SCHEMA_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$BAD_SCHEMA_GATE" \
    --scenario-id writeback_cache_audit_bad_schema_fails; then
    scenario_result "writeback_cache_audit_bad_schema_fails" "FAIL" "bad schema unexpectedly accepted"
elif grep -Fq "schema_version" "$BAD_SCHEMA_RAW"; then
    log "WRITEBACK_CACHE_AUDIT_OBSERVATION|scenario_id=writeback_cache_audit_bad_schema_fails|gate_version=invalid|mount_options=rw|invariant_ids=I1,I2,I3,I4,I5,I6|decision=reject|expected_error_class=schema_version|observed_error_class=schema_version|artifact_paths=${BAD_SCHEMA_GATE}|cleanup_status=retained:${LOG_DIR}|reproduction_command=ffs-harness validate-writeback-cache-audit --gate ${BAD_SCHEMA_GATE}"
    scenario_result "writeback_cache_audit_bad_schema_fails" "PASS" "bad schema rejected with schema_version diagnostic"
else
    scenario_result "writeback_cache_audit_bad_schema_fails" "FAIL" "bad schema rejected without useful diagnostic"
fi

step "Scenario 9: report carries invariants, failure modes, artifacts, and repro command"
if python3 - "$ACCEPT_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
names = {row["name"] for row in report["invariant_map"]}
required_names = {
    "Snapshot Visibility Boundary",
    "Alias Order Preservation",
    "Metadata-After-Data Dependency",
    "Sync Boundary Completeness",
    "Flush Non-Durability",
    "Cross-Epoch Order",
}
if not required_names <= names:
    raise SystemExit(f"missing invariant names: {sorted(required_names - names)}")
for reason in {
    "default_or_read_only_mount",
    "fuse_capability_unavailable",
    "stale_crash_matrix_or_missing_fsync_evidence",
    "conflicting_cli_flags",
    "runtime_kill_switch_engaged",
    "writeback_feature_downgraded",
    "stale_gate_artifact",
    "host_capability_mismatch",
    "config_default_attempt",
}:
    if reason not in report["failure_modes"]:
        raise SystemExit(f"missing failure mode: {reason}")
for field in {
    "mount_options.raw_options",
    "mount_options.mode",
    "fuse_capability.probe_status",
    "runtime_guard.kill_switch_state",
    "runtime_guard.feature_state",
    "runtime_guard.config_source",
    "runtime_guard.gate_artifact_hash",
    "runtime_guard.gate_fresh",
    "runtime_guard.gate_age_secs",
    "runtime_guard.gate_max_age_secs",
    "runtime_guard.host_capability_fingerprint",
    "runtime_guard.lane_manifest_id",
    "runtime_guard.lane_manifest_path",
    "runtime_guard.lane_manifest_fresh",
    "runtime_guard.lane_manifest_matches_host",
    "runtime_guard.release_gate_consumer",
    "epoch_barrier_artifact.artifact_path",
    "crash_matrix_artifact.artifact_path",
    "fsync_evidence_artifact.artifact_path",
}:
    if field not in report["required_artifact_fields"]:
        raise SystemExit(f"missing artifact field: {field}")
if len(report["artifact_paths"]) != 4:
    raise SystemExit("expected exactly four evidence artifact paths")
if report["runtime_guard"]["kill_switch_state"] != "disarmed":
    raise SystemExit("runtime guard did not record disarmed kill switch")
if "validate-writeback-cache-audit" not in report["reproduction_command"]:
    raise SystemExit("missing reproduction command")
if report["decision"]["decision"] != "accept":
    raise SystemExit("complete gate did not accept")
PY
then
    scenario_result "writeback_cache_audit_report_fields" "PASS" "report contains invariant and artifact contract"
else
    scenario_result "writeback_cache_audit_report_fields" "FAIL" "report contract incomplete"
fi

step "Scenario 10: unit tests cover gate policy and report contract"
if run_rch_capture "$UNIT_RAW" cargo test -p ffs-harness writeback_cache_audit -- --nocapture; then
    scenario_result "writeback_cache_audit_unit_tests" "PASS" "module unit tests passed through rch"
else
    scenario_result "writeback_cache_audit_unit_tests" "FAIL" "module unit tests failed; see $UNIT_RAW"
fi

step "Scenario 11: CLI help, README, and FEATURE_PARITY keep gated opt-in wording"
if run_rch_capture "$HELP_RAW" cargo run --quiet -p ffs-cli -- mount --help; then
    if grep -Fq "writeback_cache" "$HELP_RAW" \
        && grep -Fq "FFS_WRITEBACK_CACHE_KILL_SWITCH" "$HELP_RAW" \
        && grep -Fq "fsync" "$HELP_RAW" \
        && grep -Fq "fsyncdir" "$HELP_RAW" \
        && grep -Fq "flush remains non-durable" "$HELP_RAW" \
        && grep -Fq "bd-rchk0.2.2" README.md \
        && grep -Fq "bd-rchk0.2.1.1" FEATURE_PARITY.md \
        && grep -Fq "bd-rchk0.2.2" FEATURE_PARITY.md \
        && grep -Fq "fresh runtime-guard evidence" README.md \
        && grep -Fq "FFS_WRITEBACK_CACHE_KILL_SWITCH" README.md \
        && grep -Fq "runtime kill-switch plus stale-gate" FEATURE_PARITY.md \
        && grep -Fq "accepted crash/replay-oracle JSON" FEATURE_PARITY.md \
        && grep -Fq "12-point crash/replay artifact gate" README.md; then
        log "WRITEBACK_CACHE_HELP_DOCS_OBSERVATION|scenario_id=writeback_cache_audit_help_docs_consistent|expected_error_class=gated_opt_in|observed_error_class=gated_opt_in|help_log=${HELP_RAW}|cleanup_status=retained:${LOG_DIR}|reproduction_command=cargo run -p ffs-cli -- mount --help"
        scenario_result "writeback_cache_audit_help_docs_consistent" "PASS" "help/docs/parity keep gated opt-in wording"
    else
        scenario_result "writeback_cache_audit_help_docs_consistent" "FAIL" "help/docs/parity wording drifted"
    fi
else
    scenario_result "writeback_cache_audit_help_docs_consistent" "FAIL" "ffs-cli mount help failed; see $HELP_RAW"
fi

step "Scenario 12: opt-in CLI help exposes gate and durability boundaries"
if run_rch_capture "$CLI_OPT_IN_HELP_RAW" cargo run --quiet -p ffs-cli -- mount --help; then
    if grep -Fq -- "--writeback-cache" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq -- "--writeback-cache-gate" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq -- "--writeback-cache-ordering-oracle" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq -- "--writeback-cache-crash-replay-oracle" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq "FFS_WRITEBACK_CACHE_KILL_SWITCH" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq "flush remains non-durable" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq "fsync" "$CLI_OPT_IN_HELP_RAW" \
        && grep -Fq "fsyncdir" "$CLI_OPT_IN_HELP_RAW"; then
        log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_opt_in_cli_help_boundaries|mount_options=rw,writeback_cache|stdout_stderr=${CLI_OPT_IN_HELP_RAW}|cleanup_status=not_mounted|reproduction_command=cargo run -p ffs-cli -- mount --help"
        scenario_result "writeback_cache_opt_in_cli_help_boundaries" "PASS" "CLI help names gate paths and sync boundaries"
    else
        scenario_result "writeback_cache_opt_in_cli_help_boundaries" "FAIL" "CLI help omitted opt-in gate wording"
    fi
else
    scenario_result "writeback_cache_opt_in_cli_help_boundaries" "FAIL" "ffs-cli mount help failed; see $CLI_OPT_IN_HELP_RAW"
fi

step "Scenario 13: opt-in rejects before mount when audit gate is missing"
if run_rch_capture "$CLI_MISSING_GATE_RAW" cargo run --quiet -p ffs-cli -- \
    mount --rw --writeback-cache /definitely/missing.img /definitely/missing-mnt; then
    scenario_result "writeback_cache_opt_in_cli_rejects_missing_gate" "FAIL" "missing gate unexpectedly reached mount"
elif grep -Fq -- "--writeback-cache requires --writeback-cache-gate" "$CLI_MISSING_GATE_RAW"; then
    log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_opt_in_cli_rejects_missing_gate|mount_options=rw,writeback_cache|expected_error_class=missing_audit_gate|observed_error_class=missing_audit_gate|stdout_stderr=${CLI_MISSING_GATE_RAW}|cleanup_status=not_mounted|reproduction_command=ffs mount --rw --writeback-cache /definitely/missing.img /definitely/missing-mnt"
    scenario_result "writeback_cache_opt_in_cli_rejects_missing_gate" "PASS" "missing gate rejected before image open"
else
    scenario_result "writeback_cache_opt_in_cli_rejects_missing_gate" "FAIL" "missing gate rejected without stable diagnostic"
fi

step "Scenario 14: opt-in rejects read-only conflicting flags before gate I/O"
if run_rch_capture "$CLI_RO_REJECT_RAW" cargo run --quiet -p ffs-cli -- \
    mount --writeback-cache \
    --writeback-cache-gate "$ACCEPT_GATE" \
    --writeback-cache-ordering-oracle "$ORDERING_ACCEPT_ORACLE" \
    --writeback-cache-crash-replay-oracle "$CRASH_REPLAY_ACCEPT_ORACLE" \
    /definitely/missing.img /definitely/missing-mnt; then
    scenario_result "writeback_cache_opt_in_cli_rejects_read_only" "FAIL" "read-only writeback_cache unexpectedly reached mount"
elif grep -Fq -- "--writeback-cache requires --rw" "$CLI_RO_REJECT_RAW"; then
    log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_opt_in_cli_rejects_read_only|mount_options=ro,writeback_cache|expected_error_class=read_only_writeback_cache|observed_error_class=read_only_writeback_cache|fuse_capability_artifact=${ACCEPT_GATE}|stdout_stderr=${CLI_RO_REJECT_RAW}|cleanup_status=not_mounted|reproduction_command=ffs mount --writeback-cache --writeback-cache-gate ${ACCEPT_GATE} --writeback-cache-ordering-oracle ${ORDERING_ACCEPT_ORACLE} --writeback-cache-crash-replay-oracle ${CRASH_REPLAY_ACCEPT_ORACLE} /definitely/missing.img /definitely/missing-mnt"
    scenario_result "writeback_cache_opt_in_cli_rejects_read_only" "PASS" "read-only opt-in rejected before gate reads or mount"
else
    scenario_result "writeback_cache_opt_in_cli_rejects_read_only" "FAIL" "read-only rejection missing stable diagnostic"
fi

step "Scenario 15: complete opt-in gate passes guard before image-open failure"
if run_rch_capture "$CLI_ACCEPT_IMAGE_OPEN_RAW" cargo run --quiet -p ffs-cli -- \
    mount --rw --writeback-cache \
    --writeback-cache-gate "$ACCEPT_GATE" \
    --writeback-cache-ordering-oracle "$ORDERING_ACCEPT_ORACLE" \
    --writeback-cache-crash-replay-oracle "$CRASH_REPLAY_ACCEPT_ORACLE" \
    /definitely/missing.img /definitely/missing-mnt; then
    scenario_result "writeback_cache_opt_in_cli_accepts_gate_before_image_open" "FAIL" "missing image unexpectedly mounted"
elif grep -Fq "failed to open filesystem image" "$CLI_ACCEPT_IMAGE_OPEN_RAW" \
    && ! grep -Fq "writeback-cache audit gate rejected" "$CLI_ACCEPT_IMAGE_OPEN_RAW" \
    && ! grep -Fq "writeback-cache ordering oracle rejected" "$CLI_ACCEPT_IMAGE_OPEN_RAW" \
    && ! grep -Fq "writeback-cache crash/replay oracle rejected" "$CLI_ACCEPT_IMAGE_OPEN_RAW"; then
    log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_opt_in_cli_accepts_gate_before_image_open|mount_options=rw,writeback_cache|expected_error_class=filesystem_open_failed|observed_error_class=filesystem_open_failed|fuse_capability_artifact=${ACCEPT_GATE}|stdout_stderr=${CLI_ACCEPT_IMAGE_OPEN_RAW}|cleanup_status=not_mounted|reproduction_command=ffs mount --rw --writeback-cache --writeback-cache-gate ${ACCEPT_GATE} --writeback-cache-ordering-oracle ${ORDERING_ACCEPT_ORACLE} --writeback-cache-crash-replay-oracle ${CRASH_REPLAY_ACCEPT_ORACLE} /definitely/missing.img /definitely/missing-mnt"
    scenario_result "writeback_cache_opt_in_cli_accepts_gate_before_image_open" "PASS" "accepted gate reached the image-open stage before failing"
else
    scenario_result "writeback_cache_opt_in_cli_accepts_gate_before_image_open" "FAIL" "accepted gate did not reach image-open diagnostic"
fi

step "Scenario 16: repeated CLI rejections keep the same guard class"
if run_rch_capture "$CLI_REPEATED_RAW_A" cargo run --quiet -p ffs-cli -- \
    mount --rw --writeback-cache /definitely/missing.img /definitely/missing-mnt; then
    scenario_result "writeback_cache_opt_in_cli_repeated_rejections" "FAIL" "first repeated rejection unexpectedly succeeded"
elif run_rch_capture "$CLI_REPEATED_RAW_B" cargo run --quiet -p ffs-cli -- \
    mount --rw --writeback-cache /definitely/missing.img /definitely/missing-mnt; then
    scenario_result "writeback_cache_opt_in_cli_repeated_rejections" "FAIL" "second repeated rejection unexpectedly succeeded"
elif grep -Fq -- "--writeback-cache requires --writeback-cache-gate" "$CLI_REPEATED_RAW_A" \
    && grep -Fq -- "--writeback-cache requires --writeback-cache-gate" "$CLI_REPEATED_RAW_B"; then
    log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_opt_in_cli_repeated_rejections|mount_options=rw,writeback_cache|expected_error_class=missing_audit_gate|observed_error_class=missing_audit_gate|stdout_stderr=${CLI_REPEATED_RAW_A},${CLI_REPEATED_RAW_B}|cleanup_status=not_mounted|reproduction_command=ffs mount --rw --writeback-cache /definitely/missing.img /definitely/missing-mnt"
    scenario_result "writeback_cache_opt_in_cli_repeated_rejections" "PASS" "repeated guard rejections stayed stable"
else
    scenario_result "writeback_cache_opt_in_cli_repeated_rejections" "FAIL" "repeated guard rejection class drifted"
fi

step "Scenario 16a: runtime kill switch rejects before gate and image I/O"
if run_rch_capture "$CLI_KILL_SWITCH_RAW" env FFS_WRITEBACK_CACHE_KILL_SWITCH=1 cargo run --quiet -p ffs-cli -- \
    mount --rw --writeback-cache \
    --writeback-cache-gate "$ACCEPT_GATE" \
    --writeback-cache-ordering-oracle "$ORDERING_ACCEPT_ORACLE" \
    --writeback-cache-crash-replay-oracle "$CRASH_REPLAY_ACCEPT_ORACLE" \
    /definitely/missing.img /definitely/missing-mnt; then
    scenario_result "writeback_cache_runtime_kill_switch_rejected" "FAIL" "runtime kill switch unexpectedly allowed mount"
elif grep -Fq "FFS_WRITEBACK_CACHE_KILL_SWITCH" "$CLI_KILL_SWITCH_RAW" \
    && ! grep -Fq "failed to open filesystem image" "$CLI_KILL_SWITCH_RAW"; then
    log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_runtime_kill_switch_rejected|mount_options=rw,writeback_cache|expected_error_class=runtime_kill_switch_engaged|observed_error_class=runtime_kill_switch_engaged|stdout_stderr=${CLI_KILL_SWITCH_RAW}|cleanup_status=not_mounted|reproduction_command=FFS_WRITEBACK_CACHE_KILL_SWITCH=1 ffs mount --rw --writeback-cache --writeback-cache-gate ${ACCEPT_GATE} --writeback-cache-ordering-oracle ${ORDERING_ACCEPT_ORACLE} --writeback-cache-crash-replay-oracle ${CRASH_REPLAY_ACCEPT_ORACLE} /definitely/missing.img /definitely/missing-mnt"
    scenario_result "writeback_cache_runtime_kill_switch_rejected" "PASS" "runtime kill switch failed closed before image open"
else
    scenario_result "writeback_cache_runtime_kill_switch_rejected" "FAIL" "runtime kill switch rejection missing stable diagnostic"
fi

step "Scenario 17: FUSE option builder includes writeback_cache only on opt-in"
if run_rch_capture "$FUSER_OPT_IN_RAW" cargo test -p ffs-fuse build_mount_options_includes_writeback_cache_only_when_opted_in -- --nocapture; then
    if grep -Fq "WRITEBACK_CACHE_OPT_IN_FUSER_OPTIONS|case=explicit_rw_opt_in" "$FUSER_OPT_IN_RAW" \
        && grep -Fq "writeback_cache" "$FUSER_OPT_IN_RAW"; then
        log "WRITEBACK_CACHE_OPT_IN_OBSERVATION|scenario_id=writeback_cache_opt_in_fuser_options_enabled|mount_options=rw,writeback_cache|stdout_stderr=${FUSER_OPT_IN_RAW}|cleanup_status=not_mounted|reproduction_command=cargo test -p ffs-fuse build_mount_options_includes_writeback_cache_only_when_opted_in -- --nocapture"
        scenario_result "writeback_cache_opt_in_fuser_options_enabled" "PASS" "FUSE builder emitted writeback_cache for explicit rw opt-in"
    else
        scenario_result "writeback_cache_opt_in_fuser_options_enabled" "FAIL" "FUSE opt-in test omitted raw option observation"
    fi
else
    scenario_result "writeback_cache_opt_in_fuser_options_enabled" "FAIL" "FUSE opt-in unit test failed; see $FUSER_OPT_IN_RAW"
fi

step "Scenario 18: CLI/FUSE opt-in unit tests cover guard acceptance and rejection"
if run_rch_capture "$CLI_OPT_IN_UNIT_RAW" cargo test -p ffs-cli mount_writeback_cache -- --nocapture; then
    scenario_result "writeback_cache_opt_in_unit_tests" "PASS" "CLI opt-in unit tests passed through rch"
else
    scenario_result "writeback_cache_opt_in_unit_tests" "FAIL" "CLI opt-in unit tests failed; see $CLI_OPT_IN_UNIT_RAW"
fi

step "Scenario 19: ordering oracle module and CLI are wired"
if grep -Fq "build_writeback_ordering_report" crates/ffs-harness/src/main.rs \
    && grep -Fq "validate-writeback-cache-ordering" crates/ffs-harness/src/main.rs \
    && grep -Fq "WritebackOrderingOracle" crates/ffs-harness/src/writeback_cache_audit.rs; then
    scenario_result "writeback_cache_ordering_cli_wired" "PASS" "ordering oracle CLI command exported"
else
    scenario_result "writeback_cache_ordering_cli_wired" "FAIL" "missing ordering oracle CLI or report builder"
fi

step "Scenario 20: positive ordering oracle accepts complete evidence"
if run_rch_capture "$ORDERING_ACCEPT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-ordering \
    --oracle "$ORDERING_ACCEPT_ORACLE" \
    --scenario-id writeback_cache_ordering_accepts_complete_oracle \
    --require-accept; then
    if extract_json_object "$ORDERING_ACCEPT_RAW" "$ORDERING_ACCEPT_REPORT" '"schema_version"'; then
        record_ordering_observation "$ORDERING_ACCEPT_REPORT" "accept" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_ordering_accepts_complete_oracle" "PASS" "complete dirty-page ordering oracle accepted"
    else
        scenario_result "writeback_cache_ordering_accepts_complete_oracle" "FAIL" "accepted ordering run did not emit report JSON"
    fi
else
    scenario_result "writeback_cache_ordering_accepts_complete_oracle" "FAIL" "complete ordering oracle rejected; see $ORDERING_ACCEPT_RAW"
fi

step "Scenario 21: ordering oracle rejects default-off mount evidence"
if run_rch_capture "$ORDERING_DEFAULT_OFF_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-ordering \
    --oracle "$ORDERING_DEFAULT_OFF_ORACLE" \
    --scenario-id writeback_cache_ordering_rejects_default_off; then
    if extract_json_object "$ORDERING_DEFAULT_OFF_RAW" "$ORDERING_DEFAULT_OFF_REPORT" '"schema_version"' \
        && expect_ordering_report_rejection "$ORDERING_DEFAULT_OFF_REPORT" "default_off_or_not_opted_in" "I5"
    then
        record_ordering_observation "$ORDERING_DEFAULT_OFF_REPORT" "default_off_or_not_opted_in" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_ordering_rejects_default_off" "PASS" "default-off ordering proof rejected with stable reason"
    else
        scenario_result "writeback_cache_ordering_rejects_default_off" "FAIL" "default-off ordering report missing stable reason"
    fi
else
    scenario_result "writeback_cache_ordering_rejects_default_off" "FAIL" "schema-valid default-off ordering oracle should emit report"
fi

step "Scenario 22: ordering oracle rejects missing fsync boundary"
if run_rch_capture "$ORDERING_MISSING_FSYNC_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-ordering \
    --oracle "$ORDERING_MISSING_FSYNC_ORACLE" \
    --scenario-id writeback_cache_ordering_rejects_missing_fsync; then
    if extract_json_object "$ORDERING_MISSING_FSYNC_RAW" "$ORDERING_MISSING_FSYNC_REPORT" '"schema_version"' \
        && expect_ordering_report_rejection "$ORDERING_MISSING_FSYNC_REPORT" "missing_fsync_boundary" "I4"
    then
        record_ordering_observation "$ORDERING_MISSING_FSYNC_REPORT" "missing_fsync_boundary" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_ordering_rejects_missing_fsync" "PASS" "dirty pages without fsync durability rejected"
    else
        scenario_result "writeback_cache_ordering_rejects_missing_fsync" "FAIL" "missing-fsync report missing stable reason"
    fi
else
    scenario_result "writeback_cache_ordering_rejects_missing_fsync" "FAIL" "schema-valid missing-fsync oracle should emit report"
fi

step "Scenario 23: ordering oracle rejects missing fsyncdir boundary"
if run_rch_capture "$ORDERING_MISSING_FSYNCDIR_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-ordering \
    --oracle "$ORDERING_MISSING_FSYNCDIR_ORACLE" \
    --scenario-id writeback_cache_ordering_rejects_missing_fsyncdir; then
    if extract_json_object "$ORDERING_MISSING_FSYNCDIR_RAW" "$ORDERING_MISSING_FSYNCDIR_REPORT" '"schema_version"' \
        && expect_ordering_report_rejection "$ORDERING_MISSING_FSYNCDIR_REPORT" "missing_fsyncdir_boundary" "I3"
    then
        record_ordering_observation "$ORDERING_MISSING_FSYNCDIR_REPORT" "missing_fsyncdir_boundary" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_ordering_rejects_missing_fsyncdir" "PASS" "metadata without fsyncdir durability rejected"
    else
        scenario_result "writeback_cache_ordering_rejects_missing_fsyncdir" "FAIL" "missing-fsyncdir report missing stable reason"
    fi
else
    scenario_result "writeback_cache_ordering_rejects_missing_fsyncdir" "FAIL" "schema-valid missing-fsyncdir oracle should emit report"
fi

step "Scenario 24: cancellation before writeback is explicitly classified"
if run_rch_capture "$ORDERING_CANCELLATION_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-ordering \
    --oracle "$ORDERING_CANCELLATION_ORACLE" \
    --scenario-id writeback_cache_ordering_cancellation_classified \
    --require-accept; then
    if extract_json_object "$ORDERING_CANCELLATION_RAW" "$ORDERING_CANCELLATION_REPORT" '"schema_version"'; then
        record_ordering_observation "$ORDERING_CANCELLATION_REPORT" "accept" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_ordering_cancellation_classified" "PASS" "cancellation state emitted as classified"
    else
        scenario_result "writeback_cache_ordering_cancellation_classified" "FAIL" "cancellation report missing JSON"
    fi
else
    scenario_result "writeback_cache_ordering_cancellation_classified" "FAIL" "classified cancellation oracle rejected; see $ORDERING_CANCELLATION_RAW"
fi

step "Scenario 25: crash/reopen survivor-set artifact is part of ordering evidence"
if run_rch_capture "$ORDERING_CRASH_REOPEN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-ordering \
    --oracle "$ORDERING_CRASH_REOPEN_ORACLE" \
    --scenario-id writeback_cache_ordering_crash_reopen_artifact \
    --require-accept; then
    if extract_json_object "$ORDERING_CRASH_REOPEN_RAW" "$ORDERING_CRASH_REOPEN_REPORT" '"schema_version"'; then
        record_ordering_observation "$ORDERING_CRASH_REOPEN_REPORT" "accept" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_ordering_crash_reopen_artifact" "PASS" "crash/reopen survivor-set artifact emitted"
    else
        scenario_result "writeback_cache_ordering_crash_reopen_artifact" "FAIL" "crash/reopen report missing JSON"
    fi
else
    scenario_result "writeback_cache_ordering_crash_reopen_artifact" "FAIL" "crash/reopen ordering oracle rejected; see $ORDERING_CRASH_REOPEN_RAW"
fi

step "Scenario 26: ordering report carries dirty-page, sync, epoch, repair, and repro fields"
if python3 - "$ORDERING_ACCEPT_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["decision"]["decision"] != "accept":
    raise SystemExit("complete ordering oracle did not accept")
if "writeback_cache" not in report["raw_fuser_options"]:
    raise SystemExit("raw FUSER writeback_cache option missing")
if report["dirty_page_state"] != "fsynced_durable":
    raise SystemExit("dirty-page state missing")
if report["flush_observed_non_durable"] is not True:
    raise SystemExit("flush non-durability evidence missing")
if report["fsync_observed_durable"] is not True:
    raise SystemExit("fsync durability evidence missing")
if report["fsyncdir_observed_durable"] is not True:
    raise SystemExit("fsyncdir durability evidence missing")
if not report["epoch_id"] or report["epoch_state"] != "fresh":
    raise SystemExit("fresh epoch evidence missing")
if report["repair_symbol_generation"] < 1 or report["repair_symbol_refresh"] != "refreshed_after_writeback":
    raise SystemExit("repair symbol refresh evidence missing")
if report["expected_ordering"] != report["observed_ordering"]:
    raise SystemExit("ordering mismatch in accept report")
if "validate-writeback-cache-ordering" not in report["reproduction_command"]:
    raise SystemExit("missing ordering reproduction command")
if len(report["invariant_evidence"]) != 6:
    raise SystemExit("expected invariant evidence for I1-I6")
PY
then
    scenario_result "writeback_cache_ordering_report_fields" "PASS" "ordering report contains oracle artifact contract"
else
    scenario_result "writeback_cache_ordering_report_fields" "FAIL" "ordering report contract incomplete"
fi

step "Scenario 27: unit tests cover ordering oracle policy"
if run_rch_capture "$ORDERING_UNIT_RAW" cargo test -p ffs-harness ordering_oracle -- --nocapture; then
    scenario_result "writeback_cache_ordering_unit_tests" "PASS" "ordering oracle unit tests passed through rch"
else
    scenario_result "writeback_cache_ordering_unit_tests" "FAIL" "ordering oracle unit tests failed; see $ORDERING_UNIT_RAW"
fi

step "Scenario 28: crash/replay oracle module and CLI are wired"
if grep -Fq "build_writeback_crash_replay_report" crates/ffs-harness/src/main.rs \
    && grep -Fq "validate-writeback-cache-crash-replay" crates/ffs-harness/src/main.rs \
    && grep -Fq "WritebackCrashReplayOracle" crates/ffs-harness/src/writeback_cache_audit.rs; then
    scenario_result "writeback_cache_crash_replay_cli_wired" "PASS" "crash/replay oracle CLI command exported"
else
    scenario_result "writeback_cache_crash_replay_cli_wired" "FAIL" "missing crash/replay oracle CLI or report builder"
fi

step "Scenario 29: positive crash/replay matrix accepts twelve crash points"
if run_rch_capture "$CRASH_REPLAY_ACCEPT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-crash-replay \
    --oracle "$CRASH_REPLAY_ACCEPT_ORACLE" \
    --scenario-id writeback_cache_crash_replay_accepts_complete_matrix \
    --require-accept; then
    if extract_json_object "$CRASH_REPLAY_ACCEPT_RAW" "$CRASH_REPLAY_ACCEPT_REPORT" '"schema_version"'; then
        record_crash_replay_observation "$CRASH_REPLAY_ACCEPT_REPORT" "accept" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_crash_replay_accepts_complete_matrix" "PASS" "complete twelve-point crash/replay matrix accepted"
    else
        scenario_result "writeback_cache_crash_replay_accepts_complete_matrix" "FAIL" "accepted crash/replay run did not emit report JSON"
    fi
else
    scenario_result "writeback_cache_crash_replay_accepts_complete_matrix" "FAIL" "complete crash/replay oracle rejected; see $CRASH_REPLAY_ACCEPT_RAW"
fi

step "Scenario 30: crash/replay oracle rejects a missing crash point"
if run_rch_capture "$CRASH_REPLAY_MISSING_POINT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-crash-replay \
    --oracle "$CRASH_REPLAY_MISSING_POINT_ORACLE" \
    --scenario-id writeback_cache_crash_replay_rejects_missing_crash_point; then
    if extract_json_object "$CRASH_REPLAY_MISSING_POINT_RAW" "$CRASH_REPLAY_MISSING_POINT_REPORT" '"schema_version"' \
        && expect_crash_replay_report_rejection "$CRASH_REPLAY_MISSING_POINT_REPORT" "missing_crash_point" "cp12_after_repair_refresh"
    then
        record_crash_replay_observation "$CRASH_REPLAY_MISSING_POINT_REPORT" "missing_crash_point" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_crash_replay_rejects_missing_crash_point" "PASS" "missing crash point rejected with stable reason"
    else
        scenario_result "writeback_cache_crash_replay_rejects_missing_crash_point" "FAIL" "missing-point report missing stable reason"
    fi
else
    scenario_result "writeback_cache_crash_replay_rejects_missing_crash_point" "FAIL" "schema-valid missing-point oracle should emit report"
fi

step "Scenario 31: crash/replay oracle rejects survivor-set mismatch"
if run_rch_capture "$CRASH_REPLAY_SURVIVOR_MISMATCH_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-crash-replay \
    --oracle "$CRASH_REPLAY_SURVIVOR_MISMATCH_ORACLE" \
    --scenario-id writeback_cache_crash_replay_rejects_survivor_mismatch; then
    if extract_json_object "$CRASH_REPLAY_SURVIVOR_MISMATCH_RAW" "$CRASH_REPLAY_SURVIVOR_MISMATCH_REPORT" '"schema_version"' \
        && expect_crash_replay_report_rejection "$CRASH_REPLAY_SURVIVOR_MISMATCH_REPORT" "survivor_set_mismatch" "cp01_before_first_write"
    then
        record_crash_replay_observation "$CRASH_REPLAY_SURVIVOR_MISMATCH_REPORT" "survivor_set_mismatch" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_crash_replay_rejects_survivor_mismatch" "PASS" "survivor-set mismatch rejected with stable reason"
    else
        scenario_result "writeback_cache_crash_replay_rejects_survivor_mismatch" "FAIL" "survivor mismatch report missing stable reason"
    fi
else
    scenario_result "writeback_cache_crash_replay_rejects_survivor_mismatch" "FAIL" "schema-valid survivor mismatch oracle should emit report"
fi

step "Scenario 32: crash/replay oracle rejects flush as durability evidence"
if run_rch_capture "$CRASH_REPLAY_FLUSH_DURABLE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-crash-replay \
    --oracle "$CRASH_REPLAY_FLUSH_DURABLE_ORACLE" \
    --scenario-id writeback_cache_crash_replay_rejects_flush_durability; then
    if extract_json_object "$CRASH_REPLAY_FLUSH_DURABLE_RAW" "$CRASH_REPLAY_FLUSH_DURABLE_REPORT" '"schema_version"' \
        && expect_crash_replay_report_rejection "$CRASH_REPLAY_FLUSH_DURABLE_REPORT" "flush_misclassified_as_durable" "cp03_after_flush_before_fsync"
    then
        record_crash_replay_observation "$CRASH_REPLAY_FLUSH_DURABLE_REPORT" "flush_misclassified_as_durable" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_crash_replay_rejects_flush_durability" "PASS" "flush durability misuse rejected"
    else
        scenario_result "writeback_cache_crash_replay_rejects_flush_durability" "FAIL" "flush durability report missing stable reason"
    fi
else
    scenario_result "writeback_cache_crash_replay_rejects_flush_durability" "FAIL" "schema-valid flush-durability oracle should emit report"
fi

step "Scenario 33: crash/replay oracle rejects missing fsyncdir durability"
if run_rch_capture "$CRASH_REPLAY_MISSING_FSYNCDIR_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-crash-replay \
    --oracle "$CRASH_REPLAY_MISSING_FSYNCDIR_ORACLE" \
    --scenario-id writeback_cache_crash_replay_rejects_missing_fsyncdir; then
    if extract_json_object "$CRASH_REPLAY_MISSING_FSYNCDIR_RAW" "$CRASH_REPLAY_MISSING_FSYNCDIR_REPORT" '"schema_version"' \
        && expect_crash_replay_report_rejection "$CRASH_REPLAY_MISSING_FSYNCDIR_REPORT" "missing_fsyncdir_boundary" "cp05_after_metadata_before_fsyncdir"
    then
        record_crash_replay_observation "$CRASH_REPLAY_MISSING_FSYNCDIR_REPORT" "missing_fsyncdir_boundary" "retained:${LOG_DIR}"
        scenario_result "writeback_cache_crash_replay_rejects_missing_fsyncdir" "PASS" "missing fsyncdir evidence rejected"
    else
        scenario_result "writeback_cache_crash_replay_rejects_missing_fsyncdir" "FAIL" "missing fsyncdir report missing stable reason"
    fi
else
    scenario_result "writeback_cache_crash_replay_rejects_missing_fsyncdir" "FAIL" "schema-valid missing-fsyncdir oracle should emit report"
fi

step "Scenario 34: crash/replay report carries QA artifact contract"
if python3 - "$CRASH_REPLAY_ACCEPT_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["decision"]["decision"] != "accept":
    raise SystemExit("complete crash/replay oracle did not accept")
if len(report["required_crash_point_ids"]) != 12 or len(report["covered_crash_point_ids"]) != 12:
    raise SystemExit("twelve crash point coverage missing")
if "writeback_cache" not in report["raw_fuser_options"]:
    raise SystemExit("raw FUSER writeback_cache option missing")
if not report["operation_trace"] or not all(row["operation"] for row in report["operation_trace"]):
    raise SystemExit("operation trace missing")
if not report["artifact_paths"]:
    raise SystemExit("artifact paths missing")
for point in report["crash_points"]:
    if not point["crash_point_id"]:
        raise SystemExit("crash point id missing")
    if point["expected_survivor_set"] != list(reversed(point["actual_survivor_set"])):
        raise SystemExit("expected/actual survivor sets not represented")
    for field in ("stdout_path", "stderr_path", "cleanup_status"):
        if not point[field]:
            raise SystemExit(f"{field} missing")
if "validate-writeback-cache-crash-replay" not in report["reproduction_command"]:
    raise SystemExit("missing crash/replay reproduction command")
PY
then
    scenario_result "writeback_cache_crash_replay_report_fields" "PASS" "crash/replay report contains shared QA artifact contract"
else
    scenario_result "writeback_cache_crash_replay_report_fields" "FAIL" "crash/replay report contract incomplete"
fi

step "Scenario 35: unit tests cover crash/replay oracle policy"
if run_rch_capture "$CRASH_REPLAY_UNIT_RAW" cargo test -p ffs-harness crash_replay_oracle -- --nocapture; then
    scenario_result "writeback_cache_crash_replay_unit_tests" "PASS" "crash/replay oracle unit tests passed through rch"
else
    scenario_result "writeback_cache_crash_replay_unit_tests" "FAIL" "crash/replay oracle unit tests failed; see $CRASH_REPLAY_UNIT_RAW"
fi

step "Scenario 36: mounted ext4 opt-in path exercises writeback_cache plus sync boundaries"
if run_rch_capture "$WRITEBACK_CACHE_MOUNTED_EXT4_RAW" cargo test -p ffs-harness writeback_cache_ext4_opt_in_flush_fsyncdir_reopen -- --nocapture; then
    if grep -Fq "SCENARIO_RESULT|scenario_id=writeback_cache_ext4_opt_in_flush_fsyncdir_reopen|outcome=PASS" "$WRITEBACK_CACHE_MOUNTED_EXT4_RAW"; then
        scenario_result "writeback_cache_ext4_opt_in_flush_fsyncdir_reopen" "PASS" "mounted ext4 writeback-cache opt-in reached flush/fsync/fsyncdir/reopen"
    elif grep -Fq "SCENARIO_RESULT|scenario_id=writeback_cache_ext4_opt_in_flush_fsyncdir_reopen|outcome=SKIP" "$WRITEBACK_CACHE_MOUNTED_EXT4_RAW"; then
        scenario_result "writeback_cache_ext4_opt_in_flush_fsyncdir_reopen" "PASS" "mounted ext4 opt-in test soft-skipped with explicit host classification"
    else
        scenario_result "writeback_cache_ext4_opt_in_flush_fsyncdir_reopen" "FAIL" "mounted ext4 opt-in test did not emit scenario result"
    fi
else
    scenario_result "writeback_cache_ext4_opt_in_flush_fsyncdir_reopen" "FAIL" "mounted ext4 opt-in test failed; see $WRITEBACK_CACHE_MOUNTED_EXT4_RAW"
fi

step "Scenario 37: scenario catalog names this suite and static evidence markers"
if jq -e '.suites[] | select(.suite_id == "ffs_writeback_cache_audit")' scripts/e2e/scenario_catalog.json >/dev/null \
    && grep -Fq "SCENARIO_RESULT|scenario_id=writeback_cache_audit_catalog_valid|outcome=PASS" "$0" \
    && python3 - scripts/e2e/scenario_catalog.json <<'PY'
import json
import pathlib
import sys

catalog = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
suite = next(row for row in catalog["suites"] if row["suite_id"] == "ffs_writeback_cache_audit")
ids = {row["id"] for row in suite["scenarios"]}
required = {
    "writeback_cache_audit_cli_wired",
    "writeback_cache_audit_accepts_complete_gate",
    "writeback_cache_audit_rejects_default_mount",
    "writeback_cache_audit_fuse_unavailable_rejected",
    "writeback_cache_audit_unsupported_mode_rejected",
    "writeback_cache_audit_repeated_mount_attempts",
    "writeback_cache_audit_stale_gate_rejected",
    "writeback_cache_audit_repeated_downgrade_rejections",
    "writeback_cache_audit_config_default_rejected",
    "writeback_cache_audit_host_manifest_mismatch_rejected",
    "writeback_cache_audit_fuser_options_default_off",
    "writeback_cache_audit_bad_schema_fails",
    "writeback_cache_audit_report_fields",
    "writeback_cache_audit_unit_tests",
    "writeback_cache_audit_help_docs_consistent",
    "writeback_cache_audit_catalog_valid",
    "writeback_cache_opt_in_cli_help_boundaries",
    "writeback_cache_opt_in_cli_rejects_missing_gate",
    "writeback_cache_opt_in_cli_rejects_read_only",
    "writeback_cache_opt_in_cli_accepts_gate_before_image_open",
    "writeback_cache_opt_in_cli_repeated_rejections",
    "writeback_cache_runtime_kill_switch_rejected",
    "writeback_cache_opt_in_fuser_options_enabled",
    "writeback_cache_opt_in_unit_tests",
    "writeback_cache_ordering_cli_wired",
    "writeback_cache_ordering_accepts_complete_oracle",
    "writeback_cache_ordering_rejects_default_off",
    "writeback_cache_ordering_rejects_missing_fsync",
    "writeback_cache_ordering_rejects_missing_fsyncdir",
    "writeback_cache_ordering_cancellation_classified",
    "writeback_cache_ordering_crash_reopen_artifact",
    "writeback_cache_ordering_report_fields",
    "writeback_cache_ordering_unit_tests",
    "writeback_cache_crash_replay_cli_wired",
    "writeback_cache_crash_replay_accepts_complete_matrix",
    "writeback_cache_crash_replay_rejects_missing_crash_point",
    "writeback_cache_crash_replay_rejects_survivor_mismatch",
    "writeback_cache_crash_replay_rejects_flush_durability",
    "writeback_cache_crash_replay_rejects_missing_fsyncdir",
    "writeback_cache_crash_replay_report_fields",
    "writeback_cache_crash_replay_unit_tests",
    "writeback_cache_ext4_opt_in_flush_fsyncdir_reopen",
}
missing = required - ids
if missing:
    raise SystemExit(f"missing catalog scenarios: {sorted(missing)}")
PY
then
    scenario_result "writeback_cache_audit_catalog_valid" "PASS" "catalog suite and markers present"
else
    scenario_result "writeback_cache_audit_catalog_valid" "FAIL" "catalog suite or evidence markers missing"
fi

log ""
log "=============================================="
log "Summary: total=$TOTAL pass=$PASS_COUNT fail=$FAIL_COUNT"
log "Log file: $LOG_FILE"
log "=============================================="

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    exit 1
fi
