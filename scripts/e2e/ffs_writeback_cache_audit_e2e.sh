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
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_fuser_options_default_off|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_bad_schema_fails|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_report_fields|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_unit_tests|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_help_docs_consistent|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_catalog_valid|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_cli_wired|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_accepts_complete_oracle|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_rejects_default_off|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_rejects_missing_fsync|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_rejects_missing_fsyncdir|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_cancellation_classified|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_crash_reopen_artifact|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_report_fields|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_ordering_unit_tests|outcome=PASS

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
BAD_SCHEMA_GATE="$INPUT_DIR/writeback_cache_bad_schema_gate.json"
ORDERING_ACCEPT_ORACLE="$INPUT_DIR/writeback_cache_ordering_accept_oracle.json"
ORDERING_DEFAULT_OFF_ORACLE="$INPUT_DIR/writeback_cache_ordering_default_off_oracle.json"
ORDERING_MISSING_FSYNC_ORACLE="$INPUT_DIR/writeback_cache_ordering_missing_fsync_oracle.json"
ORDERING_MISSING_FSYNCDIR_ORACLE="$INPUT_DIR/writeback_cache_ordering_missing_fsyncdir_oracle.json"
ORDERING_CANCELLATION_ORACLE="$INPUT_DIR/writeback_cache_ordering_cancellation_oracle.json"
ORDERING_CRASH_REOPEN_ORACLE="$INPUT_DIR/writeback_cache_ordering_crash_reopen_oracle.json"
ACCEPT_RAW="$LOG_DIR/writeback_cache_accept.raw"
REJECT_RAW="$LOG_DIR/writeback_cache_reject.raw"
FUSE_UNAVAILABLE_RAW="$LOG_DIR/writeback_cache_fuse_unavailable.raw"
UNSUPPORTED_MODE_RAW="$LOG_DIR/writeback_cache_unsupported_mode.raw"
REPEATED_RAW_A="$LOG_DIR/writeback_cache_repeated_a.raw"
REPEATED_RAW_B="$LOG_DIR/writeback_cache_repeated_b.raw"
FUSER_OPTIONS_RAW="$LOG_DIR/writeback_cache_fuser_options.raw"
BAD_SCHEMA_RAW="$LOG_DIR/writeback_cache_bad_schema.raw"
UNIT_RAW="$LOG_DIR/writeback_cache_unit_tests.raw"
HELP_RAW="$LOG_DIR/writeback_cache_help.raw"
ORDERING_ACCEPT_RAW="$LOG_DIR/writeback_cache_ordering_accept.raw"
ORDERING_DEFAULT_OFF_RAW="$LOG_DIR/writeback_cache_ordering_default_off.raw"
ORDERING_MISSING_FSYNC_RAW="$LOG_DIR/writeback_cache_ordering_missing_fsync.raw"
ORDERING_MISSING_FSYNCDIR_RAW="$LOG_DIR/writeback_cache_ordering_missing_fsyncdir.raw"
ORDERING_CANCELLATION_RAW="$LOG_DIR/writeback_cache_ordering_cancellation.raw"
ORDERING_CRASH_REOPEN_RAW="$LOG_DIR/writeback_cache_ordering_crash_reopen.raw"
ORDERING_UNIT_RAW="$LOG_DIR/writeback_cache_ordering_unit_tests.raw"
ACCEPT_REPORT="$LOG_DIR/writeback_cache_accept_report.json"
REJECT_REPORT="$LOG_DIR/writeback_cache_reject_report.json"
FUSE_UNAVAILABLE_REPORT="$LOG_DIR/writeback_cache_fuse_unavailable_report.json"
UNSUPPORTED_MODE_REPORT="$LOG_DIR/writeback_cache_unsupported_mode_report.json"
REPEATED_REPORT_A="$LOG_DIR/writeback_cache_repeated_a_report.json"
REPEATED_REPORT_B="$LOG_DIR/writeback_cache_repeated_b_report.json"
ORDERING_ACCEPT_REPORT="$LOG_DIR/writeback_cache_ordering_accept_report.json"
ORDERING_DEFAULT_OFF_REPORT="$LOG_DIR/writeback_cache_ordering_default_off_report.json"
ORDERING_MISSING_FSYNC_REPORT="$LOG_DIR/writeback_cache_ordering_missing_fsync_report.json"
ORDERING_MISSING_FSYNCDIR_REPORT="$LOG_DIR/writeback_cache_ordering_missing_fsyncdir_report.json"
ORDERING_CANCELLATION_REPORT="$LOG_DIR/writeback_cache_ordering_cancellation_report.json"
ORDERING_CRASH_REOPEN_REPORT="$LOG_DIR/writeback_cache_ordering_crash_reopen_report.json"

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
  "conflicting_flags": []
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
  "conflicting_flags": []
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
  "conflicting_flags": []
}
JSON

python3 - "$ACCEPT_GATE" "$FUSE_UNAVAILABLE_GATE" "$UNSUPPORTED_MODE_GATE" <<'PY'
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
}:
    if reason not in report["failure_modes"]:
        raise SystemExit(f"missing failure mode: {reason}")
for field in {
    "mount_options.raw_options",
    "mount_options.mode",
    "fuse_capability.probe_status",
    "epoch_barrier_artifact.artifact_path",
    "crash_matrix_artifact.artifact_path",
    "fsync_evidence_artifact.artifact_path",
}:
    if field not in report["required_artifact_fields"]:
        raise SystemExit(f"missing artifact field: {field}")
if len(report["artifact_paths"]) != 3:
    raise SystemExit("expected exactly three evidence artifact paths")
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

step "Scenario 11: CLI help, README, and FEATURE_PARITY keep unsupported wording"
if run_rch_capture "$HELP_RAW" cargo run --quiet -p ffs-cli -- mount --help; then
    if grep -Fq "writeback_cache" "$HELP_RAW" \
        && grep -Fq "intentionally unsupported" "$HELP_RAW" \
        && grep -Fq "bd-rchk0.2.1.1" README.md \
        && grep -Fq "bd-rchk0.2.1.1" FEATURE_PARITY.md \
        && grep -Fq "must not enable it" README.md \
        && grep -Fq "remains unsupported" FEATURE_PARITY.md; then
        log "WRITEBACK_CACHE_HELP_DOCS_OBSERVATION|scenario_id=writeback_cache_audit_help_docs_consistent|expected_error_class=unsupported|observed_error_class=unsupported|help_log=${HELP_RAW}|cleanup_status=retained:${LOG_DIR}|reproduction_command=cargo run -p ffs-cli -- mount --help"
        scenario_result "writeback_cache_audit_help_docs_consistent" "PASS" "help/docs/parity keep unsupported wording"
    else
        scenario_result "writeback_cache_audit_help_docs_consistent" "FAIL" "help/docs/parity wording drifted"
    fi
else
    scenario_result "writeback_cache_audit_help_docs_consistent" "FAIL" "ffs-cli mount help failed; see $HELP_RAW"
fi

step "Scenario 12: ordering oracle module and CLI are wired"
if grep -Fq "build_writeback_ordering_report" crates/ffs-harness/src/main.rs \
    && grep -Fq "validate-writeback-cache-ordering" crates/ffs-harness/src/main.rs \
    && grep -Fq "WritebackOrderingOracle" crates/ffs-harness/src/writeback_cache_audit.rs; then
    scenario_result "writeback_cache_ordering_cli_wired" "PASS" "ordering oracle CLI command exported"
else
    scenario_result "writeback_cache_ordering_cli_wired" "FAIL" "missing ordering oracle CLI or report builder"
fi

step "Scenario 13: positive ordering oracle accepts complete evidence"
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

step "Scenario 14: ordering oracle rejects default-off mount evidence"
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

step "Scenario 15: ordering oracle rejects missing fsync boundary"
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

step "Scenario 16: ordering oracle rejects missing fsyncdir boundary"
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

step "Scenario 17: cancellation before writeback is explicitly classified"
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

step "Scenario 18: crash/reopen survivor-set artifact is part of ordering evidence"
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

step "Scenario 19: ordering report carries dirty-page, sync, epoch, repair, and repro fields"
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

step "Scenario 20: unit tests cover ordering oracle policy"
if run_rch_capture "$ORDERING_UNIT_RAW" cargo test -p ffs-harness ordering_oracle -- --nocapture; then
    scenario_result "writeback_cache_ordering_unit_tests" "PASS" "ordering oracle unit tests passed through rch"
else
    scenario_result "writeback_cache_ordering_unit_tests" "FAIL" "ordering oracle unit tests failed; see $ORDERING_UNIT_RAW"
fi

step "Scenario 21: scenario catalog names this suite and static evidence markers"
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
    "writeback_cache_audit_fuser_options_default_off",
    "writeback_cache_audit_bad_schema_fails",
    "writeback_cache_audit_report_fields",
    "writeback_cache_audit_unit_tests",
    "writeback_cache_audit_help_docs_consistent",
    "writeback_cache_audit_catalog_valid",
    "writeback_cache_ordering_cli_wired",
    "writeback_cache_ordering_accepts_complete_oracle",
    "writeback_cache_ordering_rejects_default_off",
    "writeback_cache_ordering_rejects_missing_fsync",
    "writeback_cache_ordering_rejects_missing_fsyncdir",
    "writeback_cache_ordering_cancellation_classified",
    "writeback_cache_ordering_crash_reopen_artifact",
    "writeback_cache_ordering_report_fields",
    "writeback_cache_ordering_unit_tests",
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
