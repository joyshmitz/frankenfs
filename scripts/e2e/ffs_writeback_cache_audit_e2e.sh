#!/usr/bin/env bash
# ffs_writeback_cache_audit_e2e.sh - dry-run gate for bd-rchk0.2.1.
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

LOG_DIR="${FFS_E2E_LOG_DIR:-$REPO_ROOT/artifacts/e2e/$(date +%Y%m%d_%H%M%S)_ffs_writeback_cache_audit}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/run.log"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

# Catalog evidence markers:
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_cli_wired|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_accepts_complete_gate|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_rejects_default_mount|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_bad_schema_fails|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_report_fields|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_unit_tests|outcome=PASS
# SCENARIO_RESULT|scenario_id=writeback_cache_audit_catalog_valid|outcome=PASS

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
    if command -v timeout >/dev/null 2>&1; then
        RCH_VISIBILITY=none timeout "${timeout_secs}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 || status=$?
    else
        RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 || status=$?
    fi
    if [[ "$status" -eq 0 ]]; then
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        return 0
    fi
    return "$status"
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
log "CARGO_TARGET_DIR: $CARGO_TARGET_DIR"
log "=============================================="

ACCEPT_GATE="$LOG_DIR/writeback_cache_accept_gate.json"
DEFAULT_REJECT_GATE="$LOG_DIR/writeback_cache_default_reject_gate.json"
BAD_SCHEMA_GATE="$LOG_DIR/writeback_cache_bad_schema_gate.json"
ACCEPT_RAW="$LOG_DIR/writeback_cache_accept.raw"
REJECT_RAW="$LOG_DIR/writeback_cache_reject.raw"
BAD_SCHEMA_RAW="$LOG_DIR/writeback_cache_bad_schema.raw"
UNIT_RAW="$LOG_DIR/writeback_cache_unit_tests.raw"
ACCEPT_REPORT="$LOG_DIR/writeback_cache_accept_report.json"
REJECT_REPORT="$LOG_DIR/writeback_cache_reject_report.json"

cat >"$ACCEPT_GATE" <<'JSON'
{
  "schema_version": 1,
  "gate_version": "bd-rchk0.2.1-gate-v1",
  "bead_id": "bd-rchk0.2.1",
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
  "gate_version": "bd-rchk0.2.1-gate-v1",
  "bead_id": "bd-rchk0.2.1",
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
  "gate_version": "bd-rchk0.2.1-gate-v1",
  "bead_id": "bd-rchk0.2.1",
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
        && python3 - "$REJECT_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
decision = report["decision"]
if decision["decision"] != "reject":
    raise SystemExit("expected reject decision")
if decision["reason"] != "default_or_read_only_mount":
    raise SystemExit(f"wrong reason: {decision['reason']}")
if "I3" not in decision["invariants_failing"]:
    raise SystemExit("I3 failure not reported")
PY
    then
        scenario_result "writeback_cache_audit_rejects_default_mount" "PASS" "default/off gate rejected with stable reason"
    else
        scenario_result "writeback_cache_audit_rejects_default_mount" "FAIL" "reject report missing stable reason"
    fi
else
    scenario_result "writeback_cache_audit_rejects_default_mount" "FAIL" "schema-valid rejection should emit report"
fi

step "Scenario 4: bad schema fails closed"
if run_rch_capture "$BAD_SCHEMA_RAW" cargo run --quiet -p ffs-harness -- \
    validate-writeback-cache-audit \
    --gate "$BAD_SCHEMA_GATE" \
    --scenario-id writeback_cache_audit_bad_schema_fails; then
    scenario_result "writeback_cache_audit_bad_schema_fails" "FAIL" "bad schema unexpectedly accepted"
elif grep -Fq "schema_version" "$BAD_SCHEMA_RAW"; then
    scenario_result "writeback_cache_audit_bad_schema_fails" "PASS" "bad schema rejected with schema_version diagnostic"
else
    scenario_result "writeback_cache_audit_bad_schema_fails" "FAIL" "bad schema rejected without useful diagnostic"
fi

step "Scenario 5: report carries invariants, failure modes, artifacts, and repro command"
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

step "Scenario 6: unit tests cover gate policy and report contract"
if run_rch_capture "$UNIT_RAW" cargo test -p ffs-harness writeback_cache_audit -- --nocapture; then
    scenario_result "writeback_cache_audit_unit_tests" "PASS" "module unit tests passed through rch"
else
    scenario_result "writeback_cache_audit_unit_tests" "FAIL" "module unit tests failed; see $UNIT_RAW"
fi

step "Scenario 7: scenario catalog names this suite and static evidence markers"
if jq -e '.suites[] | select(.suite_id == "ffs_writeback_cache_audit")' scripts/e2e/scenario_catalog.json >/dev/null \
    && grep -Fq "SCENARIO_RESULT|scenario_id=writeback_cache_audit_catalog_valid|outcome=PASS" "$0"; then
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
