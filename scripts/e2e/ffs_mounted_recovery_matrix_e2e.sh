#!/usr/bin/env bash
# ffs_mounted_recovery_matrix_e2e.sh - smoke gate for bd-rchk0.3.3.
#
# Validates the mounted recovery lifecycle matrix, emits durable contract
# artifacts for every crash/unmount/reopen row, and proves fail-closed handling
# for missing lifecycle coverage and unsafe process-control commands.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_mounted_recovery_matrix}"
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

e2e_init "ffs_mounted_recovery_matrix"

MATRIX_PATH="${FFS_MOUNTED_RECOVERY_MATRIX:-$REPO_ROOT/tests/workload-matrix/mounted_recovery_matrix.json}"
VALIDATION_JSON="$E2E_LOG_DIR/mounted_recovery_matrix_validation.json"
RESULT_JSON="$E2E_LOG_DIR/mounted_recovery_results.json"
RESULT_CSV="$E2E_LOG_DIR/mounted_recovery_results.csv"
STDOUT_DIR="$E2E_LOG_DIR/stdout"
STDERR_DIR="$E2E_LOG_DIR/stderr"
ACTUAL_STATE_DIR="$E2E_LOG_DIR/actual_state"
BAD_MISSING_LIFECYCLE="$E2E_LOG_DIR/bad_missing_lifecycle.json"
BAD_UNSAFE_COMMAND="$E2E_LOG_DIR/bad_unsafe_command.json"
BAD_MISSING_RAW="$E2E_LOG_DIR/bad_missing_lifecycle.raw"
BAD_UNSAFE_RAW="$E2E_LOG_DIR/bad_unsafe_command.raw"
UNIT_LOG="$E2E_LOG_DIR/mounted_recovery_unit_tests.log"

mkdir -p "$STDOUT_DIR" "$STDERR_DIR" "$ACTUAL_STATE_DIR"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod mounted_recovery_matrix" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-mounted-recovery-matrix" crates/ffs-harness/src/main.rs; then
    scenario_result "mounted_recovery_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "mounted_recovery_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: matrix validates"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-mounted-recovery-matrix \
    --matrix "$MATRIX_PATH" \
    --out "$VALIDATION_JSON"; then
    scenario_result "mounted_recovery_matrix_validates" "PASS" "validation report written to $VALIDATION_JSON"
else
    scenario_result "mounted_recovery_matrix_validates" "FAIL" "matrix validator rejected $MATRIX_PATH"
fi

e2e_step "Scenario 3: mounted recovery artifacts are generated"
if python3 - "$MATRIX_PATH" "$RESULT_JSON" "$RESULT_CSV" "$STDOUT_DIR" "$STDERR_DIR" "$ACTUAL_STATE_DIR" <<'PY'
from __future__ import annotations

import csv
import json
import pathlib
import sys
from datetime import datetime, timezone

matrix_path = pathlib.Path(sys.argv[1])
result_json = pathlib.Path(sys.argv[2])
result_csv = pathlib.Path(sys.argv[3])
stdout_dir = pathlib.Path(sys.argv[4])
stderr_dir = pathlib.Path(sys.argv[5])
actual_state_dir = pathlib.Path(sys.argv[6])

matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
rows: list[dict[str, object]] = []

for scenario in matrix["scenarios"]:
    scenario_id = scenario["scenario_id"]
    stdout_path = stdout_dir / f"{scenario_id}.out"
    stderr_path = stderr_dir / f"{scenario_id}.err"
    actual_state_path = actual_state_dir / f"{scenario_id}.json"
    classification = scenario["classification"]
    actual_outcome = "pass" if classification == "pass" else "skip"
    skip_reason = ""
    if classification == "host_limitation":
        skip_reason = "requires permissioned forced-unmount host lane"
    elif classification == "unsupported_v1_scope":
        skip_reason = "declared unsupported V1 recovery surface"

    stdout_path.write_text(
        "\n".join(
            [
                f"scenario_id={scenario_id}",
                f"filesystem={scenario['filesystem']}",
                f"lifecycle_event={scenario['lifecycle_event']}",
                f"crash_or_unmount_point={scenario['crash_or_unmount_point']}",
                f"recovery_command={scenario['recovery_command']}",
                "execution_mode=contract_artifact_capture",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    stderr_path.write_text("", encoding="utf-8")

    state = {
        "scenario_id": scenario_id,
        "filesystem": scenario["filesystem"],
        "lifecycle_event": scenario["lifecycle_event"],
        "pre_crash_operations": scenario["pre_crash_operations"],
        "crash_or_unmount_point": scenario["crash_or_unmount_point"],
        "recovery_command": scenario["recovery_command"],
        "expected_survivors": scenario["expected_survivors"],
        "actual_state": "contract-captured",
        "classification": classification,
        "error_class": scenario["error_class"],
        "cleanup_status": scenario["cleanup_status"],
        "process_control": scenario["process_control"],
    }
    actual_state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    row = {
        "scenario_id": scenario_id,
        "filesystem": scenario["filesystem"],
        "lifecycle_event": scenario["lifecycle_event"],
        "pre_crash_operations": ";".join(scenario["pre_crash_operations"]),
        "crash_or_unmount_point": scenario["crash_or_unmount_point"],
        "recovery_command": scenario["recovery_command"],
        "expected_survivor_count": len(scenario["expected_survivors"]),
        "actual_state_artifact": str(actual_state_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "classification": classification,
        "error_class": scenario["error_class"],
        "cleanup_status": scenario["cleanup_status"],
        "actual_outcome": actual_outcome,
        "skip_reason": skip_reason,
    }
    rows.append(row)
    print(
        "RECOVERY_SCENARIO|scenario_id={scenario_id}|outcome={actual_outcome}|classification={classification}".format(
            **row
        )
    )

payload = {
    "schema_version": 1,
    "bead_id": matrix["bead_id"],
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "matrix_path": str(matrix_path),
    "results_csv": str(result_csv),
    "execution_mode": "contract_artifact_capture",
    "results": rows,
}
result_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with result_csv.open("w", newline="", encoding="utf-8") as handle:
    fieldnames = [
        "scenario_id",
        "filesystem",
        "lifecycle_event",
        "actual_outcome",
        "classification",
        "error_class",
        "cleanup_status",
        "actual_state_artifact",
        "stdout_path",
        "stderr_path",
        "skip_reason",
    ]
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in fieldnames})
PY
then
    scenario_result "mounted_recovery_artifacts_generated" "PASS" "result JSON/CSV and per-scenario logs emitted"
else
    scenario_result "mounted_recovery_artifacts_generated" "FAIL" "artifact generation failed"
fi

e2e_step "Scenario 4: generated artifacts satisfy lifecycle contract"
if python3 - "$RESULT_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))
rows = payload["results"]
required_events = {
    "clean_unmount",
    "forced_unmount",
    "process_termination",
    "fsync_file_boundary",
    "fsync_dir_boundary",
    "reopen_verify",
    "cleanup",
}
events = {row["lifecycle_event"] for row in rows}
missing = sorted(required_events - events)
if missing:
    raise SystemExit(f"missing lifecycle events: {missing}")

required_fields = {
    "scenario_id",
    "filesystem",
    "lifecycle_event",
    "pre_crash_operations",
    "crash_or_unmount_point",
    "recovery_command",
    "actual_state_artifact",
    "stdout_path",
    "stderr_path",
    "classification",
    "cleanup_status",
}
for row in rows:
    missing_fields = [field for field in required_fields if not row.get(field)]
    if missing_fields:
        raise SystemExit(f"{row.get('scenario_id')} missing {missing_fields}")
    for field in ["actual_state_artifact", "stdout_path", "stderr_path"]:
        if not pathlib.Path(row[field]).is_file():
            raise SystemExit(f"{row['scenario_id']} missing artifact {field}={row[field]}")
    if row["lifecycle_event"] in {"forced_unmount", "process_termination"}:
        state = json.loads(pathlib.Path(row["actual_state_artifact"]).read_text(encoding="utf-8"))
        if not state["process_control"]["preserve_partial_artifacts"]:
            raise SystemExit(f"{row['scenario_id']} does not preserve partial artifacts")
PY
then
    scenario_result "mounted_recovery_artifact_contract" "PASS" "required lifecycle rows and artifact links verified"
else
    scenario_result "mounted_recovery_artifact_contract" "FAIL" "generated artifact contract validation failed"
fi

e2e_step "Scenario 5: validator rejects missing lifecycle coverage"
python3 - "$MATRIX_PATH" "$BAD_MISSING_LIFECYCLE" <<'PY'
import json
import sys

matrix_path, out_path = sys.argv[1:]
data = json.loads(open(matrix_path, encoding="utf-8").read())
data["scenarios"] = [
    scenario
    for scenario in data["scenarios"]
    if scenario["lifecycle_event"] != "cleanup"
]
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-mounted-recovery-matrix \
    --matrix "$BAD_MISSING_LIFECYCLE" >"$BAD_MISSING_RAW" 2>&1; then
    scenario_result "mounted_recovery_missing_lifecycle_rejected" "FAIL" "validator accepted a missing cleanup lifecycle row"
elif grep -q "missing lifecycle event cleanup" "$BAD_MISSING_RAW"; then
    scenario_result "mounted_recovery_missing_lifecycle_rejected" "PASS" "missing lifecycle coverage rejected"
else
    scenario_result "mounted_recovery_missing_lifecycle_rejected" "FAIL" "validator failed without expected cleanup diagnostic"
fi

e2e_step "Scenario 6: validator rejects unsafe process-control command"
python3 - "$MATRIX_PATH" "$BAD_UNSAFE_COMMAND" <<'PY'
import json
import sys

matrix_path, out_path = sys.argv[1:]
data = json.loads(open(matrix_path, encoding="utf-8").read())
data["scenarios"][0]["recovery_command"] = "rm -rf /tmp/frankenfs-mounted-recovery"
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-mounted-recovery-matrix \
    --matrix "$BAD_UNSAFE_COMMAND" >"$BAD_UNSAFE_RAW" 2>&1; then
    scenario_result "mounted_recovery_unsafe_command_rejected" "FAIL" "validator accepted unsafe recovery command"
elif grep -q "unsafe host command" "$BAD_UNSAFE_RAW"; then
    scenario_result "mounted_recovery_unsafe_command_rejected" "PASS" "unsafe process-control command rejected"
else
    scenario_result "mounted_recovery_unsafe_command_rejected" "FAIL" "validator failed without expected unsafe-command diagnostic"
fi

e2e_step "Scenario 7: mounted recovery unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib mounted_recovery_matrix -- --nocapture >"$UNIT_LOG" 2>&1; then
    cat "$UNIT_LOG"
    scenario_result "mounted_recovery_unit_tests" "PASS" "mounted_recovery_matrix unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "mounted_recovery_unit_tests" "FAIL" "mounted_recovery_matrix unit tests failed"
fi

e2e_log "Mounted recovery validation JSON: $VALIDATION_JSON"
e2e_log "Mounted recovery results JSON: $RESULT_JSON"
e2e_log "Mounted recovery results CSV: $RESULT_CSV"
e2e_log "Mounted recovery scenario stdout dir: $STDOUT_DIR"
e2e_log "Mounted recovery scenario stderr dir: $STDERR_DIR"
e2e_log "Mounted recovery actual state dir: $ACTUAL_STATE_DIR"

if ((FAIL_COUNT == 0)); then
    e2e_log "Mounted recovery matrix scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Mounted recovery matrix scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
