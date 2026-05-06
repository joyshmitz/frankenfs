#!/usr/bin/env bash
# ffs_mounted_write_error_classes_e2e.sh - QA artifact lane for bd-rchk0.76.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_mounted_write_error_classes_e2e}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

e2e_init "ffs_mounted_write_error_classes"
# This lane writes all durable evidence under E2E_LOG_DIR and does not need the
# auto-created temporary directory from the shared harness.
E2E_CLEANUP_ITEMS=()

CATALOG_PATH="${FFS_MOUNTED_WRITE_ERROR_CLASSES_CATALOG:-$REPO_ROOT/tests/mounted-write-error-classes/mounted_write_error_classes.json}"
MATRIX_PATH="${FFS_MOUNTED_WRITE_MATRIX:-$REPO_ROOT/tests/workload-matrix/mounted_write_workload_matrix.json}"
REPORT_JSON="$E2E_LOG_DIR/mounted_write_error_classes_report.json"
QA_ARTIFACT_JSON="$E2E_LOG_DIR/mounted_write_error_classes_qa_artifact.json"
STDOUT_PATH="$E2E_LOG_DIR/mounted_write_error_classes.stdout"
STDERR_PATH="$E2E_LOG_DIR/mounted_write_error_classes.stderr"
BAD_CATALOG_PATH="$E2E_LOG_DIR/malformed_mounted_write_error_classes.json"
BAD_REPORT_JSON="$E2E_LOG_DIR/malformed_mounted_write_error_classes_report.json"
BAD_STDOUT_PATH="$E2E_LOG_DIR/malformed_mounted_write_error_classes.stdout"
BAD_STDERR_PATH="$E2E_LOG_DIR/malformed_mounted_write_error_classes.stderr"
BAD_REMOTE_CATALOG_PATH="/tmp/ffs_malformed_mounted_write_error_classes_$$.json"

COMMAND=(
    "${RCH_BIN:-rch}"
    exec
    --
    cargo
    run
    --quiet
    -p
    ffs-harness
    --
    validate-mounted-write-error-classes
    --catalog
    "$CATALOG_PATH"
    --matrix
    "$MATRIX_PATH"
)
printf -v COMMAND_LINE '%q ' "${COMMAND[@]}"
COMMAND_LINE="${COMMAND_LINE% }"

e2e_step "Validate mounted write error class catalog"
START_NS="$(date +%s%N)"
if RCH_VISIBILITY=none "${COMMAND[@]}" >"$STDOUT_PATH" 2>"$STDERR_PATH"; then
    COMMAND_STATUS="pass"
    COMMAND_EXIT_CODE=0
else
    COMMAND_EXIT_CODE=$?
    COMMAND_STATUS="fail"
fi
END_NS="$(date +%s%N)"
DURATION_MS="$(((END_NS - START_NS) / 1000000))"

e2e_step "Probe malformed catalog fail-closed behavior"
python3 - "$BAD_CATALOG_PATH" <<'PY'
from __future__ import annotations

import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    '{"schema_version":1,"catalog_id":"malformed","entries":[',
    encoding="utf-8",
)
PY

BAD_COMMAND=(
    "${RCH_BIN:-rch}"
    exec
    --
    bash
    -c
    'set -euo pipefail
bad_path="$1"
matrix_path="$2"
printf "%s" "{\"schema_version\":1,\"catalog_id\":\"malformed\",\"entries\":[" >"$bad_path"
cargo run --quiet -p ffs-harness -- validate-mounted-write-error-classes --catalog "$bad_path" --matrix "$matrix_path"'
    _
    "$BAD_REMOTE_CATALOG_PATH"
    "$MATRIX_PATH"
)
printf -v BAD_COMMAND_LINE '%q ' "${BAD_COMMAND[@]}"
BAD_COMMAND_LINE="${BAD_COMMAND_LINE% }"

if RCH_VISIBILITY=none "${BAD_COMMAND[@]}" >"$BAD_STDOUT_PATH" 2>"$BAD_STDERR_PATH"; then
    BAD_COMMAND_STATUS="pass"
    BAD_COMMAND_EXIT_CODE=0
else
    BAD_COMMAND_EXIT_CODE=$?
    BAD_COMMAND_STATUS="fail"
fi

e2e_step "Emit mounted write error class QA artifact"
python3 - \
    "$REPORT_JSON" \
    "$QA_ARTIFACT_JSON" \
    "$STDOUT_PATH" \
    "$STDERR_PATH" \
    "$COMMAND_LINE" \
    "$COMMAND_STATUS" \
    "$COMMAND_EXIT_CODE" \
    "$DURATION_MS" \
    "$CATALOG_PATH" \
    "$MATRIX_PATH" \
    "$BAD_CATALOG_PATH" \
    "$BAD_REPORT_JSON" \
    "$BAD_STDOUT_PATH" \
    "$BAD_STDERR_PATH" \
    "$BAD_COMMAND_LINE" \
    "$BAD_COMMAND_STATUS" \
    "$BAD_COMMAND_EXIT_CODE" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

(
    report_arg,
    artifact_arg,
    stdout_arg,
    stderr_arg,
    command_line,
    command_status,
    command_exit_code_arg,
    duration_ms_arg,
    catalog_arg,
    matrix_arg,
    bad_catalog_arg,
    bad_report_arg,
    bad_stdout_arg,
    bad_stderr_arg,
    bad_command_line,
    bad_command_status,
    bad_command_exit_code_arg,
) = sys.argv[1:18]

report_path = pathlib.Path(report_arg)
artifact_path = pathlib.Path(artifact_arg)
stdout_path = pathlib.Path(stdout_arg)
stderr_path = pathlib.Path(stderr_arg)
catalog_path = pathlib.Path(catalog_arg)
matrix_path = pathlib.Path(matrix_arg)
bad_catalog_path = pathlib.Path(bad_catalog_arg)
bad_report_path = pathlib.Path(bad_report_arg)
bad_stdout_path = pathlib.Path(bad_stdout_arg)
bad_stderr_path = pathlib.Path(bad_stderr_arg)
command_exit_code = int(command_exit_code_arg)
bad_command_exit_code = int(bad_command_exit_code_arg)
duration_ms = int(duration_ms_arg)

errors: list[str] = []
if command_status != "pass":
    errors.append(f"valid catalog command failed with exit {command_exit_code}")

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def extract_report_json(text: str) -> dict:
    cleaned = ANSI_ESCAPE.sub("", text)
    decoder = json.JSONDecoder()
    for index, char in enumerate(cleaned):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[index:])
        except json.JSONDecodeError:
            continue
        if (
            isinstance(value, dict)
            and "catalog_id" in value
            and "error_classes_seen" in value
            and "broad_fallback_count" in value
        ):
            return value
    raise ValueError("mounted write error class report object not found")

if report_path.exists():
    report = json.loads(report_path.read_text(encoding="utf-8"))
else:
    report = None
    decode_errors = []
    for capture_path in (stdout_path, stderr_path):
        try:
            report = extract_report_json(capture_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            decode_errors.append(f"{capture_path}: {exc}")
        else:
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            break
    if report is None:
        errors.append(
            f"missing report JSON: {report_path}; captures did not contain report JSON: "
            + "; ".join(decode_errors)
        )
        report = {
            "valid": False,
            "catalog_id": "",
            "bead_id": "bd-rchk0.76",
            "entry_count": 0,
            "error_classes_seen": [],
            "broad_fallback_count": 0,
            "errors": errors[:],
        }

if not report.get("valid", False):
    errors.append("mounted write error class report is not valid")

diagnostic_text = (
    bad_stdout_path.read_text(encoding="utf-8", errors="replace")
    + "\n"
    + bad_stderr_path.read_text(encoding="utf-8", errors="replace")
)
failed_closed = (
    bad_command_status == "fail"
    and bad_command_exit_code != 0
    and "failed to parse mounted write error classes JSON" in diagnostic_text
)
if not failed_closed:
    errors.append(
        "malformed mounted write error class catalog did not fail closed "
        f"(status={bad_command_status} exit={bad_command_exit_code})"
    )

catalog_checksum = "sha256:" + hashlib.sha256(catalog_path.read_bytes()).hexdigest()
matrix_checksum = "sha256:" + hashlib.sha256(matrix_path.read_bytes()).hexdigest()

artifact = {
    "schema_version": 1,
    "bead_id": "bd-rchk0.76",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "catalog_id": report.get("catalog_id", ""),
    "catalog_path": str(catalog_path),
    "catalog_checksum": catalog_checksum,
    "matrix_path": str(matrix_path),
    "matrix_checksum": matrix_checksum,
    "command_line": command_line,
    "command_status": command_status,
    "command_exit_code": command_exit_code,
    "duration_ms": duration_ms,
    "stdout_path": str(stdout_path),
    "stderr_path": str(stderr_path),
    "report_json": str(report_path),
    "entry_count": report.get("entry_count", 0),
    "class_coverage": report.get("error_classes_seen", []),
    "broad_fallback_count": report.get("broad_fallback_count", 0),
    "cleanup_status": "preserved_e2e_log_dir_no_temp_cleanup",
    "reproduction_command": "./scripts/e2e/ffs_mounted_write_error_classes_e2e.sh",
    "invalid_catalog_probe": {
        "catalog_path": str(bad_catalog_path),
        "command_line": bad_command_line,
        "command_status": bad_command_status,
        "command_exit_code": bad_command_exit_code,
        "stdout_path": str(bad_stdout_path),
        "stderr_path": str(bad_stderr_path),
        "report_json": str(bad_report_path),
        "failed_closed": failed_closed,
        "diagnostic_excerpt": diagnostic_text[-1200:],
    },
    "valid": command_status == "pass"
    and bool(report.get("valid"))
    and failed_closed
    and not errors,
    "errors": errors,
}

artifact_path.write_text(
    json.dumps(artifact, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(
    "MOUNTED_WRITE_ERROR_CLASSES_QA|valid={valid}|entries={entries}|classes={classes}|broad_fallbacks={fallbacks}|artifact={artifact}".format(
        valid=artifact["valid"],
        entries=artifact["entry_count"],
        classes=len(artifact["class_coverage"]),
        fallbacks=artifact["broad_fallback_count"],
        artifact=artifact_path,
    )
)
if not artifact["valid"]:
    raise SystemExit(1)
PY

if [[ "$COMMAND_STATUS" != "pass" ]]; then
    e2e_fail "mounted write error class validation failed; stdout=$STDOUT_PATH stderr=$STDERR_PATH"
fi
if [[ "$BAD_COMMAND_STATUS" != "fail" ]]; then
    e2e_fail "malformed mounted write error class catalog unexpectedly passed"
fi

e2e_log "SCENARIO_RESULT|scenario_id=mounted_write_error_classes_qa_artifact|outcome=PASS|detail=$QA_ARTIFACT_JSON"
e2e_log "SCENARIO_RESULT|scenario_id=mounted_write_error_classes_invalid_catalog|outcome=PASS|detail=$BAD_STDERR_PATH"
e2e_pass "mounted write error class QA artifact=$QA_ARTIFACT_JSON"
