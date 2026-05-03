#!/usr/bin/env bash
# ffs_mounted_write_workload_matrix.sh - mounted write workload matrix runner.
#
# By default this validates the matrix and emits skipped JSON/CSV result
# artifacts with exact skip reasons. Set FFS_MOUNTED_WRITE_EXECUTE=1 and provide
# FFS_MOUNTED_WRITE_EXT4_MOUNTPOINT / FFS_MOUNTED_WRITE_BTRFS_MOUNTPOINT to run
# workloads against already-mounted FrankenFS FUSE directories.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_mounted_write_workload_matrix"

MATRIX_PATH="${FFS_MOUNTED_WRITE_MATRIX:-$REPO_ROOT/tests/workload-matrix/mounted_write_workload_matrix.json}"
VALIDATION_JSON="$E2E_LOG_DIR/mounted_write_workload_matrix_validation.json"
RESULT_JSON="$E2E_LOG_DIR/mounted_write_workload_results.json"
RESULT_CSV="$E2E_LOG_DIR/mounted_write_workload_results.csv"
STDOUT_DIR="$E2E_LOG_DIR/stdout"
STDERR_DIR="$E2E_LOG_DIR/stderr"

mkdir -p "$STDOUT_DIR" "$STDERR_DIR"

e2e_step "Validate mounted write workload matrix"
"${RCH_BIN:-rch}" exec -- cargo run -p ffs-harness -- validate-mounted-write-matrix \
    --matrix "$MATRIX_PATH" \
    --out "$VALIDATION_JSON"

e2e_step "Run mounted write workload matrix"
FFS_MOUNTED_WRITE_EXECUTE="${FFS_MOUNTED_WRITE_EXECUTE:-0}" \
FFS_MOUNTED_WRITE_EXT4_MOUNTPOINT="${FFS_MOUNTED_WRITE_EXT4_MOUNTPOINT:-}" \
FFS_MOUNTED_WRITE_BTRFS_MOUNTPOINT="${FFS_MOUNTED_WRITE_BTRFS_MOUNTPOINT:-}" \
FFS_MOUNTED_WRITE_MATRIX_PATH="$MATRIX_PATH" \
FFS_MOUNTED_WRITE_RESULT_JSON="$RESULT_JSON" \
FFS_MOUNTED_WRITE_RESULT_CSV="$RESULT_CSV" \
FFS_MOUNTED_WRITE_STDOUT_DIR="$STDOUT_DIR" \
FFS_MOUNTED_WRITE_STDERR_DIR="$STDERR_DIR" \
python3 - <<'PY'
from __future__ import annotations

import csv
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

matrix_path = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_MATRIX_PATH"])
result_json = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_RESULT_JSON"])
result_csv = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_RESULT_CSV"])
stdout_dir = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_STDOUT_DIR"])
stderr_dir = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_STDERR_DIR"])
execute = os.environ.get("FFS_MOUNTED_WRITE_EXECUTE") == "1"
mountpoints = {
    "ext4": os.environ.get("FFS_MOUNTED_WRITE_EXT4_MOUNTPOINT", ""),
    "btrfs": os.environ.get("FFS_MOUNTED_WRITE_BTRFS_MOUNTPOINT", ""),
}

matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
results: list[dict[str, object]] = []


def append_log(path: pathlib.Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def write_payload(path: pathlib.Path, size: int) -> None:
    block = b"frankenfs-mounted-write-matrix\n"
    remaining = size
    with path.open("wb") as handle:
        while remaining > 0:
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)


def readback_payload(path: pathlib.Path) -> None:
    if not path.exists() or path.stat().st_size == 0:
        raise RuntimeError(f"readback failed for {path}")


def fsync_file(path: pathlib.Path) -> None:
    with path.open("ab") as handle:
        handle.flush()
        os.fsync(handle.fileno())


def run_operation(root: pathlib.Path, operation: str, size: int, stdout: pathlib.Path) -> None:
    data_file = root / "data.bin"
    renamed_file = root / "data.renamed"
    subdir = root / "dir"
    link_file = root / "data.link"
    symlink_file = root / "data.symlink"

    if operation == "mkdir":
        subdir.mkdir(exist_ok=True)
    elif operation == "create":
        data_file.touch(exist_ok=True)
    elif operation == "write_readback":
        write_payload(data_file, size)
        readback_payload(data_file)
    elif operation == "fsync":
        fsync_file(data_file)
    elif operation == "rename":
        if data_file.exists():
            data_file.replace(renamed_file)
            renamed_file.replace(data_file)
    elif operation == "hardlink":
        if link_file.exists():
            link_file.unlink()
        os.link(data_file, link_file)
    elif operation == "symlink":
        if symlink_file.exists() or symlink_file.is_symlink():
            symlink_file.unlink()
        os.symlink(data_file.name, symlink_file)
    elif operation == "chmod":
        data_file.chmod(0o640)
    elif operation == "xattr_set_get":
        if not hasattr(os, "setxattr"):
            raise RuntimeError("python os.setxattr unavailable")
        os.setxattr(data_file, b"user.ffs_matrix", b"mounted")
        value = os.getxattr(data_file, b"user.ffs_matrix")
        if value != b"mounted":
            raise RuntimeError("xattr readback mismatch")
    elif operation == "fallocate_keep_size":
        if shutil.which("fallocate") is None:
            raise RuntimeError("fallocate command unavailable")
        subprocess.run(
            ["fallocate", "-n", "-l", str(size), str(data_file)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    elif operation == "truncate_extend":
        with data_file.open("ab") as handle:
            handle.truncate(size)
    elif operation == "unlink":
        if data_file.exists():
            data_file.unlink()
    elif operation == "rmdir":
        if subdir.exists():
            subdir.rmdir()
    else:
        append_log(stdout, f"operation_not_implemented={operation}")


def run_unsupported(root: pathlib.Path, operation: str) -> tuple[bool, str]:
    before = sorted(path.name for path in root.iterdir())
    try:
        if operation == "mknod_block_device":
            subprocess.run(
                ["mknod", str(root / "blocked-device"), "b", "1", "7"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        elif operation == "root_owned_write_eacces":
            probe = root / "root-owned-probe"
            probe.write_text("should-not-succeed\n", encoding="utf-8")
        else:
            return False, f"unknown unsupported operation {operation}"
    except (PermissionError, subprocess.CalledProcessError) as exc:
        after = sorted(path.name for path in root.iterdir())
        return before == after, f"rejected: {exc}"
    after = sorted(path.name for path in root.iterdir())
    return False, f"unexpected success before={before} after={after}"


def run_scenario(scenario: dict[str, object]) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    filesystem = str(scenario["filesystem"])
    workload = dict(scenario["workload"])
    expected = dict(scenario["expected_outcome"])
    stdout_path = stdout_dir / f"{scenario_id}.out"
    stderr_path = stderr_dir / f"{scenario_id}.err"
    start = time.monotonic()
    mountpoint = mountpoints.get(filesystem, "")

    base = {
        "scenario_id": scenario_id,
        "filesystem": filesystem,
        "mount_flags": list(scenario["mount_flags"]),
        "operation_sequence": list(workload["operation_sequence"]),
        "write_sizes": list(workload["write_sizes"]),
        "fsync_pattern": str(workload["fsync_pattern"]),
        "concurrency": int(workload["concurrency"]),
        "expected_outcome": str(expected["outcome_class"]),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "cleanup_status": "not_run",
        "skip_reason": "",
        "actual_outcome": "skip",
        "duration_ms": 0,
    }

    if not execute:
        base["skip_reason"] = "FFS_MOUNTED_WRITE_EXECUTE not set to 1"
        append_log(stdout_path, "dry-run skip")
        return base
    if not mountpoint:
        base["skip_reason"] = f"FFS_MOUNTED_WRITE_{filesystem.upper()}_MOUNTPOINT not set"
        append_log(stdout_path, str(base["skip_reason"]))
        return base

    root = pathlib.Path(mountpoint) / "ffs_mounted_write_matrix" / scenario_id
    try:
        root.mkdir(parents=True, exist_ok=True)
        sizes = [int(size) for size in workload["write_sizes"]]
        for operation in workload["operation_sequence"]:
            run_operation(root, str(operation), max(sizes), stdout_path)
        for operation in workload["unsupported_operations"]:
            preserved, detail = run_unsupported(root, str(operation))
            append_log(stdout_path, detail)
            if not preserved:
                base["actual_outcome"] = "fail"
                base["cleanup_status"] = "preserved_artifacts"
                base["duration_ms"] = int((time.monotonic() - start) * 1000)
                return base
        base["actual_outcome"] = "pass"
        base["cleanup_status"] = "preserved_artifacts"
    except Exception as exc:  # noqa: BLE001 - artifact runner must preserve detail.
        append_log(stderr_path, repr(exc))
        base["actual_outcome"] = "fail"
        base["cleanup_status"] = "preserved_artifacts"
    base["duration_ms"] = int((time.monotonic() - start) * 1000)
    return base


for scenario in matrix["scenarios"]:
    result = run_scenario(dict(scenario))
    results.append(result)
    print(
        "SCENARIO_RESULT|scenario_id={scenario_id}|outcome={actual_outcome}|detail={skip_reason}".format(
            **result
        )
    )

payload = {
    "schema_version": 1,
    "bead_id": matrix["bead_id"],
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "matrix_path": str(matrix_path),
    "execute": execute,
    "results_csv": str(result_csv),
    "results": results,
}
result_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with result_csv.open("w", newline="", encoding="utf-8") as handle:
    fieldnames = [
        "scenario_id",
        "filesystem",
        "expected_outcome",
        "actual_outcome",
        "fsync_pattern",
        "concurrency",
        "duration_ms",
        "cleanup_status",
        "skip_reason",
        "stdout_path",
        "stderr_path",
    ]
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    for result in results:
        writer.writerow({field: result.get(field, "") for field in fieldnames})

failed = [result for result in results if result["actual_outcome"] == "fail"]
if failed:
    sys.exit(1)
PY

e2e_log "Mounted write workload results JSON: $RESULT_JSON"
e2e_log "Mounted write workload results CSV: $RESULT_CSV"
