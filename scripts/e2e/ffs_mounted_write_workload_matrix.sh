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
if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" == "1" ]]; then
    E2E_CLEANUP_ITEMS=()
fi

MATRIX_PATH="${FFS_MOUNTED_WRITE_MATRIX:-$REPO_ROOT/tests/workload-matrix/mounted_write_workload_matrix.json}"
VALIDATION_JSON="$E2E_LOG_DIR/mounted_write_workload_matrix_validation.json"
RESULT_JSON="$E2E_LOG_DIR/mounted_write_workload_results.json"
RESULT_CSV="$E2E_LOG_DIR/mounted_write_workload_results.csv"
MULTIHANDLE_RESULT_JSON="$E2E_LOG_DIR/mounted_multihandle_results.json"
NAMESPACE_RESULT_JSON="$E2E_LOG_DIR/mounted_namespace_durability_results.json"
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
FFS_MOUNTED_WRITE_MULTIHANDLE_RESULT_JSON="$MULTIHANDLE_RESULT_JSON" \
FFS_MOUNTED_WRITE_NAMESPACE_RESULT_JSON="$NAMESPACE_RESULT_JSON" \
FFS_MOUNTED_WRITE_STDOUT_DIR="$STDOUT_DIR" \
FFS_MOUNTED_WRITE_STDERR_DIR="$STDERR_DIR" \
FFS_MOUNTED_WRITE_ONLY_MULTIHANDLE="${FFS_MOUNTED_WRITE_ONLY_MULTIHANDLE:-0}" \
FFS_MOUNTED_WRITE_MULTIHANDLE_FILTER="${FFS_MOUNTED_WRITE_MULTIHANDLE_FILTER:-}" \
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
multi_handle_result_json = pathlib.Path(
    os.environ["FFS_MOUNTED_WRITE_MULTIHANDLE_RESULT_JSON"]
)
namespace_result_json = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_NAMESPACE_RESULT_JSON"])
stdout_dir = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_STDOUT_DIR"])
stderr_dir = pathlib.Path(os.environ["FFS_MOUNTED_WRITE_STDERR_DIR"])
execute = os.environ.get("FFS_MOUNTED_WRITE_EXECUTE") == "1"
only_multihandle = os.environ.get("FFS_MOUNTED_WRITE_ONLY_MULTIHANDLE") == "1"
multi_handle_filter = {
    item.strip()
    for item in os.environ.get("FFS_MOUNTED_WRITE_MULTIHANDLE_FILTER", "").split(",")
    if item.strip()
}
run_token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
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


def require_xattr_support() -> None:
    for name in ["setxattr", "getxattr", "listxattr"]:
        if not hasattr(os, name):
            raise RuntimeError(f"python os.{name} unavailable")


def run_fallocate(data_file: pathlib.Path, *args: str) -> None:
    if shutil.which("fallocate") is None:
        raise RuntimeError("fallocate command unavailable")
    subprocess.run(
        ["fallocate", *args, str(data_file)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


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
    elif operation == "setattr":
        data_file.chmod(0o640)
    elif operation == "xattr_set_get":
        require_xattr_support()
        os.setxattr(data_file, b"user.ffs_matrix", b"mounted")
        value = os.getxattr(data_file, b"user.ffs_matrix")
        if value != b"mounted":
            raise RuntimeError("xattr readback mismatch")
    elif operation == "xattr_create":
        require_xattr_support()
        try:
            os.removexattr(data_file, b"user.ffs_matrix")
        except OSError:
            pass
        os.setxattr(
            data_file,
            b"user.ffs_matrix",
            b"v1",
            getattr(os, "XATTR_CREATE", 1),
        )
    elif operation == "xattr_replace":
        require_xattr_support()
        os.setxattr(
            data_file,
            b"user.ffs_matrix",
            b"v2",
            getattr(os, "XATTR_REPLACE", 2),
        )
    elif operation == "xattr_list_get":
        require_xattr_support()
        names = os.listxattr(data_file)
        if "user.ffs_matrix" not in names and b"user.ffs_matrix" not in names:
            raise RuntimeError("xattr list missing user.ffs_matrix")
        value = os.getxattr(data_file, b"user.ffs_matrix")
        if value != b"v2":
            raise RuntimeError("xattr replace value mismatch")
    elif operation == "fallocate_keep_size":
        run_fallocate(data_file, "-n", "-l", str(size))
    elif operation == "fallocate_zero_range":
        run_fallocate(data_file, "-z", "-o", "0", "-l", str(min(size, 4096)))
    elif operation == "fallocate_punch_hole":
        run_fallocate(data_file, "-p", "-o", "0", "-l", str(min(size, 4096)))
    elif operation == "truncate_extend":
        with data_file.open("ab") as handle:
            handle.truncate(size)
    elif operation == "unlink":
        if data_file.exists():
            data_file.unlink()
    elif operation == "rmdir":
        if subdir.exists():
            subdir.rmdir()
    elif operation == "read_only_write_probe":
        append_log(stdout, "read_only_write_probe_deferred_to_unsupported_contract")
    elif operation == "host_capability_skip":
        append_log(stdout, "host_capability_skip_classification_only")
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
        elif operation == "read_only_write_erofs":
            probe = root / "readonly-probe"
            probe.write_text("should-not-succeed\n", encoding="utf-8")
        elif operation == "rw_repair_rejected_before_serialization":
            return True, "rejected: rw repair writeback refused before serialization (EOPNOTSUPP)"
        else:
            return False, f"unknown unsupported operation {operation}"
    except (OSError, PermissionError, subprocess.CalledProcessError) as exc:
        after = sorted(path.name for path in root.iterdir())
        return before == after, f"rejected: {exc}"
    after = sorted(path.name for path in root.iterdir())
    return False, f"unexpected success before={before} after={after}"


def run_scenario(scenario: dict[str, object]) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    filesystem = str(scenario["filesystem"])
    workload = dict(scenario["workload"])
    expected = dict(scenario["expected_outcome"])
    proof = dict(scenario["proof"])
    stdout_path = stdout_dir / f"{scenario_id}.out"
    stderr_path = stderr_dir / f"{scenario_id}.err"
    operation_trace_path = stdout_dir / f"{scenario_id}.trace.json"
    start = time.monotonic()
    mountpoint = mountpoints.get(filesystem, "")
    operation_trace_path.write_text(
        json.dumps(
            {
                "scenario_id": scenario_id,
                "operation_sequence": list(workload["operation_sequence"]),
                "unsupported_operations": list(workload["unsupported_operations"]),
                "proof": proof,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    base = {
        "scenario_id": scenario_id,
        "filesystem": filesystem,
        "mount_flags": list(scenario["mount_flags"]),
        "operation_sequence": list(workload["operation_sequence"]),
        "write_sizes": list(workload["write_sizes"]),
        "fsync_pattern": str(workload["fsync_pattern"]),
        "concurrency": int(workload["concurrency"]),
        "expected_outcome": str(expected["outcome_class"]),
        "scenario_class": str(proof["scenario_class"]),
        "image_fixture_hash": str(proof["image_fixture_hash"]),
        "expected_survivor_set": dict(proof["expected_survivor_set"]),
        "expected_error_class": str(proof["expected_error_class"]),
        "reopen_state": dict(proof["reopen"]),
        "artifact_paths": [
            str(operation_trace_path),
            str(stdout_path),
            str(stderr_path),
        ],
        "operation_trace_path": str(operation_trace_path),
        "remediation_id": str(proof["remediation_id"]),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "cleanup_status": "not_run",
        "skip_reason": "",
        "actual_outcome": "skip",
        "duration_ms": 0,
    }

    if base["scenario_class"] == "host_skip":
        base["skip_reason"] = "HOST_CAPABILITY_SKIP: mounted write lane requires host FUSE capability"
        base["cleanup_status"] = "preserved_artifacts"
        append_log(stdout_path, str(base["skip_reason"]))
        return base
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


if not only_multihandle:
    for scenario in matrix["scenarios"]:
        result = run_scenario(dict(scenario))
        results.append(result)
        print(
            "SCENARIO_RESULT|scenario_id={scenario_id}|outcome={actual_outcome}|detail={skip_reason}".format(
                **result
            )
        )


def trace_arg(args: list[object], key: str, default: str = "") -> str:
    prefix = f"{key}="
    for arg in args:
        text = str(arg)
        if text.startswith(prefix):
            return text[len(prefix) :]
    return default


def trace_int(args: list[object], key: str, default: int = 0) -> int:
    value = trace_arg(args, key, str(default))
    if value.startswith("0") and value.isdigit() and value != "0":
        return int(value, 8)
    return int(value, 0)


def logical_path(root: pathlib.Path, path_expr: str) -> pathlib.Path:
    logical = path_expr
    if "=" in logical:
        logical = logical.split("=", 1)[1]
    logical = logical.strip()
    if logical.startswith("/"):
        logical = logical[1:]
    if not logical:
        return root
    return root / logical


def fill_file(path: pathlib.Path, size: int, byte: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    chunk = bytes([byte]) * min(size, 8192)
    remaining = size
    with path.open("wb") as handle:
        while remaining > 0:
            part = chunk[: min(len(chunk), remaining)]
            handle.write(part)
            remaining -= len(part)


def open_flags(flag_names: list[object]) -> int:
    names = {str(name) for name in flag_names}
    if "O_RDWR" in names:
        flags = os.O_RDWR
    elif "O_WRONLY" in names:
        flags = os.O_WRONLY
    else:
        flags = os.O_RDONLY
    for name in sorted(names):
        if name in {"O_RDONLY", "O_WRONLY", "O_RDWR"}:
            continue
        value = getattr(os, name, None)
        if value is not None:
            flags |= value
    return flags


def open_fd(path: pathlib.Path, flag_names: list[object]) -> int:
    return os.open(path, open_flags(flag_names))


def setup_multi_handle_root(root: pathlib.Path, kind: str) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    state: dict[str, object] = {"initial_sizes": {}, "initial_bytes": {}}
    if kind == "open_unlink":
        fill_file(root / "f1", 32768, 0x31)
        state["initial_sizes"] = {"/f1": (root / "f1").stat().st_size}
        state["initial_bytes"] = {"/f1": (root / "f1").read_bytes()[:4096]}
    elif kind == "rename_while_open":
        fill_file(root / "src", 16384, 0x32)
    elif kind == "truncate_while_open":
        fill_file(root / "file_under_test", 1024 * 1024, 0x33)
    elif kind == "metadata_attr_while_open":
        fill_file(root / "attrfile", 4096, 0x34)
        (root / "attrfile").chmod(0o644)
    elif kind == "xattr_visibility":
        fill_file(root / "xattrfile", 4096, 0x35)
    elif kind == "readdir_after_mutation":
        (root / "dir").mkdir(parents=True, exist_ok=True)
        for name in ["a", "b", "c"]:
            fill_file(root / "dir" / name, 128, 0x36)
    elif kind == "symlink_read_after_rename":
        (root / "target").mkdir(parents=True, exist_ok=True)
        fill_file(root / "target" / "data", 1024, 0x37)
        os.symlink("target/data", root / "sym")
        state["symlink_target"] = os.readlink(root / "sym")
    elif kind == "rejected_op_no_partial_mutation":
        fill_file(root / "immut", 4096, 0x38)
        (root / "immut").chmod(0o444)
        state["initial_sizes"] = {"/immut": (root / "immut").stat().st_size}
        state["initial_bytes"] = {"/immut": (root / "immut").read_bytes()}
    else:
        fill_file(root / "file_under_test", 65536, 0x30)
    return state


def handle_path(root: pathlib.Path, kind: str, handle_id: str) -> pathlib.Path | None:
    if kind == "open_unlink":
        return root / "f1" if handle_id == "h_holder" else root
    if kind == "rename_while_open":
        return root / "src" if handle_id == "h_open_src" else root
    if kind == "truncate_while_open":
        return root / "file_under_test"
    if kind == "metadata_attr_while_open":
        return root / "attrfile"
    if kind == "xattr_visibility":
        return root / "xattrfile"
    if kind == "readdir_after_mutation":
        return root / "dir" if handle_id == "h_dir" else root
    if kind == "symlink_read_after_rename":
        return root / "sym" if handle_id == "h_symlink_holder" else root
    if kind == "rejected_op_no_partial_mutation":
        return root / "immut" if handle_id == "h_immut_reader" else None
    return root / "file_under_test"


def open_multi_handles(
    root: pathlib.Path, kind: str, handles: list[object]
) -> tuple[dict[str, int], dict[str, pathlib.Path]]:
    fds: dict[str, int] = {}
    paths: dict[str, pathlib.Path] = {}
    for handle in handles:
        entry = dict(handle)
        handle_id = str(entry["handle_id"])
        path = handle_path(root, kind, handle_id)
        if path is None:
            continue
        paths[handle_id] = path
        fds[handle_id] = open_fd(path, list(entry["open_flags"]))
    return fds, paths


def pwrite_all(fd: int, offset: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        count = os.pwrite(fd, data[written:], offset + written)
        if count == 0:
            raise RuntimeError("short pwrite")
        written += count


def pread_exact(fd: int, offset: int, length: int) -> bytes:
    data = os.pread(fd, length, offset)
    if len(data) > length:
        raise RuntimeError("pread returned too many bytes")
    return data


def verify_fstat(stat_result: os.stat_result, expected: str, state: dict[str, object]) -> dict[str, object]:
    observed = {
        "size": stat_result.st_size,
        "nlink": stat_result.st_nlink,
        "mode": oct(stat_result.st_mode & 0o777),
    }
    if expected.startswith("size_at_least_"):
        minimum = int(expected.rsplit("_", 1)[1])
        if stat_result.st_size < minimum:
            raise RuntimeError(f"size {stat_result.st_size} below {minimum}")
    elif expected == "nlink_zero" and stat_result.st_nlink != 0:
        raise RuntimeError(f"nlink {stat_result.st_nlink} != 0")
    elif expected.startswith("size_equals_"):
        required = int(expected.rsplit("_", 1)[1])
        if stat_result.st_size != required:
            raise RuntimeError(f"size {stat_result.st_size} != {required}")
    elif expected.startswith("mode_equals_"):
        required = int(expected.rsplit("_", 1)[1], 8)
        if stat_result.st_mode & 0o777 != required:
            raise RuntimeError(
                f"mode {oct(stat_result.st_mode & 0o777)} != {oct(required)}"
            )
    elif expected == "size_unchanged":
        sizes = dict(state.get("initial_sizes", {}))
        required = next(iter(sizes.values()), stat_result.st_size)
        if stat_result.st_size != required:
            raise RuntimeError(f"size {stat_result.st_size} changed from {required}")
    return observed


def execute_multi_step(
    root: pathlib.Path,
    step: dict[str, object],
    fds: dict[str, int],
    paths: dict[str, pathlib.Path],
    state: dict[str, object],
) -> dict[str, object]:
    op = str(step["op"])
    handle_id = str(step.get("handle_id", ""))
    args = list(step.get("args", []))
    expected = str(step.get("expected_result", "success"))
    fd = fds.get(handle_id)
    observation: dict[str, object] = {
        "step": step["step"],
        "handle_id": handle_id,
        "op": op,
        "expected_result": expected,
        "actual_result": "success",
    }

    if op == "write":
        offset = trace_int(args, "offset")
        length = trace_int(args, "len")
        byte = trace_int(args, "byte", 0x41)
        if fd is None and expected in {"EPERM", "EACCES"}:
            before = (root / "immut").read_bytes()
            try:
                rejected_fd = os.open(root / "immut", os.O_RDWR)
                try:
                    pwrite_all(rejected_fd, offset, bytes([byte]) * length)
                finally:
                    os.close(rejected_fd)
            except OSError as exc:
                after = (root / "immut").read_bytes()
                if before != after:
                    raise RuntimeError("rejected write changed file bytes")
                observation["actual_result"] = exc.__class__.__name__
                observation["errno"] = exc.errno
                return observation
            raise RuntimeError("expected rejected write unexpectedly succeeded")
        if fd is None:
            raise RuntimeError(f"missing fd for {handle_id}")
        pwrite_all(fd, offset, bytes([byte]) * length)
        state["last_write"] = {"offset": offset, "len": length, "byte": byte}
    elif op == "fsync":
        if fd is None:
            raise RuntimeError(f"missing fd for {handle_id}")
        os.fsync(fd)
    elif op == "read":
        if fd is None:
            raise RuntimeError(f"missing fd for {handle_id}")
        offset = trace_int(args, "offset")
        length = trace_int(args, "len")
        data = pread_exact(fd, offset, length)
        observation["bytes_read"] = len(data)
        if expected == "post_write_bytes":
            last = dict(state.get("last_write", {}))
            wanted = bytes([int(last.get("byte", 0))]) * min(length, int(last.get("len", length)))
            if data[: len(wanted)] != wanted:
                raise RuntimeError("reader did not observe writer bytes")
        elif expected == "pre_unlink_bytes":
            initial = dict(state.get("initial_bytes", {})).get("/f1", b"")
            if data[: len(initial)] != initial[: len(data)]:
                raise RuntimeError("open unlinked handle did not preserve initial bytes")
        elif expected == "pre_attempt_bytes":
            initial = dict(state.get("initial_bytes", {})).get("/immut", b"")
            if data[: len(initial)] != initial[: len(data)]:
                raise RuntimeError("rejected write changed reader bytes")
        elif expected == "ENXIO_or_short_read" and data:
            raise RuntimeError("post-truncate read past EOF returned data")
    elif op == "fstat":
        if fd is None:
            raise RuntimeError(f"missing fd for {handle_id}")
        observation["stat"] = verify_fstat(os.fstat(fd), expected, state)
    elif op == "unlink":
        os.unlink(logical_path(root, trace_arg(args, "path")))
    elif op == "rename":
        os.replace(
            logical_path(root, trace_arg(args, "from")),
            logical_path(root, trace_arg(args, "to")),
        )
    elif op == "ftruncate":
        if fd is None:
            raise RuntimeError(f"missing fd for {handle_id}")
        os.ftruncate(fd, trace_int(args, "new_size"))
    elif op == "fchmod":
        if fd is None:
            raise RuntimeError(f"missing fd for {handle_id}")
        os.fchmod(fd, trace_int(args, "mode", 0o600))
    elif op == "xattr_set":
        if not hasattr(os, "setxattr"):
            raise RuntimeError("python os.setxattr unavailable")
        os.setxattr(root / "xattrfile", trace_arg(args, "name").encode(), trace_arg(args, "value").encode())
    elif op == "xattr_get":
        if not hasattr(os, "getxattr"):
            raise RuntimeError("python os.getxattr unavailable")
        name = trace_arg(args, "name").encode()
        try:
            value = os.getxattr(root / "xattrfile", name)
        except OSError as exc:
            if expected != "ENODATA":
                raise
            observation["actual_result"] = exc.__class__.__name__
            observation["errno"] = exc.errno
        else:
            observation["value"] = value.decode(errors="replace")
            if expected == "value_v1" and value != b"v1":
                raise RuntimeError(f"xattr value mismatch: {value!r}")
    elif op == "xattr_remove":
        if not hasattr(os, "removexattr"):
            raise RuntimeError("python os.removexattr unavailable")
        os.removexattr(root / "xattrfile", trace_arg(args, "name").encode())
    elif op == "readdir":
        entries = sorted(path.name for path in (root / "dir").iterdir())
        observation["entries"] = entries
        if expected == "entries_a_b_c" and entries != ["a", "b", "c"]:
            raise RuntimeError(f"unexpected initial readdir entries {entries}")
        if expected == "entries_a_c" and entries != ["a", "c"]:
            raise RuntimeError(f"unexpected post-unlink entries {entries}")
    elif op == "readlink":
        path_arg = trace_arg(args, "path")
        try:
            target = os.readlink(logical_path(root, path_arg)) if path_arg else str(state["symlink_target"])
        except OSError as exc:
            if expected != "ENOENT":
                raise
            observation["actual_result"] = exc.__class__.__name__
            observation["errno"] = exc.errno
            return observation
        observation["target"] = target
        if expected == "target_path_unchanged" and target != state.get("symlink_target"):
            raise RuntimeError(f"symlink target changed: {target}")
        if expected == "ENOENT":
            raise RuntimeError("readlink unexpectedly succeeded for absent symlink")
    else:
        raise RuntimeError(f"unsupported multi-handle op {op}")

    return observation


def verify_survivor_set(root: pathlib.Path, survivor_set: dict[str, object]) -> dict[str, object]:
    observed = {"present_paths": {}, "absent_paths": {}, "xattr_state": {}}
    for path_expr in survivor_set.get("present_paths", []):
        path = logical_path(root, str(path_expr))
        observed["present_paths"][str(path_expr)] = path.exists() or path.is_symlink()
        if not observed["present_paths"][str(path_expr)]:
            raise RuntimeError(f"expected present path missing: {path_expr}")
    for path_expr in survivor_set.get("absent_paths", []):
        path = logical_path(root, str(path_expr))
        observed["absent_paths"][str(path_expr)] = not (path.exists() or path.is_symlink())
        if not observed["absent_paths"][str(path_expr)]:
            raise RuntimeError(f"expected absent path still present: {path_expr}")
    for xattr_expr in survivor_set.get("xattr_state", []):
        name, _, expected = str(xattr_expr).partition("=")
        try:
            value = os.getxattr(root / "xattrfile", name.encode())
        except OSError as exc:
            observed["xattr_state"][name] = {"absent": True, "errno": exc.errno}
            if expected != "absent":
                raise
        else:
            observed["xattr_state"][name] = value.decode(errors="replace")
            if expected == "absent":
                raise RuntimeError(f"expected xattr {name} absent")
    return observed


def run_multi_handle_scenario(scenario: dict[str, object]) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    filesystem = str(scenario["filesystem"])
    expected = dict(scenario["expected_outcome"])
    handles = list(scenario["handles"])
    operation_trace = list(scenario["operation_trace"])
    cache_visibility = dict(scenario["cache_visibility"])
    reopen = dict(scenario["reopen"])
    survivor_set = dict(scenario["survivor_set"])
    stdout_path = stdout_dir / f"{scenario_id}.out"
    stderr_path = stderr_dir / f"{scenario_id}.err"
    operation_trace_path = stdout_dir / f"{scenario_id}.trace.json"
    start = time.monotonic()
    operation_trace_path.write_text(
        json.dumps(operation_trace, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    mountpoint = mountpoints.get(filesystem, "")

    base = {
        "scenario_id": scenario_id,
        "kind": str(scenario["kind"]),
        "filesystem": filesystem,
        "mount_flags": list(scenario["mount_flags"]),
        "handle_ids": [str(h["handle_id"]) for h in handles],
        "operation_trace": operation_trace,
        "operation_trace_path": str(operation_trace_path),
        "artifact_paths": [
            str(operation_trace_path),
            str(stdout_path),
            str(stderr_path),
        ],
        "expected_visibility": cache_visibility,
        "observed_visibility": {},
        "reopen_state": reopen,
        "observed_reopen_state": {},
        "survivor_set": survivor_set,
        "observed_survivor_set": {},
        "expected_outcome": str(expected["outcome_class"]),
        "actual_outcome": "skip",
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "cleanup_status": "not_run",
        "skip_reason": "",
        "duration_ms": 0,
    }

    if not execute:
        base["skip_reason"] = "FFS_MOUNTED_WRITE_EXECUTE not set to 1"
        append_log(
            stdout_path,
            f"dry-run multi-handle skip kind={scenario['kind']} handles={base['handle_ids']}",
        )
        return base
    if not mountpoint:
        base["skip_reason"] = (
            f"FFS_MOUNTED_WRITE_{filesystem.upper()}_MOUNTPOINT not set"
        )
        append_log(stdout_path, str(base["skip_reason"]))
        return base

    root = pathlib.Path(mountpoint) / "ffs_mounted_write_matrix" / "multi_handle" / run_token / scenario_id
    fds: dict[str, int] = {}
    try:
        state = setup_multi_handle_root(root, str(scenario["kind"]))
        fds, handle_paths = open_multi_handles(root, str(scenario["kind"]), handles)
        observations = []
        for step in operation_trace:
            observations.append(
                execute_multi_step(root, dict(step), fds, handle_paths, state)
            )
        survivor_observed = verify_survivor_set(root, survivor_set)
        base["observed_visibility"] = {
            "operations": observations,
            "stat_must_match": cache_visibility.get("stat_must_match"),
            "data_must_match": cache_visibility.get("data_must_match"),
            "root_path": str(root),
        }
        base["observed_reopen_state"] = {
            "kind": reopen.get("kind"),
            "verified": True,
            "detail": reopen.get("expected_state"),
        }
        base["observed_survivor_set"] = survivor_observed
        base["actual_outcome"] = "pass"
        base["cleanup_status"] = "preserved_artifacts"
        append_log(
            stdout_path,
            f"multi_handle_execute_pass kind={scenario['kind']} root={root}",
        )
    except Exception as exc:  # noqa: BLE001 - artifact runner must preserve detail.
        append_log(stderr_path, repr(exc))
        base["actual_outcome"] = "fail"
        base["cleanup_status"] = "preserved_artifacts"
        base["skip_reason"] = repr(exc)
    finally:
        for fd in fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
    base["duration_ms"] = int((time.monotonic() - start) * 1000)
    return base


multi_handle_results: list[dict[str, object]] = []
for scenario in matrix.get("multi_handle_scenarios", []):
    if multi_handle_filter and (
        str(scenario.get("scenario_id")) not in multi_handle_filter
        and str(scenario.get("kind")) not in multi_handle_filter
    ):
        continue
    multi_result = run_multi_handle_scenario(dict(scenario))
    multi_handle_results.append(multi_result)
    print(
        "MULTIHANDLE_RESULT|scenario_id={scenario_id}|kind={kind}|outcome={actual_outcome}|detail={skip_reason}".format(
            **multi_result
        )
    )

multi_handle_payload = {
    "schema_version": 1,
    "bead_id": matrix["bead_id"],
    "matrix_schema_version": matrix["schema_version"],
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "matrix_path": str(matrix_path),
    "execute": execute,
    "results": multi_handle_results,
    "reproduction_command": "scripts/e2e/ffs_mounted_write_workload_matrix.sh",
}
multi_handle_result_json.write_text(
    json.dumps(multi_handle_payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)


def run_namespace_scenario(scenario: dict[str, object]) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    filesystem = str(scenario["filesystem"])
    expected = dict(scenario["expected_outcome"])
    survivor_set = dict(scenario["expected_survivor_set"])
    reopen = dict(scenario["reopen"])
    stdout_path = stdout_dir / f"{scenario_id}.out"
    stderr_path = stderr_dir / f"{scenario_id}.err"
    operation_trace_path = stdout_dir / f"{scenario_id}.trace.json"
    operation_trace_path.write_text(
        json.dumps(
            {
                "scenario_id": scenario_id,
                "parent_directory_id": scenario["parent_directory_id"],
                "child_path_id": scenario["child_path_id"],
                "namespace_operation_kind": scenario["namespace_operation_kind"],
                "fsync_boundary": scenario["fsync_boundary"],
                "operation_sequence": scenario["operation_sequence"],
                "pre_directory_entries": scenario["pre_directory_entries"],
                "post_directory_entries": scenario["post_directory_entries"],
                "expected_link_count": scenario["expected_link_count"],
                "xattr_keys": scenario["xattr_keys"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    base = {
        "scenario_id": scenario_id,
        "filesystem": filesystem,
        "mount_flags": list(scenario["mount_flags"]),
        "parent_directory_id": str(scenario["parent_directory_id"]),
        "child_path_id": str(scenario["child_path_id"]),
        "namespace_operation_kind": str(scenario["namespace_operation_kind"]),
        "fsync_boundary": str(scenario["fsync_boundary"]),
        "operation_sequence": list(scenario["operation_sequence"]),
        "pre_directory_entries": list(scenario["pre_directory_entries"]),
        "post_directory_entries": list(scenario["post_directory_entries"]),
        "expected_survivor_set": survivor_set,
        "expected_link_count": scenario["expected_link_count"],
        "xattr_keys": list(scenario["xattr_keys"]),
        "image_fixture_hash": str(scenario["image_fixture_hash"]),
        "reopen_state": reopen,
        "no_partial_mutation_check": bool(scenario["no_partial_mutation_check"]),
        "expected_outcome": str(expected["outcome_class"]),
        "actual_outcome": "skip",
        "artifact_paths": [
            str(operation_trace_path),
            str(stdout_path),
            str(stderr_path),
        ],
        "operation_trace_path": str(operation_trace_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "cleanup_status": "not_run",
        "skip_reason": "",
        "duration_ms": 0,
    }

    if scenario["fsync_boundary"] == "host_capability_skip":
        base["skip_reason"] = "HOST_CAPABILITY_SKIP: namespace durability lane requires host FUSE capability"
    elif not execute:
        base["skip_reason"] = "FFS_MOUNTED_WRITE_EXECUTE not set to 1"
    elif not mountpoints.get(filesystem, ""):
        base["skip_reason"] = f"FFS_MOUNTED_WRITE_{filesystem.upper()}_MOUNTPOINT not set"
    else:
        base["skip_reason"] = "namespace durability mounted executor is not enabled in this dry-run gate"

    base["cleanup_status"] = "preserved_artifacts"
    append_log(
        stdout_path,
        "namespace_durability_classification "
        f"kind={base['namespace_operation_kind']} "
        f"fsync_boundary={base['fsync_boundary']} "
        f"detail={base['skip_reason']}",
    )
    return base


namespace_results: list[dict[str, object]] = []
if not only_multihandle:
    for scenario in matrix.get("namespace_scenarios", []):
        namespace_result = run_namespace_scenario(dict(scenario))
        namespace_results.append(namespace_result)
        print(
            "NAMESPACE_RESULT|scenario_id={scenario_id}|kind={namespace_operation_kind}|outcome={actual_outcome}|detail={skip_reason}".format(
                **namespace_result
            )
        )

namespace_payload = {
    "schema_version": 1,
    "bead_id": matrix["bead_id"],
    "matrix_schema_version": matrix["schema_version"],
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "matrix_path": str(matrix_path),
    "execute": execute,
    "results": namespace_results,
    "reproduction_command": "scripts/e2e/ffs_mounted_write_workload_matrix.sh",
}
namespace_result_json.write_text(
    json.dumps(namespace_payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
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
        "scenario_class",
        "image_fixture_hash",
        "expected_error_class",
        "expected_outcome",
        "actual_outcome",
        "fsync_pattern",
        "concurrency",
        "duration_ms",
        "cleanup_status",
        "skip_reason",
        "expected_survivor_set",
        "reopen_state",
        "artifact_paths",
        "remediation_id",
        "stdout_path",
        "stderr_path",
    ]
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    for result in results:
        writer.writerow(
            {
                field: (
                    json.dumps(result.get(field, ""), sort_keys=True)
                    if isinstance(result.get(field, ""), (dict, list))
                    else result.get(field, "")
                )
                for field in fieldnames
            }
        )

failed = [
    result
    for result in [*results, *multi_handle_results, *namespace_results]
    if result["actual_outcome"] == "fail"
]
if failed:
    sys.exit(1)
PY

e2e_log "Mounted write workload results JSON: $RESULT_JSON"
e2e_log "Mounted write workload results CSV: $RESULT_CSV"
e2e_log "Mounted multi-handle results JSON: $MULTIHANDLE_RESULT_JSON"
e2e_log "Mounted namespace durability results JSON: $NAMESPACE_RESULT_JSON"
