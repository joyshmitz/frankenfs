#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/mount_benchmark_probe.sh --bin <ffs-cli> --image <ext4-image> --mount-root <dir> --mode <cold|warm|recovery> [--out-json <path>]

Options:
  --bin <path>         Path to local ffs-cli binary
  --image <path>       Path to probe ext4 image
  --mount-root <path>  Directory where temporary mountpoints are created
  --mode <mode>        cold, warm, or recovery
  --out-json <path>    Write a structured probe artifact for pass/fail/skip/error
  -h, --help           Show this help
USAGE
}

FFS_BIN=""
IMAGE=""
MOUNT_ROOT=""
MODE=""
OUT_JSON=""
ATTEMPTS=()
MOUNT_READY_POLL_INTERVAL_SECS="0.005"
MOUNT_READY_MAX_POLLS=2000

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)
            [ $# -ge 2 ] || { echo "missing value for --bin" >&2; exit 2; }
            FFS_BIN="$2"
            shift 2
            ;;
        --image)
            [ $# -ge 2 ] || { echo "missing value for --image" >&2; exit 2; }
            IMAGE="$2"
            shift 2
            ;;
        --mount-root)
            [ $# -ge 2 ] || { echo "missing value for --mount-root" >&2; exit 2; }
            MOUNT_ROOT="$2"
            shift 2
            ;;
        --mode)
            [ $# -ge 2 ] || { echo "missing value for --mode" >&2; exit 2; }
            MODE="$2"
            shift 2
            ;;
        --out-json)
            [ $# -ge 2 ] || { echo "missing value for --out-json" >&2; exit 2; }
            OUT_JSON="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

write_report() {
    local outcome="$1"
    local classification="$2"
    local reason="$3"
    local exit_code="$4"

    [ -n "$OUT_JSON" ] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    mkdir -p "$(dirname "$OUT_JSON")"

    python3 - "$OUT_JSON" "$outcome" "$classification" "$reason" "$exit_code" "$MODE" "$FFS_BIN" "$IMAGE" "$MOUNT_ROOT" "$MOUNT_READY_POLL_INTERVAL_SECS" "$MOUNT_READY_MAX_POLLS" "${ATTEMPTS[@]}" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone

(
    out_path,
    outcome,
    classification,
    reason,
    exit_code,
    mode,
    ffs_bin,
    image,
    mount_root,
    poll_interval_secs,
    max_polls,
    *attempt_rows,
) = sys.argv[1:]
poll_interval_secs_float = float(poll_interval_secs)
max_polls_int = int(max_polls)

attempts = []
for row in attempt_rows:
    label, mountpoint, stdout_path, stderr_path, ready, rc, timed_out, cleanup = row.split("\t")
    attempts.append(
        {
            "label": label,
            "mountpoint": mountpoint,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "ready": ready == "1",
            "exit_code": int(rc),
            "timed_out": timed_out == "1",
            "cleanup_status": cleanup,
        }
    )

artifact = {
    "schema_version": 1,
    "probe_id": "mount_benchmark_probe",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "outcome": outcome,
    "classification": classification,
    "reason": reason,
    "exit_code": int(exit_code),
    "mode": mode,
    "kernel_fuse_mode": "permissioned_required",
    "required_capabilities": ["benchmark_host", "fuse"],
    "mount_options": {
        "writeback_cache": "disabled",
        "background_scrub": "disabled_by_probe",
        "background_repair": "not_enabled_by_probe",
    },
    "readiness_poll": {
        "interval_secs": poll_interval_secs_float,
        "max_polls": max_polls_int,
        "max_wait_secs": poll_interval_secs_float * max_polls_int,
    },
    "command": {
        "ffs_bin": ffs_bin,
        "image": image,
        "mount_root": mount_root,
    },
    "attempts": attempts,
}

pathlib.Path(out_path).write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

finish() {
    local exit_code="$1"
    local outcome="$2"
    local classification="$3"
    local reason="$4"

    write_report "$outcome" "$classification" "$reason" "$exit_code"
    if [ "$exit_code" -ne 0 ]; then
        echo "$reason" >&2
    fi
    exit "$exit_code"
}

[ -n "$FFS_BIN" ] || finish 2 "error" "input_error" "--bin is required"
[ -n "$IMAGE" ] || finish 2 "error" "input_error" "--image is required"
[ -n "$MOUNT_ROOT" ] || finish 2 "error" "input_error" "--mount-root is required"
[ -n "$MODE" ] || finish 2 "error" "input_error" "--mode is required"
[ -x "$FFS_BIN" ] || finish 2 "error" "input_error" "ffs-cli binary is not executable: $FFS_BIN"
[ -f "$IMAGE" ] || finish 2 "error" "input_error" "probe image does not exist: $IMAGE"
[ -d "$MOUNT_ROOT" ] || mkdir -p "$MOUNT_ROOT"

if ! command -v mountpoint >/dev/null 2>&1; then
    finish 2 "skip" "host_capability_skip" "mountpoint utility not available"
fi

safe_unmount() {
    local mnt="$1"
    if ! mountpoint -q "$mnt" 2>/dev/null; then
        return 0
    fi

    if command -v fusermount3 >/dev/null 2>&1; then
        fusermount3 -u "$mnt" >/dev/null 2>&1 || true
    elif command -v fusermount >/dev/null 2>&1; then
        fusermount -u "$mnt" >/dev/null 2>&1 || true
    else
        umount "$mnt" >/dev/null 2>&1 || true
    fi

    if mountpoint -q "$mnt" 2>/dev/null; then
        umount "$mnt" >/dev/null 2>&1 || umount -l "$mnt" >/dev/null 2>&1 || true
    fi
}

single_line_text() {
    tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//'
}

classify_mount_failure() {
    local reason="$1"
    case "$reason" in
        *"/dev/fuse"*|*"fusermount"*|*"FUSE"*|*"fuse"*|*"Operation not permitted"*|*"Permission denied"*|*"permission denied"*|*"CAP_SYS_ADMIN"*|*"user namespace"*)
            printf '%s\n' "host_capability_skip"
            ;;
        *)
            printf '%s\n' "mount_failed"
            ;;
    esac
}

mount_once() {
    local label="$1"
    local mnt="${MOUNT_ROOT}/${label}"
    local stdout_log="${MOUNT_ROOT}/${label}.stdout"
    local stderr_log="${MOUNT_ROOT}/${label}.stderr"
    local rc=0
    local ready=0
    local timed_out=0

    mkdir -p "$mnt"
    : >"$stdout_log"
    : >"$stderr_log"

    FFS_AUTO_UNMOUNT=0 "$FFS_BIN" mount --no-background-scrub "$IMAGE" "$mnt" >"$stdout_log" 2>"$stderr_log" &
    local pid=$!

    for _ in $(seq 1 "$MOUNT_READY_MAX_POLLS"); do
        if mountpoint -q "$mnt" 2>/dev/null; then
            if stat "$mnt" >/dev/null 2>&1; then
                ready=1
            fi
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep "$MOUNT_READY_POLL_INTERVAL_SECS"
    done

    if [ "$ready" -eq 0 ] && kill -0 "$pid" 2>/dev/null; then
        timed_out=1
        kill "$pid" >/dev/null 2>&1 || true
    fi

    safe_unmount "$mnt"
    local cleanup_status="unmounted"
    if mountpoint -q "$mnt" 2>/dev/null; then
        cleanup_status="still_mounted"
    fi

    wait "$pid" || rc=$?
    ATTEMPTS+=("${label}"$'\t'"${mnt}"$'\t'"${stdout_log}"$'\t'"${stderr_log}"$'\t'"${ready}"$'\t'"${rc}"$'\t'"${timed_out}"$'\t'"${cleanup_status}")

    if [ "$ready" -ne 1 ] || [ "$rc" -ne 0 ]; then
        local reason
        reason="$(single_line_text < "$stderr_log")"
        if [ -z "$reason" ]; then
            reason="mount probe failed"
        fi
        if [ "$timed_out" -eq 1 ]; then
            reason="${reason} (mount did not become ready within timeout)"
        fi
        MOUNT_FAILURE_REASON="$reason"
        MOUNT_FAILURE_CLASSIFICATION="$(classify_mount_failure "$reason")"
        return 1
    fi
}

MOUNT_FAILURE_REASON=""
MOUNT_FAILURE_CLASSIFICATION=""

case "$MODE" in
    cold)
        if ! mount_once "cold"; then
            finish 1 "fail" "$MOUNT_FAILURE_CLASSIFICATION" "$MOUNT_FAILURE_REASON"
        fi
        ;;
    warm)
        if ! mount_once "warm_prepare"; then
            finish 1 "fail" "$MOUNT_FAILURE_CLASSIFICATION" "$MOUNT_FAILURE_REASON"
        fi
        if ! mount_once "warm_measure"; then
            finish 1 "fail" "$MOUNT_FAILURE_CLASSIFICATION" "$MOUNT_FAILURE_REASON"
        fi
        ;;
    recovery)
        if ! mount_once "recovery"; then
            finish 1 "fail" "$MOUNT_FAILURE_CLASSIFICATION" "$MOUNT_FAILURE_REASON"
        fi
        ;;
    *)
        finish 2 "error" "input_error" "unsupported mode: $MODE (expected cold|warm|recovery)"
        ;;
esac

finish 0 "pass" "measured" "mounted benchmark probe completed"
