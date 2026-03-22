#!/usr/bin/env bash
# ffs_btrfs_rw_smoke.sh - btrfs read-write E2E smoke test for FrankenFS
#
# This suite mirrors ext4 RW smoke coverage for btrfs and records
# per-test timings plus a JUnit report for CI parsing.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-ffs=trace,fuser=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export FFS_USE_RCH="${FFS_USE_RCH:-1}"
export FFS_AUTO_UNMOUNT="${FFS_AUTO_UNMOUNT:-0}"
export TMPDIR="${TMPDIR:-$REPO_ROOT/artifacts/tmp}"
mkdir -p "$TMPDIR"
FFS_CLI_BIN="${FFS_CLI_BIN:-$REPO_ROOT/target/release/ffs-cli}"

e2e_init "ffs_btrfs_rw_smoke"
e2e_print_env

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""
WORK_IMAGE=""
MOUNT_RW=""
MOUNT_RO=""
CRASH_MATRIX_POINTS="${CRASH_MATRIX_POINTS:-10}"

JUNIT_FILE="$E2E_LOG_DIR/junit.xml"
declare -a TEST_NAMES=()
declare -a TEST_STATUSES=()
declare -a TEST_DURATIONS_MS=()
declare -a TEST_MESSAGES=()

timestamp_ms() {
    date +%s%3N
}

xml_escape() {
    local raw="$1"
    raw="${raw//&/&amp;}"
    raw="${raw//</&lt;}"
    raw="${raw//>/&gt;}"
    raw="${raw//\"/&quot;}"
    raw="${raw//\'/&apos;}"
    printf '%s' "$raw"
}

scenario_id_for_test_name() {
    local test_name="$1"
    local normalized
    normalized="$(printf '%s' "$test_name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+//; s/_+$//')"
    printf 'btrfs_rw_%s' "$normalized"
}

log_test() {
    local name="$1"
    local status="$2"
    local duration_ms="$3"
    e2e_log "[$(date -Iseconds)] TEST: $name STATUS: $status DURATION: ${duration_ms}ms"
}

record_test() {
    local name="$1"
    local status="$2"
    local duration_ms="$3"
    local message="${4:-}"
    local scenario_id
    scenario_id="$(scenario_id_for_test_name "$name")"

    TEST_NAMES+=("$name")
    TEST_STATUSES+=("$status")
    TEST_DURATIONS_MS+=("$duration_ms")
    TEST_MESSAGES+=("$message")

    log_test "$name" "$status" "$duration_ms"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|status=${status}|duration_ms=${duration_ms}"
    if [[ -n "$message" ]]; then
        e2e_log "  detail: $message"
    fi
}

emit_junit() {
    local tests="${#TEST_NAMES[@]}"
    local failures=0
    local skipped=0
    local i

    for i in "${!TEST_STATUSES[@]}"; do
        case "${TEST_STATUSES[$i]}" in
            fail) failures=$((failures + 1)) ;;
            skipped) skipped=$((skipped + 1)) ;;
        esac
    done

    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<testsuite name="ffs_btrfs_rw_smoke" tests="%d" failures="%d" skipped="%d">\n' "$tests" "$failures" "$skipped"
        for i in "${!TEST_NAMES[@]}"; do
            local name status duration_ms message duration_s
            name="$(xml_escape "${TEST_NAMES[$i]}")"
            status="${TEST_STATUSES[$i]}"
            duration_ms="${TEST_DURATIONS_MS[$i]}"
            message="$(xml_escape "${TEST_MESSAGES[$i]}")"
            duration_s="$(awk "BEGIN { printf \"%.3f\", ${duration_ms}/1000.0 }")"
            printf '  <testcase name="%s" time="%s">' "$name" "$duration_s"
            if [[ "$status" == "fail" ]]; then
                printf '<failure message="%s">%s</failure>' "$message" "$message"
            elif [[ "$status" == "skipped" ]]; then
                printf '<skipped message="%s"/>' "$message"
            fi
            printf '</testcase>\n'
        done
        printf '</testsuite>\n'
    } >"$JUNIT_FILE"

    e2e_log "JUnit report: $JUNIT_FILE"
}

capture_state() {
    local label="$1"
    e2e_log "=== State: $label ==="

    if [[ -n "$CURRENT_MOUNT_POINT" ]] && [[ -d "$CURRENT_MOUNT_POINT" ]]; then
        e2e_log "--- ls -laR $CURRENT_MOUNT_POINT ---"
        e2e_run bash -lc "ls -laR '$CURRENT_MOUNT_POINT'" || true
    else
        e2e_log "Mount point not available for state capture."
    fi

    if [[ -n "$WORK_IMAGE" ]] && [[ -f "$WORK_IMAGE" ]] && command -v btrfs >/dev/null 2>&1; then
        e2e_log "--- btrfs inspect-internal dump-tree (first 100 lines) ---"
        e2e_run bash -lc "btrfs inspect-internal dump-tree '$WORK_IMAGE' 2>/dev/null | sed -n '1,100p'" || true
    fi
}

capture_failure_diagnostics() {
    e2e_log "=== Failure diagnostics ==="
    if command -v dmesg >/dev/null 2>&1; then
        e2e_log "--- dmesg (tail -50) ---"
        e2e_run bash -lc "dmesg | tail -50" || true
    fi
    if command -v journalctl >/dev/null 2>&1; then
        e2e_log "--- journalctl -n 50 ---"
        e2e_run journalctl -n 50 || true
    fi
}

skip_suite() {
    local reason="$1"
    record_test "suite" "skipped" 0 "$reason"
    emit_junit
    e2e_log ""
    e2e_log "SKIPPED: $reason"
    e2e_log "Log file: $E2E_LOG_FILE"
    exit 0
}

fail_suite() {
    local test_name="$1"
    local duration_ms="$2"
    local detail="$3"

    record_test "$test_name" "fail" "$duration_ms" "$detail"
    capture_state "failure-$test_name"
    capture_failure_diagnostics
    emit_junit

    # Keep temp dirs for postmortem on failure.
    E2E_CLEANUP_ITEMS=()
    e2e_log "Preserving temp directory for debugging: $E2E_TEMP_DIR"
    e2e_fail "$test_name failed: $detail"
}

run_case() {
    local test_name="$1"
    shift

    local start_ms duration_ms
    start_ms="$(timestamp_ms)"
    if e2e_run "$@"; then
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        record_test "$test_name" "pass" "$duration_ms"
    else
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        fail_suite "$test_name" "$duration_ms" "command failed (exit=${E2E_LAST_EXIT_CODE})"
    fi
}

run_case_shell() {
    local test_name="$1"
    local shell_cmd="$2"
    run_case "$test_name" bash -lc "$shell_cmd"
}

run_case_cargo() {
    local test_name="$1"
    shift

    if [[ "$FFS_USE_RCH" == "1" ]] && command -v rch >/dev/null 2>&1; then
        run_case "$test_name" rch exec -- cargo "$@"
    else
        run_case "$test_name" cargo "$@"
    fi
}

expect_case_failure() {
    local test_name="$1"
    shift
    local start_ms duration_ms

    start_ms="$(timestamp_ms)"
    if e2e_run "$@"; then
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        fail_suite "$test_name" "$duration_ms" "expected failure but command succeeded"
    else
        duration_ms=$(( $(timestamp_ms) - start_ms ))
        record_test "$test_name" "pass" "$duration_ms" "expected failure observed (exit=${E2E_LAST_EXIT_CODE})"
    fi
}

wait_for_pid_exit() {
    local pid="$1"
    local timeout_seconds="${2:-10}"
    local label="${3:-process}"
    local elapsed_ticks=0

    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.2
        elapsed_ticks=$((elapsed_ticks + 1))
        if [[ $elapsed_ticks -ge $((timeout_seconds * 5)) ]]; then
            e2e_log "$label did not exit after ${timeout_seconds}s; sending SIGKILL"
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
    done

    wait "$pid" 2>/dev/null || true
}

crash_matrix_label_for_point() {
    local point="$1"
    case "$point" in
        1) printf 'create_alpha_no_fsync' ;;
        2) printf 'append_alpha_no_fsync' ;;
        3) printf 'fsync_alpha_and_parent' ;;
        4) printf 'rename_alpha_to_beta_no_fsync' ;;
        5) printf 'fsync_rename_parent' ;;
        6) printf 'create_gamma_no_fsync' ;;
        7) printf 'fsync_gamma_and_parent' ;;
        8) printf 'unlink_beta_no_fsync' ;;
        9) printf 'unlink_gamma_no_fsync' ;;
        10) printf 'fsync_unlink_parent' ;;
        *) return 1 ;;
    esac
}

crash_matrix_event_log() {
    local operation_id="$1"
    local scenario_id="$2"
    local outcome="$3"
    local error_class="${4:-none}"
    e2e_log "CRASH_MATRIX_EVENT|operation_id=${operation_id}|scenario_id=${scenario_id}|outcome=${outcome}|error_class=${error_class}"
}

run_crash_matrix_rw_steps() {
    local mount_point="$1"
    local point="$2"
    python3 - "$mount_point" "$point" <<'PY'
import os
import pathlib
import sys

mount = pathlib.Path(sys.argv[1])
point = int(sys.argv[2])
if point < 1 or point > 10:
    raise SystemExit(f"unsupported crash matrix point: {point}")

matrix = mount / "crash_matrix"
alpha = matrix / "alpha.txt"
beta = matrix / "beta.txt"
gamma = matrix / "gamma.txt"
alpha_v1 = b"alpha-v1\n"
alpha_v2 = b"alpha-v2\n"
gamma_seed = b"gamma-seed\n"

matrix.mkdir(parents=True, exist_ok=True)

def fsync_file(path: pathlib.Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def fsync_dir(path: pathlib.Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def step_1_create_alpha_no_fsync() -> None:
    alpha.write_bytes(alpha_v1)

def step_2_append_alpha_no_fsync() -> None:
    with alpha.open("ab") as handle:
        handle.write(alpha_v2)

def step_3_fsync_alpha_and_parent() -> None:
    fsync_file(alpha)
    fsync_dir(matrix)

def step_4_rename_alpha_to_beta_no_fsync() -> None:
    alpha.rename(beta)

def step_5_fsync_rename_parent() -> None:
    fsync_dir(matrix)

def step_6_create_gamma_no_fsync() -> None:
    gamma.write_bytes(gamma_seed)

def step_7_fsync_gamma_and_parent() -> None:
    fsync_file(gamma)
    fsync_dir(matrix)

def step_8_unlink_beta_no_fsync() -> None:
    if beta.exists():
        beta.unlink()

def step_9_unlink_gamma_no_fsync() -> None:
    if gamma.exists():
        gamma.unlink()

def step_10_fsync_unlink_parent() -> None:
    fsync_dir(matrix)

steps = [
    step_1_create_alpha_no_fsync,
    step_2_append_alpha_no_fsync,
    step_3_fsync_alpha_and_parent,
    step_4_rename_alpha_to_beta_no_fsync,
    step_5_fsync_rename_parent,
    step_6_create_gamma_no_fsync,
    step_7_fsync_gamma_and_parent,
    step_8_unlink_beta_no_fsync,
    step_9_unlink_gamma_no_fsync,
    step_10_fsync_unlink_parent,
]

for idx, step in enumerate(steps, start=1):
    step()
    if idx == point:
        break
PY
}

verify_crash_matrix_ro_state() {
    local mount_point="$1"
    local point="$2"
    local report_path="$3"
    python3 - "$mount_point" "$point" "$report_path" <<'PY'
import json
import pathlib
import sys

mount = pathlib.Path(sys.argv[1])
point = int(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])

matrix = mount / "crash_matrix"
alpha = matrix / "alpha.txt"
beta = matrix / "beta.txt"
gamma = matrix / "gamma.txt"
alpha_full = b"alpha-v1\nalpha-v2\n"
gamma_full = b"gamma-seed\n"
errors = []

def read_bytes(path: pathlib.Path):
    if path.exists():
        return path.read_bytes()
    return None

def prefix_ok(value, expected):
    if value is None:
        return True
    return expected.startswith(value)

alpha_data = read_bytes(alpha)
beta_data = read_bytes(beta)
gamma_data = read_bytes(gamma)

if point in (1, 2):
    if beta_data is not None:
        errors.append("beta.txt must not exist before rename points")
    if gamma_data is not None:
        errors.append("gamma.txt must not exist before gamma-create points")
    if alpha_data is not None and not prefix_ok(alpha_data, alpha_full):
        errors.append("alpha.txt contains unexpected bytes before fsync boundary")
elif point == 3:
    if alpha_data != alpha_full:
        errors.append("alpha.txt must persist full payload after fsync boundary")
    if beta_data is not None:
        errors.append("beta.txt must not exist at crash point 3")
    if gamma_data is not None:
        errors.append("gamma.txt must not exist at crash point 3")
elif point == 4:
    if gamma_data is not None:
        errors.append("gamma.txt must not exist at crash point 4")
    if alpha_data is None and beta_data is None:
        errors.append("expected alpha.txt or beta.txt after rename without fsync")
    if alpha_data is not None and alpha_data != alpha_full:
        errors.append("alpha.txt (if present) must match full payload at crash point 4")
    if beta_data is not None and beta_data != alpha_full:
        errors.append("beta.txt (if present) must match full payload at crash point 4")
elif point == 5:
    if alpha_data is not None:
        errors.append("alpha.txt must be absent after fsync rename boundary")
    if beta_data != alpha_full:
        errors.append("beta.txt must persist full payload after fsync rename boundary")
    if gamma_data is not None:
        errors.append("gamma.txt must not exist at crash point 5")
elif point == 6:
    if alpha_data is not None:
        errors.append("alpha.txt must be absent at crash point 6")
    if beta_data != alpha_full:
        errors.append("beta.txt must persist full payload at crash point 6")
    if gamma_data is not None and not prefix_ok(gamma_data, gamma_full):
        errors.append("gamma.txt contains unexpected bytes before fsync boundary")
elif point == 7:
    if alpha_data is not None:
        errors.append("alpha.txt must be absent at crash point 7")
    if beta_data != alpha_full:
        errors.append("beta.txt must persist full payload at crash point 7")
    if gamma_data != gamma_full:
        errors.append("gamma.txt must persist full payload after fsync boundary")
elif point == 8:
    if alpha_data is not None:
        errors.append("alpha.txt must be absent at crash point 8")
    if beta_data is not None and beta_data != alpha_full:
        errors.append("beta.txt (if present) must match full payload at crash point 8")
    if gamma_data != gamma_full:
        errors.append("gamma.txt must persist full payload at crash point 8")
elif point == 9:
    if alpha_data is not None:
        errors.append("alpha.txt must be absent at crash point 9")
    if beta_data is not None and beta_data != alpha_full:
        errors.append("beta.txt (if present) must match full payload at crash point 9")
    if gamma_data is not None and gamma_data != gamma_full:
        errors.append("gamma.txt (if present) must match full payload at crash point 9")
elif point == 10:
    if alpha_data is not None:
        errors.append("alpha.txt must be absent after unlink fsync boundary")
    if beta_data is not None:
        errors.append("beta.txt must be absent after unlink fsync boundary")
    if gamma_data is not None:
        errors.append("gamma.txt must be absent after unlink fsync boundary")
else:
    errors.append(f"unsupported crash matrix point: {point}")

if matrix.exists():
    for child in matrix.iterdir():
        if child.is_file():
            try:
                _ = child.read_bytes()
            except OSError as exc:
                errors.append(f"failed to read file during consistency walk: {child.name}: {exc}")

report = {
    "crash_point": point,
    "alpha_present": alpha_data is not None,
    "beta_present": beta_data is not None,
    "gamma_present": gamma_data is not None,
    "alpha_size": None if alpha_data is None else len(alpha_data),
    "beta_size": None if beta_data is None else len(beta_data),
    "gamma_size": None if gamma_data is None else len(gamma_data),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
if errors:
    for entry in errors:
        print(entry)
    raise SystemExit(1)
PY
}

run_crash_matrix_point() {
    local point="$1"
    local label="$2"
    local point_id
    point_id="$(printf '%02d' "$point")"

    local operation_id="btrfs-crash-matrix-point-${point_id}"
    local scenario_id="btrfs_rw_crash_matrix_${point_id}_${label}"
    local scenario_image="$E2E_TEMP_DIR/crash_matrix_${point_id}.btrfs"
    local mount_rw_point="$E2E_TEMP_DIR/mnt_crash_rw_${point_id}"
    local mount_ro_point="$E2E_TEMP_DIR/mnt_crash_ro_${point_id}"
    local artifact_dir="$E2E_LOG_DIR/crash_matrix/${point_id}_${label}"
    local report_path="$artifact_dir/recovery_verify_report.json"
    mkdir -p "$artifact_dir"

    cp "$BASE_IMAGE" "$scenario_image"
    crash_matrix_event_log "$operation_id" "$scenario_id" "start" "none"

    start_mount rw "$scenario_image" "$mount_rw_point" 20
    local rw_mount_log="$CURRENT_MOUNT_LOG"

    if ! run_crash_matrix_rw_steps "$mount_rw_point" "$point"; then
        crash_matrix_event_log "$operation_id" "$scenario_id" "rejected" "rw_step_execution_failed"
        return 1
    fi

    if [[ "$point" == "3" || "$point" == "5" || "$point" == "7" || "$point" == "10" ]]; then
        if ! grep -q "btrfs_sync_applied" "$rw_mount_log"; then
            crash_matrix_event_log "$operation_id" "$scenario_id" "rejected" "missing_sync_applied_log"
            return 1
        fi
        if ! grep -q "operation_id=btrfs-fsync" "$rw_mount_log" && ! grep -q "operation_id=btrfs-fsyncdir" "$rw_mount_log"; then
            crash_matrix_event_log "$operation_id" "$scenario_id" "rejected" "missing_sync_operation_id_log"
            return 1
        fi
        if ! grep -q 'scenario_id="btrfs_rw_fsync' "$rw_mount_log"; then
            crash_matrix_event_log "$operation_id" "$scenario_id" "rejected" "missing_sync_scenario_id_log"
            return 1
        fi
    fi

    crash_matrix_event_log "$operation_id" "$scenario_id" "crash_injected" "none"
    if [[ -n "$CURRENT_MOUNT_PID" ]] && kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
        wait_for_pid_exit "$CURRENT_MOUNT_PID" 10 "crash-matrix mount daemon"
    fi
    CURRENT_MOUNT_PID=""
    e2e_unmount "$mount_rw_point" || true
    cp "$rw_mount_log" "$artifact_dir/mount_rw.log" || true

    if ! "$FFS_CLI_BIN" inspect "$scenario_image" --json >"$artifact_dir/inspect_after_crash.json" 2>"$artifact_dir/inspect_after_crash.stderr"; then
        crash_matrix_event_log "$operation_id" "$scenario_id" "rejected" "post_crash_inspect_failed"
        return 1
    fi

    start_mount ro "$scenario_image" "$mount_ro_point" 20
    local ro_mount_log="$CURRENT_MOUNT_LOG"

    if ! verify_crash_matrix_ro_state "$mount_ro_point" "$point" "$report_path"; then
        crash_matrix_event_log "$operation_id" "$scenario_id" "rejected" "recovery_verification_failed"
        cp "$ro_mount_log" "$artifact_dir/mount_ro.log" || true
        stop_mount "$mount_ro_point"
        return 1
    fi

    cp "$ro_mount_log" "$artifact_dir/mount_ro.log" || true
    stop_mount "$mount_ro_point"
    crash_matrix_event_log "$operation_id" "$scenario_id" "applied" "none"
    return 0
}

wait_for_mount_ready() {
    local mount_point="$1"
    local pid="$2"
    local timeout_seconds="${3:-20}"
    local elapsed=0

    while ! mountpoint -q "$mount_point" 2>/dev/null; do
        sleep 0.5
        elapsed=$((elapsed + 1))

        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi

        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            return 2
        fi
    done
    return 0
}

start_mount() {
    local mode="$1"
    local image="$2"
    local mount_point="$3"
    local timeout_seconds="${4:-20}"

    if [[ "${SKIP_MOUNT:-0}" == "1" ]]; then
        skip_suite "mount tests skipped (SKIP_MOUNT=1)"
    fi
    if [[ ! -e /dev/fuse ]]; then
        skip_suite "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        skip_suite "/dev/fuse not accessible"
    fi
    if ! command -v mountpoint >/dev/null 2>&1; then
        skip_suite "mountpoint utility not found"
    fi

    mkdir -p "$mount_point"
    E2E_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_LOG="$E2E_LOG_DIR/mount_${mode}_$(basename "$mount_point").log"

    local cmd=("$FFS_CLI_BIN" mount "$image" "$mount_point")
    if [[ "$mode" == "rw" ]]; then
        cmd+=(--rw)
    fi

    e2e_log "Starting mount command: ${cmd[*]}"
    e2e_log "Mount log: $CURRENT_MOUNT_LOG"
    "${cmd[@]}" >"$CURRENT_MOUNT_LOG" 2>&1 &
    CURRENT_MOUNT_PID=$!

    local ready_result=0
    if wait_for_mount_ready "$mount_point" "$CURRENT_MOUNT_PID" "$timeout_seconds"; then
        ready_result=0
    else
        ready_result=$?
    fi

    if [[ $ready_result -eq 0 ]]; then
        e2e_log "Mount ready at $mount_point (pid=$CURRENT_MOUNT_PID, mode=$mode)"
        return 0
    fi

    local mount_rc=0
    if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
        mount_rc=124
    else
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || mount_rc=$?
    fi

    e2e_log "Mount failed (mode=$mode rc=$mount_rc), tailing mount log:"
    e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true

    if grep -qiE "allow_other only allowed if 'user_allow_other' is set" "$CURRENT_MOUNT_LOG"; then
        skip_suite "FUSE present but user_allow_other is not enabled in /etc/fuse.conf"
    fi
    if grep -qiE "Permission denied|Operation not permitted" "$CURRENT_MOUNT_LOG"; then
        skip_suite "FUSE mount not permitted in this environment"
    fi
    if [[ "$mode" == "rw" ]] && grep -qiE "btrfs read-write mount is not yet supported|read-write mount is not yet supported" "$CURRENT_MOUNT_LOG"; then
        skip_suite "btrfs read-write mount is not yet supported in this build"
    fi
    if [[ "$mode" == "rw" ]] && grep -qiE "logical_address \\(not covered by any chunk\\)" "$CURRENT_MOUNT_LOG"; then
        skip_suite "btrfs read-write mount skipped: current image chunk mapping is outside writable support envelope"
    fi

    if [[ $ready_result -eq 2 ]]; then
        fail_suite "mount_${mode}" 0 "mount timed out after ${timeout_seconds}s"
    fi
    fail_suite "mount_${mode}" 0 "mount process exited before mount became ready"
}

stop_mount() {
    local mount_point="${1:-$CURRENT_MOUNT_POINT}"

    e2e_unmount "$mount_point"
    if [[ -n "$CURRENT_MOUNT_PID" ]] && kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
            kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
        fi
    fi
    if [[ -n "$CURRENT_MOUNT_PID" ]]; then
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
    fi

    CURRENT_MOUNT_PID=""
    CURRENT_MOUNT_POINT=""
}

super_generation() {
    local image="$1"
    btrfs inspect-internal dump-super -f "$image" 2>/dev/null | awk '/^generation[[:space:]]/ { print $2; exit }'
}

super_root_bytenr() {
    local image="$1"
    btrfs inspect-internal dump-super -f "$image" 2>/dev/null | awk '/^root[[:space:]]/ { print $2; exit }'
}

prepare_btrfs_images() {
    local base_image="$1"
    local work_image="$2"
    local fallback_fixture="$REPO_ROOT/tests/fixtures/images/btrfs_small.img"

    if ! command -v mkfs.btrfs >/dev/null 2>&1; then
        skip_suite "mkfs.btrfs not found"
    fi
    if ! command -v btrfs >/dev/null 2>&1; then
        skip_suite "btrfs CLI not found"
    fi

    e2e_log "Preparing btrfs base image ($base_image, 256 MiB)."
    run_case "image_allocate_256mb" dd if=/dev/zero of="$base_image" bs=1M count=256 status=none
    run_case "image_mkfs_btrfs" mkfs.btrfs -f "$base_image"

    if e2e_run "$FFS_CLI_BIN" inspect "$base_image" --json; then
        e2e_log "Fresh mkfs.btrfs image is inspectable by current FrankenFS parser."
    else
        e2e_log "Fresh mkfs.btrfs image is not inspectable yet; falling back to fixture image."
        if [[ ! -f "$fallback_fixture" ]]; then
            fail_suite "image_fallback" 0 "fallback fixture missing: $fallback_fixture"
        fi
        run_case "image_fallback_copy" cp "$fallback_fixture" "$base_image"
    fi

    run_case "image_copy_work" cp "$base_image" "$work_image"
}

check_punch_hole_zeroes_range() {
    local path="$1"
    python3 - "$path" <<'PY'
import fcntl
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
try:
    if not hasattr(fcntl, "fallocate"):
        raise SystemExit("python fcntl.fallocate is unavailable")
    before_size = os.fstat(fd).st_size
    before_data = os.pread(fd, before_size, 0)
    mode = fcntl.FALLOC_FL_KEEP_SIZE | fcntl.FALLOC_FL_PUNCH_HOLE
    fcntl.fallocate(fd, mode, 0, 4096)
    after_size = os.fstat(fd).st_size
    after_data = os.pread(fd, after_size, 0)
    if after_size != before_size:
        raise SystemExit(
            f"punch-hole changed file size under KEEP_SIZE: before={before_size} after={after_size}"
        )
    if any(after_data[:4096]):
        raise SystemExit("punch-hole range was not zeroed")
    if after_data[4096:] != before_data[4096:]:
        raise SystemExit("punch-hole mutated file bytes outside the requested range")
finally:
    os.close(fd)
PY
}

check_unsupported_mode_bits_eopnotsupp() {
    local path="$1"
    python3 - "$path" <<'PY'
import errno
import fcntl
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
try:
    if not hasattr(fcntl, "fallocate"):
        raise SystemExit("python fcntl.fallocate is unavailable")
    before_size = os.fstat(fd).st_size
    before_data = os.pread(fd, min(before_size, 8192), 0)
    unsupported_mode = 0x40
    try:
        fcntl.fallocate(fd, unsupported_mode, 0, 4096)
    except OSError as exc:  # expected path
        if exc.errno == errno.EOPNOTSUPP:
            after_size = os.fstat(fd).st_size
            after_data = os.pread(fd, min(after_size, 8192), 0)
            if after_size != before_size:
                raise SystemExit(
                    f"unsupported mode bits changed file size: before={before_size} after={after_size}"
                )
            if after_data != before_data:
                raise SystemExit("unsupported mode bits mutated file bytes before rejection")
            raise SystemExit(0)
        raise SystemExit(f"expected errno {errno.EOPNOTSUPP}, got {exc.errno}: {exc}")
    raise SystemExit("expected unsupported-mode-bits fallocate to fail with EOPNOTSUPP, but it succeeded")
finally:
    os.close(fd)
PY
}

e2e_step "Phase 1: Build ffs-cli"
run_case_cargo "build_ffs_cli" build -p ffs-cli --release
run_case "build_ffs_cli_binary_exists" test -x "$FFS_CLI_BIN"

e2e_step "Phase 2: Prepare btrfs test image"
BASE_IMAGE="$E2E_TEMP_DIR/base.btrfs"
WORK_IMAGE="$E2E_TEMP_DIR/work.btrfs"
prepare_btrfs_images "$BASE_IMAGE" "$WORK_IMAGE"
run_case "inspect_work_image" "$FFS_CLI_BIN" inspect "$WORK_IMAGE" --json

GEN_BEFORE="$(super_generation "$WORK_IMAGE")"
ROOT_BEFORE="$(super_root_bytenr "$WORK_IMAGE")"
e2e_log "Initial superblock generation=$GEN_BEFORE root_bytenr=$ROOT_BEFORE"

e2e_step "Phase 3: Mount RW and execute btrfs write-path operations"
MOUNT_RW="$E2E_TEMP_DIR/mnt_rw"
start_mount rw "$WORK_IMAGE" "$MOUNT_RW" 20
capture_state "rw-mounted-before-ops"

run_case_shell "file_small_write" "printf 'small-line\\n' > '$MOUNT_RW/small.txt'"
run_case_shell "file_small_verify" "grep -Fxq 'small-line' '$MOUNT_RW/small.txt'"

run_case_shell "file_medium_write_4kb" "python3 -c \"from pathlib import Path; Path('$MOUNT_RW/medium.bin').write_bytes(b'M' * 4096)\""
run_case_shell "file_medium_md5" "md5sum '$MOUNT_RW/medium.bin' > '$E2E_LOG_DIR/medium.md5'"

run_case_shell "file_large_write_1mb" "python3 -c \"from pathlib import Path; Path('$MOUNT_RW/large.bin').write_bytes(b'L' * (1024 * 1024))\""
run_case_shell "file_large_md5" "md5sum '$MOUNT_RW/large.bin' > '$E2E_LOG_DIR/large.md5'"
run_case_shell "file_overwrite_verify" "printf 'overwritten\\n' > '$MOUNT_RW/small.txt' && grep -Fxq 'overwritten' '$MOUNT_RW/small.txt'"
run_case_shell "file_append" "printf 'append-line\\n' >> '$MOUNT_RW/small.txt' && grep -Fxq 'append-line' '$MOUNT_RW/small.txt'"

run_case_shell "file_truncate_extend_2mb" "truncate -s 2097152 '$MOUNT_RW/large.bin'"
run_case_shell "file_truncate_shrink_256b" "truncate -s 256 '$MOUNT_RW/large.bin' && test \"$(stat -c '%s' '$MOUNT_RW/large.bin')\" -eq 256"
run_case "fallocate_punch_hole_keep_size_zeroes_range" check_punch_hole_zeroes_range "$MOUNT_RW/medium.bin"
run_case "unsupported_fallocate_mode_bits_errno_eopnotsupp" check_unsupported_mode_bits_eopnotsupp "$MOUNT_RW/medium.bin"

run_case "dir_mkdir_single" mkdir "$MOUNT_RW/single_dir"
run_case "dir_mkdir_nested" mkdir -p "$MOUNT_RW/nested/a/b"
run_case "dir_rmdir_empty" rmdir "$MOUNT_RW/single_dir"
expect_case_failure "dir_rmdir_non_empty_fails" rmdir "$MOUNT_RW/nested"

run_case_shell "name_rename_within_dir" "mv '$MOUNT_RW/small.txt' '$MOUNT_RW/small_renamed.txt'"
run_case_shell "name_rename_across_dir" "mv '$MOUNT_RW/small_renamed.txt' '$MOUNT_RW/nested/a/small_renamed.txt'"
run_case_shell "name_rename_over_existing" "printf 'target\\n' > '$MOUNT_RW/target.txt'; printf 'source\\n' > '$MOUNT_RW/source.txt'; mv -f '$MOUNT_RW/source.txt' '$MOUNT_RW/target.txt'; grep -Fxq 'source' '$MOUNT_RW/target.txt'"
run_case "name_unlink_regular" rm "$MOUNT_RW/target.txt"

run_case_shell "link_symlink_create" "ln -s '$MOUNT_RW/medium.bin' '$MOUNT_RW/medium.link'"
run_case_shell "link_symlink_readlink" "test \"$(readlink '$MOUNT_RW/medium.link')\" = '$MOUNT_RW/medium.bin'"
run_case "link_symlink_unlink" rm "$MOUNT_RW/medium.link"

run_case_shell "link_hardlink_create" "ln '$MOUNT_RW/medium.bin' '$MOUNT_RW/medium.hard'"
run_case_shell "link_hardlink_inode_match" "test \"$(stat -c '%i' '$MOUNT_RW/medium.bin')\" = \"$(stat -c '%i' '$MOUNT_RW/medium.hard')\""
run_case_shell "link_hardlink_shared_data" "printf 'X' >> '$MOUNT_RW/medium.hard'; tail -c 1 '$MOUNT_RW/medium.bin' | grep -Fxq 'X'"
run_case "link_hardlink_unlink" rm "$MOUNT_RW/medium.hard"

e2e_step "Phase 3.1: COW generation checks"
run_case_shell "cow_hot_file_seed" "printf 'cow-seed\\n' > '$MOUNT_RW/cow_hot.txt'"
for i in $(seq 1 10); do
    run_case_shell "cow_rewrite_$i" "printf 'rewrite-%02d\\n' $i > '$MOUNT_RW/cow_hot.txt'"
done
run_case_shell "cow_fsync_hot_file" "python3 -c \"import os; path='$MOUNT_RW/cow_hot.txt'; fd=os.open(path, os.O_RDWR); os.fsync(fd); os.close(fd)\""
run_case "cow_sync" sync

capture_state "rw-mounted-after-ops"

e2e_step "Phase 3.2: Clean unmount"
run_case "rw_stop_mount" stop_mount "$MOUNT_RW"
if mountpoint -q "$MOUNT_RW" 2>/dev/null; then
    fail_suite "rw_unmount_verify" 0 "RW mount point still mounted: $MOUNT_RW"
fi

GEN_AFTER="$(super_generation "$WORK_IMAGE")"
ROOT_AFTER="$(super_root_bytenr "$WORK_IMAGE")"
e2e_log "Post-write superblock generation=$GEN_AFTER root_bytenr=$ROOT_AFTER"

if [[ -n "$GEN_BEFORE" ]] && [[ -n "$GEN_AFTER" ]]; then
    if (( GEN_AFTER <= GEN_BEFORE )); then
        fail_suite "cow_generation_advances" 0 "generation did not advance: before=$GEN_BEFORE after=$GEN_AFTER"
    fi
    record_test "cow_generation_advances" "pass" 0 "generation before=$GEN_BEFORE after=$GEN_AFTER"
fi
if [[ -n "$ROOT_BEFORE" ]] && [[ -n "$ROOT_AFTER" ]]; then
    if [[ "$ROOT_BEFORE" == "$ROOT_AFTER" ]]; then
        fail_suite "cow_root_changed" 0 "root bytenr unchanged after writes: before=$ROOT_BEFORE after=$ROOT_AFTER"
    fi
    record_test "cow_root_changed" "pass" 0 "root before=$ROOT_BEFORE after=$ROOT_AFTER"
fi

e2e_step "Phase 4: Remount RO and verify persistence"
MOUNT_RO="$E2E_TEMP_DIR/mnt_ro"
start_mount ro "$WORK_IMAGE" "$MOUNT_RO" 20

run_case_shell "persist_small_data" "grep -Fxq 'append-line' '$MOUNT_RO/nested/a/small_renamed.txt'"
run_case_shell "persist_medium_size" "test \"$(stat -c '%s' '$MOUNT_RO/medium.bin')\" -ge 4096"
run_case_shell "persist_large_size" "test \"$(stat -c '%s' '$MOUNT_RO/large.bin')\" -eq 256"
run_case_shell "persist_mode_preserved" "stat -c '%a' '$MOUNT_RO/nested/a/small_renamed.txt' >/dev/null"
run_case_shell "persist_mtime_present" "test \"$(stat -c '%Y' '$MOUNT_RO/nested/a/small_renamed.txt')\" -gt 0"

capture_state "ro-mounted-verification"
run_case "ro_stop_mount" stop_mount "$MOUNT_RO"
if mountpoint -q "$MOUNT_RO" 2>/dev/null; then
    fail_suite "ro_unmount_verify" 0 "RO mount point still mounted: $MOUNT_RO"
fi

e2e_step "Phase 5: Deterministic crash-consistency matrix (10 crash points)"
if [[ "$CRASH_MATRIX_POINTS" != "10" ]]; then
    fail_suite "crash_matrix_points_config" 0 "CRASH_MATRIX_POINTS must be 10 (got $CRASH_MATRIX_POINTS)"
fi
for point in $(seq 1 10); do
    point_id="$(printf '%02d' "$point")"
    label="$(crash_matrix_label_for_point "$point")"
    run_case "crash_matrix_${point_id}_${label}" run_crash_matrix_point "$point" "$label"
done

e2e_log "Cleanup is managed by scripts/e2e/lib.sh trap (EXIT)."
emit_junit
e2e_pass
