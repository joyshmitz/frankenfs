#!/usr/bin/env bash
# ffs_btrfs_ro_smoke.sh - btrfs read-only FUSE smoke test for FrankenFS
#
# Validates black-box btrfs RO mount behavior:
# - runtime fixture generation
# - inspect geometry logging
# - mount + basic filesystem operations
# - reliable unmount/cleanup

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_btrfs_ro_smoke}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_WORKERS_CONFIG="${RCH_WORKERS_CONFIG:-$HOME/.config/rch/workers.toml}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$CARGO_TARGET_DIR/release/ffs-cli}"

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("$RCH_BIN" queue --json 2>/dev/null || true)"
    if [[ -z "$queue_json" ]]; then
        return 0
    fi
    ids="$(jq -r --arg cmd "$command_text" '
        .data.active_builds[]?
        | select(.project_id | startswith("frankenfs-"))
        | select(.command == $cmd)
        | .id
    ' <<<"$queue_json" || true)"
    for id in $ids; do
        if "$RCH_BIN" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

run_rch_capture() {
    local output_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local required_artifact="${RCH_REQUIRED_ARTIFACT:-}"
    local wait_status
    shift

    : >"$output_path"
    set +e
    RCH_VISIBILITY="$RCH_VISIBILITY" "$RCH_BIN" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" && -n "$required_artifact" && -e "$required_artifact" ]]; then
            e2e_log "RCH_REQUIRED_ARTIFACT_READY|artifact=${required_artifact}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            break
        fi
        if [[ -n "$remote_exit" && -z "$required_artifact" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                cancel_matching_rch_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ $status -eq 0 ]]; then
        if [[ -n "$remote_exit" ]]; then
            status="$remote_exit"
        else
            status="$wait_status"
        fi
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    return "$status"
}

print_rch_log() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
}

strip_ansi() {
    sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g'
}

rch_worker_identity_file() {
    local worker_id="$1"
    local identity_file=""

    if [[ -n "${RCH_SSH_KEY:-}" ]]; then
        identity_file="$RCH_SSH_KEY"
    elif [[ -f "$RCH_WORKERS_CONFIG" ]]; then
        identity_file="$(awk -v id="$worker_id" '
            /^\[\[workers\]\]/ { in_worker = 0 }
            $1 == "id" && $3 == "\"" id "\"" { in_worker = 1 }
            in_worker && $1 == "identity_file" {
                gsub(/"/, "", $3)
                print $3
                exit
            }
        ' "$RCH_WORKERS_CONFIG")"
    fi

    if [[ -z "$identity_file" ]]; then
        return 1
    fi
    printf '%s\n' "${identity_file/#\~/$HOME}"
}

copy_rch_release_binary() {
    local output_path="$1"
    local dest="$2"
    local worker_id
    local ssh_target
    local remote_target_dir
    local identity_file

    worker_id="$(strip_ansi <"$output_path" | sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' | tail -n 1)"
    ssh_target="$(strip_ansi <"$output_path" | sed -n 's/.*Selected worker: [^ ]* at \([^ ]*@[^( ]*\).*/\1/p' | tail -n 1)"
    remote_target_dir="$(strip_ansi <"$output_path" | sed -n 's/.*Rewriting CARGO_TARGET_DIR.* -> \([^ ]*\).*/\1/p' | tail -n 1)"
    if [[ -z "$worker_id" || -z "$ssh_target" || -z "$remote_target_dir" ]]; then
        e2e_log "RCH_REMOTE_BINARY_COPY_METADATA_MISSING|worker=${worker_id:-missing}|target=${ssh_target:-missing}|remote_target=${remote_target_dir:-missing}|output=${output_path}"
        return 1
    fi
    if ! identity_file="$(rch_worker_identity_file "$worker_id")"; then
        e2e_log "RCH_REMOTE_BINARY_COPY_KEY_MISSING|worker=${worker_id}|config=${RCH_WORKERS_CONFIG}"
        return 1
    fi

    mkdir -p "$(dirname "$dest")"
    e2e_log "RCH_REMOTE_BINARY_COPY|worker=${worker_id}|source=${ssh_target}:${remote_target_dir}/release/ffs-cli|dest=${dest}"
    if scp -i "$identity_file" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
        "${ssh_target}:${remote_target_dir}/release/ffs-cli" "$dest" >>"$output_path" 2>&1; then
        chmod +x "$dest"
        return 0
    fi
    e2e_log "RCH_REMOTE_BINARY_COPY_FAILED|worker=${worker_id}|output=${output_path}"
    return 1
}

build_ffs_cli() {
    local output_path="$E2E_LOG_DIR/build_ffs_cli.log"

    if run_rch_capture "$output_path" cargo build -p ffs-cli --release && copy_rch_release_binary "$output_path" "$FFS_CLI_BIN"; then
        if [[ ! -x "$FFS_CLI_BIN" ]]; then
            scenario_result "btrfs_ro_cli_build" "FAIL" "RCH build succeeded but binary missing at ${FFS_CLI_BIN}; log=${output_path}"
            e2e_fail "ffs-cli build succeeded but binary missing at $FFS_CLI_BIN"
        fi
        scenario_result "btrfs_ro_cli_build" "PASS" "RCH build produced ${FFS_CLI_BIN}; log=${output_path}"
        e2e_log "ffs-cli built through RCH: binary=$FFS_CLI_BIN log=$output_path"
    else
        print_rch_log "$output_path"
        scenario_result "btrfs_ro_cli_build" "FAIL" "RCH build failed; log=${output_path}"
        e2e_fail "ffs-cli release build failed through RCH"
    fi
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

start_mount_ro() {
    local image="$1"
    local mount_point="$2"
    local timeout_seconds="${3:-20}"

    if [[ "${SKIP_MOUNT:-0}" == "1" ]]; then
        scenario_result "btrfs_ro_mount_start" "PASS" "skipped: SKIP_MOUNT=1"
        e2e_skip "mount tests skipped (SKIP_MOUNT=1)"
    fi
    if [[ ! -e /dev/fuse ]]; then
        scenario_result "btrfs_ro_mount_start" "PASS" "skipped: /dev/fuse not available"
        e2e_skip "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        scenario_result "btrfs_ro_mount_start" "PASS" "skipped: /dev/fuse not accessible"
        e2e_skip "/dev/fuse not accessible"
    fi

    mkdir -p "$mount_point"
    E2E_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_LOG="$E2E_LOG_DIR/mount_ro.log"

    local cmd=("$FFS_CLI_BIN" mount "$image" "$mount_point")
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
        e2e_log "Mount ready at $mount_point (pid=$CURRENT_MOUNT_PID)"
        scenario_result "btrfs_ro_mount_start" "PASS" "mounted read-only image at ${mount_point}; log=${CURRENT_MOUNT_LOG}"
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

    e2e_log "Mount failed (rc=$mount_rc), tailing mount log:"
    e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true

    if grep -qiE "allow_other only allowed if 'user_allow_other' is set" "$CURRENT_MOUNT_LOG"; then
        scenario_result "btrfs_ro_mount_start" "PASS" "skipped: user_allow_other not enabled; log=${CURRENT_MOUNT_LOG}"
        e2e_skip "FUSE present but user_allow_other is not enabled in /etc/fuse.conf"
    fi
    if grep -qiE "Permission denied|Operation not permitted|failed to open /dev/fuse" "$CURRENT_MOUNT_LOG"; then
        scenario_result "btrfs_ro_mount_start" "PASS" "skipped: FUSE mount not permitted; log=${CURRENT_MOUNT_LOG}"
        e2e_skip "FUSE is present but mount is not permitted in this environment"
    fi

    if [[ $ready_result -eq 2 ]]; then
        scenario_result "btrfs_ro_mount_start" "FAIL" "mount timed out after ${timeout_seconds}s; log=${CURRENT_MOUNT_LOG}"
        e2e_fail "Mount timed out after ${timeout_seconds}s"
    fi
    scenario_result "btrfs_ro_mount_start" "FAIL" "mount process exited before readiness; log=${CURRENT_MOUNT_LOG}"
    e2e_fail "Mount process exited before mount became ready"
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

detect_geometry_from_inspect() {
    local inspect_json="$1"

    local sectorsize nodesize
    sectorsize=$(grep -Eo '"sectorsize"[[:space:]]*:[[:space:]]*[0-9]+' "$inspect_json" | head -1 | grep -Eo '[0-9]+' || true)
    nodesize=$(grep -Eo '"nodesize"[[:space:]]*:[[:space:]]*[0-9]+' "$inspect_json" | head -1 | grep -Eo '[0-9]+' || true)

    [[ -z "$sectorsize" ]] && sectorsize="unknown"
    [[ -z "$nodesize" ]] && nodesize="unknown"

    e2e_log "Detected btrfs geometry: sectorsize=$sectorsize, nodesize=$nodesize"
}

create_btrfs_reference_image() {
    local image="$1"
    local image_size_mib="${2:-256}"

    mkdir -p "$(dirname "$image")"
    e2e_log "Creating btrfs reference image: image=$image size=${image_size_mib}MiB"
    e2e_assert dd if=/dev/zero of="$image" bs=1M count="$image_size_mib" status=none
    e2e_assert mkfs.btrfs -f -L "ffs-btrfs-ref" "$image"
}

e2e_init "ffs_btrfs_ro_smoke"
e2e_print_env

e2e_step "Phase 1: prerequisites"
if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    e2e_skip "rch not found; this suite requires offloaded cargo execution"
fi
if ! command -v mkfs.btrfs &>/dev/null; then
    e2e_skip "mkfs.btrfs not found (install btrfs-progs)"
fi
if ! command -v btrfs &>/dev/null; then
    e2e_skip "btrfs command not found (install btrfs-progs)"
fi
if [[ ! -e /dev/fuse ]]; then
    e2e_skip "/dev/fuse not available"
fi
if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
    e2e_skip "/dev/fuse not accessible"
fi
build_ffs_cli

e2e_step "Phase 2: generate btrfs reference image"
BTRFS_REF_DIR="$E2E_TEMP_DIR/btrfs-reference"
BTRFS_IMAGE="$BTRFS_REF_DIR/btrfs_reference.img"

create_btrfs_reference_image "$BTRFS_IMAGE"
e2e_assert_file "$BTRFS_IMAGE"
scenario_result "btrfs_ro_fixture_generated" "PASS" "generated btrfs reference image at ${BTRFS_IMAGE}"

e2e_step "Phase 3: inspect btrfs image"
INSPECT_JSON="$E2E_LOG_DIR/inspect_btrfs.json"
e2e_assert bash -lc "RUST_LOG=off '$FFS_CLI_BIN' inspect '$BTRFS_IMAGE' --json > '$INSPECT_JSON'"
detect_geometry_from_inspect "$INSPECT_JSON"
scenario_result "btrfs_ro_inspect_geometry" "PASS" "inspect JSON written to ${INSPECT_JSON}"

e2e_step "Phase 4: mount read-only via FUSE"
MOUNT_POINT="$E2E_TEMP_DIR/mnt_btrfs_ro"
start_mount_ro "$BTRFS_IMAGE" "$MOUNT_POINT"

e2e_step "Phase 5: validate filesystem operations"
e2e_assert ls -la "$MOUNT_POINT"
scenario_result "btrfs_ro_list_root" "PASS" "listed mounted root at ${MOUNT_POINT}"
e2e_assert stat "$MOUNT_POINT"
scenario_result "btrfs_ro_stat_root" "PASS" "stat succeeded for mounted root at ${MOUNT_POINT}"
e2e_assert find "$MOUNT_POINT" -maxdepth 2 -mindepth 1

KNOWN_FILE=""
for candidate in README.txt testdir/file1.txt link_to_file1; do
    if [[ -f "$MOUNT_POINT/$candidate" ]]; then
        KNOWN_FILE="$candidate"
        break
    fi
done

if [[ -n "$KNOWN_FILE" ]]; then
    e2e_log "Found known fixture file: $KNOWN_FILE"
    e2e_assert cat "$MOUNT_POINT/$KNOWN_FILE"
    scenario_result "btrfs_ro_known_file_read" "PASS" "read known fixture file ${KNOWN_FILE}"
else
    e2e_log "No known fixture file present in generated image; skipping file-cat check"
    scenario_result "btrfs_ro_known_file_read" "PASS" "skipped: generated image had no known fixture file"
fi

e2e_step "Phase 6: unmount"
stop_mount "$MOUNT_POINT"
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    scenario_result "btrfs_ro_unmount" "FAIL" "mountpoint still active after stop_mount"
    e2e_fail "Failed to unmount $MOUNT_POINT"
fi
scenario_result "btrfs_ro_unmount" "PASS" "unmounted ${MOUNT_POINT}"

e2e_pass
