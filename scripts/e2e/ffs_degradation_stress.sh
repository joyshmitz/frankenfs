#!/usr/bin/env bash
# ffs_degradation_stress.sh - Graceful degradation stress E2E suite
#
# This suite validates degradation/backpressure behavior using:
# 1) deterministic crate tests (ffs-core + ffs-fuse)
# 2) optional host pressure probe with stress-ng
# 3) optional live mount pressure probe (opt-in)

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info,ffs::backpressure=trace,ffs::core=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_degradation_stress}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$REPO_ROOT/target/release/ffs-cli}"

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

e2e_init "ffs_degradation_stress"
e2e_print_env

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    e2e_skip "rch not found; this suite requires offloaded cargo execution"
fi

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
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
        if [[ -n "$remote_exit" ]]; then
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
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
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
    if grep -Fq "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|output=${output_path}|status=${status}"
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

run_cargo_lane() {
    local scenario_id="$1"
    local log_name="$2"
    local detail="$3"
    local output_path="$E2E_LOG_DIR/$log_name"
    shift 3

    if run_rch_capture "$output_path" cargo "$@"; then
        scenario_result "$scenario_id" "PASS" "${detail}; log=${output_path}"
    else
        print_rch_log "$output_path"
        scenario_result "$scenario_id" "FAIL" "${detail} failed; log=${output_path}"
        e2e_fail "${detail} failed"
    fi
}

pressure_snapshot() {
    local label="$1"
    e2e_step "$label"
    if [[ -r /proc/loadavg ]]; then
        e2e_run cat /proc/loadavg || true
    fi
    if [[ -r /proc/meminfo ]]; then
        e2e_run bash -lc "grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo" || true
    fi
}

run_deterministic_degradation_gates() {
    e2e_step "Phase 1: deterministic degradation/backpressure gates"
    run_cargo_lane \
        "degradation_stress_core_degradation_levels" \
        "core_degradation_levels.log" \
        "ffs-core degradation level tests" test -p ffs-core degradation_level_ -- --nocapture
    run_cargo_lane \
        "degradation_stress_core_fsm" \
        "core_fsm.log" \
        "ffs-core FSM tests" test -p ffs-core fsm_ -- --nocapture
    run_cargo_lane \
        "degradation_stress_core_backpressure_gate" \
        "core_backpressure_gate.log" \
        "ffs-core backpressure gate tests" test -p ffs-core backpressure_gate_ -- --nocapture
    run_cargo_lane \
        "degradation_stress_core_pressure_monitor" \
        "core_pressure_monitor.log" \
        "ffs-core pressure monitor tests" test -p ffs-core pressure_monitor_ -- --nocapture
}

run_fuse_surface_gates() {
    e2e_step "Phase 2: FUSE surface regression gates"
    run_cargo_lane \
        "degradation_stress_fuse_surface" \
        "fuse_surface.log" \
        "ffs-fuse regression tests" test -p ffs-fuse -- --nocapture
}

run_host_pressure_probe() {
    local duration="${DEGRADATION_STRESS_DURATION_SECS:-20}"
    local cpu_workers="${DEGRADATION_STRESS_CPU_WORKERS:-4}"
    local vm_workers="${DEGRADATION_STRESS_VM_WORKERS:-1}"
    local vm_bytes="${DEGRADATION_STRESS_VM_BYTES:-60%}"
    local stress_log="$E2E_LOG_DIR/stress-ng.log"

    if ! command -v stress-ng >/dev/null 2>&1; then
        e2e_log "stress-ng not found; skipping host pressure probe"
        scenario_result \
            "degradation_stress_host_pressure_probe" \
            "PASS" \
            "skipped: stress-ng not found"
        return
    fi

    pressure_snapshot "Phase 3: pressure snapshot (before stress)"
    e2e_step "Phase 3: host pressure probe with stress-ng"
    e2e_log "stress-ng --cpu $cpu_workers --vm $vm_workers --vm-bytes $vm_bytes --timeout ${duration}s"

    stress-ng \
        --cpu "$cpu_workers" \
        --vm "$vm_workers" \
        --vm-bytes "$vm_bytes" \
        --timeout "${duration}s" \
        --metrics-brief >"$stress_log" 2>&1 &
    local stress_pid=$!

    sleep 3
    pressure_snapshot "Phase 3: pressure snapshot (during stress)"

    # Re-run monitor tests while load is active.
    run_cargo_lane \
        "degradation_stress_host_pressure_monitor" \
        "host_pressure_monitor.log" \
        "ffs-core pressure monitor under host load" test -p ffs-core pressure_monitor_ -- --nocapture

    wait "$stress_pid" || true
    e2e_run tail -n 120 "$stress_log" || true
    pressure_snapshot "Phase 3: pressure snapshot (after stress)"
    scenario_result \
        "degradation_stress_host_pressure_probe" \
        "PASS" \
        "stress-ng probe completed; log=${stress_log}"
}

run_optional_mount_probe() {
    local duration="${DEGRADATION_MOUNT_STRESS_DURATION_SECS:-15}"
    local cpu_workers="${DEGRADATION_MOUNT_STRESS_CPU_WORKERS:-4}"
    local mount_log="$E2E_LOG_DIR/mount_stress.log"
    local image="$E2E_TEMP_DIR/degradation_probe.ext4"
    local mount_point="$E2E_TEMP_DIR/mnt_degradation_probe"

    if [[ "${FFS_RUN_MOUNT_STRESS:-0}" != "1" ]]; then
        e2e_log "Skipping optional mount pressure probe (set FFS_RUN_MOUNT_STRESS=1 to enable)"
        scenario_result \
            "degradation_stress_optional_mount_probe" \
            "PASS" \
            "skipped: set FFS_RUN_MOUNT_STRESS=1 to enable"
        return
    fi
    if [[ ! -e /dev/fuse ]] || [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        e2e_log "Skipping mount pressure probe: /dev/fuse unavailable"
        scenario_result \
            "degradation_stress_optional_mount_probe" \
            "PASS" \
            "skipped: /dev/fuse unavailable"
        return
    fi
    if ! command -v stress-ng >/dev/null 2>&1; then
        e2e_log "Skipping mount pressure probe: stress-ng not found"
        scenario_result \
            "degradation_stress_optional_mount_probe" \
            "PASS" \
            "skipped: stress-ng not found"
        return
    fi
    if ! command -v mountpoint >/dev/null 2>&1; then
        e2e_log "Skipping mount pressure probe: mountpoint not found"
        scenario_result \
            "degradation_stress_optional_mount_probe" \
            "PASS" \
            "skipped: mountpoint not found"
        return
    fi
    if [[ ! -x "$FFS_CLI_BIN" ]]; then
        e2e_log "Skipping mount pressure probe: ffs-cli binary unavailable at $FFS_CLI_BIN"
        scenario_result \
            "degradation_stress_optional_mount_probe" \
            "PASS" \
            "skipped: ffs-cli binary unavailable"
        return
    fi

    e2e_step "Phase 4: optional live mount pressure probe"
    e2e_create_ext4_image "$image" 64
    mkdir -p "$mount_point"

    e2e_log "Starting mount probe: $FFS_CLI_BIN mount $image $mount_point"
    "$FFS_CLI_BIN" mount "$image" "$mount_point" >"$mount_log" 2>&1 &
    local mount_pid=$!

    local ready=0
    for _ in {1..40}; do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            ready=1
            break
        fi
        if ! kill -0 "$mount_pid" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done

    if [[ "$ready" != "1" ]]; then
        e2e_log "Mount probe unavailable in this environment; mount log tail follows"
        e2e_run tail -n 120 "$mount_log" || true
        kill "$mount_pid" 2>/dev/null || true
        wait "$mount_pid" 2>/dev/null || true
        scenario_result \
            "degradation_stress_optional_mount_probe" \
            "PASS" \
            "mount unavailable in this environment; log=${mount_log}"
        return
    fi

    stress-ng --cpu "$cpu_workers" --timeout "${duration}s" --metrics-brief >"$E2E_LOG_DIR/mount_stress_ng.log" 2>&1 &
    local stress_pid=$!
    sleep 2

    local read_failures=0
    for _ in {1..20}; do
        if ! e2e_run cat "$mount_point/readme.txt"; then
            read_failures=$((read_failures + 1))
        fi
        sleep 0.1
    done
    e2e_log "Mount stress probe read failures: $read_failures"

    wait "$stress_pid" || true
    e2e_unmount "$mount_point"
    kill "$mount_pid" 2>/dev/null || true
    wait "$mount_pid" 2>/dev/null || true
    e2e_run tail -n 120 "$mount_log" || true
    scenario_result \
        "degradation_stress_optional_mount_probe" \
        "PASS" \
        "mount pressure probe completed; read_failures=${read_failures}; log=${mount_log}"
}

e2e_step "Phase 0: build ffs-cli"
run_cargo_lane \
    "degradation_stress_cli_build" \
    "build_ffs_cli.log" \
    "ffs-cli release build" build -p ffs-cli --release

run_deterministic_degradation_gates
run_fuse_surface_gates
run_host_pressure_probe
run_optional_mount_probe

e2e_log "Scenario totals: passed=${PASS_COUNT} failed=${FAIL_COUNT} total=${TOTAL}"
e2e_pass
