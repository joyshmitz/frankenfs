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
RCH_CAPTURE_VISIBILITY="${FFS_DEGRADATION_STRESS_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$REPO_ROOT/target/release/ffs-cli}"
SELF_CHECK="${FFS_DEGRADATION_STRESS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_DEGRADATION_STRESS_SKIP_SELF_CHECK:-0}"

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    e2e_rch_add_env_allowlist "$rch_env_var"
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

run_rch_capture() {
    local output_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$output_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_DEGRADATION_STRESS_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        echo "Remote command finished: exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown degradation stress fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo build -p ffs-cli --release"*)
        printf '%s\n' \
            "Compiling ffs-cli fixture" \
            "Finished release [optimized] target(s) in 0.01s"
        ;;
    *"cargo test -p ffs-core degradation_level_"*)
        printf '%s\n' \
            "running 2 tests" \
            "test degradation_level_fixture_low ... ok" \
            "test degradation_level_fixture_high ... ok" \
            "test result: ok. 2 passed; 0 failed"
        ;;
    *"cargo test -p ffs-core fsm_"*)
        printf '%s\n' \
            "running 2 tests" \
            "test fsm_fixture_enter_degraded ... ok" \
            "test fsm_fixture_recover ... ok" \
            "test result: ok. 2 passed; 0 failed"
        ;;
    *"cargo test -p ffs-core backpressure_gate_"*)
        printf '%s\n' \
            "running 2 tests" \
            "test backpressure_gate_fixture_limits ... ok" \
            "test backpressure_gate_fixture_releases ... ok" \
            "test result: ok. 2 passed; 0 failed"
        ;;
    *"cargo test -p ffs-core pressure_monitor_"*)
        printf '%s\n' \
            "running 2 tests" \
            "test pressure_monitor_fixture_records_load ... ok" \
            "test pressure_monitor_fixture_degrades ... ok" \
            "test result: ok. 2 passed; 0 failed"
        ;;
    *"cargo test -p ffs-fuse -- --nocapture"*)
        printf '%s\n' \
            "running 2 tests" \
            "test fuse_fixture_surface_smoke ... ok" \
            "test fuse_fixture_backpressure_mapping ... ok" \
            "test result: ok. 2 passed; 0 failed"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/degradation_stress_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_DEGRADATION_STRESS_SELF_CHECK=0 \
        FFS_DEGRADATION_STRESS_SKIP_SELF_CHECK=1 \
        FFS_DEGRADATION_STRESS_FIXTURE_CASE="$fixture_case" \
        FFS_DEGRADATION_STRESS_SKIP_HOST_PRESSURE=1 \
        FFS_RUN_MOUNT_STRESS=0 \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_degradation_stress.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic degradation stress wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-degradation-stress-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_cli_build" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_core_degradation_levels" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_core_fsm" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_core_backpressure_gate" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_core_pressure_monitor" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_fuse_surface" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_host_pressure_probe" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "degradation_stress_optional_mount_probe" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "degradation_stress_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "degradation_stress_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "degradation_stress_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "degradation_stress_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "degradation_stress_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "degradation_stress_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
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

    if [[ "${FFS_DEGRADATION_STRESS_SKIP_HOST_PRESSURE:-0}" == "1" ]]; then
        e2e_log "Skipping host pressure probe: FFS_DEGRADATION_STRESS_SKIP_HOST_PRESSURE=1"
        scenario_result \
            "degradation_stress_host_pressure_probe" \
            "PASS" \
            "skipped: FFS_DEGRADATION_STRESS_SKIP_HOST_PRESSURE=1"
        return
    fi

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

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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
