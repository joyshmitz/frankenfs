#!/usr/bin/env bash
# ffs_self_healing_demo.sh - E2E test: self-healing demo runs and produces correct output
#
# Validates:
#   1. Demo runs successfully (exit code 0)
#   2. Structured output lines present (6 lines: start, created, injected, repaired, verified, PASS)
#   3. Zero data loss: corrupted_blocks == repaired_blocks
#   4. Evidence ledger integration (write + parse round-trip)
#   5. Completes within 30 seconds
#   6. Deterministic with fixed seed
#
# Usage:
#   ./scripts/e2e/ffs_self_healing_demo.sh [--rch]

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_self_healing_demo}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

for arg in "$@"; do
    case "$arg" in
        --rch) ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

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

run_demo_lane() {
    local scenario_id="$1"
    local output_path="$2"
    local detail="$3"
    shift 3

    if run_rch_capture "$output_path" "$@"; then
        scenario_result "$scenario_id" "PASS" "${detail}; log=${output_path}"
    else
        print_rch_log "$output_path"
        scenario_result "$scenario_id" "FAIL" "${detail} failed; log=${output_path}"
        e2e_fail "${detail} failed"
    fi
}

e2e_init "ffs_self_healing_demo"
e2e_print_env

# ── Phase 1: prerequisites ───────────────────────────────────────────────────

e2e_step "Phase 1: prerequisites"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    e2e_skip "rch not found; this test requires offloaded cargo execution"
fi

# Verify the demo test exists
DEMO_TEST_FILE="$REPO_ROOT/crates/ffs-repair/tests/self_healing_demo_e2e.rs"
e2e_assert_file "$DEMO_TEST_FILE"

# Verify the demo module exists
DEMO_MODULE="$REPO_ROOT/crates/ffs-repair/src/demo.rs"
e2e_assert_file "$DEMO_MODULE"

# ── Phase 2: run self-healing demo E2E tests ─────────────────────────────────

e2e_step "Phase 2: run self-healing demo E2E test suite"

run_demo_lane \
    "self_healing_demo_e2e_suite" \
    "$E2E_LOG_DIR/self_healing_demo_e2e.log" \
    "self-healing demo E2E suite" cargo test -p ffs-repair --test self_healing_demo_e2e -- --nocapture

# ── Phase 3: verify single-command binary path ───────────────────────────────

e2e_step "Phase 3: verify ffs-demo binary command"

run_demo_lane \
    "self_healing_demo_binary_command" \
    "$E2E_LOG_DIR/ffs_demo_binary.log" \
    "ffs-demo self-healing binary command" cargo run -p ffs-repair --bin ffs-demo -- self-healing

# ── Phase 4: run existing unit-level demo test ───────────────────────────────

e2e_step "Phase 4: run demo unit test"

run_demo_lane \
    "self_healing_demo_unit_shape" \
    "$E2E_LOG_DIR/demo_unit_shape.log" \
    "demo output shape unit test" cargo test -p ffs-repair demo::tests::demo_output_has_expected_shape -- --nocapture

# ── Phase 5: run basic integration test ──────────────────────────────────────

e2e_step "Phase 5: run basic integration test"

run_demo_lane \
    "self_healing_demo_basic_integration" \
    "$E2E_LOG_DIR/self_heal_demo_integration.log" \
    "basic self-heal demo integration test" cargo test -p ffs-repair --test self_heal_demo -- --nocapture

# ── Phase 6: summary ────────────────────────────────────────────────────────

e2e_step "Phase 6: summary"
e2e_log "All self-healing demo E2E tests passed:"
e2e_log "  - Output structure: 6 structured lines with expected prefixes"
e2e_log "  - Zero data loss: corrupted_blocks == repaired_blocks (2% and 5%)"
e2e_log "  - Timing: completes within 30 seconds"
e2e_log "  - Determinism: fixed seed produces identical results"
e2e_log "  - Evidence ledger: corruption/repair lifecycle captured and parsed"
e2e_log "  - Metrics parsing: output lines contain expected config values"
e2e_log "Scenario totals: passed=${PASS_COUNT} failed=${FAIL_COUNT} total=${TOTAL}"

e2e_pass
