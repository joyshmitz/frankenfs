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
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_SELF_HEALING_DEMO_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_SELF_HEALING_DEMO_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_SELF_HEALING_DEMO_SKIP_SELF_CHECK:-0}"

for arg in "$@"; do
    case "$arg" in
        --rch) ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

e2e_rch_add_env_allowlist CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE

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

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_SELF_HEALING_DEMO_FIXTURE_CASE:-complete}"

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
        echo "unknown self-healing demo fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-repair --test self_healing_demo_e2e -- --nocapture"*)
        printf '%s\n' \
            "test demo_binary_runs_via_self_healing_command ... ok" \
            "test demo_output_has_six_structured_lines ... ok" \
            "test demo_zero_data_loss_default_config ... ok" \
            "test demo_zero_data_loss_five_percent_corruption ... ok" \
            "test demo_completes_within_30_seconds ... ok" \
            "test demo_deterministic_with_fixed_seed ... ok" \
            "test demo_evidence_ledger_captures_repair_lifecycle ... ok" \
            "test demo_output_lines_contain_expected_metrics ... ok"
        ;;
    *"cargo run -p ffs-repair --bin ffs-demo -- self-healing"*)
        printf '%s\n' \
            "demo start: image_size=1048576B file_count=8 corruption_pct=2 seed=0x00000000f5f5f5f5" \
            "image created: wrote 8 payload files across 16 source blocks" \
            "corruption injected: blocks_corrupted=2 pct=2" \
            "repair complete: blocks_repaired=2 duration_ms=12" \
            "verification: files_verified=8 all_ok=true" \
            "demo result: PASS"
        ;;
    *"cargo test -p ffs-repair demo::tests::demo_output_has_expected_shape -- --nocapture"*)
        printf '%s\n' "test demo::tests::demo_output_has_expected_shape ... ok"
        ;;
    *"cargo test -p ffs-repair --test self_heal_demo -- --nocapture"*)
        printf '%s\n' "test self_heal_demo_repairs_and_verifies_all_payloads ... ok"
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
    local child_log="$E2E_LOG_DIR/self_healing_demo_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_SELF_HEALING_DEMO_SELF_CHECK=0 \
        FFS_SELF_HEALING_DEMO_SKIP_SELF_CHECK=1 \
        FFS_SELF_HEALING_DEMO_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_self_healing_demo.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic self-healing demo wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir e2e_log_path binary_log unit_log integration_log
    stub_path="$E2E_LOG_DIR/rch-self-healing-demo-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    e2e_log_path="$result_dir/self_healing_demo_e2e.log"
    binary_log="$result_dir/ffs_demo_binary.log"
    unit_log="$result_dir/demo_unit_shape.log"
    integration_log="$result_dir/self_heal_demo_integration.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$e2e_log_path" ]] \
        && [[ -f "$binary_log" ]] \
        && [[ -f "$unit_log" ]] \
        && [[ -f "$integration_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "self_healing_demo_e2e_suite" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "self_healing_demo_binary_command" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "self_healing_demo_unit_shape" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "self_healing_demo_basic_integration" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "demo_evidence_ledger_captures_repair_lifecycle" "$e2e_log_path" \
        && grep -q "demo result: PASS" "$binary_log" \
        && grep -q "demo_output_has_expected_shape" "$unit_log" \
        && grep -q "self_heal_demo_repairs_and_verifies_all_payloads" "$integration_log"; then
        scenario_result "self_healing_demo_fixture_complete_self_check" "PASS" "result=${result_path} e2e_log=${e2e_log_path}"
    else
        scenario_result "self_healing_demo_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Self-healing demo complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "self_healing_demo_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "self_healing_demo_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Self-healing demo local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "self_healing_demo_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "self_healing_demo_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Self-healing demo missing remote evidence fixture self-check failed"
    fi
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

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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
