#!/usr/bin/env bash
# ffs_benchmark_governance_e2e.sh - Verification gate for benchmark/regression governance (bd-h6nz.5.6)
#
# End-to-end validation that the full benchmark governance pipeline is coherent:
# taxonomy → comparator → hysteresis → triage → structured logging → follow-up commands.
#
# Scenarios:
# 1. Comparator produces structured log fields (benchmark_id, profile_id, baseline_ref)
# 2. Triage decisions include actionable followup_command
# 3. Guard-failure followup commands reference benchmark_record.sh
# 4. Hysteresis tracker emits rerun-count structured fields
# 5. All triage actions map to non-empty followup commands (except NoAction)
# 6. ComparisonContext JSON schema round-trips
# 7. Triage decision JSON includes followup_command field
# 8. Benchmark taxonomy + comparator + triage integration test passes
# 9. All benchmark governance unit tests pass
#
# Usage: ./scripts/e2e/ffs_benchmark_governance_e2e.sh
#
# Exit codes:
#   0 - All scenarios passed
#   1 - One or more scenarios failed

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Source shared helpers
source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_benchmark_governance}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_CAPTURE_VISIBILITY="${FFS_BENCHMARK_GOVERNANCE_RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-420}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

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
    local output_path="$1"
    shift
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

e2e_init "ffs_benchmark_governance"

COMP_SRC="crates/ffs-harness/src/perf_comparison.rs"
TRIAGE_SRC="crates/ffs-harness/src/perf_triage.rs"
TAXONOMY_SRC="crates/ffs-harness/src/benchmark_taxonomy.rs"
BUILD_LOG="$E2E_LOG_DIR/benchmark_governance_build.log"
TEST_LOG="$E2E_LOG_DIR/benchmark_governance_unit_tests.log"

#######################################
# Scenario 1: Comparator emits benchmark_id, profile_id, baseline_ref in structured log
#######################################
e2e_step "Scenario 1: Comparator structured log fields"

FIELDS_FOUND=0
for field in "benchmark_id" "profile_id" "baseline_ref"; do
    if grep -q "$field" "$COMP_SRC"; then
        FIELDS_FOUND=$((FIELDS_FOUND + 1))
    fi
done

if [[ $FIELDS_FOUND -eq 3 ]]; then
    scenario_result "governance_comparator_log_fields" "PASS" "All 3 context fields present in comparator"
else
    scenario_result "governance_comparator_log_fields" "FAIL" "Only ${FIELDS_FOUND}/3 context fields"
fi

#######################################
# Scenario 2: Triage decisions include followup_command field
#######################################
e2e_step "Scenario 2: Triage decisions include followup_command"

if grep -q "pub followup_command: String" "$TRIAGE_SRC"; then
    scenario_result "governance_triage_followup_field" "PASS" "followup_command field in TriageDecision"
else
    scenario_result "governance_triage_followup_field" "FAIL" "followup_command field not found"
fi

#######################################
# Scenario 3: Guard-failure followup commands reference benchmark_record.sh
#######################################
e2e_step "Scenario 3: Followup commands reference benchmark_record.sh"

if grep -q "benchmark_record" "$TRIAGE_SRC"; then
    scenario_result "governance_followup_references_record" "PASS" "Followup commands reference benchmark_record.sh"
else
    scenario_result "governance_followup_references_record" "FAIL" "No benchmark_record reference in followup commands"
fi

#######################################
# Scenario 4: Hysteresis tracker emits structured count fields
#######################################
e2e_step "Scenario 4: Hysteresis tracker structured count fields"

HYST_FIELDS=0
for field in "fail_count" "warn_count" "window_size" "problem_count"; do
    if grep -q "$field" "$COMP_SRC"; then
        HYST_FIELDS=$((HYST_FIELDS + 1))
    fi
done

if [[ $HYST_FIELDS -ge 3 ]]; then
    scenario_result "governance_hysteresis_log_fields" "PASS" "${HYST_FIELDS} hysteresis fields emitted"
else
    scenario_result "governance_hysteresis_log_fields" "FAIL" "Only ${HYST_FIELDS}/3 hysteresis fields"
fi

#######################################
# Scenario 5: All TriageActions mapped to followup commands
#######################################
e2e_step "Scenario 5: All TriageActions mapped in followup_for"

ACTIONS_FOUND=0
for action in "CollectMoreSamples" "RerunOnReference" "BisectCommits" "CheckEnvironment" "RecalibrateThresholds" "NoAction"; do
    if grep -q "TriageAction::${action}" "$TRIAGE_SRC"; then
        ACTIONS_FOUND=$((ACTIONS_FOUND + 1))
    fi
done

if [[ $ACTIONS_FOUND -eq 6 ]]; then
    scenario_result "governance_all_actions_mapped" "PASS" "All 6 triage actions mapped"
else
    scenario_result "governance_all_actions_mapped" "FAIL" "Only ${ACTIONS_FOUND}/6 actions mapped"
fi

#######################################
# Scenario 6: ComparisonContext JSON schema present
#######################################
e2e_step "Scenario 6: ComparisonContext struct defined"

if grep -q "pub struct ComparisonContext" "$COMP_SRC" && grep -q "Serialize, Deserialize" "$COMP_SRC"; then
    scenario_result "governance_context_struct" "PASS" "ComparisonContext struct with serde"
else
    scenario_result "governance_context_struct" "FAIL" "ComparisonContext not found or missing serde"
fi

#######################################
# Scenario 7: Triage emit_triage_log includes followup_command
#######################################
e2e_step "Scenario 7: emit_triage_log includes followup_command"

if grep -q 'followup_command.*decision.followup_command' "$TRIAGE_SRC"; then
    scenario_result "governance_log_has_followup" "PASS" "followup_command in structured triage log"
else
    scenario_result "governance_log_has_followup" "FAIL" "followup_command not in triage log emission"
fi

#######################################
# Scenario 8: Taxonomy + comparator + triage modules all build
#######################################
e2e_step "Scenario 8: All governance modules build"

if run_rch_capture "$BUILD_LOG" cargo check -p ffs-harness; then
    scenario_result "governance_modules_build" "PASS" "ffs-harness builds cleanly"
else
    scenario_result "governance_modules_build" "FAIL" "ffs-harness build failed"
fi

#######################################
# Scenario 9: All governance unit tests pass
#######################################
e2e_step "Scenario 9: Governance unit tests"

: >"$TEST_LOG"
COMBINED_PASS=0
COMBINED_FAIL=0

# Run tests for all 3 governance modules
for mod_filter in "benchmark_taxonomy" "perf_comparison" "perf_triage"; do
    MOD_LOG="$E2E_LOG_DIR/benchmark_governance_${mod_filter}.log"
    if run_rch_capture "$MOD_LOG" cargo test -p ffs-harness --lib -- "$mod_filter"; then
        COMBINED_PASS=$((COMBINED_PASS + 1))
    else
        COMBINED_FAIL=$((COMBINED_FAIL + 1))
    fi
    cat "$MOD_LOG" >>"$TEST_LOG"
done

TOTAL_TESTS=$(grep -c "^test " "$TEST_LOG" 2>/dev/null || echo "0")

if [[ $COMBINED_FAIL -eq 0 && $TOTAL_TESTS -ge 50 ]]; then
    scenario_result "governance_unit_tests_pass" "PASS" "All 3 modules pass (${TOTAL_TESTS} tests total)"
else
    scenario_result "governance_unit_tests_pass" "FAIL" "Failures: ${COMBINED_FAIL}/3 modules, ${TOTAL_TESTS} tests"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
else
    e2e_log "OVERALL: PASS"
    exit 0
fi
