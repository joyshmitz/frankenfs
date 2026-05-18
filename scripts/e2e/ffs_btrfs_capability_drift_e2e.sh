#!/usr/bin/env bash
# ffs_btrfs_capability_drift_e2e.sh - Verification gate for btrfs capability drift detection (bd-h6nz.3.5)
#
# Validates that the FEATURE_PARITY.md btrfs capability contract table stays
# synchronized with actual unit test and E2E scenario coverage.
#
# Scenarios:
# 1. Drift detection module exists in ffs-harness
# 2. FEATURE_PARITY.md contains parseable unit:: contract rows
# 3. FEATURE_PARITY.md contains parseable e2e:: contract rows
# 4. check_unit_contract verifies fn existence in ffs-core
# 5. check_e2e_contract verifies scenario names in E2E scripts
# 6. parse_capability_table ignores non-contract rows
# 7. All unit contracts have corresponding test functions
# 8. All e2e contracts have corresponding scenario references
# 9. Btrfs capability drift unit tests pass
#
# Usage: ./scripts/e2e/ffs_btrfs_capability_drift_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_btrfs_capability_drift}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_CAPABILITY_DRIFT_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_BTRFS_CAPABILITY_DRIFT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_BTRFS_CAPABILITY_DRIFT_SKIP_SELF_CHECK:-0}"

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
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    shift

    e2e_log "RCH command: $*"
    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$log_path"
    set +e
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=$*"
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
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}|command=$*"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_BTRFS_CAPABILITY_DRIFT_FIXTURE_CASE:-complete}"

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
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown btrfs capability drift fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- btrfs_capability_drift"*)
        printf '%s\n' \
            "test btrfs_capability_drift::tests::parse_capability_table_extracts_rows ... ok" \
            "test btrfs_capability_drift::tests::btrfs_capability_drift_contract_json_shape ... ok" \
            "test btrfs_capability_drift::tests::all_documented_unit_contracts_have_test_functions ... ok" \
            "test btrfs_capability_drift::tests::all_documented_e2e_contracts_have_scenario_references ... ok" \
            "test btrfs_capability_drift::tests::full_drift_check_passes_for_repo ... ok" \
            "test btrfs_capability_drift::tests::parse_ignores_non_contract_rows ... ok"
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
    local child_log="$E2E_LOG_DIR/btrfs_capability_drift_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_BTRFS_CAPABILITY_DRIFT_SELF_CHECK=0 \
        FFS_BTRFS_CAPABILITY_DRIFT_SKIP_SELF_CHECK=1 \
        FFS_BTRFS_CAPABILITY_DRIFT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_btrfs_capability_drift_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic btrfs capability drift wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir test_log
    stub_path="$E2E_LOG_DIR/rch-btrfs-capability-drift-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    test_log="$result_dir/btrfs_capability_drift_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$test_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_unit_contracts_parseable" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_e2e_contracts_parseable" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_unit_checker_pattern" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_e2e_checker_stripping" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_parser_selectivity" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_unit_coverage_test" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_e2e_coverage_test" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_drift_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && [[ "$(grep -c "test btrfs_capability_drift::tests::" "$test_log" 2>/dev/null || echo 0)" -ge 5 ]]; then
        scenario_result "btrfs_drift_fixture_complete_self_check" "PASS" "result=${result_path} unit_log=${test_log}"
    else
        scenario_result "btrfs_drift_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Btrfs capability drift complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "btrfs_drift_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "btrfs_drift_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Btrfs capability drift local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "btrfs_drift_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "btrfs_drift_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Btrfs capability drift missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_btrfs_capability_drift"
e2e_print_env

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

DRIFT_SRC="crates/ffs-harness/src/btrfs_capability_drift.rs"
PARITY_MD="FEATURE_PARITY.md"

#######################################
# Scenario 1: Module exists
#######################################
e2e_step "Scenario 1: Drift detection module exists"

if [[ -f "$DRIFT_SRC" ]] && grep -q "pub mod btrfs_capability_drift" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "btrfs_drift_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "btrfs_drift_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: Unit contract rows parseable
#######################################
e2e_step "Scenario 2: FEATURE_PARITY.md has unit:: contract rows"

UNIT_COUNT=$(grep -c '`unit::' "$PARITY_MD" || echo "0")
if [[ $UNIT_COUNT -ge 15 ]]; then
    scenario_result "btrfs_drift_unit_contracts_parseable" "PASS" "${UNIT_COUNT} unit contracts found"
else
    scenario_result "btrfs_drift_unit_contracts_parseable" "FAIL" "Only ${UNIT_COUNT} unit contracts (expected >= 15)"
fi

#######################################
# Scenario 3: E2E contract rows parseable
#######################################
e2e_step "Scenario 3: FEATURE_PARITY.md has e2e:: contract rows"

E2E_COUNT=$(grep -c '`e2e::' "$PARITY_MD" || echo "0")
if [[ $E2E_COUNT -ge 10 ]]; then
    scenario_result "btrfs_drift_e2e_contracts_parseable" "PASS" "${E2E_COUNT} e2e contracts found"
else
    scenario_result "btrfs_drift_e2e_contracts_parseable" "FAIL" "Only ${E2E_COUNT} e2e contracts (expected >= 10)"
fi

#######################################
# Scenario 4: Unit contract checker uses fn pattern
#######################################
e2e_step "Scenario 4: check_unit_contract verifies tokenized fn existence"

if grep -q 'pub fn check_unit_contract' "$DRIFT_SRC" \
    && grep -q 'CodeToken::Ident("fn")' "$DRIFT_SRC" \
    && grep -q 'function_name == bare_name' "$DRIFT_SRC" \
    && grep -q "CodeToken::Symbol('(' | '<')" "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_unit_checker_pattern" "PASS" "Unit checker tokenizes fn declarations"
else
    scenario_result "btrfs_drift_unit_checker_pattern" "FAIL" "Unit checker tokenized fn pattern not found"
fi

#######################################
# Scenario 5: E2E contract checker with progressive stripping
#######################################
e2e_step "Scenario 5: check_e2e_contract verifies scenario names"

if grep -q 'pub fn check_e2e_contract' "$DRIFT_SRC" \
    && grep -q 'split_once("_rw_")' "$DRIFT_SRC" \
    && grep -q 'strip_prefix("crash_matrix_")' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_e2e_checker_stripping" "PASS" "E2E checker uses rw-prefix and crash-matrix stripping"
else
    scenario_result "btrfs_drift_e2e_checker_stripping" "FAIL" "E2E checker stripping logic not found"
fi

#######################################
# Scenario 6: Parser ignores non-contract rows
#######################################
e2e_step "Scenario 6: Parser ignores non-contract rows"

if grep -q 'parse_ignores_non_contract_rows' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_parser_selectivity" "PASS" "Selectivity test present"
else
    scenario_result "btrfs_drift_parser_selectivity" "FAIL" "No selectivity test"
fi

#######################################
# Scenario 7: Unit contracts have test functions
#######################################
e2e_step "Scenario 7: All unit contracts have test functions in ffs-core"

if grep -q 'all_documented_unit_contracts_have_test_functions' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_unit_coverage_test" "PASS" "Unit coverage assertion test present"
else
    scenario_result "btrfs_drift_unit_coverage_test" "FAIL" "Unit coverage assertion test missing"
fi

#######################################
# Scenario 8: E2E contracts have scenario references
#######################################
e2e_step "Scenario 8: All e2e contracts have scenario references"

if grep -q 'all_documented_e2e_contracts_have_scenario_references' "$DRIFT_SRC"; then
    scenario_result "btrfs_drift_e2e_coverage_test" "PASS" "E2E coverage assertion test present"
else
    scenario_result "btrfs_drift_e2e_coverage_test" "FAIL" "E2E coverage assertion test missing"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Btrfs capability drift unit tests"

TEST_LOG="$E2E_LOG_DIR/btrfs_capability_drift_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- btrfs_capability_drift; then
    TESTS_RUN=$(grep -c "test btrfs_capability_drift::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 5 ]]; then
        scenario_result "btrfs_drift_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "btrfs_drift_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 5)"
    fi
else
    scenario_result "btrfs_drift_unit_tests_pass" "FAIL" "Drift detection tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
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
