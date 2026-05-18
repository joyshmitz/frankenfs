#!/usr/bin/env bash
# ffs_verification_gate_e2e.sh - Final acceptance gate for verification contract (bd-h6nz.9.5)
#
# Validates that:
# 1. All verification toolchain unit tests pass (artifact_manifest, log_contract, verification_runner)
# 2. Scenario catalog validation passes
# 3. Cross-epic E2E scripts follow runner conventions (conformance check)
# 4. Structured logging markers include correlation fields
# 5. Result schema is machine-parseable across representative scripts
# 6. Scenario IDs conform to the canonical regex
# 7. Runner contract and manifest schema versions are consistent
# 8. Log contract and E2E marker format are synchronized
# 9. Full ffs-harness test suite passes
#
# Usage: ./scripts/e2e/ffs_verification_gate_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_verification_gate}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_VERIFICATION_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_VERIFICATION_GATE_SKIP_SELF_CHECK:-0}"

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
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
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

log_test_tail() {
    local log_path="$1"

    [[ -f "$log_path" ]] || return 0
    e2e_log "Last 40 lines from ${log_path}:"
    tail -40 "$log_path" | while IFS= read -r line; do e2e_log "  $line"; done
}

e2e_init "ffs_verification_gate"
e2e_print_env

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_VERIFICATION_GATE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected verification-gate fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown verification-gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

emit_named_tests() {
    local module="$1"
    local count="$2"
    local index
    for index in $(seq 1 "$count"); do
        printf 'test %s::tests::case_%03d ... ok\n' "$module" "$index"
    done
}

case "$command_text" in
    "cargo test -p ffs-harness --lib -- artifact_manifest")
        emit_named_tests "artifact_manifest" 20
        finish_success
        ;;
    "cargo test -p ffs-harness --lib -- log_contract")
        emit_named_tests "log_contract" 15
        finish_success
        ;;
    "cargo test -p ffs-harness --lib -- verification_runner")
        emit_named_tests "verification_runner" 20
        finish_success
        ;;
    "cargo test -p ffs-harness --lib")
        emit_named_tests "full_harness" 180
        finish_success
        ;;
    *)
        echo "unexpected verification-gate fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/verification_gate_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_VERIFICATION_GATE_SELF_CHECK=0 \
        FFS_VERIFICATION_GATE_SKIP_SELF_CHECK=1 \
        FFS_VERIFICATION_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_verification_gate_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic verification-gate wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-verification-gate-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .invalid_scenario_marker_count == 0
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "artifact_manifest_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "log_contract_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "verification_runner_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "scenario_catalog_valid" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "cross_epic_conformance" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "structured_logging_fields" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "schema_version_consistency" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "e2e_marker_format_sync" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "full_harness_suite" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "verification_gate_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "verification_gate_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "verification_gate_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "verification_gate_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "verification_gate_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "verification_gate_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

#######################################
# Scenario 1: artifact_manifest unit tests pass
#######################################
e2e_step "Scenario 1: artifact_manifest unit tests"

TEST_LOG="$E2E_LOG_DIR/artifact_manifest_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- artifact_manifest; then
    TESTS_RUN=$(grep -c "^test artifact_manifest::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 20 ]]; then
        scenario_result "artifact_manifest_unit_tests" "PASS" "artifact_manifest tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "artifact_manifest_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 20)"
    fi
else
    log_test_tail "$TEST_LOG"
    scenario_result "artifact_manifest_unit_tests" "FAIL" "artifact_manifest tests failed"
fi

#######################################
# Scenario 2: log_contract unit tests pass
#######################################
e2e_step "Scenario 2: log_contract unit tests"

TEST_LOG="$E2E_LOG_DIR/log_contract_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- log_contract; then
    TESTS_RUN=$(grep -c "^test log_contract::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "log_contract_unit_tests" "PASS" "log_contract tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "log_contract_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    log_test_tail "$TEST_LOG"
    scenario_result "log_contract_unit_tests" "FAIL" "log_contract tests failed"
fi

#######################################
# Scenario 3: verification_runner unit tests pass
#######################################
e2e_step "Scenario 3: verification_runner unit tests"

TEST_LOG="$E2E_LOG_DIR/verification_runner_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- verification_runner; then
    TESTS_RUN=$(grep -c "^test verification_runner::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 20 ]]; then
        scenario_result "verification_runner_unit_tests" "PASS" "verification_runner tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "verification_runner_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 20)"
    fi
else
    log_test_tail "$TEST_LOG"
    scenario_result "verification_runner_unit_tests" "FAIL" "verification_runner tests failed"
fi

#######################################
# Scenario 4: Scenario catalog validates
#######################################
e2e_step "Scenario 4: Scenario catalog validation"

CATALOG="$REPO_ROOT/scripts/e2e/scenario_catalog.json"
if [[ -f "$CATALOG" ]]; then
    CATALOG_VALIDATION_LOG="$E2E_LOG_DIR/scenario_catalog_validation.log"
    if ( E2E_LOG_FILE="$CATALOG_VALIDATION_LOG" e2e_validate_scenario_catalog "$CATALOG" ); then
        scenario_result "scenario_catalog_valid" "PASS" "Catalog validator passed log=${CATALOG_VALIDATION_LOG}"
    else
        scenario_result "scenario_catalog_valid" "FAIL" "Catalog validator failed log=${CATALOG_VALIDATION_LOG}"
    fi
else
    scenario_result "scenario_catalog_valid" "FAIL" "Catalog file missing"
fi

#######################################
# Scenario 5: Cross-epic script conformance
#######################################
e2e_step "Scenario 5: Cross-epic script conformance"

CATALOG_SUITES=0
if [[ -f "$CATALOG" ]] && CATALOG_SUITES=$(jq -r '.suites | length' "$CATALOG" 2>/dev/null) \
    && ( e2e_validate_scenario_catalog "$CATALOG" ); then
    if [[ $CATALOG_SUITES -ge 5 ]]; then
        scenario_result "cross_epic_conformance" "PASS" "Scenario catalog validates ${CATALOG_SUITES} suites"
    else
        scenario_result "cross_epic_conformance" "FAIL" "Too few catalog suites: ${CATALOG_SUITES} (expected >= 5)"
    fi
else
    scenario_result "cross_epic_conformance" "FAIL" "Scenario catalog validation failed"
fi

#######################################
# Scenario 6: Structured logging correlation fields
#######################################
e2e_step "Scenario 6: Structured logging correlation fields"

RUNNER_SRC="crates/ffs-harness/src/verification_runner.rs"
CORR_FIELDS=0
for field in "operation_id" "scenario_id" "outcome"; do
    if grep -q "$field = " "$RUNNER_SRC"; then
        CORR_FIELDS=$((CORR_FIELDS + 1))
    fi
done

if [[ $CORR_FIELDS -eq 3 ]]; then
    scenario_result "structured_logging_fields" "PASS" "All 3 correlation fields present"
else
    scenario_result "structured_logging_fields" "FAIL" "Only ${CORR_FIELDS}/3 correlation fields"
fi

#######################################
# Scenario 7: Schema version consistency
#######################################
e2e_step "Scenario 7: Schema version consistency"

MANIFEST_SRC="crates/ffs-harness/src/artifact_manifest.rs"
LOG_SRC="crates/ffs-harness/src/log_contract.rs"

# All schema versions should be >= 1
VERSIONS_OK=0
if grep -q 'pub const SCHEMA_VERSION: u32 = 1' "$MANIFEST_SRC"; then
    VERSIONS_OK=$((VERSIONS_OK + 1))
fi
if grep -q 'pub const CONTRACT_VERSION: u32 = 1' "$LOG_SRC"; then
    VERSIONS_OK=$((VERSIONS_OK + 1))
fi
if grep -q 'pub const RUNNER_CONTRACT_VERSION: u32 = 1' "$RUNNER_SRC"; then
    VERSIONS_OK=$((VERSIONS_OK + 1))
fi

if [[ $VERSIONS_OK -eq 3 ]]; then
    scenario_result "schema_version_consistency" "PASS" "All 3 contract versions set"
else
    scenario_result "schema_version_consistency" "FAIL" "Only ${VERSIONS_OK}/3 versions found"
fi

#######################################
# Scenario 8: E2E marker format synchronized
#######################################
e2e_step "Scenario 8: E2E marker format synchronized"

# Check that log_contract defines the marker format constants
# and that lib.sh uses the same format
SYNC_OK=0
if grep -q 'pub const PREFIX: &str = "SCENARIO_RESULT"' "$LOG_SRC"; then
    SYNC_OK=$((SYNC_OK + 1))
fi
if grep -q 'pub const PASS: &str = "PASS"' "$LOG_SRC"; then
    SYNC_OK=$((SYNC_OK + 1))
fi
if grep -q 'pub const FAIL: &str = "FAIL"' "$LOG_SRC"; then
    SYNC_OK=$((SYNC_OK + 1))
fi
if grep -q 'SCENARIO_RESULT|scenario_id=' "$REPO_ROOT/scripts/e2e/lib.sh"; then
    SYNC_OK=$((SYNC_OK + 1))
fi

if [[ $SYNC_OK -eq 4 ]]; then
    scenario_result "e2e_marker_format_sync" "PASS" "Rust and shell marker formats synchronized"
else
    scenario_result "e2e_marker_format_sync" "FAIL" "Only ${SYNC_OK}/4 format checks passed"
fi

#######################################
# Scenario 9: Full ffs-harness test suite
#######################################
e2e_step "Scenario 9: Full ffs-harness test suite"

TEST_LOG="$E2E_LOG_DIR/full_harness_suite.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib; then
    TESTS_RUN=$(grep -c "^test .*::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 180 ]]; then
        scenario_result "full_harness_suite" "PASS" "Full suite passed (${TESTS_RUN} tests)"
    else
        scenario_result "full_harness_suite" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 180)"
    fi
else
    log_test_tail "$TEST_LOG"
    scenario_result "full_harness_suite" "FAIL" "Harness test suite failed"
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
