#!/usr/bin/env bash
# ffs_oq_decision_integration_e2e.sh - Verification gate for OQ decision integration (bd-h6nz.6.8)
#
# Validates that all 7 accepted Open Question decisions are integrated into
# specs, parity tracking, and the executable backlog with no stale sections.
#
# Scenarios:
# 1. OQ decision matrix module exists in ffs-harness
# 2. All 7 OQ decisions are tracked in the matrix
# 3. Decision documents (OQ1, OQ6, OQ7) exist on disk
# 4. E2E scripts referenced by decisions exist on disk
# 5. Implementation crates referenced by decisions exist
# 6. FEATURE_PARITY.md references OQ-affected areas
# 7. No stale OQ markers remain unresolved in spec docs
# 8. OQ decision matrix JSON round-trips
# 9. OQ decision matrix unit tests pass
#
# Usage: ./scripts/e2e/ffs_oq_decision_integration_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_oq_decision_integration}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-360}"
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
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
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

e2e_init "ffs_oq_decision_integration"

MATRIX_SRC="crates/ffs-harness/src/oq_decision_matrix.rs"

#######################################
# Scenario 1: OQ decision matrix module exists
#######################################
e2e_step "Scenario 1: OQ decision matrix module exists"

if [[ -f "$MATRIX_SRC" ]] && grep -q "pub mod oq_decision_matrix" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "oq_matrix_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "oq_matrix_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All 7 OQ decisions tracked
#######################################
e2e_step "Scenario 2: All 7 OQ decisions tracked"

OQ_COUNT=0
for oq in "OQ1" "OQ2" "OQ3" "OQ4" "OQ5" "OQ6" "OQ7"; do
    if grep -q "\"${oq}\"" "$MATRIX_SRC"; then
        OQ_COUNT=$((OQ_COUNT + 1))
    fi
done

if [[ $OQ_COUNT -eq 7 ]]; then
    scenario_result "oq_all_seven_tracked" "PASS" "All 7 OQ decisions present in matrix"
else
    scenario_result "oq_all_seven_tracked" "FAIL" "Only ${OQ_COUNT}/7 decisions found"
fi

#######################################
# Scenario 3: Decision documents exist on disk
#######################################
e2e_step "Scenario 3: Decision documents exist"

DOCS_FOUND=0
DOCS_EXPECTED=0
for doc in "docs/oq1-native-mode-boundary.md" "docs/generation-policy.md" "docs/oq7-version-store-format.md"; do
    DOCS_EXPECTED=$((DOCS_EXPECTED + 1))
    if [[ -f "$doc" ]]; then
        DOCS_FOUND=$((DOCS_FOUND + 1))
    fi
done

if [[ $DOCS_FOUND -eq $DOCS_EXPECTED ]]; then
    scenario_result "oq_decision_docs_exist" "PASS" "All ${DOCS_EXPECTED} decision docs found"
else
    scenario_result "oq_decision_docs_exist" "FAIL" "Only ${DOCS_FOUND}/${DOCS_EXPECTED} decision docs"
fi

#######################################
# Scenario 4: E2E scripts referenced exist
#######################################
e2e_step "Scenario 4: Referenced E2E scripts exist"

SCRIPTS_FOUND=0
SCRIPTS_TOTAL=0
for script in "scripts/e2e/ffs_mount_mode_e2e.sh" "scripts/e2e/ffs_refresh_policy_e2e.sh" "scripts/e2e/ffs_log_contract_e2e.sh" "scripts/e2e/ffs_version_store_format_e2e.sh"; do
    SCRIPTS_TOTAL=$((SCRIPTS_TOTAL + 1))
    if [[ -f "$script" ]]; then
        SCRIPTS_FOUND=$((SCRIPTS_FOUND + 1))
    fi
done

if [[ $SCRIPTS_FOUND -eq $SCRIPTS_TOTAL ]]; then
    scenario_result "oq_e2e_scripts_exist" "PASS" "All ${SCRIPTS_TOTAL} referenced E2E scripts found"
else
    scenario_result "oq_e2e_scripts_exist" "FAIL" "Only ${SCRIPTS_FOUND}/${SCRIPTS_TOTAL} E2E scripts"
fi

#######################################
# Scenario 5: Implementation crates exist
#######################################
e2e_step "Scenario 5: Implementation crates exist"

CRATES_FOUND=0
CRATES_TOTAL=0
for crate_name in "ffs-types" "ffs-core" "ffs-mvcc" "ffs-repair" "ffs-fuse" "ffs-cli" "ffs-inode"; do
    CRATES_TOTAL=$((CRATES_TOTAL + 1))
    if [[ -d "crates/${crate_name}" ]]; then
        CRATES_FOUND=$((CRATES_FOUND + 1))
    fi
done

if [[ $CRATES_FOUND -eq $CRATES_TOTAL ]]; then
    scenario_result "oq_impl_crates_exist" "PASS" "All ${CRATES_TOTAL} implementation crates found"
else
    scenario_result "oq_impl_crates_exist" "FAIL" "Only ${CRATES_FOUND}/${CRATES_TOTAL} crates"
fi

#######################################
# Scenario 6: FEATURE_PARITY.md references OQ-affected areas
#######################################
e2e_step "Scenario 6: FEATURE_PARITY.md references OQ areas"

PARITY_REFS=0
for keyword in "conflict" "repair" "FUSE" "mount" "generation" "WAL\|wal\|persist"; do
    if grep -qi "$keyword" "FEATURE_PARITY.md"; then
        PARITY_REFS=$((PARITY_REFS + 1))
    fi
done

if [[ $PARITY_REFS -ge 5 ]]; then
    scenario_result "oq_parity_references" "PASS" "${PARITY_REFS} OQ-related areas referenced in FEATURE_PARITY.md"
else
    scenario_result "oq_parity_references" "FAIL" "Only ${PARITY_REFS}/5 areas referenced"
fi

#######################################
# Scenario 7: No stale unresolved OQ markers in spec docs
#######################################
e2e_step "Scenario 7: No stale OQ markers"

# Check for unresolved "OPEN" or "UNRESOLVED" OQ markers in decision docs
STALE_COUNT=0
for doc in docs/oq1-native-mode-boundary.md docs/oq7-version-store-format.md docs/generation-policy.md; do
    if [[ -f "$doc" ]]; then
        stale=$(grep -ci "UNRESOLVED\|status.*open\|TBD\|TODO" "$doc" 2>/dev/null || true)
        stale="${stale:-0}"
        STALE_COUNT=$((STALE_COUNT + stale))
    fi
done

if [[ $STALE_COUNT -eq 0 ]]; then
    scenario_result "oq_no_stale_markers" "PASS" "No stale/unresolved markers in decision docs"
else
    scenario_result "oq_no_stale_markers" "FAIL" "${STALE_COUNT} stale markers found"
fi

#######################################
# Scenario 8: Matrix JSON serialization round-trips
#######################################
e2e_step "Scenario 8: Matrix JSON round-trip"

if grep -q "matrix_json_round_trips" "$MATRIX_SRC"; then
    scenario_result "oq_matrix_json_roundtrip" "PASS" "JSON round-trip test present"
else
    scenario_result "oq_matrix_json_roundtrip" "FAIL" "JSON round-trip test missing"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: OQ decision matrix unit tests"

TEST_LOG="$E2E_LOG_DIR/oq_decision_matrix_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- oq_decision_matrix; then
    TESTS_RUN=$(grep -c "test oq_decision_matrix::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 8 ]]; then
        scenario_result "oq_matrix_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "oq_matrix_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 8)"
    fi
else
    scenario_result "oq_matrix_unit_tests_pass" "FAIL" "OQ matrix tests failed"
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
