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
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-360}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_OQ_DECISION_INTEGRATION_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_OQ_DECISION_INTEGRATION_SKIP_SELF_CHECK:-0}"

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
    e2e_rch_capture "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_OQ_DECISION_INTEGRATION_FIXTURE_CASE:-complete}"

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
        echo "unknown OQ decision integration fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

if [[ "$command_text" != *"cargo test -p ffs-harness --lib -- oq_decision_matrix"* ]]; then
    echo "unexpected fixture command: $command_text" >&2
    exit 64
fi

printf '%s\n' \
    "test oq_decision_matrix::tests::matrix_has_all_seven_decisions ... ok" \
    "test oq_decision_matrix::tests::all_decisions_are_resolved ... ok" \
    "test oq_decision_matrix::tests::decision_ids_are_sequential ... ok" \
    "test oq_decision_matrix::tests::every_decision_has_at_least_one_test_pattern ... ok" \
    "test oq_decision_matrix::tests::every_decision_has_at_least_one_impl_crate ... ok" \
    "test oq_decision_matrix::tests::decision_documents_exist_on_disk ... ok" \
    "test oq_decision_matrix::tests::e2e_scripts_exist_on_disk ... ok" \
    "test oq_decision_matrix::tests::matrix_json_round_trips ... ok" \
    "test oq_decision_matrix::tests::canonical_matrix_json_shape ... ok" \
    "test oq_decision_matrix::tests::all_closing_beads_reference_epic_6 ... ok"
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
    local child_log="$E2E_LOG_DIR/oq_decision_integration_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_OQ_DECISION_INTEGRATION_SELF_CHECK=0 \
        FFS_OQ_DECISION_INTEGRATION_SKIP_SELF_CHECK=1 \
        FFS_OQ_DECISION_INTEGRATION_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_oq_decision_integration_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic OQ decision integration wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir unit_log
    stub_path="$E2E_LOG_DIR/rch-oq-decision-integration-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    unit_log="$result_dir/oq_decision_matrix_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "oq_matrix_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_all_seven_tracked" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_decision_docs_exist" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_e2e_scripts_exist" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_impl_crates_exist" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_parity_references" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_no_stale_markers" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_matrix_json_roundtrip" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "oq_matrix_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && [[ "$(grep -c "test oq_decision_matrix::tests::" "$unit_log" 2>/dev/null || echo 0)" -ge 8 ]] \
        && grep -q "matrix_has_all_seven_decisions" "$unit_log" \
        && grep -q "matrix_json_round_trips" "$unit_log"; then
        scenario_result "oq_decision_integration_fixture_complete_self_check" "PASS" "result=${result_path} unit_log=${unit_log}"
    else
        scenario_result "oq_decision_integration_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "OQ decision integration complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "oq_decision_integration_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "oq_decision_integration_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "OQ decision integration local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "oq_decision_integration_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "oq_decision_integration_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "OQ decision integration missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_oq_decision_integration"

MATRIX_SRC="crates/ffs-harness/src/oq_decision_matrix.rs"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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
