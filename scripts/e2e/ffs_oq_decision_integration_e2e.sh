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

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- oq_decision_matrix 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test oq_decision_matrix::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 8 ]]; then
        scenario_result "oq_matrix_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "oq_matrix_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 8)"
    fi
else
    scenario_result "oq_matrix_unit_tests_pass" "FAIL" "OQ matrix tests failed"
fi
rm -f "$TEST_LOG"

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
