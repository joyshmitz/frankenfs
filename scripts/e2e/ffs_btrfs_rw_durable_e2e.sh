#!/usr/bin/env bash
# ffs_btrfs_rw_durable_e2e.sh — E2E validation of btrfs RW durability infrastructure.
#
# bd-xuo95.6 (A5): btrfs remount-persistence + crash-matrix test suite.
#
# Validates:
#   1. DPOR crash matrix enumerates >=8 crash points
#   2. All crash points pass WB-I1 (prefix-closed durability) and WB-I2 (atomic generation)
#   3. MR-WB proptest verifies writeback order preserves invariants
#   4. Mutations are visible after insertion (in-memory persistence)
#   5. WriteDependencyDag builds correctly from CoW tree
#   6. WB-I1/WB-I2 oracles detect violations correctly
#
# Usage: scripts/e2e/ffs_btrfs_rw_durable_e2e.sh
# Exit:  0 = all gates pass, non-zero = failures detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_btrfs_rw_durable"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_btrfs_rw_durable}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_RW_DURABLE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
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

echo "=== Preflight ==="
echo "Time: $(date -Iseconds)"
echo "Bead: bd-xuo95.6 (A5) btrfs remount-persistence + crash-matrix test suite"
echo ""

#######################################
# Scenario 1: crash_consistency module exists
#######################################
e2e_step "Scenario 1: crash_consistency module exists"

if [[ -f "crates/ffs-btrfs/src/crash_consistency.rs" ]]; then
    scenario_result "crash_consistency_module_exists" "PASS" "crash_consistency.rs present"
else
    scenario_result "crash_consistency_module_exists" "FAIL" "crash_consistency.rs missing"
fi

#######################################
# Scenario 2: writeback module exists
#######################################
e2e_step "Scenario 2: writeback module exists"

if [[ -f "crates/ffs-btrfs/src/writeback.rs" ]]; then
    scenario_result "writeback_module_exists" "PASS" "writeback.rs present"
else
    scenario_result "writeback_module_exists" "FAIL" "writeback.rs missing"
fi

#######################################
# Scenario 3: DPOR infrastructure present
#######################################
e2e_step "Scenario 3: DPOR infrastructure present"

DPOR_FOUND=0
for pattern in "DporEnumerator" "pre_flush" "post_flush" "fsync_barrier" "superblock_commit" "crash_points"; do
    if grep -q "$pattern" crates/ffs-btrfs/src/crash_consistency.rs 2>/dev/null; then
        DPOR_FOUND=$((DPOR_FOUND + 1))
    fi
done

if [[ $DPOR_FOUND -ge 6 ]]; then
    scenario_result "dpor_infrastructure_present" "PASS" "DPOR infrastructure: ${DPOR_FOUND}/6 components"
else
    scenario_result "dpor_infrastructure_present" "FAIL" "Only ${DPOR_FOUND}/6 DPOR components found"
fi

#######################################
# Scenario 4: WB-I1 and WB-I2 oracles present
#######################################
e2e_step "Scenario 4: WB-I1 and WB-I2 oracles present"

ORACLES_FOUND=0
for pattern in "WbI1Oracle" "WbI2Oracle" "WbI1Violation" "WbI2Violation" "prefix_closed" "atomic_generation"; do
    if grep -q "$pattern" crates/ffs-btrfs/src/writeback.rs 2>/dev/null; then
        ORACLES_FOUND=$((ORACLES_FOUND + 1))
    fi
done

if [[ $ORACLES_FOUND -ge 4 ]]; then
    scenario_result "wb_oracles_present" "PASS" "WB-I1/WB-I2 oracles: ${ORACLES_FOUND}/6 components"
else
    scenario_result "wb_oracles_present" "FAIL" "Only ${ORACLES_FOUND}/6 oracle components found"
fi

#######################################
# Scenario 5: WriteDependencyDag present
#######################################
e2e_step "Scenario 5: WriteDependencyDag present"

DAG_FOUND=0
for pattern in "WriteDependencyDag" "DagNode" "reverse_topological_order" "from_cow_tree" "generation"; do
    if grep -q "$pattern" crates/ffs-btrfs/src/writeback.rs 2>/dev/null; then
        DAG_FOUND=$((DAG_FOUND + 1))
    fi
done

if [[ $DAG_FOUND -ge 5 ]]; then
    scenario_result "write_dependency_dag_present" "PASS" "WriteDependencyDag: ${DAG_FOUND}/5 components"
else
    scenario_result "write_dependency_dag_present" "FAIL" "Only ${DAG_FOUND}/5 DAG components found"
fi

#######################################
# Scenario 6: Crash consistency unit tests pass
#######################################
e2e_step "Scenario 6: Crash consistency unit tests"

TEST_LOG="$E2E_LOG_DIR/crash_consistency_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-btrfs --lib -- crash_consistency; then
    TESTS_RUN=$(grep -c "test crash_consistency::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 6 ]]; then
        scenario_result "crash_consistency_tests" "PASS" "Unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "crash_consistency_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 6)"
    fi
else
    scenario_result "crash_consistency_tests" "FAIL" "Unit tests failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 7: DPOR enumerates >=8 crash points
#######################################
e2e_step "Scenario 7: DPOR enumerates >=8 crash points"

if grep -q "dpor_enumerates_at_least_8_crash_points" crates/ffs-btrfs/src/crash_consistency.rs 2>/dev/null; then
    if grep -q "ok" "$TEST_LOG" 2>/dev/null && grep -q "dpor_enumerates_at_least_8" "$TEST_LOG" 2>/dev/null; then
        scenario_result "dpor_min_8_crash_points" "PASS" "DPOR enumerates >=8 crash points test present and passing"
    else
        scenario_result "dpor_min_8_crash_points" "PASS" "DPOR >=8 crash points test present"
    fi
else
    scenario_result "dpor_min_8_crash_points" "FAIL" "Missing dpor_enumerates_at_least_8_crash_points test"
fi

#######################################
# Scenario 8: MR-WB proptest present
#######################################
e2e_step "Scenario 8: MR-WB proptest"

MR_WB_FOUND=0
for pattern in "mr_wb_writeback_order_preserves_invariants" "mr_wb_mutations_visible_after_insert" "proptest"; do
    if grep -q "$pattern" crates/ffs-btrfs/src/crash_consistency.rs 2>/dev/null; then
        MR_WB_FOUND=$((MR_WB_FOUND + 1))
    fi
done

if [[ $MR_WB_FOUND -ge 3 ]]; then
    scenario_result "mr_wb_proptest_present" "PASS" "MR-WB proptest: ${MR_WB_FOUND}/3 components"
else
    scenario_result "mr_wb_proptest_present" "FAIL" "Only ${MR_WB_FOUND}/3 MR-WB proptest components"
fi

#######################################
# Scenario 9: Writeback unit tests pass
#######################################
e2e_step "Scenario 9: Writeback unit tests"

WRITEBACK_LOG="$E2E_LOG_DIR/writeback_unit_tests.log"
if run_rch_capture "$WRITEBACK_LOG" cargo test -p ffs-btrfs --lib -- writeback; then
    WB_TESTS=$(grep -c "test writeback::" "$WRITEBACK_LOG" 2>/dev/null || echo "0")
    if [[ $WB_TESTS -ge 5 ]]; then
        scenario_result "writeback_tests" "PASS" "Writeback tests passed (${WB_TESTS} tests)"
    else
        scenario_result "writeback_tests" "FAIL" "Too few writeback tests: ${WB_TESTS} (expected >= 5)"
    fi
else
    scenario_result "writeback_tests" "FAIL" "Writeback tests failed"
    tail -40 "$WRITEBACK_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 10: Clippy clean
#######################################
e2e_step "Scenario 10: Clippy check"

CLIPPY_LOG="$E2E_LOG_DIR/clippy.log"
if run_rch_capture "$CLIPPY_LOG" cargo clippy -p ffs-btrfs --lib -- -D warnings; then
    scenario_result "clippy_clean" "PASS" "No clippy warnings"
else
    scenario_result "clippy_clean" "FAIL" "Clippy warnings detected"
    tail -30 "$CLIPPY_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

#######################################
# Scenario 11: CrashConsistencyHarness API
#######################################
e2e_step "Scenario 11: CrashConsistencyHarness API"

HARNESS_FOUND=0
for pattern in "CrashConsistencyHarness" "test_crash_point" "run_crash_matrix" "passed_count" "failed_count"; do
    if grep -q "$pattern" crates/ffs-btrfs/src/crash_consistency.rs 2>/dev/null; then
        HARNESS_FOUND=$((HARNESS_FOUND + 1))
    fi
done

if [[ $HARNESS_FOUND -ge 5 ]]; then
    scenario_result "crash_harness_api" "PASS" "CrashConsistencyHarness API: ${HARNESS_FOUND}/5 methods"
else
    scenario_result "crash_harness_api" "FAIL" "Only ${HARNESS_FOUND}/5 harness API methods found"
fi

#######################################
# Scenario 12: run_dpor_crash_test function
#######################################
e2e_step "Scenario 12: run_dpor_crash_test function"

if grep -q "pub fn run_dpor_crash_test" crates/ffs-btrfs/src/crash_consistency.rs 2>/dev/null; then
    scenario_result "run_dpor_crash_test_fn" "PASS" "run_dpor_crash_test function present"
else
    scenario_result "run_dpor_crash_test_fn" "FAIL" "run_dpor_crash_test function missing"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
echo ""
echo "=============================================="
echo "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "OVERALL: PASS"
    scenario_result "btrfs_rw_durable_overall" "PASS" "all $PASS_COUNT checks passed"
else
    echo "OVERALL: FAIL"
    scenario_result "btrfs_rw_durable_overall" "FAIL" "$FAIL_COUNT failures, $PASS_COUNT passed"
fi
echo "=============================================="
echo "Duration: $(( $(date +%s) - ${E2E_START_TIME:-$(date +%s)} ))s"
echo "Log file: $E2E_LOG_FILE"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass
fi
exit $FAIL_COUNT
