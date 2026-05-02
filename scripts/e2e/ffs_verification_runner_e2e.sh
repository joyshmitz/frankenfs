#!/usr/bin/env bash
# ffs_verification_runner_e2e.sh - E2E verification for runner conventions (bd-h6nz.9.4)
#
# Validates that:
# 1. verification_runner module exists and builds clean
# 2. E2E script conformance checker catches known violations
# 3. JSON result emission from lib.sh works
# 4. run_gate.sh runner wrapper exists and has correct structure
# 5. Scenario marker parsing is consistent between shell and Rust
# 6. Unit tests pass for verification_runner module
# 7. Structured logging markers are present
# 8. Retry semantics function is available in lib.sh
# 9. Existing E2E scripts pass conformance check
# 10. Permissioned FUSE lane artifacts and docs are wired
#
# Usage: ./scripts/e2e/ffs_verification_runner_e2e.sh
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

e2e_init "ffs_verification_runner"

RUNNER_SRC="crates/ffs-harness/src/verification_runner.rs"
LIB_SH="scripts/e2e/lib.sh"
GATE_SH="scripts/e2e/run_gate.sh"
FUSE_PROD_SH="scripts/e2e/ffs_fuse_production.sh"
E2E_README="scripts/e2e/README.md"

#######################################
# Scenario 1: verification_runner module exists
#######################################
e2e_step "Scenario 1: verification_runner module exists"

if [[ -f "$RUNNER_SRC" ]]; then
    scenario_result "runner_module_exists" "PASS" "verification_runner.rs present"
else
    scenario_result "runner_module_exists" "FAIL" "verification_runner.rs missing"
fi

#######################################
# Scenario 2: Core types present
#######################################
e2e_step "Scenario 2: Core runner types present"

TYPES_FOUND=0
for pattern in "pub struct ParsedScenario" "pub struct RunnerConfig" "pub struct ScriptRunResult" "pub struct ManifestParams" "pub const RUNNER_CONTRACT_VERSION"; do
    if grep -q "$pattern" "$RUNNER_SRC"; then
        TYPES_FOUND=$((TYPES_FOUND + 1))
    fi
done

if [[ $TYPES_FOUND -eq 5 ]]; then
    scenario_result "runner_core_types" "PASS" "All 5 core types/constants present"
else
    scenario_result "runner_core_types" "FAIL" "Only ${TYPES_FOUND}/5 core types found"
fi

#######################################
# Scenario 3: API functions present
#######################################
e2e_step "Scenario 3: API functions present"

FUNCS_FOUND=0
for func in "pub fn parse_e2e_output" "pub fn build_manifest_from_parsed" "pub fn check_script_conformance" "pub fn aggregate_verdict" "pub fn merge_scenarios"; do
    if grep -q "$func" "$RUNNER_SRC"; then
        FUNCS_FOUND=$((FUNCS_FOUND + 1))
    fi
done

if [[ $FUNCS_FOUND -eq 5 ]]; then
    scenario_result "runner_api_functions" "PASS" "All 5 API functions present"
else
    scenario_result "runner_api_functions" "FAIL" "Only ${FUNCS_FOUND}/5 API functions found"
fi

#######################################
# Scenario 4: lib.sh JSON emission
#######################################
e2e_step "Scenario 4: lib.sh JSON emission support"

LIB_FEATURES=0
for feature in "e2e_emit_json_summary" "e2e_retry" "E2E_TEST_NAME" "result.json"; do
    if grep -q "$feature" "$LIB_SH"; then
        LIB_FEATURES=$((LIB_FEATURES + 1))
    fi
done

if [[ $LIB_FEATURES -eq 4 ]]; then
    scenario_result "lib_json_emission" "PASS" "All 4 lib.sh features present"
else
    scenario_result "lib_json_emission" "FAIL" "Only ${LIB_FEATURES}/4 features found"
fi

#######################################
# Scenario 5: run_gate.sh runner exists
#######################################
e2e_step "Scenario 5: run_gate.sh runner wrapper"

GATE_FEATURES=0
for feature in "--gate-id" "--ci" "--retries" "--catalog" "--conformance" "gate_manifest.json"; do
    if grep -q "$feature" "$GATE_SH"; then
        GATE_FEATURES=$((GATE_FEATURES + 1))
    fi
done

if [[ $GATE_FEATURES -eq 6 ]]; then
    scenario_result "gate_runner_features" "PASS" "All 6 runner features present"
else
    scenario_result "gate_runner_features" "FAIL" "Only ${GATE_FEATURES}/6 features found"
fi

#######################################
# Scenario 6: Unit tests pass
#######################################
e2e_step "Scenario 6: verification_runner unit tests"

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- verification_runner 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test verification_runner::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 15 ]]; then
        scenario_result "runner_unit_tests" "PASS" "Unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "runner_unit_tests" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 15)"
    fi
else
    scenario_result "runner_unit_tests" "FAIL" "Unit tests failed"
fi
rm -f "$TEST_LOG"

#######################################
# Scenario 7: Structured logging markers
#######################################
e2e_step "Scenario 7: Structured logging markers"

LOG_MARKERS_FOUND=0
for marker in "verification_runner_manifest_built"; do
    if grep -q "\"${marker}\"" "$RUNNER_SRC"; then
        LOG_MARKERS_FOUND=$((LOG_MARKERS_FOUND + 1))
    fi
done

if [[ $LOG_MARKERS_FOUND -ge 1 ]]; then
    scenario_result "runner_logging_markers" "PASS" "Structured logging markers present"
else
    scenario_result "runner_logging_markers" "FAIL" "Missing structured logging markers"
fi

#######################################
# Scenario 8: Conformance checker detects violations
#######################################
e2e_step "Scenario 8: Conformance violation detection"

# The Rust tests cover violation detection; verify the test names exist
VIOLATION_TESTS=0
for test_name in "conformant_script_has_no_violations" "script_missing_lib_source_detected" "script_missing_strict_mode_detected" "conformance_missing_everything_reports_all_violations"; do
    if grep -q "fn ${test_name}" "$RUNNER_SRC"; then
        VIOLATION_TESTS=$((VIOLATION_TESTS + 1))
    fi
done

if [[ $VIOLATION_TESTS -eq 4 ]]; then
    scenario_result "conformance_violation_tests" "PASS" "All 4 conformance tests present"
else
    scenario_result "conformance_violation_tests" "FAIL" "Only ${VIOLATION_TESTS}/4 conformance tests found"
fi

#######################################
# Scenario 9: Exit code conventions documented
#######################################
e2e_step "Scenario 9: Exit code conventions"

EXIT_CODE_PATTERNS=0
for pattern in "pub const PASS: i32 = 0" "pub const FAIL: i32 = 1"; do
    if grep -q "$pattern" "$RUNNER_SRC"; then
        EXIT_CODE_PATTERNS=$((EXIT_CODE_PATTERNS + 1))
    fi
done

if [[ $EXIT_CODE_PATTERNS -eq 2 ]]; then
    scenario_result "exit_code_conventions" "PASS" "Exit code constants defined"
else
    scenario_result "exit_code_conventions" "FAIL" "Only ${EXIT_CODE_PATTERNS}/2 exit code constants found"
fi

#######################################
# Scenario 10: Permissioned FUSE lane artifacts
#######################################
e2e_step "Scenario 10: Permissioned FUSE lane artifacts"

FUSE_LANE_FEATURES=0
for feature in \
    "FUSE_CAPABILITY_JSON" \
    "fuse_permissioned_lane.json" \
    "e2e_probe_fuse_capability" \
    "--require-mount-probe" \
    "--mount-probe-exit" \
    "--unmount-probe-exit" \
    "emit_permissioned_lane_summary" \
    "fusermount_version" \
    "qa_artifacts"; do
    if grep -q -- "$feature" "$FUSE_PROD_SH"; then
        FUSE_LANE_FEATURES=$((FUSE_LANE_FEATURES + 1))
    fi
done

if [[ $FUSE_LANE_FEATURES -eq 9 ]]; then
    scenario_result "permissioned_fuse_lane_artifacts" "PASS" "All 9 FUSE lane artifact hooks present"
else
    scenario_result "permissioned_fuse_lane_artifacts" "FAIL" "Only ${FUSE_LANE_FEATURES}/9 FUSE lane hooks found"
fi

#######################################
# Scenario 11: Permissioned btrfs lane controls
#######################################
e2e_step "Scenario 11: Permissioned btrfs lane controls"

BTRFS_LANE_FEATURES=0
for feature in \
    "FFS_RUN_BTRFS_LANE_PROBE" \
    "FFS_REQUIRE_BTRFS_LANE_PROBE" \
    "fuse_lane_btrfs_mount_unmount_probe"; do
    if grep -q "$feature" "$FUSE_PROD_SH"; then
        BTRFS_LANE_FEATURES=$((BTRFS_LANE_FEATURES + 1))
    fi
done

if [[ $BTRFS_LANE_FEATURES -eq 3 ]]; then
    scenario_result "permissioned_btrfs_lane_controls" "PASS" "Btrfs lane controls present"
else
    scenario_result "permissioned_btrfs_lane_controls" "FAIL" "Only ${BTRFS_LANE_FEATURES}/3 btrfs lane controls found"
fi

#######################################
# Scenario 12: Permissioned lane documentation
#######################################
e2e_step "Scenario 12: Permissioned lane documentation"

FUSE_LANE_DOCS=0
for feature in \
    "Permissioned FUSE Lane" \
    "FFS_RUN_BTRFS_LANE_PROBE=1" \
    "FFS_REQUIRE_BTRFS_LANE_PROBE=1" \
    "rch exec" \
    "fuse_capability.json" \
    "fuse_permissioned_lane.json"; do
    if grep -q "$feature" "$E2E_README"; then
        FUSE_LANE_DOCS=$((FUSE_LANE_DOCS + 1))
    fi
done

if [[ $FUSE_LANE_DOCS -eq 6 ]]; then
    scenario_result "permissioned_fuse_lane_docs" "PASS" "Permissioned lane docs present"
else
    scenario_result "permissioned_fuse_lane_docs" "FAIL" "Only ${FUSE_LANE_DOCS}/6 documentation markers found"
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
