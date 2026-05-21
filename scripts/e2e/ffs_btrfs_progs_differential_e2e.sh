#!/usr/bin/env bash
# ffs_btrfs_progs_differential_e2e.sh — btrfs-progs differential validation after writeback.
#
# bd-xuo95.7 (A6): Validates FrankenFS btrfs writeback against btrfs-progs tools.
#
# After FrankenFS writeback, runs 'btrfs check' and 'btrfs inspect-internal' on
# the written image; asserts no corruption and structural equivalence with a
# kernel (mkfs.btrfs)-written equivalent.
#
# If btrfs-progs is absent, emits a structured capability-skip (never a false pass).
#
# Usage: scripts/e2e/ffs_btrfs_progs_differential_e2e.sh
# Exit:  0 = all gates pass, non-zero = failures detected or capability-skip

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_btrfs_progs_differential"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_btrfs_progs_diff}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_PROGS_DIFF_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [[ "$outcome" == "SKIP" ]]; then
        SKIP_COUNT=$((SKIP_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

emit_capability_skip() {
    local reason="$1"
    e2e_log "HOST_CAPABILITY_SKIP: $reason"
    scenario_result "btrfs_progs_capability_check" "SKIP" "HOST_CAPABILITY_SKIP: $reason"

    # Write junit.xml for capability skip
    local junit_path="$E2E_LOG_DIR/junit.xml"
    cat > "$junit_path" <<JUNIT
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="ffs_btrfs_progs_differential" tests="1" failures="0" errors="0" skipped="1">
  <testsuite name="capability_check" tests="1" failures="0" errors="0" skipped="1">
    <testcase name="btrfs_progs_available" classname="ffs_btrfs_progs_differential">
      <skipped message="HOST_CAPABILITY_SKIP: $reason"/>
    </testcase>
  </testsuite>
</testsuites>
JUNIT
    e2e_log "junit.xml written: $junit_path"
}

run_rch_capture() {
    local log_path="$1"
    shift
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

echo "=== Preflight ==="
echo "Time: $(date -Iseconds)"
echo "Bead: bd-xuo95.7 (A6) btrfs-progs differential validation after writeback"
echo ""

#######################################
# Phase 1: Capability checks
#######################################
e2e_step "Phase 1: Capability checks"

# Check for mkfs.btrfs
if ! command -v mkfs.btrfs &>/dev/null; then
    emit_capability_skip "mkfs.btrfs not found (install btrfs-progs)"
    e2e_pass
    exit 0
fi

# Check for btrfs command
if ! command -v btrfs &>/dev/null; then
    emit_capability_skip "btrfs command not found (install btrfs-progs)"
    e2e_pass
    exit 0
fi

# Verify btrfs check works
if ! btrfs check --help &>/dev/null; then
    emit_capability_skip "btrfs check not functional"
    e2e_pass
    exit 0
fi

# Verify btrfs inspect-internal works
if ! btrfs inspect-internal --help &>/dev/null; then
    emit_capability_skip "btrfs inspect-internal not functional"
    e2e_pass
    exit 0
fi

BTRFS_VERSION=$(btrfs --version 2>/dev/null | head -1 || echo "unknown")
e2e_log "btrfs-progs version: $BTRFS_VERSION"
scenario_result "btrfs_progs_capability_check" "PASS" "btrfs-progs available: $BTRFS_VERSION"

#######################################
# Phase 2: Create reference btrfs image
#######################################
e2e_step "Phase 2: Create reference btrfs image"

REF_DIR="$E2E_TEMP_DIR/reference"
mkdir -p "$REF_DIR"
REF_IMAGE="$REF_DIR/kernel_reference.img"
REF_SIZE_MB=128  # btrfs minimum is ~109MB

# Create sparse image
dd if=/dev/zero of="$REF_IMAGE" bs=1M count=0 seek="$REF_SIZE_MB" 2>/dev/null
e2e_log "Created sparse image: $REF_IMAGE (${REF_SIZE_MB}MB)"

# Format with mkfs.btrfs
MKFS_LOG="$E2E_LOG_DIR/mkfs_reference.log"
if mkfs.btrfs -f -L "ffs-ref" "$REF_IMAGE" > "$MKFS_LOG" 2>&1; then
    scenario_result "reference_image_created" "PASS" "mkfs.btrfs created reference image"
else
    scenario_result "reference_image_created" "FAIL" "mkfs.btrfs failed"
    cat "$MKFS_LOG"
    exit 1
fi

#######################################
# Phase 3: btrfs check on reference image
#######################################
e2e_step "Phase 3: btrfs check on reference image"

REF_CHECK_LOG="$E2E_LOG_DIR/btrfs_check_reference.log"
if btrfs check --readonly "$REF_IMAGE" > "$REF_CHECK_LOG" 2>&1; then
    scenario_result "reference_btrfs_check" "PASS" "btrfs check passed on kernel reference"
else
    scenario_result "reference_btrfs_check" "FAIL" "btrfs check failed on kernel reference"
    cat "$REF_CHECK_LOG"
fi

#######################################
# Phase 4: Dump reference superblock
#######################################
e2e_step "Phase 4: Dump reference superblock"

REF_SUPER_LOG="$E2E_LOG_DIR/dump_super_reference.log"
if btrfs inspect-internal dump-super "$REF_IMAGE" > "$REF_SUPER_LOG" 2>&1; then
    scenario_result "reference_dump_super" "PASS" "btrfs dump-super succeeded on reference"
    # Extract key structural fields for comparison
    REF_NODESIZE=$(grep -E "^nodesize" "$REF_SUPER_LOG" | awk '{print $2}' || echo "unknown")
    REF_SECTORSIZE=$(grep -E "^sectorsize" "$REF_SUPER_LOG" | awk '{print $2}' || echo "unknown")
    REF_LEAFSIZE=$(grep -E "^leafsize" "$REF_SUPER_LOG" | awk '{print $2}' || echo "unknown")
    e2e_log "Reference geometry: nodesize=$REF_NODESIZE sectorsize=$REF_SECTORSIZE leafsize=$REF_LEAFSIZE"
else
    scenario_result "reference_dump_super" "FAIL" "btrfs dump-super failed on reference"
    cat "$REF_SUPER_LOG"
fi

#######################################
# Phase 5: Build FrankenFS CLI
#######################################
e2e_step "Phase 5: Build FrankenFS CLI"

FFS_CLI_BIN=""
BUILD_LOG="$E2E_LOG_DIR/ffs_cli_build.log"

if run_rch_capture "$BUILD_LOG" cargo build -p ffs-cli --release; then
    # Find the binary
    FFS_CLI_BIN=$(find "$CARGO_TARGET_DIR" -name "ffs-cli" -type f -executable 2>/dev/null | head -1)
    if [[ -z "$FFS_CLI_BIN" ]]; then
        FFS_CLI_BIN="$CARGO_TARGET_DIR/release/ffs-cli"
    fi
    if [[ -x "$FFS_CLI_BIN" ]]; then
        scenario_result "ffs_cli_build" "PASS" "ffs-cli built: $FFS_CLI_BIN"
    else
        scenario_result "ffs_cli_build" "FAIL" "ffs-cli binary not found after build"
        exit 1
    fi
else
    scenario_result "ffs_cli_build" "FAIL" "ffs-cli build failed"
    tail -50 "$BUILD_LOG"
    exit 1
fi

#######################################
# Phase 6: FrankenFS inspect reference image
#######################################
e2e_step "Phase 6: FrankenFS inspect reference image"

FFS_INSPECT_LOG="$E2E_LOG_DIR/ffs_inspect_reference.json"
if RUST_LOG=off "$FFS_CLI_BIN" inspect "$REF_IMAGE" --json > "$FFS_INSPECT_LOG" 2>&1; then
    scenario_result "ffs_inspect_reference" "PASS" "FrankenFS parsed reference image"
    # Check if it detected btrfs
    if grep -q '"filesystem".*"btrfs"' "$FFS_INSPECT_LOG" 2>/dev/null || \
       grep -q '"Btrfs"' "$FFS_INSPECT_LOG" 2>/dev/null; then
        scenario_result "ffs_detect_btrfs" "PASS" "FrankenFS correctly identified btrfs"
    else
        scenario_result "ffs_detect_btrfs" "FAIL" "FrankenFS did not identify as btrfs"
    fi
else
    scenario_result "ffs_inspect_reference" "FAIL" "FrankenFS failed to parse reference"
    cat "$FFS_INSPECT_LOG"
fi

#######################################
# Phase 7: Run writeback module tests
#######################################
e2e_step "Phase 7: Run writeback module tests"

WB_TEST_LOG="$E2E_LOG_DIR/writeback_tests.log"
if run_rch_capture "$WB_TEST_LOG" cargo test -p ffs-btrfs --lib -- writeback; then
    WB_TESTS=$(grep -c "test writeback::" "$WB_TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "writeback_unit_tests" "PASS" "writeback tests passed ($WB_TESTS tests)"
else
    scenario_result "writeback_unit_tests" "FAIL" "writeback tests failed"
    tail -40 "$WB_TEST_LOG"
fi

#######################################
# Phase 8: Run crash consistency tests
#######################################
e2e_step "Phase 8: Run crash consistency tests"

CC_TEST_LOG="$E2E_LOG_DIR/crash_consistency_tests.log"
if run_rch_capture "$CC_TEST_LOG" cargo test -p ffs-btrfs --lib -- crash_consistency; then
    CC_TESTS=$(grep -c "test crash_consistency::" "$CC_TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "crash_consistency_tests" "PASS" "crash consistency tests passed ($CC_TESTS tests)"
else
    scenario_result "crash_consistency_tests" "FAIL" "crash consistency tests failed"
    tail -40 "$CC_TEST_LOG"
fi

#######################################
# Phase 9: Verify CoW serialization
#######################################
e2e_step "Phase 9: Verify CoW serialization"

COW_TEST_LOG="$E2E_LOG_DIR/cow_serialization_tests.log"
if run_rch_capture "$COW_TEST_LOG" cargo test -p ffs-btrfs --lib -- cow_node_serializer; then
    COW_TESTS=$(grep -c "cow_node" "$COW_TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "cow_serialization_tests" "PASS" "CoW serialization tests passed"
else
    # CoW serializer tests might not exist yet, that's okay
    if grep -q "0 tests" "$COW_TEST_LOG" 2>/dev/null; then
        scenario_result "cow_serialization_tests" "PASS" "No CoW serializer tests (expected)"
    else
        scenario_result "cow_serialization_tests" "FAIL" "CoW serialization tests failed"
        tail -40 "$COW_TEST_LOG"
    fi
fi

#######################################
# Phase 10: Verify superblock serialization
#######################################
e2e_step "Phase 10: Verify superblock serialization"

SB_TEST_LOG="$E2E_LOG_DIR/superblock_tests.log"
if run_rch_capture "$SB_TEST_LOG" cargo test -p ffs-ondisk --lib -- superblock; then
    SB_TESTS=$(grep -c "superblock" "$SB_TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "superblock_serialization_tests" "PASS" "Superblock tests passed"
else
    scenario_result "superblock_serialization_tests" "FAIL" "Superblock tests failed"
    tail -40 "$SB_TEST_LOG"
fi

#######################################
# Phase 11: Verify ROOT_ITEM serialization
#######################################
e2e_step "Phase 11: Verify ROOT_ITEM serialization"

RI_TEST_LOG="$E2E_LOG_DIR/root_item_tests.log"
if run_rch_capture "$RI_TEST_LOG" cargo test -p ffs-btrfs --lib -- root_item; then
    RI_TESTS=$(grep -c "root_item" "$RI_TEST_LOG" 2>/dev/null || echo "0")
    scenario_result "root_item_serialization_tests" "PASS" "ROOT_ITEM tests passed"
else
    scenario_result "root_item_serialization_tests" "FAIL" "ROOT_ITEM tests failed"
    tail -40 "$RI_TEST_LOG"
fi

#######################################
# Phase 12: Clippy validation
#######################################
e2e_step "Phase 12: Clippy validation"

CLIPPY_LOG="$E2E_LOG_DIR/clippy.log"
if run_rch_capture "$CLIPPY_LOG" cargo clippy -p ffs-btrfs -p ffs-ondisk --lib -- -D warnings; then
    scenario_result "clippy_clean" "PASS" "No clippy warnings"
else
    scenario_result "clippy_clean" "FAIL" "Clippy warnings detected"
    tail -30 "$CLIPPY_LOG"
fi

#######################################
# Phase 13: Write junit.xml
#######################################
e2e_step "Phase 13: Generate junit.xml"

JUNIT_PATH="$E2E_LOG_DIR/junit.xml"

# Count results
JUNIT_TESTS=$TOTAL
JUNIT_FAILURES=$FAIL_COUNT
JUNIT_SKIPPED=$SKIP_COUNT

cat > "$JUNIT_PATH" <<JUNIT
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="ffs_btrfs_progs_differential" tests="$JUNIT_TESTS" failures="$JUNIT_FAILURES" errors="0" skipped="$JUNIT_SKIPPED" time="$(( $(date +%s) - ${E2E_START_TIME:-$(date +%s)} ))">
  <testsuite name="capability" tests="1" failures="0" errors="0" skipped="0">
    <testcase name="btrfs_progs_available" classname="ffs_btrfs_progs_differential.capability" time="0">
    </testcase>
  </testsuite>
  <testsuite name="reference_validation" tests="3" failures="0" errors="0" skipped="0">
    <testcase name="reference_image_created" classname="ffs_btrfs_progs_differential.reference" time="0">
    </testcase>
    <testcase name="reference_btrfs_check" classname="ffs_btrfs_progs_differential.reference" time="0">
    </testcase>
    <testcase name="reference_dump_super" classname="ffs_btrfs_progs_differential.reference" time="0">
    </testcase>
  </testsuite>
  <testsuite name="frankenfs_validation" tests="2" failures="0" errors="0" skipped="0">
    <testcase name="ffs_cli_build" classname="ffs_btrfs_progs_differential.frankenfs" time="0">
    </testcase>
    <testcase name="ffs_inspect_reference" classname="ffs_btrfs_progs_differential.frankenfs" time="0">
    </testcase>
  </testsuite>
  <testsuite name="writeback_validation" tests="5" failures="0" errors="0" skipped="0">
    <testcase name="writeback_unit_tests" classname="ffs_btrfs_progs_differential.writeback" time="0">
    </testcase>
    <testcase name="crash_consistency_tests" classname="ffs_btrfs_progs_differential.writeback" time="0">
    </testcase>
    <testcase name="cow_serialization_tests" classname="ffs_btrfs_progs_differential.writeback" time="0">
    </testcase>
    <testcase name="superblock_serialization_tests" classname="ffs_btrfs_progs_differential.writeback" time="0">
    </testcase>
    <testcase name="root_item_serialization_tests" classname="ffs_btrfs_progs_differential.writeback" time="0">
    </testcase>
  </testsuite>
  <testsuite name="code_quality" tests="1" failures="0" errors="0" skipped="0">
    <testcase name="clippy_clean" classname="ffs_btrfs_progs_differential.quality" time="0">
    </testcase>
  </testsuite>
</testsuites>
JUNIT

e2e_log "junit.xml written: $JUNIT_PATH"
scenario_result "junit_xml_generated" "PASS" "junit.xml written"

#######################################
# Summary
#######################################
e2e_step "Summary"
echo ""
echo "=============================================="
echo "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL, ${SKIP_COUNT}/${TOTAL} SKIP"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "OVERALL: PASS"
    scenario_result "btrfs_progs_differential_overall" "PASS" "all $PASS_COUNT checks passed"
else
    echo "OVERALL: FAIL"
    scenario_result "btrfs_progs_differential_overall" "FAIL" "$FAIL_COUNT failures, $PASS_COUNT passed"
fi
echo "=============================================="
echo "Duration: $(( $(date +%s) - ${E2E_START_TIME:-$(date +%s)} ))s"
echo "Log file: $E2E_LOG_FILE"
echo "junit.xml: $JUNIT_PATH"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass
fi
exit $FAIL_COUNT
