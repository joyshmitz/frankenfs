#!/usr/bin/env bash
# ffs_btrfs_rw_interlock_e2e.sh — E2E validation of btrfs RW safety interlock.
#
# bd-xuo95.1: A0 btrfs RW safety interlock - stop silent data loss.
#
# Validates:
#   1. btrfs mutations return EROFS (errno 30) when btrfs_rw_ephemeral_ok is false
#   2. Ephemeral flag permits in-memory RW (mutations succeed, no persistence)
#   3. Structured refusal log emitted when interlock triggers
#
# Usage: scripts/e2e/ffs_btrfs_rw_interlock_e2e.sh
# Exit:  0 = all gates pass, non-zero = failures detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_btrfs_rw_interlock"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_RW_INTERLOCK_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"

run_rch_capture() {
    local log_path="$1"
    shift
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    if [[ -n "$detail" ]]; then
        echo "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    else
        echo "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}"
    fi
}

echo "=== Preflight ==="
echo "Time: $(date -Iseconds)"

# Ensure the test crate compiles
echo ""
echo "=== Compile ffs-core with test profile ==="
echo "Time: $(date -Iseconds)"
COMPILE_LOG="$E2E_LOG_DIR/ffs_core_compile.log"
if run_rch_capture "$COMPILE_LOG" cargo check -p ffs-core --tests; then
    tail -20 "$COMPILE_LOG"
    scenario_result "btrfs_rw_interlock_compile" "PASS" "ffs-core test targets compile via rch"
    pass "ffs-core compiles"
else
    tail -40 "$COMPILE_LOG"
    scenario_result "btrfs_rw_interlock_compile" "FAIL" "ffs-core compile failed via rch"
    fail "ffs-core compile"
    e2e_fail "ffs-core compile failed via rch"
fi

echo ""
echo "=== Run interlock unit tests ==="
echo "Time: $(date -Iseconds)"
if run_rch_capture "$E2E_LOG_DIR/interlock_tests.log" cargo test -p ffs-core btrfs_rw_interlock; then
    tail -20 "$E2E_LOG_DIR/interlock_tests.log"
    # Extract test counts
    test_line=$(grep "test result:" "$E2E_LOG_DIR/interlock_tests.log" | head -1)
    if echo "$test_line" | grep -q "ok. 2 passed"; then
        scenario_result "btrfs_rw_interlock_unit_tests" "PASS" "2 interlock tests pass"
        pass "interlock unit tests"
    else
        scenario_result "btrfs_rw_interlock_unit_tests" "FAIL" "expected 2 passing tests"
        fail "interlock unit tests"
    fi
else
    scenario_result "btrfs_rw_interlock_unit_tests" "FAIL" "test run failed"
    fail "interlock unit tests"
fi

echo ""
echo "=== Verify EROFS without ephemeral flag ==="
echo "Time: $(date -Iseconds)"
# The test btrfs_rw_interlock_refuses_mutations_without_ack verifies this
if grep -q "btrfs_rw_interlock_refuses_mutations_without_ack.*ok" "$E2E_LOG_DIR/interlock_tests.log" 2>/dev/null; then
    scenario_result "btrfs_rw_interlock_erofs_without_flag" "PASS" "mutations refused with EROFS when flag unset"
    pass "EROFS without ephemeral flag"
else
    scenario_result "btrfs_rw_interlock_erofs_without_flag" "FAIL" "expected EROFS refusal test"
    fail "EROFS without ephemeral flag"
fi

echo ""
echo "=== Verify mutations allowed with ephemeral flag ==="
echo "Time: $(date -Iseconds)"
# The test btrfs_rw_interlock_allows_mutations_with_ack verifies this
if grep -q "btrfs_rw_interlock_allows_mutations_with_ack.*ok" "$E2E_LOG_DIR/interlock_tests.log" 2>/dev/null; then
    scenario_result "btrfs_rw_interlock_allows_with_flag" "PASS" "mutations allowed when ephemeral flag set"
    pass "mutations with ephemeral flag"
else
    scenario_result "btrfs_rw_interlock_allows_with_flag" "FAIL" "expected ephemeral allowance test"
    fail "mutations with ephemeral flag"
fi

echo ""
echo "=== Verify structured refusal log ==="
echo "Time: $(date -Iseconds)"
# Check that the helper function has the structured log
if grep -q 'error_class = "btrfs_rw_not_durable"' crates/ffs-core/src/lib.rs; then
    scenario_result "btrfs_rw_interlock_structured_log" "PASS" "structured refusal log present in code"
    pass "structured refusal log"
else
    scenario_result "btrfs_rw_interlock_structured_log" "FAIL" "missing structured refusal log"
    fail "structured refusal log"
fi

echo ""
echo "=== Verify all btrfs mutation functions have interlock ==="
echo "Time: $(date -Iseconds)"
# Check that key mutation functions call require_btrfs_rw_allowed
mutation_funcs=(
    "btrfs_create"
    "btrfs_mkdir"
    "btrfs_write"
    "btrfs_unlink_impl"
    "btrfs_rename"
    "btrfs_link"
    "btrfs_symlink"
    "btrfs_setattr"
    "btrfs_fallocate"
    "btrfs_setxattr"
    "btrfs_removexattr"
)
missing_interlock=0
for func in "${mutation_funcs[@]}"; do
    # Find the exact function impl (not test functions) and check for interlock
    # Use a pattern that matches "fn btrfs_X(" to avoid test function matches
    if ! grep -E "^\s+fn ${func}\(" crates/ffs-core/src/lib.rs -A 30 | grep -q "require_btrfs_rw_allowed"; then
        echo "  WARNING: $func may be missing interlock"
        missing_interlock=$((missing_interlock + 1))
    fi
done
if [[ $missing_interlock -eq 0 ]]; then
    scenario_result "btrfs_rw_interlock_all_mutations_guarded" "PASS" "all ${#mutation_funcs[@]} mutation functions have interlock"
    pass "all mutations guarded"
else
    scenario_result "btrfs_rw_interlock_all_mutations_guarded" "FAIL" "$missing_interlock functions missing interlock"
    fail "all mutations guarded"
fi

echo ""
echo "=============================================="
if [[ $FAIL -eq 0 ]]; then
    echo "PASSED"
    scenario_result "btrfs_rw_interlock_overall" "PASS" "all $PASS checks passed"
else
    echo "FAILED"
    scenario_result "btrfs_rw_interlock_overall" "FAIL" "$FAIL failures, $PASS passed"
fi
echo "=============================================="
echo "Duration: $(( $(date +%s) - ${E2E_START_TIME:-$(date +%s)} ))s"
echo "Log file: $E2E_LOG_FILE"

if [[ $FAIL -eq 0 ]]; then
    e2e_pass
fi
exit $FAIL
