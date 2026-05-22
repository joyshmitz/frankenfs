#!/usr/bin/env bash
# ffs_btrfs_tree_log_fast_fsync_e2e.sh - E2E gate for bd-xuo95.39.
#
# Validates that btrfs fsync writes a replayable tree-log, crash remounts apply
# the log as a read overlay, LabRuntime crash coverage passes, and the focused
# latency metric reports the tree-log surface against the A4 full-commit scan
# baseline.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_btrfs_tree_log_fast_fsync"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_btrfs_tree_log_fast_fsync}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_TREE_LOG_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"

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
echo "Bead: bd-xuo95.39 btrfs tree-log fast-fsync optimization"
echo ""

e2e_step "Scenario 1: ffs-core tree-log tests pass"
TEST_LOG="$E2E_LOG_DIR/tree_log_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-core --all-targets tree_log -- --nocapture; then
    if grep -q "btrfs_write_fsync_persists_replayable_tree_log .* ok" "$TEST_LOG" \
        && grep -q "btrfs_tree_log_lab_crash_replay_makes_fsynced_file_visible .* ok" "$TEST_LOG"; then
        scenario_result "tree_log_unit_and_lab_tests" "PASS" "focused tree-log unit and LabRuntime tests passed"
    else
        scenario_result "tree_log_unit_and_lab_tests" "FAIL" "expected focused test names missing from log"
    fi
else
    scenario_result "tree_log_unit_and_lab_tests" "FAIL" "cargo test failed"
    tail -40 "$TEST_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi

e2e_step "Scenario 2: latency metric emitted"
if grep -q "TREE_LOG_FAST_FSYNC_LATENCY" "$TEST_LOG"; then
    metric_line="$(grep "TREE_LOG_FAST_FSYNC_LATENCY" "$TEST_LOG" | tail -1)"
    scenario_result "tree_log_latency_metric" "PASS" "$metric_line"
else
    scenario_result "tree_log_latency_metric" "FAIL" "missing TREE_LOG_FAST_FSYNC_LATENCY metric"
fi

e2e_step "Scenario 3: fast fsync structured log contract present"
if grep -q 'commit_strategy = "tree_log_fast_fsync"' crates/ffs-core/src/lib.rs \
    && grep -q 'full_commit_required = false' crates/ffs-core/src/lib.rs \
    && grep -q 'btrfs_tree_log_items' crates/ffs-core/src/lib.rs; then
    scenario_result "tree_log_fast_fsync_contract" "PASS" "fast-fsync log fields and mount replay overlay present"
else
    scenario_result "tree_log_fast_fsync_contract" "FAIL" "missing fast-fsync contract fields or replay overlay"
fi

e2e_step "Summary"
echo "Total scenarios: $TOTAL"
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_log "RESULT|outcome=PASS|detail=btrfs tree-log fast fsync e2e passed ($PASS_COUNT/$TOTAL scenarios)"
    exit 0
else
    e2e_log "RESULT|outcome=FAIL|detail=btrfs tree-log fast fsync e2e failed ($FAIL_COUNT/$TOTAL scenarios failed)"
    exit 1
fi
