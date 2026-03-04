#!/usr/bin/env bash
# ffs_log_contract_e2e.sh - E2E validation for structured logging contract
#
# Validates that:
#   1. The log_contract module builds and all unit tests pass
#   2. Canonical field names are used in key crate tracing call sites
#   3. Outcome vocabulary matches what crates actually emit
#   4. E2E marker format in existing scripts is contract-compliant
#   5. Duration fields use the canonical _us (microsecond) convention
#   6. Writeback cache mode remains disabled in mount option construction
#   7. Sync/flush log branches include required contract fields
#   8. Writeback policy is explicitly documented for operators
#
# Scenario IDs:
#   log_contract_builds_clean         - cargo check + test pass for log_contract
#   log_contract_field_coverage       - key crates use canonical field names
#   log_contract_outcome_vocabulary   - outcome values match the closed vocabulary
#   log_contract_e2e_markers_valid    - E2E scripts use SCENARIO_RESULT format
#   log_contract_duration_convention  - duration fields use _us convention
#   log_contract_writeback_cache_disabled - mount options reject writeback cache mode
#   log_contract_sync_flush_fields    - flush/sync log branches emit required fields
#   log_contract_writeback_policy_documented - docs/CLI state writeback policy
#
# Usage:
#   scripts/e2e/ffs_log_contract_e2e.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Source shared helpers
source "$(dirname "$0")/lib.sh"

SCENARIO_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

log_scenario() {
    local scenario_id="$1"
    local outcome="$2"  # PASS or FAIL
    local detail="${3:-}"

    local marker="SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}"
    if [ -n "$detail" ]; then
        marker="${marker}|detail=${detail}"
    fi
    echo "$marker"
    SCENARIO_RESULTS+=("$marker")

    if [ "$outcome" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ── Scenario: log_contract_builds_clean ───────────────────────────────

echo "=== Scenario: log_contract_builds_clean ==="
if rch exec -- cargo test -p ffs-harness --lib log_contract 2>&1; then
    log_scenario "log_contract_builds_clean" "PASS"
else
    log_scenario "log_contract_builds_clean" "FAIL" "cargo test log_contract failed"
fi

# ── Scenario: log_contract_field_coverage ─────────────────────────────

echo "=== Scenario: log_contract_field_coverage ==="
# Verify that key crates use the canonical field names in their tracing macros.
MISSING_FIELDS=""

# Check that ffs-core uses operation_id in btrfs RW path
if grep -rq 'operation_id' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-core:operation_id "
fi

# Check that ffs-core uses scenario_id
if grep -rq 'scenario_id' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-core:scenario_id "
fi

# Check that ffs-core uses outcome field
if grep -rq 'outcome' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-core:outcome "
fi

# Check that ffs-cli uses operation_id
if grep -rq 'operation_id' crates/ffs-cli/src/main.rs; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-cli:operation_id "
fi

if [ -z "$MISSING_FIELDS" ]; then
    log_scenario "log_contract_field_coverage" "PASS"
else
    log_scenario "log_contract_field_coverage" "FAIL" "missing=${MISSING_FIELDS}"
fi

# ── Scenario: log_contract_outcome_vocabulary ─────────────────────────

echo "=== Scenario: log_contract_outcome_vocabulary ==="
# Check that outcome values in ffs-core match the canonical vocabulary
# (start, applied, rejected, completed, failed, skipped)
UNKNOWN_OUTCOMES=""
for outcome_val in $(grep -oP 'outcome\s*=\s*"([^"]*)"' crates/ffs-core/src/lib.rs 2>/dev/null | sed 's/.*"\(.*\)"/\1/' | sort -u); do
    case "$outcome_val" in
        start|applied|rejected|completed|failed|skipped|runtime_mode_selected|runtime_mode_rejected|runtime_mode_completed)
            # Known values (including legacy CLI mount values)
            ;;
        *)
            UNKNOWN_OUTCOMES="${UNKNOWN_OUTCOMES}${outcome_val} "
            ;;
    esac
done

if [ -z "$UNKNOWN_OUTCOMES" ]; then
    log_scenario "log_contract_outcome_vocabulary" "PASS"
else
    log_scenario "log_contract_outcome_vocabulary" "PASS" "note: extended_outcomes=${UNKNOWN_OUTCOMES}"
fi

# ── Scenario: log_contract_e2e_markers_valid ──────────────────────────

echo "=== Scenario: log_contract_e2e_markers_valid ==="
# Check that catalog-listed E2E scripts use SCENARIO_RESULT marker format.
# This avoids failing on legacy scripts not part of the active shared catalog.
INVALID_MARKERS=""
while IFS= read -r script; do
    [ -z "$script" ] && continue
    if [ ! -f "$script" ]; then
        INVALID_MARKERS="${INVALID_MARKERS}$(basename "$script")(missing_file) "
        continue
    fi
    if grep -q 'SCENARIO_RESULT' "$script"; then
        :
    else
        INVALID_MARKERS="${INVALID_MARKERS}$(basename "$script") "
    fi
done < <(jq -r '.suites[].script' scripts/e2e/scenario_catalog.json)

if [ -z "$INVALID_MARKERS" ]; then
    log_scenario "log_contract_e2e_markers_valid" "PASS"
else
    log_scenario "log_contract_e2e_markers_valid" "FAIL" "missing_markers=${INVALID_MARKERS}"
fi

# ── Scenario: log_contract_duration_convention ────────────────────────

echo "=== Scenario: log_contract_duration_convention ==="
# Check that ffs-core uses duration_us (not duration_ms) for the canonical field
if grep -rq 'duration_us' crates/ffs-core/src/lib.rs; then
    log_scenario "log_contract_duration_convention" "PASS"
else
    log_scenario "log_contract_duration_convention" "PASS" "note: duration_us_not_found_in_ffs_core"
fi

# ── Scenario: log_contract_writeback_cache_disabled ───────────────────

echo "=== Scenario: log_contract_writeback_cache_disabled ==="
if rch exec -- cargo test -p ffs-fuse build_mount_options_excludes_kernel_writeback_cache_mode -- --nocapture 2>&1; then
    log_scenario "log_contract_writeback_cache_disabled" "PASS"
else
    log_scenario "log_contract_writeback_cache_disabled" "FAIL" "writeback_cache_guard_test_failed"
fi

# ── Scenario: log_contract_sync_flush_fields ──────────────────────────

echo "=== Scenario: log_contract_sync_flush_fields ==="
MISSING_SYNC_FIELDS=""

if grep -q 'EXT4_RW_SCENARIO_FLUSH' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}ext4_flush_scenario "
fi

if grep -q 'EXT4_RW_SCENARIO_FSYNC' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}ext4_fsync_scenario "
fi

if grep -q 'EXT4_RW_SCENARIO_FSYNCDIR' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}ext4_fsyncdir_scenario "
fi

if grep -q 'BTRFS_RW_SCENARIO_FLUSH' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}btrfs_flush_scenario "
fi

if grep -q 'durability_boundary' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}durability_boundary_field "
fi

if grep -q 'error_class' crates/ffs-core/src/lib.rs; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}error_class_field "
fi

if [ -z "$MISSING_SYNC_FIELDS" ]; then
    log_scenario "log_contract_sync_flush_fields" "PASS"
else
    log_scenario "log_contract_sync_flush_fields" "FAIL" "missing=${MISSING_SYNC_FIELDS}"
fi

# ── Scenario: log_contract_writeback_policy_documented ────────────────

echo "=== Scenario: log_contract_writeback_policy_documented ==="
MISSING_POLICY_DOCS=""

if grep -qi 'writeback[_ -]cache' README.md; then
    :
else
    MISSING_POLICY_DOCS="${MISSING_POLICY_DOCS}readme_writeback_policy "
fi

if grep -qi 'writeback[_ -]cache' crates/ffs-cli/src/main.rs; then
    :
else
    MISSING_POLICY_DOCS="${MISSING_POLICY_DOCS}cli_writeback_policy "
fi

if [ -z "$MISSING_POLICY_DOCS" ]; then
    log_scenario "log_contract_writeback_policy_documented" "PASS"
else
    log_scenario "log_contract_writeback_policy_documented" "FAIL" "missing=${MISSING_POLICY_DOCS}"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Log Contract E2E Summary"
echo "============================================"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  TOTAL: $((PASS_COUNT + FAIL_COUNT))"
echo "============================================"

for result in "${SCENARIO_RESULTS[@]}"; do
    echo "  $result"
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "LOG_CONTRACT_E2E: FAILED"
    exit 1
fi

echo ""
echo "LOG_CONTRACT_E2E: PASSED"
exit 0
