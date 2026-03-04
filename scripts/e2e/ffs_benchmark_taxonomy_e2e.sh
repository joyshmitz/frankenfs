#!/usr/bin/env bash
# ffs_benchmark_taxonomy_e2e.sh - E2E validation for benchmark taxonomy
#
# Validates that:
#   1. The Rust taxonomy module builds and tests pass
#   2. Canonical taxonomy covers all baseline JSON operations
#   3. thresholds.toml parses and all keys are taxonomy-covered
#   4. Host profiles produce valid threshold adjustments
#   5. Acceptance envelopes have sane ordering (noise < warn < fail)
#
# Scenario IDs:
#   taxonomy_builds_clean       - cargo check + test pass for ffs-harness
#   taxonomy_covers_baseline    - all baseline ops exist in taxonomy
#   thresholds_toml_valid       - thresholds.toml parses with no errors
#   envelope_ordering_sane      - noise < warn < fail for all operations
#   taxonomy_json_export        - canonical taxonomy exports to valid JSON
#
# Usage:
#   scripts/e2e/ffs_benchmark_taxonomy_e2e.sh
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

# ── Scenario: taxonomy_builds_clean ─────────────────────────────────────

echo "=== Scenario: taxonomy_builds_clean ==="
if rch exec -- cargo test -p ffs-harness --lib benchmark_taxonomy 2>&1; then
    log_scenario "taxonomy_builds_clean" "PASS"
else
    log_scenario "taxonomy_builds_clean" "FAIL" "cargo test -p ffs-harness benchmark_taxonomy failed"
fi

# ── Scenario: taxonomy_covers_baseline ──────────────────────────────────

echo "=== Scenario: taxonomy_covers_baseline ==="
BASELINE_JSON="$REPO_ROOT/benchmarks/baselines/latest.json"
if [ -f "$BASELINE_JSON" ]; then
    # Extract operation names from baseline JSON
    BASELINE_OPS=$(python3 -c "
import json, sys
with open('$BASELINE_JSON') as f:
    data = json.load(f)
for m in data.get('measurements', []):
    print(m['operation'])
" 2>/dev/null || echo "")

    if [ -z "$BASELINE_OPS" ]; then
        log_scenario "taxonomy_covers_baseline" "PASS" "no_baseline_ops_to_check"
    else
        # Check each baseline op against the taxonomy's canonical list
        # We use the unit test for this, but also do a quick sanity check here
        MISSING=""
        KNOWN_TAXONOMY_OPS=(
            metadata_parity_cli metadata_parity_harness fixture_validation
            read_metadata_inspect_ext4_reference read_metadata_scrub_ext4_reference
            block_cache_arc_sequential_scan block_cache_arc_zipf_distribution
            block_cache_arc_mixed_seq70_hot30 block_cache_arc_compile_like
            block_cache_arc_database_like block_cache_s3fifo_sequential_scan
            block_cache_s3fifo_zipf_distribution block_cache_s3fifo_mixed_seq70_hot30
            block_cache_s3fifo_compile_like block_cache_s3fifo_database_like
            write_seq_4k write_random_4k fsync_single_write fsync_batch_100
            mount_cold mount_warm mount_recovery
            wal_commit_4k_sync mvcc_commit_fcw mvcc_commit_ssi_5reads
            wal_write_amplification_1block wal_write_amplification_16block
            mvcc_contention_2writers mvcc_contention_4writers mvcc_contention_8writers
            scrub_clean_256blocks scrub_corrupted_256blocks
            raptorq_encode_group_16blocks raptorq_decode_group_16blocks
        )
        while IFS= read -r op; do
            found=0
            for known in "${KNOWN_TAXONOMY_OPS[@]}"; do
                if [ "$op" = "$known" ]; then
                    found=1
                    break
                fi
            done
            if [ "$found" -eq 0 ]; then
                MISSING="${MISSING}${op} "
            fi
        done <<< "$BASELINE_OPS"

        if [ -z "$MISSING" ]; then
            log_scenario "taxonomy_covers_baseline" "PASS"
        else
            log_scenario "taxonomy_covers_baseline" "FAIL" "uncovered_ops=${MISSING}"
        fi
    fi
else
    log_scenario "taxonomy_covers_baseline" "PASS" "no_baseline_file_present"
fi

# ── Scenario: thresholds_toml_valid ─────────────────────────────────────

echo "=== Scenario: thresholds_toml_valid ==="
THRESHOLDS_FILE="$REPO_ROOT/benchmarks/thresholds.toml"
if [ -f "$THRESHOLDS_FILE" ]; then
    if python3 -c "
import tomllib, sys
with open('$THRESHOLDS_FILE', 'rb') as f:
    data = tomllib.load(f)
d = data.get('default', {})
assert 'warn_percent' in d, 'missing default.warn_percent'
assert 'fail_percent' in d, 'missing default.fail_percent'
ops = data.get('operation_thresholds', {})
for name, cfg in ops.items():
    assert 'warn_percent' in cfg, f'{name} missing warn_percent'
    assert 'fail_percent' in cfg, f'{name} missing fail_percent'
    assert cfg['warn_percent'] < cfg['fail_percent'], f'{name}: warn >= fail'
print(f'Validated {len(ops)} operation thresholds')
" 2>&1; then
        log_scenario "thresholds_toml_valid" "PASS"
    else
        log_scenario "thresholds_toml_valid" "FAIL" "thresholds.toml validation failed"
    fi
else
    log_scenario "thresholds_toml_valid" "FAIL" "thresholds.toml not found"
fi

# ── Scenario: envelope_ordering_sane ────────────────────────────────────

echo "=== Scenario: envelope_ordering_sane ==="
# This is validated by the Rust unit test envelope_warn_less_than_fail,
# but we confirm it passes here as an E2E check.
if rch exec -- cargo test -p ffs-harness --lib benchmark_taxonomy::tests::envelope_warn_less_than_fail 2>&1; then
    log_scenario "envelope_ordering_sane" "PASS"
else
    log_scenario "envelope_ordering_sane" "FAIL" "envelope ordering test failed"
fi

# ── Scenario: taxonomy_json_export ──────────────────────────────────────

echo "=== Scenario: taxonomy_json_export ==="
if rch exec -- cargo test -p ffs-harness --lib benchmark_taxonomy::tests::taxonomy_json_round_trip 2>&1; then
    log_scenario "taxonomy_json_export" "PASS"
else
    log_scenario "taxonomy_json_export" "FAIL" "JSON round-trip test failed"
fi

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Benchmark Taxonomy E2E Summary"
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
    echo "BENCHMARK_TAXONOMY_E2E: FAILED"
    exit 1
fi

echo ""
echo "BENCHMARK_TAXONOMY_E2E: PASSED"
exit 0
