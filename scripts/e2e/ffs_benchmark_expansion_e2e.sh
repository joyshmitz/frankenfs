#!/usr/bin/env bash
# ffs_benchmark_expansion_e2e.sh - E2E validation for bd-h6nz.5.2 benchmark expansion
#
# Validates that:
#   1. New Criterion bench targets compile (ffs-mvcc write amp + contention)
#   2. New Criterion bench targets compile (ffs-repair scrub/codec)
#   3. Expanded taxonomy covers all new operations
#   4. New thresholds.toml entries are valid and well-ordered
#   5. Benchmark record script references all new taxonomy IDs
#
# Scenario IDs:
#   bench_mvcc_expansion_compiles    - ffs-mvcc bench targets build
#   bench_repair_compiles            - ffs-repair bench targets build
#   expanded_taxonomy_coverage       - taxonomy includes all bd-5.2 ops
#   expanded_thresholds_valid        - new thresholds.toml entries parse
#   record_script_covers_expansion   - benchmark_record.sh references new ops
#
# Usage:
#   scripts/e2e/ffs_benchmark_expansion_e2e.sh
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

# ── Scenario: bench_mvcc_expansion_compiles ───────────────────────────

echo "=== Scenario: bench_mvcc_expansion_compiles ==="
if rch exec -- cargo check -p ffs-mvcc --benches 2>&1; then
    log_scenario "bench_mvcc_expansion_compiles" "PASS"
else
    log_scenario "bench_mvcc_expansion_compiles" "FAIL" "cargo check ffs-mvcc benches failed"
fi

# ── Scenario: bench_repair_compiles ───────────────────────────────────

echo "=== Scenario: bench_repair_compiles ==="
if rch exec -- cargo check -p ffs-repair --benches 2>&1; then
    log_scenario "bench_repair_compiles" "PASS"
else
    log_scenario "bench_repair_compiles" "FAIL" "cargo check ffs-repair benches failed"
fi

# ── Scenario: expanded_taxonomy_coverage ──────────────────────────────

echo "=== Scenario: expanded_taxonomy_coverage ==="
if rch exec -- cargo test -p ffs-harness --lib benchmark_taxonomy::tests::canonical_taxonomy_has_expanded_suite_operations 2>&1; then
    log_scenario "expanded_taxonomy_coverage" "PASS"
else
    log_scenario "expanded_taxonomy_coverage" "FAIL" "expanded taxonomy coverage test failed"
fi

# ── Scenario: expanded_thresholds_valid ───────────────────────────────

echo "=== Scenario: expanded_thresholds_valid ==="
THRESHOLDS_FILE="$REPO_ROOT/benchmarks/thresholds.toml"
EXPANDED_OPS=(
    wal_write_amplification_1block wal_write_amplification_16block
    mvcc_contention_2writers mvcc_contention_4writers mvcc_contention_8writers
    scrub_clean_256blocks scrub_corrupted_256blocks
    raptorq_encode_group_16blocks raptorq_decode_group_16blocks
)
if python3 -c "
import tomllib, sys
with open('$THRESHOLDS_FILE', 'rb') as f:
    data = tomllib.load(f)
ops = data.get('operation_thresholds', {})
expanded = $( printf '%s\n' "${EXPANDED_OPS[@]}" | python3 -c "import sys; print([l.strip() for l in sys.stdin])" )
missing = [op for op in expanded if op not in ops]
if missing:
    print(f'Missing from thresholds.toml: {missing}', file=sys.stderr)
    sys.exit(1)
for op in expanded:
    cfg = ops[op]
    assert cfg['warn_percent'] < cfg['fail_percent'], f'{op}: warn >= fail'
    assert cfg.get('noise_floor_percent', 0) < cfg['warn_percent'], f'{op}: noise >= warn'
print(f'Validated {len(expanded)} expanded threshold entries')
" 2>&1; then
    log_scenario "expanded_thresholds_valid" "PASS"
else
    log_scenario "expanded_thresholds_valid" "FAIL" "expanded thresholds validation failed"
fi

# ── Scenario: record_script_covers_expansion ──────────────────────────

echo "=== Scenario: record_script_covers_expansion ==="
RECORD_SCRIPT="$REPO_ROOT/scripts/benchmark_record.sh"
MISSING_IN_RECORD=""
for op in "${EXPANDED_OPS[@]}"; do
    if ! grep -q "$op" "$RECORD_SCRIPT"; then
        MISSING_IN_RECORD="${MISSING_IN_RECORD}${op} "
    fi
done

if [ -z "$MISSING_IN_RECORD" ]; then
    log_scenario "record_script_covers_expansion" "PASS"
else
    log_scenario "record_script_covers_expansion" "FAIL" "missing_in_record=${MISSING_IN_RECORD}"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Benchmark Expansion E2E Summary"
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
    echo "BENCHMARK_EXPANSION_E2E: FAILED"
    exit 1
fi

echo ""
echo "BENCHMARK_EXPANSION_E2E: PASSED"
exit 0
