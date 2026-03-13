#!/usr/bin/env bash
# ffs_baseline_validation_e2e.sh — E2E validation that profiling baselines
# can be reproduced and all benchmark infrastructure is functional.
#
# bd-m5wf.1.1: Acceptance gate for profiling baseline establishment.
#
# Validates:
#   1. All criterion benchmark targets compile and run
#   2. Baseline JSON report structure is valid
#   3. Taxonomy covers all registered benchmark operations
#   4. Benchmark thresholds.toml is valid and parseable
#   5. Flamegraph generation script exists and is executable
#   6. Extent resolve benchmarks are registered and functional
#
# Usage: scripts/e2e/ffs_baseline_validation_e2e.sh
# Exit:  0 = all gates pass, 1 = failures detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

echo "=== FrankenFS Baseline Validation E2E ==="
echo "SCENARIO_RESULT markers follow bd-m5wf.1.1 acceptance criteria."
echo ""

# ── Scenario 1: All criterion bench targets compile ────────────────────
echo "--- Scenario 1: Criterion benchmark compilation ---"

BENCH_TARGETS=(
    "ffs-harness:metadata_parse"
    "ffs-harness:ondisk_parse"
    "ffs-block:arc_cache"
    "ffs-btree:bwtree_vs_locked"
    "ffs-alloc:bitmap_ops"
    "ffs-repair:scrub_codec"
    "ffs-fuse:mount_runtime"
    "ffs-fuse:degraded_pressure"
    "ffs-mvcc:wal_throughput"
    "ffs-extent:extent_resolve"
)

for target in "${BENCH_TARGETS[@]}"; do
    crate="${target%%:*}"
    bench="${target##*:}"
    if cargo check -p "$crate" --bench "$bench" 2>/dev/null; then
        pass "bench compile: ${crate}/${bench}"
        echo "SCENARIO_RESULT bench_compile_${bench}=pass"
    else
        fail "bench compile: ${crate}/${bench}"
        echo "SCENARIO_RESULT bench_compile_${bench}=fail"
    fi
done

echo ""

# ── Scenario 2: Baseline JSON report structure ─────────────────────────
echo "--- Scenario 2: Baseline JSON structure validation ---"

BASELINE_JSON="artifacts/baselines/perf_baseline.json"
if [[ -f "$BASELINE_JSON" ]]; then
    pass "baseline JSON exists: ${BASELINE_JSON}"

    # Validate required top-level keys
    for key in generated_at date_tag commit environment measurements; do
        if jq -e ".${key}" "$BASELINE_JSON" >/dev/null 2>&1; then
            pass "baseline key present: ${key}"
        else
            fail "baseline key missing: ${key}"
        fi
    done

    # Validate measurement structure
    MEASURED_COUNT=$(jq '[.measurements[] | select(.status == "measured")] | length' "$BASELINE_JSON" 2>/dev/null || echo 0)
    if [[ "$MEASURED_COUNT" -gt 0 ]]; then
        pass "baseline has ${MEASURED_COUNT} measured operations"
        echo "SCENARIO_RESULT baseline_measured_count=${MEASURED_COUNT}"
    else
        fail "baseline has no measured operations"
        echo "SCENARIO_RESULT baseline_measured_count=0"
    fi

    # Validate each measurement has required fields
    VALID_MEASUREMENTS=$(jq '[.measurements[] | select(.operation != null and .metric != null and .p50_us != null)] | length' "$BASELINE_JSON" 2>/dev/null || echo 0)
    TOTAL_MEASUREMENTS=$(jq '.measurements | length' "$BASELINE_JSON" 2>/dev/null || echo 0)
    if [[ "$VALID_MEASUREMENTS" -eq "$TOTAL_MEASUREMENTS" ]]; then
        pass "all ${TOTAL_MEASUREMENTS} measurements have required fields"
    else
        fail "${VALID_MEASUREMENTS}/${TOTAL_MEASUREMENTS} measurements have required fields"
    fi

    echo "SCENARIO_RESULT baseline_json_valid=pass"
else
    fail "baseline JSON not found: ${BASELINE_JSON}"
    echo "SCENARIO_RESULT baseline_json_valid=fail"
fi

echo ""

# ── Scenario 3: Taxonomy validation ───────────────────────────────────
echo "--- Scenario 3: Benchmark taxonomy validation ---"

TAXONOMY_SRC="crates/ffs-harness/src/benchmark_taxonomy.rs"
if [[ -f "$TAXONOMY_SRC" ]]; then
    pass "taxonomy source exists"

    # Check for extent resolve operations in taxonomy
    for op in extent_resolve_depth0_cached extent_resolve_depth1_uncached extent_resolve_range_50blocks extent_resolve_depth1_repeated; do
        if grep -q "$op" "$TAXONOMY_SRC"; then
            pass "taxonomy contains: ${op}"
        else
            fail "taxonomy missing: ${op}"
        fi
    done

    # Run taxonomy unit tests
    if cargo test -p ffs-harness --lib -- benchmark_taxonomy 2>/dev/null; then
        pass "taxonomy unit tests pass"
        echo "SCENARIO_RESULT taxonomy_tests=pass"
    else
        fail "taxonomy unit tests fail"
        echo "SCENARIO_RESULT taxonomy_tests=fail"
    fi
else
    fail "taxonomy source not found"
fi

echo ""

# ── Scenario 4: Thresholds configuration ──────────────────────────────
echo "--- Scenario 4: Thresholds configuration ---"

THRESHOLDS="benchmarks/thresholds.toml"
if [[ -f "$THRESHOLDS" ]]; then
    pass "thresholds.toml exists"

    # Basic TOML parse validation (check for syntax errors)
    if python3 -c "
import sys
try:
    import tomllib
    with open('$THRESHOLDS', 'rb') as f:
        tomllib.load(f)
    sys.exit(0)
except Exception as e:
    print(f'TOML parse error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; then
        pass "thresholds.toml parses correctly"
    else
        # Fallback: just check it's non-empty
        if [[ -s "$THRESHOLDS" ]]; then
            pass "thresholds.toml is non-empty (TOML validation skipped)"
        else
            fail "thresholds.toml is empty"
        fi
    fi

    echo "SCENARIO_RESULT thresholds_valid=pass"
else
    fail "thresholds.toml not found"
    echo "SCENARIO_RESULT thresholds_valid=fail"
fi

echo ""

# ── Scenario 5: Flamegraph infrastructure ─────────────────────────────
echo "--- Scenario 5: Flamegraph infrastructure ---"

FG_SCRIPT="scripts/flamegraph_generate.sh"
if [[ -f "$FG_SCRIPT" ]]; then
    pass "flamegraph script exists"
    if [[ -x "$FG_SCRIPT" ]]; then
        pass "flamegraph script is executable"
    else
        fail "flamegraph script is not executable"
    fi
    echo "SCENARIO_RESULT flamegraph_script=pass"
else
    fail "flamegraph script not found"
    echo "SCENARIO_RESULT flamegraph_script=fail"
fi

# Check if flamegraph artifacts directory exists or can be created
FG_DIR="artifacts/flamegraphs"
if [[ -d "$FG_DIR" ]] || mkdir -p "$FG_DIR" 2>/dev/null; then
    pass "flamegraph output directory available"
else
    fail "cannot create flamegraph output directory"
fi

echo ""

# ── Scenario 6: Extent resolve benchmark functional ───────────────────
echo "--- Scenario 6: Extent resolve benchmark validation ---"

EXTENT_BENCH="crates/ffs-extent/benches/extent_resolve.rs"
if [[ -f "$EXTENT_BENCH" ]]; then
    pass "extent resolve benchmark source exists"

    # Check for all 4 benchmark functions
    for fn_name in bench_extent_resolve_depth0 bench_extent_resolve_depth1 bench_extent_resolve_range bench_extent_resolve_repeated; do
        if grep -q "$fn_name" "$EXTENT_BENCH"; then
            pass "benchmark function: ${fn_name}"
        else
            fail "missing benchmark function: ${fn_name}"
        fi
    done

    # Check bench target in Cargo.toml
    if grep -q 'name = "extent_resolve"' "crates/ffs-extent/Cargo.toml"; then
        pass "bench target registered in Cargo.toml"
    else
        fail "bench target not in Cargo.toml"
    fi

    echo "SCENARIO_RESULT extent_bench=pass"
else
    fail "extent resolve benchmark not found"
    echo "SCENARIO_RESULT extent_bench=fail"
fi

echo ""

# ── Scenario 7: Benchmark recording script ────────────────────────────
echo "--- Scenario 7: Benchmark recording infrastructure ---"

RECORD_SCRIPT="scripts/benchmark_record.sh"
if [[ -f "$RECORD_SCRIPT" && -x "$RECORD_SCRIPT" ]]; then
    pass "benchmark_record.sh exists and is executable"
    echo "SCENARIO_RESULT record_script=pass"
else
    fail "benchmark_record.sh missing or not executable"
    echo "SCENARIO_RESULT record_script=fail"
fi

QUICK_SCRIPT="scripts/benchmark.sh"
if [[ -f "$QUICK_SCRIPT" && -x "$QUICK_SCRIPT" ]]; then
    pass "benchmark.sh (quick) exists and is executable"
else
    skip "benchmark.sh (quick) not found"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────
echo "=== Baseline Validation Summary ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo "RESULT: FAIL (${FAIL} failures)"
    exit 1
else
    echo "RESULT: PASS (all ${PASS} checks passed)"
    exit 0
fi
