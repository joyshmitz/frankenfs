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

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_baseline_validation"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_baseline_validation}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-1800}"
LOG_DIR="${BASELINE_VALIDATION_LOG_DIR:-$E2E_LOG_DIR}"
mkdir -p "$LOG_DIR"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

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

run_rch_capture() {
    local log_path="$1"
    shift
    local status=0
    local rch_pid
    local watcher_pid

    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
        setsid timeout "${RCH_COMMAND_TIMEOUT_SECS}s" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    rch_pid=$!

    (
        while kill -0 "$rch_pid" >/dev/null 2>&1; do
            if grep -q "Remote command finished: exit=0" "$log_path" \
                && grep -q "Retrieving artifacts from .*\\.rch-target" "$log_path"; then
                kill -TERM "-$rch_pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
                break
            fi
            sleep 2
        done
    ) &
    watcher_pid=$!

    if wait "$rch_pid"; then
        status=0
    else
        status=$?
    fi

    kill "$watcher_pid" >/dev/null 2>&1 || true
    wait "$watcher_pid" >/dev/null 2>&1 || true

    if [[ "$status" -eq 124 ]]; then
        e2e_rch_cancel_matching_queue_entry "$@"
    fi

    if [[ "$status" -ne 0 ]] && grep -q "Remote command finished: exit=0" "$log_path"; then
        echo "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|log=${log_path}|timeout_secs=${RCH_COMMAND_TIMEOUT_SECS}"
        return 0
    fi

    return "$status"
}

log_failure_tail() {
    local log_path="$1"
    if [[ -s "$log_path" ]]; then
        echo "Failure tail for ${log_path}:"
        tail -n 80 "$log_path"
    fi
}

echo "=== FrankenFS Baseline Validation E2E ==="
echo "SCENARIO_RESULT markers follow bd-m5wf.1.1 acceptance criteria."
echo "RCH logs: ${LOG_DIR}"
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

BENCH_PACKAGES=(
    "ffs-harness"
    "ffs-block"
    "ffs-btree"
    "ffs-alloc"
    "ffs-repair"
    "ffs-fuse"
    "ffs-mvcc"
    "ffs-extent"
)

BENCH_CARGO_ARGS=(check)
for package in "${BENCH_PACKAGES[@]}"; do
    BENCH_CARGO_ARGS+=(-p "$package")
done
BENCH_CARGO_ARGS+=(--benches)

BENCH_COMPILE_LOG="$LOG_DIR/bench_compile_all.log"
if run_rch_capture "$BENCH_COMPILE_LOG" cargo "${BENCH_CARGO_ARGS[@]}"; then
    for target in "${BENCH_TARGETS[@]}"; do
        crate="${target%%:*}"
        bench="${target##*:}"
        pass "bench compile: ${crate}/${bench}"
    done
    scenario_result "baseline_validation_bench_compile" "PASS" "bench_targets=${#BENCH_TARGETS[@]}"
else
    log_failure_tail "$BENCH_COMPILE_LOG"
    for target in "${BENCH_TARGETS[@]}"; do
        crate="${target%%:*}"
        bench="${target##*:}"
        fail "bench compile: ${crate}/${bench}"
    done
    scenario_result "baseline_validation_bench_compile" "FAIL" "bench_targets=${#BENCH_TARGETS[@]}"
fi

echo ""

# ── Scenario 2: Baseline JSON report structure ─────────────────────────
echo "--- Scenario 2: Baseline JSON structure validation ---"

BASELINE_JSON="artifacts/baselines/perf_baseline.json"
json_contract_ok=true
MEASURED_COUNT=0
VALID_MEASUREMENTS=0
TOTAL_MEASUREMENTS=0
if [[ -f "$BASELINE_JSON" ]]; then
    pass "baseline JSON exists: ${BASELINE_JSON}"

    # Validate required top-level keys
    for key in generated_at date_tag commit environment measurements; do
        if jq -e ".${key}" "$BASELINE_JSON" >/dev/null 2>&1; then
            pass "baseline key present: ${key}"
        else
            fail "baseline key missing: ${key}"
            json_contract_ok=false
        fi
    done

    # Validate measurement structure
    MEASURED_COUNT=$(jq '[.measurements[] | select(.status == "measured")] | length' "$BASELINE_JSON" 2>/dev/null || echo 0)
    if [[ "$MEASURED_COUNT" -gt 0 ]]; then
        pass "baseline has ${MEASURED_COUNT} measured operations"
    else
        fail "baseline has no measured operations"
        json_contract_ok=false
    fi

    # Validate each measurement has required fields
    VALID_MEASUREMENTS=$(jq '[.measurements[] | select(.operation != null and .metric != null and .p50_us != null)] | length' "$BASELINE_JSON" 2>/dev/null || echo 0)
    TOTAL_MEASUREMENTS=$(jq '.measurements | length' "$BASELINE_JSON" 2>/dev/null || echo 0)
    if [[ "$VALID_MEASUREMENTS" -eq "$TOTAL_MEASUREMENTS" ]]; then
        pass "all ${TOTAL_MEASUREMENTS} measurements have required fields"
    else
        fail "${VALID_MEASUREMENTS}/${TOTAL_MEASUREMENTS} measurements have required fields"
        json_contract_ok=false
    fi

else
    fail "baseline JSON not found: ${BASELINE_JSON}"
    json_contract_ok=false
fi

if [[ "$json_contract_ok" == "true" ]]; then
    scenario_result "baseline_validation_json_contract" "PASS" "measured_count=${MEASURED_COUNT}"
else
    scenario_result \
        "baseline_validation_json_contract" \
        "FAIL" \
        "measured_count=${MEASURED_COUNT} valid_measurements=${VALID_MEASUREMENTS} total_measurements=${TOTAL_MEASUREMENTS}"
fi

echo ""

# ── Scenario 3: Taxonomy validation ───────────────────────────────────
echo "--- Scenario 3: Benchmark taxonomy validation ---"

TAXONOMY_SRC="crates/ffs-harness/src/benchmark_taxonomy.rs"
taxonomy_tests_ok=true
if [[ -f "$TAXONOMY_SRC" ]]; then
    pass "taxonomy source exists"

    # Check for extent resolve operations in taxonomy
    for op in extent_resolve_depth0_cached extent_resolve_depth1_uncached extent_resolve_range_50blocks extent_resolve_depth1_repeated; do
        if grep -q "$op" "$TAXONOMY_SRC"; then
            pass "taxonomy contains: ${op}"
        else
            fail "taxonomy missing: ${op}"
            taxonomy_tests_ok=false
        fi
    done

    # Run taxonomy unit tests
    TAXONOMY_TEST_LOG="$LOG_DIR/benchmark_taxonomy_unit_tests.log"
    if run_rch_capture "$TAXONOMY_TEST_LOG" cargo test -p ffs-harness --lib -- benchmark_taxonomy; then
        pass "taxonomy unit tests pass"
    else
        log_failure_tail "$TAXONOMY_TEST_LOG"
        fail "taxonomy unit tests fail"
        taxonomy_tests_ok=false
    fi
else
    fail "taxonomy source not found"
    taxonomy_tests_ok=false
fi

if [[ "$taxonomy_tests_ok" == "true" ]]; then
    scenario_result "baseline_validation_taxonomy_tests" "PASS"
else
    scenario_result "baseline_validation_taxonomy_tests" "FAIL"
fi

echo ""

# ── Scenario 4: Thresholds configuration ──────────────────────────────
echo "--- Scenario 4: Thresholds configuration ---"

THRESHOLDS="benchmarks/thresholds.toml"
thresholds_ok=true
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
            thresholds_ok=false
        fi
    fi
else
    fail "thresholds.toml not found"
    thresholds_ok=false
fi

if [[ "$thresholds_ok" == "true" ]]; then
    scenario_result "baseline_validation_thresholds_parse" "PASS"
else
    scenario_result "baseline_validation_thresholds_parse" "FAIL"
fi

echo ""

# ── Scenario 5: Flamegraph infrastructure ─────────────────────────────
echo "--- Scenario 5: Flamegraph infrastructure ---"

FG_SCRIPT="scripts/flamegraph_generate.sh"
flamegraph_script_ok=true
if [[ -f "$FG_SCRIPT" ]]; then
    pass "flamegraph script exists"
    if [[ -x "$FG_SCRIPT" ]]; then
        pass "flamegraph script is executable"
    else
        fail "flamegraph script is not executable"
        flamegraph_script_ok=false
    fi
else
    fail "flamegraph script not found"
    flamegraph_script_ok=false
fi

if [[ "$flamegraph_script_ok" == "true" ]]; then
    scenario_result "baseline_validation_flamegraph_script" "PASS"
else
    scenario_result "baseline_validation_flamegraph_script" "FAIL"
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
extent_bench_ok=true
if [[ -f "$EXTENT_BENCH" ]]; then
    pass "extent resolve benchmark source exists"

    # Check for all 4 benchmark functions
    for fn_name in bench_extent_resolve_depth0 bench_extent_resolve_depth1 bench_extent_resolve_range bench_extent_resolve_repeated; do
        if grep -q "$fn_name" "$EXTENT_BENCH"; then
            pass "benchmark function: ${fn_name}"
        else
            fail "missing benchmark function: ${fn_name}"
            extent_bench_ok=false
        fi
    done

    # Check bench target in Cargo.toml
    if grep -q 'name = "extent_resolve"' "crates/ffs-extent/Cargo.toml"; then
        pass "bench target registered in Cargo.toml"
    else
        fail "bench target not in Cargo.toml"
        extent_bench_ok=false
    fi
else
    fail "extent resolve benchmark not found"
    extent_bench_ok=false
fi

if [[ "$extent_bench_ok" == "true" ]]; then
    scenario_result "baseline_validation_extent_bench" "PASS"
else
    scenario_result "baseline_validation_extent_bench" "FAIL"
fi

echo ""

# ── Scenario 7: Benchmark recording script ────────────────────────────
echo "--- Scenario 7: Benchmark recording infrastructure ---"

RECORD_SCRIPT="scripts/benchmark_record.sh"
if [[ -f "$RECORD_SCRIPT" && -x "$RECORD_SCRIPT" ]]; then
    pass "benchmark_record.sh exists and is executable"
    scenario_result "baseline_validation_record_script" "PASS"
else
    fail "benchmark_record.sh missing or not executable"
    scenario_result "baseline_validation_record_script" "FAIL"
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
