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
#   benchmark_expansion_fixture_complete_self_check - fixture mode proves cataloged markers without cargo
#   benchmark_expansion_fixture_local_fallback_self_check - fixture mode proves local fallback rejection
#   benchmark_expansion_fixture_missing_remote_evidence_self_check - fixture mode proves missing remote evidence rejection
#
# Usage:
#   scripts/e2e/ffs_benchmark_expansion_e2e.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Source shared helpers
source "$(dirname "$0")/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_benchmark_expansion}"
RCH_CAPTURE_VISIBILITY="${FFS_BENCHMARK_EXPANSION_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_BENCHMARK_EXPANSION_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_BENCHMARK_EXPANSION_SKIP_SELF_CHECK:-0}"

e2e_rch_add_env_allowlist CARGO_TARGET_DIR

SCENARIO_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

print_rch_log() {
    local log_path="$1"
    if [[ -s "$log_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$log_path"
    fi
}

log_scenario() {
    local scenario_id="$1"
    local outcome="$2"  # PASS or FAIL
    local detail="${3:-}"

    local marker="SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}"
    if [ -n "$detail" ]; then
        marker="${marker}|detail=${detail}"
    fi
    e2e_log "$marker"
    SCENARIO_RESULTS+=("$marker")

    if [ "$outcome" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_BENCHMARK_EXPANSION_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        echo "Remote command finished: exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown benchmark expansion fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo check -p ffs-mvcc --benches"*)
        echo "    Finished dev [unoptimized + debuginfo] target(s) in 0.01s"
        ;;
    *"cargo check -p ffs-repair --benches"*)
        echo "    Finished dev [unoptimized + debuginfo] target(s) in 0.01s"
        ;;
    *"cargo test -p ffs-harness --lib benchmark_taxonomy::tests::canonical_taxonomy_has_expanded_suite_operations"*)
        printf '%s\n' \
            "running 1 test" \
            "test benchmark_taxonomy::tests::canonical_taxonomy_has_expanded_suite_operations ... ok"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/benchmark_expansion_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_BENCHMARK_EXPANSION_SELF_CHECK=0 \
        FFS_BENCHMARK_EXPANSION_SKIP_SELF_CHECK=1 \
        FFS_BENCHMARK_EXPANSION_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_benchmark_expansion_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic benchmark expansion wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-benchmark-expansion-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "bench_mvcc_expansion_compiles" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "bench_repair_compiles" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "expanded_taxonomy_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "expanded_thresholds_valid" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "record_script_covers_expansion" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        log_scenario "benchmark_expansion_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        log_scenario "benchmark_expansion_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        log_scenario "benchmark_expansion_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        log_scenario "benchmark_expansion_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        log_scenario "benchmark_expansion_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        log_scenario "benchmark_expansion_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_benchmark_expansion"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

# ── Scenario: bench_mvcc_expansion_compiles ───────────────────────────

e2e_log "=== Scenario: bench_mvcc_expansion_compiles ==="
MVCC_BENCH_LOG="$E2E_LOG_DIR/mvcc_bench_check.log"
if run_rch_capture "$MVCC_BENCH_LOG" cargo check -p ffs-mvcc --benches; then
    print_rch_log "$MVCC_BENCH_LOG"
    log_scenario "bench_mvcc_expansion_compiles" "PASS" "log=${MVCC_BENCH_LOG}"
else
    print_rch_log "$MVCC_BENCH_LOG"
    log_scenario "bench_mvcc_expansion_compiles" "FAIL" "cargo check ffs-mvcc benches failed"
fi

# ── Scenario: bench_repair_compiles ───────────────────────────────────

e2e_log "=== Scenario: bench_repair_compiles ==="
REPAIR_BENCH_LOG="$E2E_LOG_DIR/repair_bench_check.log"
if run_rch_capture "$REPAIR_BENCH_LOG" cargo check -p ffs-repair --benches; then
    print_rch_log "$REPAIR_BENCH_LOG"
    log_scenario "bench_repair_compiles" "PASS" "log=${REPAIR_BENCH_LOG}"
else
    print_rch_log "$REPAIR_BENCH_LOG"
    log_scenario "bench_repair_compiles" "FAIL" "cargo check ffs-repair benches failed"
fi

# ── Scenario: expanded_taxonomy_coverage ──────────────────────────────

e2e_log "=== Scenario: expanded_taxonomy_coverage ==="
TAXONOMY_COVERAGE_LOG="$E2E_LOG_DIR/expanded_taxonomy_coverage.log"
if run_rch_capture "$TAXONOMY_COVERAGE_LOG" cargo test -p ffs-harness --lib benchmark_taxonomy::tests::canonical_taxonomy_has_expanded_suite_operations; then
    print_rch_log "$TAXONOMY_COVERAGE_LOG"
    log_scenario "expanded_taxonomy_coverage" "PASS" "log=${TAXONOMY_COVERAGE_LOG}"
else
    print_rch_log "$TAXONOMY_COVERAGE_LOG"
    log_scenario "expanded_taxonomy_coverage" "FAIL" "expanded taxonomy coverage test failed"
fi

# ── Scenario: expanded_thresholds_valid ───────────────────────────────

e2e_log "=== Scenario: expanded_thresholds_valid ==="
THRESHOLDS_FILE="$REPO_ROOT/benchmarks/thresholds.toml"
EXPANDED_OPS=(
    cli_metadata_parse_conformance
    block_cache_arc_concurrent_hot_read_64threads block_cache_s3fifo_concurrent_hot_read_64threads
    block_cache_sharded_arc_concurrent_hot_read_64threads block_cache_sharded_s3fifo_concurrent_hot_read_64threads
    wal_commit_4k_sync
    wal_write_amplification_1block wal_write_amplification_16block
    mvcc_contention_2writers mvcc_contention_4writers mvcc_contention_8writers
    scrub_clean_256blocks scrub_corrupted_256blocks
    raptorq_encode_group_16blocks raptorq_decode_group_16blocks
    repair_symbol_refresh_staleness_latency
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

e2e_log "=== Scenario: record_script_covers_expansion ==="
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

e2e_log ""
e2e_log "============================================"
e2e_log "  Benchmark Expansion E2E Summary"
e2e_log "============================================"
e2e_log "  PASS: $PASS_COUNT"
e2e_log "  FAIL: $FAIL_COUNT"
e2e_log "  TOTAL: $((PASS_COUNT + FAIL_COUNT))"
e2e_log "============================================"

for result in "${SCENARIO_RESULTS[@]}"; do
    e2e_log "  $result"
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    e2e_log ""
    e2e_log "BENCHMARK_EXPANSION_E2E: FAILED"
    exit 1
fi

e2e_log ""
e2e_log "BENCHMARK_EXPANSION_E2E: PASSED"
exit 0
