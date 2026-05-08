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

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_benchmark_expansion}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac

SCENARIO_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("$RCH_BIN" queue --json 2>/dev/null || true)"
    if [[ -z "$queue_json" ]]; then
        return 0
    fi
    ids="$(jq -r --arg cmd "$command_text" '
        .data.active_builds[]?
        | select(.project_id | startswith("frankenfs-"))
        | select(.command == $cmd)
        | .id
    ' <<<"$queue_json" || true)"
    for id in $ids; do
        if "$RCH_BIN" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

run_rch_capture() {
    local log_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    shift

    : >"$log_path"
    set +e
    RCH_VISIBILITY="$RCH_VISIBILITY" "$RCH_BIN" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                cancel_matching_rch_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
            return 99
        fi
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|log=${log_path}|status=${status}"
        return 0
    fi
    return "$status"
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

e2e_init "ffs_benchmark_expansion"

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
