#!/usr/bin/env bash
# ffs_evidence_metrics_presets_e2e.sh - Verify evidence metrics presets via CLI
#
# Usage: ./scripts/e2e/ffs_evidence_metrics_presets_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

e2e_init "ffs_evidence_metrics_presets"

e2e_step "Scenario 1: metrics aggregate preset"
bundle_json="$E2E_LOG_DIR/metrics_bundle.json"
cat >"$bundle_json" <<'JSON'
{
  "metrics": {
    "requests_total": 100,
    "requests_ok": 97,
    "requests_err": 3,
    "bytes_read": 8192,
    "requests_throttled": 4,
    "requests_shed": 1
  },
  "cache": {
    "cache_hits": 80,
    "cache_misses": 20,
    "cache_evictions": 5,
    "cache_dirty_count": 9,
    "writeback_queue_depth": 3,
    "hit_rate": 0.8
  },
  "mvcc": {
    "active_snapshots": 2,
    "commit_rate": 15.0,
    "conflict_rate": 0.125,
    "abort_rate": 0.125,
    "version_chain_max_length": 6,
    "prune_throughput": 42.0,
    "commit_attempts_total": 80,
    "commit_successes_total": 70,
    "conflicts_total": 10,
    "aborts_total": 10,
    "pruned_versions_total": 120,
    "commit_latency_us": {
      "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 7}],
      "inf_count": 0,
      "sum": 800,
      "count": 8
    },
    "conflict_resolution_latency_us": {
      "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 3}],
      "inf_count": 0,
      "sum": 250,
      "count": 4
    }
  },
  "repair_live": {
    "groups_scrubbed": 12,
    "corruption_detected": 2,
    "decode_attempts": 5,
    "decode_successes": 4,
    "symbol_refresh_count": 8,
    "symbol_staleness_max_seconds": 12.5
  }
}
JSON
metrics_out="$E2E_LOG_DIR/metrics.out"
if rch exec -- cargo run -q -p ffs-cli -- evidence --preset metrics --json "$bundle_json" \
    >"$metrics_out" 2>&1 \
    && grep -q '"preset": "metrics"' "$metrics_out" \
    && grep -q '"repair_freshness": "fresh"' "$metrics_out" \
    && grep -q '"mvcc_contention_level": "high"' "$metrics_out"; then
    scenario_result "evidence_metrics_bundle" "PASS" "Aggregate metrics preset returned derived analyses"
else
    scenario_result "evidence_metrics_bundle" "FAIL" "Aggregate metrics preset failed"
fi

e2e_step "Scenario 2: cache preset"
cache_json="$E2E_LOG_DIR/cache_metrics.json"
cat >"$cache_json" <<'JSON'
{
  "cache_hits": 90,
  "cache_misses": 10,
  "cache_evictions": 3,
  "cache_dirty_count": 40,
  "writeback_queue_depth": 12,
  "hit_rate": 0.9
}
JSON
cache_out="$E2E_LOG_DIR/cache.out"
if rch exec -- cargo run -q -p ffs-cli -- evidence --preset cache --json "$cache_json" \
    >"$cache_out" 2>&1 \
    && grep -q '"preset": "cache"' "$cache_out" \
    && grep -q '"dirty_pressure": "high"' "$cache_out" \
    && grep -q '"writeback_pressure": "queued"' "$cache_out"; then
    scenario_result "evidence_metrics_cache" "PASS" "Cache preset returned hit/miss analysis"
else
    scenario_result "evidence_metrics_cache" "FAIL" "Cache preset failed"
fi

e2e_step "Scenario 3: mvcc preset"
mvcc_json="$E2E_LOG_DIR/mvcc_metrics.json"
cat >"$mvcc_json" <<'JSON'
{
  "active_snapshots": 3,
  "commit_rate": 10.0,
  "conflict_rate": 0.05,
  "abort_rate": 0.02,
  "version_chain_max_length": 4,
  "prune_throughput": 11.0,
  "commit_attempts_total": 50,
  "commit_successes_total": 45,
  "conflicts_total": 2,
  "aborts_total": 1,
  "pruned_versions_total": 99,
  "commit_latency_us": {
    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 4}],
    "inf_count": 0,
    "sum": 200,
    "count": 5
  },
  "conflict_resolution_latency_us": {
    "buckets": [{"le": 10, "count": 1}, {"le": 100, "count": 1}],
    "inf_count": 0,
    "sum": 50,
    "count": 2
  }
}
JSON
mvcc_out="$E2E_LOG_DIR/mvcc.out"
if rch exec -- cargo run -q -p ffs-cli -- evidence --preset mvcc --json "$mvcc_json" \
    >"$mvcc_out" 2>&1 \
    && grep -q '"preset": "mvcc"' "$mvcc_out" \
    && grep -q '"commit_success_rate": 0.9' "$mvcc_out" \
    && grep -q '"contention_level": "elevated"' "$mvcc_out"; then
    scenario_result "evidence_metrics_mvcc" "PASS" "MVCC preset returned contention analysis"
else
    scenario_result "evidence_metrics_mvcc" "FAIL" "MVCC preset failed"
fi

e2e_step "Scenario 4: repair-live preset"
repair_json="$E2E_LOG_DIR/repair_live_metrics.json"
cat >"$repair_json" <<'JSON'
{
  "groups_scrubbed": 20,
  "corruption_detected": 5,
  "decode_attempts": 8,
  "decode_successes": 6,
  "symbol_refresh_count": 14,
  "symbol_staleness_max_seconds": 120.0
}
JSON
repair_out="$E2E_LOG_DIR/repair_live.out"
if rch exec -- cargo run -q -p ffs-cli -- evidence --preset repair-live --json "$repair_json" \
    >"$repair_out" 2>&1 \
    && grep -q '"preset": "repair-live"' "$repair_out" \
    && grep -q '"decode_success_rate": 0.75' "$repair_out" \
    && grep -q '"freshness": "aging"' "$repair_out"; then
    scenario_result "evidence_metrics_repair_live" "PASS" "Repair-live preset returned freshness assessment"
else
    scenario_result "evidence_metrics_repair_live" "FAIL" "Repair-live preset failed"
fi

e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
fi

e2e_log "OVERALL: PASS"
