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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_evidence_metrics_presets}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_EVIDENCE_METRICS_PRESETS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_EVIDENCE_METRICS_PRESETS_SKIP_SELF_CHECK:-0}"

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

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
    local output_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    shift

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_VISIBILITY="$RCH_VISIBILITY" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" "$RCH_BIN" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                cancel_matching_rch_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
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
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_EVIDENCE_METRICS_PRESETS_FIXTURE_CASE:-complete}"

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
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown evidence metrics presets fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"--preset metrics "*)
        printf '%s\n' '{"preset": "metrics", "repair_freshness": "fresh", "mvcc_contention_level": "high"}'
        ;;
    *"--preset cache "*)
        printf '%s\n' '{"preset": "cache", "dirty_pressure": "high", "writeback_pressure": "queued"}'
        ;;
    *"--preset mvcc "*)
        printf '%s\n' '{"preset": "mvcc", "commit_success_rate": 0.9, "contention_level": "elevated"}'
        ;;
    *"--preset repair-live "*)
        printf '%s\n' '{"preset": "repair-live", "decode_success_rate": 0.75, "freshness": "aging"}'
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
    local child_log="$E2E_LOG_DIR/evidence_metrics_presets_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_EVIDENCE_METRICS_PRESETS_SELF_CHECK=0 \
        FFS_EVIDENCE_METRICS_PRESETS_SKIP_SELF_CHECK=1 \
        FFS_EVIDENCE_METRICS_PRESETS_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_evidence_metrics_presets_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic evidence metrics presets wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir
    stub_path="$E2E_LOG_DIR/rch-evidence-metrics-presets-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$result_dir/metrics.out" ]] \
        && [[ -f "$result_dir/cache.out" ]] \
        && [[ -f "$result_dir/mvcc.out" ]] \
        && [[ -f "$result_dir/repair_live.out" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "evidence_metrics_bundle" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_metrics_cache" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_metrics_mvcc" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_metrics_repair_live" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q '"mvcc_contention_level": "high"' "$result_dir/metrics.out" \
        && grep -q '"dirty_pressure": "high"' "$result_dir/cache.out" \
        && grep -q '"contention_level": "elevated"' "$result_dir/mvcc.out" \
        && grep -q '"freshness": "aging"' "$result_dir/repair_live.out"; then
        scenario_result "evidence_metrics_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_metrics_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Evidence metrics presets complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "evidence_metrics_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_metrics_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Evidence metrics presets local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "evidence_metrics_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_metrics_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Evidence metrics presets missing remote evidence fixture self-check failed"
    fi
}

print_rch_output() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
}

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

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/evidence_metrics_presets"
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: metrics aggregate preset"
bundle_json="$RCH_INPUT_DIR/metrics_bundle.json"
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
if run_rch_capture "$metrics_out" cargo run -q -p ffs-cli -- evidence --preset metrics --json "$bundle_json" \
    && grep -q '"preset": "metrics"' "$metrics_out" \
    && grep -q '"repair_freshness": "fresh"' "$metrics_out" \
    && grep -q '"mvcc_contention_level": "high"' "$metrics_out"; then
    print_rch_output "$metrics_out"
    scenario_result "evidence_metrics_bundle" "PASS" "Aggregate metrics preset returned derived analyses; output=${metrics_out}"
else
    print_rch_output "$metrics_out"
    scenario_result "evidence_metrics_bundle" "FAIL" "Aggregate metrics preset failed; output=${metrics_out}"
fi

e2e_step "Scenario 2: cache preset"
cache_json="$RCH_INPUT_DIR/cache_metrics.json"
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
if run_rch_capture "$cache_out" cargo run -q -p ffs-cli -- evidence --preset cache --json "$cache_json" \
    && grep -q '"preset": "cache"' "$cache_out" \
    && grep -q '"dirty_pressure": "high"' "$cache_out" \
    && grep -q '"writeback_pressure": "queued"' "$cache_out"; then
    print_rch_output "$cache_out"
    scenario_result "evidence_metrics_cache" "PASS" "Cache preset returned hit/miss analysis; output=${cache_out}"
else
    print_rch_output "$cache_out"
    scenario_result "evidence_metrics_cache" "FAIL" "Cache preset failed; output=${cache_out}"
fi

e2e_step "Scenario 3: mvcc preset"
mvcc_json="$RCH_INPUT_DIR/mvcc_metrics.json"
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
if run_rch_capture "$mvcc_out" cargo run -q -p ffs-cli -- evidence --preset mvcc --json "$mvcc_json" \
    && grep -q '"preset": "mvcc"' "$mvcc_out" \
    && grep -q '"commit_success_rate": 0.9' "$mvcc_out" \
    && grep -q '"contention_level": "elevated"' "$mvcc_out"; then
    print_rch_output "$mvcc_out"
    scenario_result "evidence_metrics_mvcc" "PASS" "MVCC preset returned contention analysis; output=${mvcc_out}"
else
    print_rch_output "$mvcc_out"
    scenario_result "evidence_metrics_mvcc" "FAIL" "MVCC preset failed; output=${mvcc_out}"
fi

e2e_step "Scenario 4: repair-live preset"
repair_json="$RCH_INPUT_DIR/repair_live_metrics.json"
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
if run_rch_capture "$repair_out" cargo run -q -p ffs-cli -- evidence --preset repair-live --json "$repair_json" \
    && grep -q '"preset": "repair-live"' "$repair_out" \
    && grep -q '"decode_success_rate": 0.75' "$repair_out" \
    && grep -q '"freshness": "aging"' "$repair_out"; then
    print_rch_output "$repair_out"
    scenario_result "evidence_metrics_repair_live" "PASS" "Repair-live preset returned freshness assessment; output=${repair_out}"
else
    print_rch_output "$repair_out"
    scenario_result "evidence_metrics_repair_live" "FAIL" "Repair-live preset failed; output=${repair_out}"
fi

e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
fi

e2e_log "OVERALL: PASS"
