#!/usr/bin/env bash
# ffs_numa_allocation_placement_e2e.sh - non-permissioned replay validator lane
# for the NUMA allocation placement evidence contract (bd-53b28.4).
#
# This wrapper is dry and non-mutating: it never mounts a filesystem, never runs
# a permissioned large-host swarm campaign, and never runs xfstests. It only
# exercises `ffs-harness validate-numa-allocation-placement` against checked-in
# replay fixtures and proves the validator accepts honest placement evidence and
# rejects stale topology and swarm.responsiveness promotion.
#
# NUMA allocation placement reports are advisory replay/downgrade evidence only.
# Nothing this lane emits upgrades `swarm.responsiveness`; the authoritative
# large-host campaign is bd-rchk0.53.8.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

FIXTURE_DIR="$REPO_ROOT/conformance/fixtures/numa_allocation_placement"
# Fixed topology-freshness reference so fixture validation is deterministic.
REFERENCE_UNIX_SECS="${FFS_NUMA_PLACEMENT_REFERENCE:-1779000000}"
SELF_CHECK="${FFS_NUMA_PLACEMENT_SELF_CHECK:-0}"

e2e_init "ffs_numa_allocation_placement"

HARNESS_BIN=""

build_harness() {
    e2e_step "Build ffs-harness validator (cargo lane)"
    local build_log="$E2E_LOG_DIR/cargo_build.log"
    if ! cargo build --quiet -p ffs-harness --bin ffs-harness >"$build_log" 2>&1; then
        cat "$build_log" >&2
        e2e_fail "cargo build -p ffs-harness failed; see $build_log"
    fi
    local target_dir
    target_dir=$(cargo metadata --no-deps --format-version 1 2>/dev/null \
        | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
    HARNESS_BIN="${target_dir:-$REPO_ROOT/target}/debug/ffs-harness"
    if [[ ! -x "$HARNESS_BIN" ]]; then
        e2e_fail "ffs-harness binary not found at $HARNESS_BIN"
    fi
    e2e_log "Validator binary: $HARNESS_BIN"
}

# Validate one fixture and assert the expected verdict.
#   $1 - scenario id   $2 - fixture file   $3 - expect: valid|rejected
check_fixture() {
    local scenario_id="$1"
    local fixture="$2"
    local expect="$3"
    local fixture_path="$FIXTURE_DIR/$fixture"
    local stdout_path="$E2E_LOG_DIR/${fixture%.json}.report.json"
    local summary_path="$E2E_LOG_DIR/${fixture%.json}.report.md"
    local stderr_path="$E2E_LOG_DIR/${fixture%.json}.stderr"

    if [[ ! -f "$fixture_path" ]]; then
        scenario_result "$scenario_id" "FAIL" "missing fixture ${fixture}"
        e2e_fail "fixture not found: $fixture_path"
        return
    fi

    local fixture_hash
    fixture_hash=$(sha256sum "$fixture_path" | cut -d' ' -f1)

    set +e
    "$HARNESS_BIN" validate-numa-allocation-placement \
        --report "$fixture_path" \
        --reference-unix-secs "$REFERENCE_UNIX_SECS" \
        --format json \
        --out "$stdout_path" \
        --summary-out "$summary_path" \
        >"$E2E_LOG_DIR/${fixture%.json}.stdout" 2>"$stderr_path"
    local status=$?
    set -e

    local valid
    valid=$(sed -n 's/.*"valid": *\(true\|false\).*/\1/p' "$stdout_path" 2>/dev/null | head -n 1)

    case "$expect" in
        valid)
            if [[ "$status" -eq 0 && "$valid" == "true" ]]; then
                scenario_result "$scenario_id" "PASS" \
                    "fixture=${fixture} verdict=valid sha256=${fixture_hash}"
            else
                scenario_result "$scenario_id" "FAIL" \
                    "fixture=${fixture} expected valid got status=${status} valid=${valid}"
                e2e_fail "expected ${fixture} to validate"
            fi
            ;;
        rejected)
            if [[ "$status" -ne 0 && "$valid" == "false" ]]; then
                local issue_count
                issue_count=$(grep -c '"path":' "$stdout_path" || true)
                scenario_result "$scenario_id" "PASS" \
                    "fixture=${fixture} verdict=rejected issues=${issue_count} sha256=${fixture_hash}"
            else
                scenario_result "$scenario_id" "FAIL" \
                    "fixture=${fixture} expected rejection got status=${status} valid=${valid}"
                e2e_fail "expected ${fixture} to be rejected"
            fi
            ;;
        *)
            e2e_fail "unknown expectation: $expect"
            ;;
    esac
}

run_self_check() {
    e2e_step "NUMA allocation placement wrapper self-check"
    build_harness
    local broken="$E2E_TEMP_DIR/broken_numa_placement.json"
    # Honest balanced fixture with the p99 outcome flipped to a false `helped`.
    sed 's/"observed_p99_micros": 3600/"observed_p99_micros": 9000/' \
        "$FIXTURE_DIR/balanced_numa.json" >"$broken"
    set +e
    "$HARNESS_BIN" validate-numa-allocation-placement --report "$broken" \
        --reference-unix-secs "$REFERENCE_UNIX_SECS" \
        >"$E2E_TEMP_DIR/self_check.out" 2>&1
    local status=$?
    set -e
    if [[ "$status" -ne 0 ]] && grep -q '"valid": false' "$E2E_TEMP_DIR/self_check.out"; then
        scenario_result "numa_placement_self_check_catches_corruption" "PASS" \
            "p99 attribution mismatch rejected status=${status}"
    else
        scenario_result "numa_placement_self_check_catches_corruption" "FAIL" \
            "corrupted placement report not rejected status=${status}"
        e2e_fail "self-check did not catch a corrupted placement report"
    fi
    set +e
    "$HARNESS_BIN" validate-numa-allocation-placement \
        --report "$E2E_TEMP_DIR/does_not_exist.json" \
        >"$E2E_TEMP_DIR/missing.out" 2>&1
    status=$?
    set -e
    if [[ "$status" -ne 0 ]]; then
        scenario_result "numa_placement_self_check_missing_report" "PASS" \
            "missing report errored status=${status}"
    else
        scenario_result "numa_placement_self_check_missing_report" "FAIL" \
            "missing report did not error"
        e2e_fail "self-check: missing placement report should be a hard error"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "NUMA allocation placement wrapper self-check"
    exit 0
fi

build_harness

e2e_step "Validate honest NUMA placement replay evidence (must pass)"
check_fixture "numa_placement_balanced_numa_replay" \
    "balanced_numa.json" "valid"
check_fixture "numa_placement_skewed_metadata_hotshards" \
    "skewed_metadata_hotshards.json" "valid"
check_fixture "numa_placement_preferred_node_exhaustion" \
    "preferred_node_exhaustion.json" "valid"
check_fixture "numa_placement_cross_node_fallback" \
    "cross_node_fallback.json" "valid"
check_fixture "numa_placement_repair_scrub_interference" \
    "repair_scrub_interference.json" "valid"
check_fixture "numa_placement_unknown_topology_fallback" \
    "unknown_topology.json" "valid"

e2e_step "Reject contract violations (must fail closed)"
check_fixture "numa_placement_stale_topology_refusal" \
    "stale_topology.json" "rejected"
check_fixture "numa_placement_swarm_promotion_refusal" \
    "swarm_promotion.json" "rejected"

e2e_pass "NUMA allocation placement validator lane: replay fixtures validated and violations rejected"
