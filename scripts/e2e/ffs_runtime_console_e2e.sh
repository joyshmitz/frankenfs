#!/usr/bin/env bash
# ffs_runtime_console_e2e.sh - non-permissioned validator lane for the
# operator runtime console artifact contract (bd-wtyxs.4).
#
# This wrapper is dry and non-mutating: it never mounts a filesystem, never
# runs xfstests, and never starts a permissioned large-host campaign. It only
# exercises `ffs-harness validate-runtime-console` against checked-in
# `runtime_console_report` fixtures and proves the validator accepts honest
# console artifacts and rejects promotion/staleness/oversize violations.
#
# The console artifact is operational observability only. Nothing this lane
# emits upgrades `swarm.responsiveness` or `adaptive_runtime` readiness.

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

FIXTURE_DIR="$REPO_ROOT/conformance/fixtures/runtime_console"
REFERENCE_TIMESTAMP="${FFS_RUNTIME_CONSOLE_REFERENCE:-2026-05-20T12:00:00Z}"
SELF_CHECK="${FFS_RUNTIME_CONSOLE_SELF_CHECK:-0}"

e2e_init "ffs_runtime_console"

HARNESS_BIN=""

# Build the validator. The rch hook routes the cargo lane to a remote worker
# when one is admissible and falls back locally otherwise; either way the
# console fixture validation below runs as a pure local, non-mutating read.
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
    local stdout_path="$E2E_LOG_DIR/${fixture%.json}.stdout"
    local stderr_path="$E2E_LOG_DIR/${fixture%.json}.stderr"

    if [[ ! -f "$fixture_path" ]]; then
        scenario_result "$scenario_id" "FAIL" "missing fixture ${fixture}"
        e2e_fail "fixture not found: $fixture_path"
        return
    fi

    set +e
    "$HARNESS_BIN" validate-runtime-console \
        --report "$fixture_path" \
        --reference-timestamp "$REFERENCE_TIMESTAMP" \
        --format json \
        >"$stdout_path" 2>"$stderr_path"
    local status=$?
    set -e

    local valid
    valid=$(sed -n 's/.*"valid": *\(true\|false\).*/\1/p' "$stdout_path" | head -n 1)

    case "$expect" in
        valid)
            if [[ "$status" -eq 0 && "$valid" == "true" ]]; then
                scenario_result "$scenario_id" "PASS" "fixture=${fixture} verdict=valid"
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
                    "fixture=${fixture} verdict=rejected issues=${issue_count}"
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

# Wrapper self-check: prove this lane catches a corrupted fixture that a naive
# pass-through would miss. A deliberately broken artifact must be rejected.
run_self_check() {
    e2e_step "Runtime console wrapper self-check"
    build_harness
    local broken="$E2E_TEMP_DIR/broken_runtime_console.json"
    # Valid managed fixture with the request classes deliberately desynced.
    sed 's/"requests_metadata": 500/"requests_metadata": 4000/' \
        "$FIXTURE_DIR/managed_clean_shutdown.json" >"$broken"
    set +e
    "$HARNESS_BIN" validate-runtime-console --report "$broken" \
        --reference-timestamp "$REFERENCE_TIMESTAMP" >"$E2E_TEMP_DIR/self_check.out" 2>&1
    local status=$?
    set -e
    if [[ "$status" -ne 0 ]] && grep -q '"valid": false' "$E2E_TEMP_DIR/self_check.out"; then
        scenario_result "runtime_console_self_check_catches_corruption" "PASS" \
            "broken fixture rejected status=${status}"
    else
        scenario_result "runtime_console_self_check_catches_corruption" "FAIL" \
            "broken fixture not rejected status=${status}"
        e2e_fail "self-check did not catch a corrupted console artifact"
    fi
    # A missing report path must be a hard error, not a silent empty pass: this
    # is the disabled-console / host-skip guard — no artifact, no evidence.
    set +e
    "$HARNESS_BIN" validate-runtime-console --report "$E2E_TEMP_DIR/does_not_exist.json" \
        >"$E2E_TEMP_DIR/missing.out" 2>&1
    status=$?
    set -e
    if [[ "$status" -ne 0 ]]; then
        scenario_result "runtime_console_self_check_missing_report" "PASS" \
            "missing report errored status=${status}"
    else
        scenario_result "runtime_console_self_check_missing_report" "FAIL" \
            "missing report did not error"
        e2e_fail "self-check: missing console report should be a hard error"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "runtime console wrapper self-check"
    exit 0
fi

build_harness

e2e_step "Validate honest console artifacts (must pass)"
check_fixture "runtime_console_managed_clean_shutdown" \
    "managed_clean_shutdown.json" "valid"
check_fixture "runtime_console_per_core_skewed_distribution" \
    "per_core_skewed.json" "valid"
check_fixture "runtime_console_backpressure_critical_shed" \
    "backpressure_critical.json" "valid"

e2e_step "Reject contract violations (must fail closed)"
check_fixture "runtime_console_malformed_advisory_promotion" \
    "malformed_advisory_promotion.json" "rejected"
check_fixture "runtime_console_stale_timestamp_refusal" \
    "stale_timestamp.json" "rejected"
check_fixture "runtime_console_future_timestamp_refusal" \
    "future_timestamp.json" "rejected"
check_fixture "runtime_console_oversized_output_refusal" \
    "oversized_capture.json" "rejected"

e2e_step "Guard the disabled-console / host-skip path (no artifact, no evidence)"
set +e
"$HARNESS_BIN" validate-runtime-console \
    --report "$E2E_TEMP_DIR/no_console_artifact.json" \
    >"$E2E_LOG_DIR/missing_report.stdout" 2>"$E2E_LOG_DIR/missing_report.stderr"
MISSING_STATUS=$?
set -e
if [[ "$MISSING_STATUS" -ne 0 ]]; then
    scenario_result "runtime_console_missing_report_refusal" "PASS" \
        "absent artifact errored status=${MISSING_STATUS}"
else
    scenario_result "runtime_console_missing_report_refusal" "FAIL" \
        "absent artifact did not error"
    e2e_fail "a disabled console must not produce a silent passing artifact"
fi

e2e_pass "runtime console validator lane: fixtures validated and contract violations rejected"
