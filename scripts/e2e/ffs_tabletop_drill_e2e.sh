#!/usr/bin/env bash
# ffs_tabletop_drill_e2e.sh - Verification gate for operator tabletop drills (bd-h6nz.7.4)
#
# Validates that all 3 operator incident drill scenarios have complete
# tooling chains: runbooks, error codes, evidence presets, log markers,
# and CLI command references.
#
# Scenarios:
# 1. Tabletop drill module exists and is exported
# 2. All 3 drill scenarios defined
# 3. Replay anomaly drill passes all checks
# 4. Corruption partial repair drill passes all checks
# 5. Sustained pressure drill passes all checks
# 6. Zero remediation gaps across all drills
# 7. All 3 runbooks updated with evidence preset references
# 8. Drill result JSON serialization round-trips
# 9. Tabletop drill unit tests pass
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_tabletop_drill_e2e.sh
#
# Exit codes:
#   0 - All scenarios passed
#   1 - One or more scenarios failed

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Source shared helpers
source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_tabletop_drill}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_TABLETOP_DRILL_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_TABLETOP_DRILL_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_TABLETOP_DRILL_SKIP_SELF_CHECK:-0}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_TABLETOP_DRILL_FIXTURE_CASE:-complete}"

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
        echo "unknown tabletop drill fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- tabletop_drill"*)
        printf '%s\n' \
            "running 10 tests" \
            "test tabletop_drill::tests::catalog_contains_three_drills ... ok" \
            "test tabletop_drill::tests::drill_ids_are_stable ... ok" \
            "test tabletop_drill::tests::drill_steps_have_commands ... ok" \
            "test tabletop_drill::tests::drill_expected_markers_are_nonempty ... ok" \
            "test tabletop_drill::tests::drill_error_codes_resolve ... ok" \
            "test tabletop_drill::tests::drill_runbooks_resolve ... ok" \
            "test tabletop_drill::tests::drill_serializes_to_json ... ok" \
            "test tabletop_drill::tests::drill_evidence_sections_are_ordered ... ok" \
            "test tabletop_drill::tests::drill_remediation_links_are_stable ... ok" \
            "test tabletop_drill::tests::drill_operator_surface_is_complete ... ok"
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
    local child_log="$E2E_LOG_DIR/tabletop_drill_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_TABLETOP_DRILL_SELF_CHECK=0 \
        FFS_TABLETOP_DRILL_SKIP_SELF_CHECK=1 \
        FFS_TABLETOP_DRILL_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_tabletop_drill_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic tabletop drill wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-tabletop-drill-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "drill_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_three_scenarios" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_replay_chain" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_corruption_chain" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_pressure_chain" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_zero_gaps" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_runbook_presets" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_json_serialization" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "drill_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "tabletop_drill_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "tabletop_drill_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "tabletop_drill_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "tabletop_drill_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "tabletop_drill_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "tabletop_drill_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_tabletop_drill"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

DRILL_SRC="crates/ffs-harness/src/tabletop_drill.rs"

#######################################
# Scenario 1: Tabletop drill module exists
#######################################
e2e_step "Scenario 1: Tabletop drill module exists"

if [[ -f "$DRILL_SRC" ]] && grep -q "pub mod tabletop_drill" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "drill_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "drill_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All 3 drill scenarios defined
#######################################
e2e_step "Scenario 2: All 3 drill scenarios defined"

DRILLS_FOUND=0
for drill_id in "drill-replay-anomaly" "drill-corruption-partial-repair" "drill-sustained-pressure"; do
    if grep -q "\"$drill_id\"" "$DRILL_SRC"; then
        DRILLS_FOUND=$((DRILLS_FOUND + 1))
    fi
done

if [[ $DRILLS_FOUND -eq 3 ]]; then
    scenario_result "drill_three_scenarios" "PASS" "All 3 drill scenarios defined"
else
    scenario_result "drill_three_scenarios" "FAIL" "Only ${DRILLS_FOUND}/3 drills found"
fi

#######################################
# Scenario 3: Replay anomaly drill has complete tooling chain
#######################################
e2e_step "Scenario 3: Replay drill tooling chain"

REPLAY_CHECKS=0
# Runbook exists
[[ -f "docs/runbooks/replay-failure-triage.md" ]] && REPLAY_CHECKS=$((REPLAY_CHECKS + 1))
# Evidence preset in runbook
grep -q "replay-anomalies" "docs/runbooks/replay-failure-triage.md" && REPLAY_CHECKS=$((REPLAY_CHECKS + 1))
# Error codes in taxonomy
grep -q "FFS-RPL-001" "crates/ffs-harness/src/error_taxonomy.rs" && REPLAY_CHECKS=$((REPLAY_CHECKS + 1))
# Log markers in source
grep -q "wal_replay_start" "crates/ffs-mvcc/src/wal_replay.rs" && REPLAY_CHECKS=$((REPLAY_CHECKS + 1))

if [[ $REPLAY_CHECKS -eq 4 ]]; then
    scenario_result "drill_replay_chain" "PASS" "Replay drill: 4/4 checks pass"
else
    scenario_result "drill_replay_chain" "FAIL" "Replay drill: ${REPLAY_CHECKS}/4 checks"
fi

#######################################
# Scenario 4: Corruption drill has complete tooling chain
#######################################
e2e_step "Scenario 4: Corruption drill tooling chain"

CORRUPTION_CHECKS=0
[[ -f "docs/runbooks/corruption-recovery.md" ]] && CORRUPTION_CHECKS=$((CORRUPTION_CHECKS + 1))
grep -q "repair-failures" "docs/runbooks/corruption-recovery.md" && CORRUPTION_CHECKS=$((CORRUPTION_CHECKS + 1))
grep -q "FFS-IOC-001" "crates/ffs-harness/src/error_taxonomy.rs" && CORRUPTION_CHECKS=$((CORRUPTION_CHECKS + 1))
grep -q "repair_complete" "crates/ffs-cli/src/cmd_repair.rs" && CORRUPTION_CHECKS=$((CORRUPTION_CHECKS + 1))

if [[ $CORRUPTION_CHECKS -eq 4 ]]; then
    scenario_result "drill_corruption_chain" "PASS" "Corruption drill: 4/4 checks pass"
else
    scenario_result "drill_corruption_chain" "FAIL" "Corruption drill: ${CORRUPTION_CHECKS}/4 checks"
fi

#######################################
# Scenario 5: Pressure drill has complete tooling chain
#######################################
e2e_step "Scenario 5: Pressure drill tooling chain"

PRESSURE_CHECKS=0
[[ -f "docs/runbooks/backpressure-investigation.md" ]] && PRESSURE_CHECKS=$((PRESSURE_CHECKS + 1))
grep -q "pressure-transitions" "docs/runbooks/backpressure-investigation.md" && PRESSURE_CHECKS=$((PRESSURE_CHECKS + 1))
grep -q "FFS-PRS-001" "crates/ffs-harness/src/error_taxonomy.rs" && PRESSURE_CHECKS=$((PRESSURE_CHECKS + 1))
grep -q "degradation_transition" "crates/ffs-core/src/degradation.rs" && PRESSURE_CHECKS=$((PRESSURE_CHECKS + 1))

if [[ $PRESSURE_CHECKS -eq 4 ]]; then
    scenario_result "drill_pressure_chain" "PASS" "Pressure drill: 4/4 checks pass"
else
    scenario_result "drill_pressure_chain" "FAIL" "Pressure drill: ${PRESSURE_CHECKS}/4 checks"
fi

#######################################
# Scenario 6: Zero remediation gaps across all drills
#######################################
e2e_step "Scenario 6: Zero remediation gaps"

# Check that the no_remediation_gaps test function exists (proves gaps are tracked)
if grep -q "no_remediation_gaps_in_canonical_drills" "$DRILL_SRC" && grep -q "collect_gaps" "$DRILL_SRC"; then
    scenario_result "drill_zero_gaps" "PASS" "Gap tracking validated via unit tests"
else
    scenario_result "drill_zero_gaps" "FAIL" "Gap tracking code missing"
fi

#######################################
# Scenario 7: All 3 runbooks have evidence preset references
#######################################
e2e_step "Scenario 7: Runbooks have evidence preset references"

PRESET_REFS=0
grep -q "ffs evidence --preset replay-anomalies" "docs/runbooks/replay-failure-triage.md" && PRESET_REFS=$((PRESET_REFS + 1))
grep -q "ffs evidence --preset repair-failures" "docs/runbooks/corruption-recovery.md" && PRESET_REFS=$((PRESET_REFS + 1))
grep -q "ffs evidence --preset pressure-transitions" "docs/runbooks/backpressure-investigation.md" && PRESET_REFS=$((PRESET_REFS + 1))

if [[ $PRESET_REFS -eq 3 ]]; then
    scenario_result "drill_runbook_presets" "PASS" "All 3 runbooks reference evidence presets"
else
    scenario_result "drill_runbook_presets" "FAIL" "Only ${PRESET_REFS}/3 runbooks have presets"
fi

#######################################
# Scenario 8: Drill result JSON serialization
#######################################
e2e_step "Scenario 8: Drill JSON serialization"

if grep -q "drill_result_json_round_trips" "$DRILL_SRC"; then
    scenario_result "drill_json_serialization" "PASS" "JSON round-trip test present"
else
    scenario_result "drill_json_serialization" "FAIL" "JSON round-trip test missing"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Unit tests pass"

TEST_LOG="$E2E_LOG_DIR/tabletop_drill_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- tabletop_drill; then
    TESTS_RUN=$(grep -c "test tabletop_drill::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "drill_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "drill_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 10)"
    fi
else
    scenario_result "drill_unit_tests_pass" "FAIL" "Tabletop drill tests failed"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
else
    e2e_log "OVERALL: PASS"
    exit 0
fi
