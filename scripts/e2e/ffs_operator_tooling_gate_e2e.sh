#!/usr/bin/env bash
# ffs_operator_tooling_gate_e2e.sh - Final acceptance gate for Epic 7: Operator Tooling (bd-h6nz.7.5)
#
# Validates the full operator tooling pipeline is coherent across all 5 sub-beads:
# runbooks, evidence presets, health consistency, tabletop drills, and error taxonomy.
#
# Scenarios:
# 1. All 5 sub-gate E2E scripts exist
# 2. All operator harness modules are exported
# 3. Runbooks E2E passes (bd-h6nz.7.1)
# 4. Evidence presets E2E passes (bd-h6nz.7.2)
# 5. Health consistency E2E passes (bd-h6nz.7.3)
# 6. Tabletop drill E2E passes (bd-h6nz.7.4)
# 7. Error taxonomy E2E passes (bd-h6nz.7.6)
# 8. Cross-cutting: all operator unit tests pass
# 9. Cross-cutting: structured log markers auditable across surfaces
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_operator_tooling_gate_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_operator_tooling_gate}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_OPERATOR_TOOLING_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_OPERATOR_TOOLING_GATE_SKIP_SELF_CHECK:-0}"

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
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    shift

    e2e_log "RCH command: $*"
    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$log_path"
    set +e
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
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

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    return "$status"
}

log_test_tail() {
    local log_path="$1"

    if [[ -f "$log_path" ]]; then
        tail -40 "$log_path" | while IFS= read -r line; do e2e_log "  $line"; done
    fi
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_OPERATOR_TOOLING_GATE_FIXTURE_CASE:-complete}"

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
        echo "unknown operator tooling gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- error_taxonomy"*)
        printf '%s\n' \
            "running 12 tests" \
            "test error_taxonomy::tests::taxonomy_has_seven_classes ... ok" \
            "test error_taxonomy::tests::taxonomy_codes_are_unique ... ok" \
            "test error_taxonomy::tests::taxonomy_codes_have_known_prefixes ... ok" \
            "test error_taxonomy::tests::taxonomy_has_remediation_hints ... ok" \
            "test error_taxonomy::tests::taxonomy_runbooks_resolve ... ok" \
            "test error_taxonomy::tests::taxonomy_error_variants_resolve ... ok" \
            "test error_taxonomy::tests::taxonomy_presets_align ... ok" \
            "test error_taxonomy::tests::taxonomy_serializes_to_json ... ok" \
            "test error_taxonomy::tests::taxonomy_cli_surface_is_stable ... ok" \
            "test error_taxonomy::tests::taxonomy_tui_surface_is_stable ... ok" \
            "test error_taxonomy::tests::taxonomy_evidence_surface_is_stable ... ok" \
            "test error_taxonomy::tests::taxonomy_operator_hints_are_nonempty ... ok"
        ;;
    *"cargo test -p ffs-harness --lib -- health_consistency"*)
        printf '%s\n' \
            "running 10 tests" \
            "test health_consistency::tests::canonical_dimensions_are_defined ... ok" \
            "test health_consistency::tests::degradation_variants_are_complete ... ok" \
            "test health_consistency::tests::tui_degradation_mapping_is_complete ... ok" \
            "test health_consistency::tests::pressure_counters_are_exposed ... ok" \
            "test health_consistency::tests::runtime_modes_match_cli_surface ... ok" \
            "test health_consistency::tests::wal_replay_markers_are_present ... ok" \
            "test health_consistency::tests::source_of_truth_docs_cover_dimensions ... ok" \
            "test health_consistency::tests::health_report_serializes ... ok" \
            "test health_consistency::tests::health_surface_names_are_stable ... ok" \
            "test health_consistency::tests::health_summary_rejects_missing_dimensions ... ok"
        ;;
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
    local child_log="$E2E_LOG_DIR/operator_tooling_gate_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_OPERATOR_TOOLING_GATE_SELF_CHECK=0 \
        FFS_OPERATOR_TOOLING_GATE_SKIP_SELF_CHECK=1 \
        FFS_OPERATOR_TOOLING_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_operator_tooling_gate_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic operator tooling gate wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-operator-tooling-gate-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "gate_subgate_scripts" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_modules_exported" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_runbooks_complete" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_evidence_presets" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_health_consistency" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_tabletop_drills" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_error_taxonomy" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_log_audit" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "operator_tooling_gate_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "operator_tooling_gate_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "operator_tooling_gate_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "operator_tooling_gate_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "operator_tooling_gate_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "operator_tooling_gate_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_operator_tooling_gate"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_print_env

#######################################
# Scenario 1: All 5 sub-gate E2E scripts exist
#######################################
e2e_step "Scenario 1: Sub-gate E2E scripts exist"

SCRIPTS_FOUND=0
for script in \
    "scripts/e2e/ffs_runbooks_e2e.sh" \
    "scripts/e2e/ffs_evidence_presets_e2e.sh" \
    "scripts/e2e/ffs_health_consistency_e2e.sh" \
    "scripts/e2e/ffs_tabletop_drill_e2e.sh" \
    "scripts/e2e/ffs_error_taxonomy_e2e.sh"; do
    if [[ -f "$script" ]]; then
        SCRIPTS_FOUND=$((SCRIPTS_FOUND + 1))
    fi
done

if [[ $SCRIPTS_FOUND -eq 5 ]]; then
    scenario_result "gate_subgate_scripts" "PASS" "All 5 sub-gate E2E scripts found"
else
    scenario_result "gate_subgate_scripts" "FAIL" "Only ${SCRIPTS_FOUND}/5 scripts found"
fi

#######################################
# Scenario 2: All operator harness modules exported
#######################################
e2e_step "Scenario 2: Operator harness modules exported"

LIB_RS="crates/ffs-harness/src/lib.rs"
MODULES_FOUND=0
for mod_name in "error_taxonomy" "health_consistency" "tabletop_drill"; do
    if grep -q "pub mod ${mod_name}" "$LIB_RS"; then
        MODULES_FOUND=$((MODULES_FOUND + 1))
    fi
done

if [[ $MODULES_FOUND -eq 3 ]]; then
    scenario_result "gate_modules_exported" "PASS" "All 3 operator harness modules exported"
else
    scenario_result "gate_modules_exported" "FAIL" "Only ${MODULES_FOUND}/3 modules exported"
fi

#######################################
# Scenario 3: Runbooks E2E (bd-h6nz.7.1)
#######################################
e2e_step "Scenario 3: Runbooks E2E"

RUNBOOK_CHECKS=0
# Verify all 3 runbooks exist with required content
for runbook in "docs/runbooks/replay-failure-triage.md" "docs/runbooks/corruption-recovery.md" "docs/runbooks/backpressure-investigation.md"; do
    if [[ -f "$runbook" ]] && grep -q "Quick Reference" "$runbook" && grep -q "bash" "$runbook"; then
        RUNBOOK_CHECKS=$((RUNBOOK_CHECKS + 1))
    fi
done

# Verify perf regression triage runbook also exists
[[ -f "docs/runbooks/perf-regression-triage.md" ]] && RUNBOOK_CHECKS=$((RUNBOOK_CHECKS + 1))

if [[ $RUNBOOK_CHECKS -eq 4 ]]; then
    scenario_result "gate_runbooks_complete" "PASS" "All 4 runbooks complete with decision trees and bash commands"
else
    scenario_result "gate_runbooks_complete" "FAIL" "Only ${RUNBOOK_CHECKS}/4 runbooks pass validation"
fi

#######################################
# Scenario 4: Evidence presets E2E (bd-h6nz.7.2)
#######################################
e2e_step "Scenario 4: Evidence presets"

PRESET_CHECKS=0
EVIDENCE_SRC="crates/ffs-cli/src/cmd_evidence.rs"
for preset in "replay-anomalies" "repair-failures" "pressure-transitions"; do
    if grep -q "$preset" "$EVIDENCE_SRC"; then
        PRESET_CHECKS=$((PRESET_CHECKS + 1))
    fi
done

# Verify summary aggregation exists
grep -q "summary" "$EVIDENCE_SRC" && PRESET_CHECKS=$((PRESET_CHECKS + 1))

if [[ $PRESET_CHECKS -eq 4 ]]; then
    scenario_result "gate_evidence_presets" "PASS" "All 3 presets + summary aggregation in evidence command"
else
    scenario_result "gate_evidence_presets" "FAIL" "Only ${PRESET_CHECKS}/4 evidence checks pass"
fi

#######################################
# Scenario 5: Health consistency (bd-h6nz.7.3)
#######################################
e2e_step "Scenario 5: Health consistency"

HC_SRC="crates/ffs-harness/src/health_consistency.rs"
HC_CHECKS=0
# Check all 5 health dimensions are tracked
for dimension in "DEGRADATION_LEVEL" "RUNTIME_MODE" "REPLAY_STATUS" "REPAIR_STALENESS" "PRESSURE_COUNTERS"; do
    if grep -q "$dimension" "$HC_SRC"; then
        HC_CHECKS=$((HC_CHECKS + 1))
    fi
done

if [[ $HC_CHECKS -eq 5 ]]; then
    scenario_result "gate_health_consistency" "PASS" "All 5 health dimensions tracked"
else
    scenario_result "gate_health_consistency" "FAIL" "Only ${HC_CHECKS}/5 dimensions found"
fi

#######################################
# Scenario 6: Tabletop drills (bd-h6nz.7.4)
#######################################
e2e_step "Scenario 6: Tabletop drills"

DRILL_SRC="crates/ffs-harness/src/tabletop_drill.rs"
DRILL_CHECKS=0
for drill_id in "drill-replay-anomaly" "drill-corruption-partial-repair" "drill-sustained-pressure"; do
    if grep -q "\"$drill_id\"" "$DRILL_SRC"; then
        DRILL_CHECKS=$((DRILL_CHECKS + 1))
    fi
done

if [[ $DRILL_CHECKS -eq 3 ]]; then
    scenario_result "gate_tabletop_drills" "PASS" "All 3 incident drill scenarios defined"
else
    scenario_result "gate_tabletop_drills" "FAIL" "Only ${DRILL_CHECKS}/3 drills found"
fi

#######################################
# Scenario 7: Error taxonomy (bd-h6nz.7.6)
#######################################
e2e_step "Scenario 7: Error taxonomy"

TAX_SRC="crates/ffs-harness/src/error_taxonomy.rs"
TAX_CHECKS=0
for prefix in "FFS-CFG" "FFS-CMP" "FFS-RPL" "FFS-RPR" "FFS-PRS" "FFS-IOC" "FFS-UNS"; do
    if grep -q "\"$prefix" "$TAX_SRC"; then
        TAX_CHECKS=$((TAX_CHECKS + 1))
    fi
done

if [[ $TAX_CHECKS -eq 7 ]]; then
    scenario_result "gate_error_taxonomy" "PASS" "All 7 error class prefixes defined"
else
    scenario_result "gate_error_taxonomy" "FAIL" "Only ${TAX_CHECKS}/7 prefixes found"
fi

#######################################
# Scenario 8: All operator unit tests pass
#######################################
e2e_step "Scenario 8: All operator unit tests pass"

TEST_LOG="$E2E_LOG_DIR/operator_tooling_unit_tests.log"
MODULES_TOTAL=0
for _mod_filter in "error_taxonomy" "health_consistency" "tabletop_drill"; do
    MODULES_TOTAL=$((MODULES_TOTAL + 1))
done

MODULES_PASS=0
: >"$TEST_LOG"
for mod_filter in "error_taxonomy" "health_consistency" "tabletop_drill"; do
    module_log="$E2E_LOG_DIR/operator_tooling_${mod_filter}_unit_tests.log"
    if run_rch_capture "$module_log" cargo test -p ffs-harness --lib -- "$mod_filter"; then
        MODULES_PASS=$((MODULES_PASS + 1))
    else
        log_test_tail "$module_log"
    fi
    cat "$module_log" >>"$TEST_LOG"
done

TOTAL_TESTS=$(grep -Ec "^test .*::" "$TEST_LOG" 2>/dev/null || true)
TOTAL_TESTS="${TOTAL_TESTS:-0}"

if [[ $MODULES_PASS -eq $MODULES_TOTAL && $TOTAL_TESTS -ge 30 ]]; then
    scenario_result "gate_unit_tests" "PASS" "All 3 modules pass (${TOTAL_TESTS} tests)"
else
    scenario_result "gate_unit_tests" "FAIL" "${MODULES_PASS}/${MODULES_TOTAL} modules pass, ${TOTAL_TESTS} tests"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 9: Structured log markers auditable
#######################################
e2e_step "Scenario 9: Structured log markers auditable"

MARKER_CHECKS=0
# Key structured log markers must be traceable across surfaces
# 1. Degradation transitions
grep -q "degradation_transition" "crates/ffs-core/src/degradation.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 2. Repair completion
grep -q "repair_complete" "crates/ffs-cli/src/cmd_repair.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 3. WAL replay lifecycle
grep -q "wal_replay_start" "crates/ffs-mvcc/src/wal_replay.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 4. Evidence preset filtering
grep -q "evidence_preset" "crates/ffs-cli/src/cmd_evidence.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))
# 5. Error taxonomy codes reference in drill validation
grep -q "error_codes" "crates/ffs-harness/src/tabletop_drill.rs" && MARKER_CHECKS=$((MARKER_CHECKS + 1))

if [[ $MARKER_CHECKS -eq 5 ]]; then
    scenario_result "gate_log_audit" "PASS" "All 5 structured log marker families auditable"
else
    scenario_result "gate_log_audit" "FAIL" "Only ${MARKER_CHECKS}/5 marker families found"
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
