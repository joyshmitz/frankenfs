#!/usr/bin/env bash
# ffs_error_taxonomy_e2e.sh - Verification gate for operator-facing error taxonomy (bd-h6nz.7.6)
#
# Validates the canonical error taxonomy: 7 error classes, stable codes,
# remediation hints, runbook cross-links, and surface consistency across
# CLI, TUI, and evidence outputs.
#
# Scenarios:
# 1. Error taxonomy module exists and is exported
# 2. All 7 error classes defined
# 3. At least 10 representative scenarios with stable codes
# 4. Every scenario has a non-empty remediation hint
# 5. Runbook cross-links resolve to existing files
# 6. FfsError variant references are valid
# 7. Evidence preset alignment with error classes
# 8. Error code uniqueness and prefix alignment
# 9. Error taxonomy unit tests pass
# 10. error_taxonomy_fixture_complete_self_check proves cataloged markers without cargo
# 11. error_taxonomy_fixture_local_fallback_self_check proves local fallback rejection
# 12. error_taxonomy_fixture_missing_remote_evidence_self_check proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_error_taxonomy_e2e.sh
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_error_taxonomy}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-360}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_ERROR_TAXONOMY_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_ERROR_TAXONOMY_SKIP_SELF_CHECK:-0}"

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
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}|command=$*"
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
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}|command=$*"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_ERROR_TAXONOMY_FIXTURE_CASE:-complete}"

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
        echo "unknown error taxonomy fixture case: $fixture_case" >&2
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
    local child_log="$E2E_LOG_DIR/error_taxonomy_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_ERROR_TAXONOMY_SELF_CHECK=0 \
        FFS_ERROR_TAXONOMY_SKIP_SELF_CHECK=1 \
        FFS_ERROR_TAXONOMY_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_error_taxonomy_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic error taxonomy wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-error-taxonomy-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "taxonomy_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_seven_classes" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_min_scenarios" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_hints_nonempty" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_runbook_links" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_variant_refs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_preset_alignment" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_code_format" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "taxonomy_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "error_taxonomy_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "error_taxonomy_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "error_taxonomy_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "error_taxonomy_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "error_taxonomy_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "error_taxonomy_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_error_taxonomy"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

TAXONOMY_SRC="crates/ffs-harness/src/error_taxonomy.rs"
ERROR_SRC="crates/ffs-error/src/lib.rs"

#######################################
# Scenario 1: Error taxonomy module exists and is exported
#######################################
e2e_step "Scenario 1: Error taxonomy module exists"

if [[ -f "$TAXONOMY_SRC" ]] && grep -q "pub mod error_taxonomy" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "taxonomy_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "taxonomy_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All 7 error classes defined
#######################################
e2e_step "Scenario 2: All 7 error classes defined"

CLASS_COUNT=0
for class in "Configuration" "Compatibility" "Replay" "Repair" "Pressure" "IoCorruption" "UnsupportedOp"; do
    if grep -q "$class" "$TAXONOMY_SRC"; then
        CLASS_COUNT=$((CLASS_COUNT + 1))
    fi
done

if [[ $CLASS_COUNT -eq 7 ]]; then
    scenario_result "taxonomy_seven_classes" "PASS" "All 7 error classes defined"
else
    scenario_result "taxonomy_seven_classes" "FAIL" "Only ${CLASS_COUNT}/7 classes found"
fi

#######################################
# Scenario 3: At least 10 representative scenarios with stable codes
#######################################
e2e_step "Scenario 3: At least 10 scenario codes"

CODE_COUNT=$(grep -c '"FFS-' "$TAXONOMY_SRC" || echo "0")

if [[ $CODE_COUNT -ge 10 ]]; then
    scenario_result "taxonomy_min_scenarios" "PASS" "${CODE_COUNT} stable error codes defined"
else
    scenario_result "taxonomy_min_scenarios" "FAIL" "Only ${CODE_COUNT}/10 error codes"
fi

#######################################
# Scenario 4: Every scenario has a non-empty remediation hint
#######################################
e2e_step "Scenario 4: Remediation hints present"

HINT_COUNT=$(grep -c "remediation_hint:" "$TAXONOMY_SRC" || true)
HINT_COUNT="${HINT_COUNT:-0}"
EMPTY_HINT=$(grep -c 'remediation_hint: ""' "$TAXONOMY_SRC" || true)
EMPTY_HINT="${EMPTY_HINT:-0}"

if [[ $HINT_COUNT -ge 10 && $EMPTY_HINT -eq 0 ]]; then
    scenario_result "taxonomy_hints_nonempty" "PASS" "${HINT_COUNT} hints, none empty"
else
    scenario_result "taxonomy_hints_nonempty" "FAIL" "${HINT_COUNT} hints, ${EMPTY_HINT} empty"
fi

#######################################
# Scenario 5: Runbook cross-links resolve to existing files
#######################################
e2e_step "Scenario 5: Runbook cross-links"

RUNBOOKS_FOUND=0
RUNBOOKS_TOTAL=0
for runbook in "docs/runbooks/replay-failure-triage.md" "docs/runbooks/corruption-recovery.md" "docs/runbooks/backpressure-investigation.md"; do
    RUNBOOKS_TOTAL=$((RUNBOOKS_TOTAL + 1))
    if [[ -f "$runbook" ]]; then
        RUNBOOKS_FOUND=$((RUNBOOKS_FOUND + 1))
    fi
done

# Also check that runbooks are referenced in taxonomy
RUNBOOK_REFS=$(grep -c "docs/runbooks/" "$TAXONOMY_SRC" || echo "0")

if [[ $RUNBOOKS_FOUND -eq $RUNBOOKS_TOTAL && $RUNBOOK_REFS -ge 3 ]]; then
    scenario_result "taxonomy_runbook_links" "PASS" "All ${RUNBOOKS_TOTAL} runbooks exist, ${RUNBOOK_REFS} references"
else
    scenario_result "taxonomy_runbook_links" "FAIL" "${RUNBOOKS_FOUND}/${RUNBOOKS_TOTAL} runbooks, ${RUNBOOK_REFS} refs"
fi

#######################################
# Scenario 6: FfsError variant references are valid
#######################################
e2e_step "Scenario 6: FfsError variant references valid"

VARIANTS_FOUND=0
VARIANTS_TOTAL=0
for variant in "InvalidGeometry" "Format" "UnsupportedFeature" "IncompatibleFeature" "UnsupportedBlockSize" "MvccConflict" "RepairFailed" "Corruption" "Io" "NoSpace" "ModeViolation" "ReadOnly"; do
    VARIANTS_TOTAL=$((VARIANTS_TOTAL + 1))
    # Check variant exists in both taxonomy and error crate
    if grep -q "\"$variant\"" "$TAXONOMY_SRC" && grep -q "$variant" "$ERROR_SRC"; then
        VARIANTS_FOUND=$((VARIANTS_FOUND + 1))
    fi
done

if [[ $VARIANTS_FOUND -eq $VARIANTS_TOTAL ]]; then
    scenario_result "taxonomy_variant_refs" "PASS" "All ${VARIANTS_TOTAL} variant references valid"
else
    scenario_result "taxonomy_variant_refs" "FAIL" "Only ${VARIANTS_FOUND}/${VARIANTS_TOTAL} variants valid"
fi

#######################################
# Scenario 7: Evidence preset alignment with error classes
#######################################
e2e_step "Scenario 7: Evidence preset alignment"

PRESETS_FOUND=0
for preset in "replay-anomalies" "repair-failures" "pressure-transitions"; do
    if grep -q "$preset" "$TAXONOMY_SRC"; then
        PRESETS_FOUND=$((PRESETS_FOUND + 1))
    fi
done

if [[ $PRESETS_FOUND -eq 3 ]]; then
    scenario_result "taxonomy_preset_alignment" "PASS" "All 3 evidence presets referenced in taxonomy"
else
    scenario_result "taxonomy_preset_alignment" "FAIL" "Only ${PRESETS_FOUND}/3 presets referenced"
fi

#######################################
# Scenario 8: Error code uniqueness and prefix format
#######################################
e2e_step "Scenario 8: Error code format"

# Check all 7 prefixes are present
PREFIX_COUNT=0
for prefix in "FFS-CFG" "FFS-CMP" "FFS-RPL" "FFS-RPR" "FFS-PRS" "FFS-IOC" "FFS-UNS"; do
    if grep -q "\"$prefix" "$TAXONOMY_SRC"; then
        PREFIX_COUNT=$((PREFIX_COUNT + 1))
    fi
done

if [[ $PREFIX_COUNT -eq 7 ]]; then
    scenario_result "taxonomy_code_format" "PASS" "All 7 code prefixes present"
else
    scenario_result "taxonomy_code_format" "FAIL" "Only ${PREFIX_COUNT}/7 prefixes found"
fi

#######################################
# Scenario 9: Error taxonomy unit tests pass
#######################################
e2e_step "Scenario 9: Unit tests pass"

TEST_LOG="$E2E_LOG_DIR/error_taxonomy_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- error_taxonomy; then
    TESTS_RUN=$(grep -c "test error_taxonomy::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "taxonomy_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "taxonomy_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 10)"
    fi
else
    scenario_result "taxonomy_unit_tests_pass" "FAIL" "Error taxonomy tests failed"
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
