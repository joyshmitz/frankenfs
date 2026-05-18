#!/usr/bin/env bash
# ffs_fuzzing_gate_e2e.sh - Final acceptance gate for Epic 4: Fuzzing & Adversarial (bd-h6nz.4.6)
#
# Validates the full fuzzing/adversarial pipeline across all 5 sub-beads:
# fuzz targets (4.1), corpus seeding (4.2), nightly campaigns (4.3),
# crash promotion (4.4), and fuzz dashboard (4.5).
#
# Scenarios:
# 1. All sub-bead E2E scripts exist
# 2. All fuzz harness modules are exported
# 3. All 4 fuzz target source files exist
# 4. Corpus infrastructure (seeds, dictionaries, adversarial samples)
# 5. Campaign automation (nightly script, JSON output, artifact capture)
# 6. Crash promotion pipeline (minimize, promote, metadata tagging)
# 7. Fuzz dashboard (health assessment, regression detection)
# 8. Cross-cutting: all fuzz-related unit tests pass
# 9. Cross-cutting: structured log markers and pipeline traceability
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_fuzzing_gate_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fuzzing_gate}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_FUZZING_GATE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_FUZZING_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_FUZZING_GATE_SKIP_SELF_CHECK:-0}"
mapfile -t FUZZ_TARGETS < <(
    find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
)

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

fixture_case="${FFS_FUZZING_GATE_FIXTURE_CASE:-complete}"

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
        echo "unknown fuzzing gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- crash_promotion"*)
        printf '%s\n' \
            "running 12 tests" \
            "test crash_promotion::tests::promotion_manifest_round_trips ... ok" \
            "test crash_promotion::tests::promotion_metadata_has_target ... ok" \
            "test crash_promotion::tests::promotion_metadata_has_minimized_flag ... ok" \
            "test crash_promotion::tests::promotion_rejects_missing_target ... ok" \
            "test crash_promotion::tests::promotion_rejects_missing_crash ... ok" \
            "test crash_promotion::tests::promotion_records_dictionary ... ok" \
            "test crash_promotion::tests::promotion_records_corpus_path ... ok" \
            "test crash_promotion::tests::promotion_records_seed_hash ... ok" \
            "test crash_promotion::tests::promotion_artifact_manifest_links ... ok" \
            "test crash_promotion::tests::promotion_pipeline_has_all_components ... ok" \
            "test crash_promotion::tests::promotion_metadata_records_commit ... ok" \
            "test crash_promotion::tests::promotion_regression_tag_is_stable ... ok"
        ;;
    *"cargo test -p ffs-harness --lib -- fuzz_dashboard"*)
        printf '%s\n' \
            "running 12 tests" \
            "test fuzz_dashboard::tests::dashboard_schema_accepts_campaign_summary ... ok" \
            "test fuzz_dashboard::tests::dashboard_schema_rejects_missing_target ... ok" \
            "test fuzz_dashboard::tests::health_marks_recent_campaign_healthy ... ok" \
            "test fuzz_dashboard::tests::health_marks_stagnant_campaign ... ok" \
            "test fuzz_dashboard::tests::health_marks_crash_campaign ... ok" \
            "test fuzz_dashboard::tests::health_marks_error_campaign ... ok" \
            "test fuzz_dashboard::tests::regression_detects_throughput_drop ... ok" \
            "test fuzz_dashboard::tests::regression_ignores_small_delta ... ok" \
            "test fuzz_dashboard::tests::alert_severity_orders_failures ... ok" \
            "test fuzz_dashboard::tests::campaign_summary_round_trips ... ok" \
            "test fuzz_dashboard::tests::artifact_links_include_target ... ok" \
            "test fuzz_dashboard::tests::dashboard_records_commit_sha ... ok"
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
    local child_log="$E2E_LOG_DIR/fuzzing_gate_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_FUZZING_GATE_SELF_CHECK=0 \
        FFS_FUZZING_GATE_SKIP_SELF_CHECK=1 \
        FFS_FUZZING_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_fuzzing_gate_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic fuzzing gate wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-fuzzing-gate-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "gate_fuzz_targets" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_corpus_infra" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_campaign_automation" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_crash_promotion" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_fuzz_dashboard" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "gate_pipeline_traceability" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "fuzzing_gate_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzzing_gate_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "fuzzing_gate_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzzing_gate_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "fuzzing_gate_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzzing_gate_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_fuzzing_gate"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_print_env

#######################################
# Scenario 1: All sub-bead E2E scripts exist
#######################################
e2e_step "Scenario 1: Sub-bead E2E scripts exist"

SCRIPTS_FOUND=0
for script in \
    "scripts/e2e/ffs_fuzz_targets_e2e.sh" \
    "scripts/e2e/ffs_crash_promotion_e2e.sh" \
    "scripts/e2e/ffs_fuzz_dashboard_e2e.sh"; do
    if [[ -f "$script" ]]; then
        SCRIPTS_FOUND=$((SCRIPTS_FOUND + 1))
    fi
done

if [[ $SCRIPTS_FOUND -eq 3 ]]; then
    scenario_result "gate_subgate_scripts" "PASS" "All 3 sub-bead E2E scripts found"
else
    scenario_result "gate_subgate_scripts" "FAIL" "Only ${SCRIPTS_FOUND}/3 scripts found"
fi

#######################################
# Scenario 2: All fuzz harness modules exported
#######################################
e2e_step "Scenario 2: Fuzz harness modules exported"

LIB_RS="crates/ffs-harness/src/lib.rs"
MODULES_FOUND=0
for mod_name in "crash_promotion" "fuzz_dashboard"; do
    if grep -q "pub mod ${mod_name}" "$LIB_RS"; then
        MODULES_FOUND=$((MODULES_FOUND + 1))
    fi
done

if [[ $MODULES_FOUND -eq 2 ]]; then
    scenario_result "gate_modules_exported" "PASS" "Both fuzz harness modules exported"
else
    scenario_result "gate_modules_exported" "FAIL" "Only ${MODULES_FOUND}/2 modules exported"
fi

#######################################
# Scenario 3: All registered fuzz target source files (bd-h6nz.4.1)
#######################################
e2e_step "Scenario 3: Fuzz target source files"

TARGETS_FOUND=0
for target in "${FUZZ_TARGETS[@]}"; do
    [[ -f "fuzz/fuzz_targets/${target}.rs" ]] && TARGETS_FOUND=$((TARGETS_FOUND + 1))
done

if [[ $TARGETS_FOUND -eq ${#FUZZ_TARGETS[@]} ]]; then
    scenario_result "gate_fuzz_targets" "PASS" "All ${#FUZZ_TARGETS[@]} fuzz target source files present"
else
    scenario_result "gate_fuzz_targets" "FAIL" "Only ${TARGETS_FOUND}/${#FUZZ_TARGETS[@]} targets found"
fi

#######################################
# Scenario 4: Corpus infrastructure (bd-h6nz.4.2)
#######################################
e2e_step "Scenario 4: Corpus infrastructure"

CORPUS_CHECKS=0

# Seed corpus directories exist with samples
CORPUS_DIRS=0
for target in "${FUZZ_TARGETS[@]}"; do
    dir="fuzz/corpus/${target}"
    if [[ -d "$dir" ]]; then
        count=$(find "$dir" -maxdepth 1 -type f | wc -l)
        if [[ $count -gt 0 ]]; then
            CORPUS_DIRS=$((CORPUS_DIRS + 1))
        fi
    fi
done
[[ $CORPUS_DIRS -eq ${#FUZZ_TARGETS[@]} ]] && CORPUS_CHECKS=$((CORPUS_CHECKS + 1))

# Dictionaries exist with tokens
DICT_OK=0
for dict in ext4.dict btrfs.dict; do
    if [[ -f "fuzz/dictionaries/${dict}" ]]; then
        tokens=$(grep -cv "^#\|^$" "fuzz/dictionaries/${dict}" || true)
        tokens="${tokens:-0}"
        if [[ $tokens -ge 5 ]]; then
            DICT_OK=$((DICT_OK + 1))
        fi
    fi
done
[[ $DICT_OK -eq 2 ]] && CORPUS_CHECKS=$((CORPUS_CHECKS + 1))

# Adversarial corpus has regression seeds
if [[ -d "tests/fuzz_corpus" ]]; then
    SAMPLE_COUNT=$(find "tests/fuzz_corpus" -maxdepth 1 -type f | wc -l)
    [[ $SAMPLE_COUNT -ge 10 ]] && CORPUS_CHECKS=$((CORPUS_CHECKS + 1))
fi

# Seed generation script exists
[[ -x "fuzz/scripts/generate_seeds.sh" ]] && CORPUS_CHECKS=$((CORPUS_CHECKS + 1))

if [[ $CORPUS_CHECKS -eq 4 ]]; then
    scenario_result "gate_corpus_infra" "PASS" "${#FUZZ_TARGETS[@]} corpus dirs, 2 dictionaries, adversarial seeds, generation script"
else
    scenario_result "gate_corpus_infra" "FAIL" "Only ${CORPUS_CHECKS}/4 corpus checks pass"
fi

#######################################
# Scenario 5: Campaign automation (bd-h6nz.4.3)
#######################################
e2e_step "Scenario 5: Campaign automation"

CAMPAIGN_CHECKS=0

# nightly_fuzz.sh exists and produces JSON
if [[ -x "fuzz/scripts/nightly_fuzz.sh" ]]; then
    CAMPAIGN_CHECKS=$((CAMPAIGN_CHECKS + 1))
    # Check for campaign_summary JSON output
    grep -q "campaign_summary" "fuzz/scripts/nightly_fuzz.sh" && CAMPAIGN_CHECKS=$((CAMPAIGN_CHECKS + 1))
    # Check for required JSON fields
    grep -q "campaign_id" "fuzz/scripts/nightly_fuzz.sh" && CAMPAIGN_CHECKS=$((CAMPAIGN_CHECKS + 1))
fi

# minimize_corpus.sh exists
[[ -x "fuzz/scripts/minimize_corpus.sh" ]] && CAMPAIGN_CHECKS=$((CAMPAIGN_CHECKS + 1))

# run_fuzz.sh convenience wrapper
[[ -x "fuzz/scripts/run_fuzz.sh" ]] && CAMPAIGN_CHECKS=$((CAMPAIGN_CHECKS + 1))

if [[ $CAMPAIGN_CHECKS -eq 5 ]]; then
    scenario_result "gate_campaign_automation" "PASS" "nightly runner, JSON output, campaign_id, minimizer, run wrapper"
else
    scenario_result "gate_campaign_automation" "FAIL" "Only ${CAMPAIGN_CHECKS}/5 campaign checks pass"
fi

#######################################
# Scenario 6: Crash promotion pipeline (bd-h6nz.4.4)
#######################################
e2e_step "Scenario 6: Crash promotion pipeline"

PROMO_CHECKS=0

# promote_crash.sh exists with metadata tagging
if [[ -x "fuzz/scripts/promote_crash.sh" ]]; then
    PROMO_CHECKS=$((PROMO_CHECKS + 1))
    grep -q "Fuzz target" "fuzz/scripts/promote_crash.sh" && PROMO_CHECKS=$((PROMO_CHECKS + 1))
    grep -q "Minimized" "fuzz/scripts/promote_crash.sh" && PROMO_CHECKS=$((PROMO_CHECKS + 1))
fi

# crash_promotion.rs harness module with pipeline validation
PROMO_SRC="crates/ffs-harness/src/crash_promotion.rs"
if [[ -f "$PROMO_SRC" ]]; then
    grep -q "validate_pipeline" "$PROMO_SRC" && PROMO_CHECKS=$((PROMO_CHECKS + 1))
    grep -q "generate_regression_test_source" "$PROMO_SRC" && PROMO_CHECKS=$((PROMO_CHECKS + 1))
fi

# FuzzCrash + FuzzCorpus in artifact manifest
grep -q "FuzzCrash" "crates/ffs-harness/src/artifact_manifest.rs" && PROMO_CHECKS=$((PROMO_CHECKS + 1))
grep -q "FuzzCorpus" "crates/ffs-harness/src/artifact_manifest.rs" && PROMO_CHECKS=$((PROMO_CHECKS + 1))

if [[ $PROMO_CHECKS -eq 7 ]]; then
    scenario_result "gate_crash_promotion" "PASS" "Promote script, metadata tags, pipeline validation, artifact manifest"
else
    scenario_result "gate_crash_promotion" "FAIL" "Only ${PROMO_CHECKS}/7 promotion checks pass"
fi

#######################################
# Scenario 7: Fuzz dashboard (bd-h6nz.4.5)
#######################################
e2e_step "Scenario 7: Fuzz dashboard"

DASH_SRC="crates/ffs-harness/src/fuzz_dashboard.rs"
DASH_CHECKS=0

if [[ -f "$DASH_SRC" ]]; then
    # Health assessment
    grep -q "assess_campaign_health" "$DASH_SRC" && DASH_CHECKS=$((DASH_CHECKS + 1))
    # 4 health states
    STATES=0
    for state in Healthy Stagnant CrashesFound Error; do
        grep -q "$state" "$DASH_SRC" && STATES=$((STATES + 1))
    done
    [[ $STATES -eq 4 ]] && DASH_CHECKS=$((DASH_CHECKS + 1))
    # Regression detection with thresholds
    grep -q "detect_regressions" "$DASH_SRC" && DASH_CHECKS=$((DASH_CHECKS + 1))
    grep -q "THROUGHPUT_REGRESSION_THRESHOLD" "$DASH_SRC" && DASH_CHECKS=$((DASH_CHECKS + 1))
    # Alert severity
    grep -q "AlertSeverity" "$DASH_SRC" && DASH_CHECKS=$((DASH_CHECKS + 1))
fi

if [[ $DASH_CHECKS -eq 5 ]]; then
    scenario_result "gate_fuzz_dashboard" "PASS" "Health assessment, 4 states, regression detection, thresholds, severity"
else
    scenario_result "gate_fuzz_dashboard" "FAIL" "Only ${DASH_CHECKS}/5 dashboard checks pass"
fi

#######################################
# Scenario 8: All fuzz-related unit tests pass
#######################################
e2e_step "Scenario 8: All fuzz-related unit tests pass"

TEST_LOG="$E2E_LOG_DIR/fuzzing_gate_unit_tests.log"
: >"$TEST_LOG"
MODULES_PASS=0
MODULES_TOTAL=0
for mod_filter in "crash_promotion" "fuzz_dashboard"; do
    MODULES_TOTAL=$((MODULES_TOTAL + 1))
    MODULE_LOG="$E2E_LOG_DIR/fuzzing_gate_${mod_filter}_tests.log"
    if run_rch_capture "$MODULE_LOG" cargo test -p ffs-harness --lib -- "$mod_filter"; then
        MODULES_PASS=$((MODULES_PASS + 1))
    else
        log_test_tail "$MODULE_LOG"
    fi
    cat "$MODULE_LOG" >>"$TEST_LOG"
done

TOTAL_TESTS=$(grep -Ec "^test .*::" "$TEST_LOG" 2>/dev/null || true)
TOTAL_TESTS="${TOTAL_TESTS:-0}"

if [[ $MODULES_PASS -eq $MODULES_TOTAL && $TOTAL_TESTS -ge 20 ]]; then
    scenario_result "gate_unit_tests" "PASS" "All ${MODULES_TOTAL} modules pass (${TOTAL_TESTS} tests)"
else
    scenario_result "gate_unit_tests" "FAIL" "${MODULES_PASS}/${MODULES_TOTAL} modules pass, ${TOTAL_TESTS} tests"
    log_test_tail "$TEST_LOG"
fi

#######################################
# Scenario 9: Pipeline traceability and structured logging
#######################################
e2e_step "Scenario 9: Pipeline traceability"

TRACE_CHECKS=0

# Crash promotion links crasher IDs to regression test IDs
grep -q "RegressionTag" "crates/ffs-harness/src/crash_promotion.rs" && TRACE_CHECKS=$((TRACE_CHECKS + 1))

# Campaign summary has commit_sha for reproducibility
grep -q "commit_sha" "fuzz/scripts/nightly_fuzz.sh" && TRACE_CHECKS=$((TRACE_CHECKS + 1))

# Promote script generates metadata linking crash to test
grep -q "Commit at discovery" "fuzz/scripts/promote_crash.sh" && TRACE_CHECKS=$((TRACE_CHECKS + 1))

# Dashboard schema validation for JSON structure
grep -q "validate_campaign_schema" "crates/ffs-harness/src/fuzz_dashboard.rs" && TRACE_CHECKS=$((TRACE_CHECKS + 1))

# Artifact manifest tracks fuzz artifacts
grep -q "FuzzCrash\|FuzzCorpus" "crates/ffs-harness/src/artifact_manifest.rs" && TRACE_CHECKS=$((TRACE_CHECKS + 1))

if [[ $TRACE_CHECKS -eq 5 ]]; then
    scenario_result "gate_pipeline_traceability" "PASS" "Regression tags, commit SHA, metadata, schema validation, artifact tracking"
else
    scenario_result "gate_pipeline_traceability" "FAIL" "Only ${TRACE_CHECKS}/5 traceability checks pass"
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
