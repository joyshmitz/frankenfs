#!/usr/bin/env bash
# ffs_crash_promotion_e2e.sh - Verification gate for crash minimization & promotion (bd-h6nz.4.4)
#
# Validates the crash-to-regression-test promotion pipeline: fuzz target
# coverage, corpus infrastructure, minimize/promote scripts, metadata
# tagging, and the harness module.
#
# Scenarios:
# 1. Crash promotion module exists and is exported
# 2. All 4 fuzz targets have source files
# 3. All 4 corpus directories have seed samples
# 4. Minimize script exists and is documented
# 5. Promote script exists with metadata generation
# 6. Dictionaries exist with tokens for both filesystems
# 7. Adversarial corpus has samples for regression seeding
# 8. Pipeline validation passes all 7 component checks
# 9. Crash promotion unit tests pass
# 10. Fixture mode proves cataloged markers without cargo
# 11. Fixture mode proves local fallback rejection
# 12. Fixture mode proves missing remote evidence rejection
#
# Usage: ./scripts/e2e/ffs_crash_promotion_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_crash_promotion}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-${FFS_CRASH_PROMOTION_RCH_TIMEOUT:-90}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS%s}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-5}"
SELF_CHECK="${FFS_CRASH_PROMOTION_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_CRASH_PROMOTION_SKIP_SELF_CHECK:-0}"
MINIMIZE_ACK_VALUE="cargo-fuzz-minimization-may-run-locally"
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
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    shift
    : >"$log_path"
    set +e
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
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
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_CRASH_PROMOTION_FIXTURE_CASE:-complete}"

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
        echo "unknown crash promotion fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-harness --lib -- crash_promotion"*)
        printf '%s\n' \
            "running 10 tests" \
            "test crash_promotion::tests::promotion_manifest_round_trips ... ok" \
            "test crash_promotion::tests::promotion_metadata_has_target ... ok" \
            "test crash_promotion::tests::promotion_metadata_has_minimized_flag ... ok" \
            "test crash_promotion::tests::promotion_rejects_missing_target ... ok" \
            "test crash_promotion::tests::promotion_rejects_missing_crash ... ok" \
            "test crash_promotion::tests::promotion_records_dictionary ... ok" \
            "test crash_promotion::tests::promotion_records_corpus_path ... ok" \
            "test crash_promotion::tests::promotion_records_seed_hash ... ok" \
            "test crash_promotion::tests::promotion_artifact_manifest_links ... ok" \
            "test crash_promotion::tests::promotion_pipeline_has_all_components ... ok"
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
    local child_log="$E2E_LOG_DIR/crash_promotion_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_CRASH_PROMOTION_SELF_CHECK=0 \
        FFS_CRASH_PROMOTION_SKIP_SELF_CHECK=1 \
        FFS_CRASH_PROMOTION_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_crash_promotion_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic crash promotion wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-crash-promotion-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "promo_module_exists" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_fuzz_targets" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_corpus_seeds" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_minimize_script" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_promote_script" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_adversarial_corpus" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_pipeline_checks" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "promo_unit_tests_pass" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "SCENARIO_RESULT|scenario_id=promo_dictionaries|outcome=PASS" "$child_log"; then
        scenario_result "crash_promotion_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "crash_promotion_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "crash_promotion_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "crash_promotion_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "crash_promotion_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "crash_promotion_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_crash_promotion"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

#######################################
# Scenario 1: Crash promotion module exists
#######################################
e2e_step "Scenario 1: Crash promotion module exists"

if [[ -f "crates/ffs-harness/src/crash_promotion.rs" ]] && grep -q "pub mod crash_promotion" "crates/ffs-harness/src/lib.rs"; then
    scenario_result "promo_module_exists" "PASS" "Module exists and is exported"
else
    scenario_result "promo_module_exists" "FAIL" "Module not found or not exported"
fi

#######################################
# Scenario 2: All registered fuzz targets have source files
#######################################
e2e_step "Scenario 2: Fuzz target source files"

TARGETS_FOUND=0
for target in "${FUZZ_TARGETS[@]}"; do
    [[ -f "fuzz/fuzz_targets/${target}.rs" ]] && TARGETS_FOUND=$((TARGETS_FOUND + 1))
done

if [[ $TARGETS_FOUND -eq ${#FUZZ_TARGETS[@]} ]]; then
    scenario_result "promo_fuzz_targets" "PASS" "All ${#FUZZ_TARGETS[@]} fuzz target source files found"
else
    scenario_result "promo_fuzz_targets" "FAIL" "Only ${TARGETS_FOUND}/${#FUZZ_TARGETS[@]} targets found"
fi

#######################################
# Scenario 3: Corpus directories have seed samples
#######################################
e2e_step "Scenario 3: Corpus seed samples"

CORPUS_OK=0
for target in "${FUZZ_TARGETS[@]}"; do
    dir="fuzz/corpus/${target}"
    if [[ -d "$dir" ]]; then
        count=$(find "$dir" -maxdepth 1 -type f | wc -l)
        if [[ $count -gt 0 ]]; then
            CORPUS_OK=$((CORPUS_OK + 1))
        fi
    fi
done

if [[ $CORPUS_OK -eq ${#FUZZ_TARGETS[@]} ]]; then
    scenario_result "promo_corpus_seeds" "PASS" "All ${#FUZZ_TARGETS[@]} corpus directories have samples"
else
    scenario_result "promo_corpus_seeds" "FAIL" "Only ${CORPUS_OK}/${#FUZZ_TARGETS[@]} have samples"
fi

#######################################
# Scenario 4: Minimize script exists
#######################################
e2e_step "Scenario 4: Minimize script"

MINIMIZE_STDOUT="$E2E_LOG_DIR/minimize_guard.stdout"
MINIMIZE_STDERR="$E2E_LOG_DIR/minimize_guard.stderr"
if [[ -s "fuzz/scripts/minimize_corpus.sh" ]] \
    && [[ -x "fuzz/scripts/minimize_corpus.sh" ]] \
    && grep -q "cargo fuzz cmin" "fuzz/scripts/minimize_corpus.sh" \
    && grep -q "FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE" "fuzz/scripts/minimize_corpus.sh" \
    && ! fuzz/scripts/minimize_corpus.sh fuzz_ext4_metadata >"$MINIMIZE_STDOUT" 2>"$MINIMIZE_STDERR" \
    && grep -q "refusing cargo fuzz cmin" "$MINIMIZE_STDERR" \
    && FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE= fuzz/scripts/minimize_corpus.sh --dry-run fuzz_ext4_metadata >"$MINIMIZE_STDOUT" 2>"$MINIMIZE_STDERR" \
    && grep -q "cargo\\ fuzz\\ cmin" "$MINIMIZE_STDOUT"; then
    scenario_result "promo_minimize_script" "PASS" "minimize_corpus.sh exists and fails closed without ${MINIMIZE_ACK_VALUE}"
else
    scenario_result "promo_minimize_script" "FAIL" "minimize script missing, incomplete, or not fail-closed"
fi

#######################################
# Scenario 5: Promote script exists with metadata
#######################################
e2e_step "Scenario 5: Promote script"

PROMOTE_CRASH="$E2E_LOG_DIR/promote_guard_crash"
PROMOTE_STDOUT="$E2E_LOG_DIR/promote_guard.stdout"
PROMOTE_STDERR="$E2E_LOG_DIR/promote_guard.stderr"
printf 'frankenfs guarded crash input\n' >"$PROMOTE_CRASH"
if [[ -x "fuzz/scripts/promote_crash.sh" ]] \
    && grep -q "Fuzz target" "fuzz/scripts/promote_crash.sh" \
    && grep -q "Minimized" "fuzz/scripts/promote_crash.sh" \
    && grep -q "FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE" "fuzz/scripts/promote_crash.sh" \
    && ! fuzz/scripts/promote_crash.sh fuzz_ext4_metadata "$PROMOTE_CRASH" >"$PROMOTE_STDOUT" 2>"$PROMOTE_STDERR" \
    && grep -q "refusing cargo fuzz tmin" "$PROMOTE_STDERR"; then
    scenario_result "promo_promote_script" "PASS" "promote_crash.sh exists with metadata tagging and fail-closed minimization"
else
    scenario_result "promo_promote_script" "FAIL" "promote script missing, incomplete, or not fail-closed"
fi

#######################################
# Scenario 6: Dictionaries exist with tokens
#######################################
e2e_step "Scenario 6: Fuzz dictionaries"

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

if [[ $DICT_OK -eq 2 ]]; then
    scenario_result "promo_dictionaries" "PASS" "Both dictionaries have >= 5 tokens"
else
    scenario_result "promo_dictionaries" "FAIL" "Only ${DICT_OK}/2 dictionaries valid"
fi

#######################################
# Scenario 7: Adversarial corpus has regression seeds
#######################################
e2e_step "Scenario 7: Adversarial corpus"

if [[ -d "tests/fuzz_corpus" ]]; then
    SAMPLE_COUNT=$(find "tests/fuzz_corpus" -maxdepth 1 -type f | wc -l)
    if [[ $SAMPLE_COUNT -ge 10 ]]; then
        scenario_result "promo_adversarial_corpus" "PASS" "${SAMPLE_COUNT} adversarial samples"
    else
        scenario_result "promo_adversarial_corpus" "FAIL" "Only ${SAMPLE_COUNT} samples (need >= 10)"
    fi
else
    scenario_result "promo_adversarial_corpus" "FAIL" "tests/fuzz_corpus directory not found"
fi

#######################################
# Scenario 8: Pipeline validation
#######################################
e2e_step "Scenario 8: Pipeline validation components"

PIPELINE_CHECKS=0
# artifact_manifest has FuzzCrash + FuzzCorpus
grep -q "FuzzCrash" "crates/ffs-harness/src/artifact_manifest.rs" && PIPELINE_CHECKS=$((PIPELINE_CHECKS + 1))
grep -q "FuzzCorpus" "crates/ffs-harness/src/artifact_manifest.rs" && PIPELINE_CHECKS=$((PIPELINE_CHECKS + 1))
# nightly campaign script exists
[[ -x "fuzz/scripts/nightly_fuzz.sh" ]] && PIPELINE_CHECKS=$((PIPELINE_CHECKS + 1))
# seed generation script exists
[[ -x "fuzz/scripts/generate_seeds.sh" ]] && PIPELINE_CHECKS=$((PIPELINE_CHECKS + 1))

if [[ $PIPELINE_CHECKS -eq 4 ]]; then
    scenario_result "promo_pipeline_checks" "PASS" "All 4 pipeline components validated"
else
    scenario_result "promo_pipeline_checks" "FAIL" "Only ${PIPELINE_CHECKS}/4 components"
fi

#######################################
# Scenario 9: Unit tests pass
#######################################
e2e_step "Scenario 9: Unit tests pass"

TEST_LOG="$E2E_LOG_DIR/crash_promotion_unit_tests.log"
if run_rch_capture "$TEST_LOG" cargo test -p ffs-harness --lib -- crash_promotion; then
    TESTS_RUN=$(grep -c "test crash_promotion::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "promo_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "promo_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 10)"
    fi
else
    cat "$TEST_LOG"
    scenario_result "promo_unit_tests_pass" "FAIL" "Crash promotion tests failed or RCH timed out before worker-side success"
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
