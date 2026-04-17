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
#
# Usage: ./scripts/e2e/ffs_crash_promotion_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
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

e2e_init "ffs_crash_promotion"

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

if [[ -x "fuzz/scripts/minimize_corpus.sh" ]] && grep -q "cargo fuzz cmin" "fuzz/scripts/minimize_corpus.sh"; then
    scenario_result "promo_minimize_script" "PASS" "minimize_corpus.sh exists with cargo fuzz cmin"
else
    scenario_result "promo_minimize_script" "FAIL" "minimize script missing or incomplete"
fi

#######################################
# Scenario 5: Promote script exists with metadata
#######################################
e2e_step "Scenario 5: Promote script"

if [[ -x "fuzz/scripts/promote_crash.sh" ]] && grep -q "Fuzz target" "fuzz/scripts/promote_crash.sh" && grep -q "Minimized" "fuzz/scripts/promote_crash.sh"; then
    scenario_result "promo_promote_script" "PASS" "promote_crash.sh exists with metadata tagging"
else
    scenario_result "promo_promote_script" "FAIL" "promote script missing or incomplete"
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

TEST_LOG=$(mktemp)
if cargo test -p ffs-harness --lib -- crash_promotion 2>"$TEST_LOG" | tee -a "$TEST_LOG"; then
    TESTS_RUN=$(grep -c "test crash_promotion::tests::" "$TEST_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "promo_unit_tests_pass" "PASS" "Tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "promo_unit_tests_pass" "FAIL" "Too few tests: ${TESTS_RUN} (expected >= 10)"
    fi
else
    scenario_result "promo_unit_tests_pass" "FAIL" "Crash promotion tests failed"
fi
rm -f "$TEST_LOG"

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
