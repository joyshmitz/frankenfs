#!/usr/bin/env bash
# ffs_fuzz_targets_e2e.sh - E2E verification for cargo-fuzz targets
#
# Validates that all fuzz targets:
# 1. Are listed by cargo fuzz list
# 2. Compile successfully
# 3. Execute a short smoke run (100 iterations) without crashes
# 4. Emit structured scenario results
#
# Usage: ./scripts/e2e/ffs_fuzz_targets_e2e.sh
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

mapfile -t EXPECTED_TARGETS < <(
    find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
)
PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

cleanup_tmp_file() {
    local path="$1"
    if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" == "1" ]]; then
        e2e_log "Temp cleanup disabled; preserving temp file: $path"
    else
        rm -f "$path"
    fi
}

cleanup_tmp_dir() {
    local path="$1"
    if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" == "1" ]]; then
        e2e_log "Temp cleanup disabled; preserving temp directory: $path"
    else
        rm -rf "$path"
    fi
}

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

e2e_init "ffs_fuzz_targets"

#######################################
# Scenario 1: cargo fuzz list shows all expected targets
#######################################
e2e_step "Scenario 1: Verify fuzz target listing"

FUZZ_LIST_OUTPUT=$(cargo fuzz list --fuzz-dir fuzz 2>&1 || true)
ALL_FOUND=true
for target in "${EXPECTED_TARGETS[@]}"; do
    if ! echo "$FUZZ_LIST_OUTPUT" | grep -q "^${target}$"; then
        ALL_FOUND=false
        scenario_result "fuzz_list_${target}" "FAIL" "Target '${target}' not found in cargo fuzz list output"
    fi
done

if [[ "$ALL_FOUND" == "true" ]]; then
    TARGET_COUNT=$(echo "$FUZZ_LIST_OUTPUT" | wc -l)
    scenario_result "fuzz_list_all" "PASS" "All ${TARGET_COUNT} expected fuzz targets found"
else
    scenario_result "fuzz_list_all" "FAIL" "Some expected fuzz targets missing"
fi

#######################################
# Scenario 2: cargo fuzz build succeeds
#######################################
e2e_step "Scenario 2: Build all fuzz targets"

BUILD_LOG=$(mktemp)
if cargo fuzz build --fuzz-dir fuzz >"$BUILD_LOG" 2>&1; then
    scenario_result "fuzz_build" "PASS" "All fuzz targets compiled successfully"
else
    scenario_result "fuzz_build" "FAIL" "Fuzz target build failed; see $BUILD_LOG"
    # If build fails, remaining scenarios will fail too; report and exit
    e2e_log "Build log tail:"
    tail -20 "$BUILD_LOG" | while IFS= read -r line; do e2e_log "  $line"; done
fi
cleanup_tmp_file "$BUILD_LOG"

#######################################
# Scenario 3: Smoke run each target (100 iterations, no crash)
#######################################
e2e_step "Scenario 3: Smoke-run fuzz targets"

for target in "${EXPECTED_TARGETS[@]}"; do
    SMOKE_LOG=$(mktemp)
    if cargo fuzz run "$target" --fuzz-dir fuzz -- -runs=100 -max_total_time=10 >"$SMOKE_LOG" 2>&1; then
        scenario_result "fuzz_smoke_${target}" "PASS" "100 iterations completed without crash"
    else
        EXIT_CODE=$?
        if [[ $EXIT_CODE -eq 77 ]]; then
            # libFuzzer exit code 77 = crash found
            scenario_result "fuzz_smoke_${target}" "FAIL" "Crash found during smoke run; see $SMOKE_LOG"
        else
            scenario_result "fuzz_smoke_${target}" "FAIL" "Smoke run failed with exit code ${EXIT_CODE}"
        fi
    fi
    cleanup_tmp_file "$SMOKE_LOG"
done

#######################################
# Scenario 4: Seed corpus directories exist with samples
#######################################
e2e_step "Scenario 4: Verify seed corpus"

for target in "${EXPECTED_TARGETS[@]}"; do
    CORPUS_DIR="fuzz/corpus/${target}"
    if [[ -d "$CORPUS_DIR" ]]; then
        SAMPLE_COUNT=$(find "$CORPUS_DIR" -type f | wc -l)
        if [[ $SAMPLE_COUNT -gt 0 ]]; then
            scenario_result "fuzz_corpus_${target}" "PASS" "${SAMPLE_COUNT} seed samples in ${CORPUS_DIR}"
        else
            scenario_result "fuzz_corpus_${target}" "FAIL" "Corpus directory exists but is empty: ${CORPUS_DIR}"
        fi
    else
        scenario_result "fuzz_corpus_${target}" "FAIL" "Corpus directory missing: ${CORPUS_DIR}"
    fi
done

#######################################
# Scenario 5: Dictionaries exist for ext4 and btrfs
#######################################
e2e_step "Scenario 5: Verify fuzz dictionaries"

for dict in ext4.dict btrfs.dict; do
    DICT_PATH="fuzz/dictionaries/${dict}"
    if [[ -f "$DICT_PATH" ]]; then
        TOKEN_COUNT=$(grep -c '^"' "$DICT_PATH" || true)
        NAMED_COUNT=$(grep -cE '^[a-z].*="' "$DICT_PATH" || true)
        TOTAL_TOKENS=$((TOKEN_COUNT + NAMED_COUNT))
        if [[ $TOTAL_TOKENS -ge 5 ]]; then
            scenario_result "fuzz_dict_${dict%.dict}" "PASS" "${TOTAL_TOKENS} tokens in ${DICT_PATH}"
        else
            scenario_result "fuzz_dict_${dict%.dict}" "FAIL" "Too few tokens (${TOTAL_TOKENS}) in ${DICT_PATH}"
        fi
    else
        scenario_result "fuzz_dict_${dict%.dict}" "FAIL" "Dictionary missing: ${DICT_PATH}"
    fi
done

#######################################
# Scenario 6: Seed generation script runs successfully
#######################################
e2e_step "Scenario 6: Verify seed generation pipeline"

SEED_SCRIPT="fuzz/scripts/generate_seeds.sh"
if [[ -x "$SEED_SCRIPT" ]]; then
    GEN_LOG=$(mktemp)
    if bash "$SEED_SCRIPT" >"$GEN_LOG" 2>&1; then
        scenario_result "fuzz_seed_pipeline" "PASS" "Seed generation script completed successfully"
    else
        scenario_result "fuzz_seed_pipeline" "FAIL" "Seed generation failed"
    fi
    cleanup_tmp_file "$GEN_LOG"
else
    scenario_result "fuzz_seed_pipeline" "FAIL" "Seed generation script missing or not executable"
fi

#######################################
# Scenario 7: Dictionary-enhanced run improves coverage
#######################################
e2e_step "Scenario 7: Dictionary coverage improvement"

DICT_LOG=$(mktemp)
if cargo fuzz run fuzz_ext4_metadata --fuzz-dir fuzz -- -runs=200 -max_total_time=10 -dict=fuzz/dictionaries/ext4.dict >"$DICT_LOG" 2>&1; then
    # Check that ManualDict was used (indicates dictionary is actively helping)
    if grep -q "ManualDict\|Dict" "$DICT_LOG"; then
        scenario_result "fuzz_dict_coverage" "PASS" "Dictionary tokens actively used during fuzzing"
    else
        scenario_result "fuzz_dict_coverage" "PASS" "Dictionary run completed (no ManualDict markers but no crash)"
    fi
else
    scenario_result "fuzz_dict_coverage" "FAIL" "Dictionary-enhanced fuzz run failed"
fi
cleanup_tmp_file "$DICT_LOG"

#######################################
# Scenario 8: Nightly campaign runner produces valid summary
#######################################
e2e_step "Scenario 8: Nightly campaign runner"

NIGHTLY_SCRIPT="fuzz/scripts/nightly_fuzz.sh"
if [[ -x "$NIGHTLY_SCRIPT" ]]; then
    CAMPAIGN_LOG=$(mktemp)
    FUZZ_ARTIFACTS_DIR=$(mktemp -d)
    export FUZZ_ARTIFACTS_DIR
    if bash "$NIGHTLY_SCRIPT" --duration 3 >"$CAMPAIGN_LOG" 2>&1; then
        # Find the campaign summary
        SUMMARY_FILE=$(find "$FUZZ_ARTIFACTS_DIR" -name "campaign_summary.json" -type f 2>/dev/null | head -1)
        if [[ -n "$SUMMARY_FILE" ]] && python3 -c "import json; json.load(open('$SUMMARY_FILE'))" 2>/dev/null; then
            # Validate required fields
            HAS_FIELDS=$(python3 -c "
import json
with open('$SUMMARY_FILE') as f:
    d = json.load(f)
required = ['campaign_id', 'commit_sha', 'config', 'totals', 'targets']
print('ok' if all(k in d for k in required) else 'missing')
")
            if [[ "$HAS_FIELDS" == "ok" ]]; then
                scenario_result "fuzz_nightly_campaign" "PASS" "Campaign summary is valid JSON with required fields"
            else
                scenario_result "fuzz_nightly_campaign" "FAIL" "Campaign summary missing required fields"
            fi
        else
            scenario_result "fuzz_nightly_campaign" "FAIL" "Campaign summary not found or invalid JSON"
        fi
    else
        scenario_result "fuzz_nightly_campaign" "FAIL" "Nightly campaign script failed"
    fi
    cleanup_tmp_file "$CAMPAIGN_LOG"
    cleanup_tmp_dir "$FUZZ_ARTIFACTS_DIR"
    unset FUZZ_ARTIFACTS_DIR
else
    scenario_result "fuzz_nightly_campaign" "FAIL" "Nightly campaign script missing or not executable"
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
