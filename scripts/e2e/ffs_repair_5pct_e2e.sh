#!/usr/bin/env bash
# ffs_repair_5pct_e2e.sh - Deterministic 5% corruption auto-repair E2E
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

source "$REPO_ROOT/scripts/e2e/lib.sh"

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
    local output_path="$1"
    shift
    local status rch_log_path
    rch_log_path="${output_path}.rch.log"
    if RCH_VISIBILITY=none RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-error}" timeout "${RCH_COMMAND_TIMEOUT_SECS:-300}s" \
        "${RCH_BIN:-rch}" exec -- env FFS_REMOTE_ARTIFACT_DIR="$ARTIFACT_DIR" bash -lc '
            set -euo pipefail
            mkdir -p "$FFS_REMOTE_ARTIFACT_DIR"
            remote_output="$FFS_REMOTE_ARTIFACT_DIR/rch-command-output.$$.log"
            set +e
            FFS_REPAIR_E2E_ARTIFACT_DIR="$FFS_REMOTE_ARTIFACT_DIR" "$@" >"$remote_output" 2>&1
            status=$?
            set -e
            printf "%s\n" "__FFS_REMOTE_OUTPUT_BEGIN__"
            cat "$remote_output"
            printf "%s\n" "__FFS_REMOTE_OUTPUT_END__"
            printf "%s\n" "__FFS_REMOTE_ARTIFACTS_BEGIN__"
            tar -C "$FFS_REMOTE_ARTIFACT_DIR" -cf - . | base64 -w 0
            printf "\n%s\n" "__FFS_REMOTE_ARTIFACTS_END__"
            exit "$status"
        ' _ "$@" >"$rch_log_path" 2>&1; then
        status=0
    else
        status=$?
    fi
    if ! awk '
        $0 == "__FFS_REMOTE_OUTPUT_BEGIN__" { capture = 1; next }
        $0 == "__FFS_REMOTE_OUTPUT_END__" { found = 1; capture = 0; next }
        capture { print }
        END { exit found ? 0 : 1 }
    ' "$rch_log_path" >"$output_path"; then
        cp "$rch_log_path" "$output_path"
    fi
    awk '
        $0 == "__FFS_REMOTE_ARTIFACTS_BEGIN__" { capture = 1; next }
        $0 == "__FFS_REMOTE_ARTIFACTS_END__" { found = 1; capture = 0; next }
        capture { print }
        END { exit found ? 0 : 1 }
    ' "$rch_log_path" | base64 --decode | tar -C "$ARTIFACT_DIR" -xf - || true
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$rch_log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}"
        return 0
    fi
    return "$status"
}

e2e_init "ffs_repair_5pct_e2e"
e2e_print_env

e2e_step "Run 5% corruption auto-repair scenario"
ARTIFACT_DIR="$E2E_LOG_DIR/repair_5pct"
mkdir -p "$ARTIFACT_DIR"
TEST_LOG="$ARTIFACT_DIR/cargo_test.log"

# Keep this runner isolated from other in-flight cargo jobs.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_5pct}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
export FFS_REPAIR_E2E_ARTIFACT_DIR="$ARTIFACT_DIR"

if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair e2e_survive_five_percent_random_block_corruption_with_daemon -- --nocapture; then
    scenario_result "repair_5pct_remote_cargo_test" "PASS" "focused repair corruption test passed via RCH"
else
    cat "$TEST_LOG"
    scenario_result "repair_5pct_remote_cargo_test" "FAIL" "focused repair corruption test failed"
fi

e2e_step "Validate generated artifacts"
if [[ -f "$ARTIFACT_DIR/before_checksums.txt" ]] \
    && [[ -f "$ARTIFACT_DIR/after_checksums.txt" ]] \
    && [[ -f "$ARTIFACT_DIR/corruption_plan.json" ]] \
    && [[ -f "$ARTIFACT_DIR/recovery_evidence.jsonl" ]]; then
    scenario_result "repair_5pct_artifacts_present" "PASS" "expected repair artifacts present"
else
    scenario_result "repair_5pct_artifacts_present" "FAIL" "missing one or more expected repair artifacts"
fi

# End-to-end guarantee: recovered content must exactly match baseline.
if cmp "$ARTIFACT_DIR/before_checksums.txt" "$ARTIFACT_DIR/after_checksums.txt"; then
    scenario_result "repair_5pct_checksum_equality" "PASS" "recovered content checksums match baseline"
else
    scenario_result "repair_5pct_checksum_equality" "FAIL" "recovered content checksums differ"
fi

if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import json, pathlib; p = pathlib.Path('$ARTIFACT_DIR/corruption_plan.json'); d = json.loads(p.read_text()); assert d['corruption_percent'] == 5; assert d['total_corrupted_blocks'] > 0"; then
        scenario_result "repair_5pct_corruption_plan" "PASS" "corruption plan records nonzero 5 percent corruption"
    else
        scenario_result "repair_5pct_corruption_plan" "FAIL" "corruption plan contract failed"
    fi
fi

if evidence_lines="$(wc -l <"$ARTIFACT_DIR/recovery_evidence.jsonl")" && [[ "$evidence_lines" -gt 0 ]]; then
    e2e_log "repair_5pct_recovery_evidence_lines=${evidence_lines}"
    scenario_result "repair_5pct_recovery_evidence" "PASS" "recovery evidence JSONL is non-empty"
else
    scenario_result "repair_5pct_recovery_evidence" "FAIL" "recovery evidence JSONL is empty or unreadable"
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass
else
    e2e_fail "repair 5pct scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
