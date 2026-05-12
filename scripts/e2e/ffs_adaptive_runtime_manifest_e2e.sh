#!/usr/bin/env bash
# ffs_adaptive_runtime_manifest_e2e.sh - non-permissioned adaptive runtime manifest gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_adaptive_runtime_manifest}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

extract_report_json() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "scenario_id" in obj and "runtime_controls_accepted" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("adaptive runtime manifest JSON report not found")
PY
}

e2e_init "ffs_adaptive_runtime_manifest"

MANIFEST_JSON="$REPO_ROOT/docs/adaptive-runtime-evidence-manifest.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/adaptive_runtime_manifest"
REPORT_JSON="$E2E_LOG_DIR/adaptive_runtime_manifest_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/adaptive_runtime_manifest_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/adaptive_runtime_manifest_markdown.raw"
GIT_MISMATCH_RAW="$E2E_LOG_DIR/adaptive_runtime_manifest_git_mismatch.raw"
BAD_MANIFEST_JSON="$RCH_INPUT_DIR/adaptive_runtime_manifest_missing_run_id.json"
BAD_MANIFEST_RAW="$E2E_LOG_DIR/adaptive_runtime_manifest_missing_run_id.raw"
UNIT_LOG="$E2E_LOG_DIR/adaptive_runtime_manifest_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: adaptive runtime manifest CLI is wired"
if grep -q "pub mod adaptive_runtime_manifest" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-adaptive-runtime-manifest" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_adaptive_runtime_manifest" scripts/e2e/scenario_catalog.json; then
    scenario_result "adaptive_runtime_manifest_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "adaptive_runtime_manifest_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in adaptive runtime manifest validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-adaptive-runtime-manifest \
    --manifest "$MANIFEST_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "adaptive_runtime_manifest_validates" "PASS" "checked-in adaptive runtime manifest accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "adaptive_runtime_manifest_validates" "FAIL" "checked-in adaptive runtime manifest rejected"
fi

e2e_step "Scenario 3: accepted-large-host contract stays explicit"
if python3 - "$REPORT_JSON" "$MANIFEST_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))

if not report["valid"]:
    raise SystemExit(report["errors"])
if not report["runtime_controls_accepted"]:
    raise SystemExit("runtime controls should be accepted for checked-in large-host evidence")
if report["release_claim_state"] != "accepted_large_host":
    raise SystemExit(f"unexpected release claim: {report['release_claim_state']}")
if report["runtime_mode"] != "per_core":
    raise SystemExit(f"unexpected runtime mode: {report['runtime_mode']}")
if report["host_lane"] != "permissioned_large_host":
    raise SystemExit(f"unexpected host lane: {report['host_lane']}")
if report["host_classification"] != "large_host_floor_met":
    raise SystemExit(f"unexpected host classification: {report['host_classification']}")
if report["fuse_capability_state"] != "available":
    raise SystemExit(f"unexpected FUSE capability: {report['fuse_capability_state']}")
if report["artifact_count"] != len(manifest["artifact_paths"]):
    raise SystemExit("artifact count drifted")
if report["raw_log_count"] != len(manifest["raw_log_paths"]):
    raise SystemExit("raw log count drifted")
if report["errors"] or report["issues"]:
    raise SystemExit("accepted manifest must not carry errors or issues")
if manifest["controlling_ack_env"] != "FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK":
    raise SystemExit("unexpected controlling ACK env")
if "validate-adaptive-runtime-manifest" not in manifest["reproduction_command"]:
    raise SystemExit("reproduction command does not point at the validator")
PY
then
    scenario_result "adaptive_runtime_manifest_contract" "PASS" "accepted evidence fields and counts verified"
else
    scenario_result "adaptive_runtime_manifest_contract" "FAIL" "accepted evidence contract failed"
fi

e2e_step "Scenario 4: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-adaptive-runtime-manifest \
    --manifest "$MANIFEST_JSON" \
    --format markdown \
    --summary-out /dev/stdout \
    && grep -q "# Adaptive Runtime Evidence Manifest" "$MARKDOWN_RAW" \
    && grep -q "Runtime controls accepted" "$MARKDOWN_RAW" \
    && grep -q "Adaptive Runtime Manifest Contract" scripts/e2e/README.md; then
    scenario_result "adaptive_runtime_manifest_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "adaptive_runtime_manifest_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 5: strict git SHA mismatch fails closed"
if e2e_rch_capture "$GIT_MISMATCH_RAW" cargo run --quiet -p ffs-harness -- \
    validate-adaptive-runtime-manifest \
    --manifest "$MANIFEST_JSON" \
    --current-git-sha "definitely-not-the-manifest-sha"; then
    scenario_result "adaptive_runtime_manifest_rejects_git_mismatch" "FAIL" "git SHA mismatch unexpectedly passed"
elif grep -q "git_sha" "$GIT_MISMATCH_RAW"; then
    scenario_result "adaptive_runtime_manifest_rejects_git_mismatch" "PASS" "git SHA mismatch rejected"
else
    cat "$GIT_MISMATCH_RAW"
    scenario_result "adaptive_runtime_manifest_rejects_git_mismatch" "FAIL" "git SHA mismatch failed without actionable diagnostics"
fi

e2e_step "Scenario 6: malformed manifest fails closed"
jq 'del(.run_id)' "$MANIFEST_JSON" >"$BAD_MANIFEST_JSON"
if e2e_rch_capture "$BAD_MANIFEST_RAW" cargo run --quiet -p ffs-harness -- \
    validate-adaptive-runtime-manifest \
    --manifest "$BAD_MANIFEST_JSON"; then
    scenario_result "adaptive_runtime_manifest_rejects_malformed" "FAIL" "missing run_id unexpectedly passed"
elif grep -q "run_id" "$BAD_MANIFEST_RAW"; then
    scenario_result "adaptive_runtime_manifest_rejects_malformed" "PASS" "missing run_id rejected"
else
    cat "$BAD_MANIFEST_RAW"
    scenario_result "adaptive_runtime_manifest_rejects_malformed" "FAIL" "malformed manifest failed without actionable diagnostics"
fi

e2e_step "Scenario 7: adaptive runtime manifest unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib adaptive_runtime_manifest -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "checked_in_adaptive_runtime_manifest_validates" \
        "strict_git_sha_mismatch_is_rejected" \
        "render_adaptive_runtime_evidence_markdown_snapshot"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "adaptive_runtime_manifest_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "adaptive_runtime_manifest_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Adaptive runtime manifest: $MANIFEST_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Adaptive runtime manifest scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Adaptive runtime manifest scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
