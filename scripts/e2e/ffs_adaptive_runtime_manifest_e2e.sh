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
SELF_CHECK="${FFS_ADAPTIVE_RUNTIME_MANIFEST_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_ADAPTIVE_RUNTIME_MANIFEST_SKIP_SELF_CHECK:-0}"

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

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_ADAPTIVE_RUNTIME_MANIFEST_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
args=("$@")
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown adaptive runtime manifest fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2

if [[ "$command_text" == *"cargo test -p ffs-harness --lib adaptive_runtime_manifest"* ]]; then
    printf '%s\n' \
        "test checked_in_adaptive_runtime_manifest_validates ... ok" \
        "test strict_git_sha_mismatch_is_rejected ... ok" \
        "test render_adaptive_runtime_evidence_markdown_snapshot ... ok"
    exit 0
fi

if [[ "$command_text" != *"cargo run --quiet -p ffs-harness -- validate-adaptive-runtime-manifest"* ]]; then
    echo "unexpected fixture command: $command_text" >&2
    exit 64
fi

manifest_path=""
format="json"
current_git_sha=""
for ((index = 0; index < ${#args[@]}; index++)); do
    case "${args[$index]}" in
        --manifest)
            manifest_path="${args[$((index + 1))]:-}"
            ;;
        --format)
            format="${args[$((index + 1))]:-json}"
            ;;
        --current-git-sha)
            current_git_sha="${args[$((index + 1))]:-}"
            ;;
    esac
done

if [[ -n "$current_git_sha" ]]; then
    echo "git_sha mismatch: expected manifest git_sha but got ${current_git_sha}" >&2
    exit 1
fi

if [[ -z "$manifest_path" || ! -f "$manifest_path" ]]; then
    echo "manifest not found: ${manifest_path}" >&2
    exit 1
fi

if ! jq -e 'has("run_id")' "$manifest_path" >/dev/null; then
    echo "run_id is required in adaptive runtime manifest" >&2
    exit 1
fi

if [[ "$format" == "markdown" ]]; then
    printf '%s\n' \
        "# Adaptive Runtime Evidence Manifest" \
        "" \
        "- Runtime controls accepted: yes" \
        "- Release claim state: accepted_large_host"
    exit 0
fi

python3 - "$manifest_path" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
report = {
    "scenario_id": "adaptive_runtime_manifest_fixture_report",
    "valid": True,
    "runtime_controls_accepted": True,
    "release_claim_state": "accepted_large_host",
    "runtime_mode": "per_core",
    "host_lane": "permissioned_large_host",
    "host_classification": "large_host_floor_met",
    "fuse_capability_state": "available",
    "artifact_count": len(manifest.get("artifact_paths", [])),
    "raw_log_count": len(manifest.get("raw_log_paths", [])),
    "errors": [],
    "issues": [],
}
print(json.dumps(report, sort_keys=True))
PY
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
    local child_log="$E2E_LOG_DIR/adaptive_runtime_manifest_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_ADAPTIVE_RUNTIME_MANIFEST_SELF_CHECK=0 \
        FFS_ADAPTIVE_RUNTIME_MANIFEST_SKIP_SELF_CHECK=1 \
        FFS_ADAPTIVE_RUNTIME_MANIFEST_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_adaptive_runtime_manifest_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic adaptive runtime manifest wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir report_path markdown_path git_mismatch_path bad_manifest_path unit_log
    stub_path="$E2E_LOG_DIR/rch-adaptive-runtime-manifest-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    report_path="$result_dir/adaptive_runtime_manifest_report.json"
    markdown_path="$result_dir/adaptive_runtime_manifest_markdown.raw"
    git_mismatch_path="$result_dir/adaptive_runtime_manifest_git_mismatch.raw"
    bad_manifest_path="$result_dir/adaptive_runtime_manifest_missing_run_id.raw"
    unit_log="$result_dir/adaptive_runtime_manifest_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$markdown_path" ]] \
        && [[ -f "$git_mismatch_path" ]] \
        && [[ -f "$bad_manifest_path" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_rejects_git_mismatch" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_rejects_malformed" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_manifest_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .runtime_controls_accepted == true
            and .release_claim_state == "accepted_large_host"
            and .runtime_mode == "per_core"
            and .host_lane == "permissioned_large_host"
            and .host_classification == "large_host_floor_met"
            and .fuse_capability_state == "available"
            and .artifact_count > 0
            and .raw_log_count > 0
            and (.errors | length) == 0
            and (.issues | length) == 0
        ' "$report_path" >/dev/null \
        && grep -q "# Adaptive Runtime Evidence Manifest" "$markdown_path" \
        && grep -q "Runtime controls accepted" "$markdown_path" \
        && grep -q "git_sha" "$git_mismatch_path" \
        && grep -q "run_id" "$bad_manifest_path" \
        && grep -q "checked_in_adaptive_runtime_manifest_validates" "$unit_log" \
        && grep -q "strict_git_sha_mismatch_is_rejected" "$unit_log" \
        && grep -q "render_adaptive_runtime_evidence_markdown_snapshot" "$unit_log"; then
        scenario_result "adaptive_runtime_manifest_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "adaptive_runtime_manifest_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "adaptive runtime manifest complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "adaptive_runtime_manifest_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "adaptive_runtime_manifest_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "adaptive runtime manifest local fallback fixture self-check failed"
    fi
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

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

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
