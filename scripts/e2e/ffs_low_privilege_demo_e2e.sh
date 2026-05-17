#!/usr/bin/env bash
# ffs_low_privilege_demo_e2e.sh - non-permissioned low-privilege demo manifest gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_low_privilege_demo}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_LOW_PRIVILEGE_DEMO_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_LOW_PRIVILEGE_DEMO_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "manifest_id" in obj and "low_privilege_kinds" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("low-privilege demo report JSON object not found")
PY
}

e2e_init "ffs_low_privilege_demo"

MANIFEST_JSON="$REPO_ROOT/tests/low-privilege-demo/low_privilege_demo_manifest.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/low_privilege_demo"
REPORT_JSON="$E2E_LOG_DIR/low_privilege_demo_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/low_privilege_demo_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/low_privilege_demo_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/low_privilege_demo_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/low_privilege_demo_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/low_privilege_demo_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_LOW_PRIVILEGE_DEMO_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    cat <<'JSON'
{
  "valid": true,
  "manifest_id": "low_privilege_demo_v1",
  "lane_count": 5,
  "low_privilege_kinds": [
    "parser_unit",
    "invariant_oracle",
    "repair_dry_run"
  ],
  "host_skipped_lanes": [
    "mounted_smoke"
  ],
  "errors": []
}
JSON
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown low-privilege demo fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib low_privilege_demo"*)
        printf '%s\n' \
            "test default_manifest_validates_required_coverage ... ok" \
            "test render_low_privilege_demo_markdown_default_manifest ... ok" \
            "test fail_on_errors_rejects_invalid_report ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Low-Privilege Demo" \
            "" \
            "low-privilege kinds: parser_unit, invariant_oracle, repair_dry_run"
        exit 0
        ;;
    *"low_privilege_demo_invalid.json"*)
        echo "unsupported capability_requirement: kernel_admin"
        exit 2
        ;;
    *)
        emit_valid_report
        exit 0
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
    local child_log="$E2E_LOG_DIR/low_privilege_demo_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_LOW_PRIVILEGE_DEMO_SELF_CHECK=0 \
        FFS_LOW_PRIVILEGE_DEMO_SKIP_SELF_CHECK=1 \
        FFS_LOW_PRIVILEGE_DEMO_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_low_privilege_demo_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic low-privilege demo wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-low-privilege-demo-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/low_privilege_demo_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .lane_count == 5
            and (.low_privilege_kinds | index("parser_unit"))
            and (.low_privilege_kinds | index("invariant_oracle"))
            and (.low_privilege_kinds | index("repair_dry_run"))
            and (.host_skipped_lanes == ["mounted_smoke"])
        ' "$report_path" >/dev/null; then
        scenario_result "low_privilege_demo_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "low_privilege_demo_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "low-privilege demo complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "low_privilege_demo_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "low_privilege_demo_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "low-privilege demo local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "low-privilege demo wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: low-privilege demo CLI is wired"
if grep -q "pub mod low_privilege_demo" crates/ffs-harness/src/lib.rs \
    && grep -q '"validate-low-privilege-demo")' crates/ffs-harness/src/main.rs \
    && grep -q "scripts/e2e/ffs_low_privilege_demo_e2e.sh" scripts/e2e/scenario_catalog.json \
    && grep -q "validate-low-privilege-demo" "$MANIFEST_JSON" \
    && ! grep -Eq "run-low-privilege-demo|run-repair-dry-run|evaluate-release-gate([^s]|$)" "$MANIFEST_JSON"; then
    scenario_result "low_privilege_demo_cli_wired" "PASS" "module, CLI command, catalog suite, and manifest command are wired"
else
    scenario_result "low_privilege_demo_cli_wired" "FAIL" "missing module export, CLI command, catalog suite, or manifest command"
fi

e2e_step "Scenario 2: checked-in low-privilege demo manifest validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-low-privilege-demo \
    --manifest "$MANIFEST_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "low_privilege_demo_validates" "PASS" "checked-in manifest accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "low_privilege_demo_validates" "FAIL" "checked-in manifest rejected"
fi

e2e_step "Scenario 3: low-privilege lanes and host skips are explicit"
if python3 - "$REPORT_JSON" "$MANIFEST_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_low_privilege = {"parser_unit", "invariant_oracle", "repair_dry_run"}
required_host_skip = {"mounted_smoke"}
allowed_harness_commands = {
    "validate-low-privilege-demo",
    "validate-repair-confidence-lab",
    "evaluate-release-gates",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["lane_count"] < 5:
    raise SystemExit("expected at least five demo lanes")
missing_low = required_low_privilege - set(report["low_privilege_kinds"])
if missing_low:
    raise SystemExit(f"missing low-privilege kinds: {sorted(missing_low)}")
missing_host_skip = required_host_skip - set(report["host_skipped_lanes"])
if missing_host_skip:
    raise SystemExit(f"missing host-skipped lanes: {sorted(missing_host_skip)}")
commands = [manifest["command_line"]]
commands.extend(lane["reproduction_command"] for lane in manifest["lanes"])
stale_commands = [
    command
    for command in commands
    if "run-low-privilege-demo" in command
    or "run-repair-dry-run" in command
    or "evaluate-release-gate --" in command
]
if stale_commands:
    raise SystemExit(f"manifest still advertises stale harness commands: {stale_commands}")
for command in commands:
    marker = "cargo run -p ffs-harness -- "
    if marker not in command:
        continue
    command_name = command.split(marker, 1)[1].split()[0]
    if command_name not in allowed_harness_commands:
        raise SystemExit(f"unsupported harness command in manifest: {command_name}")
PY
then
    scenario_result "low_privilege_demo_coverage" "PASS" "lanes, low-privilege kinds, and host skips verified"
else
    scenario_result "low_privilege_demo_coverage" "FAIL" "low-privilege demo coverage contract failed"
fi

e2e_step "Scenario 4: invalid low-privilege demo manifest fails closed"
jq '.lanes[0].capability_requirement = "kernel_admin"' "$MANIFEST_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-low-privilege-demo \
    --manifest "$INVALID_JSON"; then
    scenario_result "low_privilege_demo_invalid_rejected" "FAIL" "invalid manifest unexpectedly passed"
elif grep -q "unsupported capability_requirement" "$INVALID_RAW"; then
    scenario_result "low_privilege_demo_invalid_rejected" "PASS" "unsupported capability is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "low_privilege_demo_invalid_rejected" "FAIL" "invalid manifest failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-low-privilege-demo \
    --manifest "$MANIFEST_JSON" \
    --format markdown \
    && grep -q "# Low-Privilege Demo" "$MARKDOWN_RAW" \
    && grep -q "low-privilege kinds" "$MARKDOWN_RAW" \
    && grep -q "Low-Privilege Demo Contract" scripts/e2e/README.md; then
    scenario_result "low_privilege_demo_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "low_privilege_demo_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: low-privilege demo unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib low_privilege_demo -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_manifest_validates_required_coverage" \
        "render_low_privilege_demo_markdown_default_manifest" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "low_privilege_demo_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "low_privilege_demo_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Low-privilege demo manifest: $MANIFEST_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Low-privilege demo scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Low-privilege demo scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
