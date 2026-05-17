#!/usr/bin/env bash
# ffs_low_privilege_demo_sandbox_e2e.sh - non-permissioned low-privilege demo sandbox gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_low_privilege_demo_sandbox}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_LOW_PRIVILEGE_DEMO_SANDBOX_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_LOW_PRIVILEGE_DEMO_SANDBOX_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "manifest_id" in obj and "lane_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("low-privilege demo sandbox report JSON object not found")
PY
}

e2e_init "ffs_low_privilege_demo_sandbox"

MANIFEST_JSON="$REPO_ROOT/tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/low_privilege_demo_sandbox"
REPORT_JSON="$E2E_LOG_DIR/low_privilege_demo_sandbox_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/low_privilege_demo_sandbox_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/low_privilege_demo_sandbox_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/low_privilege_demo_sandbox_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/low_privilege_demo_sandbox_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/low_privilege_demo_sandbox_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_LOW_PRIVILEGE_DEMO_SANDBOX_FIXTURE_CASE:-complete}"

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
  "manifest_id": "low_privilege_demo_sandbox_v1",
  "fixture_count": 4,
  "lane_count": 4,
  "host_skipped_lanes": 1,
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
        echo "unknown low-privilege demo sandbox fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib low_privilege_demo_sandbox"*)
        printf '%s\n' \
            "test default_manifest_validates_required_lanes_and_side_effects ... ok" \
            "test render_low_privilege_demo_sandbox_markdown_default_manifest ... ok" \
            "test fail_on_errors_rejects_invalid_report ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Low-Privilege Demo Sandbox" \
            "" \
            "host-skipped lanes: 1"
        exit 0
        ;;
    *"low_privilege_demo_sandbox_invalid.json"*)
        echo "forbidden host root: /etc/frankenfs-demo"
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
    local child_log="$E2E_LOG_DIR/low_privilege_demo_sandbox_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_LOW_PRIVILEGE_DEMO_SANDBOX_SELF_CHECK=0 \
        FFS_LOW_PRIVILEGE_DEMO_SANDBOX_SKIP_SELF_CHECK=1 \
        FFS_LOW_PRIVILEGE_DEMO_SANDBOX_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_low_privilege_demo_sandbox_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic low-privilege demo sandbox wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-low-privilege-demo-sandbox-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/low_privilege_demo_sandbox_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_sandbox_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_sandbox_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_sandbox_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "low_privilege_demo_sandbox_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .fixture_count == 4
            and .lane_count == 4
            and .host_skipped_lanes == 1
        ' "$report_path" >/dev/null; then
        scenario_result "low_privilege_demo_sandbox_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "low_privilege_demo_sandbox_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "low-privilege demo sandbox complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "low_privilege_demo_sandbox_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "low_privilege_demo_sandbox_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "low-privilege demo sandbox local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "low-privilege demo sandbox wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: low-privilege demo sandbox CLI is wired"
if grep -q "pub mod low_privilege_demo_sandbox" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-low-privilege-demo-sandbox" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_low_privilege_demo_sandbox" scripts/e2e/scenario_catalog.json; then
    scenario_result "low_privilege_demo_sandbox_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "low_privilege_demo_sandbox_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in low-privilege demo sandbox manifest validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-low-privilege-demo-sandbox \
    --manifest "$MANIFEST_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "low_privilege_demo_sandbox_validates" "PASS" "checked-in manifest accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "low_privilege_demo_sandbox_validates" "FAIL" "checked-in manifest rejected"
fi

e2e_step "Scenario 3: sandbox coverage and host-skip limits are explicit"
if python3 - "$REPORT_JSON" "$MANIFEST_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_lanes = {
    "parser_unit",
    "invariant_oracle",
    "repair_dry_run",
    "mounted_smoke_host_skipped",
}
required_effects = {
    "no_writes_outside_workspace_root",
    "no_kernel_module_load",
    "no_root_owned_writes",
    "no_network_egress_outside_capability_probe",
    "no_modification_of_committed_fixtures",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["fixture_count"] < 4 or report["lane_count"] < 4:
    raise SystemExit("expected at least four fixtures and four lanes")
if report["host_skipped_lanes"] < 1:
    raise SystemExit("expected at least one explicit host-skipped lane")
missing_lanes = required_lanes - {lane["name"] for lane in manifest["lanes"]}
if missing_lanes:
    raise SystemExit(f"missing required lanes: {sorted(missing_lanes)}")
missing_effects = required_effects - set(manifest["forbidden_side_effects"])
if missing_effects:
    raise SystemExit(f"missing forbidden side effects: {sorted(missing_effects)}")
for lane in manifest["lanes"]:
    if lane["expected_outcome"] == "host_skipped" and lane["claims_mounted_readiness"]:
        raise SystemExit(f"host-skipped lane claims mounted readiness: {lane['lane_id']}")
PY
then
    scenario_result "low_privilege_demo_sandbox_coverage" "PASS" "lanes, side effects, and host-skip limits verified"
else
    scenario_result "low_privilege_demo_sandbox_coverage" "FAIL" "low-privilege demo sandbox coverage contract failed"
fi

e2e_step "Scenario 4: invalid low-privilege demo sandbox manifest fails closed"
jq '.allowed_workspace_root = "/etc/frankenfs-demo"' "$MANIFEST_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-low-privilege-demo-sandbox \
    --manifest "$INVALID_JSON"; then
    scenario_result "low_privilege_demo_sandbox_invalid_rejected" "FAIL" "invalid manifest unexpectedly passed"
elif grep -q "forbidden host root" "$INVALID_RAW"; then
    scenario_result "low_privilege_demo_sandbox_invalid_rejected" "PASS" "forbidden host root is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "low_privilege_demo_sandbox_invalid_rejected" "FAIL" "invalid manifest failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-low-privilege-demo-sandbox \
    --manifest "$MANIFEST_JSON" \
    --format markdown \
    && grep -q "# Low-Privilege Demo Sandbox" "$MARKDOWN_RAW" \
    && grep -q "host-skipped lanes" "$MARKDOWN_RAW" \
    && grep -q "Low-Privilege Demo Sandbox Contract" scripts/e2e/README.md; then
    scenario_result "low_privilege_demo_sandbox_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "low_privilege_demo_sandbox_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: low-privilege demo sandbox unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib low_privilege_demo_sandbox -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_manifest_validates_required_lanes_and_side_effects" \
        "render_low_privilege_demo_sandbox_markdown_default_manifest" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "low_privilege_demo_sandbox_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "low_privilege_demo_sandbox_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Low-privilege demo sandbox manifest: $MANIFEST_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Low-privilege demo sandbox scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Low-privilege demo sandbox scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
