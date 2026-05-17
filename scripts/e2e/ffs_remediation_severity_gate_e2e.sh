#!/usr/bin/env bash
# ffs_remediation_severity_gate_e2e.sh - non-permissioned remediation severity gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_remediation_severity_gate}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_REMEDIATION_SEVERITY_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REMEDIATION_SEVERITY_GATE_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "gate_id" in obj and "entry_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("remediation severity gate report JSON object not found")
PY
}

e2e_init "ffs_remediation_severity_gate"

GATE_JSON="$REPO_ROOT/tests/remediation-severity-gate/remediation_severity_gate.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/remediation_severity_gate"
REPORT_JSON="$E2E_LOG_DIR/remediation_severity_gate_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/remediation_severity_gate_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/remediation_severity_gate_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/remediation_severity_gate_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/remediation_severity_gate_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/remediation_severity_gate_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REMEDIATION_SEVERITY_GATE_FIXTURE_CASE:-complete}"

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
  "schema_version": 1,
  "gate_id": "frankenfs_remediation_severity_gate_v1",
  "bead_id": "bd-t6zqr",
  "entry_count": 11,
  "outcome_classes_covered": [
    "host_capability_skip",
    "inconclusive_oracle_conflict",
    "low_confidence_repair",
    "missing_proof_lane",
    "pass_with_experimental_caveat",
    "product_failure",
    "security_refusal",
    "stale_artifact",
    "unsafe_repair_refusal",
    "unsupported_operation"
  ],
  "block_release_count": 4,
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
        echo "unknown remediation severity gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib remediation_severity_gate"*)
        printf '%s\n' \
            "test default_gate_validates_required_classes ... ok" \
            "test render_remediation_severity_gate_markdown_default_gate ... ok" \
            "test fail_on_errors_rejects_invalid_report ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Remediation Severity Gate" \
            "" \
            "- block-release entries: \`4\`"
        exit 0
        ;;
    *"remediation_severity_gate_invalid.json"*)
        echo "data_loss_unrecoverable must use release_gate_effect=block_release"
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
    local child_log="$E2E_LOG_DIR/remediation_severity_gate_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REMEDIATION_SEVERITY_GATE_SELF_CHECK=0 \
        FFS_REMEDIATION_SEVERITY_GATE_SKIP_SELF_CHECK=1 \
        FFS_REMEDIATION_SEVERITY_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_remediation_severity_gate_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic remediation severity gate wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-remediation-severity-gate-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/remediation_severity_gate_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "remediation_severity_gate_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "remediation_severity_gate_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "remediation_severity_gate_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "remediation_severity_gate_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .entry_count == 11
            and .block_release_count == 4
            and (.outcome_classes_covered | index("product_failure"))
            and (.outcome_classes_covered | index("low_confidence_repair"))
            and (.outcome_classes_covered | index("pass_with_experimental_caveat"))
        ' "$report_path" >/dev/null; then
        scenario_result "remediation_severity_gate_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "remediation_severity_gate_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "remediation severity gate complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "remediation_severity_gate_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "remediation_severity_gate_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "remediation severity gate local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "remediation severity gate wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: remediation severity gate CLI is wired"
if grep -q "pub mod remediation_severity_gate" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-remediation-severity-gate" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_remediation_severity_gate" scripts/e2e/scenario_catalog.json; then
    scenario_result "remediation_severity_gate_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "remediation_severity_gate_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in remediation severity gate validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-severity-gate \
    --gate "$GATE_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "remediation_severity_gate_validates" "PASS" "checked-in gate accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "remediation_severity_gate_validates" "FAIL" "checked-in gate rejected"
fi

e2e_step "Scenario 3: outcome coverage and release blockers are explicit"
if python3 - "$REPORT_JSON" "$GATE_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
gate = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_classes = {
    "product_failure",
    "host_capability_skip",
    "unsafe_repair_refusal",
    "low_confidence_repair",
    "missing_proof_lane",
    "inconclusive_oracle_conflict",
    "pass_with_experimental_caveat",
}
allowed_harness_commands = {
    "validate-cross-oracle-arbitration",
    "validate-proof-bundle",
    "validate-remediation-severity-gate",
}
def harness_command_name(command):
    for marker in (
        "cargo run -p ffs-harness -- ",
        "cargo run --quiet -p ffs-harness -- ",
        "ffs-harness ",
    ):
        if marker in command:
            return command.split(marker, 1)[1].split()[0]
    return None

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["entry_count"] < 11:
    raise SystemExit("expected at least eleven remediation entries")
if report["block_release_count"] < 4:
    raise SystemExit("expected at least four block_release entries")
missing = required_classes - set(report["outcome_classes_covered"])
if missing:
    raise SystemExit(f"missing outcome classes: {sorted(missing)}")
for entry in gate["entries"]:
    if not entry["docs_target"]:
        raise SystemExit(f"missing docs_target: {entry['remediation_id']}")
    if not entry["artifact_requirements"]:
        raise SystemExit(f"missing artifact requirements: {entry['remediation_id']}")
    has_action = bool(entry["immediate_action_command"].strip())
    has_non_goal = bool(entry.get("explicit_non_goal_rationale", "").strip())
    if has_action == has_non_goal:
        raise SystemExit(f"entry must have exactly one action or non-goal rationale: {entry['remediation_id']}")
    command = entry["immediate_action_command"]
    for stale_command in ("build-operator-proof-bundle", "arbitrate-cross-oracle"):
        if stale_command in command:
            raise SystemExit(f"stale harness command in {entry['remediation_id']}: {stale_command}")
    command_name = harness_command_name(command)
    if command_name and command_name not in allowed_harness_commands:
        raise SystemExit(
            f"unsupported ffs-harness command in {entry['remediation_id']}: {command_name}"
        )
PY
then
    scenario_result "remediation_severity_gate_coverage" "PASS" "outcome coverage, blockers, docs, artifacts, and actions verified"
else
    scenario_result "remediation_severity_gate_coverage" "FAIL" "remediation severity coverage contract failed"
fi

e2e_step "Scenario 4: invalid remediation severity gate fails closed"
jq '.entries[0].release_gate_effect = "annotate_caveat"' "$GATE_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-severity-gate \
    --gate "$INVALID_JSON"; then
    scenario_result "remediation_severity_gate_invalid_rejected" "FAIL" "invalid gate unexpectedly passed"
elif grep -q "data_loss_unrecoverable" "$INVALID_RAW"; then
    scenario_result "remediation_severity_gate_invalid_rejected" "PASS" "unrecoverable-loss downgrade is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "remediation_severity_gate_invalid_rejected" "FAIL" "invalid gate failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-severity-gate \
    --gate "$GATE_JSON" \
    --format markdown \
    && grep -q "# Remediation Severity Gate" "$MARKDOWN_RAW" \
    && grep -q "block-release entries" "$MARKDOWN_RAW" \
    && grep -q "Remediation Severity Gate Contract" scripts/e2e/README.md; then
    scenario_result "remediation_severity_gate_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "remediation_severity_gate_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: remediation severity gate unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib remediation_severity_gate -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_gate_validates_required_classes" \
        "render_remediation_severity_gate_markdown_default_gate" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "remediation_severity_gate_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "remediation_severity_gate_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Remediation severity gate: $GATE_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Remediation severity gate scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Remediation severity gate scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
