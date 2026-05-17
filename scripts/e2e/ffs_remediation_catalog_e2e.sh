#!/usr/bin/env bash
# ffs_remediation_catalog_e2e.sh - non-permissioned remediation catalog gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_remediation_catalog}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_REMEDIATION_CATALOG_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REMEDIATION_CATALOG_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "catalog_id" in obj and "entry_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("remediation catalog report JSON object not found")
PY
}

e2e_init "ffs_remediation_catalog"

CATALOG_JSON="$REPO_ROOT/tests/remediation-catalog/remediation_catalog.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/remediation_catalog"
REPORT_JSON="$E2E_LOG_DIR/remediation_catalog_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/remediation_catalog_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/remediation_catalog_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/remediation_catalog_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/remediation_catalog_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/remediation_catalog_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REMEDIATION_CATALOG_FIXTURE_CASE:-complete}"

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
  "catalog_id": "frankenfs_remediation_catalog_v1",
  "entry_count": 7,
  "outcome_classes": [
    "product_failure",
    "host_capability_skip",
    "unsupported_operation",
    "stale_artifact",
    "security_refusal",
    "unsafe_repair_refusal",
    "passing_with_caveat"
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
        echo "unknown remediation catalog fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib remediation_catalog"*)
        printf '%s\n' \
            "test default_catalog_validates_required_outcomes ... ok" \
            "test render_markdown_includes_all_entries ... ok" \
            "test render_remediation_markdown_default_catalog_snapshot ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Remediation Catalog" \
            "" \
            "product_failure"
        exit 0
        ;;
    *"remediation_catalog_invalid.json"*)
        echo "unsupported outcome_class: mystery_outcome"
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
    local child_log="$E2E_LOG_DIR/remediation_catalog_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REMEDIATION_CATALOG_SELF_CHECK=0 \
        FFS_REMEDIATION_CATALOG_SKIP_SELF_CHECK=1 \
        FFS_REMEDIATION_CATALOG_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_remediation_catalog_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic remediation catalog wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-remediation-catalog-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/remediation_catalog_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "remediation_catalog_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "remediation_catalog_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "remediation_catalog_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "remediation_catalog_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .entry_count == 7
            and (.outcome_classes | index("product_failure"))
            and (.outcome_classes | index("unsafe_repair_refusal"))
        ' "$report_path" >/dev/null; then
        scenario_result "remediation_catalog_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "remediation_catalog_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "remediation catalog complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "remediation_catalog_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "remediation_catalog_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "remediation catalog local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "remediation catalog wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: remediation catalog CLI is wired"
if grep -q "pub mod remediation_catalog" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-remediation-catalog" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_remediation_catalog" scripts/e2e/scenario_catalog.json; then
    scenario_result "remediation_catalog_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "remediation_catalog_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in remediation catalog validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-catalog \
    --catalog "$CATALOG_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "remediation_catalog_validates" "PASS" "checked-in catalog accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "remediation_catalog_validates" "FAIL" "checked-in catalog rejected"
fi

e2e_step "Scenario 3: remediation catalog preserves outcome coverage and operator actions"
if python3 - "$REPORT_JSON" "$CATALOG_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
catalog = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_outcomes = {
    "product_failure",
    "host_capability_skip",
    "unsupported_operation",
    "stale_artifact",
    "security_refusal",
    "unsafe_repair_refusal",
    "passing_with_caveat",
}
allowed_harness_commands = {
    "fuse-capability-probe",
    "validate-proof-bundle",
    "validate-adversarial-threat-model",
    "validate-repair-confidence-lab",
    "validate-remediation-catalog",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["entry_count"] < len(required_outcomes):
    raise SystemExit("expected at least one entry for every required outcome class")
missing_outcomes = required_outcomes - set(report["outcome_classes"])
if missing_outcomes:
    raise SystemExit(f"missing outcome classes: {sorted(missing_outcomes)}")
for entry in catalog["entries"]:
    for field in (
        "user_summary",
        "technical_cause",
        "immediate_action",
        "safe_retry_policy",
        "reproduction_command",
        "owning_bead",
        "docs_target",
    ):
        if not str(entry[field]).strip():
            raise SystemExit(f"missing {field}: {entry['id']}")
    if not entry["artifact_links"]:
        raise SystemExit(f"missing artifact links: {entry['id']}")
    if not entry["owning_bead"].startswith("bd-"):
        raise SystemExit(f"owning bead must be a bd id: {entry['id']}")
    command = entry["reproduction_command"]
    for stale_command in ("run-repair-confidence-lab", "build-operator-proof-bundle"):
        if stale_command in command:
            raise SystemExit(f"stale harness command in {entry['id']}: {stale_command}")
    for marker in (
        "cargo run -p ffs-harness -- ",
        "cargo run --quiet -p ffs-harness -- ",
    ):
        if marker not in command:
            continue
        command_name = command.split(marker, 1)[1].split()[0]
        if command_name not in allowed_harness_commands:
            raise SystemExit(
                f"unsupported ffs-harness command in {entry['id']}: {command_name}"
            )
PY
then
    scenario_result "remediation_catalog_coverage" "PASS" "outcome coverage, actions, artifacts, and ownership verified"
else
    scenario_result "remediation_catalog_coverage" "FAIL" "remediation catalog coverage contract failed"
fi

e2e_step "Scenario 4: invalid remediation catalog fails closed"
jq '.entries[0].outcome_class = "mystery_outcome"' "$CATALOG_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-catalog \
    --catalog "$INVALID_JSON"; then
    scenario_result "remediation_catalog_invalid_rejected" "FAIL" "invalid catalog unexpectedly passed"
elif grep -q "unsupported outcome_class" "$INVALID_RAW" || grep -q "mystery_outcome" "$INVALID_RAW"; then
    scenario_result "remediation_catalog_invalid_rejected" "PASS" "unsupported outcome class is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "remediation_catalog_invalid_rejected" "FAIL" "invalid catalog failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-remediation-catalog \
    --catalog "$CATALOG_JSON" \
    --format markdown \
    --summary-out /dev/stdout \
    && grep -q "# Remediation Catalog" "$MARKDOWN_RAW" \
    && grep -q "product_failure" "$MARKDOWN_RAW" \
    && grep -q "Remediation Catalog Contract" scripts/e2e/README.md; then
    scenario_result "remediation_catalog_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "remediation_catalog_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: remediation catalog unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib remediation_catalog -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_catalog_validates_required_outcomes" \
        "render_markdown_includes_all_entries" \
        "render_remediation_markdown_default_catalog_snapshot"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "remediation_catalog_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "remediation_catalog_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Remediation catalog: $CATALOG_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Remediation catalog scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Remediation catalog scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
