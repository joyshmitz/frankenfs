#!/usr/bin/env bash
# ffs_report_schema_inventory_e2e.sh - non-permissioned report schema inventory gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_report_schema_inventory}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_REPORT_SCHEMA_INVENTORY_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REPORT_SCHEMA_INVENTORY_SKIP_SELF_CHECK:-0}"

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

extract_json_report() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = raw.find('{\n  "schema_version"')
if start < 0:
    raise SystemExit("JSON report payload missing from RCH transcript")
payload, _ = json.JSONDecoder().raw_decode(raw[start:])
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(payload, indent=2, sort_keys=False) + "\n",
    encoding="utf-8",
)
PY
}

extract_markdown_summary() {
    local raw_path="$1"
    local summary_path="$2"
    python3 - "$raw_path" "$summary_path" <<'PY'
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = raw.find("# Report Schema Inventory")
if start < 0:
    raise SystemExit("Markdown report payload missing from RCH transcript")
markdown = raw[start:]
end = len(markdown)
for marker in ("\n  \x1b[2m", "\n[RCH]"):
    marker_index = markdown.find(marker)
    if marker_index >= 0:
        end = min(end, marker_index)
pathlib.Path(sys.argv[2]).write_text(markdown[:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_report_schema_inventory"

REPORT_JSON="$E2E_LOG_DIR/report_schema_inventory_report.json"
SUMMARY_MD="$E2E_LOG_DIR/report_schema_inventory_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/report_schema_inventory_validate.raw"
SUMMARY_RAW="$E2E_LOG_DIR/report_schema_inventory_summary.raw"
UNIT_LOG="$E2E_LOG_DIR/report_schema_inventory_unit_tests.log"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REPORT_SCHEMA_INVENTORY_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_row_result() {
    local report_id="$1"
    local coverage_requirement="$2"
    cat <<JSON
    {
      "report_id": "$report_id",
      "module_path": "crates/ffs-harness/src/report_schema_inventory.rs",
      "rust_type": "ReportSchemaInventoryReport",
      "downstream_consumer": "fixture self-check",
      "coverage_requirement": "$coverage_requirement",
      "coverage_status": "covered",
      "evidence_test": "report_schema_inventory_shape",
      "snapshot_path": "crates/ffs-harness/src/snapshots/ffs_harness__report_schema_inventory__tests__report_schema_inventory_shape.snap",
      "exclusion_reason": "",
      "claim_effect": "product_evidence_none",
      "missing_evidence": [],
      "errors": []
    }
JSON
}

emit_valid_report() {
    cat <<JSON
{
  "schema_version": 1,
  "inventory_id": "ffs_harness_serialized_report_schema_inventory_v1",
  "product_evidence_claim": "none",
  "reproduction_command": "ffs-harness validate-report-schema-inventory --out artifacts/report-schema-inventory/report.json --summary-out artifacts/report-schema-inventory/report.md",
  "valid": true,
  "total_rows": 13,
  "required_rows": 6,
  "advisory_only_rows": 6,
  "permissioned_only_rows": 1,
  "covered_rows": 13,
  "missing_rows": 0,
  "excluded_rows": 0,
  "report_ids": [
    "fixture_required_1",
    "fixture_required_2",
    "fixture_required_3",
    "fixture_required_4",
    "fixture_required_5",
    "fixture_required_6",
    "fixture_advisory_1",
    "fixture_advisory_2",
    "fixture_advisory_3",
    "fixture_advisory_4",
    "fixture_advisory_5",
    "fixture_advisory_6",
    "fixture_permissioned_1"
  ],
  "uncovered_required_report_ids": [],
  "row_results": [
$(emit_row_result "fixture_required_1" "required"),
$(emit_row_result "fixture_required_2" "required"),
$(emit_row_result "fixture_required_3" "required"),
$(emit_row_result "fixture_required_4" "required"),
$(emit_row_result "fixture_required_5" "required"),
$(emit_row_result "fixture_required_6" "required"),
$(emit_row_result "fixture_advisory_1" "advisory_only"),
$(emit_row_result "fixture_advisory_2" "advisory_only"),
$(emit_row_result "fixture_advisory_3" "advisory_only"),
$(emit_row_result "fixture_advisory_4" "advisory_only"),
$(emit_row_result "fixture_advisory_5" "advisory_only"),
$(emit_row_result "fixture_advisory_6" "advisory_only"),
$(emit_row_result "fixture_permissioned_1" "permissioned_only")
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
        echo "unknown report schema inventory fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness report_schema_inventory"*)
        printf '%s\n' \
            "test report_schema_inventory_shape ... ok" \
            "test report_markdown_summary_names_claim_and_uncovered_rows ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Report Schema Inventory" \
            "" \
            "Product evidence claim: \`none\`" \
            "" \
            "## Uncovered Required Reports" \
            "" \
            "## Row Results" \
            "" \
            "Reproduction command: \`validate-report-schema-inventory\`"
        exit 0
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
    local child_log="$E2E_LOG_DIR/report_schema_inventory_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REPORT_SCHEMA_INVENTORY_SELF_CHECK=0 \
        FFS_REPORT_SCHEMA_INVENTORY_SKIP_SELF_CHECK=1 \
        FFS_REPORT_SCHEMA_INVENTORY_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_report_schema_inventory_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic report schema inventory wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path summary_path
    stub_path="$E2E_LOG_DIR/rch-report-schema-inventory-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/report_schema_inventory_report.json"
    summary_path="$(dirname "$result_path")/report_schema_inventory_summary.md"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$summary_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "report_schema_inventory_artifacts_written" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "report_schema_inventory_json_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "report_schema_inventory_evidence_tests_resolve" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "report_schema_inventory_markdown_summary" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "report_schema_inventory_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .product_evidence_claim == "none"
            and .total_rows == 13
            and .required_rows == 6
            and .permissioned_only_rows == 1
            and (.row_results | length == 13)
            and ([.row_results[] | select(.coverage_requirement == "permissioned_only" and .claim_effect == "product_evidence_none")] | length == 1)
        ' "$report_path" >/dev/null \
        && grep -q "Product evidence claim: \`none\`" "$summary_path"; then
        scenario_result "report_schema_inventory_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} summary=${summary_path}"
    else
        scenario_result "report_schema_inventory_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "report schema inventory complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "report_schema_inventory_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "report_schema_inventory_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "report schema inventory local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "report schema inventory wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: report schema inventory CLI and docs are wired"
if grep -q "pub mod report_schema_inventory" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-report-schema-inventory" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_report_schema_inventory" scripts/e2e/scenario_catalog.json \
    && grep -q "Report Schema Inventory Gate" scripts/e2e/README.md \
    && grep -q "validate-report-schema-inventory" docs/tracker-hygiene.md; then
    scenario_result "report_schema_inventory_cli_docs_wired" "PASS" "module, CLI command, catalog, and docs references are exported"
else
    scenario_result "report_schema_inventory_cli_docs_wired" "FAIL" "missing module export, CLI command, catalog entry, or docs reference"
fi

e2e_step "Scenario 2: report schema inventory CLI writes JSON and Markdown artifacts"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-report-schema-inventory --format json \
    && extract_json_report "$VALIDATE_RAW" "$REPORT_JSON" \
    && e2e_rch_capture "$SUMMARY_RAW" cargo run --quiet -p ffs-harness -- \
        validate-report-schema-inventory --format markdown \
    && extract_markdown_summary "$SUMMARY_RAW" "$SUMMARY_MD" \
    && [[ -s "$REPORT_JSON" ]] \
    && [[ -s "$SUMMARY_MD" ]]; then
    scenario_result "report_schema_inventory_artifacts_written" "PASS" "report=$REPORT_JSON summary=$SUMMARY_MD transcript=$VALIDATE_RAW summary_transcript=$SUMMARY_RAW"
else
    cat "$VALIDATE_RAW"
    scenario_result "report_schema_inventory_artifacts_written" "FAIL" "report schema inventory artifacts were not written"
fi

e2e_step "Scenario 3: JSON report preserves non-permissioned claim semantics"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["product_evidence_claim"] != "none":
    raise SystemExit(f"unexpected product_evidence_claim={report['product_evidence_claim']!r}")
if "validate-report-schema-inventory" not in report["reproduction_command"]:
    raise SystemExit("missing reproduction command")
if report["total_rows"] < 13:
    raise SystemExit("expected seeded inventory rows")
if report["required_rows"] < 6:
    raise SystemExit("expected required report rows")
if len(report["row_results"]) != report["total_rows"]:
    raise SystemExit("row_results does not cover every inventory row")
if report["uncovered_required_report_ids"]:
    raise SystemExit(f"unexpected uncovered required rows: {report['uncovered_required_report_ids']}")
if report["errors"]:
    raise SystemExit(f"unexpected validation errors: {report['errors']}")
permissioned = [
    row for row in report["row_results"]
    if row["coverage_requirement"] == "permissioned_only"
]
if not permissioned:
    raise SystemExit("expected permissioned-only row")
for row in permissioned:
    if row["claim_effect"] != "product_evidence_none":
        raise SystemExit(f"permissioned row changes product claim: {row['report_id']}")
PY
then
    scenario_result "report_schema_inventory_json_contract" "PASS" "valid report preserves product_evidence_claim=none and row coverage"
else
    scenario_result "report_schema_inventory_json_contract" "FAIL" "JSON report contract failed"
fi

e2e_step "Scenario 4: covered evidence tests resolve to declared module tests"
if python3 - "$REPORT_JSON" <<'PY'
import json
import os
import pathlib
import re
import sys

repo_root = pathlib.Path(os.environ["REPO_ROOT"])
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
errors = []

def has_test_function(source, evidence_test):
    fn_pattern = re.compile(rf"(?m)^\s*(?:pub\s+)?fn\s+{re.escape(evidence_test)}\s*\(")
    for match in fn_pattern.finditer(source):
        preceding_lines = source[: match.start()].splitlines()[-8:]
        if any(line.strip() == "#[test]" for line in preceding_lines):
            return True
    return False

def has_snapshot_assertion(source, evidence_test):
    snapshot_pattern = re.compile(
        rf'(?s)(?:insta::)?assert_(?:json_|debug_)?snapshot!\s*\(\s*"{re.escape(evidence_test)}"'
    )
    for match in snapshot_pattern.finditer(source):
        preceding_lines = source[: match.start()].splitlines()[-120:]
        if any(line.strip() == "#[test]" for line in preceding_lines):
            return True
    return False

for row in report["row_results"]:
    if row["coverage_status"] != "covered":
        continue

    report_id = row["report_id"]
    module_path = row["module_path"].strip()
    evidence_test = row["evidence_test"].strip()
    if not module_path or not evidence_test:
        errors.append(f"{report_id}: covered row missing module_path or evidence_test")
        continue

    source_path = repo_root / module_path
    if not source_path.is_file():
        errors.append(f"{report_id}: module_path not found: {module_path}")
        continue

    source = source_path.read_text(encoding="utf-8")
    if not has_test_function(source, evidence_test) and not has_snapshot_assertion(
        source, evidence_test
    ):
        errors.append(
            f"{report_id}: evidence_test `{evidence_test}` is not a #[test] function "
            f"or insta snapshot assertion in {module_path}"
        )

if errors:
    raise SystemExit("\n".join(errors[:20]))
PY
then
    scenario_result "report_schema_inventory_evidence_tests_resolve" "PASS" "covered evidence_test names resolve to #[test] functions or insta snapshot assertions in declared modules"
else
    scenario_result "report_schema_inventory_evidence_tests_resolve" "FAIL" "one or more covered evidence_test names did not resolve to declared module evidence"
fi

e2e_step "Scenario 5: Markdown summary points at row coverage instead of readiness claims"
if grep -q "# Report Schema Inventory" "$SUMMARY_MD" \
    && grep -q "Product evidence claim: \`none\`" "$SUMMARY_MD" \
    && grep -q "Uncovered Required Reports" "$SUMMARY_MD" \
    && grep -q "Row Results" "$SUMMARY_MD" \
    && grep -q "Reproduction command:" "$SUMMARY_MD"; then
    scenario_result "report_schema_inventory_markdown_summary" "PASS" "summary names product claim, uncovered row section, row results, and reproduction command"
else
    cat "$SUMMARY_MD"
    scenario_result "report_schema_inventory_markdown_summary" "FAIL" "Markdown summary missing required sections"
fi

e2e_step "Scenario 6: scenario catalog accepts the new E2E suite"
if e2e_validate_scenario_catalog; then
    scenario_result "report_schema_inventory_catalog_valid" "PASS" "scenario catalog validates with report schema suite"
else
    scenario_result "report_schema_inventory_catalog_valid" "FAIL" "scenario catalog validation failed"
fi

e2e_step "Scenario 7: focused report schema inventory unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness report_schema_inventory -- --nocapture \
    && grep -q "report_schema_inventory_shape" "$UNIT_LOG" \
    && grep -q "report_markdown_summary_names_claim_and_uncovered_rows" "$UNIT_LOG"; then
    scenario_result "report_schema_inventory_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "report_schema_inventory_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Report schema inventory JSON: $REPORT_JSON"
e2e_log "Report schema inventory summary: $SUMMARY_MD"
e2e_log "Reproduce: cargo run --quiet -p ffs-harness -- validate-report-schema-inventory --out $REPORT_JSON --summary-out $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Report schema inventory scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Report schema inventory scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
