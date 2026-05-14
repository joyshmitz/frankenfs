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

e2e_step "Scenario 4: Markdown summary points at row coverage instead of readiness claims"
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

e2e_step "Scenario 5: scenario catalog accepts the new E2E suite"
if e2e_validate_scenario_catalog; then
    scenario_result "report_schema_inventory_catalog_valid" "PASS" "scenario catalog validates with report schema suite"
else
    scenario_result "report_schema_inventory_catalog_valid" "FAIL" "scenario catalog validation failed"
fi

e2e_step "Scenario 6: focused report schema inventory unit tests pass"
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
