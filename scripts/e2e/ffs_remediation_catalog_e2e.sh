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
