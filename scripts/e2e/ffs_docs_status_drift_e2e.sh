#!/usr/bin/env bash
# ffs_docs_status_drift_e2e.sh - smoke gate for bd-jtu4q.
#
# Proves public docs/status wording is generated from support-state accounting
# and ambition evidence rows, and fails closed on overclaims or stale flat
# parity wording.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_docs_status_drift}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

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

e2e_init "ffs_docs_status_drift"

REPORT_JSON="${E2E_LOG_DIR}/docs_status_drift.json"
REPORT_MD="${E2E_LOG_DIR}/docs_status_drift.md"
REPORT_RAW="${E2E_LOG_DIR}/docs_status_drift.raw"
REPORT_MD_RAW="${E2E_LOG_DIR}/docs_status_drift_md.raw"
ISSUES_JSONL="${E2E_LOG_DIR}/issues.jsonl"
BAD_UPGRADE_JSON="${E2E_LOG_DIR}/bad_upgrade_snippets.json"
BAD_FLAT_JSON="${E2E_LOG_DIR}/bad_flat_snippets.json"
BAD_UPGRADE_RAW="${E2E_LOG_DIR}/bad_upgrade.raw"
BAD_FLAT_RAW="${E2E_LOG_DIR}/bad_flat.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"
cp .beads/issues.jsonl "$ISSUES_JSONL"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod docs_status_drift" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-docs-status-drift" crates/ffs-harness/src/main.rs; then
    scenario_result "docs_status_wired" "PASS" "module and CLI command exported"
else
    scenario_result "docs_status_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: CLI renders JSON and Markdown reports"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md >"$REPORT_RAW" 2>&1 \
    && RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
        --issues "$ISSUES_JSONL" \
        --feature-parity FEATURE_PARITY.md \
        --format markdown >"$REPORT_MD_RAW" 2>&1; then
    if python3 - "$REPORT_RAW" "$REPORT_JSON" "$REPORT_MD_RAW" "$REPORT_MD" <<'PY'
import json
import sys

json_raw, json_report, md_raw, md_report = sys.argv[1:5]
text = open(json_raw, encoding="utf-8", errors="replace").read()
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "docs_status_drift_version" in obj:
        with open(json_report, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("docs-status JSON object not found in rch output")

markdown = open(md_raw, encoding="utf-8", errors="replace").read()
marker = "# FrankenFS Docs Status Drift"
index = markdown.find(marker)
if index < 0:
    raise SystemExit("docs-status Markdown marker not found")
with open(md_report, "w", encoding="utf-8") as handle:
    handle.write(markdown[index:])
PY
    then
        scenario_result "docs_status_report_renders" "PASS" "JSON and Markdown reports captured"
    else
        scenario_result "docs_status_report_renders" "FAIL" "missing JSON or Markdown output"
    fi
else
    scenario_result "docs_status_report_renders" "FAIL" "CLI command failed"
fi

e2e_step "Scenario 3: required surfaces and public statuses are covered"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
if not data.get("release_gate_pass"):
    raise SystemExit(f"release gate should pass: {data.get('errors')}")
required_statuses = {
    "validated",
    "experimental",
    "detection-only",
    "dry-run-only",
    "parse-only",
    "opt-in mutating",
    "disabled",
    "unsupported",
    "deferred",
    "stale-evidence",
    "host-blocked",
    "security-refused",
}
required_targets = {
    "README.md",
    "FEATURE_PARITY.md",
    "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
    "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
    "EXISTING_EXT4_BTRFS_STRUCTURE.md",
    "PROPOSED_ARCHITECTURE.md",
    "CLI help/status text",
    "scripts/e2e/README.md",
    "proof-bundle summaries",
}
statuses = {row["expected_public_status"] for row in data.get("observations", [])}
targets = {row["docs_target"] for row in data.get("observations", [])}
missing_statuses = sorted(required_statuses - statuses)
missing_targets = sorted(required_targets - targets)
if missing_statuses or missing_targets:
    raise SystemExit(f"missing statuses={missing_statuses} targets={missing_targets}")
if data.get("drift_classification_counts", {}).get("matches") != data.get("observation_count"):
    raise SystemExit("all default snippets should match generated wording")
PY
then
    scenario_result "docs_status_surface_status_coverage" "PASS" "required surfaces and statuses represented"
else
    scenario_result "docs_status_surface_status_coverage" "FAIL" "surface/status coverage validation failed"
fi

e2e_step "Scenario 4: structured drift log fields are present"
TOKENS_FOUND=0
for token in \
    "docs_target" \
    "section_anchor" \
    "feature_id" \
    "source_support_state_row" \
    "gate_artifact_hash" \
    "generated_wording_id" \
    "observed_wording_hash" \
    "drift_classification" \
    "remediation_id" \
    "output_path" \
    "reproduction_command"; do
    if grep -q "\"${token}\"" "$REPORT_JSON"; then
        TOKENS_FOUND=$((TOKENS_FOUND + 1))
    fi
done

if [[ $TOKENS_FOUND -eq 11 ]]; then
    scenario_result "docs_status_log_tokens" "PASS" "all structured drift tokens present"
else
    scenario_result "docs_status_log_tokens" "FAIL" "only ${TOKENS_FOUND}/11 log tokens present"
fi

e2e_step "Scenario 5: hand-upgraded claim fails closed"
cat >"$BAD_UPGRADE_JSON" <<'JSON'
{
  "snippets": [
    {
      "feature_id": "rw_background_repair",
      "docs_target": "README.md",
      "section_anchor": "mounted-self-healing",
      "observed_text": "rw_background_repair is validated and fully supported for production automatic repair."
    }
  ]
}
JSON
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    --snippets "$BAD_UPGRADE_JSON" >"$BAD_UPGRADE_RAW" 2>&1; then
    scenario_result "docs_status_hand_upgrade_fails" "FAIL" "bad upgrade unexpectedly passed"
else
    if grep -q "feature_id=rw_background_repair" "$BAD_UPGRADE_RAW" \
        && grep -q "docs_target=README.md" "$BAD_UPGRADE_RAW" \
        && grep -q "expected_wording_id=docs.rw-background-repair.host-blocked" "$BAD_UPGRADE_RAW" \
        && grep -q "observed_wording_hash=" "$BAD_UPGRADE_RAW" \
        && grep -q "source_support_state_row=rw_background_repair:host_blocked" "$BAD_UPGRADE_RAW" \
        && grep -q "drift_classification=stronger-than-evidence" "$BAD_UPGRADE_RAW" \
        && grep -q "remediation_id=bd-bqgy8" "$BAD_UPGRADE_RAW"; then
        scenario_result "docs_status_hand_upgrade_fails" "PASS" "bad upgrade failed with exact diagnostic fields"
    else
        scenario_result "docs_status_hand_upgrade_fails" "FAIL" "failure did not include exact drift diagnostics"
    fi
fi

e2e_step "Scenario 6: stale flat parity claim fails closed"
cat >"$BAD_FLAT_JSON" <<'JSON'
{
  "snippets": [
    {
      "feature_id": "mounted_write_paths",
      "docs_target": "README.md",
      "section_anchor": "project-status",
      "observed_text": "FrankenFS has 100 percent parity, including mounted write paths."
    }
  ]
}
JSON
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    --snippets "$BAD_FLAT_JSON" >"$BAD_FLAT_RAW" 2>&1; then
    scenario_result "docs_status_flat_parity_fails" "FAIL" "flat parity wording unexpectedly passed"
else
    if grep -q "feature_id=mounted_write_paths" "$BAD_FLAT_RAW" \
        && grep -q "drift_classification=stale-flat-parity" "$BAD_FLAT_RAW"; then
        scenario_result "docs_status_flat_parity_fails" "PASS" "flat parity wording failed closed"
    else
        scenario_result "docs_status_flat_parity_fails" "FAIL" "failure did not name stale flat parity drift"
    fi
fi

e2e_step "Scenario 7: unit/schema tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib -- docs_status_drift \
    2>"$UNIT_LOG" | tee -a "$UNIT_LOG"; then
    TESTS_RUN=$(grep -c "test docs_status_drift::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 8 ]]; then
        scenario_result "docs_status_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "docs_status_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "docs_status_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_docs_status_drift completed"
else
    e2e_fail "ffs_docs_status_drift failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
