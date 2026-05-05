#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

e2e_init "ffs_open_ended_inventory_scanner"
e2e_print_env

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_open_ended_scanner}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

FIXTURE_DIR="$REPO_ROOT/tests/open-ended-inventory"
POSITIVE_FIXTURE="$FIXTURE_DIR/scanner_fixture_positive.md"
NEGATIVE_FIXTURE="$FIXTURE_DIR/scanner_fixture_negative.md"
REAL_INVENTORY="$REPO_ROOT/docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md"
POSITIVE_REPORT="$E2E_LOG_DIR/open_ended_note_positive.json"
NEGATIVE_REPORT="$E2E_LOG_DIR/open_ended_note_negative.json"
REAL_REPORT="$E2E_LOG_DIR/open_ended_note_real_inventory.json"
POSITIVE_LOG="$E2E_LOG_DIR/open_ended_note_positive.log"
NEGATIVE_LOG="$E2E_LOG_DIR/open_ended_note_negative.log"
REAL_LOG="$E2E_LOG_DIR/open_ended_note_real_inventory.log"
POSITIVE_REPRO_COMMAND="cargo run -p ffs-harness -- open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_positive.md"
NEGATIVE_REPRO_COMMAND="cargo run -p ffs-harness -- open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_negative.md"
REAL_REPRO_COMMAND="cargo run -p ffs-harness -- open-ended-note-scanner --source docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md"

HARNESS_CMD=("${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness --)

extract_note_scan_json() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and obj.get("scanner_version") == "bd-l7ov7-open-ended-note-scanner-v1" and "rows" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("open-ended note scanner JSON report not found")
PY
}

e2e_step "Scenario 1: scanner fixtures and CLI wiring are present"
e2e_assert_file "$POSITIVE_FIXTURE"
e2e_assert_file "$NEGATIVE_FIXTURE"
e2e_assert_file "$REAL_INVENTORY"
if grep -q "open-ended-note-scanner" "$REPO_ROOT/crates/ffs-harness/src/main.rs"; then
    scenario_result "open_ended_note_scanner_inputs_present" "PASS" "fixtures, inventory doc, and CLI command are present"
else
    scenario_result "open_ended_note_scanner_inputs_present" "FAIL" "CLI command missing"
    e2e_fail "open-ended note scanner command is not wired"
fi

e2e_step "Scenario 2: positive fixture emits a valid classified report"
if RCH_VISIBILITY=none "${HARNESS_CMD[@]}" open-ended-note-scanner \
    --source "$POSITIVE_FIXTURE" \
    --reproduction-command "$POSITIVE_REPRO_COMMAND" >"$POSITIVE_LOG" 2>&1; then
    extract_note_scan_json "$POSITIVE_LOG" "$POSITIVE_REPORT"
    scenario_result "open_ended_note_scanner_positive_fixture" "PASS" "positive fixture accepted"
else
    sed -n '1,160p' "$POSITIVE_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "open_ended_note_scanner_positive_fixture" "FAIL" "positive fixture rejected"
    e2e_fail "open-ended note scanner rejected the positive fixture"
fi

e2e_step "Scenario 3: negative fixture fails closed but still writes diagnostics"
set +e
RCH_VISIBILITY=none "${HARNESS_CMD[@]}" open-ended-note-scanner \
    --source "$NEGATIVE_FIXTURE" \
    --reproduction-command "$NEGATIVE_REPRO_COMMAND" >"$NEGATIVE_LOG" 2>&1
NEGATIVE_STATUS=$?
set -e
if [[ "$NEGATIVE_STATUS" -ne 0 ]] && extract_note_scan_json "$NEGATIVE_LOG" "$NEGATIVE_REPORT"; then
    scenario_result "open_ended_note_scanner_negative_fixture" "PASS" "negative fixture rejected and emitted JSON diagnostics"
else
    sed -n '1,160p' "$NEGATIVE_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "open_ended_note_scanner_negative_fixture" "FAIL" "negative fixture did not fail closed"
    e2e_fail "open-ended note scanner failed to reject the negative fixture"
fi

e2e_step "Scenario 4: scanner report schema covers proof and false-positive controls"
python3 - "$POSITIVE_REPORT" "$NEGATIVE_REPORT" "$POSITIVE_REPRO_COMMAND" "$NEGATIVE_REPRO_COMMAND" <<'PY'
import json
import pathlib
import sys

positive_path, negative_path, positive_reproduction_command, negative_reproduction_command = sys.argv[1:]
positive = json.loads(pathlib.Path(positive_path).read_text(encoding="utf-8"))
negative = json.loads(pathlib.Path(negative_path).read_text(encoding="utf-8"))

if not positive["valid"]:
    raise SystemExit(f"positive report invalid: {positive['errors']}")
if negative["valid"]:
    raise SystemExit("negative report should be invalid")
if positive["scanner_version"] != "bd-l7ov7-open-ended-note-scanner-v1":
    raise SystemExit("scanner version drifted")
if positive["reproduction_command"] != positive_reproduction_command:
    raise SystemExit("positive report did not preserve reproduction command")
if negative["reproduction_command"] != negative_reproduction_command:
    raise SystemExit("negative report did not preserve reproduction command")
if positive["match_count"] < 4:
    raise SystemExit("positive fixture should emit at least four rows")
if positive["false_positive_count"] < 2:
    raise SystemExit("positive fixture should include false-positive controls")
if positive["unresolved_note_count"] != 0:
    raise SystemExit("positive fixture should have no unresolved rows")
if negative["unresolved_note_count"] != 1:
    raise SystemExit("negative fixture should have exactly one unresolved row")
if not any("lacks linked bead/artifact" in error for error in negative["errors"]):
    raise SystemExit("negative report missing linkage diagnostic")

required_patterns = {
    "add more cases",
    "expand corpus",
    "TODO fuzz",
    "future edge cases",
    "adversarial inputs",
    "more goldens",
    "known gaps",
}
if set(positive["search_patterns"]) != required_patterns:
    raise SystemExit("scanner pattern vocabulary changed")

required_row_fields = {
    "source_path",
    "line_number",
    "section_id",
    "matched_phrase",
    "matched_text_snippet_hash",
    "decision",
    "false_positive_reason",
    "linked_bead_or_artifact",
    "risk_surface",
    "existing_evidence",
    "proof_type",
    "unit_test_expectation",
    "e2e_fuzz_smoke_expectation",
    "required_log_fields",
    "required_artifacts",
    "non_applicability_rationale",
    "reproduction_command",
}
allowed_proof_types = {
    "parser-unit",
    "mounted-e2e",
    "corpus-seed",
    "golden-fixture",
    "long-campaign",
    "property-test",
    "security-audit",
    "docs-non-goal",
}
for report in [positive, negative]:
    for row in report["rows"]:
        missing = sorted(required_row_fields - set(row))
        if missing:
            raise SystemExit(f"row missing required fields: {missing}")
        if row["proof_type"] not in allowed_proof_types:
            raise SystemExit(f"invalid proof type: {row['proof_type']}")
        if not row["existing_evidence"]:
            raise SystemExit("row missing existing evidence")
        if not row["unit_test_expectation"]:
            raise SystemExit("row missing unit test expectation")
        if row["e2e_fuzz_smoke_expectation"] != "scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh":
            raise SystemExit("row missing E2E scanner expectation")
        if row["decision"] == "false_positive" and row["non_applicability_rationale"] == "n/a":
            raise SystemExit("false-positive row missing non-applicability rationale")
        if row["decision"] != "false_positive" and row["non_applicability_rationale"] != "n/a":
            raise SystemExit("applicable row has non-n/a non-applicability rationale")
PY
scenario_result "open_ended_note_scanner_report_contract" "PASS" "pattern vocabulary, row fields, proof types, and diagnostics verified"

e2e_step "Scenario 5: current inventory document has no unresolved open-ended notes"
if RCH_VISIBILITY=none "${HARNESS_CMD[@]}" open-ended-note-scanner \
    --source "$REAL_INVENTORY" \
    --reproduction-command "$REAL_REPRO_COMMAND" >"$REAL_LOG" 2>&1; then
    extract_note_scan_json "$REAL_LOG" "$REAL_REPORT"
    python3 - "$REAL_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["unresolved_note_count"] != 0:
    raise SystemExit("current inventory scan should have no unresolved rows")
if report["match_count"] == 0:
    raise SystemExit("current inventory scan should exercise the scanner")
PY
    scenario_result "open_ended_note_scanner_real_inventory" "PASS" "current inventory scan is valid"
else
    sed -n '1,160p' "$REAL_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "open_ended_note_scanner_real_inventory" "FAIL" "current inventory scan rejected"
    e2e_fail "open-ended note scanner rejected the current inventory"
fi

e2e_pass
