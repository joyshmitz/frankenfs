#!/usr/bin/env bash
# ffs_mounted_repair_mutation_boundary_e2e.sh - non-permissioned mounted repair mutation-boundary gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_mounted_repair_mutation_boundary}"
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
    if isinstance(obj, dict) and "matrix_id" in obj and "scenario_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("mounted repair mutation boundary report JSON object not found")
PY
}

e2e_init "ffs_mounted_repair_mutation_boundary"

MATRIX_JSON="$REPO_ROOT/tests/mounted-repair-mutation-boundary/mounted_repair_mutation_boundary.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/mounted_repair_mutation_boundary"
REPORT_JSON="$E2E_LOG_DIR/mounted_repair_mutation_boundary_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/mounted_repair_mutation_boundary_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/mounted_repair_mutation_boundary_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/mounted_repair_mutation_boundary_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/mounted_repair_mutation_boundary_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/mounted_repair_mutation_boundary_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: mounted repair mutation boundary CLI is wired"
if grep -q "pub mod mounted_repair_mutation_boundary" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-mounted-repair-mutation-boundary" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_mounted_repair_mutation_boundary" scripts/e2e/scenario_catalog.json; then
    scenario_result "mounted_repair_mutation_boundary_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "mounted_repair_mutation_boundary_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in mounted repair mutation boundary validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-mounted-repair-mutation-boundary \
    --matrix "$MATRIX_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "mounted_repair_mutation_boundary_validates" "PASS" "checked-in matrix accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "mounted_repair_mutation_boundary_validates" "FAIL" "checked-in matrix rejected"
fi

e2e_step "Scenario 3: mutation-boundary coverage is explicit"
if python3 - "$REPORT_JSON" "$MATRIX_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matrix = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_kinds = {
    "default_ro_detection_only",
    "ro_repair_with_ledger_allowed",
    "rw_repair_refused",
    "stale_ledger_refused",
}
required_scopes = {
    "no_mutation",
    "image_repair_path_and_ledger",
    "refused_no_partial_mutation",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["scenario_count"] < 6:
    raise SystemExit("expected at least six mounted repair mutation-boundary scenarios")
missing_kinds = required_kinds - set(report["kinds_seen"])
if missing_kinds:
    raise SystemExit(f"missing mutation-boundary kinds: {sorted(missing_kinds)}")
scopes = {scenario["expected_mutation_scope"] for scenario in matrix["scenarios"]}
missing_scopes = required_scopes - scopes
if missing_scopes:
    raise SystemExit(f"missing mutation scopes: {sorted(missing_scopes)}")
if not any(s["expected_outcome"] == "host_skipped" and s["host_skip_reason"] for s in matrix["scenarios"]):
    raise SystemExit("host capability skip rationale is not visible")
for scenario in matrix["scenarios"]:
    if scenario["expected_outcome"] in {"rw_refused", "ledger_refused"} and not scenario["follow_up_bead"].startswith("bd-"):
        raise SystemExit(f"refusal scenario {scenario['scenario_id']} lacks follow_up_bead")
PY
then
    scenario_result "mounted_repair_mutation_boundary_coverage" "PASS" "mutation scopes, refusals, and host-skip rationale verified"
else
    scenario_result "mounted_repair_mutation_boundary_coverage" "FAIL" "mutation-boundary coverage contract failed"
fi

e2e_step "Scenario 4: invalid mounted repair mutation boundary fails closed"
jq '.scenarios[0].host_paths_touched += ["/etc/passwd"]' "$MATRIX_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-mounted-repair-mutation-boundary \
    --matrix "$INVALID_JSON"; then
    scenario_result "mounted_repair_mutation_boundary_invalid_rejected" "FAIL" "invalid matrix unexpectedly passed"
elif grep -q "host_paths_touched" "$INVALID_RAW"; then
    scenario_result "mounted_repair_mutation_boundary_invalid_rejected" "PASS" "unsafe host path touch is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "mounted_repair_mutation_boundary_invalid_rejected" "FAIL" "invalid matrix failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-mounted-repair-mutation-boundary \
    --matrix "$MATRIX_JSON" \
    --format markdown \
    && grep -q "# Mounted Repair Mutation Boundary" "$MARKDOWN_RAW" \
    && grep -q "rw_repair_refused" "$MARKDOWN_RAW" \
    && grep -q "Mounted Repair Mutation Boundary Contract" scripts/e2e/README.md; then
    scenario_result "mounted_repair_mutation_boundary_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "mounted_repair_mutation_boundary_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: mounted repair mutation boundary unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib mounted_repair_mutation_boundary -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_matrix_validates_required_kinds" \
        "render_mounted_repair_mutation_boundary_markdown_default_matrix" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "mounted_repair_mutation_boundary_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "mounted_repair_mutation_boundary_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Mounted repair mutation boundary matrix: $MATRIX_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Mounted repair mutation boundary scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Mounted repair mutation boundary scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
