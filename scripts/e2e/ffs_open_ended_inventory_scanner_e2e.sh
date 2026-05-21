#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"

SELF_CHECK="${FFS_OPEN_ENDED_INVENTORY_SCANNER_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_OPEN_ENDED_INVENTORY_SCANNER_SKIP_SELF_CHECK:-0}"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

e2e_init "ffs_open_ended_inventory_scanner"

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_OPEN_ENDED_INVENTORY_SCANNER_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected open-ended scanner fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown open-ended scanner fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

finish_failure() {
    local status="$1"
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=${status}"
    fi
    exit "$status"
}

emit_note_report() {
    local kind="$1"
    local reproduction_command="$2"
    python3 - "$kind" "$reproduction_command" <<'PY'
import json
import sys

kind, reproduction_command = sys.argv[1:3]
patterns = [
    "add more cases",
    "expand corpus",
    "TODO fuzz",
    "HACK",
    "XXX",
    "future edge cases",
    "adversarial inputs",
    "more goldens",
    "known gaps",
    "fake delay",
    "mock implementation",
    "dummy implementation",
    "placeholder implementation",
    "stub implementation",
    "not yet implemented",
    "temporary sleep",
    "thread::sleep",
]

def row(index, decision="requires_inventory_row", proof_type="parser-unit"):
    false_positive = decision == "false_positive"
    return {
        "source_path": "tests/open-ended-inventory/scanner_fixture_positive.md",
        "line_number": index + 1,
        "section_id": f"fixture-section-{index}",
        "matched_phrase": patterns[index % len(patterns)],
        "matched_text_snippet_hash": "sha256:" + str(index) * 64,
        "decision": decision,
        "false_positive_reason": "fixture intentionally exercises non-applicable prose" if false_positive else "n/a",
        "linked_bead_or_artifact": "bd-rchk0.fixture" if not false_positive else "docs-non-goal-fixture",
        "risk_surface": "source-scope",
        "existing_evidence": ["fixture-evidence"],
        "proof_type": proof_type,
        "unit_test_expectation": "open_ended_inventory::tests::fixture_contract",
        "e2e_fuzz_smoke_expectation": "scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh",
        "required_log_fields": ["scanner_version", "reproduction_command"],
        "required_artifacts": ["fixture-report.json"],
        "non_applicability_rationale": "fixture non-goal" if false_positive else "n/a",
        "reproduction_command": reproduction_command,
    }

if kind == "negative":
    rows = [
        row(0, "requires_inventory_row"),
        row(1, "requires_inventory_row", "long-campaign"),
        row(2, "requires_inventory_row", "golden-fixture"),
    ]
    report = {
        "scanner_version": "bd-mockscan-open-ended-note-scanner-v2",
        "valid": False,
        "errors": ["open-ended row lacks linked bead/artifact"],
        "reproduction_command": reproduction_command,
        "match_count": 3,
        "false_positive_count": 0,
        "unresolved_note_count": 3,
        "search_patterns": patterns,
        "rows": rows,
    }
elif kind == "real":
    rows = [row(0)]
    report = {
        "scanner_version": "bd-mockscan-open-ended-note-scanner-v2",
        "valid": True,
        "errors": [],
        "reproduction_command": reproduction_command,
        "match_count": 1,
        "false_positive_count": 0,
        "unresolved_note_count": 0,
        "search_patterns": patterns,
        "rows": rows,
    }
else:
    rows = [
        row(0),
        row(1),
        row(2, "false_positive", "docs-non-goal"),
        row(3, "false_positive", "docs-non-goal"),
    ]
    report = {
        "scanner_version": "bd-mockscan-open-ended-note-scanner-v2",
        "valid": True,
        "errors": [],
        "reproduction_command": reproduction_command,
        "match_count": 4,
        "false_positive_count": 2,
        "unresolved_note_count": 0,
        "search_patterns": patterns,
        "rows": rows,
    }

print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_source_scope_report() {
    python3 - <<'PY'
import json

required_families = [
    "readme_status_docs",
    "agent_workflow_docs",
    "feature_parity_doc",
    "canonical_spec_docs",
    "architecture_design_docs",
    "conformance_docs",
    "conformance_fixture_artifacts",
    "fixture_manifests",
    "test_control_artifacts",
    "tests",
    "checked_in_evidence_artifacts",
    "crate_manifest_and_benchmark_sources",
    "fuzz_campaign_artifacts",
    "fuzz_corpus_notes",
    "fuzz_targets",
    "fuzz_orchestration",
    "operational_scripts",
    "harness_scripts",
    "operator_runbook_docs",
    "operational_evidence_artifacts",
    "mounted_lane_docs",
    "repair_docs",
    "performance_control_artifacts",
    "performance_xfstests_notes",
]
build_output_sensitive_families = {
    "agent_workflow_docs",
    "architecture_design_docs",
    "conformance_docs",
    "conformance_fixture_artifacts",
    "test_control_artifacts",
    "tests",
    "checked_in_evidence_artifacts",
    "crate_manifest_and_benchmark_sources",
    "fuzz_campaign_artifacts",
    "fuzz_targets",
    "fuzz_orchestration",
    "operational_scripts",
    "operator_runbook_docs",
    "operational_evidence_artifacts",
    "performance_control_artifacts",
}

scanned_sources = []
for family in required_families:
    included_globs = [f"{family}/**"]
    excluded_globs = []
    if family in build_output_sensitive_families:
        excluded_globs.extend(["target/**", "**/.rch-target/**", "**/.rch-target-*/**"])
    if family == "tests":
        excluded_globs.append("vendor/**")
    if family == "harness_scripts":
        included_globs = ["scripts/e2e/**/*.sh", "scripts/e2e/**/*.py", "scripts/e2e/**/*.json"]
        excluded_globs.append("scripts/e2e/_artifacts/**")
    scanned_sources.append(
        {
            "id": f"fixture_{family}",
            "source_family": family,
            "included_globs": included_globs,
            "excluded_globs": excluded_globs,
            "inclusion_decision": "included",
            "file_or_directory_hash": "sha256:" + "0" * 64,
            "matched_note_count": 0,
            "linked_bead_or_artifact_count": 0,
            "stale_allowance": "none",
            "output_path": f"artifacts/fixture/{family}.json",
            "reproduction_command": "cargo run -p ffs-ops -- validate-source-scope-manifest --manifest tests/source-scope-manifest/source_scope_manifest.json --workspace-root .",
            "matched_paths": [{"source_path": f"{family}/fixture.txt"}],
        }
    )

report = {
    "schema_version": 1,
    "source_manifest_version": 1,
    "valid": True,
    "errors": [],
    "source_count": len(required_families),
    "reproduction_command": "cargo run -p ffs-ops -- validate-source-scope-manifest --manifest tests/source-scope-manifest/source_scope_manifest.json --workspace-root .",
    "scanned_sources": scanned_sources,
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

case "$command_text" in
    *"open-ended-note-scanner"*"scanner_fixture_positive.md"*)
        emit_note_report "positive" "cargo run -p ffs-ops -- open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_positive.md"
        finish_success
        ;;
    *"open-ended-note-scanner"*"scanner_fixture_negative.md"*)
        emit_note_report "negative" "cargo run -p ffs-ops -- open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_negative.md"
        finish_failure 1
        ;;
    *"open-ended-note-scanner"*"FUZZ_AND_CONFORMANCE_INVENTORY.md"*)
        emit_note_report "real" "cargo run -p ffs-ops -- open-ended-note-scanner --source docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md"
        finish_success
        ;;
    *"validate-source-scope-manifest"*"--remove-source-family tests"*)
        echo 'source scope manifest missing required family `tests`'
        finish_failure 1
        ;;
    *"validate-source-scope-manifest"*)
        emit_source_scope_report
        finish_success
        ;;
    *"cargo test"*source_scope_scan*)
        echo "test open_ended_inventory::tests::source_scope_scan_uses_git_tracked_files_for_canonical_hashes ... ok"
        echo "test open_ended_inventory::tests::source_scope_scan_report_json_shape ... ok"
        echo "test result: ok. fixture passed"
        finish_success
        ;;
    *)
        echo "unexpected open-ended scanner fixture command: $command_text" >&2
        exit 64
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
    local child_log="$E2E_LOG_DIR/open_ended_inventory_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_OPEN_ENDED_INVENTORY_SCANNER_SELF_CHECK=0 \
        FFS_OPEN_ENDED_INVENTORY_SCANNER_SKIP_SELF_CHECK=1 \
        FFS_OPEN_ENDED_INVENTORY_SCANNER_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic open-ended inventory scanner wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-open-ended-inventory-scanner-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .invalid_scenario_marker_count == 0
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "open_ended_note_scanner_inputs_present" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "open_ended_note_scanner_positive_fixture" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "open_ended_note_scanner_negative_fixture" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "open_ended_note_scanner_report_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "open_ended_note_scanner_real_inventory" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "source_scope_manifest_real_workspace" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "source_scope_manifest_missing_family" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "source_scope_dirty_workspace_stability" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "open_ended_inventory_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "open_ended_inventory_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "open_ended_inventory_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "open_ended_inventory_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "open_ended_inventory_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "open_ended_inventory_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_print_env

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_open_ended_scanner}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_CAPTURE_VISIBILITY="${FFS_OPEN_ENDED_INVENTORY_SCANNER_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"

FIXTURE_DIR="$REPO_ROOT/tests/open-ended-inventory"
POSITIVE_FIXTURE="$FIXTURE_DIR/scanner_fixture_positive.md"
NEGATIVE_FIXTURE="$FIXTURE_DIR/scanner_fixture_negative.md"
REAL_INVENTORY="$REPO_ROOT/docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md"
SOURCE_SCOPE_MANIFEST="$REPO_ROOT/tests/source-scope-manifest/source_scope_manifest.json"
POSITIVE_REPORT="$E2E_LOG_DIR/open_ended_note_positive.json"
NEGATIVE_REPORT="$E2E_LOG_DIR/open_ended_note_negative.json"
REAL_REPORT="$E2E_LOG_DIR/open_ended_note_real_inventory.json"
SOURCE_SCOPE_REPORT="$E2E_LOG_DIR/source_scope_manifest_real_workspace.json"
SOURCE_SCOPE_DIRTY_UNIT_LOG="$E2E_LOG_DIR/source_scope_dirty_workspace_unit.log"
POSITIVE_LOG="$E2E_LOG_DIR/open_ended_note_positive.log"
NEGATIVE_LOG="$E2E_LOG_DIR/open_ended_note_negative.log"
REAL_LOG="$E2E_LOG_DIR/open_ended_note_real_inventory.log"
SOURCE_SCOPE_LOG="$E2E_LOG_DIR/source_scope_manifest_real_workspace.log"
SOURCE_SCOPE_NEGATIVE_LOG="$E2E_LOG_DIR/source_scope_manifest_missing_tests.log"
SOURCE_SCOPE_DIRTY_SNAPSHOT="$REPO_ROOT/crates/ffs-harness/src/snapshots/ffs_harness__open_ended_inventory__tests__source_scope_scan_report_json_shape.snap"
POSITIVE_REPRO_COMMAND="cargo run -p ffs-ops -- open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_positive.md"
NEGATIVE_REPRO_COMMAND="cargo run -p ffs-ops -- open-ended-note-scanner --source tests/open-ended-inventory/scanner_fixture_negative.md"
REAL_REPRO_COMMAND="cargo run -p ffs-ops -- open-ended-note-scanner --source docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md"

HARNESS_CMD=(env "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" cargo run --quiet -p ffs-ops --)

run_harness() {
    local log_path="$1"
    shift
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-2}" \
        e2e_rch_capture "$log_path" "${HARNESS_CMD[@]}" "$@"
}

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
    if isinstance(obj, dict) and obj.get("scanner_version") == "bd-mockscan-open-ended-note-scanner-v2" and "rows" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("open-ended note scanner JSON report not found")
PY
}

extract_source_scope_json() {
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
    if (
        isinstance(obj, dict)
        and obj.get("source_manifest_version") == 1
        and "scanned_sources" in obj
    ):
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("source scope manifest JSON report not found")
PY
}

e2e_step "Scenario 1: scanner fixtures and CLI wiring are present"
e2e_assert_file "$POSITIVE_FIXTURE"
e2e_assert_file "$NEGATIVE_FIXTURE"
e2e_assert_file "$REAL_INVENTORY"
e2e_assert_file "$SOURCE_SCOPE_MANIFEST"
if grep -q "open-ended-note-scanner" "$REPO_ROOT/tools/ffs-ops/src/main.rs" \
    && grep -q "validate-source-scope-manifest" "$REPO_ROOT/tools/ffs-ops/src/main.rs"; then
    scenario_result "open_ended_note_scanner_inputs_present" "PASS" "fixtures, inventory doc, source-scope manifest, and CLI commands are present"
else
    scenario_result "open_ended_note_scanner_inputs_present" "FAIL" "CLI command missing"
    e2e_fail "open-ended inventory scanner/source-scope commands are not wired"
fi

e2e_step "Scenario 2: positive fixture emits a valid classified report"
if run_harness "$POSITIVE_LOG" open-ended-note-scanner \
    --source "$POSITIVE_FIXTURE" \
    --reproduction-command "$POSITIVE_REPRO_COMMAND"; then
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
run_harness "$NEGATIVE_LOG" open-ended-note-scanner \
    --source "$NEGATIVE_FIXTURE" \
    --reproduction-command "$NEGATIVE_REPRO_COMMAND"
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
if positive["scanner_version"] != "bd-mockscan-open-ended-note-scanner-v2":
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
if negative["unresolved_note_count"] != 3:
    raise SystemExit("negative fixture should have exactly three unresolved rows")
if not any("lacks linked bead/artifact" in error for error in negative["errors"]):
    raise SystemExit("negative report missing linkage diagnostic")

required_patterns = {
    "add more cases",
    "expand corpus",
    "TODO fuzz",
    "HACK",
    "XXX",
    "future edge cases",
    "adversarial inputs",
    "more goldens",
    "known gaps",
    "fake delay",
    "mock implementation",
    "dummy implementation",
    "placeholder implementation",
    "stub implementation",
    "not yet implemented",
    "temporary sleep",
    "thread::sleep",
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
if run_harness "$REAL_LOG" open-ended-note-scanner \
    --source "$REAL_INVENTORY" \
    --reproduction-command "$REAL_REPRO_COMMAND"; then
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

e2e_step "Scenario 6: source-scope manifest scans the real workspace"
if run_harness "$SOURCE_SCOPE_LOG" validate-source-scope-manifest \
    --manifest "$SOURCE_SCOPE_MANIFEST" \
    --workspace-root "$REPO_ROOT"; then
    extract_source_scope_json "$SOURCE_SCOPE_LOG" "$SOURCE_SCOPE_REPORT"
    python3 - "$SOURCE_SCOPE_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required_families = {
    "readme_status_docs",
    "agent_workflow_docs",
    "feature_parity_doc",
    "canonical_spec_docs",
    "architecture_design_docs",
    "conformance_docs",
    "conformance_fixture_artifacts",
    "fixture_manifests",
    "test_control_artifacts",
    "tests",
    "checked_in_evidence_artifacts",
    "crate_manifest_and_benchmark_sources",
    "fuzz_campaign_artifacts",
    "fuzz_corpus_notes",
    "fuzz_targets",
    "fuzz_orchestration",
    "operational_scripts",
    "harness_scripts",
    "operator_runbook_docs",
    "operational_evidence_artifacts",
    "mounted_lane_docs",
    "repair_docs",
    "performance_control_artifacts",
    "performance_xfstests_notes",
}
build_output_sensitive_families = {
    "agent_workflow_docs",
    "architecture_design_docs",
    "conformance_docs",
    "conformance_fixture_artifacts",
    "test_control_artifacts",
    "tests",
    "checked_in_evidence_artifacts",
    "crate_manifest_and_benchmark_sources",
    "fuzz_campaign_artifacts",
    "fuzz_targets",
    "fuzz_orchestration",
    "operational_scripts",
    "operator_runbook_docs",
    "operational_evidence_artifacts",
    "performance_control_artifacts",
}
required_build_exclusions = {
    "target/**",
    "**/.rch-target/**",
    "**/.rch-target-*/**",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["schema_version"] != 1 or report["source_manifest_version"] != 1:
    raise SystemExit("source-scope schema version drifted")
if report["source_count"] != len(required_families):
    raise SystemExit("source-scope report should scan every required family")
families = {source["source_family"] for source in report["scanned_sources"]}
if families != required_families:
    raise SystemExit(f"source-scope families drifted: {sorted(families)}")
if not report["reproduction_command"].startswith("cargo run -p ffs-ops -- validate-source-scope-manifest"):
    raise SystemExit("source-scope report did not preserve reproduction command")
for source in report["scanned_sources"]:
    for field in [
        "id",
        "source_family",
        "included_globs",
        "excluded_globs",
        "inclusion_decision",
        "file_or_directory_hash",
        "matched_note_count",
        "linked_bead_or_artifact_count",
        "stale_allowance",
        "output_path",
        "reproduction_command",
        "matched_paths",
    ]:
        if field not in source:
            raise SystemExit(f"source-scope row missing {field}")
    if source["inclusion_decision"] != "included":
        raise SystemExit(f"unexpected source inclusion decision: {source}")
    if not source["file_or_directory_hash"].startswith("sha256:"):
        raise SystemExit(f"source {source['id']} missing aggregate hash")
    if not source["included_globs"]:
        raise SystemExit(f"source {source['id']} missing included globs")
    if source["source_family"] in build_output_sensitive_families:
        missing_build_exclusions = required_build_exclusions - set(source["excluded_globs"])
        if missing_build_exclusions:
            raise SystemExit(
                f"source {source['id']} missing build-output exclusions: "
                f"{sorted(missing_build_exclusions)}"
            )
tests_source = next(source for source in report["scanned_sources"] if source["source_family"] == "tests")
if any(path["source_path"].startswith("vendor/") for path in tests_source["matched_paths"]):
    raise SystemExit("source-scope tests scan should not include vendored paths")
harness_source = next(source for source in report["scanned_sources"] if source["source_family"] == "harness_scripts")
required_harness_globs = {
    "scripts/e2e/**/*.sh",
    "scripts/e2e/**/*.py",
    "scripts/e2e/**/*.json",
}
missing_harness_globs = required_harness_globs - set(harness_source["included_globs"])
if missing_harness_globs:
    raise SystemExit(f"harness_scripts source missing globs: {sorted(missing_harness_globs)}")
if "scripts/e2e/_artifacts/**" not in harness_source["excluded_globs"]:
    raise SystemExit("harness_scripts source must exclude generated e2e artifacts")
PY
    scenario_result "source_scope_manifest_real_workspace" "PASS" "real workspace source-scope scan is valid"
else
    sed -n '1,160p' "$SOURCE_SCOPE_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "source_scope_manifest_real_workspace" "FAIL" "real workspace source-scope scan rejected"
    e2e_fail "source-scope manifest rejected the real workspace"
fi

e2e_step "Scenario 7: source-scope manifest fails closed when a required family is removed"
set +e
run_harness "$SOURCE_SCOPE_NEGATIVE_LOG" validate-source-scope-manifest \
    --manifest "$SOURCE_SCOPE_MANIFEST" \
    --workspace-root "$REPO_ROOT" \
    --remove-source-family tests
SOURCE_SCOPE_NEGATIVE_STATUS=$?
set -e
if [[ "$SOURCE_SCOPE_NEGATIVE_STATUS" -ne 0 ]] \
    && grep -Fq "Remote command finished: exit=1" "$SOURCE_SCOPE_NEGATIVE_LOG" \
    && grep -Fq 'source scope manifest missing required family `tests`' "$SOURCE_SCOPE_NEGATIVE_LOG"; then
    scenario_result "source_scope_manifest_missing_family" "PASS" "required source family omission rejected"
elif grep -Fq "RCH_LOCAL_FALLBACK_REJECTED" "$SOURCE_SCOPE_NEGATIVE_LOG"; then
    sed -n '1,160p' "$SOURCE_SCOPE_NEGATIVE_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "source_scope_manifest_missing_family_rch_blocked" "FAIL" "RCH local fallback rejected before missing-family verdict"
    e2e_fail "source-scope manifest missing-family proof blocked by RCH local fallback"
else
    sed -n '1,160p' "$SOURCE_SCOPE_NEGATIVE_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    scenario_result "source_scope_manifest_missing_family" "FAIL" "required source family omission did not fail closed"
    e2e_fail "source-scope manifest accepted a missing required source family"
fi

e2e_step "Scenario 8: source-scope dirty workspace proof runs through RCH"
if RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
    RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-2}" \
    e2e_rch_capture "$SOURCE_SCOPE_DIRTY_UNIT_LOG" \
    env "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
    cargo test -p ffs-harness source_scope_scan -- --nocapture; then
    if grep -Fq "source_scope_scan_uses_git_tracked_files_for_canonical_hashes" "$SOURCE_SCOPE_DIRTY_UNIT_LOG" \
        && grep -Fq "source_scope_scan_report_json_shape" "$SOURCE_SCOPE_DIRTY_UNIT_LOG" \
        && grep -Fq '"source_path": "artifacts/e2e/20990101_000000_untracked_local/run.log"' "$SOURCE_SCOPE_DIRTY_SNAPSHOT" \
        && grep -Fq '"exclusion_reason": "untracked path excluded from canonical source hash"' "$SOURCE_SCOPE_DIRTY_SNAPSHOT" \
        && grep -Fq '"untracked_matched_path_count": 1' "$SOURCE_SCOPE_DIRTY_SNAPSHOT"; then
        scenario_result "source_scope_dirty_workspace_stability" "PASS" "dirty workspace unit proof ran remotely and snapshot pins excluded untracked path"
    else
        sed -n '1,200p' "$SOURCE_SCOPE_DIRTY_UNIT_LOG" | while IFS= read -r line; do
            e2e_log "  $line"
        done
        scenario_result "source_scope_dirty_workspace_stability" "FAIL" "dirty workspace proof or snapshot evidence missing"
        e2e_fail "source-scope dirty workspace proof did not expose expected diagnostics"
    fi
else
    sed -n '1,200p' "$SOURCE_SCOPE_DIRTY_UNIT_LOG" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    if grep -Fq "RCH_LOCAL_FALLBACK_REJECTED" "$SOURCE_SCOPE_DIRTY_UNIT_LOG"; then
        scenario_result "source_scope_dirty_workspace_stability_rch_blocked" "FAIL" "RCH local fallback rejected before dirty workspace verdict"
        e2e_fail "source-scope dirty workspace proof blocked by RCH local fallback"
    else
        scenario_result "source_scope_dirty_workspace_stability" "FAIL" "dirty workspace source-scope unit proof failed"
        e2e_fail "source-scope dirty workspace unit proof failed"
    fi
fi

e2e_pass
