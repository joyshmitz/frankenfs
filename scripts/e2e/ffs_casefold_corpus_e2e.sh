#!/usr/bin/env bash
# ffs_casefold_corpus_e2e.sh - non-permissioned ext4 casefold corpus gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_casefold_corpus}"
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
    if isinstance(obj, dict) and "corpus_id" in obj and "case_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("casefold corpus report JSON object not found")
PY
}

e2e_init "ffs_casefold_corpus"

CORPUS_JSON="$REPO_ROOT/tests/casefold-corpus/casefold_corpus.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/casefold_corpus"
REPORT_JSON="$E2E_LOG_DIR/casefold_corpus_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/casefold_corpus_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/casefold_corpus_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/casefold_corpus_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/casefold_corpus_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/casefold_corpus_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: ext4 casefold corpus CLI is wired"
if grep -q "pub mod casefold_corpus" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-casefold-corpus" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_casefold_corpus" scripts/e2e/scenario_catalog.json; then
    scenario_result "casefold_corpus_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "casefold_corpus_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in ext4 casefold corpus validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-casefold-corpus \
    --corpus "$CORPUS_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "casefold_corpus_validates" "PASS" "checked-in corpus accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "casefold_corpus_validates" "FAIL" "checked-in corpus rejected"
fi

e2e_step "Scenario 3: corpus report preserves operation and refusal coverage"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required_operations = {
    "lookup",
    "create",
    "rename",
    "cross_directory_rename",
    "mount_feature_check",
}
required_outcomes = {
    "create_collision_refused",
    "rename_collision_refused",
    "invalid_encoding_refused",
    "mount_feature_accepted",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["case_count"] < 10:
    raise SystemExit("expected at least ten casefold cases")
missing_operations = required_operations - set(report["operations_seen"])
if missing_operations:
    raise SystemExit(f"missing operations: {sorted(missing_operations)}")
missing_outcomes = required_outcomes - set(report["outcomes_seen"])
if missing_outcomes:
    raise SystemExit(f"missing outcomes: {sorted(missing_outcomes)}")
if report["kernel_compared_count"] < 1:
    raise SystemExit("expected at least one kernel-compared case")
PY
then
    scenario_result "casefold_corpus_coverage" "PASS" "operation and refusal coverage verified"
else
    scenario_result "casefold_corpus_coverage" "FAIL" "casefold coverage contract failed"
fi

e2e_step "Scenario 4: invalid ext4 casefold corpus fails closed"
jq 'del(.cases[0].source_name_bytes_hex)' "$CORPUS_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-casefold-corpus \
    --corpus "$INVALID_JSON"; then
    scenario_result "casefold_corpus_invalid_rejected" "FAIL" "invalid corpus unexpectedly passed"
elif grep -q "source_name_bytes_hex" "$INVALID_RAW" \
    || grep -q "failed to parse casefold corpus JSON" "$INVALID_RAW"; then
    scenario_result "casefold_corpus_invalid_rejected" "PASS" "missing source-name hex is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "casefold_corpus_invalid_rejected" "FAIL" "invalid corpus failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-casefold-corpus \
    --corpus "$CORPUS_JSON" \
    --format markdown \
    && grep -q "# Ext4 Casefold Corpus" "$MARKDOWN_RAW" \
    && grep -q "invalid_encoding_refused" "$MARKDOWN_RAW" \
    && grep -q "Ext4 Casefold Corpus Contract" scripts/e2e/README.md; then
    scenario_result "casefold_corpus_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "casefold_corpus_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: ext4 casefold corpus unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib casefold_corpus -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_corpus_validates_required_coverage" \
        "render_markdown_summarizes_default_corpus" \
        "malformed_source_hex_is_rejected"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "casefold_corpus_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "casefold_corpus_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Ext4 casefold corpus: $CORPUS_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Ext4 casefold corpus scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Ext4 casefold corpus scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
