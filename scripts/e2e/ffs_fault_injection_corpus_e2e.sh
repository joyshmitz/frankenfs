#!/usr/bin/env bash
# ffs_fault_injection_corpus_e2e.sh - non-permissioned fault-injection corpus gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fault_injection_corpus}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_FAULT_INJECTION_CORPUS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_FAULT_INJECTION_CORPUS_SKIP_SELF_CHECK:-0}"

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
    raise SystemExit("fault injection corpus report JSON object not found")
PY
}

e2e_init "ffs_fault_injection_corpus"

CORPUS_JSON="$REPO_ROOT/tests/fault-injection-corpus/fault_injection_corpus.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/fault_injection_corpus"
REPORT_JSON="$E2E_LOG_DIR/fault_injection_corpus_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/fault_injection_corpus_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/fault_injection_corpus_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/fault_injection_corpus_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/fault_injection_corpus_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/fault_injection_corpus_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_FAULT_INJECTION_CORPUS_FIXTURE_CASE:-complete}"

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
  "corpus_id": "frankenfs_fault_injection_corpus_v1",
  "case_count": 7,
  "fault_kinds_seen": [
    "bit_flip",
    "block_erasure",
    "reordered_blocks",
    "truncated_repair_metadata",
    "mismatched_symbol_set",
    "adversarial_seed"
  ],
  "repair_classes_seen": [
    "clean_repair",
    "partial_repair",
    "detection_only",
    "false_positive",
    "unsafe_to_repair"
  ],
  "adversarial_count": 1,
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
        echo "unknown fault injection corpus fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib fault_injection_corpus"*)
        printf '%s\n' \
            "test default_corpus_validates_required_coverage ... ok" \
            "test render_markdown_summarizes_default_corpus ... ok" \
            "test malformed_image_hash_is_rejected ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Fault Injection Corpus" \
            "" \
            "repair classes include unsafe_to_repair"
        exit 0
        ;;
    *"fault_injection_corpus_invalid.json"*)
        echo "original_image_hash is required"
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
    local child_log="$E2E_LOG_DIR/fault_injection_corpus_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_FAULT_INJECTION_CORPUS_SELF_CHECK=0 \
        FFS_FAULT_INJECTION_CORPUS_SKIP_SELF_CHECK=1 \
        FFS_FAULT_INJECTION_CORPUS_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_fault_injection_corpus_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic fault injection corpus wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-fault-injection-corpus-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/fault_injection_corpus_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "fault_injection_corpus_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "fault_injection_corpus_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "fault_injection_corpus_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "fault_injection_corpus_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .case_count == 7
            and .adversarial_count == 1
            and (.fault_kinds_seen | index("adversarial_seed"))
            and (.repair_classes_seen | index("unsafe_to_repair"))
        ' "$report_path" >/dev/null; then
        scenario_result "fault_injection_corpus_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "fault_injection_corpus_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "fault injection corpus complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "fault_injection_corpus_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fault_injection_corpus_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "fault injection corpus local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "fault injection corpus wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: fault injection corpus CLI is wired"
if grep -q "pub mod fault_injection_corpus" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-fault-injection-corpus" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_fault_injection_corpus" scripts/e2e/scenario_catalog.json; then
    scenario_result "fault_injection_corpus_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "fault_injection_corpus_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in fault injection corpus validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-fault-injection-corpus \
    --corpus "$CORPUS_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "fault_injection_corpus_validates" "PASS" "checked-in corpus accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "fault_injection_corpus_validates" "FAIL" "checked-in corpus rejected"
fi

e2e_step "Scenario 3: corpus report preserves fault and repair coverage"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required_fault_kinds = {
    "bit_flip",
    "block_erasure",
    "reordered_blocks",
    "truncated_repair_metadata",
    "mismatched_symbol_set",
    "adversarial_seed",
}
required_repair_classes = {
    "clean_repair",
    "partial_repair",
    "detection_only",
    "false_positive",
    "unsafe_to_repair",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["case_count"] < 7:
    raise SystemExit("expected at least seven fault-injection cases")
missing_faults = required_fault_kinds - set(report["fault_kinds_seen"])
if missing_faults:
    raise SystemExit(f"missing fault kinds: {sorted(missing_faults)}")
missing_classes = required_repair_classes - set(report["repair_classes_seen"])
if missing_classes:
    raise SystemExit(f"missing repair classes: {sorted(missing_classes)}")
if report["adversarial_count"] < 1:
    raise SystemExit("expected at least one adversarial case")
PY
then
    scenario_result "fault_injection_corpus_coverage" "PASS" "fault kinds, repair classes, and adversarial coverage verified"
else
    scenario_result "fault_injection_corpus_coverage" "FAIL" "fault-injection coverage contract failed"
fi

e2e_step "Scenario 4: invalid fault injection corpus fails closed"
jq 'del(.cases[0].original_image_hash)' "$CORPUS_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-fault-injection-corpus \
    --corpus "$INVALID_JSON"; then
    scenario_result "fault_injection_corpus_invalid_rejected" "FAIL" "invalid corpus unexpectedly passed"
elif grep -q "original_image_hash" "$INVALID_RAW" \
    || grep -q "failed to parse fault injection corpus JSON" "$INVALID_RAW"; then
    scenario_result "fault_injection_corpus_invalid_rejected" "PASS" "missing image hash is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "fault_injection_corpus_invalid_rejected" "FAIL" "invalid corpus failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-fault-injection-corpus \
    --corpus "$CORPUS_JSON" \
    --format markdown \
    && grep -q "# Fault Injection Corpus" "$MARKDOWN_RAW" \
    && grep -q "unsafe_to_repair" "$MARKDOWN_RAW" \
    && grep -q "Fault Injection Corpus Contract" scripts/e2e/README.md; then
    scenario_result "fault_injection_corpus_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "fault_injection_corpus_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: fault injection corpus unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib fault_injection_corpus -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_corpus_validates_required_coverage" \
        "render_markdown_summarizes_default_corpus" \
        "malformed_image_hash_is_rejected"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "fault_injection_corpus_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "fault_injection_corpus_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Fault injection corpus: $CORPUS_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Fault injection corpus scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Fault injection corpus scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
