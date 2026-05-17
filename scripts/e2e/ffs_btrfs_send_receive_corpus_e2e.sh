#!/usr/bin/env bash
# ffs_btrfs_send_receive_corpus_e2e.sh - non-permissioned btrfs send/receive corpus gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_btrfs_send_receive_corpus}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_BTRFS_SEND_RECEIVE_CORPUS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_BTRFS_SEND_RECEIVE_CORPUS_SKIP_SELF_CHECK:-0}"

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
    raise SystemExit("btrfs send/receive corpus report JSON object not found")
PY
}

e2e_init "ffs_btrfs_send_receive_corpus"

CORPUS_JSON="$REPO_ROOT/tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/btrfs_send_receive_corpus"
REPORT_JSON="$E2E_LOG_DIR/btrfs_send_receive_corpus_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/btrfs_send_receive_corpus_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/btrfs_send_receive_corpus_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/btrfs_send_receive_corpus_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/btrfs_send_receive_corpus_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/btrfs_send_receive_corpus_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_BTRFS_SEND_RECEIVE_CORPUS_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    cat <<JSON
{
  "schema_version": 1,
  "corpus_id": "frankenfs_btrfs_send_receive_corpus_v1",
  "valid": true,
  "case_count": 6,
  "supported_subsets": [
    "parse_only",
    "export_only",
    "receive_only",
    "roundtrip_supported",
    "unsupported"
  ],
  "refusal_kinds": [
    "refused_unsupported_record",
    "refused_incremental_parent_mismatch"
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
        echo "unknown btrfs send/receive corpus fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib btrfs_send_receive_corpus"*)
        printf '%s\n' \
            "test default_corpus_validates_required_subsets_and_refusals ... ok" \
            "test render_markdown_summarizes_default_corpus ... ok" \
            "test refusal_outcome_must_use_unsupported_subset ... ok"
        exit 0
        ;;
    *"btrfs_send_receive_corpus_invalid.json"*)
        echo "failed to parse btrfs send/receive corpus JSON: missing field expected_stream_hash" >&2
        exit 1
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Btrfs Send/Receive Corpus" \
            "" \
            "- corpus: \`frankenfs_btrfs_send_receive_corpus_v1\`" \
            "- subset: \`roundtrip_supported\`" \
            "- refusal: \`refused_incremental_parent_mismatch\`"
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
    local child_log="$E2E_LOG_DIR/btrfs_send_receive_corpus_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_BTRFS_SEND_RECEIVE_CORPUS_SELF_CHECK=0 \
        FFS_BTRFS_SEND_RECEIVE_CORPUS_SKIP_SELF_CHECK=1 \
        FFS_BTRFS_SEND_RECEIVE_CORPUS_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_btrfs_send_receive_corpus_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic btrfs send/receive corpus wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path markdown_path
    stub_path="$E2E_LOG_DIR/rch-btrfs-send-receive-corpus-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/btrfs_send_receive_corpus_report.json"
    markdown_path="$(dirname "$result_path")/btrfs_send_receive_corpus_markdown.raw"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$markdown_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "btrfs_send_receive_corpus_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_send_receive_corpus_state_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_send_receive_corpus_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_send_receive_corpus_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "btrfs_send_receive_corpus_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .case_count >= 6
            and ((.supported_subsets | index("parse_only")) != null)
            and ((.supported_subsets | index("export_only")) != null)
            and ((.supported_subsets | index("receive_only")) != null)
            and ((.supported_subsets | index("roundtrip_supported")) != null)
            and ((.supported_subsets | index("unsupported")) != null)
            and ((.refusal_kinds | index("refused_unsupported_record")) != null)
            and ((.refusal_kinds | index("refused_incremental_parent_mismatch")) != null)
        ' "$report_path" >/dev/null \
        && grep -q "# Btrfs Send/Receive Corpus" "$markdown_path" \
        && grep -q "roundtrip_supported" "$markdown_path"; then
        scenario_result "btrfs_send_receive_corpus_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} markdown=${markdown_path}"
    else
        scenario_result "btrfs_send_receive_corpus_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "btrfs send/receive corpus complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "btrfs_send_receive_corpus_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "btrfs_send_receive_corpus_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "btrfs send/receive corpus local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "btrfs send/receive corpus wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: btrfs send/receive corpus CLI is wired"
if grep -q "pub mod btrfs_send_receive_corpus" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-btrfs-send-receive-corpus" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_btrfs_send_receive_corpus" scripts/e2e/scenario_catalog.json; then
    scenario_result "btrfs_send_receive_corpus_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "btrfs_send_receive_corpus_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in btrfs send/receive corpus validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-btrfs-send-receive-corpus \
    --corpus "$CORPUS_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "btrfs_send_receive_corpus_validates" "PASS" "checked-in corpus accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "btrfs_send_receive_corpus_validates" "FAIL" "checked-in corpus rejected"
fi

e2e_step "Scenario 3: corpus report preserves support-state and refusal coverage"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required_subsets = {
    "parse_only",
    "export_only",
    "receive_only",
    "roundtrip_supported",
    "unsupported",
}
required_refusals = {
    "refused_unsupported_record",
    "refused_incremental_parent_mismatch",
}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["case_count"] < 6:
    raise SystemExit("expected at least six send/receive cases")
missing_subsets = required_subsets - set(report["supported_subsets"])
if missing_subsets:
    raise SystemExit(f"missing supported subsets: {sorted(missing_subsets)}")
missing_refusals = required_refusals - set(report["refusal_kinds"])
if missing_refusals:
    raise SystemExit(f"missing refusal kinds: {sorted(missing_refusals)}")
PY
then
    scenario_result "btrfs_send_receive_corpus_state_coverage" "PASS" "support states and refusal kinds verified"
else
    scenario_result "btrfs_send_receive_corpus_state_coverage" "FAIL" "support-state coverage contract failed"
fi

e2e_step "Scenario 4: invalid btrfs send/receive corpus fails closed"
jq 'del(.cases[0].expected_stream_hash)' "$CORPUS_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-btrfs-send-receive-corpus \
    --corpus "$INVALID_JSON"; then
    scenario_result "btrfs_send_receive_corpus_invalid_rejected" "FAIL" "invalid corpus unexpectedly passed"
elif grep -q "expected_stream_hash" "$INVALID_RAW" \
    || grep -q "failed to parse btrfs send/receive corpus JSON" "$INVALID_RAW"; then
    scenario_result "btrfs_send_receive_corpus_invalid_rejected" "PASS" "missing stream hash is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "btrfs_send_receive_corpus_invalid_rejected" "FAIL" "invalid corpus failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-btrfs-send-receive-corpus \
    --corpus "$CORPUS_JSON" \
    --format markdown \
    && grep -q "# Btrfs Send/Receive Corpus" "$MARKDOWN_RAW" \
    && grep -q "roundtrip_supported" "$MARKDOWN_RAW" \
    && grep -q "Btrfs Send/Receive Corpus Contract" scripts/e2e/README.md; then
    scenario_result "btrfs_send_receive_corpus_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "btrfs_send_receive_corpus_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: btrfs send/receive corpus unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib btrfs_send_receive_corpus -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_corpus_validates_required_subsets_and_refusals" \
        "render_markdown_summarizes_default_corpus" \
        "refusal_outcome_must_use_unsupported_subset"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "btrfs_send_receive_corpus_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "btrfs_send_receive_corpus_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Btrfs send/receive corpus: $CORPUS_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Btrfs send/receive corpus scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Btrfs send/receive corpus scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
