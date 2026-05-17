#!/usr/bin/env bash
# ffs_chaos_replay_lab_e2e.sh - non-permissioned chaos replay lab gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_chaos_replay_lab}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_CHAOS_REPLAY_LAB_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_CHAOS_REPLAY_LAB_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "lab_id" in obj and "schedule_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("chaos replay lab report JSON object not found")
PY
}

e2e_init "ffs_chaos_replay_lab"

LAB_JSON="$REPO_ROOT/tests/chaos-replay-lab/chaos_replay_lab.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/chaos_replay_lab"
REPORT_JSON="$E2E_LOG_DIR/chaos_replay_lab_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/chaos_replay_lab_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/chaos_replay_lab_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/chaos_replay_lab_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/chaos_replay_lab_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/chaos_replay_lab_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_CHAOS_REPLAY_LAB_FIXTURE_CASE:-complete}"

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
  "lab_id": "frankenfs_chaos_replay_lab_v1",
  "schedule_count": 7,
  "minimized_count": 3,
  "crash_taxonomies_seen": [
    "pre_commit_crash",
    "post_commit_pre_flush_crash",
    "replay_interruption",
    "repair_interruption",
    "metadata_data_ordering_boundary"
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
        echo "unknown chaos replay lab fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib chaos_replay_lab"*)
        printf '%s\n' \
            "test default_lab_validates_required_taxonomy_coverage ... ok" \
            "test render_chaos_replay_lab_markdown_default_lab ... ok" \
            "test fail_on_errors_rejects_invalid_report ... ok"
        exit 0
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Chaos Replay Lab" \
            "" \
            "Crash Taxonomies: pre_commit_crash, repair_interruption"
        exit 0
        ;;
    *"chaos_replay_lab_invalid.json"*)
        echo "unsupported crash_taxonomy: vibes_taxonomy"
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
    local child_log="$E2E_LOG_DIR/chaos_replay_lab_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_CHAOS_REPLAY_LAB_SELF_CHECK=0 \
        FFS_CHAOS_REPLAY_LAB_SKIP_SELF_CHECK=1 \
        FFS_CHAOS_REPLAY_LAB_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_chaos_replay_lab_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic chaos replay lab wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-chaos-replay-lab-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/chaos_replay_lab_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "chaos_replay_lab_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "chaos_replay_lab_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "chaos_replay_lab_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "chaos_replay_lab_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .schedule_count == 7
            and .minimized_count == 3
            and (.crash_taxonomies_seen | index("metadata_data_ordering_boundary"))
        ' "$report_path" >/dev/null; then
        scenario_result "chaos_replay_lab_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "chaos_replay_lab_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "chaos replay lab complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "chaos_replay_lab_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "chaos_replay_lab_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "chaos replay lab local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "chaos replay lab wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: chaos replay lab CLI is wired"
if grep -q "pub mod chaos_replay_lab" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-chaos-replay-lab" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_chaos_replay_lab" scripts/e2e/scenario_catalog.json; then
    scenario_result "chaos_replay_lab_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "chaos_replay_lab_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in chaos replay lab validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-chaos-replay-lab \
    --lab "$LAB_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "chaos_replay_lab_validates" "PASS" "checked-in lab accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "chaos_replay_lab_validates" "FAIL" "checked-in lab rejected"
fi

e2e_step "Scenario 3: chaos replay coverage is explicit"
if python3 - "$REPORT_JSON" "$LAB_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
lab = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_taxonomies = {
    "pre_commit_crash",
    "post_commit_pre_flush_crash",
    "replay_interruption",
    "repair_interruption",
    "metadata_data_ordering_boundary",
}
allowed_lanes = {"core_labruntime", "mounted_e2e", "fixture_dry_run", "host_skip"}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["schedule_count"] < 7:
    raise SystemExit("expected at least seven chaos replay schedules")
if report["minimized_count"] < 3:
    raise SystemExit("expected at least three minimized schedules")
missing = required_taxonomies - set(report["crash_taxonomies_seen"])
if missing:
    raise SystemExit(f"missing crash taxonomies: {sorted(missing)}")
for schedule in lab["schedules"]:
    if schedule["lane"] not in allowed_lanes:
        raise SystemExit(f"unsupported lane: {schedule['schedule_id']}")
    if not schedule["raw_log_path"]:
        raise SystemExit(f"missing raw log: {schedule['schedule_id']}")
    if not schedule["replay_command"].startswith("rch exec -- cargo test"):
        raise SystemExit(f"replay command must be RCH cargo test: {schedule['schedule_id']}")
    if schedule["lane"] == "host_skip" and not schedule["host_skip_reason"]:
        raise SystemExit(f"host skip lacks reason: {schedule['schedule_id']}")
    if schedule["lane"] != "host_skip" and not (
        schedule["expected_survivor_paths"] or schedule["expected_absent_paths"]
    ):
        raise SystemExit(f"non-skip schedule lacks survivor contract: {schedule['schedule_id']}")
PY
then
    scenario_result "chaos_replay_lab_coverage" "PASS" "taxonomies, replay commands, logs, survivor contracts, and host-skip reason verified"
else
    scenario_result "chaos_replay_lab_coverage" "FAIL" "chaos replay coverage contract failed"
fi

e2e_step "Scenario 4: invalid chaos replay lab fails closed"
jq '.schedules[0].crash_taxonomy = "vibes_taxonomy"' "$LAB_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-chaos-replay-lab \
    --lab "$INVALID_JSON"; then
    scenario_result "chaos_replay_lab_invalid_rejected" "FAIL" "invalid lab unexpectedly passed"
elif grep -q "unsupported crash_taxonomy" "$INVALID_RAW"; then
    scenario_result "chaos_replay_lab_invalid_rejected" "PASS" "unsupported crash taxonomy is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "chaos_replay_lab_invalid_rejected" "FAIL" "invalid lab failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-chaos-replay-lab \
    --lab "$LAB_JSON" \
    --format markdown \
    && grep -q "# Chaos Replay Lab" "$MARKDOWN_RAW" \
    && grep -q "Crash Taxonomies" "$MARKDOWN_RAW" \
    && grep -q "Chaos Replay Lab Contract" scripts/e2e/README.md; then
    scenario_result "chaos_replay_lab_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "chaos_replay_lab_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: chaos replay lab unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib chaos_replay_lab -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_lab_validates_required_taxonomy_coverage" \
        "render_chaos_replay_lab_markdown_default_lab" \
        "fail_on_errors_rejects_invalid_report"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "chaos_replay_lab_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "chaos_replay_lab_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Chaos replay lab: $LAB_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Chaos replay lab scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Chaos replay lab scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
