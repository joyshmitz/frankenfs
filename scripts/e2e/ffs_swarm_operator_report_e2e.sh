#!/usr/bin/env bash
# ffs_swarm_operator_report_e2e.sh - non-permissioned swarm operator report gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_swarm_operator_report}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
SELF_CHECK="${FFS_SWARM_OPERATOR_REPORT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_SWARM_OPERATOR_REPORT_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "report_id" in obj and "card_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("swarm operator report JSON object not found")
PY
}

e2e_init "ffs_swarm_operator_report"

REPORT_SOURCE="$REPO_ROOT/benchmarks/swarm_operator_report.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/swarm_operator_report"
REPORT_JSON="$E2E_LOG_DIR/swarm_operator_report_validation.json"
VALIDATE_RAW="$E2E_LOG_DIR/swarm_operator_report_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/swarm_operator_report_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/swarm_operator_report_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/swarm_operator_report_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/swarm_operator_report_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_SWARM_OPERATOR_REPORT_FIXTURE_CASE:-complete}"

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
  "report_id": "frankenfs_swarm_operator_report_v1",
  "card_count": 6,
  "proof_bundle_consumer_count": 2,
  "release_gate_consumer_count": 2,
  "claim_state_counts": {
    "analysis_ready": 4,
    "permissioned_required": 2
  },
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
        echo "unknown swarm operator report fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib swarm_operator_report"*)
        printf '%s\n' \
            "test checked_in_swarm_operator_report_validates ... ok" \
            "test claim_upgrade_without_evidence_fails ... ok" \
            "test render_swarm_operator_report_markdown_sample_snapshot ... ok"
        exit 0
        ;;
    *"swarm_operator_report_invalid.json"*)
        echo "evidence references unlinked bead bd-unlinked" >&2
        exit 1
        ;;
    *"--format markdown"*)
        printf '%s\n' \
            "# Swarm Operator Decision Report" \
            "" \
            "- card: \`tail_latency_decomposition\`" \
            "- card: \`cache_budget_controller\`" \
            "- release claim: \`permissioned_required\`"
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
    local child_log="$E2E_LOG_DIR/swarm_operator_report_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_SWARM_OPERATOR_REPORT_SELF_CHECK=0 \
        FFS_SWARM_OPERATOR_REPORT_SKIP_SELF_CHECK=1 \
        FFS_SWARM_OPERATOR_REPORT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_swarm_operator_report_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic swarm operator report wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path markdown_path
    stub_path="$E2E_LOG_DIR/rch-swarm-operator-report-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/swarm_operator_report_validation.json"
    markdown_path="$(dirname "$result_path")/swarm_operator_report_markdown.raw"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$markdown_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "swarm_operator_report_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "swarm_operator_report_operator_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "swarm_operator_report_invalid_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "swarm_operator_report_markdown_docs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "swarm_operator_report_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .card_count == 6
            and .proof_bundle_consumer_count > 0
            and .release_gate_consumer_count > 0
            and (.claim_state_counts.measured_authoritative == null)
        ' "$report_path" >/dev/null \
        && grep -q "# Swarm Operator Decision Report" "$markdown_path" \
        && grep -q "tail_latency_decomposition" "$markdown_path"; then
        scenario_result "swarm_operator_report_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} markdown=${markdown_path}"
    else
        scenario_result "swarm_operator_report_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "swarm operator report complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "swarm_operator_report_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "swarm_operator_report_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "swarm operator report local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "swarm operator report wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: swarm operator report CLI is wired"
if grep -q "pub mod swarm_operator_report" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-swarm-operator-report" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_swarm_operator_report" scripts/e2e/scenario_catalog.json; then
    scenario_result "swarm_operator_report_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "swarm_operator_report_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in swarm operator report validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-swarm-operator-report \
    --report "$REPORT_SOURCE" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "swarm_operator_report_validates" "PASS" "checked-in operator report accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "swarm_operator_report_validates" "FAIL" "checked-in operator report rejected"
fi

e2e_step "Scenario 3: report keeps operator cards and conservative claim states explicit"
if python3 - "$REPORT_JSON" "$REPORT_SOURCE" <<'PY'
import json
import pathlib
import sys

validation = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
source = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
required_cards = {
    "tail_latency_decomposition",
    "numa_shard_harness",
    "rcu_qsbr_metadata",
    "parallel_wal_group_commit",
    "cache_budget_controller",
    "scrub_repair_scheduler",
}
if not validation["valid"]:
    raise SystemExit(validation["errors"])
if validation["card_count"] != len(required_cards):
    raise SystemExit("expected exactly the required operator cards")
if set(source["required_card_ids"]) != required_cards:
    raise SystemExit("required_card_ids drifted")
if {card["idea_id"] for card in source["cards"]} != required_cards:
    raise SystemExit("operator card set drifted")
if validation["proof_bundle_consumer_count"] == 0 or validation["release_gate_consumer_count"] == 0:
    raise SystemExit("proof-bundle and release-gate consumers must be declared")
if "measured_authoritative" in validation["claim_state_counts"]:
    raise SystemExit("non-permissioned report must not claim authoritative measurement")
for card in source["cards"]:
    if not card["evidence"]:
        raise SystemExit(f"missing evidence: {card['idea_id']}")
    if not card["validation_command"].strip():
        raise SystemExit(f"missing validation command: {card['idea_id']}")
    if not card["expected_loss_rule"].strip() or not card["fallback"].strip():
        raise SystemExit(f"missing operator policy: {card['idea_id']}")
    for bead_id in card["linked_bead_ids"]:
        if not bead_id.startswith("bd-"):
            raise SystemExit(f"linked bead must be a bd id: {card['idea_id']}")
PY
then
    scenario_result "swarm_operator_report_operator_contract" "PASS" "cards, consumers, evidence, and conservative claims verified"
else
    scenario_result "swarm_operator_report_operator_contract" "FAIL" "operator report contract failed"
fi

e2e_step "Scenario 4: invalid evidence linkage fails closed"
jq '.cards[0].evidence[0].linked_bead_id = "bd-unlinked"' "$REPORT_SOURCE" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-swarm-operator-report \
    --report "$INVALID_JSON"; then
    scenario_result "swarm_operator_report_invalid_rejected" "FAIL" "invalid report unexpectedly passed"
elif grep -q "unlinked bead" "$INVALID_RAW" || grep -q "references unlinked bead" "$INVALID_RAW"; then
    scenario_result "swarm_operator_report_invalid_rejected" "PASS" "unlinked evidence bead is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "swarm_operator_report_invalid_rejected" "FAIL" "invalid report failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-swarm-operator-report \
    --report "$REPORT_SOURCE" \
    --format markdown \
    --summary-out /dev/stdout \
    && grep -q "# Swarm Operator Decision Report" "$MARKDOWN_RAW" \
    && grep -q "tail_latency_decomposition" "$MARKDOWN_RAW" \
    && grep -q "Swarm Operator Report Contract" scripts/e2e/README.md; then
    scenario_result "swarm_operator_report_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "swarm_operator_report_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: swarm operator report unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib swarm_operator_report -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "checked_in_swarm_operator_report_validates" \
        "claim_upgrade_without_evidence_fails" \
        "render_swarm_operator_report_markdown_sample_snapshot"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "swarm_operator_report_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "swarm_operator_report_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Swarm operator report: $REPORT_SOURCE"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Swarm operator report scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Swarm operator report scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
