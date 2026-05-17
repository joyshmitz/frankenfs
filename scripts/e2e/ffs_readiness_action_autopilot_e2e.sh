#!/usr/bin/env bash
# ffs_readiness_action_autopilot_e2e.sh - non-permissioned readiness action gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_readiness_action_autopilot}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-6}"
SELF_CHECK="${FFS_READINESS_ACTION_AUTOPILOT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_READINESS_ACTION_AUTOPILOT_SKIP_SELF_CHECK:-0}"

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
    if isinstance(obj, dict) and "dry_run" in obj and "planner_result" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("readiness action dry-run JSON report not found")
PY
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_READINESS_ACTION_AUTOPILOT_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown readiness action autopilot fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"recommend-readiness-actions"*"--input"*)
        echo "failed to parse readiness action input: missing field scenarios" >&2
        exit 1
        ;;
    *"recommend-readiness-actions"*)
        cat <<'REPORT'
{
  "dry_run": true,
  "report_id": "readiness_action_autopilot_e2e",
  "generated_at": "2026-05-12T00:00:00Z",
  "command_metadata": {
    "cleanup_status": "not_required_dry_run",
    "output_paths": [
      {"kind": "json_report"},
      {"kind": "markdown_report"},
      {"kind": "stdout_log"},
      {"kind": "stderr_log"}
    ]
  },
  "scenarios": [
    {"action_id": "claim-source-aware-task", "safety_class": "local_safe", "public_claim_effect": "downgrade_required", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "preserve-degraded-rch-proof-ledger", "safety_class": "local_safe", "public_claim_effect": "block_upgrade", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "block-permission-gated-claimability-row", "safety_class": "permissioned", "public_claim_effect": "block_upgrade", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "preserve-foreign-owner-handoff", "safety_class": "impossible", "public_claim_effect": "block_upgrade", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "define-readiness-action-schema", "safety_class": "local_safe", "public_claim_effect": "downgrade_required", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "run-permissioned-xfstests-baseline", "safety_class": "permissioned", "public_claim_effect": "block_upgrade", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "refresh-large-host-swarm-campaign", "safety_class": "permissioned", "public_claim_effect": "block_upgrade", "dry_run_note": "no reproduction command was executed"},
    {"action_id": "publish-operator-evidence", "safety_class": "local_safe", "public_claim_effect": "downgrade_required", "dry_run_note": "no reproduction command was executed"}
  ],
  "planner_result": {
    "report": {
      "recommendations": [
        {"action_id": "claim-source-aware-task", "safety_class": "local_safe", "public_claim_effect": "downgrade_required", "mail_thread_id": "bd-0chpv.5", "reservation_artifact_path": "artifacts/reservation.json"},
        {"action_id": "preserve-degraded-rch-proof-ledger", "safety_class": "local_safe", "public_claim_effect": "block_upgrade", "proof_artifact_path": "artifacts/rch-proof.json"},
        {"action_id": "block-permission-gated-claimability-row", "safety_class": "permissioned", "public_claim_effect": "block_upgrade"},
        {"action_id": "preserve-foreign-owner-handoff", "safety_class": "impossible", "public_claim_effect": "block_upgrade"},
        {"action_id": "define-readiness-action-schema", "safety_class": "local_safe", "public_claim_effect": "downgrade_required"},
        {"action_id": "run-permissioned-xfstests-baseline", "safety_class": "permissioned", "public_claim_effect": "block_upgrade"},
        {"action_id": "refresh-large-host-swarm-campaign", "safety_class": "permissioned", "public_claim_effect": "block_upgrade"},
        {"action_id": "publish-operator-evidence", "safety_class": "local_safe", "public_claim_effect": "downgrade_required"}
      ]
    }
  }
}
# Readiness Action Dry-Run Report
readiness-action-dry-run recommendations=8 scenarios=8 cleanup_status=not_required_dry_run
no reproduction commands executed
permissioned, destructive, and stale-evidence commands stayed dry-run only
LocalSafe Permissioned DowngradeRequired Operator Evidence
REPORT
        ;;
    *"cargo test -p ffs-harness readiness_action -- --nocapture"*)
        printf '%s\n' \
            "test readiness_action_autopilot::tests::default_fixture_set_covers_required_schema_surface ... ok" \
            "test readiness_action_autopilot::tests::recommend_readiness_actions_cmd_writes_dry_run_report_pack ... ok" \
            "test readiness_action_autopilot::tests::dry_run_json_report_matches_golden ... ok"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/readiness_action_autopilot_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_READINESS_ACTION_AUTOPILOT_SELF_CHECK=0 \
        FFS_READINESS_ACTION_AUTOPILOT_SKIP_SELF_CHECK=1 \
        FFS_READINESS_ACTION_AUTOPILOT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_readiness_action_autopilot_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic readiness action autopilot wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir dry_raw unit_log
    stub_path="$E2E_LOG_DIR/rch-readiness-action-autopilot-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    dry_raw="$result_dir/readiness_action_autopilot_dry_run.raw"
    unit_log="$result_dir/readiness_action_autopilot_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$dry_raw" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_report_pack" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_report_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_dry_run_logs" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_rejects_bad_input" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_docs_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_action_autopilot_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "# Readiness Action Dry-Run Report" "$dry_raw" \
        && grep -q "default_fixture_set_covers_required_schema_surface" "$unit_log"; then
        scenario_result "readiness_action_autopilot_fixture_complete_self_check" "PASS" "result=${result_path} dry_raw=${dry_raw}"
    else
        scenario_result "readiness_action_autopilot_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Readiness action autopilot complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "readiness_action_autopilot_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "readiness_action_autopilot_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Readiness action autopilot local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "readiness_action_autopilot_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "readiness_action_autopilot_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Readiness action autopilot missing remote evidence fixture self-check failed"
    fi
}

e2e_init "ffs_readiness_action_autopilot"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/readiness-action-autopilot"
REPORT_JSON="$E2E_LOG_DIR/readiness_action_autopilot_report.json"
DRY_RUN_RAW="$E2E_LOG_DIR/readiness_action_autopilot_dry_run.raw"
BAD_INPUT_JSON="$RCH_INPUT_DIR/readiness_action_bad_input.json"
BAD_INPUT_RAW="$E2E_LOG_DIR/readiness_action_autopilot_bad_input.raw"
UNIT_LOG="$E2E_LOG_DIR/readiness_action_autopilot_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: readiness action autopilot CLI is wired"
if grep -q "recommend-readiness-actions" crates/ffs-harness/src/main.rs \
    && grep -q "ReadinessActionDryRunReport" crates/ffs-harness/src/readiness_action_autopilot.rs \
    && grep -q "ffs_readiness_action_autopilot" scripts/e2e/scenario_catalog.json; then
    scenario_result "readiness_action_autopilot_cli_wired" "PASS" "CLI command, report schema, and catalog suite are exported"
else
    scenario_result "readiness_action_autopilot_cli_wired" "FAIL" "missing CLI command, report schema, or catalog suite"
fi

e2e_step "Scenario 2: dry-run report pack is emitted"
if e2e_rch_capture "$DRY_RUN_RAW" cargo run --quiet -p ffs-harness -- \
    recommend-readiness-actions \
    --out-json /dev/stdout \
    --out-md /dev/stdout \
    --stdout-log /dev/stdout \
    --stderr-log /dev/stdout \
    --report-id "readiness_action_autopilot_e2e" \
    --generated-at "2026-05-12T00:00:00Z" \
    --invocation "scripts/e2e/ffs_readiness_action_autopilot_e2e.sh" \
    && extract_report_json "$DRY_RUN_RAW" "$REPORT_JSON" \
    && grep -q "# Readiness Action Dry-Run Report" "$DRY_RUN_RAW" \
    && grep -q "readiness-action-dry-run" "$DRY_RUN_RAW" \
    && grep -q "no reproduction commands executed" "$DRY_RUN_RAW"; then
    scenario_result "readiness_action_autopilot_report_pack" "PASS" "JSON, Markdown, stdout, and stderr dry-run outputs were emitted"
else
    cat "$DRY_RUN_RAW"
    scenario_result "readiness_action_autopilot_report_pack" "FAIL" "dry-run command failed"
fi

e2e_step "Scenario 3: dry-run report keeps safety classifications explicit"
if python3 - "$REPORT_JSON" "$DRY_RUN_RAW" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
raw_output = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["dry_run"]:
    raise SystemExit("report must be dry_run")
if report["report_id"] != "readiness_action_autopilot_e2e":
    raise SystemExit("report_id drifted")
if report["generated_at"] != "2026-05-12T00:00:00Z":
    raise SystemExit("generated_at drifted")
metadata = report["command_metadata"]
if metadata["cleanup_status"] != "not_required_dry_run":
    raise SystemExit(f"unexpected cleanup status: {metadata['cleanup_status']}")
output_kinds = {row["kind"] for row in metadata["output_paths"]}
if output_kinds != {"json_report", "markdown_report", "stdout_log", "stderr_log"}:
    raise SystemExit(f"unexpected output paths: {output_kinds}")
scenarios = report["scenarios"]
if len(scenarios) != 8:
    raise SystemExit(f"expected 8 dry-run scenarios, got {len(scenarios)}")
action_ids = {row["action_id"] for row in scenarios}
required_actions = {
    "claim-source-aware-task",
    "preserve-degraded-rch-proof-ledger",
    "block-permission-gated-claimability-row",
    "preserve-foreign-owner-handoff",
    "define-readiness-action-schema",
    "run-permissioned-xfstests-baseline",
    "refresh-large-host-swarm-campaign",
}
if not required_actions <= action_ids:
    raise SystemExit(f"missing required actions: {required_actions - action_ids}")
safety_classes = {row["safety_class"] for row in scenarios}
if not {"local_safe", "permissioned", "impossible"} <= safety_classes:
    raise SystemExit(f"missing safety classes: {safety_classes}")
claim_effects = {row["public_claim_effect"] for row in scenarios}
if "downgrade_required" not in claim_effects and "block_upgrade" not in claim_effects:
    raise SystemExit(f"missing conservative claim effects: {claim_effects}")
if any("no reproduction command was executed" not in row["dry_run_note"] for row in scenarios):
    raise SystemExit("every scenario must carry a dry-run note")
if report["planner_result"]["report"]["recommendations"][0]["public_claim_effect"] == "upgrade_eligible":
    raise SystemExit("advisory planning evidence must not rank as a public upgrade")
advisory = [
    row for row in report["planner_result"]["report"]["recommendations"]
    if row["action_id"] in {
        "claim-source-aware-task",
        "preserve-degraded-rch-proof-ledger",
        "block-permission-gated-claimability-row",
        "preserve-foreign-owner-handoff",
    }
]
if len(advisory) != 4:
    raise SystemExit("missing advisory claimability/rch recommendations")
if any(row["public_claim_effect"] == "upgrade_eligible" for row in advisory):
    raise SystemExit("advisory claimability/rch recommendations must not upgrade public claims")
if not any(row.get("mail_thread_id") == "bd-0chpv.5" for row in advisory):
    raise SystemExit("claimability recommendation missing mail thread id")
if not any(row.get("proof_artifact_path") for row in advisory):
    raise SystemExit("rch proof recommendation missing proof artifact path")
if not any(row.get("reservation_artifact_path") for row in advisory):
    raise SystemExit("claimability recommendation missing reservation artifact path")
if any(row["action_id"] == "claim-raw-bv-parent-epic" for row in report["planner_result"]["report"]["recommendations"]):
    raise SystemExit("raw bv parent epic claim leaked into recommendations")
if "# Readiness Action Dry-Run Report" not in raw_output:
    raise SystemExit("markdown heading missing")
for marker in ("LocalSafe", "Permissioned", "DowngradeRequired", "Operator Evidence"):
    if marker not in raw_output:
        raise SystemExit(f"markdown missing {marker}")
PY
then
    scenario_result "readiness_action_autopilot_report_contract" "PASS" "dry-run classifications and conservative claim states verified"
else
    scenario_result "readiness_action_autopilot_report_contract" "FAIL" "dry-run report contract failed"
fi

e2e_step "Scenario 4: deterministic logs prove no commands executed"
if grep -q "readiness-action-dry-run" "$DRY_RUN_RAW" \
    && grep -q "recommendations=8" "$DRY_RUN_RAW" \
    && grep -q "scenarios=8" "$DRY_RUN_RAW" \
    && grep -q "cleanup_status=not_required_dry_run" "$DRY_RUN_RAW" \
    && grep -q "no reproduction commands executed" "$DRY_RUN_RAW" \
    && grep -q "permissioned, destructive, and stale-evidence commands stayed dry-run only" "$DRY_RUN_RAW"; then
    scenario_result "readiness_action_autopilot_dry_run_logs" "PASS" "stdout/stderr logs preserve dry-run safety evidence"
else
    cat "$DRY_RUN_RAW"
    scenario_result "readiness_action_autopilot_dry_run_logs" "FAIL" "dry-run logs missing safety evidence"
fi

e2e_step "Scenario 5: invalid input fails closed"
printf '{"report_id":42}\n' >"$BAD_INPUT_JSON"
if e2e_rch_capture "$BAD_INPUT_RAW" cargo run --quiet -p ffs-harness -- \
    recommend-readiness-actions \
    --input "$BAD_INPUT_JSON" \
    --out-json /dev/stdout \
    --out-md /dev/stdout \
    --stdout-log /dev/stdout \
    --stderr-log /dev/stdout; then
    scenario_result "readiness_action_autopilot_rejects_bad_input" "FAIL" "invalid input unexpectedly passed"
elif grep -q "failed to parse readiness action input" "$BAD_INPUT_RAW" \
    || grep -q "missing field" "$BAD_INPUT_RAW" \
    || grep -q "invalid type" "$BAD_INPUT_RAW"; then
    scenario_result "readiness_action_autopilot_rejects_bad_input" "PASS" "invalid input rejected"
else
    cat "$BAD_INPUT_RAW"
    scenario_result "readiness_action_autopilot_rejects_bad_input" "FAIL" "invalid input failed without actionable diagnostics"
fi

e2e_step "Scenario 6: docs contract is wired"
if grep -q "Readiness Action Autopilot Contract" scripts/e2e/README.md \
    && grep -q "recommend-readiness-actions" docs/runbooks/readiness-action-autopilot.md \
    && grep -q "readiness_action_autopilot_report_pack" scripts/e2e/scenario_catalog.json; then
    scenario_result "readiness_action_autopilot_docs_contract" "PASS" "E2E README, runbook, and catalog references are present"
else
    scenario_result "readiness_action_autopilot_docs_contract" "FAIL" "docs or catalog contract missing"
fi

e2e_step "Scenario 7: readiness action autopilot tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness readiness_action -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_fixture_set_covers_required_schema_surface" \
        "recommend_readiness_actions_cmd_writes_dry_run_report_pack" \
        "dry_run_json_report_matches_golden"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "readiness_action_autopilot_unit_tests" "PASS" "focused readiness action tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "readiness_action_autopilot_unit_tests" "FAIL" "focused readiness action tests failed"
fi

e2e_log "Readiness action report: $REPORT_JSON"
e2e_log "Readiness action raw output: $DRY_RUN_RAW"

if ((FAIL_COUNT == 0)); then
    e2e_log "Readiness action autopilot scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Readiness action autopilot scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
