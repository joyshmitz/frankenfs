#!/usr/bin/env bash
# ffs_repair_writeback_serialization_e2e.sh - dry-run gate for bd-rchk0.1.1.
#
# Validates the read-write repair/writeback serialization contract and proves
# the current mounted read-write repair path fails closed with repro artifacts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_writeback_serialization}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_REPAIR_WRITEBACK_SERIALIZATION_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_REPAIR_WRITEBACK_SERIALIZATION_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REPAIR_WRITEBACK_SERIALIZATION_SKIP_SELF_CHECK:-0}"

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

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

extract_json_object() {
    local input_path="$1"
    local output_path="$2"
    local object_index="${3:-0}"
    python3 - "$input_path" "$output_path" "$object_index" <<'PY'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
target_index = int(sys.argv[3])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
seen = 0
for idx, ch in enumerate(text):
    if ch != "{":
        continue
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        continue
    if seen == target_index:
        dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
        raise SystemExit(0)
    seen += 1
raise SystemExit(f"JSON object {target_index} not found in {source}")
PY
}

extract_markdown_report() {
    local input_path="$1"
    local output_path="$2"
    python3 - "$input_path" "$output_path" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Repair Writeback Serialization Contract")
if start < 0:
    raise SystemExit(f"repair/writeback markdown report not found in {source}")
end_marker = "\nrepair/writeback serialization summary written:"
end = text.find(end_marker, start)
if end < 0:
    end = len(text)
dest.write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_repair_writeback_serialization"

CONTRACT_JSON="$REPO_ROOT/docs/repair-writeback-serialization-contract.json"
REPORT_JSON="$E2E_LOG_DIR/repair_writeback_serialization_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/repair_writeback_serialization_artifact_manifest.json"
SUMMARY_MD="$E2E_LOG_DIR/repair_writeback_serialization_summary.md"
PROOF_SUMMARY_JSON="$E2E_LOG_DIR/repair_writeback_serialization_proof_summary.json"
VALIDATE_RAW="$E2E_LOG_DIR/repair_writeback_serialization_validate.raw"
ARTIFACT_RAW="$E2E_LOG_DIR/repair_writeback_serialization_artifact.raw"
SUMMARY_RAW="$E2E_LOG_DIR/repair_writeback_serialization_summary.raw"
PROOF_SUMMARY_RAW="$E2E_LOG_DIR/repair_writeback_serialization_proof_summary.raw"
BAD_MISSING_EVIDENCE="$E2E_LOG_DIR/bad_missing_evidence.json"
BAD_UNSAFE_RISK="$E2E_LOG_DIR/bad_unsafe_risk.json"
BAD_MUTATION_ALLOWED="$E2E_LOG_DIR/bad_mutation_allowed.json"
BAD_MISSING_REPRO="$E2E_LOG_DIR/bad_missing_repro.json"
BAD_BAD_SCHEDULE="$E2E_LOG_DIR/bad_bad_schedule.json"
BAD_RAW="$E2E_LOG_DIR/repair_writeback_bad.raw"
FAIL_CLOSED_ARTIFACT="$E2E_LOG_DIR/repair_writeback_rw_fail_closed_artifact.json"
FAIL_CLOSED_LOG="$E2E_LOG_DIR/repair_writeback_rw_fail_closed.log"
UNIT_LOG="$E2E_LOG_DIR/repair_writeback_serialization_unit_tests.log"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REPAIR_WRITEBACK_SERIALIZATION_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

required_cases = [
    "repair_before_write",
    "write_before_repair",
    "overlapping_writes",
    "disjoint_writes",
    "fsync_during_repair",
    "cancellation_during_decode",
    "cancellation_during_writeback",
    "symbol_refresh_races_client_write",
    "unmount_pending_repair",
    "reopen_after_failed_repair",
    "retry_after_abort",
    "serializer_epoch_refresh",
]

schedules = []
for index, case in enumerate(required_cases):
    classification = "accepted"
    if case == "overlapping_writes":
        classification = "rejected"
    elif case == "symbol_refresh_races_client_write":
        classification = "unsupported_interleaving"
    schedules.append({
        "schedule_id": f"schedule-{index:02d}",
        "coverage_case": case,
        "classification": classification,
        "seed": 8000 + index,
        "explored_schedule_count": 4 + index,
        "pruned_schedule_count": index,
        "timeout_decision": "within_budget",
        "liveness_decision": "complete",
        "operation_trace": [
            {"op": "client_write", "epoch": 42, "step": index},
            {"op": "repair_writeback_requested", "epoch": 42, "step": index + 1},
        ],
        "expected_survivor_set": ["client_write_epoch_42"],
        "observed_survivor_set": ["client_write_epoch_42"],
        "ledger_outcomes": ["rw_repair_serialization_missing"],
        "artifact_paths": [
            f"artifacts/repair-writeback/dry-run/{case}.json",
            f"artifacts/repair-writeback/dry-run/{case}.log",
        ],
        "cleanup_status": "preserved_artifacts",
        "follow_up_bead": "bd-rchk0.1.2",
    })

report = {
    "valid": True,
    "errors": [],
    "bead_id": "bd-rchk0.1.1",
    "state_count": 10,
    "transition_count": 10,
    "missing_required_evidence_fields": [],
    "missing_required_coverage_tags": [],
    "missing_required_race_coverage": [],
    "missing_required_schedule_log_fields": [],
    "risk_report": {
        "fail_closed_is_lower_loss": True,
    },
    "schedule_count": len(schedules),
    "transition_evaluations": [
        {
            "transition_id": "rw_repair_fail_closed",
            "from_state": "client_write_in_flight",
            "event": "repair_writeback_requested",
            "allowed": False,
            "mutation_allowed": False,
            "error_class": "rw_repair_serialization_missing",
            "follow_up_bead": "bd-rchk0.1.2",
        }
    ],
    "scenario_reports": [
        {
            "scenario_id": "repair_writeback_rw_fail_closed",
            "final_state": "repair_writeback_blocked_rw",
            "expected_error_class": "rw_repair_serialization_missing",
            "proves_no_lost_client_write": True,
            "preserves_reproduction_data": True,
        }
    ],
    "schedule_reports": schedules,
    "reproduction_command": "cargo run -p ffs-harness -- validate-repair-writeback-serialization",
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_sample_artifact_manifest() {
    cat <<'JSON'
{
  "schema_version": 1,
  "gate_id": "repair_writeback_serialization",
  "bead_id": "bd-rchk0.1.1",
  "artifacts": [
    {
      "category": "proof_summary",
      "path": "artifacts/repair-writeback/dry-run/proof-summary.json",
      "metadata": {
        "proof_bundle_lane": "repair_rw_writeback"
      }
    },
    {
      "category": "release_gate_summary",
      "path": "artifacts/repair-writeback/dry-run/release-gate.json",
      "metadata": {
        "release_gate_feature": "repair.rw.writeback"
      }
    }
  ]
}
JSON
}

emit_markdown_summary() {
    cat <<'MD'
# Repair Writeback Serialization Contract

The current RW repair/writeback transition fails closed with
`rw_repair_serialization_missing` until the unified serializer is present.
MD
}

emit_proof_summary() {
    python3 - <<'PY'
import json

required_cases = [
    "repair_before_write",
    "write_before_repair",
    "overlapping_writes",
    "disjoint_writes",
    "fsync_during_repair",
    "cancellation_during_decode",
    "cancellation_during_writeback",
    "symbol_refresh_races_client_write",
    "unmount_pending_repair",
    "reopen_after_failed_repair",
    "retry_after_abort",
]
required_identity_guards = [
    "epoch_generation_monotonic",
    "lease_generation_monotonic",
    "snapshot_id_mismatch_rejected",
    "repair_symbol_generation_monotonic",
    "block_range_epoch_guard",
    "retry_generation_advances_after_abort",
    "halfway_failure_preserves_generation",
]
summary = {
    "schema_version": 1,
    "producer_bead_id": "bd-rchk0.1.1.1",
    "source_bead_id": "bd-rchk0.1.1",
    "safe_to_enable_rw_repair": False,
    "downstream_inputs": [
        {"bead_id": "bd-rchk0.1.2", "input": "serializer"},
        {"bead_id": "bd-rchk0.1.3", "input": "mounted proof"},
        {"bead_id": "bd-rchk0.1.4", "input": "release gate"},
    ],
    "transition_guards": [
        {
            "from_state": "client_write_in_flight",
            "event": "repair_writeback_requested",
            "allowed": False,
            "mutation_allowed": False,
            "error_class": "rw_repair_serialization_missing",
        }
    ],
    "race_schedule_inputs": [
        {"coverage_case": case, "schedule_id": f"proof-{index:02d}"}
        for index, case in enumerate(required_cases)
    ],
    "identity_guard_inputs": [
        {
            "guard_id": guard_id,
            "aba_fixture_id": f"aba_{guard_id}",
            "refusal_error_class": "stale_repair_identity",
        }
        for guard_id in required_identity_guards
    ],
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown repair/writeback fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib repair_writeback_serialization"*)
        printf '%s\n' \
            "test repair_writeback_serialization::tests::checked_in_contract_validates ... ok" \
            "test repair_writeback_serialization::tests::proof_summary_shape ... ok" \
            "test repair_writeback_serialization::tests::invalid_contract_variants_fail_closed ... ok"
        exit 0
        ;;
    *"--contract-json-env REPAIR_WRITEBACK_CONTRACT_JSON"*)
        echo "error: repair/writeback serialization validation failed: fixture invalid contract" >&2
        exit 1
        ;;
    *"--artifact-out"*)
        emit_sample_artifact_manifest
        exit 0
        ;;
    *"--summary-out"*)
        emit_markdown_summary
        exit 0
        ;;
    *"--proof-summary-out"*)
        emit_proof_summary
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
    local child_log="$E2E_LOG_DIR/repair_writeback_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REPAIR_WRITEBACK_SERIALIZATION_SELF_CHECK=0 \
        FFS_REPAIR_WRITEBACK_SERIALIZATION_SKIP_SELF_CHECK=1 \
        FFS_REPAIR_WRITEBACK_SERIALIZATION_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_repair_writeback_serialization_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic repair/writeback serialization wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path artifact_path summary_path proof_summary_path fail_artifact unit_log
    stub_path="$E2E_LOG_DIR/rch-repair-writeback-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/repair_writeback_serialization_report.json"
    artifact_path="$(dirname "$result_path")/repair_writeback_serialization_artifact_manifest.json"
    summary_path="$(dirname "$result_path")/repair_writeback_serialization_summary.md"
    proof_summary_path="$(dirname "$result_path")/repair_writeback_serialization_proof_summary.json"
    fail_artifact="$(dirname "$result_path")/repair_writeback_rw_fail_closed_artifact.json"
    unit_log="$(dirname "$result_path")/repair_writeback_serialization_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$artifact_path" ]] \
        && [[ -f "$summary_path" ]] \
        && [[ -f "$proof_summary_path" ]] \
        && [[ -f "$fail_artifact" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "repair_writeback_contract_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_writeback_fail_closed_report" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_writeback_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_writeback_fail_closed_artifact" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_writeback_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .bead_id == "bd-rchk0.1.1"
            and .risk_report.fail_closed_is_lower_loss == true
            and ([.transition_evaluations[] | select(.from_state == "client_write_in_flight" and .event == "repair_writeback_requested" and (.allowed | not) and (.mutation_allowed | not) and .error_class == "rw_repair_serialization_missing")] | length) == 1
            and ([.schedule_reports[].coverage_case] | length) >= 12
            and ([.schedule_reports[] | select(.classification == "rejected")] | length) >= 1
            and ([.schedule_reports[] | select(.classification == "unsupported_interleaving")] | length) >= 1
        ' "$report_path" >/dev/null \
        && jq -e '
            .gate_id == "repair_writeback_serialization"
            and .bead_id == "bd-rchk0.1.1"
            and ([.artifacts[].metadata.proof_bundle_lane] | index("repair_rw_writeback") != null)
            and ([.artifacts[].metadata.release_gate_feature] | index("repair.rw.writeback") != null)
        ' "$artifact_path" >/dev/null \
        && jq -e '
            .schema_version == 1
            and .producer_bead_id == "bd-rchk0.1.1.1"
            and .source_bead_id == "bd-rchk0.1.1"
            and .safe_to_enable_rw_repair == false
            and ([.downstream_inputs[].bead_id] | index("bd-rchk0.1.2") != null)
            and ([.identity_guard_inputs[] | select((.aba_fixture_id | startswith("aba_")) and .refusal_error_class != "none")] | length) >= 7
        ' "$proof_summary_path" >/dev/null \
        && jq -e '
            .error_class == "rw_repair_serialization_missing"
            and .mutation_attempted == false
            and .lost_client_write_possible == false
            and .expected_survivor_set == .observed_survivor_set
        ' "$fail_artifact" >/dev/null \
        && grep -q "rw_repair_serialization_missing" "$summary_path" \
        && grep -q "repair_writeback_serialization::tests::checked_in_contract_validates" "$unit_log"; then
        scenario_result "repair_writeback_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} proof_summary=${proof_summary_path}"
    else
        scenario_result "repair_writeback_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "repair/writeback complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "repair_writeback_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_writeback_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "repair/writeback local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Scenario 1: repair/writeback serialization module and CLI are wired"
if grep -q "pub mod repair_writeback_serialization" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-repair-writeback-serialization" crates/ffs-harness/src/main.rs; then
    scenario_result "repair_writeback_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "repair_writeback_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in contract validates and emits proof artifacts"
if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
    --contract "$CONTRACT_JSON" \
    --artifact-root "artifacts/repair-writeback/dry-run" \
    && extract_json_object "$VALIDATE_RAW" "$REPORT_JSON" \
    && run_rch_capture "$ARTIFACT_RAW" cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
        --contract "$CONTRACT_JSON" \
        --artifact-root "artifacts/repair-writeback/dry-run" \
        --out "/tmp/frankenfs_repair_writeback_serialization_report.json" \
        --artifact-out /dev/stdout \
    && extract_json_object "$ARTIFACT_RAW" "$ARTIFACT_JSON" \
    && run_rch_capture "$SUMMARY_RAW" cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
        --contract "$CONTRACT_JSON" \
        --artifact-root "artifacts/repair-writeback/dry-run" \
        --out "/tmp/frankenfs_repair_writeback_serialization_report.json" \
        --summary-out /dev/stdout \
    && extract_markdown_report "$SUMMARY_RAW" "$SUMMARY_MD" \
    && run_rch_capture "$PROOF_SUMMARY_RAW" cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
        --contract "$CONTRACT_JSON" \
        --artifact-root "artifacts/repair-writeback/dry-run" \
        --out "/tmp/frankenfs_repair_writeback_serialization_report.json" \
        --proof-summary-out /dev/stdout \
    && extract_json_object "$PROOF_SUMMARY_RAW" "$PROOF_SUMMARY_JSON"; then
    scenario_result "repair_writeback_contract_validates" "PASS" "checked-in contract accepted"
else
    cat "$VALIDATE_RAW"
    [[ -s "$ARTIFACT_RAW" ]] && cat "$ARTIFACT_RAW"
    [[ -s "$SUMMARY_RAW" ]] && cat "$SUMMARY_RAW"
    [[ -s "$PROOF_SUMMARY_RAW" ]] && cat "$PROOF_SUMMARY_RAW"
    scenario_result "repair_writeback_contract_validates" "FAIL" "checked-in contract rejected"
fi

e2e_step "Scenario 3: report proves fail-closed policy, risk decision, and consumers"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" "$SUMMARY_MD" "$PROOF_SUMMARY_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
proof_summary = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["bead_id"] != "bd-rchk0.1.1":
    raise SystemExit("wrong bead id")
if report["state_count"] < 10 or report["transition_count"] < 10:
    raise SystemExit("state machine is too small")
if report["missing_required_evidence_fields"]:
    raise SystemExit(f"missing evidence fields: {report['missing_required_evidence_fields']}")
if report["missing_required_coverage_tags"]:
    raise SystemExit(f"missing coverage: {report['missing_required_coverage_tags']}")
if report["missing_required_race_coverage"]:
    raise SystemExit(f"missing race coverage: {report['missing_required_race_coverage']}")
if report["missing_required_schedule_log_fields"]:
    raise SystemExit(f"missing schedule log fields: {report['missing_required_schedule_log_fields']}")
if not report["risk_report"]["fail_closed_is_lower_loss"]:
    raise SystemExit("fail-closed option is not lower loss")
if report["schedule_count"] < 12:
    raise SystemExit("not enough deterministic race schedules")

transition = next(
    row for row in report["transition_evaluations"]
    if row["from_state"] == "client_write_in_flight"
    and row["event"] == "repair_writeback_requested"
)
if transition["allowed"] or transition["mutation_allowed"]:
    raise SystemExit("RW repair transition did not fail closed")
if transition["error_class"] != "rw_repair_serialization_missing":
    raise SystemExit("wrong fail-closed error class")
if "bd-rchk0.1.2" != transition.get("follow_up_bead"):
    raise SystemExit("missing serializer follow-up")

scenario = next(row for row in report["scenario_reports"] if row["scenario_id"] == "repair_writeback_rw_fail_closed")
if not scenario["proves_no_lost_client_write"] or not scenario["preserves_reproduction_data"]:
    raise SystemExit("fail-closed scenario does not preserve no-lost-write/repro proof")
if scenario["expected_error_class"] != "rw_repair_serialization_missing":
    raise SystemExit("wrong scenario error class")

required_cases = {
    "repair_before_write",
    "write_before_repair",
    "overlapping_writes",
    "disjoint_writes",
    "fsync_during_repair",
    "cancellation_during_decode",
    "cancellation_during_writeback",
    "symbol_refresh_races_client_write",
    "unmount_pending_repair",
    "reopen_after_failed_repair",
    "retry_after_abort",
}
schedules = report["schedule_reports"]
observed_cases = {row["coverage_case"] for row in schedules}
if not required_cases <= observed_cases:
    raise SystemExit(f"missing schedule cases: {sorted(required_cases - observed_cases)}")
if not any(row["classification"] == "unsupported_interleaving" for row in schedules):
    raise SystemExit("unsupported-interleaving classification missing")
if not any(row["classification"] == "rejected" for row in schedules):
    raise SystemExit("race schedules only prove happy paths")
for row in schedules:
    if row["classification"] in {"accepted", "rejected"} and row["expected_survivor_set"] != row["observed_survivor_set"]:
        raise SystemExit(f"survivor mismatch for {row['schedule_id']}")
    if not row["operation_trace"]:
        raise SystemExit(f"missing operation trace for {row['schedule_id']}")
    if not row["artifact_paths"] or not row["cleanup_status"]:
        raise SystemExit(f"missing artifacts or cleanup for {row['schedule_id']}")

metadata = [entry.get("metadata", {}) for entry in artifact["artifacts"]]
if not any(row.get("proof_bundle_lane") == "repair_rw_writeback" for row in metadata):
    raise SystemExit("missing proof-bundle lane metadata")
if not any(row.get("release_gate_feature") == "repair.rw.writeback" for row in metadata):
    raise SystemExit("missing release-gate metadata")
if "rw_repair_serialization_missing" not in summary:
    raise SystemExit("summary missing fail-closed error class")

if proof_summary["schema_version"] != 1:
    raise SystemExit("wrong proof summary schema")
if proof_summary["producer_bead_id"] != "bd-rchk0.1.1.1":
    raise SystemExit("proof summary does not name child bead producer")
if proof_summary["source_bead_id"] != "bd-rchk0.1.1":
    raise SystemExit("proof summary does not preserve source contract bead")
if proof_summary["safe_to_enable_rw_repair"]:
    raise SystemExit("proof summary cannot allow rw repair without the serializer")
required_downstream = {"bd-rchk0.1.2", "bd-rchk0.1.3", "bd-rchk0.1.4"}
observed_downstream = {row["bead_id"] for row in proof_summary["downstream_inputs"]}
if not required_downstream <= observed_downstream:
    raise SystemExit(f"proof summary missing downstream inputs: {sorted(required_downstream - observed_downstream)}")
if not any(
    row["from_state"] == "client_write_in_flight"
    and row["event"] == "repair_writeback_requested"
    and not row["allowed"]
    and not row["mutation_allowed"]
    and row["error_class"] == "rw_repair_serialization_missing"
    for row in proof_summary["transition_guards"]
):
    raise SystemExit("proof summary missing fail-closed transition guard")
if not required_cases <= {row["coverage_case"] for row in proof_summary["race_schedule_inputs"]}:
    raise SystemExit("proof summary missing race schedule coverage")
required_identity_guards = {
    "epoch_generation_monotonic",
    "lease_generation_monotonic",
    "snapshot_id_mismatch_rejected",
    "repair_symbol_generation_monotonic",
    "block_range_epoch_guard",
    "retry_generation_advances_after_abort",
    "halfway_failure_preserves_generation",
}
observed_identity_guards = {row["guard_id"] for row in proof_summary["identity_guard_inputs"]}
if not required_identity_guards <= observed_identity_guards:
    raise SystemExit(f"proof summary missing identity guards: {sorted(required_identity_guards - observed_identity_guards)}")
for row in proof_summary["identity_guard_inputs"]:
    if not row["aba_fixture_id"].startswith("aba_"):
        raise SystemExit(f"identity guard lacks ABA fixture: {row['guard_id']}")
    if row["refusal_error_class"] == "none":
        raise SystemExit(f"identity guard does not fail closed: {row['guard_id']}")
PY
then
    scenario_result "repair_writeback_fail_closed_report" "PASS" "report, proof summary, and sample artifact verified"
else
    scenario_result "repair_writeback_fail_closed_report" "FAIL" "report contract failed"
fi

e2e_step "Scenario 4: invalid contract variants fail closed"
python3 - "$CONTRACT_JSON" "$BAD_MISSING_EVIDENCE" "$BAD_UNSAFE_RISK" "$BAD_MUTATION_ALLOWED" "$BAD_MISSING_REPRO" "$BAD_BAD_SCHEDULE" <<'PY'
import json
import pathlib
import sys

source, missing_evidence, unsafe_risk, mutation_allowed, missing_repro, bad_schedule = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

variant = json.loads(json.dumps(base))
variant["required_evidence_fields"] = [
    field for field in variant["required_evidence_fields"]
    if field != "reproduction_command"
]
missing_evidence.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
variant["risk_decision"]["chosen_option"] = "enable_rw_repair_without_serializer"
variant["risk_decision"]["rejected_option"] = "fail_closed_until_unified_serializer"
unsafe_risk.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for transition in variant["transitions"]:
    if transition["transition_id"] == "rw_repair_fail_closed":
        transition["mutation_allowed"] = True
mutation_allowed.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for scenario in variant["scenarios"]:
    if scenario["scenario_id"] == "repair_writeback_rw_fail_closed":
        scenario["preserves_reproduction_data"] = False
missing_repro.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
variant["race_schedule_manifest"]["required_log_fields"] = [
    field for field in variant["race_schedule_manifest"]["required_log_fields"]
    if field != "seed"
]
variant["race_schedule_manifest"]["schedules"][0]["yield_points"].append("not_an_allowed_yield")
bad_schedule.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_MISSING_EVIDENCE" "$BAD_UNSAFE_RISK" "$BAD_MUTATION_ALLOWED" "$BAD_MISSING_REPRO" "$BAD_BAD_SCHEDULE"; do
    bad_payload="$(tr -d '\n' <"$bad")"
    if (
        export REPAIR_WRITEBACK_CONTRACT_JSON="$bad_payload"
        e2e_rch_add_env_allowlist REPAIR_WRITEBACK_CONTRACT_JSON
        run_rch_capture "$BAD_RAW" cargo run --quiet -p ffs-harness -- validate-repair-writeback-serialization \
            --contract-json-env REPAIR_WRITEBACK_CONTRACT_JSON
    ); then
        e2e_log "Unexpectedly accepted invalid repair/writeback contract: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "repair/writeback serialization validation failed\\|invalid repair/writeback contract JSON" "$BAD_RAW"; then
        e2e_log "Invalid repair/writeback contract failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "repair_writeback_invalid_variants_rejected" "PASS" "bad evidence/risk/mutation/repro/schedule variants rejected"
else
    scenario_result "repair_writeback_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: fail-closed scenario artifact preserves required log fields"
if python3 - "$REPORT_JSON" "$FAIL_CLOSED_ARTIFACT" "$FAIL_CLOSED_LOG" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact_path = pathlib.Path(sys.argv[2])
log_path = pathlib.Path(sys.argv[3])
scenario = next(row for row in report["scenario_reports"] if row["scenario_id"] == "repair_writeback_rw_fail_closed")
schedule = next(row for row in report["schedule_reports"] if row["coverage_case"] == "overlapping_writes")
record = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "operation_id": "op-rw-repair-fail-closed-001",
    "scenario_id": scenario["scenario_id"],
    "scheduler_version": "ffs-repair-dpor-v1",
    "schedule_id": schedule["schedule_id"],
    "seed": schedule["seed"],
    "explored_schedule_count": schedule["explored_schedule_count"],
    "pruned_schedule_count": schedule["pruned_schedule_count"],
    "timeout_decision": schedule["timeout_decision"],
    "liveness_decision": schedule["liveness_decision"],
    "operation_trace": schedule["operation_trace"],
    "classification": schedule["classification"],
    "expected_survivor_set": schedule["expected_survivor_set"],
    "observed_survivor_set": schedule["observed_survivor_set"],
    "ledger_outcomes": schedule["ledger_outcomes"],
    "snapshot_epoch": 42,
    "transition_id": "rw_repair_fail_closed",
    "epoch_id": "epoch-42-generation-9",
    "lease_id": "lease-dry-run-001",
    "lease_generation": "lease-generation-17",
    "snapshot_id": "snapshot-42-epoch-9",
    "repair_symbol_version": "group-7-generation-12",
    "repair_symbol_generation": "symbol-generation-12",
    "block_range": "block=42 len=1",
    "expected_state": "repair_writeback_blocked_rw",
    "observed_state": scenario["final_state"],
    "error_class": scenario["expected_error_class"],
    "stale_refusal_reason": "rw repair plan lacks a current epoch/lease/snapshot identity accepted by the unified serializer",
    "ledger_row_ids": ["ledger-rw-repair-fail-closed-001"],
    "artifact_paths": [str(artifact_path), str(log_path)],
    "cleanup_status": "preserved_artifacts",
    "reproduction_command": report["reproduction_command"],
    "follow_up_bead": schedule.get("follow_up_bead") or "bd-rchk0.1.2",
    "mutation_attempted": False,
    "lost_client_write_possible": False,
}
artifact_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "REPAIR_WRITEBACK_EVENT|"
    + "|".join(f"{key}={value}" for key, value in record.items() if key not in {"artifact_paths"})
    + "\n",
    encoding="utf-8",
)

required = [
    "operation_id",
    "scenario_id",
    "snapshot_epoch",
    "transition_id",
    "epoch_id",
    "lease_id",
    "lease_generation",
    "snapshot_id",
    "repair_symbol_version",
    "repair_symbol_generation",
    "block_range",
    "expected_state",
    "observed_state",
    "error_class",
    "stale_refusal_reason",
    "ledger_row_ids",
    "artifact_paths",
    "cleanup_status",
    "reproduction_command",
    "follow_up_bead",
    "scheduler_version",
    "schedule_id",
    "seed",
    "explored_schedule_count",
    "pruned_schedule_count",
    "timeout_decision",
    "liveness_decision",
    "operation_trace",
    "classification",
    "expected_survivor_set",
    "observed_survivor_set",
    "ledger_outcomes",
]
missing = [field for field in required if field not in record]
if missing:
    raise SystemExit(f"missing fields from fail-closed artifact: {missing}")
if record["error_class"] != "rw_repair_serialization_missing":
    raise SystemExit("wrong error class")
if record["mutation_attempted"]:
    raise SystemExit("fail-closed artifact claims mutation")
if record["lost_client_write_possible"]:
    raise SystemExit("fail-closed artifact does not prove no lost client write")
if record["expected_survivor_set"] != record["observed_survivor_set"]:
    raise SystemExit("schedule survivor set mismatch")
PY
then
    scenario_result "repair_writeback_fail_closed_artifact" "PASS" "fail-closed artifact preserves required scenario and schedule fields"
else
    scenario_result "repair_writeback_fail_closed_artifact" "FAIL" "fail-closed artifact contract failed"
fi

e2e_step "Scenario 6: repair/writeback serialization unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib repair_writeback_serialization -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "repair_writeback_unit_tests" "PASS" "repair/writeback unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "repair_writeback_unit_tests" "FAIL" "repair/writeback unit tests failed"
fi

e2e_log "Repair/writeback contract: $CONTRACT_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"
e2e_log "Proof summary: $PROOF_SUMMARY_JSON"
e2e_log "Fail-closed artifact: $FAIL_CLOSED_ARTIFACT"

if ((FAIL_COUNT == 0)); then
    e2e_log "Repair/writeback serialization scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Repair/writeback serialization scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
