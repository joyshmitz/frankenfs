#!/usr/bin/env bash
# ffs_readiness_dashboard_e2e.sh - read-only operator readiness dashboard smoke.
#
# Builds synthetic validator reports, renders JSON and Markdown dashboards, and
# proves recommendations link back to validator reports or tracker beads.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd -P)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_readiness_dashboard}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"
RCH_CAPTURE_VISIBILITY="${FFS_READINESS_DASHBOARD_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_READINESS_DASHBOARD_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_READINESS_DASHBOARD_SKIP_SELF_CHECK:-0}"

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
    local output_path="$1"
    shift
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
        return 99
    fi
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_READINESS_DASHBOARD_FIXTURE_CASE:-complete}"

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
        echo "[RCH] remote worker=fixture exit=0" >&2
        echo "Remote command finished: exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown readiness dashboard fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo run --quiet -p ffs-harness -- readiness-dashboard"*"--format markdown"*)
        cat <<'MD'
# FrankenFS Operator Readiness Dashboard

- release_gate:xfstests.baseline hidden validator=release_gate_report.json bead=bd-rchk3.3
- permissioned:swarm-large-host handoff_only validator=permissioned_campaign_report.json
- readiness_lab:readiness_lab_host_simulation:dashboard-host-simulation advisory_only validator=readiness_lab_host_simulation.json
- Tracker Follow-Up Beads: bd-rchk3.3 bd-4v16z.10
MD
        ;;
    *"cargo run --quiet -p ffs-harness -- readiness-dashboard"*)
        cat <<'JSON'
{
  "claims": [
    {
      "claim_id": "release_gate:mount.rw.ext4",
      "claim_state": "validated",
      "evidence_basis": [
        "release_gate"
      ],
      "remediation_bead": "bd-4v16z.10",
      "validator_report": "release_gate_report.json"
    },
    {
      "claim_id": "release_gate:xfstests.baseline",
      "claim_state": "hidden",
      "controlling_lane": "xfstests",
      "evidence_basis": [
        "release_gate"
      ],
      "next_safe_command": "br show bd-rchk3.3 --no-db --json",
      "remediation_bead": "bd-rchk3.3",
      "validator_report": "release_gate_report.json"
    },
    {
      "claim_id": "permissioned:swarm-large-host",
      "claim_state": "handoff_only",
      "evidence_basis": [
        "permissioned_campaign"
      ],
      "remediation_bead": "bd-4v16z.10",
      "validator_report": "permissioned_campaign_report.json"
    },
    {
      "claim_id": "proof_bundle:dashboard-proof-bundle:missing:xfstests",
      "claim_state": "blocked",
      "evidence_basis": [
        "proof_bundle"
      ],
      "remediation_bead": "bd-4v16z.10",
      "validator_report": "proof_bundle_report.json"
    },
    {
      "claim_id": "operational_evidence:swarm_tail_latency:tail_latency",
      "claim_state": "validated",
      "evidence_basis": [
        "operational_evidence"
      ],
      "remediation_bead": "bd-4v16z.10",
      "validator_report": "operational_evidence_index.json"
    },
    {
      "claim_id": "readiness_lab:readiness_lab_host_simulation:dashboard-host-simulation",
      "claim_state": "advisory_only",
      "evidence_basis": [
        "product_evidence_claim:none"
      ],
      "remediation_bead": "bd-919xg",
      "validator_report": "readiness_lab_host_simulation.json"
    },
    {
      "claim_id": "readiness_lab:readiness_lab_rch_schedule:dashboard-rch-plan",
      "claim_state": "advisory_only",
      "evidence_basis": [
        "product_evidence_claim:none"
      ],
      "remediation_bead": "bd-919xg",
      "validator_report": "readiness_lab_rch_schedule.json"
    },
    {
      "claim_id": "readiness_lab:readiness_lab_truth_graph:dashboard-truth-graph",
      "claim_state": "advisory_only",
      "evidence_basis": [
        "product_evidence_claim:none"
      ],
      "remediation_bead": "bd-919xg",
      "validator_report": "readiness_lab_truth_graph.json"
    },
    {
      "claim_id": "readiness_lab:readiness_lab_replay:dashboard-numa-p99",
      "claim_state": "advisory_only",
      "evidence_basis": [
        "product_evidence_claim:none"
      ],
      "remediation_bead": "bd-919xg",
      "validator_report": "readiness_lab_numa_p99_replay.json"
    }
  ],
  "dashboard_id": "frankenfs-readiness-dashboard:v1",
  "recommendations": [
    {
      "claim_id": "release_gate:xfstests.baseline",
      "validator_report": "release_gate_report.json"
    },
    {
      "claim_id": "readiness_lab:readiness_lab_host_simulation:dashboard-host-simulation",
      "validator_report": "readiness_lab_host_simulation.json"
    },
    {
      "bead_id": "bd-4v16z.10",
      "claim_id": "proof_bundle:dashboard-proof-bundle:missing:xfstests"
    }
  ],
  "release_ready": false,
  "source_report_count": 8,
  "tracker_follow_up_beads": [
    {
      "issue_id": "bd-4v16z.10"
    },
    {
      "issue_id": "bd-rchk3.3"
    }
  ]
}
JSON
        ;;
    *"cargo test -p ffs-harness --lib readiness_dashboard"*)
        printf '%s\n' \
            "running 5 tests" \
            "test readiness_dashboard::tests::fixture_claim_states ... ok" \
            "test readiness_dashboard::tests::fixture_advisory_links ... ok" \
            "test readiness_dashboard::tests::fixture_tracker_followups ... ok" \
            "test readiness_dashboard::tests::fixture_markdown_markers ... ok" \
            "test readiness_dashboard::tests::fixture_release_not_ready ... ok" \
            "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
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
    local child_log="$E2E_LOG_DIR/readiness_dashboard_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_READINESS_DASHBOARD_SELF_CHECK=0 \
        FFS_READINESS_DASHBOARD_SKIP_SELF_CHECK=1 \
        FFS_READINESS_DASHBOARD_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_readiness_dashboard_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic readiness dashboard wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-readiness-dashboard-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "readiness_dashboard_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_dashboard_fixtures_written" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_dashboard_json" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_dashboard_markdown" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "readiness_dashboard_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "readiness_dashboard_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "readiness_dashboard_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "readiness_dashboard_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "readiness_dashboard_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "readiness_dashboard_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "readiness_dashboard_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

extract_dashboard_json() {
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
noise_prefixes = (
    "readiness dashboard written:",
    "readiness dashboard summary written:",
    "Remote command finished:",
)
text = "\n".join(
    line for line in text.splitlines() if not line.startswith(noise_prefixes)
) + "\n"
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and obj.get("dashboard_id") == "frankenfs-readiness-dashboard:v1":
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("readiness dashboard JSON output not found")
PY
}

extract_dashboard_markdown() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# FrankenFS Operator Readiness Dashboard")
if start < 0:
    raise SystemExit("readiness dashboard markdown output not found")
end = text.find("\nreadiness dashboard written:", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
pathlib.Path(report_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_readiness_dashboard"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

FIXTURE_DIR="$REPO_ROOT/artifacts/rch_e2e/$(basename "$E2E_LOG_DIR")/readiness_dashboard_fixture"
REPORT_DIR="$E2E_LOG_DIR/readiness_dashboard_reports"
RAW_JSON="$E2E_LOG_DIR/readiness_dashboard_json_command.log"
RAW_MD="$E2E_LOG_DIR/readiness_dashboard_markdown_command.log"
UNIT_LOG="$E2E_LOG_DIR/readiness_dashboard_unit_tests.log"
DASHBOARD_JSON="$REPORT_DIR/dashboard.json"
DASHBOARD_MD="$REPORT_DIR/dashboard.md"

PROOF_REPORT="$FIXTURE_DIR/proof_bundle_report.json"
RELEASE_REPORT="$FIXTURE_DIR/release_gate_report.json"
EVIDENCE_INDEX="$FIXTURE_DIR/operational_evidence_index.json"
PERMISSIONED_REPORT="$FIXTURE_DIR/permissioned_campaign_report.json"
LAB_HOST_REPORT="$FIXTURE_DIR/readiness_lab_host_simulation.json"
LAB_SCHEDULE_REPORT="$FIXTURE_DIR/readiness_lab_rch_schedule.json"
LAB_TRUTH_REPORT="$FIXTURE_DIR/readiness_lab_truth_graph.json"
LAB_REPLAY_REPORT="$FIXTURE_DIR/readiness_lab_numa_p99_replay.json"
BEADS_FILE="$FIXTURE_DIR/issues.jsonl"

mkdir -p "$FIXTURE_DIR" "$REPORT_DIR"

e2e_step "Scenario 1: CLI and module wiring are present"
if grep -q 'Some("readiness-dashboard")' crates/ffs-harness/src/main.rs \
    && grep -q "pub mod readiness_dashboard" crates/ffs-harness/src/lib.rs; then
    scenario_result "readiness_dashboard_cli_wired" "PASS" "CLI command and module export found"
else
    scenario_result "readiness_dashboard_cli_wired" "FAIL" "missing readiness dashboard command wiring"
fi

e2e_step "Scenario 2: synthetic validator and advisory lab reports are written"
if python3 - "$PROOF_REPORT" "$RELEASE_REPORT" "$EVIDENCE_INDEX" "$PERMISSIONED_REPORT" "$LAB_HOST_REPORT" "$LAB_SCHEDULE_REPORT" "$LAB_TRUTH_REPORT" "$LAB_REPLAY_REPORT" "$BEADS_FILE" <<'PY'
import json
import pathlib
import sys

(
    proof_report,
    release_report,
    evidence_index,
    permissioned_report,
    lab_host_report,
    lab_schedule_report,
    lab_truth_report,
    lab_replay_report,
    beads_file,
) = map(pathlib.Path, sys.argv[1:])
for path in [
    proof_report,
    release_report,
    evidence_index,
    permissioned_report,
    lab_host_report,
    lab_schedule_report,
    lab_truth_report,
    lab_replay_report,
    beads_file,
]:
    path.parent.mkdir(parents=True, exist_ok=True)

proof_report.write_text(json.dumps({
    "schema_version": 1,
    "bundle_id": "dashboard-proof-bundle",
    "manifest_path": "fixtures/proof/manifest.json",
    "valid": False,
    "totals": {"pass": 1, "fail": 0, "skip": 0, "error": 0, "lanes": 1, "scenarios": 1, "artifacts": 1},
    "missing_required_lanes": ["xfstests"],
    "duplicate_lane_ids": [],
    "duplicate_scenario_ids": [],
    "stale_git_sha": None,
    "stale_timestamp": None,
    "broken_links": [
        {"lane_id": "xfstests", "field": "raw_log_path", "path": "logs/xfstests.log", "diagnostic": "missing"}
    ],
    "raw_log_hash_mismatches": [],
    "artifact_hash_mismatches": [],
    "artifact_hash_chain": None,
    "artifact_reports": [],
    "redaction_errors": [],
    "redaction_leaks": [],
    "integrity_errors": [],
    "lanes": [
        {"lane_id": "conformance", "status": "pass", "raw_log_path": "logs/conformance.log", "summary_path": "summaries/conformance.md", "scenario_count": 1, "artifact_count": 1, "metadata": {}}
    ],
    "lane_provenance": [
        {
            "lane_id": "conformance",
            "status": "pass",
            "provenance_class": "executed_product_evidence",
            "claim_effect": "strengthens_public_claim",
            "artifact_roles": ["validator_report"],
            "source_command": "cargo run -p ffs-harness -- validate-proof-bundle --bundle fixtures/proof/manifest.json",
            "git_sha": "fixture",
            "freshness": "fresh",
            "host_class": "permissioned_large_host",
            "raw_log_path": "logs/conformance.log",
            "raw_log_present": True,
            "rationale": "synthetic executed evidence"
        }
    ],
    "swarm_evidence": [],
    "adaptive_runtime_evidence": [],
    "errors": ["missing required lane xfstests"],
    "warnings": [],
    "reproduction_command": "cargo run -p ffs-harness -- validate-proof-bundle --bundle fixtures/proof/manifest.json"
}, indent=2) + "\n", encoding="utf-8")

release_report.write_text(json.dumps({
    "schema_version": 1,
    "policy_id": "dashboard-release-policy",
    "bundle_id": "dashboard-proof-bundle",
    "valid": True,
    "release_ready": False,
    "proof_bundle_valid": True,
    "feature_reports": [
        {"feature_id": "mount.rw.ext4", "docs_wording_id": "docs-mount", "previous_state": "experimental", "target_state": "validated", "final_state": "validated", "upgrade_allowed": True, "finding_ids": []},
        {"feature_id": "xfstests.baseline", "docs_wording_id": "docs-xfstests", "previous_state": "hidden", "target_state": "validated", "final_state": "hidden", "upgrade_allowed": False, "finding_ids": ["missing-xfstests"]}
    ],
    "findings": [
        {
            "finding_id": "missing-xfstests",
            "feature_id": "xfstests.baseline",
            "severity": "block",
            "previous_state": "hidden",
            "proposed_state": "validated",
            "final_state": "hidden",
            "transition_reason": "fresh permissioned xfstests baseline proof lane is missing",
            "controlling_lane": "xfstests",
            "remediation_id": "bd-rchk3.3",
            "docs_wording_id": "docs-xfstests",
            "reproduction_command": "cargo run -p ffs-harness -- evaluate-release-gates --bundle fixtures/proof/manifest.json --policy fixtures/release/policy.json"
        }
    ],
    "generated_wording": [],
    "required_log_fields": [],
    "errors": [],
    "warnings": [],
    "reproduction_command": "cargo run -p ffs-harness -- evaluate-release-gates --bundle fixtures/proof/manifest.json --policy fixtures/release/policy.json"
}, indent=2) + "\n", encoding="utf-8")

evidence_index.write_text(json.dumps({
    "schema_version": 1,
    "index_id": "operational-evidence-index:dashboard",
    "source_root": "fixtures/e2e",
    "readiness_report_id": "dashboard-readiness",
    "source_record_count": 1,
    "selected_record_count": 1,
    "authoritative_record_count": 1,
    "stale_record_count": 0,
    "missing_raw_log_record_count": 0,
    "conflict_count": 0,
    "duplicate_run_id_count": 0,
    "host_downgrade_count": 0,
    "records": [
        {
            "record_id": "swarm:tail_latency:bd-rchk0.53.8:run-a:0",
            "lane_id": "swarm_tail_latency",
            "scenario_id": "tail_latency",
            "bead_id": "bd-rchk0.53.8",
            "git_sha": "fixture",
            "run_id": "run-a",
            "gate_id": "gate-a",
            "source_path": "artifacts/e2e/swarm_tail_latency.json",
            "source_kind": "artifact_manifest",
            "host_class": "permissioned_large_host",
            "freshness": "fresh",
            "outcome": "pass",
            "taxonomy_class": "product_pass",
            "release_claim_effect": "strengthens",
            "raw_log_paths": ["logs/swarm.log"],
            "artifact_refs": ["swarm_tail_latency.json"],
            "missing_raw_logs": False,
            "authoritative": True,
            "selected": True,
            "stale_git_sha": False,
            "stale_artifact": False,
            "reproduction_command": "cargo run -p ffs-harness -- operational-evidence-index --artifacts artifacts/e2e",
            "cleanup_status": "clean",
            "remediation_hint": None,
            "detail": "synthetic latest truth"
        }
    ],
    "selections": [
        {"lane_id": "swarm_tail_latency", "scenario_id": "tail_latency", "bead_id": "bd-rchk0.53.8", "selected_record_id": "swarm:tail_latency:bd-rchk0.53.8:run-a:0", "selected_run_id": "run-a", "selected_source_path": "artifacts/e2e/swarm_tail_latency.json", "selected_outcome": "pass", "selected_release_claim_effect": "strengthens", "superseded_record_ids": []}
    ],
    "conflicts": [],
    "duplicate_run_ids": []
}, indent=2) + "\n", encoding="utf-8")

permissioned_report.write_text(json.dumps({
    "schema_version": 1,
    "campaign_id": "swarm-large-host",
    "lane_kind": "swarm.responsiveness",
    "valid": True,
    "packet_status": "ready_for_operator_approval",
    "product_evidence_claim": "none",
    "target_beads": ["bd-rchk0.53.8"],
    "required_executed_evidence": ["raw workload logs", "p99 attribution ledger", "proof-bundle swarm lanes", "release-gate output"],
    "expected_artifact_paths": ["artifacts/permissioned/swarm/report.json"],
    "host_facts": [{"fact_id": "host_class", "observed_value": "permissioned_large_host_candidate", "required_value": "permissioned_large_host", "proof_path": "host.json"}]
}, indent=2) + "\n", encoding="utf-8")

lab_host_report.write_text(json.dumps({
    "schema_version": 1,
    "simulation_id": "dashboard-host-simulation",
    "valid": True,
    "product_evidence_claim": "none",
    "release_gate_effect": "advisory host simulation only; public readiness unchanged",
    "source_bead": "bd-919xg",
    "real_campaign_bead": "bd-c7fqh",
    "host_count": 2,
    "candidate_count": 1,
    "blocked_count": 0,
    "rows": [
        {
            "host_id": "large-host-a",
            "valid": True,
            "classification": "permissioned_large_host_candidate",
            "candidate_for_authorized_run": True,
            "product_evidence_claim": "none",
            "source_bead": "bd-919xg"
        }
    ],
    "errors": [],
    "warnings": []
}, indent=2) + "\n", encoding="utf-8")

lab_schedule_report.write_text(json.dumps({
    "schema_version": 1,
    "plan_id": "dashboard-rch-plan",
    "valid": True,
    "dry_run_only": True,
    "product_evidence_claim": "none",
    "release_gate_effect": "rehearsal schedule only; public readiness unchanged",
    "source_bead": "bd-919xg",
    "lane_count": 2,
    "planned_lane_count": 2,
    "rows": [
        {
            "lane_id": "xfstests",
            "valid": True,
            "product_evidence_claim": "none",
            "source_bead": "bd-919xg"
        }
    ],
    "errors": [],
    "warnings": []
}, indent=2) + "\n", encoding="utf-8")

lab_truth_report.write_text(json.dumps({
    "schema_version": 1,
    "graph_id": "dashboard-truth-graph",
    "valid": True,
    "product_evidence_claim": "none",
    "source_bead": "bd-919xg",
    "source_count": 2,
    "claim_count": 2,
    "node_count": 2,
    "edge_count": 1,
    "stale_claim_count": 0,
    "contradictory_claim_count": 0,
    "nodes": [
        {"node_id": "bead:bd-919xg", "bead_id": "bd-919xg", "product_evidence_claim": None},
        {"node_id": "claim:advisory", "bead_id": "bd-919xg", "product_evidence_claim": "none"}
    ],
    "edges": [
        {"from_node_id": "bead:bd-919xg", "to_node_id": "claim:advisory", "bead_id": "bd-919xg", "validator_report_path": "readiness_lab_truth_graph.json"}
    ],
    "errors": [],
    "warnings": []
}, indent=2) + "\n", encoding="utf-8")

lab_replay_report.write_text(json.dumps({
    "schema_version": 1,
    "replay_id": "dashboard-numa-p99",
    "valid": True,
    "product_evidence_claim": "none",
    "release_gate_effect": "replay fixture is advisory only; public readiness unchanged",
    "source_bead": "bd-919xg",
    "fixture_count": 1,
    "stale_artifact_count": 0,
    "rows": [
        {
            "fixture_id": "balanced-numa",
            "valid": True,
            "product_evidence_claim": "none",
            "source_bead": "bd-919xg"
        }
    ],
    "errors": [],
    "warnings": []
}, indent=2) + "\n", encoding="utf-8")

beads_file.write_text(
    "\n".join([
        json.dumps({"id": "bd-4v16z.10", "title": "Build operator readiness dashboard over proof and evidence state", "status": "in_progress", "priority": 3}),
        json.dumps({"id": "bd-rchk3.3", "title": "Execute the fresh xfstests baseline and publish artifacts", "status": "open", "priority": 1}),
        json.dumps({"id": "br-r37-c1", "title": "Foreign project row", "status": "open", "priority": 1}),
    ]) + "\n",
    encoding="utf-8",
)
PY
then
    scenario_result "readiness_dashboard_fixtures_written" "PASS" "synthetic validator, advisory lab, and tracker rows emitted"
else
    scenario_result "readiness_dashboard_fixtures_written" "FAIL" "fixture generation failed"
fi

e2e_step "Scenario 3: JSON dashboard preserves validator-backed states"
if run_rch_capture "$RAW_JSON" cargo run --quiet -p ffs-harness -- readiness-dashboard \
    --proof-bundle-report "$PROOF_REPORT" \
    --release-gate-report "$RELEASE_REPORT" \
    --operational-evidence-index "$EVIDENCE_INDEX" \
    --permissioned-campaign-report "$PERMISSIONED_REPORT" \
    --readiness-lab-report "$LAB_HOST_REPORT" \
    --readiness-lab-report "$LAB_SCHEDULE_REPORT" \
    --readiness-lab-report "$LAB_TRUTH_REPORT" \
    --readiness-lab-report "$LAB_REPLAY_REPORT" \
    --beads "$BEADS_FILE" \
    --default-remediation-bead bd-4v16z.10 \
    --format json \
    && extract_dashboard_json "$RAW_JSON" "$DASHBOARD_JSON" \
    && python3 - "$DASHBOARD_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
if data.get("release_ready") is True:
    raise SystemExit("dashboard must not mark release_ready=true from advisory lab reports")
if data["source_report_count"] != 8:
    raise SystemExit(f"expected eight source reports, got {data['source_report_count']}")
claims = {claim["claim_id"]: claim for claim in data["claims"]}
required = {
    "release_gate:mount.rw.ext4": "validated",
    "release_gate:xfstests.baseline": "hidden",
    "permissioned:swarm-large-host": "handoff_only",
    "proof_bundle:dashboard-proof-bundle:missing:xfstests": "blocked",
    "operational_evidence:swarm_tail_latency:tail_latency": "validated",
    "readiness_lab:readiness_lab_host_simulation:dashboard-host-simulation": "advisory_only",
    "readiness_lab:readiness_lab_rch_schedule:dashboard-rch-plan": "advisory_only",
    "readiness_lab:readiness_lab_truth_graph:dashboard-truth-graph": "advisory_only",
    "readiness_lab:readiness_lab_replay:dashboard-numa-p99": "advisory_only",
}
for claim_id, state in required.items():
    if claims.get(claim_id, {}).get("claim_state") != state:
        raise SystemExit(f"{claim_id} state {claims.get(claim_id)} != {state}")
for claim_id in [claim_id for claim_id in required if claim_id.startswith("readiness_lab:")]:
    claim = claims[claim_id]
    if "product_evidence_claim:none" not in claim["evidence_basis"]:
        raise SystemExit(f"{claim_id} lost explicit non-product evidence basis: {claim}")
    if not claim["validator_report"]:
        raise SystemExit(f"{claim_id} lost validator report path")
    if claim["remediation_bead"] != "bd-919xg":
        raise SystemExit(f"{claim_id} lost advisory source bead: {claim}")
hidden = claims["release_gate:xfstests.baseline"]
if hidden["controlling_lane"] != "xfstests" or hidden["remediation_bead"] != "bd-rchk3.3":
    raise SystemExit(f"release-gate follow-up link lost: {hidden}")
if "br show bd-rchk3.3 --no-db --json" != hidden["next_safe_command"]:
    raise SystemExit(f"unexpected next command: {hidden['next_safe_command']}")
if not all(rec.get("validator_report") or rec.get("bead_id") for rec in data["recommendations"]):
    raise SystemExit("every recommendation must link to a validator report or bead")
for rec in data["recommendations"]:
    if rec["claim_id"].startswith("readiness_lab:") and not (rec.get("validator_report") or rec.get("bead_id")):
        raise SystemExit(f"advisory lab recommendation lacks source link: {rec}")
tracker_ids = {row["issue_id"] for row in data["tracker_follow_up_beads"]}
if "bd-4v16z.10" not in tracker_ids or "bd-rchk3.3" not in tracker_ids:
    raise SystemExit(f"tracker follow-up beads missing: {tracker_ids}")
if "br-r37-c1" in tracker_ids:
    raise SystemExit("foreign tracker row leaked into local follow-up list")
PY
then
    scenario_result "readiness_dashboard_json" "PASS" "JSON dashboard links states to validator reports and beads"
else
    scenario_result "readiness_dashboard_json" "FAIL" "JSON dashboard validation failed"
fi

e2e_step "Scenario 4: Markdown dashboard renders operator view"
if run_rch_capture "$RAW_MD" cargo run --quiet -p ffs-harness -- readiness-dashboard \
    --proof-bundle-report "$PROOF_REPORT" \
    --release-gate-report "$RELEASE_REPORT" \
    --operational-evidence-index "$EVIDENCE_INDEX" \
    --permissioned-campaign-report "$PERMISSIONED_REPORT" \
    --readiness-lab-report "$LAB_HOST_REPORT" \
    --readiness-lab-report "$LAB_SCHEDULE_REPORT" \
    --readiness-lab-report "$LAB_TRUTH_REPORT" \
    --readiness-lab-report "$LAB_REPLAY_REPORT" \
    --beads "$BEADS_FILE" \
    --default-remediation-bead bd-4v16z.10 \
    --format markdown \
    && extract_dashboard_markdown "$RAW_MD" "$DASHBOARD_MD"; then
    if grep -q "FrankenFS Operator Readiness Dashboard" "$DASHBOARD_MD" \
        && grep -q "release_gate:xfstests.baseline" "$DASHBOARD_MD" \
        && grep -q "handoff_only" "$DASHBOARD_MD" \
        && grep -q "readiness_lab:readiness_lab_host_simulation:dashboard-host-simulation" "$DASHBOARD_MD" \
        && grep -q "advisory_only" "$DASHBOARD_MD" \
        && grep -q "validator=" "$DASHBOARD_MD" \
        && grep -q "bd-rchk3.3" "$DASHBOARD_MD" \
        && grep -q "Tracker Follow-Up Beads" "$DASHBOARD_MD"; then
        scenario_result "readiness_dashboard_markdown" "PASS" "Markdown operator view preserves claims, recommendations, and tracker rows"
    else
        scenario_result "readiness_dashboard_markdown" "FAIL" "Markdown content validation failed"
    fi
else
    scenario_result "readiness_dashboard_markdown" "FAIL" "Markdown dashboard command failed"
fi

e2e_step "Scenario 5: unit tests pass"
RCH_TEST_RC=0
run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib readiness_dashboard -- --nocapture || RCH_TEST_RC=$?
TEST_OK_COUNT=$(grep -c "test result: ok" "$UNIT_LOG" 2>/dev/null || true)
TEST_OK_COUNT="${TEST_OK_COUNT:-0}"
if [[ "$RCH_TEST_RC" -eq 0 || "$TEST_OK_COUNT" -ge 1 ]]; then
    TESTS_RUN=$(grep -c "test readiness_dashboard::tests::" "$UNIT_LOG" 2>/dev/null || true)
    TESTS_RUN="${TESTS_RUN:-0}"
    if [[ $TESTS_RUN -ge 5 ]]; then
        scenario_result "readiness_dashboard_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "readiness_dashboard_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "readiness_dashboard_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_readiness_dashboard completed"
else
    e2e_fail "ffs_readiness_dashboard failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
