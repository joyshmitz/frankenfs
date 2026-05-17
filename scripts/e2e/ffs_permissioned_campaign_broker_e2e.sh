#!/usr/bin/env bash
# ffs_permissioned_campaign_broker_e2e.sh - dry-run broker packet gate.
#
# Generates permissioned campaign broker manifests, validates them, renders
# operator handoff packets, and proves blocker artifacts remain non-execution
# evidence. This script never starts xfstests, mounted workloads, or large-host
# swarm workers.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_permissioned_campaign_broker}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_PERMISSIONED_CAMPAIGN_BROKER_RCH_VISIBILITY:-summary}"

REFERENCE_TIMESTAMP="${FFS_PERMISSIONED_BROKER_REFERENCE_TIMESTAMP:-2026-05-07T00:00:00Z}"
GIT_SHA="$(git rev-parse HEAD)"
AGENT_NAME="${AGENT_NAME:-FrostyRobin}"
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

quote_command() {
    local quoted_parts=()
    local arg quoted
    for arg in "$@"; do
        printf -v quoted "%q" "$arg"
        quoted_parts+=("$quoted")
    done
    local IFS=" "
    printf "%s" "${quoted_parts[*]}"
}

record_command() {
    local scenario_id="$1"
    local status="$2"
    local command_text="$3"
    local stdout_path="$4"
    local stderr_path="$5"
    local worker_identity
    worker_identity="${RCH_WORKER_IDENTITY:-${RCH_WORKER:-local:$(hostname -s 2>/dev/null || printf unknown)}}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Iseconds)" \
        "$scenario_id" \
        "$status" \
        "$command_text" \
        "$stdout_path" \
        "$stderr_path" \
        "$worker_identity" >>"$COMMAND_TRANSCRIPT"
}

run_capture() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    shift 3
    local command_text status
    command_text="$(quote_command "$@")"
    if "$@" >"$stdout_path" 2>"$stderr_path"; then
        status=0
    else
        status=$?
    fi
    record_command "$scenario_id" "$status" "$command_text" "$stdout_path" "$stderr_path"
    return "$status"
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
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
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
noise_prefixes = (
    "Error:",
    "permissioned campaign broker report written:",
    "permissioned campaign broker summary written:",
    "permissioned campaign handoff packet written:",
    "permissioned campaign handoff summary written:",
    "swarm capability calibration report written:",
    "swarm capability calibration summary written:",
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
    if isinstance(obj, dict) and (
        "valid" in obj or "packet_id" in obj or "authorization_notice" in obj
    ):
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("permissioned campaign broker JSON output not found")
PY
}

extract_report_markdown() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
starts = [
    index
    for index in (
        text.find("# Permissioned Campaign Broker"),
        text.find("# Permissioned Campaign Execution Ledger"),
        text.find("# Permissioned Campaign Handoff"),
        text.find("# Swarm Capability Calibration"),
    )
    if index >= 0
]
if not starts:
    raise SystemExit("permissioned campaign broker Markdown output not found")
start = min(starts)
tail = text[start:]
match = re.search(r"\n\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*\brch::", tail)
end = start + match.start() if match else len(text)
pathlib.Path(report_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

run_harness() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    shift 3
    local status=0 manifest_path="" ledger_path="" out_path="" summary_out_path=""
    local sync_dir sync_manifest sync_ledger json_raw markdown_raw command_text
    local -a base_args=()
    local arg
    while (($# > 0)); do
        arg="$1"
        case "$arg" in
            --manifest)
                manifest_path="$2"
                shift 2
                ;;
            --ledger)
                ledger_path="$2"
                shift 2
                ;;
            --out)
                out_path="$2"
                shift 2
                ;;
            --summary-out)
                summary_out_path="$2"
                shift 2
                ;;
            --format)
                shift 2
                ;;
            *)
                base_args+=("$arg")
                shift
                ;;
        esac
    done

    if [[ -z "$manifest_path" ]]; then
        printf '%s\n' "run_harness requires --manifest" >"$stderr_path"
        record_command "$scenario_id" 2 "cargo run --quiet -p ffs-harness" "$stdout_path" "$stderr_path"
        return 2
    fi

    sync_dir="$RCH_INPUT_ROOT/$scenario_id"
    mkdir -p "$sync_dir"
    sync_manifest="$sync_dir/manifest.json"
    cp "$manifest_path" "$sync_manifest"
    base_args+=("--manifest" "$sync_manifest")
    if [[ -n "$ledger_path" ]]; then
        sync_ledger="$sync_dir/ledger.json"
        cp "$ledger_path" "$sync_ledger"
        base_args+=("--ledger" "$sync_ledger")
    fi

    json_raw="${stdout_path}.json.rch.log"
    markdown_raw="${stdout_path}.markdown.rch.log"
    command_text="$(quote_command "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- "${base_args[@]}")"

    run_rch_capture "$json_raw" cargo run --quiet -p ffs-harness -- "${base_args[@]}" || status=$?
    cp "$json_raw" "$stderr_path"

    if extract_report_json "$json_raw" "$stdout_path"; then
        if [[ -n "$out_path" ]]; then
            cp "$stdout_path" "$out_path"
        fi
    else
        cp "$json_raw" "$stdout_path"
        if [[ "$status" -eq 0 ]]; then
            status=1
        fi
    fi

    if [[ "$status" -eq 0 && -n "$summary_out_path" ]]; then
        if run_rch_capture "$markdown_raw" cargo run --quiet -p ffs-harness -- "${base_args[@]}" --format markdown; then
            if ! extract_report_markdown "$markdown_raw" "$summary_out_path"; then
                status=1
            fi
        else
            status=$?
        fi
        printf '\n--- markdown rch transcript ---\n' >>"$stderr_path"
        cat "$markdown_raw" >>"$stderr_path"
    fi

    record_command "$scenario_id" "$status" "$command_text" "$stdout_path" "$stderr_path"
    return "$status"
}

write_detailed_result() {
    local verdict="$1"
    local summary="$2"
    python3 - "$DETAILED_RESULT_JSON" "$verdict" "$summary" "$PASS_COUNT" "$FAIL_COUNT" "$TOTAL" \
        "$COMMAND_TRANSCRIPT" "$SAFETY_REPORT_JSON" "$XFSTESTS_PACKET_JSON" "$SWARM_PACKET_JSON" \
        "$SWARM_BLOCKER_PACKET_JSON" "$XFSTESTS_LEDGER_JSON" "$SWARM_LEDGER_JSON" \
        "$XFSTESTS_MISSING_INPUTS_JSON" "$SWARM_MISSING_INPUTS_JSON" \
        "$SWARM_CALIBRATION_CANDIDATE_REPORT_JSON" "$SWARM_CALIBRATION_BLOCKED_REPORT_JSON" \
        "$SWARM_CALIBRATION_RELEASE_GATE_REPORT_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

(
    out_path,
    verdict,
    summary,
    pass_count,
    fail_count,
    total,
    command_transcript,
    safety_report,
    xfstests_packet,
    swarm_packet,
    swarm_blocker_packet,
    xfstests_ledger,
    swarm_ledger,
    xfstests_missing,
    swarm_missing,
    swarm_calibration_candidate,
    swarm_calibration_blocked,
    swarm_calibration_release_gate,
) = sys.argv[1:]

payload = {
    "schema_version": 1,
    "gate_id": "ffs_permissioned_campaign_broker",
    "verdict": verdict,
    "summary": summary,
    "pass_count": int(pass_count),
    "fail_count": int(fail_count),
    "total": int(total),
    "cleanup_status": "preserved_artifacts",
    "permissioned_execution_attempted": False,
    "destructive_workload_started": False,
    "large_host_runner_started": False,
    "command_transcript": command_transcript,
    "safety_report": safety_report,
    "packet_artifacts": [
        xfstests_packet,
        swarm_packet,
        swarm_blocker_packet,
    ],
    "execution_ledgers": [
        xfstests_ledger,
        swarm_ledger,
    ],
    "blocker_artifacts": [
        xfstests_missing,
        swarm_missing,
    ],
    "swarm_calibration_packets": [
        swarm_calibration_candidate,
        swarm_calibration_blocked,
    ],
    "swarm_calibration_release_gate_report": swarm_calibration_release_gate,
}
pathlib.Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_permissioned_campaign_broker"
e2e_print_env

RCH_INPUT_ROOT="$REPO_ROOT/artifacts/rch_e2e/$(basename "$E2E_LOG_DIR")/permissioned_campaign_broker"
ARTIFACT_ROOT="$E2E_LOG_DIR/permissioned_campaign_broker"
E2E_LOG_REL="${E2E_LOG_DIR#"$REPO_ROOT"/}"
ARTIFACT_ROOT_REL="$E2E_LOG_REL/permissioned_campaign_broker"
MANIFEST_DIR="$ARTIFACT_ROOT/manifests"
REPORT_DIR="$ARTIFACT_ROOT/reports"
PACKET_DIR="$ARTIFACT_ROOT/packets"
LEDGER_DIR="$ARTIFACT_ROOT/ledgers"
BLOCKER_DIR="$ARTIFACT_ROOT/blockers"
LOG_DIR="$ARTIFACT_ROOT/logs"
mkdir -p "$RCH_INPUT_ROOT" "$MANIFEST_DIR" "$REPORT_DIR" "$PACKET_DIR" "$LEDGER_DIR" "$BLOCKER_DIR" "$LOG_DIR"

COMMAND_TRANSCRIPT="$ARTIFACT_ROOT/command_transcript.tsv"
DETAILED_RESULT_JSON="$ARTIFACT_ROOT/permissioned_campaign_broker_result.json"
SAFETY_REPORT_JSON="$ARTIFACT_ROOT/non_execution_safety_report.json"
FIXTURE_STDOUT="$LOG_DIR/write_fixtures.stdout"
FIXTURE_STDERR="$LOG_DIR/write_fixtures.stderr"

XFSTESTS_MANIFEST="$MANIFEST_DIR/xfstests_ready_manifest.json"
SWARM_MANIFEST="$MANIFEST_DIR/swarm_ready_manifest.json"
SWARM_BLOCKER_MANIFEST="$MANIFEST_DIR/swarm_blocker_manifest.json"
SWARM_CALIBRATION_CANDIDATE_MANIFEST="$MANIFEST_DIR/swarm_calibration_candidate_manifest.json"
SWARM_CALIBRATION_BLOCKED_MANIFEST="$MANIFEST_DIR/swarm_calibration_blocked_manifest.json"
SWARM_CALIBRATION_RELEASE_GATE_BUNDLE="$MANIFEST_DIR/swarm_calibration_release_gate_bundle.json"
SWARM_CALIBRATION_RELEASE_GATE_POLICY="$MANIFEST_DIR/swarm_calibration_release_gate_policy.json"
INVALID_MANIFEST="$MANIFEST_DIR/invalid_missing_ack_manifest.json"

XFSTESTS_REPORT_JSON="$REPORT_DIR/xfstests_ready_report.json"
XFSTESTS_REPORT_MD="$REPORT_DIR/xfstests_ready_report.md"
SWARM_REPORT_JSON="$REPORT_DIR/swarm_ready_report.json"
SWARM_REPORT_MD="$REPORT_DIR/swarm_ready_report.md"
SWARM_BLOCKER_REPORT_JSON="$REPORT_DIR/swarm_blocker_report.json"
SWARM_BLOCKER_REPORT_MD="$REPORT_DIR/swarm_blocker_report.md"
SWARM_CALIBRATION_CANDIDATE_REPORT_JSON="$REPORT_DIR/swarm_calibration_candidate_report.json"
SWARM_CALIBRATION_CANDIDATE_REPORT_MD="$REPORT_DIR/swarm_calibration_candidate_report.md"
SWARM_CALIBRATION_BLOCKED_REPORT_JSON="$REPORT_DIR/swarm_calibration_blocked_report.json"
SWARM_CALIBRATION_BLOCKED_REPORT_MD="$REPORT_DIR/swarm_calibration_blocked_report.md"
SWARM_CALIBRATION_RELEASE_GATE_REPORT_JSON="$REPORT_DIR/swarm_calibration_release_gate_report.json"
SWARM_CALIBRATION_RELEASE_GATE_RAW="$REPORT_DIR/swarm_calibration_release_gate.raw"
INVALID_REPORT_RAW="$REPORT_DIR/invalid_missing_ack.raw"

XFSTESTS_PACKET_JSON="$PACKET_DIR/xfstests_handoff_packet.json"
XFSTESTS_PACKET_MD="$PACKET_DIR/xfstests_handoff_packet.md"
SWARM_PACKET_JSON="$PACKET_DIR/swarm_handoff_packet.json"
SWARM_PACKET_MD="$PACKET_DIR/swarm_handoff_packet.md"
SWARM_BLOCKER_PACKET_JSON="$PACKET_DIR/swarm_blocker_handoff_packet.json"
SWARM_BLOCKER_PACKET_MD="$PACKET_DIR/swarm_blocker_handoff_packet.md"

XFSTESTS_LEDGER_JSON="$LEDGER_DIR/xfstests_execution_ledger.json"
XFSTESTS_LEDGER_REPORT_JSON="$REPORT_DIR/xfstests_execution_ledger_report.json"
XFSTESTS_LEDGER_REPORT_MD="$REPORT_DIR/xfstests_execution_ledger_report.md"
SWARM_LEDGER_JSON="$LEDGER_DIR/swarm_execution_ledger.json"
SWARM_LEDGER_REPORT_JSON="$REPORT_DIR/swarm_execution_ledger_report.json"
SWARM_LEDGER_REPORT_MD="$REPORT_DIR/swarm_execution_ledger_report.md"
INVALID_LEDGER_JSON="$LEDGER_DIR/invalid_dry_run_pass_ledger.json"
INVALID_LEDGER_REPORT_JSON="$REPORT_DIR/invalid_dry_run_pass_ledger_report.json"

XFSTESTS_MISSING_INPUTS_JSON="$BLOCKER_DIR/xfstests_missing_inputs.json"
SWARM_MISSING_INPUTS_JSON="$BLOCKER_DIR/swarm_missing_inputs.json"

printf 'created_at\tscenario_id\texit_status\tcommand\tstdout_path\tstderr_path\tworker_identity\n' >"$COMMAND_TRANSCRIPT"

e2e_step "Scenario 1: broker CLI is wired"
if grep -q "validate-permissioned-campaign-broker" crates/ffs-harness/src/main.rs \
    && grep -q "generate-permissioned-campaign-packet" crates/ffs-harness/src/main.rs \
    && grep -q "validate-swarm-capability-calibration" crates/ffs-harness/src/main.rs \
    && grep -q "pub mod permissioned_campaign_broker" crates/ffs-harness/src/lib.rs; then
    scenario_result "permissioned_broker_cli_wired" "PASS" "validator, packet generator, and calibration CLI are exported"
else
    scenario_result "permissioned_broker_cli_wired" "FAIL" "missing broker/calibration CLI or module export"
fi

e2e_step "Scenario 2: fixture manifests and blocker artifacts are generated"
if run_capture "permissioned_broker_write_fixtures" "$FIXTURE_STDOUT" "$FIXTURE_STDERR" \
    python3 - "$REPO_ROOT" "$E2E_LOG_DIR" "$REFERENCE_TIMESTAMP" "$GIT_SHA" "$AGENT_NAME" <<'PY'
from __future__ import annotations

import json
import hashlib
import pathlib
import sys
from datetime import datetime, timezone

repo_root = pathlib.Path(sys.argv[1])
e2e_log_dir = pathlib.Path(sys.argv[2])
reference_timestamp = sys.argv[3]
git_sha = sys.argv[4]
agent_name = sys.argv[5]
base_rel = e2e_log_dir.relative_to(repo_root)
artifact_root = base_rel / "permissioned_campaign_broker"
manifest_dir = artifact_root / "manifests"
blocker_dir = artifact_root / "blockers"

observed_at = datetime.fromisoformat(reference_timestamp.replace("Z", "+00:00")).astimezone(
    timezone.utc
)
observed_days = observed_at.date().toordinal() - 1


def rel(*parts: str) -> str:
    return (artifact_root.joinpath(*parts)).as_posix()


def write_json(relative_path: pathlib.Path, data: dict) -> None:
    path = repo_root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ack(env_var: str, exact_value: str, prompt: str) -> dict:
    return {
        "env_var": env_var,
        "exact_value": exact_value,
        "operator_prompt": prompt,
    }


def runner_env(env_var: str, purpose: str, expected_shape: str) -> dict:
    return {
        "env_var": env_var,
        "purpose": purpose,
        "expected_shape": expected_shape,
    }


def host_fact(fact_id: str, observed: str, required: str, proof: str) -> dict:
    return {
        "fact_id": fact_id,
        "observed_value": observed,
        "required_value": required,
        "proof_path": proof,
    }


def path_root(root_id: str, path: str, purpose: str) -> dict:
    return {
        "root_id": root_id,
        "path": path,
        "purpose": purpose,
    }


def cleanup(policy_id: str) -> dict:
    return {
        "policy_id": policy_id,
        "expected_status": "preserved_artifacts",
        "partial_artifact_policy": "preserve command transcript, stdout, stderr, raw logs, blocker artifacts, and generated packets",
    }


def boundary(required: list[str], text: str) -> dict:
    return {
        "packet_status": "ready_for_operator_approval",
        "product_evidence_claim": "none",
        "required_executed_evidence": required,
        "claim_text": text,
    }


def preflight(preflight_id: str, path: str, summary: str) -> dict:
    return {
        "preflight_id": preflight_id,
        "artifact_path": path,
        "observed_at_epoch_days": observed_days,
        "max_age_days": 14,
        "summary": summary,
    }


def command(command_id: str, role: str, exact: str) -> dict:
    return {
        "command_id": command_id,
        "command_role": role,
        "exact_command": exact,
    }


xfstests_root = rel("xfstests", "real-run")
xfstests_preflight = rel("xfstests", "preflight", "report.json")
xfstests_manifest = {
    "schema_version": 1,
    "campaign_id": "bd-rchk3.3-xfstests-real-dry-run-handoff",
    "lane_kind": "xfstests_real_baseline",
    "target_beads": ["bd-rchk3.3", "bd-rchk3"],
    "generated_at": reference_timestamp,
    "required_ack": ack(
        "XFSTESTS_REAL_RUN_ACK",
        "xfstests-may-mutate-test-and-scratch-devices",
        "Approve real xfstests execution against scoped TEST_DIR, SCRATCH_MNT, and RESULT_BASE",
    ),
    "required_runner_env": [
        runner_env("XFSTESTS_DIR", "xfstests source tree with built helpers", "third_party/xfstests-dev"),
        runner_env("TEST_DIR", "explicit xfstests test root", rel("xfstests", "test-dir")),
        runner_env("SCRATCH_MNT", "explicit xfstests scratch root", rel("xfstests", "scratch")),
        runner_env("RESULT_BASE", "raw xfstests result artifact root", xfstests_root),
    ],
    "host_capability_facts": [
        host_fact("xfstests_helpers", "present", "present", xfstests_preflight),
        host_fact("explicit_test_and_scratch_paths", "provided", "provided", xfstests_preflight),
    ],
    "safe_path_roots": [
        path_root("test_dir", rel("xfstests", "test-dir"), "test_data"),
        path_root("scratch_mnt", rel("xfstests", "scratch"), "scratch"),
        path_root("result_base", xfstests_root, "artifact_root"),
    ],
    "destructive_operations": [
        "mount_test_device",
        "mount_scratch_device",
        "mutate_test_device",
        "mutate_scratch_device",
    ],
    "expected_artifact_paths": [
        f"{xfstests_root}/summary.json",
        f"{xfstests_root}/results.json",
        f"{xfstests_root}/junit.xml",
        f"{xfstests_root}/artifact_manifest.json",
        f"{xfstests_root}/command_transcript.tsv",
        f"{xfstests_root}/raw-results",
        f"{xfstests_root}/failure_to_beads.json",
        f"{xfstests_root}/stdout.log",
        f"{xfstests_root}/stderr.log",
    ],
    "cleanup_policy": cleanup("xfstests_preserve_dry_run_handoff_artifacts"),
    "claim_boundary": boundary(
        ["raw xfstests logs", "pass/fail/not-run summary", "failure-to-bead extraction report"],
        "authorization handoff only; xfstests not-run rows are blockers and this packet cannot upgrade product pass/fail status",
    ),
    "preflight_references": [
        preflight("xfstests-explicit-path-preflight", xfstests_preflight, "dry-run fixture records explicit paths; real execution not started")
    ],
    "operator_risks": [
        "real xfstests may mutate test and scratch roots",
        "partial runs must preserve logs and not-run classifications",
    ],
    "exact_commands": [
        command(
            "xfstests_preflight",
            "preflight",
            f"XFSTESTS_DIR='third_party/xfstests-dev' TEST_DIR='{rel('xfstests', 'test-dir')}' SCRATCH_MNT='{rel('xfstests', 'scratch')}' RESULT_BASE='{xfstests_root}' scripts/e2e/ffs_xfstests_e2e.sh --dry-run",
        ),
        command(
            "xfstests_permissioned_run",
            "permissioned_run",
            f"XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices XFSTESTS_DIR='third_party/xfstests-dev' TEST_DIR='{rel('xfstests', 'test-dir')}' SCRATCH_MNT='{rel('xfstests', 'scratch')}' RESULT_BASE='{xfstests_root}' scripts/e2e/ffs_xfstests_e2e.sh",
        ),
        command(
            "xfstests_preserve_artifacts",
            "cleanup",
            f"RESULT_BASE='{xfstests_root}' find '{xfstests_root}' -maxdepth 3 -type f -print | sort > '{xfstests_root}/artifact_file_list.txt'",
        ),
    ],
}

swarm_root = rel("swarm", "large-host")
swarm_preflight = rel("swarm", "preflight", "report.json")
swarm_lanes = [
    f"{swarm_root}/proof/swarm_workload_harness.json",
    f"{swarm_root}/proof/swarm_tail_latency.json",
    f"{swarm_root}/proof/adaptive_runtime.json",
]


def swarm_manifest(capable: bool) -> dict:
    cpus = "96" if capable else "16"
    ram = "512" if capable else "64"
    numa_visible = "true" if capable else "false"
    numa_nodes = "2" if capable else "0"
    claim = (
        "operator approval material only; cannot upgrade swarm.responsiveness until executed large-host evidence, p99 attribution, proof-bundle lanes, and release-gate output are recorded"
        if capable
        else "capability blocker: logical_cpus=16 below required >=64; ram_gib=64 below required >=256; numa_topology_visible=false; numa_nodes=0 below required >=2; cannot upgrade swarm.responsiveness from this broker packet"
    )
    summary = (
        "large-host preflight satisfies CPU, RAM, and NUMA visibility floors; permissioned execution not started"
        if capable
        else "large-host preflight is blocked by insufficient CPU/RAM/NUMA proof; permissioned execution must not be treated as authoritative"
    )
    suffix = "ready" if capable else "blocker"
    return {
        "schema_version": 1,
        "campaign_id": f"bd-rchk0.53.8-swarm-{suffix}-dry-run-handoff",
        "lane_kind": "large_host_swarm_responsiveness",
        "target_beads": ["bd-rchk0.53.8", "bd-rchk0.53"],
        "generated_at": reference_timestamp,
        "required_ack": ack(
            "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
            "swarm-workload-may-use-permissioned-large-host",
            "Approve permissioned large-host swarm workload execution after host proof review",
        ),
        "required_runner_env": [
            runner_env("FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD", "default-off permissioned opt-in", "1"),
            runner_env("FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER", "large-host runner path", "tools/permissioned/swarm-large-host-runner"),
            runner_env("FFS_SWARM_WORKLOAD_ARTIFACT_ROOT", "swarm artifact root", swarm_root),
        ],
        "host_capability_facts": [
            host_fact("logical_cpus", cpus, ">=64", rel("swarm", "preflight", "host.json")),
            host_fact("ram_gib", ram, ">=256", rel("swarm", "preflight", "host.json")),
            host_fact("numa_topology_visible", numa_visible, "true", rel("swarm", "preflight", "numa.json")),
            host_fact("numa_nodes", numa_nodes, ">=2", rel("swarm", "preflight", "numa.json")),
        ],
        "safe_path_roots": [
            path_root("runner_workspace", rel("swarm", "workspace"), "runner_workspace"),
            path_root("swarm_artifacts", swarm_root, "artifact_root"),
        ],
        "destructive_operations": [
            "generate_filesystem_load",
            "spawn_large_host_workers",
            "consume_large_temp_storage",
            "kill_replay_worker",
        ],
        "expected_artifact_paths": [
            f"{swarm_root}/resource_caps.json",
            f"{swarm_root}/p99_attribution.json",
            f"{swarm_root}/raw.log",
            f"{swarm_root}/release_gate.json",
            f"{swarm_root}/proof/bundle.json",
            *swarm_lanes,
        ],
        "cleanup_policy": cleanup("swarm_preserve_dry_run_handoff_artifacts"),
        "claim_boundary": boundary(
            [
                "swarm workload harness measured_authoritative permissioned_large_host report",
                "p99 attribution ledger",
                "proof-bundle lanes: swarm_workload_harness, swarm_tail_latency, adaptive_runtime",
                "release-gate output",
                "raw command logs",
            ],
            claim,
        ),
        "preflight_references": [preflight("swarm-large-host-capability-preflight", swarm_preflight, summary)],
        "operator_risks": [
            "permissioned swarm run may consume >=64 CPUs and large temporary storage",
            "small_host_smoke and capability_downgraded_smoke cannot upgrade swarm.responsiveness",
        ],
        "exact_commands": [
            command(
                "swarm_workload_preflight",
                "preflight",
                "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest benchmarks/swarm_workload_harness_manifest.json",
            ),
            command(
                "swarm_permissioned_run",
                "permissioned_run",
                f"FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER='tools/permissioned/swarm-large-host-runner' FFS_SWARM_WORKLOAD_ARTIFACT_ROOT='{swarm_root}' scripts/e2e/ffs_swarm_workload_harness_e2e.sh",
            ),
        ],
    }


def swarm_calibration_manifest(kind: str) -> dict:
    capable = kind == "candidate"
    blocked = kind == "blocked"
    observed_root = swarm_root if not blocked else rel("swarm", "unexpected-root")
    return {
        "schema_version": 1,
        "packet_id": f"bd-4v16z.9-swarm-calibration-{kind}",
        "generated_at": reference_timestamp,
        "target_beads": ["bd-4v16z.9", "bd-rchk0.53.8"],
        "host": {
            "logical_cpus": 96 if capable or blocked else 16,
            "ram_total_gib": 512.0 if capable or blocked else 64.0,
            "ram_available_gib": 384.0 if capable or blocked else 48.0,
            "numa_topology_visible": capable or blocked,
            "numa_nodes": 2 if capable or blocked else 0,
            "storage_class": "local_nvme",
            "fuse": {
                "state": "available" if capable or blocked else "missing",
                "detail": "/dev/fuse and fusermount3 available" if capable or blocked else "/dev/fuse unavailable",
            },
        },
        "worker": {
            "rch_worker_identity": "rch:large-host-01",
            "worker_fingerprint": "worker=large-host-01 cpu=96 ram=512g numa=2",
            "worker_fingerprint_observed_at_epoch_days": observed_days - (30 if blocked else 0),
            "worker_fingerprint_max_age_days": 7,
            "queue_isolation": "dedicated" if capable or blocked else "shared",
            "target_dir_isolated": not blocked,
            "target_dir": rel("swarm", "calibration", kind, "target"),
        },
        "artifact_plan": {
            "expected_artifact_root": swarm_root,
            "observed_artifact_root": observed_root,
        },
        "resource_caps": {
            "max_duration_secs": 7200,
            "max_threads": 96 if capable or blocked else 16,
            "max_memory_gib": 384.0 if capable or blocked else 32.0,
            "max_temp_storage_gib": 512.0,
            "max_queue_depth": 4096,
        },
        "release_gate_policy_path": "tests/release-gates/release_gate_policy_v1.json",
        "real_campaign_bead": "bd-rchk0.53.8",
        "handoff_summary": "calibration packet only; run bd-rchk0.53.8 for executed evidence",
    }


def release_gate_missing_swarm_bundle() -> dict:
    return {
        "schema_version": 1,
        "bundle_id": "bd-4v16z.9-calibration-only-bundle",
        "generated_at": reference_timestamp,
        "git_sha": git_sha,
        "toolchain": "rust-nightly-2024",
        "kernel": "linux-calibration-e2e",
        "mount_capability": "not_required",
        "required_lanes": [
            "swarm_workload_harness",
            "swarm_tail_latency",
            "adaptive_runtime",
        ],
        "lanes": [],
        "redaction": {
            "redacted_fields": ["hostname", "token"],
            "preserved_fields": [
                "reproduction_command",
                "git_sha",
                "bundle_id",
                "artifact_paths",
                "scenario_ids",
            ],
            "reproduction_command": "cargo run -p ffs-harness -- validate-proof-bundle --bundle swarm_calibration_release_gate_bundle.json",
        },
    }


def release_gate_swarm_policy() -> dict:
    def lane(lane_id: str, risk_class: str = "generic") -> dict:
        return {
            "lane_id": lane_id,
            "expected_outcome": "pass",
            "missing_state": "hidden",
            "failed_state": "experimental",
            "risk_class": risk_class,
            "skipped_state": "experimental",
            "allow_capability_skip": False,
            "remediation_id": "bd-rchk0.53.8",
        }

    return {
        "schema_version": 1,
        "policy_id": "bd-4v16z.9-swarm-calibration-release-gate",
        "reproduction_command": "cargo run -p ffs-harness -- evaluate-release-gates --bundle swarm_calibration_release_gate_bundle.json --policy swarm_calibration_release_gate_policy.json",
        "required_log_fields": [
            "feature_id",
            "previous_state",
            "proposed_state",
            "final_state",
            "transition_reason",
            "controlling_artifact_hash",
            "threshold_value",
            "observed_value",
            "remediation_id",
            "docs_wording_id",
            "output_path",
            "reproduction_command",
        ],
        "features": [
            {
                "feature_id": "swarm.responsiveness",
                "docs_wording_id": "feature_parity.swarm_responsiveness",
                "previous_state": "disabled",
                "target_state": "validated",
                "required_lanes": [
                    lane("swarm_workload_harness", "host_capability_skip"),
                    lane("swarm_tail_latency", "noisy_performance"),
                    lane("adaptive_runtime", "host_capability_skip"),
                ],
                "thresholds": [],
                "kill_switches": [
                    {
                        "switch_id": "missing-evidence",
                        "trigger": "any_required_lane_missing",
                        "downgrade_to": "hidden",
                        "reason": "calibration packets are not executed swarm evidence",
                        "remediation_id": "bd-rchk0.53.8",
                    }
                ],
                "remediation_id": "bd-rchk0.53.8",
            }
        ],
    }


invalid_manifest = dict(xfstests_manifest)
invalid_manifest["campaign_id"] = "bd-rchk3.3-invalid-missing-ack"
invalid_manifest["required_ack"] = dict(invalid_manifest["required_ack"])
invalid_manifest["required_ack"]["exact_value"] = ""


def command_plan_hash(manifest: dict) -> str:
    hasher = hashlib.sha256()
    parts: list[str] = [manifest["campaign_id"], manifest["lane_kind"]]
    for item in manifest["exact_commands"]:
        parts.extend([item["command_id"], item["command_role"], item["exact_command"]])
    for part in parts:
        hasher.update(part.encode("utf-8"))
        hasher.update(b"\0")
    return "sha256:" + hasher.hexdigest()


def fixture_sha256(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def artifact(artifact_id: str, path: str, role: str, stale: bool = False) -> dict:
    return {
        "artifact_id": artifact_id,
        "path": path,
        "sha256": fixture_sha256(path),
        "role": role,
        "stale": stale,
    }


def ledger_step(
    step_id: str,
    command_id: str,
    status: str,
    raw_logs: list[str],
    checkpoints: list[str],
    note: str,
) -> dict:
    return {
        "step_id": step_id,
        "command_id": command_id,
        "status": status,
        "started_at": reference_timestamp,
        "finished_at": reference_timestamp,
        "raw_log_paths": raw_logs,
        "checkpoint_artifacts": checkpoints,
        "note": note,
    }


def execution_ledger(manifest: dict, final_status: str, resumed: bool = False) -> dict:
    raw_log = rel("logs", f"{manifest['campaign_id']}.raw.log")
    checkpoint = rel("ledgers", f"{manifest['campaign_id']}.checkpoint.json")
    cleanup_report = rel("ledgers", f"{manifest['campaign_id']}.cleanup.json")
    lane_artifact = rel("ledgers", f"{manifest['campaign_id']}.proof-lane.json")
    steps = [
        ledger_step(
            "step-00-running",
            manifest["exact_commands"][-1]["command_id"],
            "running",
            [raw_log],
            [],
            "synthetic permissioned command entered running state without starting a real workload",
        )
    ]
    if resumed:
        steps.extend(
            [
                ledger_step(
                    "step-01-interrupted",
                    manifest["exact_commands"][-1]["command_id"],
                    "interrupted",
                    [raw_log],
                    [checkpoint],
                    "synthetic partial run checkpoint preserved for resume handoff",
                ),
                ledger_step(
                    "step-02-resumed",
                    manifest["exact_commands"][-1]["command_id"],
                    "resumed",
                    [raw_log],
                    [checkpoint],
                    "synthetic resume token points at the preserved checkpoint",
                ),
            ]
        )
    else:
        steps.append(
            ledger_step(
                f"step-01-{final_status}",
                manifest["exact_commands"][-1]["command_id"],
                final_status,
                [raw_log],
                [],
                f"synthetic {final_status} terminal state; no permissioned command was started",
            )
        )
    terminal = final_status in {"passed", "failed", "cleanup_failed", "artifact_stale"} and not resumed
    artifacts = [
        artifact("raw-log", raw_log, "raw_log"),
        artifact("resume-checkpoint", checkpoint, "resume_checkpoint"),
        artifact("proof-lane", lane_artifact, "proof_bundle_lane"),
    ]
    if terminal:
        artifacts.append(artifact("cleanup-report", cleanup_report, "cleanup_report"))
    return {
        "schema_version": 1,
        "campaign_id": manifest["campaign_id"],
        "lane_kind": manifest["lane_kind"],
        "target_beads": manifest["target_beads"],
        "git_sha": git_sha,
        "command_plan_hash": command_plan_hash(manifest),
        "required_ack": {
            "env_var": manifest["required_ack"]["env_var"],
            "exact_value": manifest["required_ack"]["exact_value"],
            "observed_value": manifest["required_ack"]["exact_value"],
            "recorded_at": reference_timestamp,
        },
        "preflight_snapshot": {
            "snapshot_id": f"{manifest['campaign_id']}-preflight",
            "observed_at": reference_timestamp,
            "artifact_path": manifest["preflight_references"][0]["artifact_path"],
            "git_sha": git_sha,
            "host_class": "synthetic_permissioned_fixture",
            "blockers": [],
        },
        "steps": steps,
        "artifacts": artifacts,
        "resume_state": {
            "resume_token": "synthetic-resume-token" if resumed else None,
            "last_checkpoint_artifact": checkpoint,
            "partial_artifacts_preserved": True,
            "next_command_id": manifest["exact_commands"][-1]["command_id"],
        },
        "cleanup": {
            "status": "preserved_artifacts" if terminal else "not_started",
            "report_path": cleanup_report if terminal else None,
            "completed_at": reference_timestamp if terminal else None,
        },
        "proof_bundle_lane_candidates": [
            {
                "lane_id": manifest["lane_kind"],
                "artifact_path": lane_artifact,
                "promotion_status": "candidate" if final_status == "passed" else "blocked",
                "note": "synthetic dry-run ledger keeps this as a candidate until raw operator artifacts exist",
            }
        ],
        "product_evidence_claim": "executed_evidence_recorded" if final_status == "passed" else "none",
    }


xfstests_ledger = execution_ledger(xfstests_manifest, "failed")
swarm_ledger = execution_ledger(swarm_manifest(True), "resumed", resumed=True)
invalid_dry_run_pass_ledger = {
    **execution_ledger(xfstests_manifest, "passed"),
    "steps": [
        ledger_step(
            "step-00-not-authorized",
            "xfstests_preflight",
            "not_authorized",
            [],
            [],
            "operator ACK missing; packet must remain a dry-run handoff",
        )
    ],
    "required_ack": {
        "env_var": "XFSTESTS_REAL_RUN_ACK",
        "exact_value": "xfstests-may-mutate-test-and-scratch-devices",
        "observed_value": None,
        "recorded_at": None,
    },
    "cleanup": {"status": "not_started", "report_path": None, "completed_at": None},
    "product_evidence_claim": "packet_counts_as_pass_fail",
}

write_json(manifest_dir / "xfstests_ready_manifest.json", xfstests_manifest)
write_json(manifest_dir / "swarm_ready_manifest.json", swarm_manifest(True))
write_json(manifest_dir / "swarm_blocker_manifest.json", swarm_manifest(False))
write_json(manifest_dir / "swarm_calibration_candidate_manifest.json", swarm_calibration_manifest("candidate"))
write_json(manifest_dir / "swarm_calibration_blocked_manifest.json", swarm_calibration_manifest("blocked"))
write_json(manifest_dir / "swarm_calibration_release_gate_bundle.json", release_gate_missing_swarm_bundle())
write_json(manifest_dir / "swarm_calibration_release_gate_policy.json", release_gate_swarm_policy())
write_json(manifest_dir / "invalid_missing_ack_manifest.json", invalid_manifest)
write_json(manifest_dir.parent / "ledgers" / "xfstests_execution_ledger.json", xfstests_ledger)
write_json(manifest_dir.parent / "ledgers" / "swarm_execution_ledger.json", swarm_ledger)
write_json(
    manifest_dir.parent / "ledgers" / "invalid_dry_run_pass_ledger.json",
    invalid_dry_run_pass_ledger,
)

write_json(
    blocker_dir / "xfstests_missing_inputs.json",
    {
        "schema_version": 1,
        "blocker_id": "xfstests_missing_explicit_paths",
        "created_at": reference_timestamp,
        "permissioned_execution_attempted": False,
        "cleanup_status": "not_started_dry_run",
        "missing_inputs": ["TEST_DIR", "SCRATCH_MNT", "RESULT_BASE"],
        "required_ack": {
            "env": "XFSTESTS_REAL_RUN_ACK",
            "value": "xfstests-may-mutate-test-and-scratch-devices",
        },
        "stdout_path": rel("logs", "xfstests_missing_inputs.stdout"),
        "stderr_path": rel("logs", "xfstests_missing_inputs.stderr"),
        "artifact_paths": [
            rel("blockers", "xfstests_missing_inputs.json"),
            rel("manifests", "xfstests_ready_manifest.json"),
        ],
    },
)
write_json(
    blocker_dir / "swarm_missing_inputs.json",
    {
        "schema_version": 1,
        "blocker_id": "swarm_missing_permissioned_runner_and_host_proof",
        "created_at": reference_timestamp,
        "permissioned_execution_attempted": False,
        "cleanup_status": "not_started_dry_run",
        "missing_inputs": [
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1",
            "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
            "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER",
            ">=64 logical CPUs",
            ">=256 GiB RAM",
            "visible NUMA topology",
        ],
        "required_ack": {
            "env": "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
            "value": "swarm-workload-may-use-permissioned-large-host",
        },
        "stdout_path": rel("logs", "swarm_missing_inputs.stdout"),
        "stderr_path": rel("logs", "swarm_missing_inputs.stderr"),
        "artifact_paths": [
            rel("blockers", "swarm_missing_inputs.json"),
            rel("manifests", "swarm_blocker_manifest.json"),
        ],
    },
)
write_json(
    artifact_root / "non_execution_safety_report.json",
    {
        "schema_version": 1,
        "created_at": reference_timestamp,
        "generated_by": agent_name,
        "git_sha": git_sha,
        "permissioned_execution_attempted": False,
        "mounted_workload_started": False,
        "large_host_runner_started": False,
        "destructive_commands_started": [],
        "allowed_commands_executed": [
            "validate-permissioned-campaign-broker",
            "generate-permissioned-campaign-packet",
            "validate-permissioned-campaign-ledger",
            "validate-swarm-capability-calibration",
            "evaluate-release-gates",
        ],
        "cleanup_status": "preserved_artifacts",
        "artifact_root": artifact_root.as_posix(),
    },
)
PY
then
    scenario_result "permissioned_broker_fixtures_written" "PASS" "manifests, blockers, and safety report emitted"
else
    scenario_result "permissioned_broker_fixtures_written" "FAIL" "fixture generation failed"
fi

e2e_step "Scenario 3: JSON artifacts parse"
if jq empty \
    "$XFSTESTS_MANIFEST" \
    "$SWARM_MANIFEST" \
    "$SWARM_BLOCKER_MANIFEST" \
    "$SWARM_CALIBRATION_CANDIDATE_MANIFEST" \
    "$SWARM_CALIBRATION_BLOCKED_MANIFEST" \
    "$SWARM_CALIBRATION_RELEASE_GATE_BUNDLE" \
    "$SWARM_CALIBRATION_RELEASE_GATE_POLICY" \
    "$INVALID_MANIFEST" \
    "$XFSTESTS_LEDGER_JSON" \
    "$SWARM_LEDGER_JSON" \
    "$INVALID_LEDGER_JSON" \
    "$XFSTESTS_MISSING_INPUTS_JSON" \
    "$SWARM_MISSING_INPUTS_JSON" \
    "$SAFETY_REPORT_JSON"; then
    scenario_result "permissioned_broker_json_artifacts_parse" "PASS" "all generated JSON artifacts parse"
else
    scenario_result "permissioned_broker_json_artifacts_parse" "FAIL" "generated JSON artifact parse failure"
fi

e2e_step "Scenario 4: xfstests broker packet dry-run renders JSON and Markdown"
XFSTESTS_VALIDATE_STDOUT="$LOG_DIR/xfstests_validate.stdout"
XFSTESTS_VALIDATE_STDERR="$LOG_DIR/xfstests_validate.stderr"
XFSTESTS_PACKET_STDOUT="$LOG_DIR/xfstests_packet.stdout"
XFSTESTS_PACKET_STDERR="$LOG_DIR/xfstests_packet.stderr"
if run_harness "permissioned_broker_xfstests_validate" "$XFSTESTS_VALIDATE_STDOUT" "$XFSTESTS_VALIDATE_STDERR" \
    validate-permissioned-campaign-broker \
    --manifest "$XFSTESTS_MANIFEST" \
    --reference-timestamp "$REFERENCE_TIMESTAMP" \
    --out "$XFSTESTS_REPORT_JSON" \
    --summary-out "$XFSTESTS_REPORT_MD" \
    && run_harness "permissioned_broker_xfstests_packet" "$XFSTESTS_PACKET_STDOUT" "$XFSTESTS_PACKET_STDERR" \
        generate-permissioned-campaign-packet \
        --manifest "$XFSTESTS_MANIFEST" \
        --reference-timestamp "$REFERENCE_TIMESTAMP" \
        --generated-at "$REFERENCE_TIMESTAMP" \
        --generated-by "$AGENT_NAME" \
        --git-sha "$GIT_SHA" \
        --out "$XFSTESTS_PACKET_JSON" \
        --summary-out "$XFSTESTS_PACKET_MD" \
    && jq -e '
        .valid == true
        and .product_evidence_claim == "none"
        and .packet_status == "ready_for_operator_approval"
        and .ack_env == "XFSTESTS_REAL_RUN_ACK"
        and (.expected_artifact_paths | any(endswith("artifact_manifest.json")))
        and (.expected_artifact_paths | any(endswith("command_transcript.tsv")))
        and (.exact_commands | any(.command_role == "cleanup" and .command_id == "xfstests_preserve_artifacts"))
    ' "$XFSTESTS_REPORT_JSON" >/dev/null \
    && jq -e '
        .product_evidence_claim == "none"
        and .packet_status == "ready_for_operator_approval"
        and (.authorization_notice | contains("not executed evidence"))
        and .required_ack.env_var == "XFSTESTS_REAL_RUN_ACK"
        and (.expected_artifact_paths | any(endswith("artifact_manifest.json")))
        and (.exact_commands | any(.command_role == "cleanup" and .command_id == "xfstests_preserve_artifacts"))
    ' "$XFSTESTS_PACKET_JSON" >/dev/null \
    && grep -q "not executed evidence" "$XFSTESTS_PACKET_MD"; then
    scenario_result "permissioned_broker_xfstests_packet" "PASS" "xfstests validator report and handoff packet emitted"
else
    scenario_result "permissioned_broker_xfstests_packet" "FAIL" "xfstests dry-run packet contract failed"
fi

e2e_step "Scenario 5: swarm capable-host broker packet renders JSON and Markdown"
SWARM_VALIDATE_STDOUT="$LOG_DIR/swarm_validate.stdout"
SWARM_VALIDATE_STDERR="$LOG_DIR/swarm_validate.stderr"
SWARM_PACKET_STDOUT="$LOG_DIR/swarm_packet.stdout"
SWARM_PACKET_STDERR="$LOG_DIR/swarm_packet.stderr"
if run_harness "permissioned_broker_swarm_validate" "$SWARM_VALIDATE_STDOUT" "$SWARM_VALIDATE_STDERR" \
    validate-permissioned-campaign-broker \
    --manifest "$SWARM_MANIFEST" \
    --reference-timestamp "$REFERENCE_TIMESTAMP" \
    --out "$SWARM_REPORT_JSON" \
    --summary-out "$SWARM_REPORT_MD" \
    && run_harness "permissioned_broker_swarm_packet" "$SWARM_PACKET_STDOUT" "$SWARM_PACKET_STDERR" \
        generate-permissioned-campaign-packet \
        --manifest "$SWARM_MANIFEST" \
        --reference-timestamp "$REFERENCE_TIMESTAMP" \
        --generated-at "$REFERENCE_TIMESTAMP" \
        --generated-by "$AGENT_NAME" \
        --git-sha "$GIT_SHA" \
        --out "$SWARM_PACKET_JSON" \
        --summary-out "$SWARM_PACKET_MD" \
    && jq -e --arg p99_path "$ARTIFACT_ROOT_REL/swarm/large-host/p99_attribution.json" '
        .valid == true
        and .product_evidence_claim == "none"
        and (.expected_artifact_paths | index($p99_path))
    ' "$SWARM_REPORT_JSON" >/dev/null \
    && jq -e --arg proof_lane "$ARTIFACT_ROOT_REL/swarm/large-host/proof/swarm_tail_latency.json" '
        .product_evidence_claim == "none"
        and (.claim_text | contains("cannot upgrade swarm.responsiveness"))
        and (.required_ack.exact_value == "swarm-workload-may-use-permissioned-large-host")
        and (.host_capability_facts | any(.fact_id == "logical_cpus" and .observed_value == "96"))
        and (.expected_artifact_paths | index($proof_lane))
    ' "$SWARM_PACKET_JSON" >/dev/null \
    && grep -q "Command Transcript Template" "$SWARM_PACKET_MD"; then
    scenario_result "permissioned_broker_swarm_packet" "PASS" "swarm capable-host validator report and handoff packet emitted"
else
    scenario_result "permissioned_broker_swarm_packet" "FAIL" "swarm capable-host packet contract failed"
fi

e2e_step "Scenario 6: insufficient swarm host proof renders a structured blocker packet"
SWARM_BLOCKER_VALIDATE_STDOUT="$LOG_DIR/swarm_blocker_validate.stdout"
SWARM_BLOCKER_VALIDATE_STDERR="$LOG_DIR/swarm_blocker_validate.stderr"
SWARM_BLOCKER_PACKET_STDOUT="$LOG_DIR/swarm_blocker_packet.stdout"
SWARM_BLOCKER_PACKET_STDERR="$LOG_DIR/swarm_blocker_packet.stderr"
if run_harness "permissioned_broker_swarm_blocker_validate" "$SWARM_BLOCKER_VALIDATE_STDOUT" "$SWARM_BLOCKER_VALIDATE_STDERR" \
    validate-permissioned-campaign-broker \
    --manifest "$SWARM_BLOCKER_MANIFEST" \
    --reference-timestamp "$REFERENCE_TIMESTAMP" \
    --out "$SWARM_BLOCKER_REPORT_JSON" \
    --summary-out "$SWARM_BLOCKER_REPORT_MD" \
    && run_harness "permissioned_broker_swarm_blocker_packet" "$SWARM_BLOCKER_PACKET_STDOUT" "$SWARM_BLOCKER_PACKET_STDERR" \
        generate-permissioned-campaign-packet \
        --manifest "$SWARM_BLOCKER_MANIFEST" \
        --reference-timestamp "$REFERENCE_TIMESTAMP" \
        --generated-at "$REFERENCE_TIMESTAMP" \
        --generated-by "$AGENT_NAME" \
        --git-sha "$GIT_SHA" \
        --out "$SWARM_BLOCKER_PACKET_JSON" \
        --summary-out "$SWARM_BLOCKER_PACKET_MD" \
    && jq -e '
        .valid == true
        and (.claim_text | contains("capability blocker"))
    ' "$SWARM_BLOCKER_REPORT_JSON" >/dev/null \
    && jq -e '
        .product_evidence_claim == "none"
        and (.claim_text | contains("capability blocker"))
        and (.claim_text | contains("cannot upgrade swarm.responsiveness"))
        and (.host_capability_facts | any(.fact_id == "numa_topology_visible" and .observed_value == "false"))
    ' "$SWARM_BLOCKER_PACKET_JSON" >/dev/null; then
    scenario_result "permissioned_broker_swarm_blocker_packet" "PASS" "insufficient host proof produces blocker handoff packet"
else
    scenario_result "permissioned_broker_swarm_blocker_packet" "FAIL" "swarm blocker packet contract failed"
fi

e2e_step "Scenario 7: swarm capability calibration emits candidate and blocked packets"
SWARM_CALIBRATION_CANDIDATE_STDOUT="$LOG_DIR/swarm_calibration_candidate.stdout"
SWARM_CALIBRATION_CANDIDATE_STDERR="$LOG_DIR/swarm_calibration_candidate.stderr"
SWARM_CALIBRATION_BLOCKED_STDOUT="$LOG_DIR/swarm_calibration_blocked.stdout"
SWARM_CALIBRATION_BLOCKED_STDERR="$LOG_DIR/swarm_calibration_blocked.stderr"
if run_harness "swarm_calibration_candidate" "$SWARM_CALIBRATION_CANDIDATE_STDOUT" "$SWARM_CALIBRATION_CANDIDATE_STDERR" \
    validate-swarm-capability-calibration \
    --manifest "$SWARM_CALIBRATION_CANDIDATE_MANIFEST" \
    --reference-timestamp "$REFERENCE_TIMESTAMP" \
    --out "$SWARM_CALIBRATION_CANDIDATE_REPORT_JSON" \
    --summary-out "$SWARM_CALIBRATION_CANDIDATE_REPORT_MD" \
    && run_harness "swarm_calibration_blocked" "$SWARM_CALIBRATION_BLOCKED_STDOUT" "$SWARM_CALIBRATION_BLOCKED_STDERR" \
        validate-swarm-capability-calibration \
        --manifest "$SWARM_CALIBRATION_BLOCKED_MANIFEST" \
        --reference-timestamp "$REFERENCE_TIMESTAMP" \
        --out "$SWARM_CALIBRATION_BLOCKED_REPORT_JSON" \
        --summary-out "$SWARM_CALIBRATION_BLOCKED_REPORT_MD" \
    && jq -e '
        .valid == true
        and .classification == "authoritative_large_host_candidate"
        and .candidate_for_authorized_run == true
        and .product_evidence_claim == "none"
        and (.release_gate_effect | contains("swarm.responsiveness remains hidden"))
    ' "$SWARM_CALIBRATION_CANDIDATE_REPORT_JSON" >/dev/null \
    && jq -e '
        .valid == true
        and .classification == "blocked"
        and .candidate_for_authorized_run == false
        and .product_evidence_claim == "none"
        and (.blockers | any(contains("worker_fingerprint_stale")))
        and (.blockers | any(contains("artifact_root_mismatch")))
    ' "$SWARM_CALIBRATION_BLOCKED_REPORT_JSON" >/dev/null \
    && grep -q "Product evidence claim: \`none\`" "$SWARM_CALIBRATION_CANDIDATE_REPORT_MD"; then
    scenario_result "swarm_capability_calibration_packets" "PASS" "candidate and blocked calibration packets emitted without product evidence"
else
    scenario_result "swarm_capability_calibration_packets" "FAIL" "swarm calibration packet contract failed"
fi

e2e_step "Scenario 8: calibration-only evidence keeps swarm.responsiveness hidden at release gate"
SWARM_CALIBRATION_RELEASE_GATE_SYNC_DIR="$RCH_INPUT_ROOT/swarm_calibration_release_gate"
mkdir -p "$SWARM_CALIBRATION_RELEASE_GATE_SYNC_DIR"
SWARM_CALIBRATION_RELEASE_GATE_SYNC_BUNDLE="$SWARM_CALIBRATION_RELEASE_GATE_SYNC_DIR/bundle.json"
SWARM_CALIBRATION_RELEASE_GATE_SYNC_POLICY="$SWARM_CALIBRATION_RELEASE_GATE_SYNC_DIR/policy.json"
cp "$SWARM_CALIBRATION_RELEASE_GATE_BUNDLE" "$SWARM_CALIBRATION_RELEASE_GATE_SYNC_BUNDLE"
cp "$SWARM_CALIBRATION_RELEASE_GATE_POLICY" "$SWARM_CALIBRATION_RELEASE_GATE_SYNC_POLICY"
set +e
run_rch_capture "$SWARM_CALIBRATION_RELEASE_GATE_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$SWARM_CALIBRATION_RELEASE_GATE_SYNC_BUNDLE" \
    --policy "$SWARM_CALIBRATION_RELEASE_GATE_SYNC_POLICY" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000
SWARM_CALIBRATION_RELEASE_GATE_STATUS=$?
set -e
if [[ "$SWARM_CALIBRATION_RELEASE_GATE_STATUS" -ne 0 ]] \
    && extract_report_json "$SWARM_CALIBRATION_RELEASE_GATE_RAW" "$SWARM_CALIBRATION_RELEASE_GATE_REPORT_JSON" \
    && jq -e '
        .release_ready == false
        and (.feature_reports[] | select(.feature_id == "swarm.responsiveness") | .final_state == "hidden")
        and any(.findings[]; .feature_id == "swarm.responsiveness" and (.finding_id | contains("::missing_required_lane::")))
    ' "$SWARM_CALIBRATION_RELEASE_GATE_REPORT_JSON" >/dev/null; then
    scenario_result "swarm_calibration_release_gate_hidden" "PASS" "release gate keeps swarm.responsiveness hidden without executed campaign artifacts"
else
    scenario_result "swarm_calibration_release_gate_hidden" "FAIL" "calibration-only release gate did not fail closed"
fi

e2e_step "Scenario 9: synthetic xfstests and swarm execution ledgers validate"
XFSTESTS_LEDGER_STDOUT="$LOG_DIR/xfstests_ledger.stdout"
XFSTESTS_LEDGER_STDERR="$LOG_DIR/xfstests_ledger.stderr"
SWARM_LEDGER_STDOUT="$LOG_DIR/swarm_ledger.stdout"
SWARM_LEDGER_STDERR="$LOG_DIR/swarm_ledger.stderr"
if run_harness "permissioned_broker_xfstests_ledger" "$XFSTESTS_LEDGER_STDOUT" "$XFSTESTS_LEDGER_STDERR" \
    validate-permissioned-campaign-ledger \
    --manifest "$XFSTESTS_MANIFEST" \
    --ledger "$XFSTESTS_LEDGER_JSON" \
    --current-git-sha "$GIT_SHA" \
    --out "$XFSTESTS_LEDGER_REPORT_JSON" \
    --summary-out "$XFSTESTS_LEDGER_REPORT_MD" \
    && run_harness "permissioned_broker_swarm_ledger" "$SWARM_LEDGER_STDOUT" "$SWARM_LEDGER_STDERR" \
        validate-permissioned-campaign-ledger \
        --manifest "$SWARM_MANIFEST" \
        --ledger "$SWARM_LEDGER_JSON" \
        --current-git-sha "$GIT_SHA" \
        --out "$SWARM_LEDGER_REPORT_JSON" \
        --summary-out "$SWARM_LEDGER_REPORT_MD" \
    && jq -e '
        .valid == true
        and .final_status == "failed"
        and .cleanup_status == "preserved_artifacts"
        and .product_evidence_claim == "none"
    ' "$XFSTESTS_LEDGER_REPORT_JSON" >/dev/null \
    && jq -e '
        .valid == true
        and .final_status == "resumed"
        and .cleanup_status == "not_started"
        and (.proof_bundle_lane_candidates | length == 1)
    ' "$SWARM_LEDGER_REPORT_JSON" >/dev/null \
    && grep -q "Permissioned Campaign Execution Ledger" "$XFSTESTS_LEDGER_REPORT_MD"; then
    scenario_result "permissioned_broker_execution_ledgers_validate" "PASS" "synthetic xfstests and swarm ledgers validated"
else
    scenario_result "permissioned_broker_execution_ledgers_validate" "FAIL" "synthetic execution ledger validation failed"
fi

e2e_step "Scenario 10: dry-run packets cannot be promoted as pass evidence"
INVALID_LEDGER_STDOUT="$LOG_DIR/invalid_dry_run_pass_ledger.stdout"
INVALID_LEDGER_STDERR="$LOG_DIR/invalid_dry_run_pass_ledger.stderr"
set +e
run_harness "permissioned_broker_invalid_dry_run_ledger" "$INVALID_LEDGER_STDOUT" "$INVALID_LEDGER_STDERR" \
    validate-permissioned-campaign-ledger \
    --manifest "$XFSTESTS_MANIFEST" \
    --ledger "$INVALID_LEDGER_JSON" \
    --current-git-sha "$GIT_SHA" \
    --out "$INVALID_LEDGER_REPORT_JSON"
INVALID_LEDGER_STATUS=$?
set -e
if [[ "$INVALID_LEDGER_STATUS" -ne 0 ]] \
    && jq -e '.valid == false and (.issues | any(.code == "dry_run_packet_as_pass_evidence"))' "$INVALID_LEDGER_REPORT_JSON" >/dev/null; then
    scenario_result "permissioned_broker_invalid_dry_run_ledger_refused" "PASS" "dry-run pass-evidence ledger refused"
else
    scenario_result "permissioned_broker_invalid_dry_run_ledger_refused" "FAIL" "dry-run pass-evidence ledger was not refused"
fi

e2e_step "Scenario 11: missing inputs produce structured blocker artifacts"
if jq -e '
    .permissioned_execution_attempted == false
    and .cleanup_status == "not_started_dry_run"
    and (.missing_inputs | index("TEST_DIR"))
    and (.required_ack.env == "XFSTESTS_REAL_RUN_ACK")
    and (.artifact_paths | length >= 2)
' "$XFSTESTS_MISSING_INPUTS_JSON" >/dev/null \
    && jq -e '
        .permissioned_execution_attempted == false
        and .cleanup_status == "not_started_dry_run"
        and (.missing_inputs | index("FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER"))
        and (.missing_inputs | index(">=64 logical CPUs"))
        and (.required_ack.env == "FFS_SWARM_WORKLOAD_REAL_RUN_ACK")
        and (.artifact_paths | length >= 2)
    ' "$SWARM_MISSING_INPUTS_JSON" >/dev/null; then
    scenario_result "permissioned_broker_missing_inputs_blockers" "PASS" "missing input blocker artifacts are structured"
else
    scenario_result "permissioned_broker_missing_inputs_blockers" "FAIL" "missing input blocker artifact contract failed"
fi

e2e_step "Scenario 12: invalid manifest is refused before packet generation"
INVALID_STDOUT="$LOG_DIR/invalid_manifest.stdout"
INVALID_STDERR="$LOG_DIR/invalid_manifest.stderr"
set +e
run_harness "permissioned_broker_invalid_manifest_refused" "$INVALID_STDOUT" "$INVALID_STDERR" \
    validate-permissioned-campaign-broker \
    --manifest "$INVALID_MANIFEST" \
    --reference-timestamp "$REFERENCE_TIMESTAMP" \
    --out "$INVALID_REPORT_RAW"
INVALID_STATUS=$?
set -e
if [[ "$INVALID_STATUS" -ne 0 ]] && grep -q "permissioned campaign broker validation failed" "$INVALID_STDERR"; then
    scenario_result "permissioned_broker_invalid_manifest_refused" "PASS" "invalid missing ACK manifest refused"
else
    scenario_result "permissioned_broker_invalid_manifest_refused" "FAIL" "invalid manifest was not refused"
fi

e2e_step "Scenario 13: non-execution safety report and command transcript are complete"
if jq -e '
    .permissioned_execution_attempted == false
    and .mounted_workload_started == false
    and .large_host_runner_started == false
    and (.destructive_commands_started | length == 0)
    and (.allowed_commands_executed | index("validate-permissioned-campaign-broker"))
    and (.allowed_commands_executed | index("generate-permissioned-campaign-packet"))
    and (.allowed_commands_executed | index("validate-swarm-capability-calibration"))
    and (.allowed_commands_executed | index("evaluate-release-gates"))
' "$SAFETY_REPORT_JSON" >/dev/null \
    && [[ "$(wc -l <"$COMMAND_TRANSCRIPT")" -ge 8 ]] \
    && grep -q "validate-permissioned-campaign-broker" "$COMMAND_TRANSCRIPT" \
    && grep -q "generate-permissioned-campaign-packet" "$COMMAND_TRANSCRIPT" \
    && grep -q "validate-swarm-capability-calibration" "$COMMAND_TRANSCRIPT"; then
    scenario_result "permissioned_broker_non_execution_guard" "PASS" "safety report and command transcript prove dry-run-only execution"
else
    scenario_result "permissioned_broker_non_execution_guard" "FAIL" "non-execution safety guard failed"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    write_detailed_result "FAIL" "${PASS_COUNT}/${TOTAL} scenarios passed"
    e2e_fail "ffs_permissioned_campaign_broker failed: ${PASS_COUNT}/${TOTAL} scenarios passed"
fi

write_detailed_result "PASS" "${PASS_COUNT}/${TOTAL} scenarios passed"
e2e_pass
