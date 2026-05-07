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

run_harness() {
    local scenario_id="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    shift 3
    run_capture "$scenario_id" "$stdout_path" "$stderr_path" \
        cargo run --quiet -p ffs-harness -- "$@"
}

write_detailed_result() {
    local verdict="$1"
    local summary="$2"
    python3 - "$DETAILED_RESULT_JSON" "$verdict" "$summary" "$PASS_COUNT" "$FAIL_COUNT" "$TOTAL" \
        "$COMMAND_TRANSCRIPT" "$SAFETY_REPORT_JSON" "$XFSTESTS_PACKET_JSON" "$SWARM_PACKET_JSON" \
        "$SWARM_BLOCKER_PACKET_JSON" "$XFSTESTS_MISSING_INPUTS_JSON" "$SWARM_MISSING_INPUTS_JSON" <<'PY'
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
    xfstests_missing,
    swarm_missing,
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
    "blocker_artifacts": [
        xfstests_missing,
        swarm_missing,
    ],
}
pathlib.Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_permissioned_campaign_broker"
e2e_print_env

ARTIFACT_ROOT="$E2E_LOG_DIR/permissioned_campaign_broker"
E2E_LOG_REL="${E2E_LOG_DIR#"$REPO_ROOT"/}"
ARTIFACT_ROOT_REL="$E2E_LOG_REL/permissioned_campaign_broker"
MANIFEST_DIR="$ARTIFACT_ROOT/manifests"
REPORT_DIR="$ARTIFACT_ROOT/reports"
PACKET_DIR="$ARTIFACT_ROOT/packets"
BLOCKER_DIR="$ARTIFACT_ROOT/blockers"
LOG_DIR="$ARTIFACT_ROOT/logs"
mkdir -p "$MANIFEST_DIR" "$REPORT_DIR" "$PACKET_DIR" "$BLOCKER_DIR" "$LOG_DIR"

COMMAND_TRANSCRIPT="$ARTIFACT_ROOT/command_transcript.tsv"
DETAILED_RESULT_JSON="$ARTIFACT_ROOT/permissioned_campaign_broker_result.json"
SAFETY_REPORT_JSON="$ARTIFACT_ROOT/non_execution_safety_report.json"
FIXTURE_STDOUT="$LOG_DIR/write_fixtures.stdout"
FIXTURE_STDERR="$LOG_DIR/write_fixtures.stderr"

XFSTESTS_MANIFEST="$MANIFEST_DIR/xfstests_ready_manifest.json"
SWARM_MANIFEST="$MANIFEST_DIR/swarm_ready_manifest.json"
SWARM_BLOCKER_MANIFEST="$MANIFEST_DIR/swarm_blocker_manifest.json"
INVALID_MANIFEST="$MANIFEST_DIR/invalid_missing_ack_manifest.json"

XFSTESTS_REPORT_JSON="$REPORT_DIR/xfstests_ready_report.json"
XFSTESTS_REPORT_MD="$REPORT_DIR/xfstests_ready_report.md"
SWARM_REPORT_JSON="$REPORT_DIR/swarm_ready_report.json"
SWARM_REPORT_MD="$REPORT_DIR/swarm_ready_report.md"
SWARM_BLOCKER_REPORT_JSON="$REPORT_DIR/swarm_blocker_report.json"
SWARM_BLOCKER_REPORT_MD="$REPORT_DIR/swarm_blocker_report.md"
INVALID_REPORT_RAW="$REPORT_DIR/invalid_missing_ack.raw"

XFSTESTS_PACKET_JSON="$PACKET_DIR/xfstests_handoff_packet.json"
XFSTESTS_PACKET_MD="$PACKET_DIR/xfstests_handoff_packet.md"
SWARM_PACKET_JSON="$PACKET_DIR/swarm_handoff_packet.json"
SWARM_PACKET_MD="$PACKET_DIR/swarm_handoff_packet.md"
SWARM_BLOCKER_PACKET_JSON="$PACKET_DIR/swarm_blocker_handoff_packet.json"
SWARM_BLOCKER_PACKET_MD="$PACKET_DIR/swarm_blocker_handoff_packet.md"

XFSTESTS_MISSING_INPUTS_JSON="$BLOCKER_DIR/xfstests_missing_inputs.json"
SWARM_MISSING_INPUTS_JSON="$BLOCKER_DIR/swarm_missing_inputs.json"

printf 'created_at\tscenario_id\texit_status\tcommand\tstdout_path\tstderr_path\tworker_identity\n' >"$COMMAND_TRANSCRIPT"

e2e_step "Scenario 1: broker CLI is wired"
if grep -q "validate-permissioned-campaign-broker" crates/ffs-harness/src/main.rs \
    && grep -q "generate-permissioned-campaign-packet" crates/ffs-harness/src/main.rs \
    && grep -q "pub mod permissioned_campaign_broker" crates/ffs-harness/src/lib.rs; then
    scenario_result "permissioned_broker_cli_wired" "PASS" "validator and packet generator are exported"
else
    scenario_result "permissioned_broker_cli_wired" "FAIL" "missing broker CLI or module export"
fi

e2e_step "Scenario 2: fixture manifests and blocker artifacts are generated"
if run_capture "permissioned_broker_write_fixtures" "$FIXTURE_STDOUT" "$FIXTURE_STDERR" \
    python3 - "$REPO_ROOT" "$E2E_LOG_DIR" "$REFERENCE_TIMESTAMP" "$GIT_SHA" "$AGENT_NAME" <<'PY'
from __future__ import annotations

import json
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


invalid_manifest = dict(xfstests_manifest)
invalid_manifest["campaign_id"] = "bd-rchk3.3-invalid-missing-ack"
invalid_manifest["required_ack"] = dict(invalid_manifest["required_ack"])
invalid_manifest["required_ack"]["exact_value"] = ""

write_json(manifest_dir / "xfstests_ready_manifest.json", xfstests_manifest)
write_json(manifest_dir / "swarm_ready_manifest.json", swarm_manifest(True))
write_json(manifest_dir / "swarm_blocker_manifest.json", swarm_manifest(False))
write_json(manifest_dir / "invalid_missing_ack_manifest.json", invalid_manifest)

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
    "$INVALID_MANIFEST" \
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
    ' "$XFSTESTS_REPORT_JSON" >/dev/null \
    && jq -e '
        .product_evidence_claim == "none"
        and .packet_status == "ready_for_operator_approval"
        and (.authorization_notice | contains("not executed evidence"))
        and .required_ack.env_var == "XFSTESTS_REAL_RUN_ACK"
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

e2e_step "Scenario 7: missing inputs produce structured blocker artifacts"
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

e2e_step "Scenario 8: invalid manifest is refused before packet generation"
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

e2e_step "Scenario 9: non-execution safety report and command transcript are complete"
if jq -e '
    .permissioned_execution_attempted == false
    and .mounted_workload_started == false
    and .large_host_runner_started == false
    and (.destructive_commands_started | length == 0)
    and (.allowed_commands_executed | index("validate-permissioned-campaign-broker"))
    and (.allowed_commands_executed | index("generate-permissioned-campaign-packet"))
' "$SAFETY_REPORT_JSON" >/dev/null \
    && [[ "$(wc -l <"$COMMAND_TRANSCRIPT")" -ge 8 ]] \
    && grep -q "validate-permissioned-campaign-broker" "$COMMAND_TRANSCRIPT" \
    && grep -q "generate-permissioned-campaign-packet" "$COMMAND_TRANSCRIPT"; then
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
