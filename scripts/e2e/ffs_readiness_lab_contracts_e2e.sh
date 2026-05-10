#!/usr/bin/env bash
# ffs_readiness_lab_contracts_e2e.sh - advisory readiness-lab contract smoke.
#
# Builds synthetic non-permissioned readiness-lab manifests, validates JSON and
# Markdown output through RCH, and proves product evidence claims fail closed.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd -P)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_readiness_lab_contracts}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"

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
        RCH_VISIBILITY=none \
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
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
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

    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
        return 99
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
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and obj.get("schema_version") == 1 and (
        "lab_id" in obj
        or "simulation_id" in obj
        or "plan_id" in obj
        or "graph_id" in obj
        or "replay_id" in obj
    ):
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("readiness lab report JSON output not found")
PY
}

e2e_init "ffs_readiness_lab_contracts"

FIXTURE_DIR="$REPO_ROOT/artifacts/rch_e2e/$(basename "$E2E_LOG_DIR")/readiness_lab_contracts"
REPORT_DIR="$E2E_LOG_DIR/readiness_lab_contracts"
VALID_MANIFEST="$FIXTURE_DIR/valid_contracts.json"
BAD_MANIFEST="$FIXTURE_DIR/product_claim_contracts.json"
HOST_MANIFEST="$FIXTURE_DIR/host_simulation.json"
SCHEDULER_MANIFEST="$FIXTURE_DIR/rch_lane_schedule.json"
TRUTH_GRAPH_MANIFEST="$FIXTURE_DIR/truth_graph.json"
NUMA_REPLAY_MANIFEST="$FIXTURE_DIR/numa_p99_replay.json"
NUMA_REPLAY_BAD_MANIFEST="$FIXTURE_DIR/numa_p99_replay_product_claim.json"
RAW_JSON="$REPORT_DIR/valid_json_command.log"
RAW_MD="$REPORT_DIR/valid_markdown_command.log"
BAD_RAW="$REPORT_DIR/product_claim_command.log"
HOST_RAW_JSON="$REPORT_DIR/host_simulation_json_command.log"
HOST_RAW_MD="$REPORT_DIR/host_simulation_markdown_command.log"
SCHEDULER_RAW_JSON="$REPORT_DIR/rch_lane_schedule_json_command.log"
SCHEDULER_RAW_MD="$REPORT_DIR/rch_lane_schedule_markdown_command.log"
TRUTH_GRAPH_RAW_JSON="$REPORT_DIR/truth_graph_json_command.log"
TRUTH_GRAPH_RAW_MD="$REPORT_DIR/truth_graph_markdown_command.log"
NUMA_REPLAY_RAW_JSON="$REPORT_DIR/numa_p99_replay_json_command.log"
NUMA_REPLAY_RAW_MD="$REPORT_DIR/numa_p99_replay_markdown_command.log"
NUMA_REPLAY_BAD_RAW="$REPORT_DIR/numa_p99_replay_product_claim_command.log"
UNIT_LOG="$REPORT_DIR/unit_tests.log"
REPORT_JSON="$REPORT_DIR/report.json"
REPORT_MD="$REPORT_DIR/report.md"
HOST_REPORT_JSON="$REPORT_DIR/host_simulation_report.json"
HOST_REPORT_MD="$REPORT_DIR/host_simulation_report.md"
SCHEDULER_REPORT_JSON="$REPORT_DIR/rch_lane_schedule_report.json"
SCHEDULER_REPORT_MD="$REPORT_DIR/rch_lane_schedule_report.md"
TRUTH_GRAPH_REPORT_JSON="$REPORT_DIR/truth_graph_report.json"
TRUTH_GRAPH_REPORT_MD="$REPORT_DIR/truth_graph_report.md"
NUMA_REPLAY_REPORT_JSON="$REPORT_DIR/numa_p99_replay_report.json"
NUMA_REPLAY_REPORT_MD="$REPORT_DIR/numa_p99_replay_report.md"

mkdir -p "$FIXTURE_DIR" "$REPORT_DIR"

e2e_step "Scenario 1: CLI and module wiring are present"
if grep -q 'Some("validate-readiness-lab-contracts")' crates/ffs-harness/src/main.rs \
    && grep -q 'Some("simulate-readiness-lab-hosts")' crates/ffs-harness/src/main.rs \
    && grep -q 'Some("plan-readiness-lab-rch-lanes")' crates/ffs-harness/src/main.rs \
    && grep -q 'Some("build-readiness-lab-truth-graph")' crates/ffs-harness/src/main.rs \
    && grep -q 'Some("validate-readiness-lab-numa-p99-replay")' crates/ffs-harness/src/main.rs \
    && grep -q "pub mod readiness_lab" crates/ffs-harness/src/lib.rs; then
    scenario_result "readiness_lab_cli_wired" "PASS" "CLI command and module export found"
else
    scenario_result "readiness_lab_cli_wired" "FAIL" "missing readiness lab command wiring"
fi

e2e_step "Scenario 2: synthetic advisory manifests are written"
if python3 - "$VALID_MANIFEST" "$BAD_MANIFEST" "$HOST_MANIFEST" "$SCHEDULER_MANIFEST" "$TRUTH_GRAPH_MANIFEST" "$NUMA_REPLAY_MANIFEST" "$NUMA_REPLAY_BAD_MANIFEST" <<'PY'
import copy
import json
import pathlib
import sys

(
    valid_path,
    bad_path,
    host_path,
    scheduler_path,
    truth_graph_path,
    numa_replay_path,
    numa_replay_bad_path,
) = map(pathlib.Path, sys.argv[1:])
valid_path.parent.mkdir(parents=True, exist_ok=True)
manifest = {
    "schema_version": 1,
    "lab_id": "readiness-lab-e2e",
    "generated_at_epoch_days": 20000,
    "advisory_notice": "advisory readiness-lab material only; not product evidence",
    "artifacts": [
        {
            "artifact_id": "host-sim",
            "artifact_kind": "simulated_host_capability",
            "source_bead": "bd-4532j",
            "path": "artifacts/readiness-lab/host-sim.json",
            "product_evidence_claim": "none",
            "freshness": {
                "observed_at_epoch_days": 20000,
                "max_age_days": 7,
                "git_sha": "1234567",
                "host_class": "synthetic",
            },
            "required_fields": ["logical_cpus", "ram_gib", "numa_nodes"],
        },
        {
            "artifact_id": "rch-plan",
            "artifact_kind": "rch_scheduling_plan",
            "source_bead": "bd-hejjl",
            "path": "artifacts/readiness-lab/rch-plan.json",
            "product_evidence_claim": "advisory_only",
            "freshness": {
                "observed_at_epoch_days": 20000,
                "max_age_days": 7,
                "git_sha": "1234567",
                "host_class": "not_applicable",
            },
            "required_fields": ["command", "target_dir", "env_allowlist"],
        },
    ],
    "lane_plans": [
        {
            "lane_id": "swarm-simulation",
            "lane_kind": "large_host_swarm_simulation",
            "expected_artifact_ids": ["host-sim", "rch-plan"],
            "next_safe_command": "rch exec -- cargo run -p ffs-harness -- validate-readiness-lab-contracts",
            "permission_boundary": "no_permission_needed",
        }
    ],
    "rch_assumptions": [
        {
            "assumption_id": "harness-unit-tests",
            "command": "rch exec -- cargo test -p ffs-harness readiness_lab",
            "target_dir": "/data/tmp/rch_target_frankenfs_readiness_lab",
            "env_allowlist": ["CARGO_TARGET_DIR"],
            "executes_cargo": True,
            "local_fallback_allowed": False,
        }
    ],
}
valid_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
bad = copy.deepcopy(manifest)
bad["artifacts"][0]["product_evidence_claim"] = "product_pass_fail"
bad_path.write_text(json.dumps(bad, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def host(host_id, **updates):
    row = {
        "host_id": host_id,
        "observed_at_epoch_days": 20000,
        "max_age_days": 7,
        "logical_cpus": 64,
        "ram_total_gib": 256,
        "ram_available_gib": 220,
        "numa_topology_visible": True,
        "numa_nodes": 2,
        "storage_class": "local-nvme",
        "storage_visible": True,
        "fuse_available": True,
        "runner_configured": True,
        "swarm_ack_configured": True,
        "rch_worker_identity": "vmi-sim-64c-256gb",
        "worker_fingerprint": f"{host_id}-abcdef1",
        "queue_isolation": "dedicated",
        "target_dir_isolated": True,
        "target_dir": "artifacts/swarm/target",
        "artifact_root": "artifacts/swarm/large-host",
        "max_threads": 64,
        "max_memory_gib": 192,
        "max_temp_storage_gib": 256,
        "max_queue_depth": 32,
    }
    row.update(updates)
    return row

host_manifest = {
    "schema_version": 1,
    "simulation_id": "readiness-lab-host-simulation-e2e",
    "generated_at_epoch_days": 20000,
    "advisory_notice": "advisory readiness-lab material only; not product evidence",
    "source_bead": "bd-4532j",
    "real_campaign_bead": "bd-rchk0.53.8",
    "expected_artifact_root": "artifacts/swarm/large-host",
    "release_gate_policy_path": "artifacts/swarm/release_gate_policy.json",
    "hosts": [
        host("candidate"),
        host("small", logical_cpus=16, ram_total_gib=128, max_threads=16, max_memory_gib=96),
        host("numa-hidden", numa_topology_visible=False, numa_nodes=None),
        host("runner-missing", runner_configured=False, swarm_ack_configured=False),
        host("stale", observed_at_epoch_days=19900),
    ],
}
host_path.write_text(json.dumps(host_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def rch_command(target_dir, cargo_command):
    return (
        f"CARGO_TARGET_DIR={target_dir} "
        "RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR "
        f"rch exec -- {cargo_command}"
    )

check_target = "/data/tmp/rch_target_frankenfs_readiness_lab_check"
check_command = rch_command(check_target, "cargo check -p ffs-harness --all-targets")
scheduler_manifest = {
    "schema_version": 1,
    "plan_id": "readiness-lab-rch-scheduler-e2e",
    "generated_at_epoch_days": 20000,
    "advisory_notice": "advisory readiness-lab material only; not product evidence",
    "source_bead": "bd-hejjl",
    "artifact_root": "artifacts/readiness-lab/rch-schedule",
    "lanes": [
        {
            "lane_id": "check",
            "lane_kind": "cargo_check",
            "command": check_command,
            "dependencies": [],
            "target_dir": check_target,
            "artifact_path": "artifacts/readiness-lab/rch-schedule/check.json",
            "env_allowlist": ["CARGO_TARGET_DIR"],
            "estimated_cost_units": 2,
            "required_evidence_ids": ["rch-worker-fresh"],
            "worker_hint": "worker-a",
            "executes_cargo": True,
            "local_fallback_allowed": False,
        },
        {
            "lane_id": "test",
            "lane_kind": "cargo_test",
            "command": rch_command(
                "/data/tmp/rch_target_frankenfs_readiness_lab_test",
                "cargo test -p ffs-harness --lib readiness_lab",
            ),
            "dependencies": ["check"],
            "target_dir": "/data/tmp/rch_target_frankenfs_readiness_lab_test",
            "artifact_path": "artifacts/readiness-lab/rch-schedule/test.json",
            "env_allowlist": ["CARGO_TARGET_DIR"],
            "estimated_cost_units": 4,
            "required_evidence_ids": ["rch-worker-fresh"],
            "worker_hint": "worker-a",
            "executes_cargo": True,
            "local_fallback_allowed": False,
        },
        {
            "lane_id": "clippy",
            "lane_kind": "cargo_clippy",
            "command": rch_command(
                "/data/tmp/rch_target_frankenfs_readiness_lab_clippy",
                "cargo clippy -p ffs-harness --all-targets -- -D warnings",
            ),
            "dependencies": ["check"],
            "target_dir": "/data/tmp/rch_target_frankenfs_readiness_lab_clippy",
            "artifact_path": "artifacts/readiness-lab/rch-schedule/clippy.json",
            "env_allowlist": ["CARGO_TARGET_DIR"],
            "estimated_cost_units": 6,
            "required_evidence_ids": ["rch-worker-fresh"],
            "worker_hint": "worker-a",
            "executes_cargo": True,
            "local_fallback_allowed": False,
        },
        {
            "lane_id": "dashboard",
            "lane_kind": "readiness_dashboard",
            "command": rch_command(
                "/data/tmp/rch_target_frankenfs_readiness_lab_dashboard",
                "cargo run -p ffs-harness -- readiness-dashboard --format json",
            ),
            "dependencies": ["test", "clippy"],
            "target_dir": "/data/tmp/rch_target_frankenfs_readiness_lab_dashboard",
            "artifact_path": "artifacts/readiness-lab/rch-schedule/dashboard.json",
            "env_allowlist": ["CARGO_TARGET_DIR"],
            "estimated_cost_units": 3,
            "required_evidence_ids": ["rch-worker-fresh"],
            "worker_hint": "worker-a",
            "executes_cargo": True,
            "local_fallback_allowed": False,
        },
        {
            "lane_id": "check-copy",
            "lane_kind": "cargo_check",
            "command": check_command,
            "dependencies": [],
            "target_dir": check_target,
            "artifact_path": "artifacts/readiness-lab/rch-schedule/check.json",
            "env_allowlist": ["CARGO_TARGET_DIR"],
            "estimated_cost_units": 2,
            "required_evidence_ids": ["rch-worker-fresh"],
            "worker_hint": "worker-a",
            "executes_cargo": True,
            "local_fallback_allowed": False,
        },
    ],
    "evidence": [
        {
            "evidence_id": "rch-worker-fresh",
            "observed_at_epoch_days": 20000,
            "max_age_days": 7,
            "worker_identity": "vmi-sim",
            "rch_available": True,
            "detail": "fresh RCH scheduler evidence fixture",
        }
    ],
    "worker_hints": [
        {
            "worker_id": "worker-a",
            "logical_cpus": 32,
            "ram_gib": 128,
            "max_parallel_lanes": 4,
        }
    ],
}
scheduler_path.write_text(
    json.dumps(scheduler_manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

def truth_graph_claim(
    claim_id,
    state,
    product_claim,
    report_path,
    bead,
    observed,
    artifact_id,
    artifact_kind,
    raw_log_required=True,
    raw_log_present=True,
    host=None,
    blockers=None,
    permission=None,
):
    return {
        "claim_id": claim_id,
        "claim_state": state,
        "product_evidence_claim": product_claim,
        "validator_report_path": report_path,
        "source_bead": bead,
        "command": f"cat {report_path} && br show {bead} --no-db --json",
        "artifacts": [
            {
                "artifact_id": artifact_id,
                "artifact_kind": artifact_kind,
                "path": f"artifacts/readiness-lab/truth-graph/{artifact_id}.json",
                "raw_log_required": raw_log_required,
                "raw_log_present": raw_log_present,
            }
        ],
        "host": host,
        "freshness": {
            "observed_at_epoch_days": observed,
            "max_age_days": 7,
            "git_sha": "1234567",
            "host_class": "permissioned_large_host" if product_claim == "product_pass_fail" else "synthetic",
        },
        "blockers": blockers or [],
        "permission": permission,
        "supersedes_claim_ids": [],
    }

truth_graph_manifest = {
    "schema_version": 1,
    "graph_id": "readiness-lab-truth-graph-e2e",
    "generated_at_epoch_days": 20000,
    "advisory_notice": "advisory readiness-lab material only; not product evidence",
    "source_bead": "bd-xyypn",
    "sources": [
        {
            "source_id": "proof-old",
            "source_kind": "proof_bundle_report",
            "path": "artifacts/proof/old-report.json",
            "valid": True,
            "claims": [
                truth_graph_claim(
                    "swarm.responsiveness",
                    "validated",
                    "product_pass_fail",
                    "artifacts/proof/old-report.json",
                    "bd-rchk0.53.8",
                    19990,
                    "old-swarm-log",
                    "planned_workload_lane",
                )
            ],
        },
        {
            "source_id": "proof-fresh",
            "source_kind": "release_gate_report",
            "path": "artifacts/proof/fresh-release-gate.json",
            "valid": True,
            "claims": [
                truth_graph_claim(
                    "swarm.responsiveness",
                    "validated",
                    "product_pass_fail",
                    "artifacts/proof/fresh-release-gate.json",
                    "bd-rchk0.53.8",
                    20000,
                    "fresh-swarm-log",
                    "planned_workload_lane",
                )
            ],
        },
        {
            "source_id": "host-sim",
            "source_kind": "readiness_lab_report",
            "path": "artifacts/readiness-lab/host-simulation.json",
            "valid": True,
            "claims": [
                truth_graph_claim(
                    "swarm.capability.simulated",
                    "simulated",
                    "none",
                    "artifacts/readiness-lab/host-simulation.json",
                    "bd-4532j",
                    20000,
                    "host-simulation",
                    "simulated_host_capability",
                    raw_log_required=False,
                    raw_log_present=False,
                    host={
                        "host_id": "candidate-sim",
                        "host_class": "synthetic",
                        "logical_cpus": 64,
                        "ram_total_gib": 256,
                        "numa_topology_visible": True,
                    },
                )
            ],
        },
        {
            "source_id": "xfstests-handoff",
            "source_kind": "permissioned_campaign_packet",
            "path": "artifacts/readiness-lab/xfstests-handoff.json",
            "valid": True,
            "claims": [
                truth_graph_claim(
                    "xfstests.baseline",
                    "handoff_only",
                    "none",
                    "artifacts/readiness-lab/xfstests-handoff.json",
                    "bd-c7fqh",
                    20000,
                    "xfstests-handoff",
                    "permissioned_run_rehearsal",
                    raw_log_required=False,
                    raw_log_present=False,
                    blockers=[
                        {
                            "blocker_id": "operator-ack-missing",
                            "reason": "real xfstests run requires explicit operator ack",
                            "bead_id": "bd-rchk3",
                        }
                    ],
                    permission={
                        "permission_id": "xfstests-real-run-ack",
                        "boundary": "requires_xfstests_ack",
                        "bead_id": "bd-rchk3",
                        "ack_env": "XFSTESTS_REAL_RUN_ACK",
                    },
                )
            ],
        },
    ],
}
truth_graph_path.write_text(
    json.dumps(truth_graph_manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

def replay_components(dominant, p99):
    components = [
        "queueing",
        "service",
        "io",
        "synchronization",
        "allocator",
        "repair_backlog",
        "cache_pressure",
        "rch_worker_contention",
        "numa_remote_access",
        "memory_reclaim",
    ]
    rows = []
    for component in components:
        component_p99 = p99 * (0.32 if component == dominant else 0.06)
        rows.append(
            {
                "component": component,
                "p50_us": component_p99 / 4,
                "p95_us": component_p99 / 2,
                "p99_us": component_p99,
                "detail": f"synthetic {component} replay attribution",
            }
        )
    return rows

def replay_fixture(shape, dominant, p99, workers, hot_shards, repair, memory_pressure, queue_isolation="dedicated"):
    return {
        "fixture_id": f"fixture-{shape}",
        "fixture_shape": shape,
        "source_bead": "bd-w6nuy",
        "observed_at_epoch_days": 20000,
        "max_age_days": 7,
        "host": {
            "logical_cpus": 96,
            "numa_nodes": 4,
            "ram_total_gib": 384.0,
            "ram_available_gib": 300.0,
            "storage_class": "local-nvme",
            "rch_worker_identity": "synthetic-rch-large-host",
            "queue_isolation": queue_isolation,
        },
        "workload": {
            "operation_count": 250000,
            "duration_ms": 90000,
            "worker_count": workers,
            "hot_shard_count": hot_shards,
            "repair_scrub_active": repair,
            "memory_pressure_percent": memory_pressure,
        },
        "latency": {
            "p50_latency_us": p99 / 4,
            "p95_latency_us": p99 / 2,
            "p99_latency_us": p99,
            "attribution": replay_components(dominant, p99),
        },
        "queue_depth": {"average": 8.0, "p99": 28.0, "max": 64},
        "raw_log_path": f"artifacts/readiness-lab/numa-p99/{shape}.log",
        "reproduction_command": f"cargo run -p ffs-harness -- validate-readiness-lab-numa-p99-replay --select {shape}",
    }

numa_replay_manifest = {
    "schema_version": 1,
    "replay_id": "readiness-lab-numa-p99-e2e",
    "generated_at_epoch_days": 20000,
    "advisory_notice": "advisory readiness-lab material only; not product evidence",
    "source_bead": "bd-w6nuy",
    "product_evidence_claim": "none",
    "fixtures": [
        replay_fixture("balanced_numa", "service", 9000.0, 64, 16, False, 45),
        replay_fixture("skewed_numa", "numa_remote_access", 15000.0, 64, 8, False, 50),
        replay_fixture("metadata_read_hot_shards", "synchronization", 18000.0, 72, 2, False, 55),
        replay_fixture("repair_scrub_interference", "repair_backlog", 21000.0, 64, 12, True, 60),
        replay_fixture("rch_worker_contention", "rch_worker_contention", 24000.0, 48, 12, False, 62, "shared"),
        replay_fixture("memory_pressure", "memory_reclaim", 27000.0, 56, 10, True, 88),
    ],
}
numa_replay_path.write_text(
    json.dumps(numa_replay_manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
numa_bad = copy.deepcopy(numa_replay_manifest)
numa_bad["product_evidence_claim"] = "product_pass_fail"
numa_replay_bad_path.write_text(
    json.dumps(numa_bad, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
then
    scenario_result "readiness_lab_fixtures_written" "PASS" "valid and invalid manifests generated"
else
    scenario_result "readiness_lab_fixtures_written" "FAIL" "failed to generate manifests"
fi

e2e_step "Scenario 3: valid advisory manifest validates as JSON"
if run_rch_capture "$RAW_JSON" cargo run --quiet -p ffs-harness -- \
    validate-readiness-lab-contracts \
    --manifest "$VALID_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json \
    && extract_report_json "$RAW_JSON" "$REPORT_JSON" \
    && jq -e '.valid == true and .artifact_count == 2 and .advisory_artifact_count == 2 and .product_claim_violation_count == 0' "$REPORT_JSON" >/dev/null; then
    scenario_result "readiness_lab_valid_json" "PASS" "valid advisory manifest accepted"
else
    scenario_result "readiness_lab_valid_json" "FAIL" "valid advisory manifest rejected"
fi

e2e_step "Scenario 4: Markdown rendering names advisory boundaries"
if run_rch_capture "$RAW_MD" cargo run --quiet -p ffs-harness -- \
    validate-readiness-lab-contracts \
    --manifest "$VALID_MANIFEST" \
    --reference-epoch-days 20001 \
    --format markdown \
    && grep -q "FrankenFS Readiness Lab Contract Report" "$RAW_MD" \
    && grep -q "Product-claim violations: \`0\`" "$RAW_MD"; then
    cp "$RAW_MD" "$REPORT_MD"
    scenario_result "readiness_lab_markdown" "PASS" "markdown summary rendered"
else
    scenario_result "readiness_lab_markdown" "FAIL" "markdown summary missing expected content"
fi

e2e_step "Scenario 5: product pass/fail claims fail closed"
if run_rch_capture "$BAD_RAW" cargo run --quiet -p ffs-harness -- \
    validate-readiness-lab-contracts \
    --manifest "$BAD_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json; then
    scenario_result "readiness_lab_product_claim_rejected" "FAIL" "product evidence claim was accepted"
elif grep -q "product_evidence_claim_violation" "$BAD_RAW"; then
    scenario_result "readiness_lab_product_claim_rejected" "PASS" "product evidence claim rejected"
else
    scenario_result "readiness_lab_product_claim_rejected" "FAIL" "expected product-claim diagnostic missing"
fi

e2e_step "Scenario 6: synthetic host simulation renders JSON"
if run_rch_capture "$HOST_RAW_JSON" cargo run --quiet -p ffs-harness -- \
    simulate-readiness-lab-hosts \
    --manifest "$HOST_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json \
    && extract_report_json "$HOST_RAW_JSON" "$HOST_REPORT_JSON" \
    && jq -e '.valid == true and .product_evidence_claim == "none" and .candidate_count == 1 and .small_host_count == 1 and .capability_downgrade_count == 1 and .blocked_count == 2 and (.release_gate_effect | test("swarm.responsiveness remains hidden"))' "$HOST_REPORT_JSON" >/dev/null; then
    scenario_result "readiness_lab_host_simulation_json" "PASS" "synthetic host matrix classified as advisory"
else
    scenario_result "readiness_lab_host_simulation_json" "FAIL" "host simulation JSON missing expected classifications"
fi

e2e_step "Scenario 7: synthetic host simulation renders Markdown"
if run_rch_capture "$HOST_RAW_MD" cargo run --quiet -p ffs-harness -- \
    simulate-readiness-lab-hosts \
    --manifest "$HOST_MANIFEST" \
    --reference-epoch-days 20001 \
    --format markdown \
    && grep -q "FrankenFS Readiness Lab Host Simulation" "$HOST_RAW_MD" \
    && grep -q "Product evidence claim: \`none\`" "$HOST_RAW_MD" \
    && grep -q "swarm.responsiveness remains hidden" "$HOST_RAW_MD"; then
    cp "$HOST_RAW_MD" "$HOST_REPORT_MD"
    scenario_result "readiness_lab_host_simulation_markdown" "PASS" "synthetic host matrix markdown rendered"
else
    scenario_result "readiness_lab_host_simulation_markdown" "FAIL" "host simulation markdown missing advisory boundary"
fi

e2e_step "Scenario 8: RCH lane scheduler renders JSON without executing planned lanes"
if run_rch_capture "$SCHEDULER_RAW_JSON" cargo run --quiet -p ffs-harness -- \
    plan-readiness-lab-rch-lanes \
    --manifest "$SCHEDULER_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json \
    && extract_report_json "$SCHEDULER_RAW_JSON" "$SCHEDULER_REPORT_JSON" \
    && jq -e '.valid == true and .dry_run_only == true and .product_evidence_claim == "none" and .lane_count == 5 and .planned_lane_count == 4 and .coalesced_duplicate_count == 1 and .rows[0].lane_id == "check" and (.rows[] | select(.lane_id == "dashboard") | .dependencies == ["clippy", "test"])' "$SCHEDULER_REPORT_JSON" >/dev/null; then
    scenario_result "readiness_lab_rch_lane_schedule_json" "PASS" "RCH lane dry-run plan emitted without executing planned lanes"
else
    scenario_result "readiness_lab_rch_lane_schedule_json" "FAIL" "RCH lane schedule JSON missing expected dry-run plan"
fi

e2e_step "Scenario 9: RCH lane scheduler renders Markdown"
if run_rch_capture "$SCHEDULER_RAW_MD" cargo run --quiet -p ffs-harness -- \
    plan-readiness-lab-rch-lanes \
    --manifest "$SCHEDULER_MANIFEST" \
    --reference-epoch-days 20001 \
    --format markdown \
    && grep -q "FrankenFS Readiness Lab RCH Lane Schedule" "$SCHEDULER_RAW_MD" \
    && grep -q "Dry run only: \`true\`" "$SCHEDULER_RAW_MD" \
    && grep -q "Coalesced duplicates: \`1\`" "$SCHEDULER_RAW_MD"; then
    cp "$SCHEDULER_RAW_MD" "$SCHEDULER_REPORT_MD"
    scenario_result "readiness_lab_rch_lane_schedule_markdown" "PASS" "RCH lane dry-run markdown rendered"
else
    scenario_result "readiness_lab_rch_lane_schedule_markdown" "FAIL" "RCH lane schedule markdown missing expected content"
fi

e2e_step "Scenario 10: truth graph renders JSON with linked blockers"
if run_rch_capture "$TRUTH_GRAPH_RAW_JSON" cargo run --quiet -p ffs-harness -- \
    build-readiness-lab-truth-graph \
    --manifest "$TRUTH_GRAPH_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json \
    && extract_report_json "$TRUTH_GRAPH_RAW_JSON" "$TRUTH_GRAPH_REPORT_JSON" \
    && jq -e '.valid == true and .dry_run_only == true and .product_evidence_claim == "none" and .source_count == 4 and .stale_claim_count == 1 and .contradictory_claim_count == 0 and .permission_requirement_count == 1 and .simulated_node_count >= 2 and .blocker_edge_count >= 2 and ([.edges[] | select(.edge_kind == "blocks") | ((.validator_report_path // "") != "" or (.bead_id // "") != "")] | all) and ([.edges[] | select(.edge_kind == "supersedes")] | length >= 1)' "$TRUTH_GRAPH_REPORT_JSON" >/dev/null; then
    scenario_result "readiness_lab_truth_graph_json" "PASS" "truth graph emitted linked blocker and supersedes edges"
else
    scenario_result "readiness_lab_truth_graph_json" "FAIL" "truth graph JSON missing expected provenance edges"
fi

e2e_step "Scenario 11: truth graph renders Markdown"
if run_rch_capture "$TRUTH_GRAPH_RAW_MD" cargo run --quiet -p ffs-harness -- \
    build-readiness-lab-truth-graph \
    --manifest "$TRUTH_GRAPH_MANIFEST" \
    --reference-epoch-days 20001 \
    --format markdown \
    && grep -q "FrankenFS Readiness Lab Truth Graph" "$TRUTH_GRAPH_RAW_MD" \
    && grep -q "Product evidence claim: \`none\`" "$TRUTH_GRAPH_RAW_MD" \
    && grep -q "Permission requirements: \`1\`" "$TRUTH_GRAPH_RAW_MD"; then
    cp "$TRUTH_GRAPH_RAW_MD" "$TRUTH_GRAPH_REPORT_MD"
    scenario_result "readiness_lab_truth_graph_markdown" "PASS" "truth graph markdown rendered"
else
    scenario_result "readiness_lab_truth_graph_markdown" "FAIL" "truth graph markdown missing expected content"
fi

e2e_step "Scenario 12: NUMA/p99 replay fixture rollup renders JSON"
if run_rch_capture "$NUMA_REPLAY_RAW_JSON" cargo run --quiet -p ffs-harness -- \
    validate-readiness-lab-numa-p99-replay \
    --manifest "$NUMA_REPLAY_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json \
    && extract_report_json "$NUMA_REPLAY_RAW_JSON" "$NUMA_REPLAY_REPORT_JSON" \
    && jq -e '.valid == true and .replay_only == true and .product_evidence_claim == "none" and .fixture_count == 6 and .missing_shape_count == 0 and (.shape_counts | length == 6) and (.release_gate_effect | test("public readiness unchanged"))' "$NUMA_REPLAY_REPORT_JSON" >/dev/null; then
    scenario_result "readiness_lab_numa_p99_replay_json" "PASS" "NUMA/p99 replay JSON kept advisory-only claim state"
else
    scenario_result "readiness_lab_numa_p99_replay_json" "FAIL" "NUMA/p99 replay JSON missing advisory rollup"
fi

e2e_step "Scenario 13: NUMA/p99 replay fixture rollup renders Markdown"
if run_rch_capture "$NUMA_REPLAY_RAW_MD" cargo run --quiet -p ffs-harness -- \
    validate-readiness-lab-numa-p99-replay \
    --manifest "$NUMA_REPLAY_MANIFEST" \
    --reference-epoch-days 20001 \
    --format markdown \
    && grep -q "FrankenFS Readiness Lab NUMA/p99 Replay" "$NUMA_REPLAY_RAW_MD" \
    && grep -q "Product evidence claim: \`none\`" "$NUMA_REPLAY_RAW_MD" \
    && grep -q "public readiness unchanged" "$NUMA_REPLAY_RAW_MD"; then
    cp "$NUMA_REPLAY_RAW_MD" "$NUMA_REPLAY_REPORT_MD"
    scenario_result "readiness_lab_numa_p99_replay_markdown" "PASS" "NUMA/p99 replay markdown rendered"
else
    scenario_result "readiness_lab_numa_p99_replay_markdown" "FAIL" "NUMA/p99 replay markdown missing advisory boundary"
fi

e2e_step "Scenario 14: NUMA/p99 replay rejects product evidence claims"
if run_rch_capture "$NUMA_REPLAY_BAD_RAW" cargo run --quiet -p ffs-harness -- \
    validate-readiness-lab-numa-p99-replay \
    --manifest "$NUMA_REPLAY_BAD_MANIFEST" \
    --reference-epoch-days 20001 \
    --format json; then
    scenario_result "readiness_lab_numa_p99_product_claim_rejected" "FAIL" "NUMA/p99 product evidence claim was accepted"
elif grep -q "product_evidence_claim_violation" "$NUMA_REPLAY_BAD_RAW"; then
    scenario_result "readiness_lab_numa_p99_product_claim_rejected" "PASS" "NUMA/p99 product evidence claim rejected"
else
    scenario_result "readiness_lab_numa_p99_product_claim_rejected" "FAIL" "expected NUMA/p99 product-claim diagnostic missing"
fi

e2e_step "Scenario 15: readiness_lab unit tests pass through RCH"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib readiness_lab -- --nocapture; then
    scenario_result "readiness_lab_unit_tests" "PASS" "unit tests passed"
else
    scenario_result "readiness_lab_unit_tests" "FAIL" "unit tests failed"
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass "ffs_readiness_lab_contracts completed (${PASS_COUNT}/${TOTAL})"
else
    e2e_fail "ffs_readiness_lab_contracts failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
