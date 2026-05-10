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
        "lab_id" in obj or "simulation_id" in obj
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
RAW_JSON="$REPORT_DIR/valid_json_command.log"
RAW_MD="$REPORT_DIR/valid_markdown_command.log"
BAD_RAW="$REPORT_DIR/product_claim_command.log"
HOST_RAW_JSON="$REPORT_DIR/host_simulation_json_command.log"
HOST_RAW_MD="$REPORT_DIR/host_simulation_markdown_command.log"
UNIT_LOG="$REPORT_DIR/unit_tests.log"
REPORT_JSON="$REPORT_DIR/report.json"
REPORT_MD="$REPORT_DIR/report.md"
HOST_REPORT_JSON="$REPORT_DIR/host_simulation_report.json"
HOST_REPORT_MD="$REPORT_DIR/host_simulation_report.md"

mkdir -p "$FIXTURE_DIR" "$REPORT_DIR"

e2e_step "Scenario 1: CLI and module wiring are present"
if grep -q 'Some("validate-readiness-lab-contracts")' crates/ffs-harness/src/main.rs \
    && grep -q 'Some("simulate-readiness-lab-hosts")' crates/ffs-harness/src/main.rs \
    && grep -q "pub mod readiness_lab" crates/ffs-harness/src/lib.rs; then
    scenario_result "readiness_lab_cli_wired" "PASS" "CLI command and module export found"
else
    scenario_result "readiness_lab_cli_wired" "FAIL" "missing readiness lab command wiring"
fi

e2e_step "Scenario 2: synthetic advisory manifests are written"
if python3 - "$VALID_MANIFEST" "$BAD_MANIFEST" "$HOST_MANIFEST" <<'PY'
import copy
import json
import pathlib
import sys

valid_path, bad_path, host_path = map(pathlib.Path, sys.argv[1:])
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

e2e_step "Scenario 8: readiness_lab unit tests pass through RCH"
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
