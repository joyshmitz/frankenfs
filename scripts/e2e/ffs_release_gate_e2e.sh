#!/usr/bin/env bash
# ffs_release_gate_e2e.sh - smoke gate for bd-rchk0.5.6.1.
#
# Builds a proof bundle plus release-gate policy, proves passing gates emit
# generated public wording, and proves stale, missing, refused, noisy, and
# host-capability-limited evidence downgrades public feature state.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_release_gate}"
RCH_CAPTURE_VISIBILITY="${FFS_RELEASE_GATE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_RELEASE_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_RELEASE_GATE_SKIP_SELF_CHECK:-0}"

e2e_rch_add_env_allowlist CARGO_TARGET_DIR

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
pos = 0
while pos < len(text):
    idx = text.find("{", pos)
    if idx < 0:
        break
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        pos = idx + 1
        continue
    if seen == target_index:
        dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
        raise SystemExit(0)
    seen += 1
    pos = idx + end
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
start = text.find("# FrankenFS Release Gate")
if start < 0:
    raise SystemExit(f"release-gate markdown report not found in {source}")
end = text.find("\n[RCH]", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
dest.write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

extract_wording_tsv() {
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
lines = [
    line
    for line in text.splitlines()
    if line.count("\t") >= 3
    and not line.startswith("[RCH]")
    and not line.startswith("Remote command finished:")
    and not line.startswith("release gate ")
]
if not lines:
    raise SystemExit(f"release-gate wording TSV not found in {source}")
dest.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
PY
}

write_lane_status_variant() {
    local source_manifest="$1"
    local output_manifest="$2"
    local lane_id="$3"
    local status="$4"
    python3 - "$source_manifest" "$output_manifest" "$lane_id" "$status" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

source_path, output_path, lane_id, status = sys.argv[1:]
data = json.loads(pathlib.Path(source_path).read_text(encoding="utf-8"))
for lane in data["lanes"]:
    if lane["lane_id"] == lane_id:
        lane["status"] = status
        raw_log = pathlib.Path(data["lanes"][0]["raw_log_path"]).parent / f"{lane_id}.log"
        lane["raw_log_path"] = raw_log.as_posix()
        break
else:
    raise SystemExit(f"lane {lane_id} not found")
pathlib.Path(output_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_release_gate"

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_RELEASE_GATE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected release-gate fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        ;;
    *)
        echo "unknown release-gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0" >&2
    fi
    exit 0
}

finish_failure() {
    local status="$1"
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=${status}" >&2
    fi
    exit "$status"
}

emit_report() {
    local mode="$1"
    python3 - "$mode" <<'PY'
import json
import sys

mode = sys.argv[1]

def base_report(valid=True, release_ready=True):
    return {
        "valid": valid,
        "release_ready": release_ready,
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
        "feature_reports": [
            {"feature_id": "mount.rw.ext4", "final_state": "validated"},
            {"feature_id": "repair.rw.writeback", "final_state": "opt_in_mutating"},
            {"feature_id": "writeback_cache", "final_state": "opt_in_mutating"},
            {"feature_id": "swarm.responsiveness", "final_state": "validated"},
            {"feature_id": "background_scrub_mutation", "final_state": "detection_only"},
        ],
        "findings": [],
    }

report = base_report()

if mode == "missing":
    report = base_report(valid=False, release_ready=False)
    report["findings"] = [{"finding_id": "missing_required_lane.release_gates"}]
elif mode == "stale":
    report = base_report(valid=False, release_ready=False)
    report["findings"] = [{"finding_id": "stale_evidence.git_sha"}]
elif mode == "threshold":
    report = base_report(valid=False, release_ready=False)
    report["findings"] = [{"finding_id": "threshold_failure.pass_lanes"}]
elif mode == "hostile":
    report = base_report(valid=False, release_ready=False)
    report["feature_reports"][0]["final_state"] = "disabled"
    report["findings"] = [
        {"finding_id": "security_refused.conformance", "remediation_id": "bd-rchk0.5.6.1"}
    ]
elif mode == "unsafe_repair":
    report = base_report(valid=False, release_ready=False)
    report["feature_reports"][1]["final_state"] = "detection_only"
    report["findings"] = [
        {"finding_id": "unsafe_repair_refused.repair_lab", "remediation_id": "bd-rchk0.5.6.1"}
    ]
elif mode == "noisy":
    report = base_report(valid=False, release_ready=False)
    report["feature_reports"][2]["final_state"] = "experimental"
    report["findings"] = [
        {"finding_id": "noisy_performance.performance", "remediation_id": "bd-rchk0.5.6.1"}
    ]
elif mode == "capability":
    report = base_report(valid=True, release_ready=False)
    report["feature_reports"][0]["final_state"] = "experimental"
    report["findings"] = [
        {
            "finding_id": "host_capability_skip.fuse",
            "severity": "warn",
            "remediation_id": "bd-rchk0.5.6.1",
        }
    ]

print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_wording_tsv() {
    printf '%s\n' \
        $'readme.mount.rw.ext4\tmount.rw.ext4\texperimental\tvalidated\tvalidated read-write mount support' \
        $'readme.repair.rw.writeback\trepair.rw.writeback\tdisabled\topt_in_mutating\trepair writeback is opt-in mutating' \
        $'readme.writeback_cache\twriteback_cache\tdisabled\topt_in_mutating\twriteback cache remains opt-in mutating' \
        $'feature_parity.swarm_responsiveness\tswarm.responsiveness\tdisabled\tvalidated\tswarm responsiveness validated'
}

emit_markdown_report() {
    cat <<'MD'
# FrankenFS Release Gate

Fresh release-gate evidence is valid.

## Feature States

- mount.rw.ext4: validated
- repair.rw.writeback: opt_in_mutating
- writeback_cache: opt_in_mutating
- swarm.responsiveness: validated
- background_scrub_mutation: detection_only
MD
}

case "$command_text" in
    *"cargo test -p ffs-harness --lib release_gate"*)
        printf '%s\n' \
            "running 33 tests" \
            "test release_gate::tests::sample_policy_passes ... ok" \
            "test release_gate::tests::missing_required_lane_fails_closed ... ok" \
            "test release_gate::tests::host_capability_skip_downgrades ... ok" \
            "test result: ok. 33 passed; 0 failed; 0 ignored"
        finish_success
        ;;
    *"release_gate_missing_lane.json"*)
        echo "release gate evaluation failed"
        emit_report "missing"
        finish_failure 1
        ;;
    *"stale-sha-for-release-gate"*)
        echo "release gate evaluation failed"
        emit_report "stale"
        finish_failure 1
        ;;
    *"release_gate_threshold_fail_policy.json"*)
        echo "release gate evaluation failed"
        emit_report "threshold"
        finish_failure 1
        ;;
    *"release_gate_hostile_image.json"*)
        emit_report "hostile"
        finish_failure 1
        ;;
    *"release_gate_unsafe_repair.json"*)
        emit_report "unsafe_repair"
        finish_failure 1
        ;;
    *"release_gate_noisy_performance.json"*)
        emit_report "noisy"
        finish_failure 1
        ;;
    *"release_gate_host_capability_skip.json"*)
        emit_report "capability"
        finish_success
        ;;
    *"evaluate-release-gates"*"--wording-out /dev/stdout"*)
        emit_wording_tsv
        finish_success
        ;;
    *"evaluate-release-gates"*"--format markdown"*)
        emit_markdown_report
        finish_success
        ;;
    *"evaluate-release-gates"*)
        emit_report "valid"
        finish_success
        ;;
    *)
        echo "unexpected release-gate fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/release_gate_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_RELEASE_GATE_SELF_CHECK=0 \
        FFS_RELEASE_GATE_SKIP_SELF_CHECK=1 \
        FFS_RELEASE_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_release_gate_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic release gate wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-release-gate-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "release_gate_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_sample_passes" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_generated_wording" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_missing_evidence_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_stale_evidence_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_threshold_failure_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_hostile_image_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_unsafe_repair_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_noisy_performance_downgrades" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_host_capability_skip_downgrades" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "release_gate_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "release_gate_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "release_gate_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "release_gate_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "release_gate_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "release_gate_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "release_gate_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

GIT_SHA="$(git rev-parse HEAD)"
RCH_OUTPUT_DIR="$REPO_ROOT/artifacts/rch/release_gate/$(basename "$E2E_LOG_DIR")"
BUNDLE_DIR="$RCH_OUTPUT_DIR/release_gate_bundle"
MANIFEST_JSON="$BUNDLE_DIR/manifest.json"
POLICY_JSON="$BUNDLE_DIR/release_gate_policy.json"
REPORT_JSON="$E2E_LOG_DIR/release_gate_report.json"
SUMMARY_MD="$E2E_LOG_DIR/release_gate_summary.md"
WORDING_TSV="$E2E_LOG_DIR/release_gate_wording.tsv"
VALIDATE_RAW="$E2E_LOG_DIR/release_gate_validate.raw"
WORDING_RAW="$E2E_LOG_DIR/release_gate_wording.raw"
SUMMARY_RAW="$E2E_LOG_DIR/release_gate_summary.raw"
MISSING_MANIFEST="$BUNDLE_DIR/release_gate_missing_lane.json"
MISSING_REPORT="$E2E_LOG_DIR/release_gate_missing_lane_report.json"
MISSING_RAW="$E2E_LOG_DIR/release_gate_missing_lane.raw"
STALE_REPORT="$E2E_LOG_DIR/release_gate_stale_report.json"
STALE_RAW="$E2E_LOG_DIR/release_gate_stale.raw"
THRESHOLD_POLICY="$BUNDLE_DIR/release_gate_threshold_fail_policy.json"
THRESHOLD_REPORT="$E2E_LOG_DIR/release_gate_threshold_fail_report.json"
THRESHOLD_RAW="$E2E_LOG_DIR/release_gate_threshold_fail.raw"
HOSTILE_MANIFEST="$BUNDLE_DIR/release_gate_hostile_image.json"
HOSTILE_REPORT="$E2E_LOG_DIR/release_gate_hostile_image_report.json"
HOSTILE_RAW="$E2E_LOG_DIR/release_gate_hostile_image.raw"
UNSAFE_REPAIR_MANIFEST="$BUNDLE_DIR/release_gate_unsafe_repair.json"
UNSAFE_REPAIR_REPORT="$E2E_LOG_DIR/release_gate_unsafe_repair_report.json"
UNSAFE_REPAIR_RAW="$E2E_LOG_DIR/release_gate_unsafe_repair.raw"
NOISY_PERFORMANCE_MANIFEST="$BUNDLE_DIR/release_gate_noisy_performance.json"
NOISY_PERFORMANCE_REPORT="$E2E_LOG_DIR/release_gate_noisy_performance_report.json"
NOISY_PERFORMANCE_RAW="$E2E_LOG_DIR/release_gate_noisy_performance.raw"
CAPABILITY_MANIFEST="$BUNDLE_DIR/release_gate_host_capability_skip.json"
CAPABILITY_POLICY="$BUNDLE_DIR/release_gate_host_capability_skip_policy.json"
CAPABILITY_REPORT="$E2E_LOG_DIR/release_gate_host_capability_skip_report.json"
CAPABILITY_RAW="$E2E_LOG_DIR/release_gate_host_capability_skip.raw"
UNIT_LOG="$E2E_LOG_DIR/release_gate_unit_tests.log"

mkdir -p "$BUNDLE_DIR"

e2e_step "Scenario 1: release gate module and CLI are wired"
if grep -q "pub mod release_gate" crates/ffs-harness/src/lib.rs \
    && grep -q "evaluate-release-gates" crates/ffs-harness/src/main.rs; then
    scenario_result "release_gate_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "release_gate_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: sample policy and proof bundle pass"
if python3 - "$BUNDLE_DIR" "$MANIFEST_JSON" "$POLICY_JSON" "$GIT_SHA" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

bundle_dir = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
policy_path = pathlib.Path(sys.argv[3])
git_sha = sys.argv[4]

lanes = [
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
    "adaptive_runtime",
]

records = []
for lane in lanes:
    raw_log = pathlib.Path("logs") / f"{lane}.log"
    summary = pathlib.Path("summaries") / f"{lane}.md"
    gate_input = pathlib.Path("inputs") / f"{lane}.json"
    artifact = pathlib.Path("artifacts") / f"{lane}.json"
    p99_artifact = pathlib.Path("artifacts") / f"{lane}_p99_attribution.json"
    runner_artifact = pathlib.Path("artifacts") / f"{lane}_runner.json"
    payloads = [
        (raw_log, f"lane={lane}\nstatus=pass\n"),
        (summary, f"# {lane}\n\nRelease gate sample summary.\n"),
        (gate_input, json.dumps({"lane": lane, "gate": "bd-rchk0.5.6.1"}, sort_keys=True) + "\n"),
        (artifact, json.dumps({"lane": lane, "artifact": "release_gate"}, sort_keys=True) + "\n"),
    ]
    for relative, text in payloads:
        path = bundle_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    raw_log_digest = hashlib.sha256((bundle_dir / raw_log).read_bytes()).hexdigest()
    digest = hashlib.sha256((bundle_dir / artifact).read_bytes()).hexdigest()
    artifacts = [
        {
            "path": artifact.as_posix(),
            "sha256": digest,
            "redacted": False,
            "role": (
                "adaptive_runtime_validator_report"
                if lane == "adaptive_runtime"
                else "swarm_validator_report"
                if lane in {"swarm_workload_harness", "swarm_tail_latency"}
                else "release_gate_evidence"
            ),
        }
    ]
    metadata = {}
    if lane in {"swarm_workload_harness", "swarm_tail_latency"}:
        metadata = {
            "freshness": "fresh",
            "host_class": "permissioned_large_host",
            "manifest_hash": "b" * 64,
            "release_claim": "authoritative_large_host",
            "validator_report": artifact.as_posix(),
        }
    if lane == "swarm_tail_latency":
        p99_payload = {"lane": lane, "artifact": "p99_attribution"}
        p99_path = bundle_dir / p99_artifact
        p99_path.parent.mkdir(parents=True, exist_ok=True)
        p99_path.write_text(json.dumps(p99_payload, sort_keys=True) + "\n", encoding="utf-8")
        p99_digest = hashlib.sha256(p99_path.read_bytes()).hexdigest()
        metadata["p99_attribution_artifact"] = p99_artifact.as_posix()
        artifacts.append(
            {
                "path": p99_artifact.as_posix(),
                "sha256": p99_digest,
                "redacted": False,
                "role": "p99_attribution_ledger",
            }
        )
    if lane == "adaptive_runtime":
        runner_payload = {"lane": lane, "artifact": "adaptive_runtime_runner"}
        runner_path = bundle_dir / runner_artifact
        runner_path.parent.mkdir(parents=True, exist_ok=True)
        runner_path.write_text(json.dumps(runner_payload, sort_keys=True) + "\n", encoding="utf-8")
        runner_digest = hashlib.sha256(runner_path.read_bytes()).hexdigest()
        metadata = {
            "scenario_id": "adaptive_runtime_accepted_large_host",
            "run_id": "adaptive-runtime-run-20260508T000000Z",
            "freshness": "fresh",
            "release_claim_state": "accepted_large_host",
            "host_classification": "accepted_large_host",
            "cleanup_status": "clean",
            "validator_report": artifact.as_posix(),
            "runner_report": runner_artifact.as_posix(),
        }
        artifacts.append(
            {
                "path": runner_artifact.as_posix(),
                "sha256": runner_digest,
                "redacted": False,
                "role": "adaptive_runtime_runner_report",
            }
        )
    records.append(
        {
            "lane_id": lane,
            "status": "pass",
            "raw_log_path": raw_log.as_posix(),
            "raw_log_sha256": raw_log_digest,
            "summary_path": summary.as_posix(),
            "scenario_ids": [f"{lane}_release_gate_primary"],
            "gate_inputs": [gate_input.as_posix()],
            "artifacts": artifacts,
            "metadata": metadata,
        }
    )

manifest = {
    "schema_version": 1,
    "bundle_id": "bd-rchk0.5.6.1-release-gate-bundle",
    "generated_at": "2026-05-01T00:00:00Z",
    "git_sha": git_sha,
    "toolchain": "rust-nightly-2024",
    "kernel": "linux-release-gate-e2e",
    "mount_capability": "available",
    "required_lanes": lanes,
    "lanes": records,
    "redaction": {
        "redacted_fields": ["hostname", "token"],
        "preserved_fields": [
            "reproduction_command",
            "git_sha",
            "bundle_id",
            "artifact_paths",
            "scenario_ids",
        ],
        "reproduction_command": (
            "cargo run -p ffs-harness -- validate-proof-bundle "
            "--bundle release_gate_bundle/manifest.json"
        ),
    },
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def required_lane(
    lane: str,
    *,
    risk_class: str = "generic",
    failed_state: str = "disabled",
    skipped_state: str = "experimental",
    allow_capability_skip: bool = True,
) -> dict[str, object]:
    return {
        "lane_id": lane,
        "expected_outcome": "pass",
        "missing_state": "hidden",
        "failed_state": failed_state,
        "risk_class": risk_class,
        "skipped_state": skipped_state,
        "allow_capability_skip": allow_capability_skip,
        "remediation_id": "bd-rchk0.5.6.1",
    }

def required_lane_for_feature(feature_id: str, lane: str) -> dict[str, object]:
    if feature_id == "mount.rw.ext4" and lane == "conformance":
        return required_lane(lane, risk_class="security_refused", failed_state="disabled")
    if feature_id == "mount.rw.ext4" and lane == "fuse":
        return required_lane(
            lane,
            risk_class="host_capability_skip",
            failed_state="hidden",
            skipped_state="experimental",
        )
    if feature_id == "repair.rw.writeback" and lane == "repair_lab":
        return required_lane(
            lane,
            risk_class="unsafe_repair_refused",
            failed_state="detection_only",
        )
    if feature_id == "writeback_cache" and lane == "performance":
        return required_lane(lane, risk_class="noisy_performance", failed_state="experimental")
    if feature_id == "swarm.responsiveness" and lane == "swarm_workload_harness":
        return required_lane(
            lane,
            risk_class="host_capability_skip",
            failed_state="experimental",
        )
    if feature_id == "swarm.responsiveness" and lane == "swarm_tail_latency":
        return required_lane(
            lane,
            risk_class="noisy_performance",
            failed_state="experimental",
        )
    return required_lane(lane)

def feature(feature_id: str, docs_id: str, previous: str, target: str, feature_lanes: list[str]) -> dict[str, object]:
    return {
        "feature_id": feature_id,
        "docs_wording_id": docs_id,
        "previous_state": previous,
        "target_state": target,
        "required_lanes": [required_lane_for_feature(feature_id, lane) for lane in feature_lanes],
        "thresholds": [
            {
                "metric": "pass_lanes",
                "comparator": "at_least",
                "value": 9,
                "downgrade_to": "experimental",
                "remediation_id": "bd-rchk0.5.6.1",
            },
            {
                "metric": "error_lanes",
                "comparator": "at_most",
                "value": 0,
                "downgrade_to": "disabled",
                "remediation_id": "bd-rchk0.5.6.1",
            },
        ],
        "kill_switches": [
            {
                "switch_id": "stale-evidence",
                "trigger": "stale_evidence",
                "downgrade_to": "disabled",
                "reason": "stale evidence cannot upgrade public release status",
                "remediation_id": "bd-rchk0.5.6.1",
            },
            {
                "switch_id": "missing-evidence",
                "trigger": "any_required_lane_missing",
                "downgrade_to": "hidden",
                "reason": "missing required lane hides public claim",
                "remediation_id": "bd-rchk0.5.6.1",
            },
        ],
        "remediation_id": "bd-rchk0.5.6.1",
    }

policy = {
    "schema_version": 1,
    "policy_id": "bd-rchk0.5.6.1-release-gates",
    "reproduction_command": (
        "cargo run -p ffs-harness -- evaluate-release-gates "
        "--bundle release_gate_bundle/manifest.json "
        "--policy release_gate_bundle/release_gate_policy.json"
    ),
    "required_log_fields": [],
    "features": [
        feature("mount.rw.ext4", "readme.mount.rw.ext4", "experimental", "validated", ["fuse", "release_gates", "conformance"]),
        feature("repair.rw.writeback", "readme.repair.rw.writeback", "disabled", "opt_in_mutating", ["repair_lab", "release_gates", "crash_replay"]),
        feature("writeback_cache", "readme.writeback_cache", "disabled", "opt_in_mutating", ["writeback_cache", "release_gates", "performance"]),
        feature("swarm.responsiveness", "feature_parity.swarm_responsiveness", "disabled", "validated", ["swarm_workload_harness", "swarm_tail_latency", "release_gates"]),
        feature("background_scrub_mutation", "readme.background_scrub_mutation", "detection_only", "detection_only", ["repair_lab", "release_gates"]),
    ],
}
policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
then
    if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
        --bundle "$MANIFEST_JSON" \
        --policy "$POLICY_JSON" \
        --current-git-sha "$GIT_SHA" \
        --max-age-days 10000 \
        && extract_json_object "$VALIDATE_RAW" "$REPORT_JSON" \
        && run_rch_capture "$WORDING_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
            --bundle "$MANIFEST_JSON" \
            --policy "$POLICY_JSON" \
            --current-git-sha "$GIT_SHA" \
            --max-age-days 10000 \
            --out /dev/null \
            --wording-out /dev/stdout \
        && extract_wording_tsv "$WORDING_RAW" "$WORDING_TSV" \
        && run_rch_capture "$SUMMARY_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
            --bundle "$MANIFEST_JSON" \
            --policy "$POLICY_JSON" \
            --current-git-sha "$GIT_SHA" \
            --max-age-days 10000 \
            --format markdown \
        && extract_markdown_report "$SUMMARY_RAW" "$SUMMARY_MD"; then
        printf 'release gate report written: %s\nrelease gate wording written: %s\n' "$REPORT_JSON" "$WORDING_TSV" >>"$VALIDATE_RAW"
        scenario_result "release_gate_sample_passes" "PASS" "release gate accepted fresh sample evidence"
    else
        scenario_result "release_gate_sample_passes" "FAIL" "release gate rejected fresh sample evidence"
    fi
else
    scenario_result "release_gate_sample_passes" "FAIL" "failed to generate release gate fixtures"
fi

e2e_step "Scenario 3: generated public wording comes from policy data"
if python3 - "$REPORT_JSON" "$WORDING_TSV" "$VALIDATE_RAW" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
wording = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
raw = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
if not report["valid"] or not report["release_ready"]:
    raise SystemExit("passing report is not release-ready")
states = {row["feature_id"]: row["final_state"] for row in report["feature_reports"]}
expected = {
    "mount.rw.ext4": "validated",
    "repair.rw.writeback": "opt_in_mutating",
    "writeback_cache": "opt_in_mutating",
    "swarm.responsiveness": "validated",
    "background_scrub_mutation": "detection_only",
}
if states != expected:
    raise SystemExit(f"unexpected states: {states}")
for field in [
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
]:
    if field not in report["required_log_fields"]:
        raise SystemExit(f"missing required log field {field}")
for output_name in ["release_gate_report.json", "release_gate_wording.tsv"]:
    if output_name not in raw:
        raise SystemExit(f"CLI log did not include output path for {output_name}")
if "readme.writeback_cache" not in wording or "opt-in mutating" not in wording:
    raise SystemExit("wording TSV did not preserve generated docs-safe wording")
PY
then
    scenario_result "release_gate_generated_wording" "PASS" "wording and required logs verified"
else
    scenario_result "release_gate_generated_wording" "FAIL" "generated wording contract failed"
fi

e2e_step "Scenario 4: missing required lane fails closed"
python3 - "$MANIFEST_JSON" "$MISSING_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"] = [lane for lane in data["lanes"] if lane["lane_id"] != "release_gates"]
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$MISSING_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$MISSING_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "release_gate_missing_evidence_rejected" "FAIL" "missing lane was accepted"
elif extract_json_object "$MISSING_RAW" "$MISSING_REPORT" \
    && grep -q "release gate evaluation failed" "$MISSING_RAW" \
    && grep -q "missing_required_lane" "$MISSING_REPORT"; then
    scenario_result "release_gate_missing_evidence_rejected" "PASS" "missing evidence failed closed"
else
    scenario_result "release_gate_missing_evidence_rejected" "FAIL" "missing evidence failed without expected diagnostics"
fi

e2e_step "Scenario 5: stale proof bundle fails closed"
if run_rch_capture "$STALE_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$MANIFEST_JSON" \
    --policy "$POLICY_JSON" \
    --current-git-sha "stale-sha-for-release-gate" \
    --max-age-days 10000; then
    scenario_result "release_gate_stale_evidence_rejected" "FAIL" "stale SHA was accepted"
elif extract_json_object "$STALE_RAW" "$STALE_REPORT" \
    && grep -q "release gate evaluation failed" "$STALE_RAW" \
    && grep -q "stale_evidence" "$STALE_REPORT"; then
    scenario_result "release_gate_stale_evidence_rejected" "PASS" "stale evidence failed closed"
else
    scenario_result "release_gate_stale_evidence_rejected" "FAIL" "stale evidence failed without expected diagnostics"
fi

e2e_step "Scenario 6: threshold failure fails closed"
python3 - "$POLICY_JSON" "$THRESHOLD_POLICY" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

policy_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(policy_path).read_text(encoding="utf-8"))
for feature in data["features"]:
    for threshold in feature["thresholds"]:
        if threshold["metric"] == "pass_lanes":
            threshold["value"] = 99
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$THRESHOLD_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$MANIFEST_JSON" \
    --policy "$THRESHOLD_POLICY" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "release_gate_threshold_failure_rejected" "FAIL" "threshold failure was accepted"
elif extract_json_object "$THRESHOLD_RAW" "$THRESHOLD_REPORT" \
    && grep -q "release gate evaluation failed" "$THRESHOLD_RAW" \
    && grep -q "threshold_failure" "$THRESHOLD_REPORT"; then
    scenario_result "release_gate_threshold_failure_rejected" "PASS" "threshold failure failed closed"
else
    scenario_result "release_gate_threshold_failure_rejected" "FAIL" "threshold failure lacked expected diagnostic"
fi

e2e_step "Scenario 7: hostile image/security refusal fails closed"
write_lane_status_variant "$MANIFEST_JSON" "$HOSTILE_MANIFEST" "conformance" "fail"
if run_rch_capture "$HOSTILE_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$HOSTILE_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "release_gate_hostile_image_rejected" "FAIL" "security-refused hostile image was accepted"
elif extract_json_object "$HOSTILE_RAW" "$HOSTILE_REPORT" \
    && python3 - "$HOSTILE_REPORT" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
states = {row["feature_id"]: row["final_state"] for row in report["feature_reports"]}
if states.get("mount.rw.ext4") != "disabled":
    raise SystemExit(f"mount.rw.ext4 was not disabled: {states.get('mount.rw.ext4')}")
if not any(
    "security_refused" in finding["finding_id"]
    and finding.get("remediation_id") == "bd-rchk0.5.6.1"
    for finding in report["findings"]
):
    raise SystemExit("security_refused finding with remediation was not emitted")
PY
then
    scenario_result "release_gate_hostile_image_rejected" "PASS" "security refusal disabled hostile-image readiness"
else
    scenario_result "release_gate_hostile_image_rejected" "FAIL" "security refusal lacked expected public state or remediation"
fi

e2e_step "Scenario 8: unsafe repair refusal downgrades mutation to detection-only"
write_lane_status_variant "$MANIFEST_JSON" "$UNSAFE_REPAIR_MANIFEST" "repair_lab" "fail"
if run_rch_capture "$UNSAFE_REPAIR_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$UNSAFE_REPAIR_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "release_gate_unsafe_repair_rejected" "FAIL" "unsafe repair refusal was accepted"
elif extract_json_object "$UNSAFE_REPAIR_RAW" "$UNSAFE_REPAIR_REPORT" \
    && python3 - "$UNSAFE_REPAIR_REPORT" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
states = {row["feature_id"]: row["final_state"] for row in report["feature_reports"]}
if states.get("repair.rw.writeback") != "detection_only":
    raise SystemExit(f"repair.rw.writeback was not detection-only: {states.get('repair.rw.writeback')}")
if not any(
    "unsafe_repair_refused" in finding["finding_id"]
    and finding.get("remediation_id") == "bd-rchk0.5.6.1"
    for finding in report["findings"]
):
    raise SystemExit("unsafe_repair_refused finding with remediation was not emitted")
PY
then
    scenario_result "release_gate_unsafe_repair_rejected" "PASS" "unsafe repair refusal downgraded mutation to detection-only"
else
    scenario_result "release_gate_unsafe_repair_rejected" "FAIL" "unsafe repair refusal lacked expected public state or remediation"
fi

e2e_step "Scenario 9: noisy performance evidence downgrades readiness"
write_lane_status_variant "$MANIFEST_JSON" "$NOISY_PERFORMANCE_MANIFEST" "performance" "fail"
if run_rch_capture "$NOISY_PERFORMANCE_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$NOISY_PERFORMANCE_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "release_gate_noisy_performance_downgrades" "FAIL" "noisy performance was accepted"
elif extract_json_object "$NOISY_PERFORMANCE_RAW" "$NOISY_PERFORMANCE_REPORT" \
    && python3 - "$NOISY_PERFORMANCE_REPORT" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
states = {row["feature_id"]: row["final_state"] for row in report["feature_reports"]}
if states.get("writeback_cache") != "experimental":
    raise SystemExit(f"writeback_cache was not experimental: {states.get('writeback_cache')}")
if not any(
    "noisy_performance" in finding["finding_id"]
    and finding.get("remediation_id") == "bd-rchk0.5.6.1"
    for finding in report["findings"]
):
    raise SystemExit("noisy_performance finding with remediation was not emitted")
PY
then
    scenario_result "release_gate_noisy_performance_downgrades" "PASS" "noisy performance downgraded public readiness"
else
    scenario_result "release_gate_noisy_performance_downgrades" "FAIL" "noisy performance lacked expected public state or remediation"
fi

e2e_step "Scenario 10: host capability skip downgrades without a blocking error"
write_lane_status_variant "$MANIFEST_JSON" "$CAPABILITY_MANIFEST" "fuse" "skip"
python3 - "$POLICY_JSON" "$CAPABILITY_POLICY" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

policy_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(policy_path).read_text(encoding="utf-8"))
for feature in data["features"]:
    for threshold in feature["thresholds"]:
        if threshold["metric"] == "pass_lanes":
            threshold["value"] = 8
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$CAPABILITY_RAW" cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$CAPABILITY_MANIFEST" \
    --policy "$CAPABILITY_POLICY" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    && extract_json_object "$CAPABILITY_RAW" "$CAPABILITY_REPORT" \
    && python3 - "$CAPABILITY_REPORT" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
states = {row["feature_id"]: row["final_state"] for row in report["feature_reports"]}
if not report["valid"] or report["release_ready"]:
    raise SystemExit("capability skip should be valid but not release-ready")
if states.get("mount.rw.ext4") != "experimental":
    raise SystemExit(f"mount.rw.ext4 was not experimental: {states.get('mount.rw.ext4')}")
if not any(
    "host_capability_skip" in finding["finding_id"]
    and finding["severity"] == "warn"
    and finding.get("remediation_id") == "bd-rchk0.5.6.1"
    for finding in report["findings"]
):
    raise SystemExit("host_capability_skip warning with remediation was not emitted")
PY
then
    scenario_result "release_gate_host_capability_skip_downgrades" "PASS" "host capability skip downgraded without blocking"
else
    scenario_result "release_gate_host_capability_skip_downgrades" "FAIL" "host capability skip lacked expected warning downgrade"
fi

e2e_step "Scenario 11: release gate unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib release_gate -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "release_gate_unit_tests" "PASS" "release_gate unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "release_gate_unit_tests" "FAIL" "release_gate unit tests failed"
fi

e2e_log "Release gate manifest: $MANIFEST_JSON"
e2e_log "Release gate policy: $POLICY_JSON"
e2e_log "Release gate report: $REPORT_JSON"
e2e_log "Release gate wording: $WORDING_TSV"

if ((FAIL_COUNT == 0)); then
    e2e_log "Release gate scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Release gate scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
