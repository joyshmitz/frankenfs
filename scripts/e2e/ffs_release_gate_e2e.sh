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
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

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

GIT_SHA="$(git rev-parse HEAD)"
BUNDLE_DIR="$E2E_LOG_DIR/release_gate_bundle"
MANIFEST_JSON="$BUNDLE_DIR/manifest.json"
POLICY_JSON="$BUNDLE_DIR/release_gate_policy.json"
REPORT_JSON="$E2E_LOG_DIR/release_gate_report.json"
SUMMARY_MD="$E2E_LOG_DIR/release_gate_summary.md"
WORDING_TSV="$E2E_LOG_DIR/release_gate_wording.tsv"
VALIDATE_RAW="$E2E_LOG_DIR/release_gate_validate.raw"
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
]

records = []
for lane in lanes:
    raw_log = pathlib.Path("logs") / f"{lane}.log"
    summary = pathlib.Path("summaries") / f"{lane}.md"
    gate_input = pathlib.Path("inputs") / f"{lane}.json"
    artifact = pathlib.Path("artifacts") / f"{lane}.json"
    p99_artifact = pathlib.Path("artifacts") / f"{lane}_p99_attribution.json"
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
    digest = hashlib.sha256((bundle_dir / artifact).read_bytes()).hexdigest()
    artifacts = [
        {
            "path": artifact.as_posix(),
            "sha256": digest,
            "redacted": False,
            "role": "swarm_validator_report"
            if lane in {"swarm_workload_harness", "swarm_tail_latency"}
            else "release_gate_evidence",
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
    records.append(
        {
            "lane_id": lane,
            "status": "pass",
            "raw_log_path": raw_log.as_posix(),
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
    "generated_at": "2030-01-01T00:00:00Z",
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
    if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
        --bundle "$MANIFEST_JSON" \
        --policy "$POLICY_JSON" \
        --current-git-sha "$GIT_SHA" \
        --max-age-days 10000 \
        --out "$REPORT_JSON" \
        --wording-out "$WORDING_TSV" >"$VALIDATE_RAW" 2>&1 \
        && cargo run --quiet -p ffs-harness -- evaluate-release-gates \
            --bundle "$MANIFEST_JSON" \
            --policy "$POLICY_JSON" \
            --current-git-sha "$GIT_SHA" \
            --max-age-days 10000 \
            --format markdown >"$SUMMARY_MD" 2>>"$VALIDATE_RAW"; then
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
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$MISSING_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    --out "$MISSING_REPORT" >"$MISSING_RAW" 2>&1; then
    scenario_result "release_gate_missing_evidence_rejected" "FAIL" "missing lane was accepted"
elif grep -q "release gate evaluation failed" "$MISSING_RAW" \
    && grep -q "missing_required_lane" "$MISSING_REPORT"; then
    scenario_result "release_gate_missing_evidence_rejected" "PASS" "missing evidence failed closed"
else
    scenario_result "release_gate_missing_evidence_rejected" "FAIL" "missing evidence failed without expected diagnostics"
fi

e2e_step "Scenario 5: stale proof bundle fails closed"
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$MANIFEST_JSON" \
    --policy "$POLICY_JSON" \
    --current-git-sha "stale-sha-for-release-gate" \
    --max-age-days 10000 \
    --out "$STALE_REPORT" >"$STALE_RAW" 2>&1; then
    scenario_result "release_gate_stale_evidence_rejected" "FAIL" "stale SHA was accepted"
elif grep -q "release gate evaluation failed" "$STALE_RAW" \
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
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$MANIFEST_JSON" \
    --policy "$THRESHOLD_POLICY" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    --out "$THRESHOLD_REPORT" >"$THRESHOLD_RAW" 2>&1; then
    scenario_result "release_gate_threshold_failure_rejected" "FAIL" "threshold failure was accepted"
elif grep -q "release gate evaluation failed" "$THRESHOLD_RAW" \
    && grep -q "threshold_failure" "$THRESHOLD_REPORT"; then
    scenario_result "release_gate_threshold_failure_rejected" "PASS" "threshold failure failed closed"
else
    scenario_result "release_gate_threshold_failure_rejected" "FAIL" "threshold failure lacked expected diagnostic"
fi

e2e_step "Scenario 7: hostile image/security refusal fails closed"
write_lane_status_variant "$MANIFEST_JSON" "$HOSTILE_MANIFEST" "conformance" "fail"
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$HOSTILE_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    --out "$HOSTILE_REPORT" >"$HOSTILE_RAW" 2>&1; then
    scenario_result "release_gate_hostile_image_rejected" "FAIL" "security-refused hostile image was accepted"
elif python3 - "$HOSTILE_REPORT" <<'PY'
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
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$UNSAFE_REPAIR_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    --out "$UNSAFE_REPAIR_REPORT" >"$UNSAFE_REPAIR_RAW" 2>&1; then
    scenario_result "release_gate_unsafe_repair_rejected" "FAIL" "unsafe repair refusal was accepted"
elif python3 - "$UNSAFE_REPAIR_REPORT" <<'PY'
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
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$NOISY_PERFORMANCE_MANIFEST" \
    --policy "$POLICY_JSON" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    --out "$NOISY_PERFORMANCE_REPORT" >"$NOISY_PERFORMANCE_RAW" 2>&1; then
    scenario_result "release_gate_noisy_performance_downgrades" "FAIL" "noisy performance was accepted"
elif python3 - "$NOISY_PERFORMANCE_REPORT" <<'PY'
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
if cargo run --quiet -p ffs-harness -- evaluate-release-gates \
    --bundle "$CAPABILITY_MANIFEST" \
    --policy "$CAPABILITY_POLICY" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 \
    --out "$CAPABILITY_REPORT" >"$CAPABILITY_RAW" 2>&1 \
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
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib release_gate -- --nocapture >"$UNIT_LOG" 2>&1; then
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
