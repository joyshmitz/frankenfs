#!/usr/bin/env bash
# ffs_release_gate_e2e.sh - smoke gate for bd-rchk0.5.6.1.
#
# Builds a proof bundle plus release-gate policy, proves passing gates emit
# generated public wording, and proves missing, stale, and threshold-failing
# evidence fail closed.

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
    "writeback_cache",
    "release_gates",
]

records = []
for lane in lanes:
    raw_log = pathlib.Path("logs") / f"{lane}.log"
    summary = pathlib.Path("summaries") / f"{lane}.md"
    gate_input = pathlib.Path("inputs") / f"{lane}.json"
    artifact = pathlib.Path("artifacts") / f"{lane}.json"
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
    records.append(
        {
            "lane_id": lane,
            "status": "pass",
            "raw_log_path": raw_log.as_posix(),
            "summary_path": summary.as_posix(),
            "scenario_ids": [f"{lane}_release_gate_primary"],
            "gate_inputs": [gate_input.as_posix()],
            "artifacts": [
                {
                    "path": artifact.as_posix(),
                    "sha256": digest,
                    "redacted": False,
                    "role": "release_gate_evidence",
                }
            ],
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

def required_lane(lane: str) -> dict[str, object]:
    return {
        "lane_id": lane,
        "expected_outcome": "pass",
        "missing_state": "hidden",
        "failed_state": "disabled",
        "skipped_state": "experimental",
        "allow_capability_skip": True,
        "remediation_id": "bd-rchk0.5.6.1",
    }

def feature(feature_id: str, docs_id: str, previous: str, target: str, feature_lanes: list[str]) -> dict[str, object]:
    return {
        "feature_id": feature_id,
        "docs_wording_id": docs_id,
        "previous_state": previous,
        "target_state": target,
        "required_lanes": [required_lane(lane) for lane in feature_lanes],
        "thresholds": [
            {
                "metric": "pass_lanes",
                "comparator": "at_least",
                "value": 9,
                "downgrade_to": "experimental",
                "remediation_id": "bd-rchk0.5.6.1",
            },
            {
                "metric": "fail_lanes",
                "comparator": "at_most",
                "value": 0,
                "downgrade_to": "disabled",
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
            {
                "switch_id": "failed-evidence",
                "trigger": "any_required_lane_failed",
                "downgrade_to": "disabled",
                "reason": "failed lane disables user-data-affecting feature",
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
if python3 - "$REPORT_JSON" "$WORDING_TSV" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
wording = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
if not report["valid"] or not report["release_ready"]:
    raise SystemExit("passing report is not release-ready")
states = {row["feature_id"]: row["final_state"] for row in report["feature_reports"]}
expected = {
    "mount.rw.ext4": "validated",
    "repair.rw.writeback": "opt_in_mutating",
    "writeback_cache": "opt_in_mutating",
    "background_scrub_mutation": "detection_only",
}
if states != expected:
    raise SystemExit(f"unexpected states: {states}")
for field in ["feature_id", "previous_state", "final_state", "docs_wording_id", "reproduction_command"]:
    if field not in report["required_log_fields"]:
        raise SystemExit(f"missing required log field {field}")
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
            threshold["value"] = 10
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

e2e_step "Scenario 7: release gate unit tests pass"
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
