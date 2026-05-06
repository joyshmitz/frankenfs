#!/usr/bin/env bash
# ffs_proof_bundle_e2e.sh - smoke gate for bd-rchk0.5.4.1.
#
# Builds an offline proof bundle with every release-readiness lane, validates
# links and SHA-256 hashes, emits JSON/Markdown reports, and proves fail-closed
# handling for stale or corrupted evidence.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_proof_bundle}"
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

e2e_init "ffs_proof_bundle"

GIT_SHA="$(git rev-parse HEAD)"
BUNDLE_DIR="$E2E_LOG_DIR/proof_bundle"
MANIFEST_JSON="$BUNDLE_DIR/manifest.json"
REPORT_JSON="$E2E_LOG_DIR/proof_bundle_report.json"
SUMMARY_MD="$E2E_LOG_DIR/proof_bundle_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/proof_bundle_validate.raw"
SUMMARY_RAW="$E2E_LOG_DIR/proof_bundle_summary.raw"
BAD_HASH_MANIFEST="$BUNDLE_DIR/proof_bundle_bad_hash.json"
BAD_HASH_RAW="$E2E_LOG_DIR/proof_bundle_bad_hash.raw"
BAD_STALE_MANIFEST="$BUNDLE_DIR/proof_bundle_stale_sha.json"
BAD_STALE_RAW="$E2E_LOG_DIR/proof_bundle_stale_sha.raw"
BAD_LINK_MANIFEST="$BUNDLE_DIR/proof_bundle_missing_artifact.json"
BAD_LINK_RAW="$E2E_LOG_DIR/proof_bundle_missing_artifact.raw"
BAD_CHAIN_MANIFEST="$BUNDLE_DIR/proof_bundle_bad_hash_chain.json"
BAD_CHAIN_RAW="$E2E_LOG_DIR/proof_bundle_bad_hash_chain.raw"
BAD_REDACTION_MANIFEST="$BUNDLE_DIR/proof_bundle_redaction_leak.json"
BAD_REDACTION_RAW="$E2E_LOG_DIR/proof_bundle_redaction_leak.raw"
BAD_PLACEHOLDER_MANIFEST="$BUNDLE_DIR/proof_bundle_missing_placeholder.json"
BAD_PLACEHOLDER_RAW="$E2E_LOG_DIR/proof_bundle_missing_placeholder.raw"
UNIT_LOG="$E2E_LOG_DIR/proof_bundle_unit_tests.log"

mkdir -p "$BUNDLE_DIR"

e2e_step "Scenario 1: proof bundle module and CLI are wired"
if grep -q "pub mod proof_bundle" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-proof-bundle" crates/ffs-harness/src/main.rs; then
    scenario_result "proof_bundle_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "proof_bundle_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: sample proof bundle validates"
if python3 - "$BUNDLE_DIR" "$MANIFEST_JSON" "$GIT_SHA" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

bundle_dir = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
git_sha = sys.argv[3]

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
statuses = ["pass", "fail", "skip", "error"]

records = []
for index, lane in enumerate(lanes):
    raw_log = pathlib.Path("logs") / f"{lane}.log"
    summary = pathlib.Path("summaries") / f"{lane}.md"
    gate_input = pathlib.Path("inputs") / f"{lane}.json"
    artifact = pathlib.Path("artifacts") / f"{lane}.json"
    p99_artifact = pathlib.Path("artifacts") / f"{lane}_p99_attribution.json"
    redacted = index % 2 == 0
    artifact_payload = {"lane": lane, "artifact": "primary"}
    if redacted:
        artifact_payload["redacted_value"] = "[REDACTED]"
    for relative, text in [
        (raw_log, f"lane={lane}\nstatus={statuses[index % len(statuses)]}\n"),
        (summary, f"# {lane}\n\nSummary for {lane}.\n"),
        (gate_input, json.dumps({"lane": lane, "gate": "bd-rchk0.5.4.1"}, sort_keys=True) + "\n"),
        (artifact, json.dumps(artifact_payload, sort_keys=True) + "\n"),
    ]:
        path = bundle_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    digest = hashlib.sha256((bundle_dir / artifact).read_bytes()).hexdigest()
    artifacts = [
        {
            "path": artifact.as_posix(),
            "sha256": digest,
            "redacted": redacted,
            "role": "swarm_validator_report"
            if lane in {"swarm_workload_harness", "swarm_tail_latency"}
            else "primary_evidence",
        }
    ]
    metadata = {}
    if lane in {"swarm_workload_harness", "swarm_tail_latency"}:
        status = statuses[index % len(statuses)]
        metadata = {
            "freshness": "fresh",
            "manifest_hash": "a" * 64,
            "validator_report": artifact.as_posix(),
        }
        if status == "pass":
            metadata["host_class"] = "permissioned_large_host"
            metadata["release_claim"] = "authoritative_large_host"
        elif status == "skip":
            metadata["host_class"] = "developer_smoke"
            metadata["release_claim"] = "small_host_smoke"
            metadata["downgrade_reason"] = (
                "small host smoke cannot support release wording"
            )
        elif status == "fail":
            metadata["host_class"] = "developer_smoke"
            metadata["release_claim"] = "failed"
            metadata["downgrade_reason"] = "swarm evidence failed release checks"
        else:
            metadata["host_class"] = "developer_smoke"
            metadata["release_claim"] = "error"
            metadata["downgrade_reason"] = "swarm evidence errored during collection"
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
            "status": statuses[index % len(statuses)],
            "raw_log_path": raw_log.as_posix(),
            "summary_path": summary.as_posix(),
            "scenario_ids": [f"{lane}_proof_bundle_primary"],
            "gate_inputs": [gate_input.as_posix()],
            "artifacts": artifacts,
            "metadata": metadata,
        }
    )

def hash_chain_part(hasher: "hashlib._Hash", value: str) -> None:
    encoded = value.encode("utf-8")
    hasher.update(str(len(encoded)).encode("utf-8"))
    hasher.update(b":")
    hasher.update(encoded)
    hasher.update(b";")

def artifact_hash_chain_sha256(bundle_records: list[dict[str, object]]) -> str:
    hasher = hashlib.sha256()
    for record in bundle_records:
        hash_chain_part(hasher, "lane")
        hash_chain_part(hasher, str(record["lane_id"]))
        for artifact_record in record["artifacts"]:
            hash_chain_part(hasher, "artifact")
            hash_chain_part(hasher, str(artifact_record["path"]))
            hash_chain_part(hasher, str(artifact_record["sha256"]))
            hash_chain_part(hasher, "redacted" if artifact_record["redacted"] else "clear")
            hash_chain_part(hasher, str(artifact_record["role"]))
    return hasher.hexdigest()

manifest = {
    "schema_version": 1,
    "bundle_id": "bd-rchk0.5.4.1-proof-bundle",
    "generated_at": "2030-01-01T00:00:00Z",
    "git_sha": git_sha,
    "toolchain": "rust-nightly-2024",
    "kernel": "linux-proof-bundle-e2e",
    "mount_capability": "available",
    "required_lanes": lanes,
    "lanes": records,
    "redaction": {
        "redacted_fields": ["hostname", "api_key", "token"],
        "preserved_fields": [
            "reproduction_command",
            "git_sha",
            "bundle_id",
            "artifact_paths",
            "scenario_ids",
        ],
        "reproduction_command": (
            "cargo run -p ffs-harness -- validate-proof-bundle "
            "--bundle proof_bundle/manifest.json"
        ),
        "policy_version": "redaction-v1",
        "redacted_value_placeholder": "[REDACTED]",
        "forbidden_unredacted_markers": ["SECRET_TOKEN", "/home/ubuntu", "host-prod"],
        "require_placeholder_in_redacted_artifacts": True,
    },
    "integrity": {
        "artifact_hash_chain_sha256": artifact_hash_chain_sha256(records),
        "artifact_count": sum(len(record["artifacts"]) for record in records),
        "redaction_policy_version": "redaction-v1",
    },
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
then
    if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
        --bundle "$MANIFEST_JSON" \
        --current-git-sha "$GIT_SHA" \
        --max-age-days 10000 >"$REPORT_JSON" 2>"$VALIDATE_RAW" \
        && cargo run --quiet -p ffs-harness -- validate-proof-bundle \
            --bundle "$MANIFEST_JSON" \
            --current-git-sha "$GIT_SHA" \
            --max-age-days 10000 \
            --format markdown >"$SUMMARY_MD" 2>"$SUMMARY_RAW"; then
        scenario_result "proof_bundle_sample_validates" "PASS" "validation JSON and summary captured locally"
    else
        scenario_result "proof_bundle_sample_validates" "FAIL" "validator rejected generated sample bundle"
    fi
else
    scenario_result "proof_bundle_sample_validates" "FAIL" "failed to generate sample proof bundle"
fi

e2e_step "Scenario 3: generated summary preserves lane links and totals"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
required_lanes = {
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
}
observed_lanes = {lane["lane_id"] for lane in report["lanes"]}
if observed_lanes != required_lanes:
    raise SystemExit(f"unexpected lanes: {sorted(observed_lanes)}")
if report["totals"]["pass"] < 1 or report["totals"]["fail"] < 1:
    raise SystemExit("pass/fail totals not captured")
if not report.get("artifact_hash_chain"):
    raise SystemExit("artifact hash-chain report missing")
if report["artifact_hash_chain"]["redaction_policy_version"] != "redaction-v1":
    raise SystemExit("redaction policy version was not preserved in hash-chain report")
artifact_rows = report.get("artifact_reports", [])
if len(artifact_rows) != len(required_lanes) + 1:
    raise SystemExit(f"unexpected artifact report count: {len(artifact_rows)}")
if not all(row.get("sha256") and row.get("path") for row in artifact_rows):
    raise SystemExit("artifact report rows did not preserve path and hash")
if not any(row.get("role") == "p99_attribution_ledger" for row in artifact_rows):
    raise SystemExit("p99 attribution ledger artifact was not preserved")
swarm_rows = report.get("swarm_evidence", [])
if len(swarm_rows) != 2:
    raise SystemExit(f"unexpected swarm evidence rows: {len(swarm_rows)}")
if not all(row.get("host_class") and row.get("manifest_hash") for row in swarm_rows):
    raise SystemExit("swarm evidence did not preserve host class and manifest hash")
for lane in required_lanes:
    if f"logs/{lane}.log" not in summary:
        raise SystemExit(f"missing raw log link for {lane}")
    if f"summaries/{lane}.md" not in summary:
        raise SystemExit(f"missing summary link for {lane}")
if "validate-proof-bundle" not in summary:
    raise SystemExit("summary did not preserve reproduction command")
if "Artifact hash chain" not in summary:
    raise SystemExit("summary did not preserve hash-chain diagnostics")
if "Swarm Evidence" not in summary or "p99_attribution" not in summary:
    raise SystemExit("summary did not preserve swarm evidence diagnostics")
PY
then
    scenario_result "proof_bundle_summary_links" "PASS" "summary contains totals and raw log links"
else
    scenario_result "proof_bundle_summary_links" "FAIL" "summary/report contract check failed"
fi

e2e_step "Scenario 4: validator rejects artifact hash drift"
python3 - "$MANIFEST_JSON" "$BAD_HASH_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"][0]["artifacts"][0]["sha256"] = "0" * 64
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_HASH_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 >"$BAD_HASH_RAW" 2>&1; then
    scenario_result "proof_bundle_hash_drift_rejected" "FAIL" "validator accepted corrupted artifact"
elif grep -q "artifact hash mismatch" "$BAD_HASH_RAW"; then
    scenario_result "proof_bundle_hash_drift_rejected" "PASS" "hash drift rejected"
else
    scenario_result "proof_bundle_hash_drift_rejected" "FAIL" "validator failed without hash mismatch diagnostic"
fi

e2e_step "Scenario 5: validator rejects stale git SHA"
python3 - "$MANIFEST_JSON" "$BAD_STALE_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_STALE_MANIFEST" \
    --current-git-sha "stale-sha-for-e2e" \
    --max-age-days 10000 >"$BAD_STALE_RAW" 2>&1; then
    scenario_result "proof_bundle_stale_sha_rejected" "FAIL" "validator accepted stale git SHA"
elif grep -q "stale git_sha" "$BAD_STALE_RAW"; then
    scenario_result "proof_bundle_stale_sha_rejected" "PASS" "stale git SHA rejected"
else
    scenario_result "proof_bundle_stale_sha_rejected" "FAIL" "validator failed without stale git diagnostic"
fi

e2e_step "Scenario 6: validator rejects missing artifact links"
python3 - "$MANIFEST_JSON" "$BAD_LINK_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"][1]["artifacts"][0]["path"] = "artifacts/does_not_exist.json"
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_LINK_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 >"$BAD_LINK_RAW" 2>&1; then
    scenario_result "proof_bundle_missing_artifact_rejected" "FAIL" "validator accepted missing artifact link"
elif grep -q "broken link" "$BAD_LINK_RAW"; then
    scenario_result "proof_bundle_missing_artifact_rejected" "PASS" "missing artifact link rejected"
else
    scenario_result "proof_bundle_missing_artifact_rejected" "FAIL" "validator failed without broken link diagnostic"
fi

e2e_step "Scenario 7: validator rejects artifact hash-chain tampering"
python3 - "$MANIFEST_JSON" "$BAD_CHAIN_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["integrity"]["artifact_hash_chain_sha256"] = "f" * 64
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_CHAIN_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 >"$BAD_CHAIN_RAW" 2>&1; then
    scenario_result "proof_bundle_hash_chain_rejected" "FAIL" "validator accepted tampered hash chain"
elif grep -q "artifact hash-chain mismatch" "$BAD_CHAIN_RAW"; then
    scenario_result "proof_bundle_hash_chain_rejected" "PASS" "hash-chain tamper rejected"
else
    scenario_result "proof_bundle_hash_chain_rejected" "FAIL" "validator failed without hash-chain diagnostic"
fi

e2e_step "Scenario 8: validator rejects unredacted sensitive markers"
python3 - "$MANIFEST_JSON" "$BAD_REDACTION_MANIFEST" "$BUNDLE_DIR" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path, bundle_dir = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
leaky_summary = pathlib.Path("summaries") / "conformance_leaky.md"
(pathlib.Path(bundle_dir) / leaky_summary).write_text(
    "# conformance\n\nhost-prod leaked SECRET_TOKEN\n",
    encoding="utf-8",
)
data["lanes"][0]["summary_path"] = leaky_summary.as_posix()
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_REDACTION_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 >"$BAD_REDACTION_RAW" 2>&1; then
    scenario_result "proof_bundle_redaction_leak_rejected" "FAIL" "validator accepted unredacted sensitive marker"
elif grep -q "redaction leak" "$BAD_REDACTION_RAW"; then
    scenario_result "proof_bundle_redaction_leak_rejected" "PASS" "unredacted sensitive marker rejected"
else
    scenario_result "proof_bundle_redaction_leak_rejected" "FAIL" "validator failed without redaction leak diagnostic"
fi

e2e_step "Scenario 9: validator rejects redacted artifacts without placeholders"
python3 - "$MANIFEST_JSON" "$BAD_PLACEHOLDER_MANIFEST" "$BUNDLE_DIR" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

manifest_path, out_path, bundle_dir = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
artifact_path = pathlib.Path("artifacts") / "conformance_no_placeholder.json"
artifact_abs = pathlib.Path(bundle_dir) / artifact_path
artifact_abs.write_text(json.dumps({"redacted": "missing-placeholder"}, sort_keys=True) + "\n", encoding="utf-8")
data["lanes"][0]["artifacts"][0]["path"] = artifact_path.as_posix()
data["lanes"][0]["artifacts"][0]["sha256"] = hashlib.sha256(artifact_abs.read_bytes()).hexdigest()
data["lanes"][0]["artifacts"][0]["redacted"] = True
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_PLACEHOLDER_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 >"$BAD_PLACEHOLDER_RAW" 2>&1; then
    scenario_result "proof_bundle_redaction_placeholder_rejected" "FAIL" "validator accepted redacted artifact without placeholder"
elif grep -q "lacks placeholder" "$BAD_PLACEHOLDER_RAW"; then
    scenario_result "proof_bundle_redaction_placeholder_rejected" "PASS" "missing redaction placeholder rejected"
else
    scenario_result "proof_bundle_redaction_placeholder_rejected" "FAIL" "validator failed without placeholder diagnostic"
fi

e2e_step "Scenario 10: proof bundle unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib proof_bundle -- --nocapture >"$UNIT_LOG" 2>&1; then
    cat "$UNIT_LOG"
    scenario_result "proof_bundle_unit_tests" "PASS" "proof_bundle unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "proof_bundle_unit_tests" "FAIL" "proof_bundle unit tests failed"
fi

e2e_log "Proof bundle manifest: $MANIFEST_JSON"
e2e_log "Proof bundle validation report: $REPORT_JSON"
e2e_log "Proof bundle summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Proof bundle scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Proof bundle scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
