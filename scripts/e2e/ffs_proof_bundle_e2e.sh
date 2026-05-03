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
    "writeback_cache",
    "release_gates",
]
statuses = ["pass", "fail", "skip", "error"]

records = []
for index, lane in enumerate(lanes):
    raw_log = pathlib.Path("logs") / f"{lane}.log"
    summary = pathlib.Path("summaries") / f"{lane}.md"
    gate_input = pathlib.Path("inputs") / f"{lane}.json"
    artifact = pathlib.Path("artifacts") / f"{lane}.json"
    for relative, text in [
        (raw_log, f"lane={lane}\nstatus={statuses[index % len(statuses)]}\n"),
        (summary, f"# {lane}\n\nSummary for {lane}.\n"),
        (gate_input, json.dumps({"lane": lane, "gate": "bd-rchk0.5.4.1"}, sort_keys=True) + "\n"),
        (artifact, json.dumps({"lane": lane, "artifact": "primary"}, sort_keys=True) + "\n"),
    ]:
        path = bundle_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    digest = hashlib.sha256((bundle_dir / artifact).read_bytes()).hexdigest()
    records.append(
        {
            "lane_id": lane,
            "status": statuses[index % len(statuses)],
            "raw_log_path": raw_log.as_posix(),
            "summary_path": summary.as_posix(),
            "scenario_ids": [f"{lane}_proof_bundle_primary"],
            "gate_inputs": [gate_input.as_posix()],
            "artifacts": [
                {
                    "path": artifact.as_posix(),
                    "sha256": digest,
                    "redacted": index % 2 == 0,
                    "role": "primary_evidence",
                }
            ],
        }
    )

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
    "writeback_cache",
    "release_gates",
}
observed_lanes = {lane["lane_id"] for lane in report["lanes"]}
if observed_lanes != required_lanes:
    raise SystemExit(f"unexpected lanes: {sorted(observed_lanes)}")
if report["totals"]["pass"] < 1 or report["totals"]["fail"] < 1:
    raise SystemExit("pass/fail totals not captured")
for lane in required_lanes:
    if f"logs/{lane}.log" not in summary:
        raise SystemExit(f"missing raw log link for {lane}")
    if f"summaries/{lane}.md" not in summary:
        raise SystemExit(f"missing summary link for {lane}")
if "validate-proof-bundle" not in summary:
    raise SystemExit("summary did not preserve reproduction command")
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
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-proof-bundle \
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
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-proof-bundle \
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
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_LINK_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000 >"$BAD_LINK_RAW" 2>&1; then
    scenario_result "proof_bundle_missing_artifact_rejected" "FAIL" "validator accepted missing artifact link"
elif grep -q "broken link" "$BAD_LINK_RAW"; then
    scenario_result "proof_bundle_missing_artifact_rejected" "PASS" "missing artifact link rejected"
else
    scenario_result "proof_bundle_missing_artifact_rejected" "FAIL" "validator failed without broken link diagnostic"
fi

e2e_step "Scenario 7: proof bundle unit tests pass"
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
