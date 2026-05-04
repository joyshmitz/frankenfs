#!/usr/bin/env bash
# ffs_fuzz_smoke_e2e.sh - deterministic fixed-seed parser smoke gate for bd-rchk7.4.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fuzz_smoke}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

e2e_init "ffs_fuzz_smoke"

MANIFEST_PATH="${FFS_FUZZ_SMOKE_MANIFEST:-$REPO_ROOT/tests/fuzz-smoke/fuzz_smoke_manifest.json}"
REPORT_JSON="$E2E_LOG_DIR/fuzz_smoke_report.json"
QA_ARTIFACT_JSON="$E2E_LOG_DIR/fuzz_smoke_qa_artifact.json"
STDOUT_PATH="$E2E_LOG_DIR/fuzz_smoke.stdout"
STDERR_PATH="$E2E_LOG_DIR/fuzz_smoke.stderr"

COMMAND=(
    "${RCH_BIN:-rch}"
    exec
    --
    cargo
    run
    --quiet
    -p
    ffs-harness
    --
    validate-fuzz-smoke
    --manifest
    "$MANIFEST_PATH"
    --workspace-root
    "$REPO_ROOT"
    --out
    "$REPORT_JSON"
)
printf -v COMMAND_LINE '%q ' "${COMMAND[@]}"
COMMAND_LINE="${COMMAND_LINE% }"

e2e_step "Run deterministic fuzz-smoke manifest"
START_NS="$(date +%s%N)"
if RCH_VISIBILITY=none "${COMMAND[@]}" >"$STDOUT_PATH" 2>"$STDERR_PATH"; then
    COMMAND_STATUS="pass"
else
    COMMAND_STATUS="fail"
fi
END_NS="$(date +%s%N)"
DURATION_MS="$(((END_NS - START_NS) / 1000000))"

e2e_step "Emit shared QA artifact"
python3 - \
    "$REPORT_JSON" \
    "$QA_ARTIFACT_JSON" \
    "$STDOUT_PATH" \
    "$STDERR_PATH" \
    "$COMMAND_LINE" \
    "$COMMAND_STATUS" \
    "$DURATION_MS" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone

report_path = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
stdout_path = pathlib.Path(sys.argv[3])
stderr_path = pathlib.Path(sys.argv[4])
command_line = sys.argv[5]
command_status = sys.argv[6]
duration_ms = int(sys.argv[7])

if not report_path.exists():
    report = {
        "valid": False,
        "seed_ids": [],
        "corpus_checksum": "",
        "target_summary": {},
        "errors": [f"missing report_json: {report_path}"],
    }
else:
    report = json.loads(report_path.read_text(encoding="utf-8"))

artifact = {
    "schema_version": 1,
    "bead_id": "bd-rchk7.4",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "command_line": command_line,
    "command_status": command_status,
    "seed_ids": report.get("seed_ids", []),
    "corpus_checksum": report.get("corpus_checksum", ""),
    "duration_ms": duration_ms,
    "stdout_path": str(stdout_path),
    "stderr_path": str(stderr_path),
    "report_json": str(report_path),
    "coverage_summary": report.get("target_summary", {}),
    "cleanup_status": "registered_with_e2e_cleanup_trap",
    "valid": command_status == "pass" and bool(report.get("valid")),
    "errors": report.get("errors", []),
}

artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(
    "FUZZ_SMOKE_QA|valid={valid}|seeds={seed_count}|checksum={checksum}|artifact={artifact}".format(
        valid=artifact["valid"],
        seed_count=len(artifact["seed_ids"]),
        checksum=artifact["corpus_checksum"],
        artifact=artifact_path,
    )
)

if not artifact["valid"]:
    raise SystemExit(1)
PY

if [[ "$COMMAND_STATUS" != "pass" ]]; then
    e2e_fail "fuzz-smoke command failed; stdout=$STDOUT_PATH stderr=$STDERR_PATH"
fi

e2e_pass "fuzz-smoke report=$REPORT_JSON qa_artifact=$QA_ARTIFACT_JSON"
