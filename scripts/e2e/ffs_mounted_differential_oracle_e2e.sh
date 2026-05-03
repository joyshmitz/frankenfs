#!/usr/bin/env bash
# ffs_mounted_differential_oracle_e2e.sh - mounted differential oracle contract smoke.
#
# This is a safe dry-run artifact lane by default. Permissioned workers can set
# FFS_MOUNTED_DIFFERENTIAL_EXECUTE=1 later, but the current gate focuses on the
# consumer contract: normalized observations, exact allowlists, host skips, and
# unsupported-scope records.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_mounted_differential_oracle"

REPORT_JSON="$E2E_LOG_DIR/mounted_differential_report.json"
VALIDATION_JSON="$E2E_LOG_DIR/mounted_differential_validation.json"
VALIDATION_MD="$E2E_LOG_DIR/mounted_differential_validation.md"
BROAD_REPORT_JSON="$E2E_LOG_DIR/broad_allowlist_report.json"
BROAD_VALIDATION_JSON="$E2E_LOG_DIR/broad_allowlist_validation.json"

e2e_step "Generate mounted differential oracle dry-run report"

FFS_MOUNTED_DIFFERENTIAL_REPORT="$REPORT_JSON" \
FFS_MOUNTED_DIFFERENTIAL_EXECUTE="${FFS_MOUNTED_DIFFERENTIAL_EXECUTE:-0}" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import platform
from datetime import datetime, timezone

report_path = pathlib.Path(os.environ["FFS_MOUNTED_DIFFERENTIAL_REPORT"])
execute = os.environ.get("FFS_MOUNTED_DIFFERENTIAL_EXECUTE") == "1"
hash_a = "a" * 64
hash_b = "b" * 64


def observation(side: str, result: str, errno: str | None = None) -> dict[str, object]:
    return {
        "side": side,
        "result": result,
        "errno": errno,
        "stdout_path": f"{report_path.parent}/stdout/{side}.log",
        "stderr_path": f"{report_path.parent}/stderr/{side}.log",
        "image_hash_before": hash_a,
        "image_hash_after": hash_b,
        "mount_options": [] if result == "skip" else ["rw", "default_permissions"],
        "uid": os.getuid(),
    }


allowlist = {
    "allowlist_id": "allow_ext4_fiemap_transport_errno",
    "scenario_id": "mounted_diff_ext4_fiemap_transport_errno",
    "operation_id": "fiemap_probe",
    "field": "result",
    "kernel_value": "EOPNOTSUPP",
    "frankenfs_value": "ENOTTY",
    "reason": "current FUSE transport may reject FIEMAP before userspace dispatch",
    "owner_bead": "bd-29cpd",
    "expires_on": "2026-12-31",
    "removal_plan": "remove once kernel baseline provenance proves ioctl forwarding",
}

scenarios = [
    {
        "scenario_id": "mounted_diff_ext4_create_readback",
        "operation_id": "open_readback",
        "filesystem": "ext4",
        "scenario_kind": "positive",
        "classification": "pass",
        "kernel_observation": observation("kernel", "ok"),
        "frankenfs_observation": observation("frankenfs", "ok"),
        "normalized_diff": [],
        "cleanup_status": "clean",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_create_readback",
        "artifact_paths": [str(report_path)],
    },
    {
        "scenario_id": "mounted_diff_ext4_fiemap_transport_errno",
        "operation_id": "fiemap_probe",
        "filesystem": "ext4",
        "scenario_kind": "positive",
        "classification": "allowed_diff",
        "allowlist_id": "allow_ext4_fiemap_transport_errno",
        "kernel_observation": observation("kernel", "errno", "EOPNOTSUPP"),
        "frankenfs_observation": observation("frankenfs", "errno", "ENOTTY"),
        "normalized_diff": [
            {
                "field": "result",
                "kernel_value": "EOPNOTSUPP",
                "frankenfs_value": "ENOTTY",
            }
        ],
        "cleanup_status": "clean",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_fiemap_transport_errno",
        "artifact_paths": [str(report_path), str(report_path.parent / "stdout/kernel.log")],
    },
    {
        "scenario_id": "mounted_diff_ext4_fuse_permission_skip",
        "operation_id": "mount_probe",
        "filesystem": "ext4",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "fuse_permission_denied",
        "kernel_observation": observation("kernel", "skip", "fuse_permission_denied"),
        "frankenfs_observation": observation("frankenfs", "skip", "fuse_permission_denied"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_fuse_permission_skip",
        "artifact_paths": [str(report_path)],
    },
    {
        "scenario_id": "mounted_diff_btrfs_default_permissions_root_owned",
        "operation_id": "root_owned_write_probe",
        "filesystem": "btrfs",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "btrfs_default_permissions_root_owned",
        "kernel_observation": observation("kernel", "skip", "btrfs_default_permissions_root_owned"),
        "frankenfs_observation": observation("frankenfs", "skip", "btrfs_default_permissions_root_owned"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_btrfs_default_permissions_root_owned",
        "artifact_paths": [str(report_path)],
    },
    {
        "scenario_id": "mounted_diff_btrfs_unsupported_clone_range",
        "operation_id": "clone_range",
        "filesystem": "btrfs",
        "scenario_kind": "unsupported",
        "classification": "unsupported",
        "owner_bead": "bd-rchk0.5.2",
        "kernel_observation": observation("kernel", "errno", "EOPNOTSUPP"),
        "frankenfs_observation": observation("frankenfs", "errno", "EOPNOTSUPP"),
        "normalized_diff": [],
        "cleanup_status": "clean",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_btrfs_unsupported_clone_range",
        "artifact_paths": [str(report_path)],
    },
]

report = {
    "schema_version": 1,
    "bead_id": "bd-rchk0.5.2.1",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "kernel_release": platform.release(),
    "runner": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh",
    "execute_permissioned": execute,
    "capability": {
        "fuse": "permission_denied",
        "kernel_mount": "permission_denied",
        "mkfs_ext4": "available",
        "mkfs_btrfs": "available",
    },
    "allowlist": [allowlist],
    "scenarios": scenarios,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

e2e_step "Validate mounted differential oracle report"
e2e_assert "${RCH_BIN:-rch}" exec -- cargo run -p ffs-harness -- \
    validate-mounted-differential-oracle \
    --report "$REPORT_JSON" \
    --out "$VALIDATION_JSON"
e2e_assert "${RCH_BIN:-rch}" exec -- cargo run -p ffs-harness -- \
    validate-mounted-differential-oracle \
    --report "$REPORT_JSON" \
    --format markdown \
    --out "$VALIDATION_MD"

echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_create_readback|outcome=PASS|detail=normalized observations match" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_fiemap_transport_errno|outcome=DIFF|detail=exact expiring allowlist accepted" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_fuse_permission_skip|outcome=SKIP|detail=permission denied is host skip" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_btrfs_default_permissions_root_owned|outcome=SKIP|detail=btrfs DefaultPermissions root-owned EACCES isolated" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_btrfs_unsupported_clone_range|outcome=UNSUPPORTED|detail=unsupported scope has owner bead" | tee -a "$E2E_LOG_FILE"

e2e_step "Reject broad allowlist fixture"
FFS_MOUNTED_DIFFERENTIAL_REPORT="$REPORT_JSON" \
FFS_MOUNTED_DIFFERENTIAL_BROAD_REPORT="$BROAD_REPORT_JSON" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib

source = pathlib.Path(os.environ["FFS_MOUNTED_DIFFERENTIAL_REPORT"])
target = pathlib.Path(os.environ["FFS_MOUNTED_DIFFERENTIAL_BROAD_REPORT"])
payload = json.loads(source.read_text(encoding="utf-8"))
payload["allowlist"][0]["scenario_id"] = "*"
payload["allowlist"][0]["expires_on"] = "2026-01-01"
target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if e2e_run "${RCH_BIN:-rch}" exec -- cargo run -p ffs-harness -- \
    validate-mounted-differential-oracle \
    --report "$BROAD_REPORT_JSON" \
    --out "$BROAD_VALIDATION_JSON"; then
    e2e_fail "broad allowlist report unexpectedly validated"
fi
echo "SCENARIO_RESULT|scenario_id=mounted_diff_broad_allowlist_rejected|outcome=ERROR|detail=validator rejected intentionally broad allowlist" | tee -a "$E2E_LOG_FILE"

e2e_log "Mounted differential report: $REPORT_JSON"
e2e_log "Validation JSON: $VALIDATION_JSON"
e2e_log "Validation Markdown: $VALIDATION_MD"
e2e_log "Broad allowlist rejection artifact: $BROAD_VALIDATION_JSON"

e2e_pass
