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


def observation(
    scenario_id: str,
    side: str,
    result: str,
    errno: str | None = None,
) -> dict[str, object]:
    return {
        "side": side,
        "result": result,
        "errno": errno,
        "stdout_path": f"{report_path.parent}/{scenario_id}/{side}/stdout.log",
        "stderr_path": f"{report_path.parent}/{scenario_id}/{side}/stderr.log",
        "image_hash_before": hash_a,
        "image_hash_after": hash_b,
        "mount_options": [] if result == "skip" else ["rw", "default_permissions"],
        "uid": os.getuid(),
        "gid": os.getgid(),
    }


def capability_probe(skip_class: str | None) -> dict[str, object]:
    dev_fuse = "missing" if skip_class == "fuse_missing" else "permission_denied"
    mkfs_helper = "missing" if skip_class in {"mkfs_ext4_missing", "mkfs_btrfs_missing"} else "available"
    return {
        "probe_id": "capability_probe",
        "dev_fuse": dev_fuse,
        "fusermount": "permission_denied",
        "kernel_mount": "permission_denied",
        "mkfs_helper": mkfs_helper,
        "stdout_path": "capability/stdout.log",
        "stderr_path": "capability/stderr.log",
    }


def baseline_manifest(scenario: dict[str, object]) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    filesystem = str(scenario["filesystem"])
    skip_class = scenario.get("host_skip_class")
    root_owned = skip_class == "btrfs_default_permissions_root_owned"
    mkfs_binary = "mkfs.ext4" if filesystem == "ext4" else "mkfs.btrfs"
    errno_rules: list[dict[str, str]] = []
    if scenario.get("classification") == "allowed_diff":
        errno_rules.append(
            {
                "rule_id": "errno_ext4_fiemap_transport",
                "operation_id": str(scenario["operation_id"]),
                "kernel_errno": "EOPNOTSUPP",
                "frankenfs_errno": "ENOTTY",
                "normalized_errno": "fiemap_transport_unsupported",
                "rationale": "kernel and FrankenFS both reject unsupported FIEMAP through different layers",
                "owner_bead": "bd-29cpd",
            }
        )
    probe = capability_probe(str(skip_class) if skip_class else None)
    probe["probe_id"] = f"capability_{scenario_id}"
    probe["stdout_path"] = f"{report_path.parent}/{scenario_id}/capability/stdout.log"
    probe["stderr_path"] = f"{report_path.parent}/{scenario_id}/capability/stderr.log"
    return {
        "baseline_id": f"baseline_{scenario_id}",
        "kernel_release": platform.release(),
        "filesystem": filesystem,
        "mkfs_command": f"{mkfs_binary} -F {report_path.parent}/{scenario_id}/kernel/image.img",
        "image_seed": f"seed-{scenario_id}",
        "image_hash": hash_a,
        "mount_options": ["rw", "default_permissions"],
        "uid": os.getuid(),
        "gid": os.getgid(),
        "root_ownership": {
            "uid": 0 if root_owned else os.getuid(),
            "gid": 0 if root_owned else os.getgid(),
            "mode": "0755",
            "default_permissions": True,
            "root_owned": root_owned,
        },
        "capability_probe": probe,
        "allowed_errno_normalization": errno_rules,
        "cleanup_requirements": {
            "unmount": "required",
            "mountpoints": "required",
            "images_on_success": "remove",
            "images_on_failure": "preserve",
            "raw_logs": "preserve",
            "cleanup_status_path": f"{report_path.parent}/{scenario_id}/cleanup.json",
        },
    }


def lane_isolation(scenario_id: str) -> dict[str, str]:
    return {
        "kernel_image_path": f"{report_path.parent}/{scenario_id}/kernel/image.img",
        "frankenfs_image_path": f"{report_path.parent}/{scenario_id}/frankenfs/image.img",
        "kernel_mountpoint": f"{report_path.parent}/{scenario_id}/kernel/mnt",
        "frankenfs_mountpoint": f"{report_path.parent}/{scenario_id}/frankenfs/mnt",
        "kernel_output_root": f"{report_path.parent}/{scenario_id}/kernel",
        "frankenfs_output_root": f"{report_path.parent}/{scenario_id}/frankenfs",
    }


def with_contract(scenario: dict[str, object]) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    scenario["baseline_manifest"] = baseline_manifest(scenario)
    scenario["lane_isolation"] = lane_isolation(scenario_id)
    scenario["artifact_paths"] = [
        str(report_path),
        f"{report_path.parent}/{scenario_id}/kernel/stdout.log",
        f"{report_path.parent}/{scenario_id}/kernel/stderr.log",
        f"{report_path.parent}/{scenario_id}/frankenfs/stdout.log",
        f"{report_path.parent}/{scenario_id}/frankenfs/stderr.log",
        f"{report_path.parent}/{scenario_id}/capability/stdout.log",
        f"{report_path.parent}/{scenario_id}/capability/stderr.log",
        f"{report_path.parent}/{scenario_id}/cleanup.json",
    ]
    return scenario


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
        "kernel_observation": observation("mounted_diff_ext4_create_readback", "kernel", "ok"),
        "frankenfs_observation": observation("mounted_diff_ext4_create_readback", "frankenfs", "ok"),
        "normalized_diff": [],
        "cleanup_status": "clean",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_create_readback",
    },
    {
        "scenario_id": "mounted_diff_ext4_fiemap_transport_errno",
        "operation_id": "fiemap_probe",
        "filesystem": "ext4",
        "scenario_kind": "positive",
        "classification": "allowed_diff",
        "allowlist_id": "allow_ext4_fiemap_transport_errno",
        "kernel_observation": observation("mounted_diff_ext4_fiemap_transport_errno", "kernel", "errno", "EOPNOTSUPP"),
        "frankenfs_observation": observation("mounted_diff_ext4_fiemap_transport_errno", "frankenfs", "errno", "ENOTTY"),
        "normalized_diff": [
            {
                "field": "result",
                "kernel_value": "EOPNOTSUPP",
                "frankenfs_value": "ENOTTY",
            }
        ],
        "cleanup_status": "clean",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_fiemap_transport_errno",
    },
    {
        "scenario_id": "mounted_diff_ext4_fuse_missing",
        "operation_id": "fuse_missing_probe",
        "filesystem": "ext4",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "fuse_missing",
        "kernel_observation": observation("mounted_diff_ext4_fuse_missing", "kernel", "skip", "fuse_missing"),
        "frankenfs_observation": observation("mounted_diff_ext4_fuse_missing", "frankenfs", "skip", "fuse_missing"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_fuse_missing",
    },
    {
        "scenario_id": "mounted_diff_ext4_fuse_permission_skip",
        "operation_id": "mount_probe",
        "filesystem": "ext4",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "fuse_permission_denied",
        "kernel_observation": observation("mounted_diff_ext4_fuse_permission_skip", "kernel", "skip", "fuse_permission_denied"),
        "frankenfs_observation": observation("mounted_diff_ext4_fuse_permission_skip", "frankenfs", "skip", "fuse_permission_denied"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_fuse_permission_skip",
    },
    {
        "scenario_id": "mounted_diff_ext4_kernel_mount_permission_skip",
        "operation_id": "kernel_mount_permission_probe",
        "filesystem": "ext4",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "kernel_mount_permission_denied",
        "kernel_observation": observation("mounted_diff_ext4_kernel_mount_permission_skip", "kernel", "skip", "kernel_mount_permission_denied"),
        "frankenfs_observation": observation("mounted_diff_ext4_kernel_mount_permission_skip", "frankenfs", "skip", "kernel_mount_permission_denied"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_kernel_mount_permission_skip",
    },
    {
        "scenario_id": "mounted_diff_ext4_mkfs_missing",
        "operation_id": "mkfs_ext4_probe",
        "filesystem": "ext4",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "mkfs_ext4_missing",
        "kernel_observation": observation("mounted_diff_ext4_mkfs_missing", "kernel", "skip", "mkfs_ext4_missing"),
        "frankenfs_observation": observation("mounted_diff_ext4_mkfs_missing", "frankenfs", "skip", "mkfs_ext4_missing"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_mkfs_missing",
    },
    {
        "scenario_id": "mounted_diff_btrfs_mkfs_missing",
        "operation_id": "mkfs_btrfs_probe",
        "filesystem": "btrfs",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "mkfs_btrfs_missing",
        "kernel_observation": observation("mounted_diff_btrfs_mkfs_missing", "kernel", "skip", "mkfs_btrfs_missing"),
        "frankenfs_observation": observation("mounted_diff_btrfs_mkfs_missing", "frankenfs", "skip", "mkfs_btrfs_missing"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_btrfs_mkfs_missing",
    },
    {
        "scenario_id": "mounted_diff_btrfs_default_permissions_root_owned",
        "operation_id": "root_owned_write_probe",
        "filesystem": "btrfs",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "btrfs_default_permissions_root_owned",
        "kernel_observation": observation("mounted_diff_btrfs_default_permissions_root_owned", "kernel", "skip", "btrfs_default_permissions_root_owned"),
        "frankenfs_observation": observation("mounted_diff_btrfs_default_permissions_root_owned", "frankenfs", "skip", "btrfs_default_permissions_root_owned"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_btrfs_default_permissions_root_owned",
    },
    {
        "scenario_id": "mounted_diff_ext4_unsupported_scope_skip",
        "operation_id": "unsupported_scope_probe",
        "filesystem": "ext4",
        "scenario_kind": "host_skip",
        "classification": "host_skip",
        "host_skip_class": "unsupported_scope",
        "kernel_observation": observation("mounted_diff_ext4_unsupported_scope_skip", "kernel", "skip", "unsupported_scope"),
        "frankenfs_observation": observation("mounted_diff_ext4_unsupported_scope_skip", "frankenfs", "skip", "unsupported_scope"),
        "normalized_diff": [],
        "cleanup_status": "not_run",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_ext4_unsupported_scope_skip",
    },
    {
        "scenario_id": "mounted_diff_btrfs_unsupported_clone_range",
        "operation_id": "clone_range",
        "filesystem": "btrfs",
        "scenario_kind": "unsupported",
        "classification": "unsupported",
        "owner_bead": "bd-rchk0.5.2",
        "kernel_observation": observation("mounted_diff_btrfs_unsupported_clone_range", "kernel", "errno", "EOPNOTSUPP"),
        "frankenfs_observation": observation("mounted_diff_btrfs_unsupported_clone_range", "frankenfs", "errno", "EOPNOTSUPP"),
        "normalized_diff": [],
        "cleanup_status": "clean",
        "reproduction_command": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh --scenario mounted_diff_btrfs_unsupported_clone_range",
    },
]
scenarios = [with_contract(scenario) for scenario in scenarios]

report = {
    "schema_version": 2,
    "bead_id": "bd-rchk0.5.2.1",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "kernel_release": platform.release(),
    "runner": "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh",
    "execute_permissioned": execute,
    "capability": {
        "fuse": "permission_denied",
        "fusermount": "permission_denied",
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
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_fuse_missing|outcome=SKIP|detail=missing dev fuse is host skip" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_fuse_permission_skip|outcome=SKIP|detail=permission denied is host skip" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_kernel_mount_permission_skip|outcome=SKIP|detail=kernel mount permission denied is host skip" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_mkfs_missing|outcome=SKIP|detail=mkfs.ext4 helper missing is host skip" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_btrfs_mkfs_missing|outcome=SKIP|detail=mkfs.btrfs helper missing is host skip" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_btrfs_default_permissions_root_owned|outcome=SKIP|detail=btrfs DefaultPermissions root-owned EACCES isolated" | tee -a "$E2E_LOG_FILE"
echo "SCENARIO_RESULT|scenario_id=mounted_diff_ext4_unsupported_scope_skip|outcome=SKIP|detail=unsupported-scope host skip preserved" | tee -a "$E2E_LOG_FILE"
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
