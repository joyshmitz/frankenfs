#!/usr/bin/env bash
# ffs_xfstests_preflight_e2e.sh - hermetic xfstests prerequisite proof.
#
# The manifest emitted here separates host setup failures from FrankenFS
# behavior. It is intentionally standalone so it can run before any harness
# binary or xfstests checkout exists.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

OUT_PATH=""
FIXTURE_MODE="${XFSTESTS_PREFLIGHT_FIXTURE:-}"
SELF_TEST=0

usage() {
    cat <<'EOF'
Usage: scripts/e2e/ffs_xfstests_preflight_e2e.sh [OPTIONS]

Options:
  --out FILE          Write the prerequisite manifest to FILE.
  --fixture NAME     Use a simulated host state: all-present, blocked,
                     host-missing, permission-denied, dpkg-locked,
                     worker, worker-mismatch, unsupported-local.
  --self-test        Run fixture-mode script tests and write a self-test report.
  -h, --help         Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)
            OUT_PATH="${2:?--out requires a path}"
            shift 2
            ;;
        --fixture)
            FIXTURE_MODE="${2:?--fixture requires a name}"
            shift 2
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$OUT_PATH" ]]; then
    timestamp=$(date +%Y%m%d_%H%M%S)
    OUT_PATH="$REPO_ROOT/artifacts/e2e/${timestamp}_xfstests_preflight/preflight.json"
fi

export OUT_PATH FIXTURE_MODE SELF_TEST

python3 - <<'PY'
import json
import os
import pathlib
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

STATUS_VALUES = {
    "present",
    "missing",
    "blocked-by-host",
    "blocked-by-lock",
    "unsupported-locally",
    "available-on-worker",
}

PREFLIGHT_ID = "xfstests-preflight-v1"
PROBE_VERSION = "xfstests-preflight-2026-05-05"
RISK_VALUES = {"satisfied", "blocking", "advisory"}
LANE_IMPACT_VALUES = {
    "none",
    "blocks_permissioned_real_xfstests",
    "release_evidence_requires_worker",
}
SIDE_EFFECT_POLICY = "read_only_probe_no_install_no_mount_no_host_mutation"
SAFE_REMEDIATION = {
    "automation": "manual_only",
    "runner_executes_remediation": False,
    "auto_install": False,
    "mounts_or_unmounts": False,
    "creates_persistent_paths": False,
}
PACKAGE_MANAGER_COMMANDS = {
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "brew",
}
PERSISTENT_MUTATION_COMMANDS = {
    "cp",
    "dd",
    "install",
    "mkdir",
    "mv",
    "rm",
    "rmdir",
    "tee",
    "touch",
    "truncate",
}
VERSION_ONLY_COMMANDS = {
    "mkfs.ext4",
    "mkfs.xfs",
    "mount",
    "umount",
    "fusermount",
    "fusermount3",
}
VERSION_ARGS = {"--version", "-V", "-v", "-h", "--help"}

REQUIRED_PROBES = [
    "xfs_headers",
    "libaio",
    "ltp_fsstress",
    "xfstests_helpers",
    "mkfs_mount_helpers",
    "dev_fuse",
    "fusermount3",
    "user_namespace_or_mount_permissions",
    "scratch_test_directories",
    "dpkg_lock_state",
    "rch_ci_worker_identity",
]

out_path = pathlib.Path(os.environ["OUT_PATH"])
fixture_mode = os.environ.get("FIXTURE_MODE", "")
self_test = os.environ.get("SELF_TEST") == "1"
repo_root = pathlib.Path(os.environ.get("REPO_ROOT", os.getcwd()))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_safe(value):
    if isinstance(value, pathlib.Path):
        return str(value)
    return value


def run_probe(name: str, argv: list[str], transcript_dir: pathlib.Path) -> dict:
    stdout_path = transcript_dir / f"{name}.stdout"
    stderr_path = transcript_dir / f"{name}.stderr"
    started = time.time()
    rc = 127
    try:
        proc = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        rc = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except FileNotFoundError as exc:
        stdout = ""
        stderr = str(exc)
    except subprocess.TimeoutExpired as exc:
        rc = 124
        stdout = exc.stdout or ""
        stderr = exc.stderr or "probe timed out"

    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
    return {
        "name": name,
        "argv": argv,
        "exit_code": rc,
        "duration_ms": round((time.time() - started) * 1000, 3),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def preflight_reproduction_command() -> str:
    env_parts = []
    for key in ["XFSTESTS_DIR", "TEST_DIR", "SCRATCH_MNT"]:
        value = os.environ.get(key, "")
        if value:
            env_parts.append(f"{key}={shlex.quote(value)}")
    command = f"{repo_root}/scripts/e2e/ffs_xfstests_preflight_e2e.sh --out {shlex.quote(str(out_path))}"
    return " ".join([*env_parts, command])


def risk_level_for(status: str, blocks: bool) -> str:
    if blocks and status != "present":
        return "blocking"
    if status in {"unsupported-locally", "available-on-worker"}:
        return "advisory"
    return "satisfied"


def lane_impact_for(name: str, status: str, blocks: bool) -> str:
    if blocks and status != "present":
        return "blocks_permissioned_real_xfstests"
    if name == "rch_ci_worker_identity" and status == "unsupported-locally":
        return "release_evidence_requires_worker"
    return "none"


def command_version(command: str, args: list[str], transcript_dir: pathlib.Path) -> tuple[bool, str | None, dict]:
    path = shutil.which(command)
    if path is None:
        return False, None, {
            "name": f"{command}_version",
            "argv": [command, *args],
            "exit_code": 127,
            "stdout_path": "",
            "stderr_path": "",
        }
    probe = run_probe(f"{command.replace('.', '_')}_version", [path, *args], transcript_dir)
    version_text = None
    for candidate_path in (probe["stdout_path"], probe["stderr_path"]):
        if not candidate_path:
            continue
        text = pathlib.Path(candidate_path).read_text(encoding="utf-8", errors="replace").strip()
        if text:
            version_text = text.splitlines()[0]
            break
    return True, version_text or path, probe


def prereq(
    name: str,
    status: str,
    *,
    blocks: bool,
    remediation: str,
    evidence: list[str] | None = None,
    version: str | None = None,
    probes: list[dict] | None = None,
    observed_value: str | None = None,
) -> dict:
    assert status in STATUS_VALUES, status
    risk_level = risk_level_for(status, blocks)
    lane_impact = lane_impact_for(name, status, blocks)
    observed = observed_value
    if observed is None:
        observed = "; ".join(evidence or []) or status
    requires_operator_action = status != "present"
    return {
        "name": name,
        "prerequisite_id": name,
        "preflight_id": PREFLIGHT_ID,
        "probe_version": PROBE_VERSION,
        "status": status,
        "classification": f"{name}:{status}",
        "blocks_real_xfstests": blocks,
        "observed_value": observed,
        "remediation": remediation,
        "remediation_text_id": f"xfstests-preflight-{name.replace('_', '-')}",
        "risk_level": risk_level,
        "authoritative_lane_impact": lane_impact,
        "side_effect_policy": SIDE_EFFECT_POLICY,
        "safe_remediation": dict(SAFE_REMEDIATION),
        "safe_guidance": {
            "user_action_text": remediation,
            "requires_operator_action": requires_operator_action,
            "requires_fresh_follow_up_probe": True,
            "may_run_package_manager": False,
            "may_run_install": False,
            "may_mount_or_unmount": False,
            "may_create_persistent_paths": False,
            "claim_state_after_remediation": (
                "blocked_until_fresh_probe" if requires_operator_action else "satisfied_by_current_probe"
            ),
        },
        "reproduction_command": preflight_reproduction_command(),
        "evidence": evidence or [],
        "version": version,
        "probes": probes or [],
    }


def fixture_manifest(mode: str, artifact_dir: pathlib.Path) -> dict:
    fixture_modes = {
        "all-present",
        "blocked",
        "host-missing",
        "permission-denied",
        "dpkg-locked",
        "worker",
        "worker-mismatch",
        "unsupported-local",
    }
    if mode not in fixture_modes:
        raise SystemExit(f"unknown fixture mode: {mode}")

    status_by_name: dict[str, tuple[str, bool, str]] = {
        name: ("present", False, "fixture marks prerequisite present")
        for name in REQUIRED_PROBES
    }

    def set_status(name: str, status: str, blocks: bool, remediation: str) -> None:
        status_by_name[name] = (status, blocks, remediation)

    if mode == "blocked":
        set_status("xfs_headers", "missing", True, "install xfslibs-dev or xfsprogs-devel")
        set_status("libaio", "missing", True, "install libaio-dev")
        set_status("ltp_fsstress", "missing", True, "build xfstests ltp/fsstress helper")
        set_status("xfstests_helpers", "missing", True, "provide a built xfstests checkout")
        set_status("mkfs_mount_helpers", "missing", True, "install e2fsprogs, xfsprogs, and util-linux helpers")
        set_status("dev_fuse", "blocked-by-host", True, "enable /dev/fuse with read/write access")
        set_status("fusermount3", "missing", True, "install fuse3")
        set_status("scratch_test_directories", "blocked-by-host", True, "provide writable TEST_DIR and SCRATCH_MNT")
        set_status("dpkg_lock_state", "blocked-by-lock", True, "wait for package manager lock to clear")
        set_status(
            "rch_ci_worker_identity",
            "unsupported-locally",
            False,
            "run through RCH/CI to record worker identity",
        )
    elif mode == "host-missing":
        set_status("xfs_headers", "missing", True, "install xfslibs-dev or xfsprogs-devel")
        set_status("libaio", "missing", True, "install libaio-dev")
        set_status("ltp_fsstress", "missing", True, "build xfstests ltp/fsstress helper")
        set_status("xfstests_helpers", "missing", True, "provide a built xfstests checkout")
        set_status("mkfs_mount_helpers", "missing", True, "install e2fsprogs, xfsprogs, and util-linux helpers")
        set_status("fusermount3", "missing", True, "install fuse3")
    elif mode == "permission-denied":
        set_status("dev_fuse", "blocked-by-host", True, "grant the runner read/write access to /dev/fuse")
        set_status("fusermount3", "blocked-by-host", True, "fix fusermount3 permission for the runner user")
        set_status(
            "user_namespace_or_mount_permissions",
            "blocked-by-host",
            True,
            "run as a user with mount permission or enable unprivileged user namespaces",
        )
        set_status(
            "scratch_test_directories",
            "blocked-by-host",
            True,
            "provide writable TEST_DIR and SCRATCH_MNT owned by the runner user",
        )
    elif mode == "dpkg-locked":
        set_status("dpkg_lock_state", "blocked-by-lock", True, "wait for apt/dpkg locks to clear before installing prerequisites")
    elif mode == "worker":
        status_by_name["rch_ci_worker_identity"] = (
            "available-on-worker",
            False,
            "worker identity captured from fixture",
        )
    elif mode == "worker-mismatch":
        set_status(
            "rch_ci_worker_identity",
            "blocked-by-host",
            True,
            "rerun on the configured RCH/CI worker identity before claiming release evidence",
        )
    elif mode == "unsupported-local":
        set_status(
            "rch_ci_worker_identity",
            "unsupported-locally",
            False,
            "local lane is advisory only; rerun through RCH/CI for authoritative release evidence",
        )

    return build_manifest(
        [
            prereq(
                name,
                status,
                blocks=blocks,
                remediation=remediation,
                evidence=[f"fixture:{mode}:{name}"],
                version=f"fixture-{mode}",
                observed_value=f"fixture:{mode}:{name}:{status}",
            )
            for name, (status, blocks, remediation) in status_by_name.items()
        ],
        artifact_dir=artifact_dir,
        fixture=mode,
    )


def detect_manifest(artifact_dir: pathlib.Path) -> dict:
    transcript_dir = artifact_dir / "transcripts"
    transcript_dir.mkdir(parents=True, exist_ok=True)
    prereqs: list[dict] = []

    xfstests_dir = pathlib.Path(os.environ.get("XFSTESTS_DIR", "") or "/nonexistent")
    xfs_header_candidates = [
        pathlib.Path("/usr/include/xfs/xfs.h"),
        pathlib.Path("/usr/include/xfs/linux.h"),
        pathlib.Path("/usr/include/xfs/xfs_format.h"),
    ]
    xfs_headers = [str(path) for path in xfs_header_candidates if path.exists()]
    prereqs.append(
        prereq(
            "xfs_headers",
            "present" if xfs_headers else "missing",
            blocks=not bool(xfs_headers),
            remediation="install xfslibs-dev on Debian/Ubuntu or xfsprogs-devel on Fedora",
            evidence=xfs_headers,
        )
    )

    libaio_header = pathlib.Path("/usr/include/libaio.h")
    libaio_present = libaio_header.exists() or shutil.which("pkg-config") is not None and subprocess.run(
        ["pkg-config", "--exists", "libaio"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    prereqs.append(
        prereq(
            "libaio",
            "present" if libaio_present else "missing",
            blocks=not libaio_present,
            remediation="install libaio-dev on Debian/Ubuntu or libaio-devel on Fedora",
            evidence=[str(libaio_header)] if libaio_header.exists() else [],
        )
    )

    fsstress_candidates = [
        xfstests_dir / "ltp" / "fsstress",
        xfstests_dir / "src" / "fsstress",
    ]
    fsstress_on_path = shutil.which("fsstress")
    if fsstress_on_path:
        fsstress_candidates.insert(0, pathlib.Path(fsstress_on_path))
    fsstress_paths = [str(path) for path in fsstress_candidates if path.exists()]
    prereqs.append(
        prereq(
            "ltp_fsstress",
            "present" if fsstress_paths else "missing",
            blocks=not bool(fsstress_paths),
            remediation="build xfstests ltp/fsstress or expose fsstress on PATH",
            evidence=fsstress_paths,
        )
    )

    helper_paths = [
        xfstests_dir / "check",
        xfstests_dir / "common" / "rc",
        xfstests_dir / "tests" / "generic",
        xfstests_dir / "tests" / "ext4",
    ]
    present_helpers = [str(path) for path in helper_paths if path.exists()]
    helpers_present = len(present_helpers) == len(helper_paths) and os.access(xfstests_dir / "check", os.X_OK)
    prereqs.append(
        prereq(
            "xfstests_helpers",
            "present" if helpers_present else "missing",
            blocks=not helpers_present,
            remediation="set XFSTESTS_DIR to a built xfstests checkout with check, common/rc, tests/generic, and tests/ext4",
            evidence=present_helpers,
        )
    )

    helper_probes = []
    helper_versions = []
    for command, args in (
        ("mkfs.ext4", ["-V"]),
        ("mkfs.xfs", ["-V"]),
        ("mount", ["--version"]),
        ("umount", ["--version"]),
    ):
        present, version, probe = command_version(command, args, transcript_dir)
        helper_probes.append(probe)
        if present and version:
            helper_versions.append(f"{command}: {version}")
    prereqs.append(
        prereq(
            "mkfs_mount_helpers",
            "present" if len(helper_versions) >= 3 else "missing",
            blocks=len(helper_versions) < 3,
            remediation="install e2fsprogs, xfsprogs, and util-linux mount helpers",
            evidence=helper_versions,
            version="; ".join(helper_versions) if helper_versions else None,
            probes=helper_probes,
        )
    )

    dev_fuse = pathlib.Path("/dev/fuse")
    dev_fuse_present = dev_fuse.exists() and os.access(dev_fuse, os.R_OK | os.W_OK)
    prereqs.append(
        prereq(
            "dev_fuse",
            "present" if dev_fuse_present else "blocked-by-host",
            blocks=not dev_fuse_present,
            remediation="enable /dev/fuse and grant read/write access to the runner user",
            evidence=[str(dev_fuse)] if dev_fuse.exists() else [],
        )
    )

    fusermount_present, fusermount_version, fusermount_probe = command_version(
        "fusermount3", ["--version"], transcript_dir
    )
    if not fusermount_present:
        fusermount_present, fusermount_version, fusermount_probe = command_version(
            "fusermount", ["--version"], transcript_dir
        )
    prereqs.append(
        prereq(
            "fusermount3",
            "present" if fusermount_present else "missing",
            blocks=not fusermount_present,
            remediation="install fuse3 so fusermount3 is available",
            evidence=[fusermount_version] if fusermount_version else [],
            version=fusermount_version,
            probes=[fusermount_probe],
        )
    )

    userns_evidence = []
    userns_ok = os.geteuid() == 0
    userns_path = pathlib.Path("/proc/sys/kernel/unprivileged_userns_clone")
    if userns_path.exists():
        userns_evidence.append(f"{userns_path}={userns_path.read_text(encoding='utf-8').strip()}")
        userns_ok = userns_ok or userns_path.read_text(encoding="utf-8").strip() == "1"
    unshare_path = shutil.which("unshare")
    if unshare_path:
        probe = run_probe("unshare_userns_probe", [unshare_path, "-Ur", "true"], transcript_dir)
        userns_evidence.append(f"unshare_rc={probe['exit_code']}")
        userns_ok = userns_ok or probe["exit_code"] == 0
        userns_probes = [probe]
    else:
        userns_probes = []
    prereqs.append(
        prereq(
            "user_namespace_or_mount_permissions",
            "present" if userns_ok else "blocked-by-host",
            blocks=not userns_ok,
            remediation="run as a user with mount/FUSE permission or enable unprivileged user namespaces",
            evidence=userns_evidence,
            probes=userns_probes,
        )
    )

    test_dir_raw = os.environ.get("TEST_DIR", "")
    scratch_mnt_raw = os.environ.get("SCRATCH_MNT", "")
    dirs = [
        pathlib.Path(test_dir_raw) if test_dir_raw else None,
        pathlib.Path(scratch_mnt_raw) if scratch_mnt_raw else None,
    ]
    dirs_present = all(path is not None and path.exists() and os.access(path, os.W_OK) for path in dirs)
    prereqs.append(
        prereq(
            "scratch_test_directories",
            "present" if dirs_present else "blocked-by-host",
            blocks=not dirs_present,
            remediation="set TEST_DIR and SCRATCH_MNT to writable, isolated xfstests directories",
            evidence=[str(path) for path in dirs if path is not None and path.exists()],
        )
    )

    lock_paths = [
        pathlib.Path("/var/lib/dpkg/lock-frontend"),
        pathlib.Path("/var/lib/dpkg/lock"),
        pathlib.Path("/var/cache/apt/archives/lock"),
    ]
    active_locks = []
    lock_probes = []
    fuser = shutil.which("fuser")
    for lock_path in lock_paths:
        if not lock_path.exists():
            continue
        if fuser:
            probe = run_probe(
                f"dpkg_lock_{lock_path.name.replace('-', '_')}",
                [fuser, str(lock_path)],
                transcript_dir,
            )
            lock_probes.append(probe)
            if probe["exit_code"] == 0:
                active_locks.append(str(lock_path))
    prereqs.append(
        prereq(
            "dpkg_lock_state",
            "blocked-by-lock" if active_locks else "present",
            blocks=bool(active_locks),
            remediation="wait for apt/dpkg activity to finish before installing xfstests prerequisites",
            evidence=active_locks,
            probes=lock_probes,
        )
    )

    worker_env = {
        key: value
        for key, value in os.environ.items()
        if key.startswith(("RCH_", "CI", "GITHUB_ACTIONS", "BUILDKITE", "TEAMCITY"))
    }
    worker_status = "available-on-worker" if any(key.startswith("RCH_") for key in worker_env) else (
        "present" if worker_env.get("CI") or worker_env.get("GITHUB_ACTIONS") else "unsupported-locally"
    )
    prereqs.append(
        prereq(
            "rch_ci_worker_identity",
            worker_status,
            blocks=False,
            remediation="run through rch exec or CI when worker identity is required for release evidence",
            evidence=[f"{key}={value}" for key, value in sorted(worker_env.items())],
            version=socket.gethostname(),
        )
    )

    return build_manifest(prereqs, artifact_dir=artifact_dir, fixture=None)


def build_manifest(prereqs: list[dict], *, artifact_dir: pathlib.Path, fixture: str | None) -> dict:
    blocking = [
        item["name"]
        for item in prereqs
        if item["blocks_real_xfstests"] and item["status"] != "present"
    ]
    status_counts: dict[str, int] = {}
    for item in prereqs:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
    return {
        "schema_version": 1,
        "preflight_id": PREFLIGHT_ID,
        "probe_version": PROBE_VERSION,
        "bead_id": "bd-rchk3.1.1",
        "refinement_bead_id": "bd-f3hug",
        "created_at": iso_now(),
        "fixture_mode": fixture,
        "verdict": "pass" if not blocking else "blocked",
        "status_vocabulary": sorted(STATUS_VALUES),
        "risk_vocabulary": sorted(RISK_VALUES),
        "authoritative_lane_impact_vocabulary": sorted(LANE_IMPACT_VALUES),
        "blocking_prerequisites": blocking,
        "status_counts": dict(sorted(status_counts.items())),
        "prerequisites": prereqs,
        "remediation_safety": {
            "side_effect_policy": SIDE_EFFECT_POLICY,
            "runner_executes_remediation": False,
            "auto_install": False,
            "mounts_or_unmounts": False,
            "creates_persistent_paths": False,
            "requires_fresh_follow_up_probe": True,
        },
        "coverage_claim_policy": {
            "product_baseline_requires_verdict": "pass",
            "missing_or_blocked_prerequisites_block_product_baseline": True,
            "remediation_never_satisfies_without_fresh_probe": True,
            "unsupported_local_lane_is_advisory_for_local_runs": True,
            "authoritative_release_evidence_requires_worker_or_ci": True,
        },
        "host": {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "platform": platform.platform(),
            "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
            "uid": os.geteuid(),
        },
        "worker_identity": {
            "hostname": socket.gethostname(),
            "rch": {
                key: value
                for key, value in sorted(os.environ.items())
                if key.startswith("RCH_")
            },
            "ci": {
                key: value
                for key, value in sorted(os.environ.items())
                if key in {"CI", "GITHUB_ACTIONS", "BUILDKITE", "TEAMCITY_VERSION"}
            },
        },
        "paths": {
            "repo_root": str(repo_root),
            "xfstests_dir": os.environ.get("XFSTESTS_DIR", ""),
            "test_dir": os.environ.get("TEST_DIR", ""),
            "scratch_mnt": os.environ.get("SCRATCH_MNT", ""),
            "artifact_dir": str(artifact_dir),
        },
        "transcript_dir": str(artifact_dir / "transcripts"),
        "stdout_path": str(artifact_dir / "stdout.log"),
        "stderr_path": str(artifact_dir / "stderr.log"),
        "cleanup_status": "no_mounts_or_temp_files_created",
        "reproduction_command": preflight_reproduction_command(),
        "links": {
            "selected_test_policy_bead": "bd-rchk3.2",
            "real_execution_bead": "bd-rchk3.3",
        },
    }


def is_safe_probe_argv(argv: object) -> bool:
    if not isinstance(argv, list) or not argv:
        return False
    command = pathlib.Path(str(argv[0])).name
    args = [str(arg) for arg in argv[1:]]
    if command in PACKAGE_MANAGER_COMMANDS or command in PERSISTENT_MUTATION_COMMANDS:
        return False
    if command in VERSION_ONLY_COMMANDS:
        return bool(args) and all(arg in VERSION_ARGS for arg in args)
    return True


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("manifest schema_version must be 1")
    if manifest.get("preflight_id") != PREFLIGHT_ID:
        errors.append(f"manifest preflight_id must be {PREFLIGHT_ID}")
    if manifest.get("probe_version") != PROBE_VERSION:
        errors.append(f"manifest probe_version must be {PROBE_VERSION}")
    if manifest.get("bead_id") != "bd-rchk3.1.1":
        errors.append("manifest bead_id must be bd-rchk3.1.1")
    if set(manifest.get("status_vocabulary", [])) != STATUS_VALUES:
        errors.append("manifest status_vocabulary does not match required statuses")
    if set(manifest.get("risk_vocabulary", [])) != RISK_VALUES:
        errors.append("manifest risk_vocabulary does not match required risk levels")
    if set(manifest.get("authoritative_lane_impact_vocabulary", [])) != LANE_IMPACT_VALUES:
        errors.append("manifest authoritative lane-impact vocabulary does not match required values")

    safety = manifest.get("remediation_safety")
    if not isinstance(safety, dict):
        errors.append("manifest missing remediation_safety")
    else:
        if safety.get("side_effect_policy") != SIDE_EFFECT_POLICY:
            errors.append("manifest has unexpected side_effect_policy")
        for field in [
            "runner_executes_remediation",
            "auto_install",
            "mounts_or_unmounts",
            "creates_persistent_paths",
        ]:
            if safety.get(field) is not False:
                errors.append(f"manifest remediation_safety {field} must be false")
        if safety.get("requires_fresh_follow_up_probe") is not True:
            errors.append("manifest remediation_safety requires_fresh_follow_up_probe must be true")

    claim_policy = manifest.get("coverage_claim_policy")
    if not isinstance(claim_policy, dict):
        errors.append("manifest missing coverage_claim_policy")
    else:
        if claim_policy.get("product_baseline_requires_verdict") != "pass":
            errors.append("coverage_claim_policy product_baseline_requires_verdict must be pass")
        for field in [
            "missing_or_blocked_prerequisites_block_product_baseline",
            "remediation_never_satisfies_without_fresh_probe",
            "authoritative_release_evidence_requires_worker_or_ci",
        ]:
            if claim_policy.get(field) is not True:
                errors.append(f"coverage_claim_policy {field} must be true")

    prereqs = manifest.get("prerequisites")
    if not isinstance(prereqs, list):
        return ["manifest prerequisites must be a list"]
    names = {item.get("name") for item in prereqs if isinstance(item, dict)}
    for name in REQUIRED_PROBES:
        if name not in names:
            errors.append(f"missing prerequisite probe: {name}")
    for item in prereqs:
        if not isinstance(item, dict):
            errors.append("prerequisite row must be an object")
            continue
        name = item.get("name", "<unknown>")
        if item.get("preflight_id") != PREFLIGHT_ID:
            errors.append(f"{name} missing preflight_id {PREFLIGHT_ID}")
        if item.get("probe_version") != PROBE_VERSION:
            errors.append(f"{name} missing probe_version {PROBE_VERSION}")
        if item.get("prerequisite_id") != name:
            errors.append(f"{name} prerequisite_id must match name")
        if item.get("status") not in STATUS_VALUES:
            errors.append(f"{name} has invalid status {item.get('status')!r}")
        if not item.get("observed_value"):
            errors.append(f"{name} missing observed_value")
        if not item.get("remediation"):
            errors.append(f"{name} missing remediation")
        if not str(item.get("remediation_text_id", "")).startswith("xfstests-preflight-"):
            errors.append(f"{name} missing remediation_text_id")
        if item.get("risk_level") not in RISK_VALUES:
            errors.append(f"{name} has invalid risk_level {item.get('risk_level')!r}")
        if item.get("authoritative_lane_impact") not in LANE_IMPACT_VALUES:
            errors.append(
                f"{name} has invalid authoritative_lane_impact {item.get('authoritative_lane_impact')!r}"
            )
        if item.get("side_effect_policy") != SIDE_EFFECT_POLICY:
            errors.append(f"{name} has unexpected side_effect_policy")
        safe = item.get("safe_remediation")
        if not isinstance(safe, dict):
            errors.append(f"{name} missing safe_remediation")
        else:
            if safe.get("automation") != "manual_only":
                errors.append(f"{name} remediation automation must be manual_only")
            for field in [
                "runner_executes_remediation",
                "auto_install",
                "mounts_or_unmounts",
                "creates_persistent_paths",
            ]:
                if safe.get(field) is not False:
                    errors.append(f"{name} safe_remediation {field} must be false")
        guidance = item.get("safe_guidance")
        if not isinstance(guidance, dict):
            errors.append(f"{name} missing safe_guidance")
        else:
            if guidance.get("user_action_text") != item.get("remediation"):
                errors.append(f"{name} safe_guidance must repeat remediation text")
            if guidance.get("requires_fresh_follow_up_probe") is not True:
                errors.append(f"{name} safe_guidance must require a fresh follow-up probe")
            for field in [
                "may_run_package_manager",
                "may_run_install",
                "may_mount_or_unmount",
                "may_create_persistent_paths",
            ]:
                if guidance.get(field) is not False:
                    errors.append(f"{name} safe_guidance {field} must be false")
            requires_action = item.get("status") != "present"
            if guidance.get("requires_operator_action") is not requires_action:
                errors.append(f"{name} safe_guidance requires_operator_action mismatch")
            expected_claim_state = (
                "blocked_until_fresh_probe" if requires_action else "satisfied_by_current_probe"
            )
            if guidance.get("claim_state_after_remediation") != expected_claim_state:
                errors.append(f"{name} safe_guidance claim_state_after_remediation must be {expected_claim_state}")
        if not item.get("reproduction_command"):
            errors.append(f"{name} missing reproduction_command")
        if "blocks_real_xfstests" not in item:
            errors.append(f"{name} missing blocks_real_xfstests")
        expected_risk = risk_level_for(str(item.get("status")), bool(item.get("blocks_real_xfstests")))
        if item.get("risk_level") != expected_risk:
            errors.append(f"{name} risk_level must be {expected_risk}")
        expected_impact = lane_impact_for(
            str(item.get("name")), str(item.get("status")), bool(item.get("blocks_real_xfstests"))
        )
        if item.get("authoritative_lane_impact") != expected_impact:
            errors.append(f"{name} authoritative_lane_impact must be {expected_impact}")
        for probe in item.get("probes", []):
            if isinstance(probe, dict) and not is_safe_probe_argv(probe.get("argv")):
                errors.append(f"{name} probe argv is not side-effect safe: {probe.get('argv')}")
    for field in [
        "created_at",
        "verdict",
        "host",
        "worker_identity",
        "paths",
        "status_vocabulary",
        "risk_vocabulary",
        "authoritative_lane_impact_vocabulary",
        "blocking_prerequisites",
        "transcript_dir",
        "stdout_path",
        "stderr_path",
        "cleanup_status",
        "reproduction_command",
    ]:
        if field not in manifest:
            errors.append(f"manifest missing {field}")
    blocking = manifest.get("blocking_prerequisites")
    if not isinstance(blocking, list):
        errors.append("manifest blocking_prerequisites must be a list")
    else:
        if blocking and manifest.get("verdict") != "blocked":
            errors.append("manifest verdict must be blocked when blocking prerequisites exist")
        if not blocking and manifest.get("verdict") != "pass":
            errors.append("manifest verdict must be pass when no blocking prerequisites exist")
    if manifest.get("cleanup_status") != "no_mounts_or_temp_files_created":
        errors.append("manifest cleanup_status must prove no mounts or temp files were created")
    links = manifest.get("links", {})
    if links.get("selected_test_policy_bead") != "bd-rchk3.2":
        errors.append("manifest must link selected-test policy bead bd-rchk3.2")
    if links.get("real_execution_bead") != "bd-rchk3.3":
        errors.append("manifest must link real execution bead bd-rchk3.3")
    return errors


def write_manifest(manifest: dict, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact_dir = path.parent
    transcript_dir = pathlib.Path(str(manifest.get("transcript_dir") or artifact_dir / "transcripts"))
    transcript_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = pathlib.Path(str(manifest.get("stdout_path") or artifact_dir / "stdout.log"))
    stderr_path = pathlib.Path(str(manifest.get("stderr_path") or artifact_dir / "stderr.log"))
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text("", encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_written_artifacts(manifest: dict) -> list[str]:
    errors: list[str] = []
    for field in ["stdout_path", "stderr_path"]:
        raw = manifest.get(field)
        if not raw:
            errors.append(f"manifest missing {field}")
            continue
        path = pathlib.Path(str(raw))
        if not path.is_file():
            errors.append(f"manifest {field} does not exist: {path}")
    transcript_dir_raw = manifest.get("transcript_dir")
    if not transcript_dir_raw:
        errors.append("manifest missing transcript_dir")
    else:
        transcript_dir = pathlib.Path(str(transcript_dir_raw))
        if not transcript_dir.is_dir():
            errors.append(f"manifest transcript_dir does not exist: {transcript_dir}")
    for row in manifest.get("prerequisites", []):
        if not isinstance(row, dict):
            continue
        for probe in row.get("probes", []):
            if not isinstance(probe, dict):
                continue
            for field in ["stdout_path", "stderr_path"]:
                raw = probe.get(field)
                if raw and not pathlib.Path(str(raw)).is_file():
                    errors.append(f"{row.get('name')} probe {field} does not exist: {raw}")
    return errors


def run_self_test() -> int:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base = repo_root / "artifacts" / "e2e" / f"{timestamp}_xfstests_preflight_selftest"
    base.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    summaries = []

    current_dir = base / "current_host"
    current_manifest = detect_manifest(current_dir)
    current_errors = validate_manifest(current_manifest)
    if current_manifest.get("verdict") not in {"pass", "blocked"}:
        current_errors.append(
            f"current host expected verdict pass or blocked, got {current_manifest.get('verdict')}"
        )
    current_out = current_dir / "preflight.json"
    write_manifest(current_manifest, current_out)
    current_errors.extend(validate_written_artifacts(current_manifest))
    current_outcome = "PASS" if not current_errors else "FAIL"
    print(
        f"SCENARIO_RESULT|scenario_id=xfstests_preflight_current_host|outcome={current_outcome}|detail={current_out}"
    )
    failures.extend(current_errors)
    summaries.append(
        {
            "fixture": None,
            "scenario_id": "xfstests_preflight_current_host",
            "out": str(current_out),
            "verdict": current_manifest.get("verdict"),
            "blocking_prerequisites": current_manifest.get("blocking_prerequisites", []),
            "errors": current_errors,
        }
    )

    expected = {
        "all-present": ("pass", "xfstests_preflight_all_present"),
        "blocked": ("blocked", "xfstests_preflight_blocked"),
        "host-missing": ("blocked", "xfstests_preflight_host_missing"),
        "permission-denied": ("blocked", "xfstests_preflight_permission_denied"),
        "dpkg-locked": ("blocked", "xfstests_preflight_dpkg_locked"),
        "worker": ("pass", "xfstests_preflight_worker"),
        "worker-mismatch": ("blocked", "xfstests_preflight_worker_mismatch"),
        "unsupported-local": ("pass", "xfstests_preflight_unsupported_local"),
    }
    expected_blockers = {
        "host-missing": {
            "xfs_headers",
            "libaio",
            "ltp_fsstress",
            "xfstests_helpers",
            "mkfs_mount_helpers",
            "fusermount3",
        },
        "permission-denied": {
            "dev_fuse",
            "fusermount3",
            "user_namespace_or_mount_permissions",
            "scratch_test_directories",
        },
        "dpkg-locked": {"dpkg_lock_state"},
        "worker-mismatch": {"rch_ci_worker_identity"},
    }
    for mode, (expected_verdict, scenario_id) in expected.items():
        manifest = fixture_manifest(mode, base / mode)
        errors = validate_manifest(manifest)
        if manifest.get("verdict") != expected_verdict:
            errors.append(
                f"fixture {mode} expected verdict {expected_verdict}, got {manifest.get('verdict')}"
            )
        if mode == "blocked":
            observed_statuses = {row["status"] for row in manifest["prerequisites"]}
            for required_status in {"missing", "blocked-by-host", "blocked-by-lock", "unsupported-locally"}:
                if required_status not in observed_statuses:
                    errors.append(f"blocked fixture missing status {required_status}")
            unsafe_rows = [
                row["name"]
                for row in manifest["prerequisites"]
                if row.get("blocks_real_xfstests")
                and row.get("status") != "present"
                and row.get("risk_level") != "blocking"
            ]
            if unsafe_rows:
                errors.append(f"blocked fixture missing blocking risk rows: {unsafe_rows}")
        if mode in expected_blockers:
            blockers = set(manifest.get("blocking_prerequisites", []))
            missing = sorted(expected_blockers[mode] - blockers)
            if missing:
                errors.append(f"fixture {mode} missing expected blockers: {missing}")
        if mode == "worker":
            worker_row = next(row for row in manifest["prerequisites"] if row["name"] == "rch_ci_worker_identity")
            if worker_row["status"] != "available-on-worker":
                errors.append("worker fixture did not classify worker identity as available-on-worker")
        if mode == "unsupported-local":
            worker_row = next(row for row in manifest["prerequisites"] if row["name"] == "rch_ci_worker_identity")
            if worker_row["status"] != "unsupported-locally":
                errors.append("unsupported-local fixture did not classify worker identity as unsupported-locally")
            if worker_row["risk_level"] != "advisory":
                errors.append("unsupported-local fixture should keep worker identity advisory")
        for row in manifest["prerequisites"]:
            safe = row.get("safe_remediation", {})
            if safe.get("runner_executes_remediation") is not False or safe.get("auto_install") is not False:
                errors.append(f"fixture {mode} unsafe remediation row: {row.get('name')}")
            guidance = row.get("safe_guidance", {})
            if (
                guidance.get("may_run_package_manager") is not False
                or guidance.get("may_mount_or_unmount") is not False
                or guidance.get("may_create_persistent_paths") is not False
                or guidance.get("requires_fresh_follow_up_probe") is not True
            ):
                errors.append(f"fixture {mode} unsafe guidance row: {row.get('name')}")
        out = base / mode / "preflight.json"
        write_manifest(manifest, out)
        errors.extend(validate_written_artifacts(manifest))
        outcome = "PASS" if not errors else "FAIL"
        print(f"SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}|detail={out}")
        failures.extend(errors)
        summaries.append(
            {
                "fixture": mode,
                "scenario_id": scenario_id,
                "out": str(out),
                "verdict": manifest.get("verdict"),
                "blocking_prerequisites": manifest.get("blocking_prerequisites", []),
                "errors": errors,
            }
        )
    summary = {
        "schema_version": 1,
        "bead_id": "bd-rchk3.1.1",
        "created_at": iso_now(),
        "fixtures": summaries,
        "verdict": "pass" if not failures else "fail",
        "failures": failures,
    }
    summary_path = base / "self_test_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"self-test summary: {summary_path}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


if self_test:
    raise SystemExit(run_self_test())

artifact_dir = out_path.parent
artifact_dir.mkdir(parents=True, exist_ok=True)
if fixture_mode:
    manifest = fixture_manifest(fixture_mode, artifact_dir)
else:
    manifest = detect_manifest(artifact_dir)
errors = validate_manifest(manifest)
write_manifest(manifest, out_path)
print(f"xfstests preflight manifest: {out_path}")
print(f"verdict: {manifest['verdict']}")
for name in manifest["blocking_prerequisites"]:
    print(f"blocking prerequisite: {name}")
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
PY
