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
  --fixture NAME     Use a simulated host state: all-present, blocked, worker.
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
) -> dict:
    assert status in STATUS_VALUES, status
    return {
        "name": name,
        "status": status,
        "blocks_real_xfstests": blocks,
        "remediation": remediation,
        "evidence": evidence or [],
        "version": version,
        "probes": probes or [],
    }


def fixture_manifest(mode: str, artifact_dir: pathlib.Path) -> dict:
    if mode not in {"all-present", "blocked", "worker"}:
        raise SystemExit(f"unknown fixture mode: {mode}")

    status_by_name: dict[str, tuple[str, bool, str]] = {
        name: ("present", False, "fixture marks prerequisite present")
        for name in REQUIRED_PROBES
    }
    if mode == "blocked":
        status_by_name.update(
            {
                "xfs_headers": ("missing", True, "install xfslibs-dev or xfsprogs-devel"),
                "libaio": ("missing", True, "install libaio-dev"),
                "ltp_fsstress": ("missing", True, "build xfstests ltp/fsstress helper"),
                "xfstests_helpers": ("missing", True, "provide a built xfstests checkout"),
                "dev_fuse": ("blocked-by-host", True, "enable /dev/fuse with read/write access"),
                "fusermount3": ("missing", True, "install fuse3"),
                "scratch_test_directories": (
                    "blocked-by-host",
                    True,
                    "provide writable TEST_DIR and SCRATCH_MNT",
                ),
                "dpkg_lock_state": ("blocked-by-lock", True, "wait for package manager lock to clear"),
                "rch_ci_worker_identity": (
                    "unsupported-locally",
                    False,
                    "run through RCH/CI to record worker identity",
                ),
            }
        )
    elif mode == "worker":
        status_by_name["rch_ci_worker_identity"] = (
            "available-on-worker",
            False,
            "worker identity captured from fixture",
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
        "bead_id": "bd-rchk3.1.1",
        "created_at": iso_now(),
        "fixture_mode": fixture,
        "verdict": "pass" if not blocking else "blocked",
        "status_vocabulary": sorted(STATUS_VALUES),
        "blocking_prerequisites": blocking,
        "status_counts": dict(sorted(status_counts.items())),
        "prerequisites": prereqs,
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
        "reproduction_command": (
            f"XFSTESTS_DIR={os.environ.get('XFSTESTS_DIR', '')} "
            f"TEST_DIR={os.environ.get('TEST_DIR', '')} "
            f"SCRATCH_MNT={os.environ.get('SCRATCH_MNT', '')} "
            f"{repo_root}/scripts/e2e/ffs_xfstests_preflight_e2e.sh --out {out_path}"
        ),
        "links": {
            "selected_test_policy_bead": "bd-rchk3.2",
            "real_execution_bead": "bd-rchk3.3",
        },
    }


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
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
        if item.get("status") not in STATUS_VALUES:
            errors.append(f"{name} has invalid status {item.get('status')!r}")
        if not item.get("remediation"):
            errors.append(f"{name} missing remediation")
        if "blocks_real_xfstests" not in item:
            errors.append(f"{name} missing blocks_real_xfstests")
    for field in [
        "created_at",
        "verdict",
        "status_vocabulary",
        "blocking_prerequisites",
        "transcript_dir",
        "stdout_path",
        "stderr_path",
        "cleanup_status",
        "reproduction_command",
    ]:
        if field not in manifest:
            errors.append(f"manifest missing {field}")
    links = manifest.get("links", {})
    if links.get("selected_test_policy_bead") != "bd-rchk3.2":
        errors.append("manifest must link selected-test policy bead bd-rchk3.2")
    if links.get("real_execution_bead") != "bd-rchk3.3":
        errors.append("manifest must link real execution bead bd-rchk3.3")
    return errors


def write_manifest(manifest: dict, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact_dir = path.parent
    (artifact_dir / "stdout.log").write_text("", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> int:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base = repo_root / "artifacts" / "e2e" / f"{timestamp}_xfstests_preflight_selftest"
    base.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    summaries = []
    expected = {
        "all-present": "pass",
        "blocked": "blocked",
        "worker": "pass",
    }
    for mode, expected_verdict in expected.items():
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
        if mode == "worker":
            worker_row = next(row for row in manifest["prerequisites"] if row["name"] == "rch_ci_worker_identity")
            if worker_row["status"] != "available-on-worker":
                errors.append("worker fixture did not classify worker identity as available-on-worker")
        out = base / mode / "preflight.json"
        write_manifest(manifest, out)
        outcome = "PASS" if not errors else "FAIL"
        print(f"SCENARIO_RESULT|scenario_id=xfstests_preflight_{mode}|outcome={outcome}|detail={out}")
        failures.extend(errors)
        summaries.append({"fixture": mode, "out": str(out), "errors": errors})
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
