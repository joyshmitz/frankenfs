#!/usr/bin/env bash
# ffs_adaptive_runtime_runner_e2e.sh - dry-run gate for bd-jv6pj.5.
#
# Exercises the adaptive runtime runner without mounting or generating load.
# Permissioned-real checks are refusal-only unless the exact ACK and
# artifact-scoped TEST_DIR/SCRATCH_MNT paths are supplied.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_adaptive_runtime_runner}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"

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
    local output_path="$1"
    shift
    local status rch_log_path
    rch_log_path="${output_path}.rch.log"
    if RCH_VISIBILITY=none RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-error}" timeout "${RCH_COMMAND_TIMEOUT_SECS}s" \
        "${RCH_BIN:-rch}" exec -- env FFS_REMOTE_RUNNER_ROOT="$RUNNER_ROOT" bash -lc '
            set -euo pipefail
            mkdir -p "$FFS_REMOTE_RUNNER_ROOT"
            remote_output="$FFS_REMOTE_RUNNER_ROOT/rch-command-output.$$.log"
            set +e
            "$@" >"$remote_output" 2>&1
            status=$?
            set -e
            printf "%s\n" "__FFS_REMOTE_OUTPUT_BEGIN__"
            cat "$remote_output"
            printf "%s\n" "__FFS_REMOTE_OUTPUT_END__"
            printf "%s\n" "__FFS_REMOTE_TREE_BEGIN__"
            tar -C "$FFS_REMOTE_RUNNER_ROOT" -cf - . | base64 -w 0
            printf "\n%s\n" "__FFS_REMOTE_TREE_END__"
            exit "$status"
        ' _ "$@" >"$rch_log_path" 2>&1; then
        status=0
    else
        status=$?
    fi
    if ! awk '
        $0 == "__FFS_REMOTE_OUTPUT_BEGIN__" { capture = 1; next }
        $0 == "__FFS_REMOTE_OUTPUT_END__" { found = 1; capture = 0; next }
        capture { print }
        END { exit found ? 0 : 1 }
    ' "$rch_log_path" >"$output_path"; then
        cp "$rch_log_path" "$output_path"
    fi
    awk '
        $0 == "__FFS_REMOTE_TREE_BEGIN__" { capture = 1; next }
        $0 == "__FFS_REMOTE_TREE_END__" { found = 1; capture = 0; next }
        capture { print }
        END { exit found ? 0 : 1 }
    ' "$rch_log_path" | base64 --decode | tar -C "$RUNNER_ROOT" -xf - || true
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$rch_log_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=${output_path}"
        return 0
    fi
    return "$status"
}

e2e_init "ffs_adaptive_runtime_runner"

GIT_SHA="$(git rev-parse --short HEAD)"
RUNNER_ROOT="$E2E_LOG_DIR/adaptive-runtime-runner"
DRY_RUN_ROOT="$RUNNER_ROOT/dry-run"
PERMISSIONED_ROOT="$RUNNER_ROOT/permissioned-real"
UNSAFE_ROOT="$RUNNER_ROOT/unsafe-path"
DRY_RUN_REPORT="$DRY_RUN_ROOT/report.json"
DRY_RUN_SUMMARY="$DRY_RUN_ROOT/report.md"
DRY_RUN_RAW="$DRY_RUN_ROOT/cmd.raw"
PERMISSIONED_REPORT="$PERMISSIONED_ROOT/report.json"
PERMISSIONED_SUMMARY="$PERMISSIONED_ROOT/report.md"
PERMISSIONED_RAW="$PERMISSIONED_ROOT/cmd.raw"
UNSAFE_REPORT="$UNSAFE_ROOT/report.json"
UNSAFE_SUMMARY="$UNSAFE_ROOT/report.md"
UNSAFE_RAW="$UNSAFE_ROOT/cmd.raw"
UNIT_LOG="$RUNNER_ROOT/unit_tests.log"

mkdir -p "$DRY_RUN_ROOT" "$PERMISSIONED_ROOT" "$UNSAFE_ROOT"

e2e_step "Scenario 1: adaptive runtime runner CLI is wired"
if grep -q "adaptive-runtime-runner" crates/ffs-harness/src/main.rs \
    && grep -q "AdaptiveRuntimeRunnerReport" crates/ffs-harness/src/adaptive_runtime_manifest.rs; then
    scenario_result "adaptive_runtime_runner_cli_wired" "PASS" "runner command and report schema exported"
else
    scenario_result "adaptive_runtime_runner_cli_wired" "FAIL" "missing runner command or schema"
fi

e2e_step "Scenario 2: default dry-run emits report, manifest, logs, cleanup, and host facts"
if run_rch_capture "$DRY_RUN_RAW" cargo run --quiet -p ffs-harness -- adaptive-runtime-runner \
    --artifact-root "$DRY_RUN_ROOT" \
    --out "$DRY_RUN_REPORT" \
    --summary-out "$DRY_RUN_SUMMARY" \
    --generated-at "2026-05-07T00:00:00Z" \
    --git-sha "$GIT_SHA"; then
    scenario_result "adaptive_runtime_runner_dry_run_writes_artifacts" "PASS" "dry-run artifacts emitted"
else
    cat "$DRY_RUN_RAW"
    scenario_result "adaptive_runtime_runner_dry_run_writes_artifacts" "FAIL" "dry-run command failed"
fi

e2e_step "Scenario 3: dry-run artifact contract is downgrade-only"
if python3 - "$DRY_RUN_REPORT" "$DRY_RUN_SUMMARY" "$DRY_RUN_ROOT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
root = pathlib.Path(sys.argv[3])

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["mode"] != "dry_run":
    raise SystemExit(report["mode"])
if report["classification"] not in {"small_host_smoke", "capability_downgraded_smoke"}:
    raise SystemExit(report["classification"])
if report["classification"] == "accepted_large_host":
    raise SystemExit("dry-run must not upgrade release evidence")
if report["execution"]["permissioned_real_allowed"]:
    raise SystemExit("dry-run unexpectedly allowed permissioned real")
for key in [
    "raw_stdout_path",
    "raw_stderr_path",
    "structured_log_path",
    "runner_manifest_path",
    "cleanup_report_path",
    "host_facts_path",
]:
    path = pathlib.Path(report["path_plan"][key])
    if not path.exists():
        raise SystemExit(f"missing {key}: {path}")
    if not path.is_relative_to(root):
        raise SystemExit(f"{key} escaped artifact root: {path}")
structured = pathlib.Path(report["path_plan"]["structured_log_path"]).read_text(encoding="utf-8")
if "adaptive_runtime_runner_result" not in structured:
    raise SystemExit("structured result event missing")
cleanup = json.loads(pathlib.Path(report["path_plan"]["cleanup_report_path"]).read_text(encoding="utf-8"))
if cleanup["mutating_workload_started"]:
    raise SystemExit("dry-run cleanup claims mutation")
host = json.loads(pathlib.Path(report["path_plan"]["host_facts_path"]).read_text(encoding="utf-8"))
for field in ["cpu_count", "ram_bytes", "numa_nodes", "kernel", "fuse_capability_summary"]:
    if field not in host:
        raise SystemExit(f"missing host field {field}")
if "Permissioned real allowed: `false`" not in summary:
    raise SystemExit("summary missing downgrade marker")
PY
then
    scenario_result "adaptive_runtime_runner_dry_run_contract" "PASS" "dry-run contract verified"
else
    scenario_result "adaptive_runtime_runner_dry_run_contract" "FAIL" "dry-run artifact contract failed"
fi

e2e_step "Scenario 4: permissioned-real mode refuses missing ACK"
set +e
run_rch_capture "$PERMISSIONED_RAW" cargo run --quiet -p ffs-harness -- adaptive-runtime-runner \
    --mode permissioned-real \
    --artifact-root "$PERMISSIONED_ROOT" \
    --out "$PERMISSIONED_REPORT" \
    --summary-out "$PERMISSIONED_SUMMARY" \
    --test-dir "$PERMISSIONED_ROOT/test-dir" \
    --scratch-mnt "$PERMISSIONED_ROOT/scratch-mnt"
missing_ack_status=$?
set -e

if [[ $missing_ack_status -ne 0 ]] \
    && python3 - "$PERMISSIONED_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["valid"]:
    raise SystemExit("missing ACK report is valid")
if report["execution"]["permissioned_real_allowed"]:
    raise SystemExit("missing ACK allowed permissioned real")
if not any("FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK is required" in reason for reason in report["refusal_reasons"]):
    raise SystemExit(report["refusal_reasons"])
PY
then
    scenario_result "adaptive_runtime_runner_refuses_missing_ack" "PASS" "missing ACK refused before side effects"
else
    cat "$PERMISSIONED_RAW"
    scenario_result "adaptive_runtime_runner_refuses_missing_ack" "FAIL" "missing ACK was not refused"
fi

e2e_step "Scenario 5: permissioned-real mode refuses unsafe paths even with ACK"
set +e
FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK="adaptive-runtime-may-mount-and-generate-load" \
    run_rch_capture "$UNSAFE_RAW" cargo run --quiet -p ffs-harness -- adaptive-runtime-runner \
    --mode permissioned-real \
    --artifact-root "$UNSAFE_ROOT" \
    --out "$UNSAFE_REPORT" \
    --summary-out "$UNSAFE_SUMMARY" \
    --test-dir "/" \
    --scratch-mnt "$UNSAFE_ROOT/scratch-mnt"
unsafe_status=$?
set -e

if [[ $unsafe_status -ne 0 ]] \
    && python3 - "$UNSAFE_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["valid"]:
    raise SystemExit("unsafe path report is valid")
if report["execution"]["permissioned_real_allowed"]:
    raise SystemExit("unsafe path allowed permissioned real")
if not any("test_dir must live under artifact_root" in reason for reason in report["refusal_reasons"]):
    raise SystemExit(report["refusal_reasons"])
PY
then
    scenario_result "adaptive_runtime_runner_refuses_unsafe_paths" "PASS" "unsafe TEST_DIR refused"
else
    cat "$UNSAFE_RAW"
    scenario_result "adaptive_runtime_runner_refuses_unsafe_paths" "FAIL" "unsafe path was not refused"
fi

e2e_step "Scenario 6: focused Rust tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness adaptive_runtime_runner -- --nocapture; then
    scenario_result "adaptive_runtime_runner_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "adaptive_runtime_runner_unit_tests" "FAIL" "focused unit tests failed"
fi

if ((FAIL_COUNT == 0)); then
    e2e_pass
else
    e2e_fail "adaptive runtime runner scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
