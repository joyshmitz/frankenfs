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
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_FAILURE_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_FAILURE_ARTIFACT_RETRIEVAL_GRACE_SECS:-30}"
RCH_CAPTURE_VISIBILITY="${FFS_ADAPTIVE_RUNTIME_RUNNER_RCH_VISIBILITY:-summary}"
SELF_CHECK="${FFS_ADAPTIVE_RUNTIME_RUNNER_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_ADAPTIVE_RUNTIME_RUNNER_SKIP_SELF_CHECK:-0}"

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
    local status=0
    local rch_log_path
    local pid
    local deadline
    local retrieval_deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0
    rch_log_path="${output_path}.rch.log"

    case $- in
        *e*) had_errexit=1 ;;
    esac

    mkdir -p "$(dirname "$output_path")"
    : >"$rch_log_path"
    set +e
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$rch_log_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$rch_log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            if [[ "$remote_exit" == "0" ]]; then
                retrieval_deadline=$((SECONDS + RCH_ARTIFACT_RETRIEVAL_GRACE_SECS))
            else
                retrieval_deadline=$((SECONDS + RCH_FAILURE_ARTIFACT_RETRIEVAL_GRACE_SECS))
            fi
            while kill -0 "$pid" >/dev/null 2>&1 && ((SECONDS < retrieval_deadline)); do
                if grep -Fq "Artifacts retrieved:" "$rch_log_path"; then
                    break
                fi
                sleep 1
            done
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    cp "$rch_log_path" "$output_path"
    if grep -Fq "[RCH] local" "$rch_log_path" || grep -Fq "exec called with non-compilation command" "$rch_log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if ! grep -Fq "Remote command finished: exit=${status}" "$rch_log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|status=${status}"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi

    return "$status"
}

extract_adaptive_runner_report() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if (
        isinstance(obj, dict)
        and "execution" in obj
        and "path_plan" in obj
        and "host_facts" in obj
        and "artifact_paths" in obj
        and "capability_downgrade_reasons" in obj
    ):
        pathlib.Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("adaptive runtime runner JSON report not found")
PY
}

extract_adaptive_runner_summary() {
    local raw_path="$1"
    local summary_path="$2"

    python3 - "$raw_path" "$summary_path" <<'PY'
import pathlib
import re
import sys

raw_path, summary_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Adaptive Runtime Runner")
if start < 0:
    raise SystemExit("adaptive runtime runner Markdown summary not found")
end = len(text)
for marker in ("\nadaptive runtime runner report written:",):
    found = text.find(marker, start)
    if found >= 0:
        end = min(end, found)
match = re.search(r"\n\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*\brch::", text[start:])
if match:
    end = min(end, start + match.start())
pathlib.Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(summary_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_ADAPTIVE_RUNTIME_RUNNER_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected adaptive runtime fixture rch invocation: $*" >&2
    exit 64
fi
shift 2

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown adaptive runtime fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

artifact_root=""
mode="dry_run"
test_dir=""
command_kind="run"
if [[ "${1:-}" == "cargo" && "${2:-}" == "test" ]]; then
    command_kind="test"
fi

while (($#)); do
    case "$1" in
        --artifact-root)
            artifact_root="${2:-}"
            shift 2
            ;;
        --mode)
            mode="${2:-}"
            shift 2
            ;;
        --test-dir)
            test_dir="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ "$command_kind" == "test" ]]; then
    echo "test adaptive_runtime_runner::fixture_dry_run_report ... ok"
    echo "test adaptive_runtime_runner::fixture_refusal_paths ... ok"
    echo "test result: ok. 2 passed; 0 failed; 0 ignored"
    [[ "$fixture_case" == "complete" ]] && echo "Remote command finished: exit=0"
    exit 0
fi

if [[ -z "$artifact_root" ]]; then
    artifact_root="/data/tmp/adaptive-runtime-runner-fixture"
fi

if [[ "$mode" == "permissioned-real" && "$test_dir" == "/" ]]; then
    cat <<JSON
{
  "valid": false,
  "mode": "permissioned_real",
  "classification": "refused",
  "execution": {
    "permissioned_real_allowed": false
  },
  "path_plan": {
    "raw_stdout_path": "${artifact_root}/raw.stdout",
    "raw_stderr_path": "${artifact_root}/raw.stderr",
    "structured_log_path": "${artifact_root}/structured.log",
    "runner_manifest_path": "${artifact_root}/runner-manifest.json",
    "cleanup_report_path": "${artifact_root}/cleanup.json",
    "host_facts_path": "${artifact_root}/host-facts.json"
  },
  "host_facts": {
    "cpu_count": 4,
    "ram_bytes": 8589934592,
    "numa_nodes": 1,
    "kernel": "fixture",
    "fuse_capability_summary": "fixture"
  },
  "artifact_paths": {},
  "capability_downgrade_reasons": ["fixture unsafe path refusal"],
  "cleanup_status": "no_mutating_workload_started",
  "refusal_reasons": ["test_dir must live under artifact_root"]
}
JSON
    echo "# Adaptive Runtime Runner"
    echo
    echo "Permissioned real allowed: \`false\`"
    echo "adaptive runtime runner report written:"
    [[ "$fixture_case" == "complete" ]] && echo "Remote command finished: exit=2"
    exit 2
fi

if [[ "$mode" == "permissioned-real" ]]; then
    cat <<JSON
{
  "valid": false,
  "mode": "permissioned_real",
  "classification": "refused",
  "execution": {
    "permissioned_real_allowed": false
  },
  "path_plan": {
    "raw_stdout_path": "${artifact_root}/raw.stdout",
    "raw_stderr_path": "${artifact_root}/raw.stderr",
    "structured_log_path": "${artifact_root}/structured.log",
    "runner_manifest_path": "${artifact_root}/runner-manifest.json",
    "cleanup_report_path": "${artifact_root}/cleanup.json",
    "host_facts_path": "${artifact_root}/host-facts.json"
  },
  "host_facts": {
    "cpu_count": 4,
    "ram_bytes": 8589934592,
    "numa_nodes": 1,
    "kernel": "fixture",
    "fuse_capability_summary": "fixture"
  },
  "artifact_paths": {},
  "capability_downgrade_reasons": ["fixture missing ACK refusal"],
  "cleanup_status": "no_mutating_workload_started",
  "refusal_reasons": ["FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK is required for permissioned real runs"]
}
JSON
    echo "# Adaptive Runtime Runner"
    echo
    echo "Permissioned real allowed: \`false\`"
    echo "adaptive runtime runner report written:"
    [[ "$fixture_case" == "complete" ]] && echo "Remote command finished: exit=2"
    exit 2
fi

cat <<JSON
{
  "valid": true,
  "mode": "dry_run",
  "classification": "capability_downgraded_smoke",
  "execution": {
    "permissioned_real_allowed": false
  },
  "path_plan": {
    "raw_stdout_path": "${artifact_root}/raw.stdout",
    "raw_stderr_path": "${artifact_root}/raw.stderr",
    "structured_log_path": "${artifact_root}/structured.log",
    "runner_manifest_path": "${artifact_root}/runner-manifest.json",
    "cleanup_report_path": "${artifact_root}/cleanup.json",
    "host_facts_path": "${artifact_root}/host-facts.json"
  },
  "host_facts": {
    "cpu_count": 4,
    "ram_bytes": 8589934592,
    "numa_nodes": 1,
    "kernel": "fixture",
    "fuse_capability_summary": "fixture"
  },
  "artifact_paths": {
    "report": "${artifact_root}/report.json",
    "summary": "${artifact_root}/report.md"
  },
  "capability_downgrade_reasons": ["fixture dry run"],
  "cleanup_status": "no_mutating_workload_started",
  "refusal_reasons": []
}
JSON
echo "# Adaptive Runtime Runner"
echo
echo "Permissioned real allowed: \`false\`"
echo "adaptive runtime runner report written:"
[[ "$fixture_case" == "complete" ]] && echo "Remote command finished: exit=0"
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/adaptive_runtime_runner_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_ADAPTIVE_RUNTIME_RUNNER_SELF_CHECK=0 \
        FFS_ADAPTIVE_RUNTIME_RUNNER_SKIP_SELF_CHECK=1 \
        FFS_ADAPTIVE_RUNTIME_RUNNER_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        RCH_FAILURE_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_adaptive_runtime_runner_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic adaptive runtime runner wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-adaptive-runtime-runner-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_runner_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_runner_dry_run_writes_artifacts" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_runner_dry_run_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_runner_refuses_missing_ack" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_runner_refuses_unsafe_paths" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adaptive_runtime_runner_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "adaptive_runtime_runner_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "adaptive_runtime_runner_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "adaptive_runtime_runner_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "adaptive_runtime_runner_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "adaptive_runtime_runner_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "adaptive_runtime_runner_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_adaptive_runtime_runner"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

GIT_SHA="$(git rev-parse --short HEAD)"
RUNNER_LOG_ROOT="$E2E_LOG_DIR/adaptive-runtime-runner"
RUNNER_ROOT="${REPO_ROOT}/artifacts/rch_e2e/$(basename "$E2E_LOG_DIR")/adaptive-runtime-runner"
DRY_RUN_ROOT="$RUNNER_ROOT/dry-run"
PERMISSIONED_ROOT="$RUNNER_ROOT/permissioned-real"
UNSAFE_ROOT="$RUNNER_ROOT/unsafe-path"
DRY_RUN_REPORT="$DRY_RUN_ROOT/report.json"
DRY_RUN_SUMMARY="$DRY_RUN_ROOT/report.md"
DRY_RUN_RAW="$RUNNER_LOG_ROOT/dry-run/cmd.raw"
PERMISSIONED_REPORT="$PERMISSIONED_ROOT/report.json"
PERMISSIONED_SUMMARY="$PERMISSIONED_ROOT/report.md"
PERMISSIONED_RAW="$RUNNER_LOG_ROOT/permissioned-real/cmd.raw"
UNSAFE_REPORT="$UNSAFE_ROOT/report.json"
UNSAFE_SUMMARY="$UNSAFE_ROOT/report.md"
UNSAFE_RAW="$RUNNER_LOG_ROOT/unsafe-path/cmd.raw"
UNIT_LOG="$RUNNER_LOG_ROOT/unit_tests.log"

mkdir -p "$DRY_RUN_ROOT" "$PERMISSIONED_ROOT" "$UNSAFE_ROOT" \
    "$RUNNER_LOG_ROOT/dry-run" "$RUNNER_LOG_ROOT/permissioned-real" "$RUNNER_LOG_ROOT/unsafe-path"

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
    --out /dev/stdout \
    --summary-out /dev/stdout \
    --generated-at "2026-05-07T00:00:00Z" \
    --git-sha "$GIT_SHA" \
    && extract_adaptive_runner_report "$DRY_RUN_RAW" "$DRY_RUN_REPORT" \
    && extract_adaptive_runner_summary "$DRY_RUN_RAW" "$DRY_RUN_SUMMARY"; then
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
    if not path.is_relative_to(root):
        raise SystemExit(f"{key} escaped artifact root: {path}")
for field in ["cpu_count", "ram_bytes", "numa_nodes", "kernel", "fuse_capability_summary"]:
    if field not in report["host_facts"]:
        raise SystemExit(f"missing host field {field}")
if report["cleanup_status"] == "mutating_workload_started":
    raise SystemExit("dry-run cleanup claims mutation")
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
    --out /dev/stdout \
    --summary-out /dev/stdout \
    --test-dir "$PERMISSIONED_ROOT/test-dir" \
    --scratch-mnt "$PERMISSIONED_ROOT/scratch-mnt"
missing_ack_status=$?
set -e
extract_adaptive_runner_report "$PERMISSIONED_RAW" "$PERMISSIONED_REPORT" || true
extract_adaptive_runner_summary "$PERMISSIONED_RAW" "$PERMISSIONED_SUMMARY" || true

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
    --out /dev/stdout \
    --summary-out /dev/stdout \
    --test-dir "/" \
    --scratch-mnt "$UNSAFE_ROOT/scratch-mnt"
unsafe_status=$?
set -e
extract_adaptive_runner_report "$UNSAFE_RAW" "$UNSAFE_REPORT" || true
extract_adaptive_runner_summary "$UNSAFE_RAW" "$UNSAFE_SUMMARY" || true

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
