#!/usr/bin/env bash
# ffs_topology_runtime_advisor_e2e.sh - advisory-only dry-run gate.
#
# Exercises the topology runtime advisor through RCH-backed dry-run commands.
# This script never mounts FUSE, runs xfstests, starts large-host workloads, or
# consumes permissioned ACK variables.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd -P)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

AGENT_NAME_FOR_TARGET="${AGENT_NAME:-SunnyHill}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/.cargo-target-frankenfs-${AGENT_NAME_FOR_TARGET}-topology-advisor-e2e}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR

RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-420}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_TOPOLOGY_RUNTIME_ADVISOR_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_TOPOLOGY_RUNTIME_ADVISOR_SKIP_SELF_CHECK:-0}"

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

assert_no_permissioned_ack() {
    local phase="$1"
    local forbidden=(
        "XFSTESTS_REAL_RUN_ACK"
        "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD"
        "FFS_SWARM_WORKLOAD_REAL_RUN_ACK"
        "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER"
        "FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK"
        "FFS_ENABLE_PERMISSIONED_CRASH_REPLAY"
        "FFS_PERMISSIONED_CRASH_REPLAY_RUNNER"
    )
    local present=()
    local name
    for name in "${forbidden[@]}"; do
        if [[ -n "${!name:-}" ]]; then
            present+=("$name")
        fi
    done
    if ((${#present[@]} > 0)); then
        e2e_log "PERMISSIONED_ACK_ENV_PRESENT|phase=${phase}|count=${#present[@]}"
        return 1
    fi
    return 0
}

copy_command_streams() {
    local raw_log="$1"
    local stdout_path="$2"
    local stderr_path="$3"

    cp "$raw_log" "$stdout_path"
    : >"$stderr_path"
}

run_rch_no_errexit() {
    local raw_log="$1"
    local status
    shift

    set +e
    e2e_rch_capture "$raw_log" "$@"
    status=$?
    set -e
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_TOPOLOGY_RUNTIME_ADVISOR_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected topology-advisor fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

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
        echo "unknown topology-advisor fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

finish_expected_failure() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "[RCH] remote worker=fixture exit=1"
        echo "Remote command finished: exit=1"
    fi
    exit 1
}

emit_validation_json() {
    cat <<'JSON'
{
  "advisory_only": true,
  "artifact_count": 3,
  "artifact_root": "artifacts/rch_e2e/fixture/topology_runtime_advisor",
  "error_class": "none",
  "issues": [],
  "manifest_path": "docs/topology-runtime-advisor-manifest.json",
  "manifest_version": 1,
  "operation_id": "fixture-topology-runtime-advisor-validation",
  "outcome": "accepted",
  "product_evidence_claim": "none",
  "release_gate_effect": "advisory_only",
  "runtime_candidate_count": 2,
  "scenario_id": "fixture_validation",
  "valid": true
}
JSON
}

emit_stale_validation_json() {
    cat <<'JSON'
{
  "advisory_only": true,
  "artifact_count": 0,
  "artifact_root": "artifacts/rch_e2e/fixture/topology_runtime_advisor",
  "error_class": "stale_manifest",
  "errors": ["manifest stale relative to reference timestamp"],
  "issues": ["manifest stale relative to reference timestamp"],
  "manifest_path": "docs/topology-runtime-advisor-manifest.json",
  "manifest_version": 1,
  "operation_id": "fixture-topology-runtime-advisor-validation",
  "outcome": "rejected",
  "product_evidence_claim": "none",
  "release_gate_effect": "advisory_only",
  "runtime_candidate_count": 2,
  "scenario_id": "fixture_stale_validation",
  "valid": false
}
JSON
}

emit_score_json() {
    cat <<'JSON'
{
  "advisory_only": true,
  "candidate_scores": [
    {
      "rejection_reason": "",
      "runtime_candidate": "asupersync-lab",
      "score": 0.91
    },
    {
      "rejection_reason": "forbidden runtime family",
      "runtime_candidate": "tokio",
      "score": 0.0
    }
  ],
  "confidence_tier": "fixture",
  "errors": [],
  "loss_risk_ledger": [
    {
      "expected_loss": 0.1,
      "risk": "advisory-only fixture"
    }
  ],
  "operation_id": "fixture-topology-runtime-advisor-score",
  "product_evidence_claim": "none",
  "recommendation": "asupersync-lab",
  "rejected_candidates": 1,
  "release_claim_state": "not_product_evidence",
  "release_gate_effect": "advisory_only",
  "scenario_id": "fixture_scoring",
  "valid": true
}
JSON
}

case "$command_text" in
    *"validate-topology-runtime-advisor"*2026-06-30T00:00:00Z*)
        emit_stale_validation_json
        finish_expected_failure
        ;;
    *"validate-topology-runtime-advisor"*)
        emit_validation_json
        finish_success
        ;;
    *"score-topology-runtime-advisor"*)
        emit_score_json
        finish_success
        ;;
    "cargo test -p ffs-harness topology_runtime_advisor -- --nocapture")
        echo "test topology_runtime_advisor::tests::fixture_contract ... ok"
        echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
        finish_success
        ;;
    "cargo check -p ffs-harness --all-targets")
        echo "topology-advisor fixture cargo check succeeded"
        finish_success
        ;;
    "cargo clippy -p ffs-harness --all-targets -- -D warnings")
        echo "topology-advisor fixture clippy succeeded"
        finish_success
        ;;
    *)
        echo "unexpected topology-advisor fixture command: $command_text" >&2
        exit 64
        ;;
esac
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
    local child_log="$E2E_LOG_DIR/topology_advisor_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_TOPOLOGY_RUNTIME_ADVISOR_SELF_CHECK=0 \
        FFS_TOPOLOGY_RUNTIME_ADVISOR_SKIP_SELF_CHECK=1 \
        FFS_TOPOLOGY_RUNTIME_ADVISOR_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_topology_runtime_advisor_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic topology runtime advisor wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-topology-advisor-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .invalid_scenario_marker_count == 0
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_permission_boundary" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_validation_dry_run" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_scoring_dry_run" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_advisory_output_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_missing_artifact_fails_closed" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_stale_manifest_fails_closed" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_invalid_jsonl_fails_closed" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_cargo_check" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "topology_advisor_cargo_clippy" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "topology_advisor_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "topology_advisor_fixture_complete_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "topology_advisor_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "topology_advisor_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "topology_advisor_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "topology_advisor_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

extract_json_report() {
    local raw_log="$1"
    local report_path="$2"
    local report_kind="$3"

    python3 - "$raw_log" "$report_path" "$report_kind" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path, report_kind = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()

def matches(obj):
    if not isinstance(obj, dict):
        return False
    if obj.get("product_evidence_claim") != "none":
        return False
    if report_kind == "validation":
        return {
            "manifest_version",
            "operation_id",
            "outcome",
            "advisory_only",
            "runtime_candidate_count",
            "artifact_count",
        }.issubset(obj)
    if report_kind == "score":
        return {
            "operation_id",
            "advisory_only",
            "release_claim_state",
            "candidate_scores",
            "loss_risk_ledger",
        }.issubset(obj)
    raise SystemExit(f"unknown report kind {report_kind}")

for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if matches(obj):
        pathlib.Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit(f"{report_kind} JSON report not found in {raw_path}")
PY
}

write_validation_artifacts() {
    python3 - "$VALIDATE_REPORT" "$VALIDATE_SUMMARY" "$VALIDATE_STRUCTURED_LOG" <<'PY'
import json
import pathlib
import sys

report_path, summary_path, structured_log_path = map(pathlib.Path, sys.argv[1:])
report = json.loads(report_path.read_text(encoding="utf-8"))
summary_lines = [
    "# Topology Runtime Advisor Report",
    "",
    f"- Operation: `{report['operation_id']}`",
    f"- Scenario: `{report['scenario_id']}`",
    f"- Valid: `{str(report['valid']).lower()}`",
    f"- Outcome: `{report['outcome']}`",
    f"- Advisory only: `{str(report['advisory_only']).lower()}`",
    f"- Product evidence claim: `{report['product_evidence_claim']}`",
    f"- Release gate effect: `{report['release_gate_effect']}`",
    f"- Artifact root: `{report['artifact_root']}`",
]
summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
events = [
    {
        "event": "topology_runtime_advisor_validation_start",
        "operation_id": report["operation_id"],
        "scenario_id": report["scenario_id"],
        "advisory_only": True,
        "manifest_path": report["manifest_path"],
        "artifact_root": report["artifact_root"],
    },
    {
        "event": "topology_runtime_advisor_validation_result",
        "operation_id": report["operation_id"],
        "scenario_id": report["scenario_id"],
        "outcome": report["outcome"],
        "advisory_only": report["advisory_only"],
        "product_evidence_claim": report["product_evidence_claim"],
        "release_gate_effect": report["release_gate_effect"],
        "error_class": report["error_class"],
        "issue_count": len(report["issues"]),
    },
]
structured_log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)
PY
}

write_score_artifacts() {
    python3 - "$SCORE_REPORT" "$SCORE_SUMMARY" "$SCORE_STRUCTURED_LOG" <<'PY'
import json
import pathlib
import sys

report_path, summary_path, structured_log_path = map(pathlib.Path, sys.argv[1:])
report = json.loads(report_path.read_text(encoding="utf-8"))
summary_lines = [
    "# Topology Runtime Advisor Score",
    "",
    f"- Operation: `{report['operation_id']}`",
    f"- Scenario: `{report['scenario_id']}`",
    f"- Valid: `{str(report['valid']).lower()}`",
    f"- Advisory only: `{str(report['advisory_only']).lower()}`",
    f"- Product evidence claim: `{report['product_evidence_claim']}`",
    f"- Release gate effect: `{report['release_gate_effect']}`",
    f"- Release claim state: `{report['release_claim_state']}`",
    f"- Recommendation: `{report.get('recommendation') or 'none'}`",
    f"- Confidence: `{report['confidence_tier']}`",
]
summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
events = []
for candidate in report["candidate_scores"]:
    events.append(
        {
            "event": "topology_runtime_advisor_score_candidate",
            "operation_id": report["operation_id"],
            "scenario_id": report["scenario_id"],
            "runtime_candidate": candidate["runtime_candidate"],
            "score": candidate["score"],
            "confidence_tier": report["confidence_tier"],
            "rejection_reason": candidate["rejection_reason"],
            "advisory_only": report["advisory_only"],
        }
    )
events.append(
    {
        "event": "topology_runtime_advisor_score_result",
        "operation_id": report["operation_id"],
        "scenario_id": report["scenario_id"],
        "runtime_candidate": report.get("recommendation"),
        "confidence_tier": report["confidence_tier"],
        "advisory_only": report["advisory_only"],
        "product_evidence_claim": report["product_evidence_claim"],
        "release_gate_effect": report["release_gate_effect"],
        "release_claim_state": report["release_claim_state"],
        "rejected_candidates": report["rejected_candidates"],
        "error_count": len(report["errors"]),
    }
)
structured_log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)
PY
}

validate_jsonl_file() {
    local path="$1"
    python3 - "$path" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        raise SystemExit(f"blank JSONL line at {line_number}")
    json.loads(line)
PY
}

write_artifact_manifest() {
    python3 - \
        "$REPO_ROOT" \
        "$ADVISOR_ARTIFACT_DIR" \
        "$ARTIFACT_MANIFEST_JSON" \
        "$VALIDATION_SUMMARY_JSON" \
        "$VALIDATION_SUMMARY_MD" \
        "$VALIDATE_REPORT" \
        "$VALIDATE_SUMMARY" \
        "$VALIDATE_STRUCTURED_LOG" \
        "$VALIDATE_RAW" \
        "$VALIDATE_STDOUT" \
        "$VALIDATE_STDERR" \
        "$SCORE_REPORT" \
        "$SCORE_SUMMARY" \
        "$SCORE_STRUCTURED_LOG" \
        "$SCORE_RAW" \
        "$SCORE_STDOUT" \
        "$SCORE_STDERR" \
        "$COMMAND_TRANSCRIPT_JSON" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_root,
    artifact_root,
    manifest_path,
    summary_json_path,
    summary_md_path,
    validate_report,
    validate_summary,
    validate_structured_log,
    validate_raw,
    validate_stdout,
    validate_stderr,
    score_report,
    score_summary,
    score_structured_log,
    score_raw,
    score_stdout,
    score_stderr,
    command_transcript_path,
) = map(pathlib.Path, sys.argv[1:])

def git(args):
    return subprocess.check_output(["git", "-C", str(repo_root), *args], text=True).strip()

dirty_paths = [
    line[3:] if len(line) > 3 else line
    for line in git(["status", "--porcelain", "--untracked-files=normal"]).splitlines()
    if line
]

def artifact(kind, path):
    data = path.read_bytes()
    return {
        "kind": kind,
        "path": str(path),
        "required": True,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

commands = [
    {
        "scenario_id": "topology_advisor_validation_dry_run",
        "command": (
            "cargo run --quiet -p ffs-harness -- validate-topology-runtime-advisor "
            "--manifest docs/topology-runtime-advisor-manifest.json "
            "--reference-timestamp 2026-05-10T00:00:00Z "
            "--format json"
        ),
        "rch_log_path": str(validate_raw),
        "stdout_path": str(validate_stdout),
        "stderr_path": str(validate_stderr),
        "status": "PASS",
    },
    {
        "scenario_id": "topology_advisor_scoring_dry_run",
        "command": (
            "cargo run --quiet -p ffs-harness -- score-topology-runtime-advisor "
            "--manifest docs/topology-runtime-advisor-manifest.json "
            "--reference-timestamp 2026-05-10T00:00:00Z "
            "--format json"
        ),
        "rch_log_path": str(score_raw),
        "stdout_path": str(score_stdout),
        "stderr_path": str(score_stderr),
        "status": "PASS",
    },
]
command_transcript_path.write_text(
    json.dumps({"commands": commands}, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

artifacts = [
    artifact("validation_report", validate_report),
    artifact("validation_summary", validate_summary),
    artifact("validation_structured_jsonl", validate_structured_log),
    artifact("validation_rch_log", validate_raw),
    artifact("validation_stdout", validate_stdout),
    artifact("validation_stderr", validate_stderr),
    artifact("score_report", score_report),
    artifact("score_summary", score_summary),
    artifact("score_structured_jsonl", score_structured_log),
    artifact("score_rch_log", score_raw),
    artifact("score_stdout", score_stdout),
    artifact("score_stderr", score_stderr),
    artifact("command_transcript", command_transcript_path),
]

manifest = {
    "schema_version": 1,
    "gate_id": "ffs_topology_runtime_advisor",
    "source_bead": "bd-rchk0.212.3",
    "real_campaign_bead": "bd-rchk0.53.8",
    "valid": True,
    "advisory_only": True,
    "product_evidence_claim": "none",
    "release_gate_effect": "advisory_only",
    "permissioned_ack_consumed": False,
    "artifact_root": str(artifact_root),
    "git": {
        "sha": git(["rev-parse", "HEAD"]),
        "clean": not dirty_paths,
        "dirty_paths": dirty_paths,
    },
    "commands": commands,
    "artifacts": artifacts,
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

summary = {
    "valid": True,
    "scenario_pass_count": 0,
    "scenario_fail_count": 0,
    "artifact_count": len(artifacts),
    "product_evidence_claim": "none",
    "release_gate_effect": "advisory_only",
    "permissioned_ack_consumed": False,
    "git_clean": not dirty_paths,
}
summary_json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
summary_md_path.write_text(
    "\n".join(
        [
            "# Topology Runtime Advisor E2E",
            "",
            "- Product evidence claim: `none`",
            "- Release gate effect: `advisory_only`",
            "- Permissioned ACK consumed: `false`",
            f"- Artifacts: `{len(artifacts)}`",
            f"- Git clean: `{str(not dirty_paths).lower()}`",
        ]
    )
    + "\n",
    encoding="utf-8",
)
PY
}

validate_artifact_manifest() {
    local path="$1"
    python3 - "$path" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if manifest["product_evidence_claim"] != "none":
    raise SystemExit("product evidence claim must remain none")
if manifest["release_gate_effect"] not in {"advisory_only", "hidden"}:
    raise SystemExit("release gate effect must remain advisory-only or hidden")
if manifest["permissioned_ack_consumed"]:
    raise SystemExit("permissioned ACK must not be consumed")
if not isinstance(manifest["git"]["clean"], bool):
    raise SystemExit("git clean flag must be boolean")
if manifest["git"]["clean"] == bool(manifest["git"]["dirty_paths"]):
    raise SystemExit("git clean flag disagrees with dirty path list")
for artifact in manifest["artifacts"]:
    artifact_path = pathlib.Path(artifact["path"])
    if not artifact_path.is_file():
        raise SystemExit(f"missing required artifact: {artifact_path}")
    if artifact_path.stat().st_size != artifact["size_bytes"]:
        raise SystemExit(f"size drift for artifact: {artifact_path}")
PY
}

assert_advisory_outputs() {
    python3 - \
        "$VALIDATE_REPORT" \
        "$VALIDATE_SUMMARY" \
        "$VALIDATE_STRUCTURED_LOG" \
        "$SCORE_REPORT" \
        "$SCORE_SUMMARY" \
        "$SCORE_STRUCTURED_LOG" \
        "$ARTIFACT_MANIFEST_JSON" \
        "$VALIDATION_SUMMARY_JSON" \
        "$VALIDATION_SUMMARY_MD" <<'PY'
import json
import pathlib
import sys

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if "accepted_large_host" in text:
        raise SystemExit(f"forbidden promotion marker in {path}")
    for token in (
        "XFSTESTS_REAL_RUN_ACK",
        "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
        "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER",
    ):
        if token in text:
            raise SystemExit(f"permissioned token leaked into {path}")

validate_report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
score_report = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
artifact_manifest = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
for report in (validate_report, score_report, artifact_manifest):
    if report["product_evidence_claim"] != "none":
        raise SystemExit(report)
    if report["release_gate_effect"] not in {"advisory_only", "hidden"}:
        raise SystemExit(report)
if not validate_report["advisory_only"]:
    raise SystemExit("validation report is not advisory-only")
if not score_report["advisory_only"]:
    raise SystemExit("score report is not advisory-only")
if score_report["release_claim_state"] != "not_product_evidence":
    raise SystemExit("score report changed release claim state")
PY
}

e2e_init "ffs_topology_runtime_advisor"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

ADVISOR_LOG_DIR="$E2E_LOG_DIR/topology_runtime_advisor"
ADVISOR_ARTIFACT_DIR="${REPO_ROOT}/artifacts/rch_e2e/$(basename "$E2E_LOG_DIR")/topology_runtime_advisor"
mkdir -p "$ADVISOR_LOG_DIR" "$ADVISOR_ARTIFACT_DIR"

VALIDATE_REPORT="$ADVISOR_ARTIFACT_DIR/report.json"
VALIDATE_SUMMARY="$ADVISOR_ARTIFACT_DIR/summary.md"
VALIDATE_STRUCTURED_LOG="$ADVISOR_ARTIFACT_DIR/structured.jsonl"
VALIDATE_RAW="$ADVISOR_LOG_DIR/validate.rch.log"
VALIDATE_STDOUT="$ADVISOR_ARTIFACT_DIR/stdout.log"
VALIDATE_STDERR="$ADVISOR_ARTIFACT_DIR/stderr.log"

SCORE_REPORT="$ADVISOR_ARTIFACT_DIR/score.json"
SCORE_SUMMARY="$ADVISOR_ARTIFACT_DIR/score.md"
SCORE_STRUCTURED_LOG="$ADVISOR_ARTIFACT_DIR/score.jsonl"
SCORE_RAW="$ADVISOR_LOG_DIR/score.rch.log"
SCORE_STDOUT="$ADVISOR_ARTIFACT_DIR/score.stdout.log"
SCORE_STDERR="$ADVISOR_ARTIFACT_DIR/score.stderr.log"

COMMAND_TRANSCRIPT_JSON="$ADVISOR_ARTIFACT_DIR/command_transcript.json"
ARTIFACT_MANIFEST_JSON="$ADVISOR_ARTIFACT_DIR/artifact_manifest.json"
VALIDATION_SUMMARY_JSON="$ADVISOR_ARTIFACT_DIR/validation_summary.json"
VALIDATION_SUMMARY_MD="$ADVISOR_ARTIFACT_DIR/validation_summary.md"
MISSING_PATH_MANIFEST="$ADVISOR_ARTIFACT_DIR/artifact_manifest_missing_path.json"
INVALID_JSONL="$ADVISOR_ARTIFACT_DIR/invalid.jsonl"
STALE_REPORT="$ADVISOR_ARTIFACT_DIR/stale_report.json"
STALE_RAW="$ADVISOR_LOG_DIR/stale.rch.log"
UNIT_LOG="$ADVISOR_LOG_DIR/unit_tests.rch.log"
CHECK_LOG="$ADVISOR_LOG_DIR/check.rch.log"
CLIPPY_LOG="$ADVISOR_LOG_DIR/clippy.rch.log"

e2e_step "Scenario 1: permissioned ACK boundary is absent"
if assert_no_permissioned_ack "start"; then
    scenario_result "topology_advisor_permission_boundary" "PASS" "no permissioned ACK env vars present"
else
    scenario_result "topology_advisor_permission_boundary" "FAIL" "permissioned ACK env vars present"
fi

e2e_step "Scenario 2: validation dry-run emits report artifacts"
if run_rch_no_errexit \
    "$VALIDATE_RAW" \
    cargo run --quiet -p ffs-harness -- validate-topology-runtime-advisor \
        --manifest docs/topology-runtime-advisor-manifest.json \
        --reference-timestamp 2026-05-10T00:00:00Z \
        --format json \
    && extract_json_report "$VALIDATE_RAW" "$VALIDATE_REPORT" "validation" \
    && write_validation_artifacts; then
    copy_command_streams "$VALIDATE_RAW" "$VALIDATE_STDOUT" "$VALIDATE_STDERR"
    scenario_result "topology_advisor_validation_dry_run" "PASS" "RCH validation report extracted"
else
    scenario_result "topology_advisor_validation_dry_run" "FAIL" "RCH validation report extraction failed; log=${VALIDATE_RAW}"
fi

e2e_step "Scenario 3: scoring dry-run emits report artifacts"
if run_rch_no_errexit \
    "$SCORE_RAW" \
    cargo run --quiet -p ffs-harness -- score-topology-runtime-advisor \
        --manifest docs/topology-runtime-advisor-manifest.json \
        --reference-timestamp 2026-05-10T00:00:00Z \
        --format json \
    && extract_json_report "$SCORE_RAW" "$SCORE_REPORT" "score" \
    && write_score_artifacts; then
    copy_command_streams "$SCORE_RAW" "$SCORE_STDOUT" "$SCORE_STDERR"
    scenario_result "topology_advisor_scoring_dry_run" "PASS" "RCH score report extracted"
else
    scenario_result "topology_advisor_scoring_dry_run" "FAIL" "RCH score report extraction failed; log=${SCORE_RAW}"
fi

e2e_step "Scenario 4: JSON, Markdown, and JSONL outputs stay advisory-only"
if [[ -f "$VALIDATE_REPORT" && -f "$VALIDATE_SUMMARY" && -f "$VALIDATE_STRUCTURED_LOG" \
    && -f "$SCORE_REPORT" && -f "$SCORE_SUMMARY" && -f "$SCORE_STRUCTURED_LOG" ]] \
    && validate_jsonl_file "$VALIDATE_STRUCTURED_LOG" \
    && validate_jsonl_file "$SCORE_STRUCTURED_LOG" \
    && write_artifact_manifest \
    && validate_artifact_manifest "$ARTIFACT_MANIFEST_JSON" \
    && assert_advisory_outputs; then
    scenario_result "topology_advisor_advisory_output_contract" "PASS" "advisory-only report, summary, log, and manifest verified"
else
    scenario_result "topology_advisor_advisory_output_contract" "FAIL" "advisory-only artifact validation failed"
fi

e2e_step "Scenario 5: missing artifact paths fail closed"
if python3 - "$ARTIFACT_MANIFEST_JSON" "$MISSING_PATH_MANIFEST" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest["artifacts"][0]["path"] = str(pathlib.Path(sys.argv[2]).with_suffix(".missing"))
pathlib.Path(sys.argv[2]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
then
    set +e
    validate_artifact_manifest "$MISSING_PATH_MANIFEST"
    missing_status=$?
    set -e
    if [[ $missing_status -ne 0 ]]; then
        scenario_result "topology_advisor_missing_artifact_fails_closed" "PASS" "missing artifact was rejected"
    else
        scenario_result "topology_advisor_missing_artifact_fails_closed" "FAIL" "missing artifact was accepted"
    fi
else
    scenario_result "topology_advisor_missing_artifact_fails_closed" "FAIL" "could not write negative manifest"
fi

e2e_step "Scenario 6: stale sample manifest fails closed"
set +e
e2e_rch_capture "$STALE_RAW" cargo run --quiet -p ffs-harness -- validate-topology-runtime-advisor \
    --manifest docs/topology-runtime-advisor-manifest.json \
    --reference-timestamp 2026-06-30T00:00:00Z \
    --format json
stale_status=$?
set -e
extract_json_report "$STALE_RAW" "$STALE_REPORT" "validation" || true
if [[ $stale_status -ne 0 ]] \
    && [[ -f "$STALE_REPORT" ]] \
    && ! grep -Fq "[RCH] local" "$STALE_RAW" \
    && jq -e '.valid == false and ((.errors | join(" ")) | test("stale|expired"))' "$STALE_REPORT" >/dev/null; then
    scenario_result "topology_advisor_stale_manifest_fails_closed" "PASS" "stale manifest rejected"
else
    scenario_result "topology_advisor_stale_manifest_fails_closed" "FAIL" "stale manifest was not rejected"
fi

e2e_step "Scenario 7: invalid structured JSONL fails closed"
printf '{"event":"valid"}\nnot-json\n' >"$INVALID_JSONL"
set +e
validate_jsonl_file "$INVALID_JSONL"
jsonl_status=$?
set -e
if [[ $jsonl_status -ne 0 ]]; then
    scenario_result "topology_advisor_invalid_jsonl_fails_closed" "PASS" "invalid JSONL rejected"
else
    scenario_result "topology_advisor_invalid_jsonl_fails_closed" "FAIL" "invalid JSONL accepted"
fi

e2e_step "Scenario 8: focused Rust unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness topology_runtime_advisor -- --nocapture; then
    scenario_result "topology_advisor_unit_tests" "PASS" "focused unit tests passed"
else
    scenario_result "topology_advisor_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_step "Scenario 9: focused harness cargo check passes"
if e2e_rch_capture "$CHECK_LOG" cargo check -p ffs-harness --all-targets; then
    scenario_result "topology_advisor_cargo_check" "PASS" "harness cargo check passed"
else
    scenario_result "topology_advisor_cargo_check" "FAIL" "harness cargo check failed"
fi

e2e_step "Scenario 10: focused harness clippy passes"
if e2e_rch_capture "$CLIPPY_LOG" cargo clippy -p ffs-harness --all-targets -- -D warnings; then
    scenario_result "topology_advisor_cargo_clippy" "PASS" "harness clippy passed"
else
    scenario_result "topology_advisor_cargo_clippy" "FAIL" "harness clippy failed"
fi

if ((FAIL_COUNT == 0)); then
    python3 - "$VALIDATION_SUMMARY_JSON" "$PASS_COUNT" "$TOTAL" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
pass_count = int(sys.argv[2])
total = int(sys.argv[3])
summary = json.loads(path.read_text(encoding="utf-8"))
summary["scenario_pass_count"] = pass_count
summary["scenario_fail_count"] = total - pass_count
path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    e2e_pass
else
    e2e_fail "topology runtime advisor scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
