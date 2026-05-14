#!/usr/bin/env bash
# ffs_rch_proof_ledger_e2e.sh - fixture-only proof ledger gate for RCH transcripts.
#
# This suite is intentionally no-worker and no-cargo: it validates the
# operator artifact contract using synthetic RCH transcripts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

e2e_init "ffs_rch_proof_ledger"
e2e_print_env

TRANSCRIPT_DIR="$E2E_LOG_DIR/transcripts"
REPORT_DIR="$E2E_LOG_DIR/proof_ledgers"
mkdir -p "$TRANSCRIPT_DIR" "$REPORT_DIR"

SUCCESS_TRANSCRIPT="$TRANSCRIPT_DIR/remote_success.log"
WARNING_TRANSCRIPT="$TRANSCRIPT_DIR/artifact_warning.log"
FALLBACK_TRANSCRIPT="$TRANSCRIPT_DIR/local_fallback.log"
REPORT_BUNDLE="$REPORT_DIR/rch_proof_ledger_reports.json"
SUMMARY_MD="$REPORT_DIR/rch_proof_ledger_summary.md"

cat >"$SUCCESS_TRANSCRIPT" <<'LOG'
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Executing command remotely: cargo test -p ffs-harness rch_proof_ledger -- --nocapture
Remote command finished: exit=0 in 30485ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 1307 files, 44.0M
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
Custom CARGO_TARGET_DIR artifacts retrieved: 824 files, 26.0M
[RCH] remote vmi1227854 (142.8s)
LOG

cat >"$WARNING_TRANSCRIPT" <<'LOG'
Selected worker: vmi1227854 at ubuntu@203.0.113.10
Executing command remotely: cargo check -p ffs-harness --all-targets
Remote command finished: exit=0 in 1200ms
Retrieving artifacts from /data/projects/frankenfs on vmi1227854
Artifacts retrieved: 4 files, 16K
Retrieving artifacts from /data/projects/frankenfs/.rch-target on vmi1227854
Artifact retrieval failed: rsync target verification warning
[RCH] remote vmi1227854 (1.2s)
LOG

cat >"$FALLBACK_TRANSCRIPT" <<'LOG'
Remote execution failed before worker proof was captured.
[RCH] local (remote execution failed)
LOG

write_fixture_reports() {
    python3 - "$TRANSCRIPT_DIR" "$REPORT_DIR" "$REPORT_BUNDLE" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import re
import sys

transcript_dir = pathlib.Path(sys.argv[1])
report_dir = pathlib.Path(sys.argv[2])
bundle_path = pathlib.Path(sys.argv[3])
summary_path = pathlib.Path(sys.argv[4])

config = {
    "command": ["cargo", "test", "-p", "ffs-harness", "rch_proof_ledger"],
    "cwd": "/data/projects/frankenfs",
    "env_allowlist": ["CARGO_TARGET_DIR"],
}

def push_unique(values, value):
    if value not in values:
        values.append(value)

def duration_ms(raw):
    raw = raw.strip()
    if raw.endswith("ms"):
        return int(raw[:-2])
    if raw.endswith("s"):
        seconds = raw[:-1]
        if "." in seconds:
            whole, fractional = seconds.split(".", 1)
        else:
            whole, fractional = seconds, ""
        fractional = (fractional + "000")[:3]
        return int(whole) * 1000 + int(fractional)
    raise ValueError(f"unknown duration: {raw}")

def artifact_warning(status):
    return status in {"warning", "stalled", "failed"}

def render_markdown(report):
    warnings = ", ".join(report["warnings"]) if report["warnings"] else "none"
    return f"""# RCH Proof Ledger

- Verdict: `{report["proof_verdict"]}`
- Worker: `{report["worker_id"] or "unknown"}`
- Remote exit code: `{report["remote_exit_code"] if report["remote_exit_code"] is not None else "unknown"}`
- Source artifact retrieval: `{report["artifact_retrieval_status"]["source"]}`
- Target artifact retrieval: `{report["artifact_retrieval_status"]["target"]}`
- Warnings: `{warnings}`

## Operator Decision

{operator_decision(report)}
"""

def operator_decision(report):
    verdict = report["proof_verdict"]
    if verdict == "remote_success":
        return "Worker-side exit=0 is sufficient validation proof when the command and worker match the claimed gate."
    if verdict == "remote_success_artifact_warning":
        return "Worker-side exit=0 is usable proof only with a degraded-proof note naming the artifact retrieval or rsync warning."
    if verdict == "invalid_local_fallback":
        return "Local fallback is not remote validation proof. Rerun on RCH or report the remote-execution blocker."
    return "Remote worker evidence is incomplete or failed; do not claim validation."

def parse_report(case_id, path):
    text = path.read_text(encoding="utf-8")
    worker_id = None
    remote_exit_code = None
    remote_duration_ms = None
    fallback_reason = None
    source_status = "not_attempted"
    target_status = "not_attempted"
    warnings = []

    for line in text.splitlines():
        if worker_id is None:
            selected = re.search(r"Selected worker: ([^ ]+)", line)
            summary = re.search(r"^\[RCH\] remote ([^ ]+)", line)
            if selected:
                worker_id = selected.group(1)
            elif summary:
                worker_id = summary.group(1)
        finished = re.search(r"Remote command finished: exit=([0-9]+) in ([0-9.]+m?s)", line)
        if finished:
            remote_exit_code = int(finished.group(1))
            remote_duration_ms = duration_ms(finished.group(2))
        elif line.startswith("[RCH] remote ") and " failed (exit " in line:
            remote_exit_code = int(line.rsplit(" failed (exit ", 1)[1].rstrip(")"))
        elif line.startswith("[RCH] remote ") and remote_exit_code is None:
            remote_exit_code = 0

        if line.startswith("[RCH] local (") and line.endswith(")"):
            fallback_reason = line[len("[RCH] local ("):-1]
            push_unique(warnings, "local_fallback_detected")

        lower = line.lower()
        if "retrieving artifacts from " in lower:
            if ".rch-target" in lower or "cargo_target_dir" in lower or "target artifact" in lower:
                target_status = "started"
            else:
                source_status = "started"
        if "custom cargo_target_dir artifacts retrieved" in lower:
            target_status = "retrieved"
        elif "artifacts retrieved:" in lower and source_status == "started":
            source_status = "retrieved"
        if "artifact retrieval failed" in lower or "failed to retrieve artifacts" in lower:
            if target_status == "started" or ".rch-target" in lower:
                target_status = "warning"
            else:
                source_status = "warning"
            push_unique(warnings, "artifact_retrieval_warning")
        if "rsync" in lower and ("warning" in lower or "failed" in lower or "mismatch" in lower):
            push_unique(warnings, "rsync_verification_warning")

    if remote_exit_code == 0 and target_status == "started":
        target_status = "stalled"
        push_unique(warnings, "target_artifact_retrieval_stalled")
    if remote_exit_code == 0 and source_status == "started":
        source_status = "stalled"
        push_unique(warnings, "source_artifact_retrieval_stalled")
    if remote_exit_code not in (None, 0):
        push_unique(warnings, "remote_command_failed")
    if worker_id is None:
        push_unique(warnings, "worker_id_missing")

    fallback_detected = fallback_reason is not None
    status = {"source": source_status, "target": target_status}
    if fallback_detected:
        verdict = "invalid_local_fallback"
    elif remote_exit_code == 0 and (
        artifact_warning(source_status)
        or artifact_warning(target_status)
        or "rsync_verification_warning" in warnings
        or "artifact_retrieval_warning" in warnings
    ):
        verdict = "remote_success_artifact_warning"
    elif remote_exit_code == 0:
        verdict = "remote_success"
    elif remote_exit_code is None:
        verdict = "missing_remote_evidence"
    else:
        verdict = "remote_failure"

    report = {
        "schema_version": 1,
        "case_id": case_id,
        "command": config["command"],
        "cwd": config["cwd"],
        "env_allowlist": config["env_allowlist"],
        "worker_id": worker_id,
        "remote_exit_code": remote_exit_code,
        "remote_duration_ms": remote_duration_ms,
        "fallback_detected": fallback_detected,
        "local_fallback_reason": fallback_reason,
        "artifact_retrieval_status": status,
        "warnings": warnings,
        "proof_verdict": verdict,
        "transcript_path": str(path),
    }
    return report

reports = [
    parse_report("remote_success", transcript_dir / "remote_success.log"),
    parse_report("artifact_warning", transcript_dir / "artifact_warning.log"),
    parse_report("local_fallback", transcript_dir / "local_fallback.log"),
]

for report in reports:
    (report_dir / f"{report['case_id']}.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    (report_dir / f"{report['case_id']}.md").write_text(
        render_markdown(report),
        encoding="utf-8",
    )

bundle_path.write_text(json.dumps({"schema_version": 1, "reports": reports}, indent=2) + "\n", encoding="utf-8")
summary_lines = [
    "# RCH Proof Ledger Fixture Summary",
    "",
    "| Case | Verdict | Source artifacts | Target artifacts | Warnings |",
    "|---|---|---|---|---|",
]
for report in reports:
    summary_lines.append(
        f"| `{report['case_id']}` | `{report['proof_verdict']}` | "
        f"`{report['artifact_retrieval_status']['source']}` | "
        f"`{report['artifact_retrieval_status']['target']}` | "
        f"`{', '.join(report['warnings']) if report['warnings'] else 'none'}` |"
    )
summary_lines.extend([
    "",
    "Remote worker exit=0 is proof only when fallback is false and the transcript names the worker and command.",
    "Artifact retrieval or rsync warnings require a degraded-proof note.",
    "Local fallback invalidates remote-only validation proof.",
])
summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
PY
}

e2e_step "Scenario 1: rch proof ledger CLI, renderer, and docs are wired"
if grep -q "rch-proof-ledger" crates/ffs-harness/src/main.rs \
    && grep -q "render_rch_proof_ledger_markdown" crates/ffs-harness/src/verification_runner.rs \
    && grep -q "RCH Proof Ledger Runbook" docs/runbooks/rch-proof-ledger.md; then
    scenario_result "rch_proof_ledger_cli_docs_wired" "PASS" "CLI command, renderer, and runbook references exist"
else
    scenario_result "rch_proof_ledger_cli_docs_wired" "FAIL" "missing CLI command, renderer, or runbook"
fi

e2e_step "Scenario 2: synthetic transcripts produce JSON and Markdown proof artifacts"
if write_fixture_reports \
    && [[ -s "$REPORT_BUNDLE" ]] \
    && [[ -s "$SUMMARY_MD" ]] \
    && [[ -s "$REPORT_DIR/remote_success.json" ]] \
    && [[ -s "$REPORT_DIR/artifact_warning.md" ]] \
    && [[ -s "$REPORT_DIR/local_fallback.md" ]]; then
    scenario_result "rch_proof_ledger_artifacts_written" "PASS" "reports=$REPORT_BUNDLE summary=$SUMMARY_MD"
else
    scenario_result "rch_proof_ledger_artifacts_written" "FAIL" "proof artifacts were not written"
fi

e2e_step "Scenario 3: remote success transcript is sufficient proof"
if python3 - "$REPORT_BUNDLE" <<'PY'
import json
import sys
reports = {row["case_id"]: row for row in json.load(open(sys.argv[1], encoding="utf-8"))["reports"]}
row = reports["remote_success"]
assert row["proof_verdict"] == "remote_success"
assert row["remote_exit_code"] == 0
assert row["worker_id"] == "vmi1227854"
assert row["artifact_retrieval_status"] == {"source": "retrieved", "target": "retrieved"}
assert not row["fallback_detected"]
PY
then
    scenario_result "rch_proof_ledger_remote_success_contract" "PASS" "remote exit=0 with retrieved artifacts is sufficient proof"
else
    scenario_result "rch_proof_ledger_remote_success_contract" "FAIL" "remote success contract failed"
fi

e2e_step "Scenario 4: target artifact warning becomes degraded proof"
if python3 - "$REPORT_BUNDLE" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys
reports = {row["case_id"]: row for row in json.load(open(sys.argv[1], encoding="utf-8"))["reports"]}
row = reports["artifact_warning"]
assert row["proof_verdict"] == "remote_success_artifact_warning"
assert row["remote_exit_code"] == 0
assert row["artifact_retrieval_status"]["target"] == "warning"
assert "artifact_retrieval_warning" in row["warnings"]
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
assert "degraded-proof note" in summary
PY
then
    scenario_result "rch_proof_ledger_artifact_warning_degraded" "PASS" "target retrieval warning degrades proof without erasing worker success"
else
    scenario_result "rch_proof_ledger_artifact_warning_degraded" "FAIL" "artifact warning contract failed"
fi

e2e_step "Scenario 5: local fallback invalidates remote-only proof"
if python3 - "$REPORT_BUNDLE" <<'PY'
import json
import sys
reports = {row["case_id"]: row for row in json.load(open(sys.argv[1], encoding="utf-8"))["reports"]}
row = reports["local_fallback"]
assert row["proof_verdict"] == "invalid_local_fallback"
assert row["fallback_detected"] is True
assert row["local_fallback_reason"] == "remote execution failed"
assert row["remote_exit_code"] is None
assert "local_fallback_detected" in row["warnings"]
PY
then
    scenario_result "rch_proof_ledger_local_fallback_invalid" "PASS" "local fallback is rejected as remote proof"
else
    scenario_result "rch_proof_ledger_local_fallback_invalid" "FAIL" "local fallback contract failed"
fi

e2e_step "Scenario 6: operator runbook documents proof boundaries"
if grep -q "Worker-side exit=0" docs/runbooks/rch-proof-ledger.md \
    && grep -q "degraded-proof note" docs/runbooks/rch-proof-ledger.md \
    && grep -q "Local fallback is not remote validation proof" docs/runbooks/rch-proof-ledger.md \
    && grep -q "ffs-harness rch-proof-ledger" docs/runbooks/rch-proof-ledger.md; then
    scenario_result "rch_proof_ledger_operator_docs_boundaries" "PASS" "runbook documents success, degraded proof, fallback rejection, and CLI"
else
    scenario_result "rch_proof_ledger_operator_docs_boundaries" "FAIL" "runbook missing required proof boundary wording"
fi

e2e_step "Scenario 7: fixture lane avoids live cargo and live worker execution"
if python3 - "$0" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
patterns = [
    "e2e_" + "rch_capture",
    "run_" + "rch_capture",
    "RCH_" + "BIN",
    "rch" + " exec",
    "cargo" + " run",
]
for pattern in patterns:
    if pattern in text:
        raise SystemExit(f"live invocation token present: {pattern}")
PY
then
    scenario_result "rch_proof_ledger_fixture_no_live_worker" "PASS" "script does not invoke cargo or rch"
else
    scenario_result "rch_proof_ledger_fixture_no_live_worker" "FAIL" "script contains a live cargo or rch invocation"
fi

e2e_step "Scenario 8: scenario catalog accepts the proof ledger suite"
if e2e_validate_scenario_catalog; then
    scenario_result "rch_proof_ledger_catalog_valid" "PASS" "scenario catalog validates with proof ledger suite"
else
    scenario_result "rch_proof_ledger_catalog_valid" "FAIL" "scenario catalog validation failed"
fi

e2e_log "RCH proof ledger report bundle: $REPORT_BUNDLE"
e2e_log "RCH proof ledger Markdown summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "RCH proof ledger scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "RCH proof ledger scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
