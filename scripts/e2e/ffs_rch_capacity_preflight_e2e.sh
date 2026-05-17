#!/usr/bin/env bash
# ffs_rch_capacity_preflight_e2e.sh - live, non-mutating RCH capacity report.
#
# This suite records why remote proof lanes are or are not currently admissible.
# The default path does not invoke workers. The optional probe uses a small
# remote-required cargo check and refuses local fallback as proof.

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

json_field() {
    local path="$1"
    local expr="$2"
    python3 - "$path" "$expr" <<'PY'
import json
import sys

path, expr = sys.argv[1:]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

value = data
for part in expr.split("."):
    if not part:
        continue
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break

if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
else:
    print(value)
PY
}

e2e_init "ffs_rch_capacity_preflight"
e2e_print_env

RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_RCH_CAPACITY_PREFLIGHT_RCH_VISIBILITY:-summary}"
RUN_PROBE="${FFS_RCH_CAPACITY_PREFLIGHT_RUN_PROBE:-0}"
SKIP_FIXTURE_SELF_CHECK="${FFS_RCH_CAPACITY_PREFLIGHT_SKIP_FIXTURE_SELF_CHECK:-0}"

STATUS_JSON="$E2E_LOG_DIR/rch_status.json"
STATUS_STDERR="$E2E_LOG_DIR/rch_status.stderr"
PROBE_RAW="$E2E_LOG_DIR/rch_capacity_probe.raw"
REPORT_JSON="$E2E_LOG_DIR/rch_capacity_preflight_report.json"
REPORT_MD="$E2E_LOG_DIR/rch_capacity_preflight_summary.md"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case_name="${FFS_RCH_CAPACITY_PREFLIGHT_FIXTURE_CASE:-remote_success}"

if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
    case "$case_name" in
        remote_success)
            cat <<'JSON'
{
  "api_version": "1.0",
  "timestamp": 1,
  "command": "status",
  "success": true,
  "data": {
    "posture": "ready",
    "posture_description": "fixture remote capacity available",
    "daemon": {
      "daemon": {
        "workers_total": 1,
        "workers_healthy": 1,
        "slots_total": 4,
        "slots_available": 4,
        "version": "fixture",
        "socket_path": "/tmp/rch-fixture.sock"
      },
      "workers": [
        {
          "id": "fixture-remote",
          "status": "healthy",
          "circuit_state": "closed",
          "pressure_state": "normal",
          "pressure_confidence": "high",
          "pressure_reason_code": "ok",
          "pressure_policy_rule": "fixture",
          "pressure_disk_free_gb": 100.0,
          "pressure_disk_free_ratio": 0.5,
          "pressure_telemetry_fresh": true,
          "pressure_telemetry_age_secs": 1,
          "last_error": null
        }
      ],
      "alerts": [],
      "issues": []
    },
    "remediation_hints": []
  }
}
JSON
            ;;
        local_fallback)
            cat <<'JSON'
{
  "api_version": "1.0",
  "timestamp": 2,
  "command": "status",
  "success": true,
  "data": {
    "posture": "degraded",
    "posture_description": "fixture workers blocked by pressure",
    "daemon": {
      "daemon": {
        "workers_total": 2,
        "workers_healthy": 2,
        "slots_total": 8,
        "slots_available": 8,
        "version": "fixture",
        "socket_path": "/tmp/rch-fixture.sock"
      },
      "workers": [
        {
          "id": "fixture-critical-a",
          "status": "healthy",
          "circuit_state": "closed",
          "pressure_state": "critical",
          "pressure_confidence": "high",
          "pressure_reason_code": "disk_ratio_below_critical",
          "pressure_policy_rule": "disk_free_ratio<=critical_free_ratio",
          "pressure_disk_free_gb": 1.0,
          "pressure_disk_free_ratio": 0.01,
          "pressure_telemetry_fresh": true,
          "pressure_telemetry_age_secs": 1,
          "last_error": null
        },
        {
          "id": "fixture-critical-b",
          "status": "healthy",
          "circuit_state": "closed",
          "pressure_state": "critical",
          "pressure_confidence": "high",
          "pressure_reason_code": "disk_free_below_critical_gb",
          "pressure_policy_rule": "disk_free_gb<=critical_free_gb",
          "pressure_disk_free_gb": 2.0,
          "pressure_disk_free_ratio": 0.02,
          "pressure_telemetry_fresh": true,
          "pressure_telemetry_age_secs": 1,
          "last_error": null
        }
      ],
      "alerts": [],
      "issues": [
        {
          "severity": "error",
          "summary": "fixture workers in critical pressure state",
          "remediation": "rch workers capabilities --refresh"
        }
      ]
    },
    "remediation_hints": [
      {
        "reason_code": "pressure_critical",
        "severity": "critical",
        "message": "fixture worker under critical storage pressure",
        "suggested_action": "inspect fixture worker disk pressure"
      }
    ]
  }
}
JSON
            ;;
        *)
            echo "unknown fixture case: $case_name" >&2
            exit 64
            ;;
    esac
    exit 0
fi

if [[ "${1:-}" == "exec" && "${2:-}" == "--" ]]; then
    case "$case_name" in
        remote_success)
            echo "[RCH] remote worker=fixture-remote exit=0"
            exit 0
            ;;
        local_fallback)
            echo "[RCH] local (no admissible workers: critical_pressure=2)"
            echo "remote required; refusing local fallback"
            exit 1
            ;;
        *)
            echo "unknown fixture case: $case_name" >&2
            exit 64
            ;;
    esac
fi

echo "unexpected fixture rch invocation: $*" >&2
exit 64
SH
    chmod +x "$stub_path"
}

run_fixture_case() {
    local stub_path="$1"
    local fixture_case="$2"
    local scenario_id="$3"
    local expected_capacity="$4"
    local expected_probe="$5"
    local expected_fallback_count="$6"
    local child_log child_result

    child_log="$E2E_LOG_DIR/rch_capacity_fixture_${fixture_case}.log"
    if FFS_RCH_CAPACITY_PREFLIGHT_SKIP_FIXTURE_SELF_CHECK=1 \
        FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_RCH_CAPACITY_PREFLIGHT_RUN_PROBE=1 \
        FFS_RCH_CAPACITY_PREFLIGHT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_rch_capacity_preflight_e2e.sh" >"$child_log" 2>&1; then
        child_result="$(sed -n 's/^JSON summary written: //p' "$child_log" | tail -n 1)"
        if [[ -n "$child_result" ]] \
            && jq -e \
                --arg capacity "$expected_capacity" \
                --arg probe "$expected_probe" \
                --argjson fallback_count "$expected_fallback_count" \
                '
                    .verdict == "PASS"
                    and .capacity_verdict == $capacity
                    and .probe_verdict == $probe
                    and .invalid_scenario_marker_count == 0
                    and .rch_local_fallback_rejected_count == $fallback_count
                    and (.capacity_report_path | type == "string" and length > 0)
                ' "$child_result" >/dev/null; then
            scenario_result "$scenario_id" "PASS" "fixture=${fixture_case} result=${child_result}"
        else
            scenario_result "$scenario_id" "FAIL" "fixture=${fixture_case} unexpected result"
            e2e_log "Fixture child log: $child_log"
            [[ -n "${child_result:-}" ]] && e2e_log "Fixture child result: $child_result"
            return 1
        fi
    else
        scenario_result "$scenario_id" "FAIL" "fixture=${fixture_case} child failed"
        e2e_log "Fixture child log: $child_log"
        return 1
    fi
}

run_fixture_self_check() {
    if [[ "$SKIP_FIXTURE_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    # Catalog evidence hooks for the variable-driven fixture helper:
    # scenario_result "rch_capacity_fixture_remote_success_self_check" "PASS"
    # scenario_result "rch_capacity_fixture_local_fallback_self_check" "PASS"
    e2e_step "Deterministic fixture self-check"
    local stub_path
    stub_path="$E2E_TEMP_DIR/rch-fixture"
    write_fixture_rch_stub "$stub_path"
    run_fixture_case \
        "$stub_path" \
        "remote_success" \
        "rch_capacity_fixture_remote_success_self_check" \
        "admissible_capacity_available" \
        "remote_success" \
        0
    run_fixture_case \
        "$stub_path" \
        "local_fallback" \
        "rch_capacity_fixture_local_fallback_self_check" \
        "no_admissible_workers" \
        "local_fallback_rejected" \
        1
}

e2e_step "Capture live RCH status"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    scenario_result "rch_capacity_status_json_parses" "FAIL" "rch binary not found: ${RCH_BIN}"
    e2e_fail "rch binary not found: $RCH_BIN"
fi

STATUS_EXIT=0
"$RCH_BIN" status --json >"$STATUS_JSON" 2>"$STATUS_STDERR" || STATUS_EXIT=$?
e2e_log "RCH status exit code: $STATUS_EXIT"
e2e_log "RCH status JSON: $STATUS_JSON"
e2e_log "RCH status stderr: $STATUS_STDERR"

if python3 -m json.tool "$STATUS_JSON" >/dev/null 2>&1; then
    scenario_result "rch_capacity_status_json_parses" "PASS" "status_json=${STATUS_JSON}"
else
    scenario_result "rch_capacity_status_json_parses" "FAIL" "status output was not JSON"
    e2e_fail "rch status --json did not emit parseable JSON"
fi

PROBE_EXIT="not_run"
if [[ "$RUN_PROBE" == "1" ]]; then
    e2e_step "Run optional remote-required RCH probe"
    PROBE_EXIT=0
    RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        "$RCH_BIN" exec -- cargo check -p ffs-error --lib >"$PROBE_RAW" 2>&1 || PROBE_EXIT=$?
    e2e_log "RCH probe exit code: $PROBE_EXIT"
    e2e_log "RCH probe raw log: $PROBE_RAW"
    if grep -q '^\[RCH\] local ' "$PROBE_RAW"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${PROBE_RAW}|command=cargo check -p ffs-error --lib"
    fi
else
    printf 'probe not requested; set FFS_RCH_CAPACITY_PREFLIGHT_RUN_PROBE=1 to run remote-required probe\n' >"$PROBE_RAW"
fi

e2e_step "Build capacity preflight report"

if ! python3 - "$STATUS_JSON" "$STATUS_STDERR" "$PROBE_RAW" "$REPORT_JSON" "$REPORT_MD" \
    "$STATUS_EXIT" "$RUN_PROBE" "$PROBE_EXIT" <<'PY'
import datetime as dt
import json
import pathlib
import re
import sys

(
    status_json_arg,
    status_stderr_arg,
    probe_raw_arg,
    report_json_arg,
    report_md_arg,
    status_exit_arg,
    run_probe_arg,
    probe_exit_arg,
) = sys.argv[1:]

status_json_path = pathlib.Path(status_json_arg)
status_stderr_path = pathlib.Path(status_stderr_arg)
probe_raw_path = pathlib.Path(probe_raw_arg)
report_json_path = pathlib.Path(report_json_arg)
report_md_path = pathlib.Path(report_md_arg)

status_payload = json.loads(status_json_path.read_text(encoding="utf-8"))
status_exit = int(status_exit_arg)
probe_requested = run_probe_arg == "1"
probe_exit = None if probe_exit_arg == "not_run" else int(probe_exit_arg)
probe_text = probe_raw_path.read_text(encoding="utf-8") if probe_raw_path.exists() else ""

data = status_payload.get("data") or {}
daemon = data.get("daemon") or {}
daemon_info = daemon.get("daemon") or {}
workers = daemon.get("workers") or []
alerts = daemon.get("alerts") or []
issues = daemon.get("issues") or []
remediation_hints = data.get("remediation_hints") or []


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def compact_worker(worker):
    return {
        "id": worker.get("id"),
        "status": worker.get("status"),
        "circuit_state": worker.get("circuit_state"),
        "pressure_state": worker.get("pressure_state"),
        "pressure_confidence": worker.get("pressure_confidence"),
        "pressure_reason_code": worker.get("pressure_reason_code"),
        "pressure_policy_rule": worker.get("pressure_policy_rule"),
        "pressure_disk_free_gb": worker.get("pressure_disk_free_gb"),
        "pressure_disk_free_ratio": worker.get("pressure_disk_free_ratio"),
        "pressure_telemetry_fresh": worker.get("pressure_telemetry_fresh"),
        "pressure_telemetry_age_secs": worker.get("pressure_telemetry_age_secs"),
        "last_error": worker.get("last_error"),
    }


def is_admissible(worker):
    if worker.get("status") != "healthy":
        return False
    if worker.get("circuit_state") not in (None, "closed"):
        return False
    if worker.get("pressure_state") in {"critical", "telemetry_gap"}:
        return False
    return True


workers_total = as_int(daemon_info.get("workers_total"), len(workers))
workers_healthy = as_int(
    daemon_info.get("workers_healthy"),
    sum(1 for worker in workers if worker.get("status") == "healthy"),
)

admissible_workers = [compact_worker(worker) for worker in workers if is_admissible(worker)]
critical_workers = [
    compact_worker(worker) for worker in workers if worker.get("pressure_state") == "critical"
]
telemetry_gap_workers = [
    compact_worker(worker) for worker in workers if worker.get("pressure_state") == "telemetry_gap"
]
telemetry_stale_workers = [
    compact_worker(worker)
    for worker in workers
    if worker.get("pressure_telemetry_fresh") is False
]
unhealthy_workers = [
    compact_worker(worker) for worker in workers if worker.get("status") != "healthy"
]
active_offline_alerts = [
    alert
    for alert in alerts
    if alert.get("kind") == "worker_offline" and alert.get("state") == "active"
]
unreachable_worker_ids = sorted(
    {
        worker.get("id")
        for worker in workers
        if worker.get("status") in {"offline", "unreachable"}
    }
    | {alert.get("worker_id") for alert in active_offline_alerts if alert.get("worker_id")}
)

if status_exit != 0 or status_payload.get("success") is False:
    capacity_verdict = "status_capture_failed"
elif admissible_workers:
    capacity_verdict = "admissible_capacity_available"
elif workers_total == 0:
    capacity_verdict = "no_workers_reported"
else:
    capacity_verdict = "no_admissible_workers"

blocker_reasons = []
if critical_workers:
    blocker_reasons.append("critical_pressure")
if telemetry_gap_workers:
    blocker_reasons.append("telemetry_gap")
if unreachable_worker_ids:
    blocker_reasons.append("unreachable_workers")
if unhealthy_workers:
    blocker_reasons.append("unhealthy_workers")
if status_exit != 0 or status_payload.get("success") is False:
    blocker_reasons.append("status_capture_failed")

if not probe_requested:
    probe_verdict = "not_run"
elif re.search(r"^\[RCH\] local ", probe_text, flags=re.MULTILINE):
    probe_verdict = "local_fallback_rejected"
elif re.search(r"^\[RCH\] remote ", probe_text, flags=re.MULTILINE) and probe_exit == 0:
    probe_verdict = "remote_success"
elif "remote required" in probe_text.lower() or "no admissible workers" in probe_text.lower():
    probe_verdict = "remote_required_refused"
elif re.search(r"^\[RCH\] remote ", probe_text, flags=re.MULTILINE):
    probe_verdict = "remote_failure"
else:
    probe_verdict = "no_remote_summary"

operator_actions = []
for hint in remediation_hints:
    operator_actions.append(
        {
            "source": "remediation_hints",
            "worker_id": hint.get("worker_id"),
            "severity": hint.get("severity"),
            "reason_code": hint.get("reason_code"),
            "message": hint.get("message"),
            "suggested_action": hint.get("suggested_action"),
        }
    )
for issue in issues:
    operator_actions.append(
        {
            "source": "daemon_issues",
            "worker_id": None,
            "severity": issue.get("severity"),
            "reason_code": None,
            "message": issue.get("summary"),
            "suggested_action": issue.get("remediation"),
        }
    )

report = {
    "schema_version": 1,
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "capacity_verdict": capacity_verdict,
    "posture": data.get("posture"),
    "posture_description": data.get("posture_description"),
    "status_capture": {
        "exit_code": status_exit,
        "success": status_payload.get("success"),
        "status_path": str(status_json_path),
        "stderr_path": str(status_stderr_path),
        "api_version": status_payload.get("api_version"),
        "timestamp": status_payload.get("timestamp"),
    },
    "daemon": {
        "workers_total": workers_total,
        "workers_healthy": workers_healthy,
        "slots_total": daemon_info.get("slots_total"),
        "slots_available": daemon_info.get("slots_available"),
        "version": daemon_info.get("version"),
        "socket_path": daemon_info.get("socket_path"),
    },
    "worker_counts": {
        "admissible": len(admissible_workers),
        "critical_pressure": len(critical_workers),
        "telemetry_gap": len(telemetry_gap_workers),
        "telemetry_stale": len(telemetry_stale_workers),
        "unhealthy": len(unhealthy_workers),
        "unreachable": len(unreachable_worker_ids),
    },
    "worker_groups": {
        "admissible": admissible_workers,
        "critical_pressure": critical_workers,
        "telemetry_gap": telemetry_gap_workers,
        "telemetry_stale": telemetry_stale_workers,
        "unhealthy": unhealthy_workers,
        "unreachable_worker_ids": unreachable_worker_ids,
    },
    "blocker_reasons": blocker_reasons,
    "operator_actions": operator_actions,
    "probe": {
        "requested": probe_requested,
        "command": ["cargo", "check", "-p", "ffs-error", "--lib"],
        "exit_code": probe_exit,
        "verdict": probe_verdict,
        "fail_closed": probe_requested and probe_verdict != "remote_success",
        "raw_log": str(probe_raw_path),
    },
    "artifact_paths": {
        "status_json": str(status_json_path),
        "status_stderr": str(status_stderr_path),
        "probe_raw": str(probe_raw_path),
        "report_json": str(report_json_path),
        "summary_md": str(report_md_path),
    },
}

report_json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

worker_counts = report["worker_counts"]
actions_line = "none"
if operator_actions:
    actions_line = f"{len(operator_actions)} action(s); first: {operator_actions[0].get('suggested_action') or operator_actions[0].get('message')}"

summary = f"""# RCH Capacity Preflight

- Verdict: `{capacity_verdict}`
- Posture: `{report["posture"] or "unknown"}`
- Workers: `{workers_healthy}/{workers_total}` healthy, `{worker_counts["admissible"]}` admissible
- Critical pressure workers: `{worker_counts["critical_pressure"]}`
- Telemetry gap workers: `{worker_counts["telemetry_gap"]}`
- Unreachable workers: `{worker_counts["unreachable"]}`
- Probe verdict: `{probe_verdict}`
- Operator actions: `{actions_line}`

## Artifact Paths

- Status JSON: `{status_json_path}`
- Probe log: `{probe_raw_path}`
- Report JSON: `{report_json_path}`
"""
report_md_path.write_text(summary, encoding="utf-8")
PY
then
    scenario_result "rch_capacity_worker_pressure_classified" "FAIL" "report generation failed"
    e2e_fail "RCH capacity report generation failed"
fi

e2e_log "RCH capacity report: $REPORT_JSON"
e2e_log "RCH capacity summary: $REPORT_MD"

if jq -e '
    (.capacity_verdict | type == "string" and length > 0)
    and (.worker_counts.admissible | type == "number")
    and (.worker_counts.critical_pressure | type == "number")
    and (.worker_counts.telemetry_gap | type == "number")
    and (.worker_counts.unreachable | type == "number")
' "$REPORT_JSON" >/dev/null; then
    scenario_result "rch_capacity_worker_pressure_classified" "PASS" "report=${REPORT_JSON}"
else
    scenario_result "rch_capacity_worker_pressure_classified" "FAIL" "worker classification missing from report"
    e2e_fail "RCH capacity report missing worker classification fields"
fi

CAPACITY_VERDICT="$(json_field "$REPORT_JSON" "capacity_verdict")"
case "$CAPACITY_VERDICT" in
    admissible_capacity_available | no_admissible_workers | no_workers_reported | status_capture_failed)
        scenario_result "rch_capacity_capacity_verdict_recorded" "PASS" "verdict=${CAPACITY_VERDICT}"
        ;;
    *)
        scenario_result "rch_capacity_capacity_verdict_recorded" "FAIL" "verdict=${CAPACITY_VERDICT}"
        e2e_fail "Unknown RCH capacity verdict: $CAPACITY_VERDICT"
        ;;
esac

ACTION_COUNT="$(jq -r '.operator_actions | length' "$REPORT_JSON")"
if [[ "$CAPACITY_VERDICT" == "admissible_capacity_available" || "$ACTION_COUNT" -gt 0 ]]; then
    scenario_result "rch_capacity_operator_actions_reported" "PASS" "operator_actions=${ACTION_COUNT}"
else
    scenario_result "rch_capacity_operator_actions_reported" "FAIL" "blocked verdict without operator actions"
    e2e_fail "RCH capacity report has a blocked verdict without operator actions"
fi

PROBE_VERDICT="$(json_field "$REPORT_JSON" "probe.verdict")"
PROBE_FAIL_CLOSED="$(json_field "$REPORT_JSON" "probe.fail_closed")"
if [[ "$RUN_PROBE" == "1" ]]; then
    if [[ "$PROBE_VERDICT" == "remote_success" ]]; then
        scenario_result "rch_capacity_probe_remote_success" "PASS" "probe_log=${PROBE_RAW}"
    elif [[ "$PROBE_FAIL_CLOSED" == "true" && "$PROBE_VERDICT" != "no_remote_summary" ]]; then
        scenario_result "rch_capacity_probe_fail_closed" "PASS" "probe_verdict=${PROBE_VERDICT}"
    else
        scenario_result "rch_capacity_probe_fail_closed" "FAIL" "probe_verdict=${PROBE_VERDICT}"
        e2e_fail "RCH capacity probe did not produce remote success or explicit fail-closed RCH evidence"
    fi
else
    scenario_result "rch_capacity_probe_optional_boundary" "PASS" "probe not requested"
fi

if python3 - "$REPO_ROOT/scripts/e2e/scenario_catalog.json" "$0" <<'PY'
import json
import pathlib
import sys

catalog_path = pathlib.Path(sys.argv[1])
script_path = pathlib.Path(sys.argv[2])
catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
script_text = script_path.read_text(encoding="utf-8")

required_ids = {
    "rch_capacity_status_json_parses",
    "rch_capacity_worker_pressure_classified",
    "rch_capacity_capacity_verdict_recorded",
    "rch_capacity_operator_actions_reported",
    "rch_capacity_probe_remote_success",
    "rch_capacity_probe_fail_closed",
    "rch_capacity_probe_optional_boundary",
    "rch_capacity_fixture_remote_success_self_check",
    "rch_capacity_fixture_local_fallback_self_check",
    "rch_capacity_catalog_valid",
}
required_categories = {"happy", "degradation", "error"}

suite = next(
    (item for item in catalog.get("suites", []) if item.get("suite_id") == "ffs_rch_capacity_preflight"),
    None,
)
if suite is None:
    raise SystemExit("ffs_rch_capacity_preflight suite missing")
if suite.get("script") != "scripts/e2e/ffs_rch_capacity_preflight_e2e.sh":
    raise SystemExit(f"unexpected suite script: {suite.get('script')}")

active = {
    scenario.get("id"): scenario
    for scenario in suite.get("scenarios", [])
    if scenario.get("status", "active") == "active"
}
missing = sorted(required_ids - set(active))
if missing:
    raise SystemExit(f"missing active scenario IDs: {missing}")

seen_categories = {scenario.get("category") for scenario in active.values()}
missing_categories = sorted(required_categories - seen_categories)
if missing_categories:
    raise SystemExit(f"missing required categories: {missing_categories}")

for scenario_id in sorted(required_ids):
    scenario = active[scenario_id]
    evidence = scenario.get("evidence", "")
    expected = f"SCENARIO_RESULT|scenario_id={scenario_id}|outcome=PASS"
    helper = f'scenario_result "{scenario_id}" "PASS"'
    if expected not in evidence:
        raise SystemExit(f"bad evidence for {scenario_id}: {evidence}")
    if helper not in script_text:
        raise SystemExit(f"script helper missing for {scenario_id}")
PY
then
    scenario_result "rch_capacity_catalog_valid" "PASS" "catalog validation passed"
else
    scenario_result "rch_capacity_catalog_valid" "FAIL" "catalog validation failed"
    e2e_fail "Scenario catalog validation failed"
fi

run_fixture_self_check

python3 - "$REPORT_JSON" "$E2E_LOG_DIR/result.json" <<'PY'
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
result_path = pathlib.Path(sys.argv[2])
report = json.loads(report_path.read_text(encoding="utf-8"))
result_path.write_text(
    json.dumps(
        {
            "capacity_report_path": str(report_path),
            "capacity_verdict": report["capacity_verdict"],
            "admissible_worker_count": report["worker_counts"]["admissible"],
            "critical_pressure_worker_count": report["worker_counts"]["critical_pressure"],
            "telemetry_gap_worker_count": report["worker_counts"]["telemetry_gap"],
            "probe_verdict": report["probe"]["verdict"],
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

if ((FAIL_COUNT > 0)); then
    e2e_fail "RCH capacity preflight scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi

e2e_log "Scenario totals: pass=${PASS_COUNT} fail=${FAIL_COUNT} total=${TOTAL}"
e2e_pass
