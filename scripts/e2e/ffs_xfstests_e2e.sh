#!/usr/bin/env bash
# ffs_xfstests_e2e.sh - xfstests subset planning/execution for FrankenFS
#
# This suite tracks a curated generic/ext4 subset for FrankenFS and can:
# - plan mode: validate list files + emit subset artifacts
# - run mode: invoke xfstests `check` against the selected subset
#
# Defaults are intentionally CI-safe:
# - `XFSTESTS_MODE=auto` resolves to plan mode unless a usable xfstests tree is found.
# - `XFSTESTS_STRICT=0` causes missing prerequisites to skip (exit 0) with artifacts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_xfstests_e2e"
e2e_print_env

XFSTESTS_MODE="${XFSTESTS_MODE:-auto}"        # auto | plan | run
XFSTESTS_STRICT="${XFSTESTS_STRICT:-0}"       # 0 | 1
XFSTESTS_DRY_RUN="${XFSTESTS_DRY_RUN:-1}"     # 0 | 1 (run mode only)
XFSTESTS_FILTER="${XFSTESTS_FILTER:-all}"     # all | generic | ext4 | btrfs
XFSTESTS_DIR="${XFSTESTS_DIR:-}"
XFSTESTS_GENERIC_LIST="${XFSTESTS_GENERIC_LIST:-$REPO_ROOT/scripts/e2e/xfstests_generic.list}"
XFSTESTS_EXT4_LIST="${XFSTESTS_EXT4_LIST:-$REPO_ROOT/scripts/e2e/xfstests_ext4.list}"
XFSTESTS_BTRFS_LIST="${XFSTESTS_BTRFS_LIST:-$REPO_ROOT/scripts/e2e/xfstests_btrfs.list}"
XFSTESTS_REGRESSION_GUARD_JSON="${XFSTESTS_REGRESSION_GUARD_JSON:-$REPO_ROOT/scripts/e2e/xfstests_regression_guard.json}"
XFSTESTS_ALLOWLIST_JSON="${XFSTESTS_ALLOWLIST_JSON:-$REPO_ROOT/scripts/e2e/xfstests_allowlist.json}"
XFSTESTS_BASELINE_JSON="${XFSTESTS_BASELINE_JSON:-}"
XFSTESTS_PREFLIGHT_SCRIPT="${XFSTESTS_PREFLIGHT_SCRIPT:-$REPO_ROOT/scripts/e2e/ffs_xfstests_preflight_e2e.sh}"
XFSTESTS_PREFLIGHT_MAX_AGE_SECS="${XFSTESTS_PREFLIGHT_MAX_AGE_SECS:-3600}"
FFS_HARNESS_BIN="${FFS_HARNESS_BIN:-$REPO_ROOT/target/debug/ffs-harness}"

ARTIFACT_DIR="$E2E_LOG_DIR/xfstests"
SELECTED_FILE="$ARTIFACT_DIR/selected_tests.txt"
SUMMARY_JSON="$ARTIFACT_DIR/summary.json"
RESULTS_JSON="$ARTIFACT_DIR/results.json"
JUNIT_FILE="$ARTIFACT_DIR/junit.xml"
CHECK_LOG="$ARTIFACT_DIR/check.log"
POLICY_PLAN_JSON="$ARTIFACT_DIR/policy_plan.json"
POLICY_REPORT_MD="$ARTIFACT_DIR/policy_report.md"
XFSTESTS_PREFLIGHT_JSON="${XFSTESTS_PREFLIGHT_JSON:-$ARTIFACT_DIR/preflight.json}"
mkdir -p "$ARTIFACT_DIR"

declare -a GENERIC_TESTS=()
declare -a EXT4_TESTS=()
declare -a BTRFS_TESTS=()
declare -a SELECTED_TESTS=()
EFFECTIVE_MODE="$XFSTESTS_MODE"
LAST_CHECK_RC="null"

harness_supports_xfstests_report() {
    [[ -x "$FFS_HARNESS_BIN" ]] || return 1
    "$FFS_HARNESS_BIN" help 2>&1 | grep -Fq "xfstests-report"
}

resolve_xfstests_dir() {
    if [[ -n "$XFSTESTS_DIR" ]]; then
        return 0
    fi

    local candidate
    for candidate in \
        "$REPO_ROOT/third_party/xfstests-dev" \
        "/opt/xfstests-dev" \
        "$HOME/src/xfstests-dev"; do
        if [[ -x "$candidate/check" ]]; then
            XFSTESTS_DIR="$candidate"
            return 0
        fi
    done
}

write_summary() {
    local status="$1"
    local mode="$2"
    local reason="${3:-}"
    local check_rc="${4:-null}"
    local safe_reason="${reason//\"/\\\"}"
    local safe_dir="${XFSTESTS_DIR//\"/\\\"}"
    local safe_guard="${XFSTESTS_REGRESSION_GUARD_JSON//\"/\\\"}"
    local safe_allowlist="${XFSTESTS_ALLOWLIST_JSON//\"/\\\"}"
    local safe_baseline="${XFSTESTS_BASELINE_JSON//\"/\\\"}"
    local safe_results="${RESULTS_JSON//\"/\\\"}"
    local safe_junit="${JUNIT_FILE//\"/\\\"}"
    local safe_selected="${SELECTED_FILE//\"/\\\"}"
    local safe_check_log="${CHECK_LOG//\"/\\\"}"
    local safe_policy_plan="${POLICY_PLAN_JSON//\"/\\\"}"
    local safe_policy_report="${POLICY_REPORT_MD//\"/\\\"}"
    local safe_preflight="${XFSTESTS_PREFLIGHT_JSON//\"/\\\"}"
    local safe_summary="${SUMMARY_JSON//\"/\\\"}"
    local command_plan="./check"
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        command_plan+=" -n"
    fi
    command_plan+=" ${SELECTED_TESTS[*]}"
    local safe_command_plan="${command_plan//\"/\\\"}"
    local repro_command="XFSTESTS_MODE=$XFSTESTS_MODE XFSTESTS_FILTER=$XFSTESTS_FILTER XFSTESTS_DRY_RUN=$XFSTESTS_DRY_RUN XFSTESTS_STRICT=$XFSTESTS_STRICT ./scripts/e2e/ffs_xfstests_e2e.sh"
    local safe_repro_command="${repro_command//\"/\\\"}"

    cat >"$SUMMARY_JSON" <<EOF
{
  "status": "$status",
  "mode": "$mode",
  "filter": "$XFSTESTS_FILTER",
  "dry_run": $XFSTESTS_DRY_RUN,
  "strict": $XFSTESTS_STRICT,
  "check_rc": $check_rc,
  "xfstests_dir": "$safe_dir",
  "regression_guard_json": "$safe_guard",
  "allowlist_json": "$safe_allowlist",
  "baseline_json": "$safe_baseline",
  "selected_file": "$safe_selected",
  "results_json": "$safe_results",
  "junit_xml": "$safe_junit",
  "check_log": "$safe_check_log",
  "preflight_json": "$safe_preflight",
  "policy_plan_json": "$safe_policy_plan",
  "policy_report_md": "$safe_policy_report",
  "command_plan": "$safe_command_plan",
  "reproduction_command": "$safe_repro_command",
  "artifact_paths": {
    "selected_file": "$safe_selected",
    "results_json": "$safe_results",
    "junit_xml": "$safe_junit",
    "check_log": "$safe_check_log",
    "preflight_json": "$safe_preflight",
    "policy_plan_json": "$safe_policy_plan",
    "policy_report_md": "$safe_policy_report",
    "summary_json": "$safe_summary"
  },
  "generic_count": ${#GENERIC_TESTS[@]},
  "ext4_count": ${#EXT4_TESTS[@]},
  "btrfs_count": ${#BTRFS_TESTS[@]},
  "selected_count": ${#SELECTED_TESTS[@]},
  "reason": "$safe_reason"
}
EOF
}

write_policy_plan() {
    if ! command -v python3 >/dev/null 2>&1; then
        e2e_fail "python3 is required to validate and emit xfstests policy plan"
    fi

    python3 - "$SELECTED_FILE" "$XFSTESTS_ALLOWLIST_JSON" "$POLICY_PLAN_JSON" "$POLICY_REPORT_MD" "$ARTIFACT_DIR" "$XFSTESTS_FILTER" "$XFSTESTS_DRY_RUN" "$XFSTESTS_MODE" "$XFSTESTS_DIR" <<'PY'
import json
import pathlib
import sys
from collections import Counter

selected_file = pathlib.Path(sys.argv[1])
policy_file = pathlib.Path(sys.argv[2])
policy_plan = pathlib.Path(sys.argv[3])
policy_report = pathlib.Path(sys.argv[4])
artifact_dir = pathlib.Path(sys.argv[5])
xfstests_filter = sys.argv[6]
dry_run = sys.argv[7]
requested_mode = sys.argv[8]
xfstests_dir = sys.argv[9]

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
policy_entries = json.loads(policy_file.read_text(encoding="utf-8"))
policy_by_id = {}
errors = []
required_fields = [
    "policy_row_id",
    "test_id",
    "filesystem_flavor",
    "v1_scope_mapping",
    "expected_operation_class",
    "user_risk_category",
    "expected_outcome",
    "selection_decision",
    "status",
    "classification",
    "failure_reason",
    "tracker_id",
    "repro_command",
]
required_artifacts = {
    "selected_tests.txt",
    "policy_plan.json",
    "policy_report.md",
    "summary.json",
    "results.json",
    "junit.xml",
    "check.log",
}
allowed_plan_lanes = {
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
}
allowed_plan_privileges = {
    "none",
    "user_mount",
    "fuse_mount",
    "root_required",
    "cap_sys_admin",
    "scratch_device",
    "host_tooling",
}
allowed_plan_outcomes = {
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
    "product_failure",
    "harness_failure",
    "cleanup_failure",
}

def is_temp_path(value):
    return isinstance(value, str) and (
        value.startswith("${TMPDIR:-/tmp}/frankenfs-xfstests/")
        or value.startswith("$TMPDIR/frankenfs-xfstests/")
        or value.startswith("/tmp/frankenfs-xfstests/")
    )

def is_broad_shell_token(value):
    return value in {"sh", "bash", "zsh", "-c", "shell"} or any(
        token in value for token in ["&&", ";", "*"]
    )

def validate_command_plan(test_id, plan):
    plan_errors = []
    if not isinstance(plan, dict):
        return [f"policy {test_id} missing command_plan"]

    for field in [
        "plan_id",
        "execution_lane",
        "image_path",
        "scratch_path",
        "mountpoint",
        "test_device",
        "scratch_device",
        "image_hash",
        "helper_binaries",
        "required_privileges",
        "mutation_surface",
        "cleanup_action",
        "argv",
        "expected_plan_outcome",
        "command_summary",
    ]:
        value = plan.get(field)
        if value is None or value == "":
            plan_errors.append(f"policy {test_id} command plan missing {field}")

    if not str(plan.get("plan_id", "")).startswith("xfstests-plan-"):
        plan_errors.append(f"policy {test_id} command plan has malformed plan_id")
    if plan.get("execution_lane") not in allowed_plan_lanes:
        plan_errors.append(f"policy {test_id} command plan has unknown execution_lane")
    if not is_temp_path(plan.get("image_path")):
        plan_errors.append(f"policy {test_id} command plan has non-temporary image_path")
    if not is_temp_path(plan.get("scratch_path")):
        plan_errors.append(f"policy {test_id} command plan has non-temporary scratch_path")
    if not is_temp_path(plan.get("mountpoint")):
        plan_errors.append(f"policy {test_id} command plan has non-temporary mountpoint")
    if not is_temp_path(plan.get("test_device")):
        plan_errors.append(f"policy {test_id} command plan has non-temporary test_device")
    if not is_temp_path(plan.get("scratch_device")):
        plan_errors.append(f"policy {test_id} command plan has non-temporary scratch_device")
    if not str(plan.get("image_hash", "")).startswith("sha256:"):
        plan_errors.append(f"policy {test_id} command plan missing image_hash")

    helpers = plan.get("helper_binaries", [])
    if not isinstance(helpers, list) or not helpers:
        plan_errors.append(f"policy {test_id} command plan missing helper_binaries")
        helpers = []
    for helper in helpers:
        if not isinstance(helper, str) or not helper or "<" in helper or is_broad_shell_token(helper):
            plan_errors.append(f"policy {test_id} command plan has unresolved helper binary")

    privileges = plan.get("required_privileges", [])
    if not isinstance(privileges, list) or not privileges:
        plan_errors.append(f"policy {test_id} command plan missing required_privileges")
        privileges = []
    for privilege in privileges:
        if privilege not in allowed_plan_privileges:
            plan_errors.append(f"policy {test_id} command plan has unknown privilege {privilege}")

    argv = plan.get("argv", [])
    if not isinstance(argv, list) or not argv:
        plan_errors.append(f"policy {test_id} command plan missing argv")
        argv = []
    if test_id not in argv:
        plan_errors.append(f"policy {test_id} command plan argv does not name the test id")
    for arg in argv:
        if not isinstance(arg, str) or is_broad_shell_token(arg):
            plan_errors.append(f"policy {test_id} command plan has broad shell command token")

    if plan.get("expected_plan_outcome") not in allowed_plan_outcomes:
        plan_errors.append(f"policy {test_id} command plan has unknown expected_plan_outcome")
    if plan.get("destructive") and plan.get("execution_lane") != "permissioned_real":
        plan_errors.append(f"policy {test_id} command plan marks destructive action outside permissioned_real lane")

    return plan_errors

for entry in policy_entries:
    test_id = entry.get("test_id")
    if not isinstance(test_id, str) or not test_id:
        errors.append("policy entry missing test_id")
        continue
    if test_id in policy_by_id:
        errors.append(f"duplicate policy id: {test_id}")
    policy_by_id[test_id] = entry
    for field in required_fields:
        value = entry.get(field)
        if value is None or value == "":
            errors.append(f"policy {test_id} missing {field}")
    artifacts = entry.get("artifact_requirements")
    if not isinstance(artifacts, list):
        errors.append(f"policy {test_id} missing artifact_requirements")
        artifacts = []
    missing_artifacts = sorted(required_artifacts - {item for item in artifacts if isinstance(item, str)})
    for artifact in missing_artifacts:
        errors.append(f"policy {test_id} missing artifact requirement: {artifact}")
    errors.extend(validate_command_plan(test_id, entry.get("command_plan")))

selected_set = set(selected)
for test_id in selected:
    if test_id not in policy_by_id:
        errors.append(f"selected xfstests id lacks policy metadata: {test_id}")

for test_id in sorted(policy_by_id):
    if xfstests_filter == "all" and test_id not in selected_set:
        errors.append(f"policy references unselected xfstests id: {test_id}")

check_argv = ["./check"]
if dry_run == "1":
    check_argv.append("-n")
check_argv.extend(selected)

tests = []
capabilities = set()
status_counts = Counter()
classification_counts = Counter()
outcome_counts = Counter()
operation_counts = Counter()
flavor_counts = Counter()
lane_counts = Counter()
plan_outcome_counts = Counter()
command_plans = []
artifact_paths = {
    "selected_file": str(artifact_dir / "selected_tests.txt"),
    "results_json": str(artifact_dir / "results.json"),
    "junit_xml": str(artifact_dir / "junit.xml"),
    "check_log": str(artifact_dir / "check.log"),
    "summary_json": str(artifact_dir / "summary.json"),
    "policy_plan_json": str(policy_plan),
    "policy_report_md": str(policy_report),
}
for test_id in selected:
    entry = policy_by_id.get(test_id, {})
    command_plan = entry.get("command_plan", {})
    required = [cap for cap in entry.get("required_capabilities", []) if isinstance(cap, str)]
    capabilities.update(required)
    status = entry.get("status", "missing_policy")
    classification = entry.get("classification")
    expected_outcome = entry.get("expected_outcome")
    operation_class = entry.get("expected_operation_class")
    filesystem_flavor = entry.get("filesystem_flavor", test_id.split("/", 1)[0])
    status_counts[status] += 1
    classification_counts[classification or "missing"] += 1
    outcome_counts[expected_outcome or "missing"] += 1
    operation_counts[operation_class or "missing"] += 1
    flavor_counts[filesystem_flavor or "missing"] += 1
    lane_counts[command_plan.get("execution_lane", "missing")] += 1
    plan_outcome_counts[command_plan.get("expected_plan_outcome", "missing")] += 1
    command_plans.append(command_plan)
    for tag in entry.get("operation_class_tags", []):
        if isinstance(tag, str):
            operation_counts[tag] += 1
    skip_reason = None if status == "expected_pass" else entry.get("failure_reason")
    tests.append({
        "policy_row_id": entry.get("policy_row_id"),
        "test_id": test_id,
        "filesystem_flavor": filesystem_flavor,
        "v1_scope_mapping": entry.get("v1_scope_mapping"),
        "expected_operation_class": operation_class,
        "operation_class_tags": entry.get("operation_class_tags", []),
        "user_risk_category": entry.get("user_risk_category"),
        "expected_outcome": expected_outcome,
        "selection_decision": entry.get("selection_decision"),
        "status": status,
        "classification": classification,
        "required_capabilities": required,
        "artifact_requirements": entry.get("artifact_requirements", []),
        "skip_decision": {
            "status": status,
            "reason": skip_reason,
        },
        "scope_reference": entry.get("scope_reference"),
        "tracker_id": entry.get("tracker_id"),
        "repro_command": entry.get(
            "repro_command",
            f"XFSTESTS_MODE=run XFSTESTS_DRY_RUN={dry_run} ./scripts/e2e/ffs_xfstests_e2e.sh",
        ),
        "command_plan": command_plan,
        "log_fields": {
            "source_xfstests_id": test_id,
            "command_plan_id": command_plan.get("plan_id"),
            "policy_row_id": entry.get("policy_row_id"),
            "filesystem_flavor": filesystem_flavor,
            "risk_category": entry.get("user_risk_category"),
            "selected_or_skipped": entry.get("selection_decision"),
            "capability_requirement": required,
            "image_path": command_plan.get("image_path"),
            "image_hash": command_plan.get("image_hash"),
            "test_device": command_plan.get("test_device"),
            "scratch_device": command_plan.get("scratch_device"),
            "helper_versions": {
                helper: "not_resolved_in_plan_mode"
                for helper in command_plan.get("helper_binaries", [])
                if isinstance(helper, str)
            },
            "required_privileges": command_plan.get("required_privileges"),
            "mutation_surface": command_plan.get("mutation_surface"),
            "execution_lane": command_plan.get("execution_lane"),
            "command_summary": command_plan.get("command_summary"),
            "cleanup_status": "not_started_plan_mode",
            "linked_artifact_or_bead": entry.get("tracker_id"),
            "docs_scope_citation": entry.get("v1_scope_mapping") or entry.get("scope_reference"),
            "artifact_paths": artifact_paths,
            "reproduction_command": entry.get("repro_command"),
        },
    })

payload = {
    "requested_mode": requested_mode,
    "filter": xfstests_filter,
    "dry_run": dry_run == "1",
    "xfstests_dir": xfstests_dir,
    "command_plan": {
        "working_directory": xfstests_dir or "<resolved xfstests checkout>",
        "argv": check_argv,
        "display": " ".join(check_argv),
    },
    "reproduction_command": (
        f"XFSTESTS_MODE={requested_mode} XFSTESTS_FILTER={xfstests_filter} "
        f"XFSTESTS_DRY_RUN={dry_run} ./scripts/e2e/ffs_xfstests_e2e.sh"
    ),
    "artifact_paths": artifact_paths,
    "capability_checks": [
        {"capability": capability, "required": True, "source": "xfstests_policy"}
        for capability in sorted(capabilities)
    ],
    "status_counts": dict(sorted(status_counts.items())),
    "classification_counts": dict(sorted(classification_counts.items())),
    "expected_outcome_counts": dict(sorted(outcome_counts.items())),
    "operation_class_counts": dict(sorted(operation_counts.items())),
    "filesystem_flavor_counts": dict(sorted(flavor_counts.items())),
    "command_plan_lane_counts": dict(sorted(lane_counts.items())),
    "command_plan_outcome_counts": dict(sorted(plan_outcome_counts.items())),
    "command_plan_proof": {
        "default_non_destructive": all(not plan.get("destructive") for plan in command_plans),
        "temp_root": "${TMPDIR:-/tmp}/frankenfs-xfstests",
        "paths_verified_temp_scoped": all(
            is_temp_path(plan.get("image_path"))
            and is_temp_path(plan.get("scratch_path"))
            and is_temp_path(plan.get("mountpoint"))
            and is_temp_path(plan.get("test_device"))
            and is_temp_path(plan.get("scratch_device"))
            for plan in command_plans
        ),
        "broad_shell_commands_rejected": True,
        "permissioned_destructive_lane_required": True,
        "plans": command_plans,
    },
    "tests": tests,
    "validation_errors": errors,
}

policy_plan.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
report_lines = [
    "# xfstests subset policy report",
    "",
    "This report is a planning artifact. It counts product failures, environment blockers, harness blockers, expected unsupported rows, and not-run rows separately from passes.",
    "",
    "## Counts",
    "",
]
for label, counter in [
    ("Status", status_counts),
    ("Classification", classification_counts),
    ("Expected outcome", outcome_counts),
    ("Filesystem flavor", flavor_counts),
    ("Operation class", operation_counts),
    ("Command plan lane", lane_counts),
    ("Command plan outcome", plan_outcome_counts),
]:
    report_lines.append(f"### {label}")
    report_lines.append("")
    for key, value in sorted(counter.items()):
        report_lines.append(f"- {key}: {value}")
    report_lines.append("")

report_lines.extend([
    "## Rows",
    "",
    "| Policy row | Plan | Test id | Flavor | Operation | Risk | Outcome | Lane | Summary | Decision | Capability requirement | Artifact/bead | Scope | Reproduction |",
    "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
])
for test in tests:
    capability = ", ".join(test["required_capabilities"])
    plan = test.get("command_plan", {})
    report_lines.append(
        "| {policy_row_id} | {plan_id} | {test_id} | {filesystem_flavor} | {operation} | {risk} | {outcome} | {lane} | {summary} | {decision} | {capability} | {artifact} | {scope} | `{repro}` |".format(
            policy_row_id=test.get("policy_row_id") or "",
            plan_id=plan.get("plan_id") or "",
            test_id=test["test_id"],
            filesystem_flavor=test.get("filesystem_flavor") or "",
            operation=test.get("expected_operation_class") or "",
            risk=test.get("user_risk_category") or "",
            outcome=test.get("expected_outcome") or "",
            lane=plan.get("execution_lane") or "",
            summary=plan.get("command_summary") or "",
            decision=test.get("selection_decision") or "",
            capability=capability,
            artifact=test.get("tracker_id") or "",
            scope=test.get("v1_scope_mapping") or test.get("scope_reference") or "",
            repro=test.get("repro_command") or "",
        )
    )
report_lines.append("")
policy_report.write_text("\n".join(report_lines), encoding="utf-8")
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY
}

write_uniform_results() {
    local status="$1"
    local note="${2:-}"
    local note_safe="${note//\"/\\\"}"

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$SELECTED_FILE" "$RESULTS_JSON" "$JUNIT_FILE" "$status" "$note_safe" <<'PY'
import json
import pathlib
import sys
import xml.sax.saxutils

selected_file = pathlib.Path(sys.argv[1])
results_json = pathlib.Path(sys.argv[2])
junit_xml = pathlib.Path(sys.argv[3])
status = sys.argv[4]
note = sys.argv[5]

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
tests = [{"id": tid, "status": status} for tid in selected]

counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0, "planned": 0}
if status in counts:
    counts[status] = len(selected)
else:
    counts["not_run"] = len(selected)

pass_rate = 0.0
if selected and counts["passed"] > 0:
    pass_rate = counts["passed"] / len(selected)

payload = {
    "source": "uniform",
    "status": status,
    "note": note,
    "total": len(selected),
    "passed": counts["passed"],
    "failed": counts["failed"],
    "skipped": counts["skipped"],
    "not_run": counts["not_run"],
    "planned": counts["planned"],
    "pass_rate": pass_rate,
    "tests": tests,
}
results_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with junit_xml.open("w", encoding="utf-8") as fh:
    failures = counts["failed"]
    skipped = counts["skipped"] + counts["not_run"] + counts["planned"]
    fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fh.write(f'<testsuite name="ffs_xfstests_e2e" tests="{len(selected)}" failures="{failures}" skipped="{skipped}">\n')
    for tid in selected:
        esc = xml.sax.saxutils.escape(tid, {'"': "&quot;", "'": "&apos;"})
        fh.write(f'  <testcase name="{esc}" time="0.000">')
        if status == "failed":
            msg = xml.sax.saxutils.escape(note or "failed", {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<failure message="{msg}">{msg}</failure>')
        elif status in {"skipped", "not_run", "planned"}:
            msg = xml.sax.saxutils.escape(note or status, {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<skipped message="{msg}"/>')
        fh.write("</testcase>\n")
    fh.write("</testsuite>\n")
PY
        return 0
    fi

    # Fallback without python3: write minimal JSON and omit JUnit.
    cat >"$RESULTS_JSON" <<EOF
{
  "source": "uniform",
  "status": "$status",
  "note": "$note_safe",
  "total": ${#SELECTED_TESTS[@]},
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "not_run": ${#SELECTED_TESTS[@]},
  "planned": 0,
  "pass_rate": 0.0,
  "tests": []
}
EOF
}

skip_or_fail() {
    local reason="$1"
    if [[ ! -f "$RESULTS_JSON" ]]; then
        write_uniform_results "not_run" "$reason"
    fi
    write_summary "skipped" "$EFFECTIVE_MODE" "$reason" "$LAST_CHECK_RC"
    if [[ "$XFSTESTS_STRICT" == "1" ]]; then
        e2e_fail "$reason"
    fi
    e2e_skip "$reason"
}

ensure_xfstests_preflight() {
    e2e_step "xfstests prerequisite preflight"

    if [[ ! -f "$XFSTESTS_PREFLIGHT_JSON" ]]; then
        if [[ ! -f "$XFSTESTS_PREFLIGHT_SCRIPT" ]]; then
            skip_or_fail "xfstests prerequisite preflight script missing: $XFSTESTS_PREFLIGHT_SCRIPT"
        fi
        if ! "$XFSTESTS_PREFLIGHT_SCRIPT" --out "$XFSTESTS_PREFLIGHT_JSON" >"$ARTIFACT_DIR/preflight.stdout" 2>"$ARTIFACT_DIR/preflight.stderr"; then
            skip_or_fail "xfstests prerequisite preflight failed to emit proof (stdout=$ARTIFACT_DIR/preflight.stdout stderr=$ARTIFACT_DIR/preflight.stderr)"
        fi
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        skip_or_fail "python3 is required to validate xfstests prerequisite proof"
    fi

    local preflight_reason
    if ! preflight_reason="$(python3 - "$XFSTESTS_PREFLIGHT_JSON" "$XFSTESTS_PREFLIGHT_MAX_AGE_SECS" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

manifest_path = pathlib.Path(sys.argv[1])
max_age_secs = int(sys.argv[2])
required = {
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
}
side_effect_policy = "read_only_probe_no_install_no_mount_no_host_mutation"
risk_values = {"satisfied", "blocking", "advisory"}
lane_impacts = {
    "none",
    "blocks_permissioned_real_xfstests",
    "release_evidence_requires_worker",
}
package_manager_commands = {"apt", "apt-get", "dnf", "yum", "pacman", "zypper", "brew"}
persistent_mutation_commands = {"cp", "dd", "install", "mkdir", "mv", "rm", "rmdir", "tee", "touch", "truncate"}
version_only_commands = {"mkfs.ext4", "mkfs.xfs", "mount", "umount", "fusermount", "fusermount3"}
version_args = {"--version", "-V", "-v", "-h", "--help"}


def risk_level_for(status, blocks):
    if blocks and status != "present":
        return "blocking"
    if status in {"unsupported-locally", "available-on-worker"}:
        return "advisory"
    return "satisfied"


def lane_impact_for(name, status, blocks):
    if blocks and status != "present":
        return "blocks_permissioned_real_xfstests"
    if name == "rch_ci_worker_identity" and status == "unsupported-locally":
        return "release_evidence_requires_worker"
    return "none"


def safe_probe_argv(argv):
    if not isinstance(argv, list) or not argv:
        return False
    command = pathlib.Path(str(argv[0])).name
    args = [str(arg) for arg in argv[1:]]
    if command in package_manager_commands or command in persistent_mutation_commands:
        return False
    if command in version_only_commands:
        return bool(args) and all(arg in version_args for arg in args)
    return True

if not manifest_path.exists():
    print(f"missing preflight manifest: {manifest_path}")
    sys.exit(1)

try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"invalid preflight manifest JSON: {exc}")
    sys.exit(1)

created_at = manifest.get("created_at")
try:
    created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
except ValueError:
    print(f"invalid preflight created_at: {created_at}")
    sys.exit(1)
age = (datetime.now(timezone.utc) - created).total_seconds()
if age > max_age_secs:
    print(f"stale preflight manifest: age_secs={age:.0f} max_age_secs={max_age_secs}")
    sys.exit(1)

prereqs = manifest.get("prerequisites")
if not isinstance(prereqs, list):
    print("preflight manifest prerequisites must be a list")
    sys.exit(1)
names = {row.get("name") for row in prereqs if isinstance(row, dict)}
missing_names = sorted(required - names)
if missing_names:
    print(f"preflight manifest missing prerequisite probes: {', '.join(missing_names)}")
    sys.exit(1)

safety = manifest.get("remediation_safety")
if not isinstance(safety, dict):
    print("preflight manifest missing remediation_safety")
    sys.exit(1)
if safety.get("side_effect_policy") != side_effect_policy:
    print("preflight manifest has unsupported side-effect policy")
    sys.exit(1)
for field in [
    "runner_executes_remediation",
    "auto_install",
    "mounts_or_unmounts",
    "creates_persistent_paths",
]:
    if safety.get(field) is not False:
        print(f"preflight remediation_safety {field} must be false")
        sys.exit(1)
if safety.get("requires_fresh_follow_up_probe") is not True:
    print("preflight remediation_safety must require a fresh follow-up probe")
    sys.exit(1)

blocking = manifest.get("blocking_prerequisites", [])
if manifest.get("verdict") != "pass" or blocking:
    blocking_text = ", ".join(blocking) if isinstance(blocking, list) else str(blocking)
    print(f"preflight verdict={manifest.get('verdict')} blocking={blocking_text}")
    sys.exit(1)

for row in prereqs:
    if not isinstance(row, dict):
        print("preflight prerequisite row must be an object")
        sys.exit(1)
    name = str(row.get("name"))
    status = str(row.get("status"))
    blocks = bool(row.get("blocks_real_xfstests"))
    if blocks and status != "present":
        print(f"blocking prerequisite is not present: {name} status={status}")
        sys.exit(1)
    if row.get("risk_level") not in risk_values:
        print(f"preflight prerequisite {name} has invalid risk_level")
        sys.exit(1)
    if row.get("risk_level") != risk_level_for(status, blocks):
        print(f"preflight prerequisite {name} has inconsistent risk_level")
        sys.exit(1)
    if row.get("authoritative_lane_impact") not in lane_impacts:
        print(f"preflight prerequisite {name} has invalid authoritative_lane_impact")
        sys.exit(1)
    if row.get("authoritative_lane_impact") != lane_impact_for(name, status, blocks):
        print(f"preflight prerequisite {name} has inconsistent authoritative_lane_impact")
        sys.exit(1)
    if row.get("side_effect_policy") != side_effect_policy:
        print(f"preflight prerequisite {name} has unsupported side-effect policy")
        sys.exit(1)
    safe = row.get("safe_remediation")
    if not isinstance(safe, dict) or safe.get("automation") != "manual_only":
        print(f"preflight prerequisite {name} missing manual-only remediation contract")
        sys.exit(1)
    for field in [
        "runner_executes_remediation",
        "auto_install",
        "mounts_or_unmounts",
        "creates_persistent_paths",
    ]:
        if safe.get(field) is not False:
            print(f"preflight prerequisite {name} safe_remediation {field} must be false")
            sys.exit(1)
    if not str(row.get("remediation_text_id", "")).startswith("xfstests-preflight-"):
        print(f"preflight prerequisite {name} missing remediation_text_id")
        sys.exit(1)
    if not row.get("reproduction_command"):
        print(f"preflight prerequisite {name} missing reproduction_command")
        sys.exit(1)
    for probe in row.get("probes", []):
        if isinstance(probe, dict) and not safe_probe_argv(probe.get("argv")):
            print(f"preflight prerequisite {name} has mutating probe argv: {probe.get('argv')}")
            sys.exit(1)

print("preflight passed")
PY
)"; then
        skip_or_fail "xfstests prerequisite proof unavailable for product baseline: $preflight_reason"
    fi

    e2e_log "Preflight manifest accepted: $XFSTESTS_PREFLIGHT_JSON ($preflight_reason)"
}

load_test_list() {
    local list_path="$1"
    local kind="$2"
    local -n output_ref="$3"

    if [[ ! -f "$list_path" ]]; then
        e2e_fail "Test list not found: $list_path"
    fi

    mapfile -t output_ref < <(awk '{
        line = $0
        sub(/#.*/, "", line)
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line != "") print line
    }' "$list_path")

    if [[ ${#output_ref[@]} -eq 0 ]]; then
        e2e_fail "Test list is empty: $list_path"
    fi

    local test_id
    for test_id in "${output_ref[@]}"; do
        if [[ ! "$test_id" =~ ^${kind}/[0-9]{3}$ ]]; then
            e2e_fail "Invalid test id '$test_id' in $list_path (expected ${kind}/NNN)"
        fi
    done
}

build_selection() {
    local -a raw_selection=()
    case "$XFSTESTS_FILTER" in
        all)
            raw_selection=("${GENERIC_TESTS[@]}" "${EXT4_TESTS[@]}" "${BTRFS_TESTS[@]}")
            ;;
        generic)
            raw_selection=("${GENERIC_TESTS[@]}")
            ;;
        ext4)
            raw_selection=("${EXT4_TESTS[@]}")
            ;;
        btrfs)
            raw_selection=("${BTRFS_TESTS[@]}")
            ;;
        *)
            e2e_fail "Invalid XFSTESTS_FILTER='$XFSTESTS_FILTER' (expected all|generic|ext4|btrfs)"
            ;;
    esac

    declare -A seen=()
    local test_id
    for test_id in "${raw_selection[@]}"; do
        if [[ -z "${seen[$test_id]+x}" ]]; then
            seen[$test_id]=1
            SELECTED_TESTS+=("$test_id")
        fi
    done

    if [[ ${#SELECTED_TESTS[@]} -eq 0 ]]; then
        e2e_fail "No tests selected after applying filter '$XFSTESTS_FILTER'"
    fi
}

verify_tests_exist() {
    local -a missing=()
    local test_id
    for test_id in "${SELECTED_TESTS[@]}"; do
        if [[ ! -f "$XFSTESTS_DIR/tests/$test_id" ]]; then
            missing+=("$test_id")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        e2e_log "Missing tests in $XFSTESTS_DIR/tests:"
        printf '%s\n' "${missing[@]}" | while IFS= read -r line; do
            e2e_log "  $line"
        done
        e2e_fail "Selected xfstests ids missing from xfstests checkout"
    fi
}

generate_results_from_check_log() {
    local check_rc="$1"
    LAST_CHECK_RC="$check_rc"

    if harness_supports_xfstests_report; then
        local -a harness_args=(
            xfstests-report
            --selected "$SELECTED_FILE"
            --check-log "$CHECK_LOG"
            --results-json "$RESULTS_JSON"
            --junit-xml "$JUNIT_FILE"
            --check-rc "$check_rc"
            --dry-run "$XFSTESTS_DRY_RUN"
            --allowlist-json "$XFSTESTS_ALLOWLIST_JSON"
        )
        if [[ -n "$XFSTESTS_BASELINE_JSON" ]]; then
            harness_args+=(--baseline-json "$XFSTESTS_BASELINE_JSON")
        fi
        "$FFS_HARNESS_BIN" "${harness_args[@]}"
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        e2e_log "python3 not found; writing fallback not_run result artifacts"
        write_uniform_results "not_run" "python3 unavailable; unable to parse check output"
        return 0
    fi

    python3 - "$SELECTED_FILE" "$CHECK_LOG" "$RESULTS_JSON" "$JUNIT_FILE" "$check_rc" "$XFSTESTS_DRY_RUN" <<'PY'
import json
import pathlib
import re
import sys
import xml.sax.saxutils

selected_file = pathlib.Path(sys.argv[1])
check_log = pathlib.Path(sys.argv[2])
results_json = pathlib.Path(sys.argv[3])
junit_xml = pathlib.Path(sys.argv[4])
check_rc = int(sys.argv[5])
dry_run = int(sys.argv[6])

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
status = {tid: "not_run" for tid in selected}
seen = set()
rank = {"not_run": 1, "planned": 1, "skipped": 2, "passed": 3, "failed": 4}

def line_mentions_test_id(line: str, test_id: str) -> bool:
    return any(part == test_id for part in line.split())

if check_log.exists():
    for line in check_log.read_text(encoding="utf-8", errors="replace").splitlines():
        low = line.lower()
        for tid in selected:
            if not line_mentions_test_id(line, tid):
                continue
            candidate = None
            if "not run" in low or "notrun" in low:
                candidate = "not_run"
            elif "skipped" in low:
                candidate = "skipped"
            elif re.search(r"\b(fail|failed|error)\b", low):
                candidate = "failed"
            elif re.search(r"\b(pass|passed|ok|success)\b", low):
                candidate = "passed"
            if candidate and rank[candidate] >= rank[status[tid]]:
                seen.add(tid)
                status[tid] = candidate

if check_rc == 0 and dry_run == 0:
    for tid, current in status.items():
        if current == "not_run" and tid not in seen:
            status[tid] = "passed"

tests = [{"id": tid, "status": status[tid]} for tid in selected]
counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0, "planned": 0}
for rec in tests:
    key = rec["status"]
    counts[key] = counts.get(key, 0) + 1

total = len(selected)
pass_rate = (counts["passed"] / total) if total else 0.0

payload = {
    "source": "check-log",
    "check_rc": check_rc,
    "dry_run": dry_run,
    "total": total,
    "passed": counts["passed"],
    "failed": counts["failed"],
    "skipped": counts["skipped"],
    "not_run": counts["not_run"],
    "planned": counts["planned"],
    "pass_rate": pass_rate,
    "tests": tests,
}
results_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with junit_xml.open("w", encoding="utf-8") as fh:
    failures = counts["failed"]
    skipped = counts["skipped"] + counts["not_run"] + counts["planned"]
    fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fh.write(f'<testsuite name="ffs_xfstests_e2e" tests="{total}" failures="{failures}" skipped="{skipped}">\n')
    for rec in tests:
        tid = xml.sax.saxutils.escape(rec["id"], {'"': "&quot;", "'": "&apos;"})
        test_status = rec["status"]
        fh.write(f'  <testcase name="{tid}" time="0.000">')
        if test_status == "failed":
            fh.write('<failure message="xfstests failure">xfstests failure</failure>')
        elif test_status in {"skipped", "not_run", "planned"}:
            msg = xml.sax.saxutils.escape(test_status, {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<skipped message="{msg}"/>')
        fh.write("</testcase>\n")
    fh.write("</testsuite>\n")
PY
}

enforce_regression_guard() {
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        e2e_log "Skipping regression guard in dry-run mode"
        return 0
    fi

    if [[ ! -f "$XFSTESTS_REGRESSION_GUARD_JSON" ]]; then
        e2e_log "Regression guard file not found; skipping guard: $XFSTESTS_REGRESSION_GUARD_JSON"
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        if [[ "$XFSTESTS_STRICT" == "1" ]]; then
            e2e_fail "python3 is required to enforce xfstests regression guard in strict mode"
        fi
        e2e_log "python3 not found; skipping regression guard"
        return 0
    fi

    if ! python3 - "$RESULTS_JSON" "$XFSTESTS_REGRESSION_GUARD_JSON" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
guard_path = pathlib.Path(sys.argv[2])
results = json.loads(results_path.read_text(encoding="utf-8"))
guard = json.loads(guard_path.read_text(encoding="utf-8"))

status_by_test = {rec.get("id"): rec.get("status") for rec in results.get("tests", [])}
passed = int(results.get("passed", 0))
pass_rate = float(results.get("pass_rate", 0.0))

must_pass = [t for t in guard.get("must_pass", []) if isinstance(t, str)]
min_pass_count = int(guard.get("min_pass_count", 0))
min_pass_rate = float(guard.get("min_pass_rate", 0.0))

failures = []
for tid in must_pass:
    if status_by_test.get(tid) != "passed":
        failures.append(f"must-pass test did not pass: {tid} (status={status_by_test.get(tid)})")

if passed < min_pass_count:
    failures.append(f"passed={passed} below min_pass_count={min_pass_count}")
if pass_rate < min_pass_rate:
    failures.append(f"pass_rate={pass_rate:.4f} below min_pass_rate={min_pass_rate:.4f}")

if failures:
    print("xfstests regression guard failures:", file=sys.stderr)
    for item in failures:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)
PY
    then
        e2e_fail "xfstests regression guard failed"
    fi
}

run_xfstests_subset() {
    local -a check_args=()
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        check_args+=("-n")
    fi
    check_args+=("${SELECTED_TESTS[@]}")

    e2e_log "Running xfstests command from $XFSTESTS_DIR:"
    e2e_log "  ./check ${check_args[*]}"

    local rc=0
    (cd "$XFSTESTS_DIR" && ./check "${check_args[@]}") >"$CHECK_LOG" 2>&1 || rc=$?
    generate_results_from_check_log "$rc"

    if [[ $rc -ne 0 ]]; then
        if grep -qiE "not found or executable|must be run as root|Permission denied" "$CHECK_LOG"; then
            skip_or_fail "xfstests prerequisites unavailable for execution (see $CHECK_LOG)"
        fi
        e2e_log "xfstests check failed; tailing log:"
        e2e_run tail -n 120 "$CHECK_LOG" || true
        e2e_fail "xfstests check failed with exit code $rc"
    fi

    enforce_regression_guard
    e2e_log "xfstests check completed successfully"
}

e2e_step "Load curated xfstests subsets"
load_test_list "$XFSTESTS_GENERIC_LIST" "generic" GENERIC_TESTS
load_test_list "$XFSTESTS_EXT4_LIST" "ext4" EXT4_TESTS
load_test_list "$XFSTESTS_BTRFS_LIST" "btrfs" BTRFS_TESTS
build_selection

printf '%s\n' "${SELECTED_TESTS[@]}" >"$SELECTED_FILE"
e2e_log "Selected tests written to: $SELECTED_FILE"
e2e_log "Selected test count: ${#SELECTED_TESTS[@]}"
write_policy_plan
e2e_log "Policy plan written to: $POLICY_PLAN_JSON"
e2e_log "Policy report written to: $POLICY_REPORT_MD"

resolve_xfstests_dir
EFFECTIVE_MODE="$XFSTESTS_MODE"
if [[ "$EFFECTIVE_MODE" == "auto" ]]; then
    if [[ -n "$XFSTESTS_DIR" ]] && [[ -x "$XFSTESTS_DIR/check" ]]; then
        EFFECTIVE_MODE="run"
    else
        EFFECTIVE_MODE="plan"
    fi
fi

if [[ "$EFFECTIVE_MODE" == "plan" ]]; then
    e2e_step "Plan mode"
    if harness_supports_xfstests_report; then
        "$FFS_HARNESS_BIN" xfstests-report \
            --selected "$SELECTED_FILE" \
            --results-json "$RESULTS_JSON" \
            --junit-xml "$JUNIT_FILE" \
            --allowlist-json "$XFSTESTS_ALLOWLIST_JSON" \
            --uniform-status planned \
            --uniform-note "subset materialized; execution not requested"
    else
        write_uniform_results "planned" "subset materialized; execution not requested"
    fi
    write_summary "planned" "$EFFECTIVE_MODE" "subset materialized; execution not requested" "null"
    e2e_log "Plan summary: $SUMMARY_JSON"
    e2e_pass
    exit 0
fi

if [[ "$EFFECTIVE_MODE" != "run" ]]; then
    e2e_fail "Invalid XFSTESTS_MODE='$XFSTESTS_MODE' (expected auto|plan|run)"
fi

ensure_xfstests_preflight

if [[ -z "$XFSTESTS_DIR" ]]; then
    skip_or_fail "XFSTESTS_DIR is not set and no default xfstests checkout was found"
fi
if [[ ! -x "$XFSTESTS_DIR/check" ]]; then
    skip_or_fail "xfstests check runner not found at $XFSTESTS_DIR/check"
fi

e2e_step "Run xfstests subset"
e2e_log "XFSTESTS_DIR: $XFSTESTS_DIR"
e2e_log "XFSTESTS_DRY_RUN: $XFSTESTS_DRY_RUN"
verify_tests_exist
run_xfstests_subset

write_summary "passed" "$EFFECTIVE_MODE" "xfstests subset check completed" "$LAST_CHECK_RC"
e2e_log "Run summary: $SUMMARY_JSON"
e2e_pass
exit 0
