#!/usr/bin/env bash
# ffs_operational_readiness_report_e2e.sh - smoke gate for bd-rchk0.4.3.
#
# Builds a small readiness artifact directory, runs the one-command aggregator,
# and checks that JSON plus Markdown output preserve operational links while
# separating product failures from environment blockers.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_operational_readiness_report}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

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

e2e_init "ffs_operational_readiness_report"

FIXTURE_DIR="$E2E_LOG_DIR/readiness_fixture"
REPORT_JSON="$E2E_LOG_DIR/operational_readiness_report.json"
REPORT_MD="$E2E_LOG_DIR/operational_readiness_report.md"
UNIT_LOG="$(mktemp)"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod operational_readiness_report" crates/ffs-harness/src/lib.rs \
    && grep -q "operational-readiness-report" crates/ffs-harness/src/main.rs; then
    scenario_result "readiness_report_wired" "PASS" "module and CLI command exported"
else
    scenario_result "readiness_report_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: fixture artifacts cover readiness workstreams"
if python3 - "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)

def touch(rel):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{rel}\n", encoding="utf-8")

for rel in [
    "run/stdout.log",
    "run/stderr.log",
    "xfstests/results.json",
    "xfstests_generic_subset/stdout.log",
    "xfstests_generic_subset/stderr.log",
    "fuse/capability.json",
    "fuse_capability_probe/stdout.log",
    "fuse_capability_probe/stderr.log",
    "mounted/ext4_rw.json",
    "mounted_ext4_rw/stdout.log",
    "mounted_ext4_rw/stderr.log",
    "repair/policy.json",
    "repair_policy_refusal/stdout.log",
    "repair_policy_refusal/stderr.log",
    "writeback/crash.json",
    "writeback_crash_matrix/stdout.log",
    "writeback_crash_matrix/stderr.log",
    "fuzz/repair.json",
    "fuzz_repair_smoke/stdout.log",
    "fuzz_repair_smoke/stderr.log",
    "perf/baseline.json",
    "perf_baseline_run/stdout.log",
    "perf_baseline_run/stderr.log",
    "proof/bundle.json",
    "proof_bundle_stale/stdout.log",
    "proof_bundle_stale/stderr.log",
    "release/unsupported.json",
    "release_gate_unsupported/stdout.log",
    "release_gate_unsupported/stderr.log",
    "legacy/run.log",
]:
    touch(rel)

cases = [
    ("xfstests_generic_subset", "xfstests/results.json", "PASS", "pass", None, None, None),
    ("fuse_capability_probe", "fuse/capability.json", "SKIP", "skip", "fuse_permission_skip", "fuse_permission_denied", "rerun with /dev/fuse access"),
    ("mounted_ext4_rw", "mounted/ext4_rw.json", "PASS", "pass", None, None, None),
    ("repair_policy_refusal", "repair/policy.json", "FAIL", "fail", "product_failure", None, "open repair policy bead"),
    ("writeback_crash_matrix", "writeback/crash.json", "FAIL", "fail", "product_failure", None, "open writeback crash bead"),
    ("fuzz_repair_smoke", "fuzz/repair.json", "FAIL", "error", "worker_dependency_missing", None, "run on fuzz-capable worker"),
    ("perf_baseline_run", "perf/baseline.json", "SKIP", "error", "host_environment_failure", "worker_dependency_missing", "run on performance worker"),
    ("proof_bundle_stale", "proof/bundle.json", "FAIL", "fail", "stale_tracker_tooling_failure", None, "refresh proof bundle before release"),
    ("release_gate_unsupported", "release/unsupported.json", "SKIP", "skip", "unsupported_v1_scope", "unsupported_v1_scope", "document explicit V1 non-goal"),
]

manifest = {
    "schema_version": 1,
    "run_id": "fixture-operational",
    "created_at": "2026-05-03T00:00:00Z",
    "gate_id": "operational_readiness",
    "bead_id": "bd-rchk0.4.3",
    "git_context": {"commit": "fixture-head", "branch": "main", "clean": True},
    "environment": {
        "hostname": "fixture-host",
        "cpu_model": "fixture-cpu",
        "cpu_count": 64,
        "memory_gib": 256,
        "kernel": "Linux 6.17.0",
        "rustc_version": "rustc fixture",
        "cargo_version": "cargo fixture",
    },
    "scenarios": {},
    "operational_context": {
        "command_line": ["scripts/e2e/fixture.sh"],
        "worker": {"host": "fixture-host", "worker_id": "fixture-worker"},
        "fuse_capability": "permission_denied",
        "stdout_path": "run/stdout.log",
        "stderr_path": "run/stderr.log",
    },
    "operational_scenarios": {},
    "artifacts": [
        {"path": "run/stdout.log", "category": "raw_log", "content_type": "text/plain", "size_bytes": 12, "redacted": False, "metadata": {}},
        {"path": "run/stderr.log", "category": "raw_log", "content_type": "text/plain", "size_bytes": 12, "redacted": False, "metadata": {}},
    ],
    "verdict": "FAIL",
    "duration_secs": 7.0,
}

for scenario_id, artifact, result, classification, error_class, skip_reason, remediation in cases:
    manifest["scenarios"][scenario_id] = {
        "scenario_id": scenario_id,
        "outcome": result,
        "detail": remediation,
        "duration_secs": 1.0,
    }
    manifest["artifacts"].extend([
        {"path": artifact, "category": "summary_report", "content_type": "application/json", "size_bytes": 128, "redacted": False, "metadata": {}},
        {"path": f"{scenario_id}/stdout.log", "category": "raw_log", "content_type": "text/plain", "size_bytes": 64, "redacted": False, "metadata": {}},
        {"path": f"{scenario_id}/stderr.log", "category": "raw_log", "content_type": "text/plain", "size_bytes": 64, "redacted": False, "metadata": {}},
    ])
    record = {
        "scenario_id": scenario_id,
        "filesystem": "not_applicable",
        "mount_options": [],
        "expected_outcome": result,
        "actual_outcome": result,
        "classification": classification,
        "exit_status": 0 if result == "PASS" else 1,
        "stdout_path": f"{scenario_id}/stdout.log",
        "stderr_path": f"{scenario_id}/stderr.log",
        "ledger_paths": [],
        "artifact_refs": [artifact],
        "cleanup_status": "clean",
    }
    if error_class:
        record["error_class"] = error_class
    if skip_reason:
        record["skip_reason"] = skip_reason
    if remediation:
        record["remediation_hint"] = remediation
    manifest["operational_scenarios"][scenario_id] = record

(root / "operational_manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

legacy = {
    "schema_version": 1,
    "runner_contract_version": 1,
    "gate_id": "legacy_fuse_gate",
    "run_id": "legacy-old",
    "created_at": "2026-05-03T00:00:00Z",
    "git_context": {"commit": "old-head", "branch": "main", "clean": True},
    "scenarios": [
        {
            "scenario_id": "fuse_capability_probe",
            "outcome": "FAIL",
            "detail": "FUSE permission denied on worker",
        }
    ],
    "verdict": "FAIL",
    "duration_secs": 4,
    "log_file": "legacy/run.log",
}
(root / "legacy_result.json").write_text(
    json.dumps(legacy, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
then
    scenario_result "readiness_report_fixture" "PASS" "fixture manifests and logs created"
else
    scenario_result "readiness_report_fixture" "FAIL" "fixture generation failed"
fi

e2e_step "Scenario 3: JSON report aggregates outcomes and diagnostics"
if "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- operational-readiness-report \
    --artifacts "$FIXTURE_DIR" \
    --current-git-sha fixture-head \
    --out "$REPORT_JSON"; then
    if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
required_workstreams = {
    "xfstests",
    "fuse_lane",
    "mounted_scenario_matrix",
    "repair_policy",
    "writeback_cache",
    "fuzz_smoke",
    "performance",
    "proof_bundle",
    "release_gate",
}
missing = sorted(required_workstreams - set(data["workstreams"]))
if missing:
    raise SystemExit(f"missing workstreams: {missing}")
if data["totals"]["product_failures"] < 2:
    raise SystemExit("expected product failures")
if data["totals"]["environment_blockers"] < 3:
    raise SystemExit("expected environment blockers")
if "fuse_capability_probe" not in data["duplicate_scenario_ids"]:
    raise SystemExit("expected duplicate fuse scenario id")
if len(data["stale_git_shas"]) != 1:
    raise SystemExit("expected one stale git sha")
if data["missing_log_paths"]:
    raise SystemExit(f"unexpected missing logs: {data['missing_log_paths']}")
if data["required_workstreams_missing"]:
    raise SystemExit(f"missing required workstreams: {data['required_workstreams_missing']}")
if not data["contract_failed"]:
    raise SystemExit("stale legacy artifact should fail the readiness contract")
taxonomy = {row["scenario_id"]: row["taxonomy_class"] for row in data["scenarios"]}
expected_taxonomy = {
    "repair_policy_refusal": "product_failure",
    "fuse_capability_probe": "host_capability_skip",
    "proof_bundle_stale": "stale_artifact",
    "release_gate_unsupported": "unsupported_by_scope",
}
for scenario_id, expected in expected_taxonomy.items():
    if taxonomy.get(scenario_id) != expected:
        raise SystemExit(f"{scenario_id} taxonomy {taxonomy.get(scenario_id)} != {expected}")
if not all(row.get("reproduction_command") for row in data["scenarios"]):
    raise SystemExit("every row must preserve a reproduction command")
PY
    then
        scenario_result "readiness_report_json" "PASS" "JSON report aggregates workstreams"
    else
        scenario_result "readiness_report_json" "FAIL" "JSON report validation failed"
    fi
else
    scenario_result "readiness_report_json" "FAIL" "report command failed"
fi

e2e_step "Scenario 4: Markdown report preserves raw artifact links"
if "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- operational-readiness-report \
    --artifacts "$FIXTURE_DIR" \
    --current-git-sha fixture-head \
    --format markdown \
    --out "$REPORT_MD" \
    && grep -q "artifact \`mounted/ext4_rw.json\`" "$REPORT_MD" \
    && grep -q "Diagnostics: duplicate_scenarios=1 stale_git_shas=1 missing_logs=0" "$REPORT_MD" \
    && grep -q "Contract: failed=true missing_workstreams=0 violations=0" "$REPORT_MD"; then
    scenario_result "readiness_report_markdown" "PASS" "Markdown preserves links and diagnostics"
else
    scenario_result "readiness_report_markdown" "FAIL" "Markdown report validation failed"
fi

e2e_step "Scenario 5: unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness operational_readiness_report \
    2>"$UNIT_LOG" | tee -a "$UNIT_LOG"; then
    TESTS_RUN=$(grep -c "test operational_readiness_report::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 4 ]]; then
        scenario_result "readiness_report_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "readiness_report_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "readiness_report_unit_tests" "FAIL" "unit tests failed"
fi

rm -f "$UNIT_LOG"

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_operational_readiness_report completed"
else
    e2e_fail "ffs_operational_readiness_report failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
