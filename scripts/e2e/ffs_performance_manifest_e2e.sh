#!/usr/bin/env bash
# ffs_performance_manifest_e2e.sh - dry-run gate for bd-rchk5.1.
#
# Validates the performance baseline manifest without running heavyweight
# benchmarks, expands commands, and emits a sample shared QA artifact manifest.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_performance_manifest}"
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

e2e_init "ffs_performance_manifest"

MANIFEST_JSON="$REPO_ROOT/benchmarks/performance_baseline_manifest.json"
REPORT_JSON="$E2E_LOG_DIR/performance_manifest_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/performance_sample_artifact_manifest.json"
VALIDATE_RAW="$E2E_LOG_DIR/performance_manifest_validate.raw"
BAD_CAP_JSON="$E2E_LOG_DIR/performance_manifest_bad_capability.json"
BAD_ENV_JSON="$E2E_LOG_DIR/performance_manifest_bad_environment.json"
BAD_ARTIFACT_JSON="$E2E_LOG_DIR/performance_manifest_bad_artifact.json"
BAD_UNIT_JSON="$E2E_LOG_DIR/performance_manifest_bad_unit.json"
BAD_TARGET_JSON="$E2E_LOG_DIR/performance_manifest_bad_target_dir.json"
BAD_RAW_LOG_JSON="$E2E_LOG_DIR/performance_manifest_bad_raw_log.json"
BAD_FIXTURE_JSON="$E2E_LOG_DIR/performance_manifest_bad_fixture.json"
BAD_RAW="$E2E_LOG_DIR/performance_manifest_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/performance_manifest_unit_tests.log"

e2e_step "Scenario 1: performance manifest module and CLI are wired"
if grep -q "pub mod performance_baseline_manifest" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-performance-baseline-manifest" crates/ffs-harness/src/main.rs; then
    scenario_result "performance_manifest_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "performance_manifest_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in manifest validates and emits shared QA artifact"
if cargo run --quiet -p ffs-harness -- validate-performance-baseline-manifest \
    --manifest "$MANIFEST_JSON" \
    --artifact-root "artifacts/performance/dry-run" \
    --out "$REPORT_JSON" \
    --artifact-out "$ARTIFACT_JSON" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "performance_manifest_validates" "PASS" "checked-in performance manifest accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "performance_manifest_validates" "FAIL" "checked-in performance manifest rejected"
fi

e2e_step "Scenario 3: command expansion and artifact mapping are dry-run only"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))

if not report["valid"]:
    raise SystemExit("manifest report invalid")
if report["workload_count"] < 8:
    raise SystemExit("expected representative workload coverage")
if report["missing_required_workload_kinds"]:
    raise SystemExit(f"missing workload kinds: {report['missing_required_workload_kinds']}")
required_classes = {"pass", "warn", "fail", "noisy", "stale", "missing"}
classes = set(report["fixture_classification_counts"])
if not required_classes <= classes:
    raise SystemExit(f"missing fixture classifications: {required_classes - classes}")
commands = {row["workload_id"]: row["command"] for row in report["command_expansions"]}
if "{profile}" in "\n".join(commands.values()):
    raise SystemExit("unexpanded profile placeholder")
if not all(row["target_dir"] for row in report["command_expansions"]):
    raise SystemExit("missing target_dir expansion")
if not any("cargo bench" in command for command in commands.values()):
    raise SystemExit("no cargo bench command expansion")
if not any("mount_benchmark_probe.sh" in command for command in commands.values()):
    raise SystemExit("no mounted FUSE dry-run command expansion")
if not any(
    row["workload_kind"] == "long_campaign_observation"
    and row["skip_semantics"] == "long_campaign_deferred"
    for row in report["command_expansions"]
):
    raise SystemExit("no long-campaign observation workload with deferred skip semantics")
for row in report["fixture_evidence_reports"]:
    for field in (
        "workload_id",
        "baseline_id",
        "current_artifact_id",
        "current_artifact_hash",
        "environment_fingerprint",
        "metric_unit",
        "observed_value",
        "threshold",
        "noise_decision",
        "stale_decision",
        "comparison_verdict",
        "public_claim_state",
        "raw_stdout_path",
        "raw_stderr_path",
        "reproduction_command",
    ):
        if field not in row:
            raise SystemExit(f"fixture evidence row missing {field}")
    if row["comparison_verdict"] in {"fail", "noisy", "stale", "missing"}:
        if row["public_claim_state"] not in {"unknown", "experimental"}:
            raise SystemExit(f"quarantined row overclaims public state: {row}")
        if not row["follow_up_bead"].startswith("bd-"):
            raise SystemExit(f"quarantined row missing follow-up bead: {row}")
if artifact["gate_id"] != "performance_baseline_manifest":
    raise SystemExit("wrong artifact gate_id")
if artifact.get("bead_id") != "bd-rchk5.1":
    raise SystemExit("missing bead id")
categories = {entry["category"] for entry in artifact["artifacts"]}
if "benchmark_baseline" not in categories or "benchmark_report" not in categories:
    raise SystemExit(f"missing benchmark artifact categories: {categories}")
PY
then
    scenario_result "performance_manifest_dry_run_expands" "PASS" "commands and shared QA artifact verified"
else
    scenario_result "performance_manifest_dry_run_expands" "FAIL" "dry-run expansion contract failed"
fi

e2e_step "Scenario 4: invalid manifest variants fail closed"
python3 - "$MANIFEST_JSON" "$BAD_CAP_JSON" "$BAD_ENV_JSON" "$BAD_ARTIFACT_JSON" "$BAD_UNIT_JSON" "$BAD_TARGET_JSON" "$BAD_RAW_LOG_JSON" "$BAD_FIXTURE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

source, bad_cap, bad_env, bad_artifact, bad_unit, bad_target, bad_raw_log, bad_fixture = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

cap = json.loads(json.dumps(base))
cap["workloads"][0]["required_capabilities"].append("unknown_accelerator")
bad_cap.write_text(json.dumps(cap, indent=2, sort_keys=True) + "\n", encoding="utf-8")

env = json.loads(json.dumps(base))
env["required_environment_fields"] = [f for f in env["required_environment_fields"] if f != "git_sha"]
bad_env.write_text(json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8")

artifact = json.loads(json.dumps(base))
artifact["workloads"][0]["output_artifact"]["aggregate_key"] = "median_ns"
artifact["workloads"][0]["output_artifact"]["path_template"] = "results/static.json"
bad_artifact.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")

unit = json.loads(json.dumps(base))
unit["workloads"][0]["metric_unit"] = "invalid_unit"
bad_unit.write_text(json.dumps(unit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

target = json.loads(json.dumps(base))
target["workloads"][0]["target_dir_template"] = "static-target"
bad_target.write_text(json.dumps(target, indent=2, sort_keys=True) + "\n", encoding="utf-8")

raw_log = json.loads(json.dumps(base))
raw_log["workloads"][0]["required_raw_logs"] = ["stdout"]
bad_raw_log.write_text(json.dumps(raw_log, indent=2, sort_keys=True) + "\n", encoding="utf-8")

fixture = json.loads(json.dumps(base))
for workload in fixture["workloads"]:
    if workload["workload_id"] == "mvcc_conflict_detection_rate":
        workload["quarantine_policy"]["follow_up_bead"] = ""
bad_fixture.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_CAP_JSON" "$BAD_ENV_JSON" "$BAD_ARTIFACT_JSON" "$BAD_UNIT_JSON" "$BAD_TARGET_JSON" "$BAD_RAW_LOG_JSON" "$BAD_FIXTURE_JSON"; do
    if cargo run --quiet -p ffs-harness -- validate-performance-baseline-manifest \
        --manifest "$bad" \
        --out "$E2E_LOG_DIR/$(basename "$bad" .json).report.json" >"$BAD_RAW" 2>&1; then
        e2e_log "Unexpectedly accepted invalid manifest: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "performance baseline manifest validation failed\\|invalid performance manifest JSON" "$BAD_RAW"; then
        e2e_log "Invalid manifest failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "performance_manifest_invalid_variants_rejected" "PASS" "bad capability/env/artifact/unit rejected"
else
    scenario_result "performance_manifest_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: performance manifest unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib performance_baseline_manifest -- --nocapture >"$UNIT_LOG" 2>&1; then
    cat "$UNIT_LOG"
    scenario_result "performance_manifest_unit_tests" "PASS" "performance manifest unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "performance_manifest_unit_tests" "FAIL" "performance manifest unit tests failed"
fi

e2e_log "Performance manifest: $MANIFEST_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Performance manifest scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Performance manifest scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
