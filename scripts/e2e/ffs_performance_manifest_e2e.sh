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
BAD_CLAIM_JSON="$E2E_LOG_DIR/performance_manifest_bad_claim_policy.json"
BAD_STATS_JSON="$E2E_LOG_DIR/performance_manifest_bad_statistical_summary.json"
BAD_AUTHORITATIVE_JSON="$E2E_LOG_DIR/performance_manifest_bad_authoritative_claim.json"
BAD_RAW="$E2E_LOG_DIR/performance_manifest_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/performance_manifest_unit_tests.log"
MOUNT_PROBE_JSON="$E2E_LOG_DIR/mount_benchmark_probe_input_error.json"
MOUNT_PROBE_RAW="$E2E_LOG_DIR/mount_benchmark_probe_input_error.raw"
MOUNT_PENDING_BASELINE_JSON="$REPO_ROOT/benchmarks/baselines/history/20260503-bd-rchk5-3-mount-warm-pending.json"
MOUNT_PENDING_PROBE_JSON="$REPO_ROOT/baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-pending/ffs_cli_mount_cold_probe_report.json"

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
required_classes = {
    "pass",
    "warn",
    "fail",
    "noisy",
    "stale",
    "missing",
    "missing_baseline",
    "environment_mismatch",
    "budget_exceeded",
    "instrumentation_overhead_exceeded",
    "degraded_but_accepted",
    "blocked",
}
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
        "claim_tier_before",
        "claim_tier_after",
        "evidence_authority",
        "baseline_id",
        "baseline_artifact_hash",
        "current_artifact_id",
        "current_artifact_hash",
        "environment_fingerprint",
        "environment_matches_claim_lane",
        "metric_unit",
        "observed_value",
        "threshold",
        "freshness_window_days",
        "overhead_budget",
        "runtime_seconds",
        "memory_mib",
        "instrumentation_overhead_percent",
        "statistical_summary",
        "noise_decision",
        "stale_decision",
        "budget_decision",
        "overhead_decision",
        "comparison_verdict",
        "public_claim_state",
        "release_claim_effect",
        "docs_wording_id",
        "output_path",
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
    if row["comparison_verdict"] in {
        "missing_baseline",
        "environment_mismatch",
        "budget_exceeded",
        "instrumentation_overhead_exceeded",
    } and row["public_claim_state"] not in {"unknown", "experimental"}:
        raise SystemExit(f"budget/evidence failure overclaims public state: {row}")
    if row["claim_tier_after"] in {"measured_authoritative", "regression_free"}:
        if row["evidence_authority"] != "authoritative":
            raise SystemExit(f"authoritative claim lacks authoritative evidence: {row}")
        if row["stale_decision"] != "fresh":
            raise SystemExit(f"authoritative claim is stale: {row}")
        if row["budget_decision"] != "budget_within_limit":
            raise SystemExit(f"authoritative claim exceeded runtime/memory budget: {row}")
        if row["overhead_decision"] != "instrumentation_overhead_within_limit":
            raise SystemExit(f"authoritative claim exceeded instrumentation budget: {row}")
if not any(
    row["fixture_id"] == "fixture_pass_core"
    and row["claim_tier_after"] == "regression_free"
    for row in report["fixture_evidence_reports"]
):
    raise SystemExit("missing regression-free claim mapping")
if not any(
    row["comparison_verdict"] == "degraded_but_accepted"
    and row["claim_tier_after"] == "degraded_but_accepted"
    for row in report["fixture_evidence_reports"]
):
    raise SystemExit("missing degraded-but-accepted claim mapping")
if not any(
    row["comparison_verdict"] == "blocked"
    and row["claim_tier_after"] == "blocked"
    for row in report["fixture_evidence_reports"]
):
    raise SystemExit("missing blocked claim mapping")
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

e2e_step "Scenario 3b: mounted benchmark probe emits structured failure artifacts"
set +e
scripts/mount_benchmark_probe.sh \
    --bin "$E2E_TEMP_DIR/missing-ffs-cli" \
    --image "$E2E_TEMP_DIR/missing.ext4" \
    --mount-root "$E2E_TEMP_DIR/mount-benchmark" \
    --mode warm \
    --out-json "$MOUNT_PROBE_JSON" >"$MOUNT_PROBE_RAW" 2>&1
MOUNT_PROBE_RC=$?
set -e

if python3 - "$MOUNT_PROBE_JSON" "$MOUNT_PROBE_RC" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
rc = int(sys.argv[2])

if rc != 2:
    raise SystemExit(f"expected input-error exit 2, got {rc}")
if report["schema_version"] != 1:
    raise SystemExit("wrong schema_version")
if report["probe_id"] != "mount_benchmark_probe":
    raise SystemExit("wrong probe_id")
if report["outcome"] != "error" or report["classification"] != "input_error":
    raise SystemExit(f"wrong outcome/classification: {report}")
if report["mode"] != "warm":
    raise SystemExit("mode was not preserved")
if report["kernel_fuse_mode"] != "permissioned_required":
    raise SystemExit("missing FUSE lane classification")
if "fuse" not in report["required_capabilities"]:
    raise SystemExit("missing FUSE required capability")
if report["mount_options"]["writeback_cache"] != "disabled":
    raise SystemExit("writeback-cache policy missing")
if report["attempts"]:
    raise SystemExit("input validation error should not create mount attempts")
if "ffs-cli binary is not executable" not in report["reason"]:
    raise SystemExit("input-error reason was not preserved")
PY
then
    scenario_result "performance_mount_probe_structured_failure" "PASS" "mount benchmark probe writes structured input-error artifact"
else
    cat "$MOUNT_PROBE_RAW"
    scenario_result "performance_mount_probe_structured_failure" "FAIL" "mount benchmark probe structured failure contract failed"
fi

e2e_step "Scenario 3c: mounted benchmark pending artifact preserves probe evidence"
if python3 - "$MOUNT_PENDING_BASELINE_JSON" "$MOUNT_PENDING_PROBE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

baseline_path = pathlib.Path(sys.argv[1])
probe_path = pathlib.Path(sys.argv[2])
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
probe = json.loads(probe_path.read_text(encoding="utf-8"))

coverage = baseline["measurement_coverage"]
if coverage["measured_count"] != 0 or coverage["pending_count"] != 1:
    raise SystemExit(f"unexpected coverage: {coverage}")
measurements = baseline["measurements"]
if len(measurements) != 1:
    raise SystemExit(f"expected one targeted pending row, got {len(measurements)}")
row = measurements[0]
if row["operation"] != "mount_warm" or row["status"] != "pending":
    raise SystemExit(f"wrong pending row: {row}")
expected_probe = "baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-pending/ffs_cli_mount_cold_probe_report.json"
if row["source_json"] != expected_probe or row["probe_report_json"] != expected_probe:
    raise SystemExit(f"pending row lost probe path: {row}")
if "Permission denied" not in row["reason"]:
    raise SystemExit("pending reason did not preserve FUSE denial")
if probe["classification"] != "host_capability_skip":
    raise SystemExit(f"wrong probe classification: {probe['classification']}")
if probe["outcome"] != "fail":
    raise SystemExit(f"wrong probe outcome: {probe['outcome']}")
if probe["kernel_fuse_mode"] != "permissioned_required":
    raise SystemExit("missing permissioned FUSE lane")
attempts = probe["attempts"]
if len(attempts) != 1 or attempts[0]["cleanup_status"] != "unmounted":
    raise SystemExit(f"probe did not preserve cleanup evidence: {attempts}")
PY
then
    scenario_result "performance_mount_pending_artifact_preserves_probe" "PASS" "targeted mount_warm pending row points at structured FUSE denial report"
else
    scenario_result "performance_mount_pending_artifact_preserves_probe" "FAIL" "checked-in mount pending artifact lost probe evidence"
fi

e2e_step "Scenario 4: invalid manifest variants fail closed"
python3 - "$MANIFEST_JSON" "$BAD_CAP_JSON" "$BAD_ENV_JSON" "$BAD_ARTIFACT_JSON" "$BAD_UNIT_JSON" "$BAD_TARGET_JSON" "$BAD_RAW_LOG_JSON" "$BAD_FIXTURE_JSON" "$BAD_CLAIM_JSON" "$BAD_STATS_JSON" "$BAD_AUTHORITATIVE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

(
    source,
    bad_cap,
    bad_env,
    bad_artifact,
    bad_unit,
    bad_target,
    bad_raw_log,
    bad_fixture,
    bad_claim,
    bad_stats,
    bad_authoritative,
) = map(pathlib.Path, sys.argv[1:])
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

claim = json.loads(json.dumps(base))
claim["workloads"][0]["claim_policy"]["clean_claim_tier"] = "measured_authoritative"
claim["workloads"][0]["claim_policy"]["release_claim_effect"] = "local_claim"
bad_claim.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n", encoding="utf-8")

stats = json.loads(json.dumps(base))
del stats["fixture_evidence"][0]["statistical_summary"]
bad_stats.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")

authoritative = json.loads(json.dumps(base))
authoritative["fixture_evidence"][0]["evidence_authority"] = "local"
bad_authoritative.write_text(json.dumps(authoritative, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_CAP_JSON" "$BAD_ENV_JSON" "$BAD_ARTIFACT_JSON" "$BAD_UNIT_JSON" "$BAD_TARGET_JSON" "$BAD_RAW_LOG_JSON" "$BAD_FIXTURE_JSON" "$BAD_CLAIM_JSON" "$BAD_STATS_JSON" "$BAD_AUTHORITATIVE_JSON"; do
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
    scenario_result "performance_manifest_invalid_variants_rejected" "PASS" "bad capability/env/artifact/unit/claim/budget variants rejected"
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
