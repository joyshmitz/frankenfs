#!/usr/bin/env bash
# ffs_soak_canary_campaign_e2e.sh - dry-run gate for bd-rchk0.5.9.
#
# Validates the soak/canary campaign manifest, expands bounded dry-run command
# plans, and proves flake/failure classifications preserve repro artifacts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_soak_canary_campaign}"
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

e2e_init "ffs_soak_canary_campaign"

MANIFEST_JSON="$REPO_ROOT/benchmarks/soak_canary_campaign_manifest.json"
REPORT_JSON="$E2E_LOG_DIR/soak_canary_campaign_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/soak_canary_sample_artifact_manifest.json"
SUMMARY_MD="$E2E_LOG_DIR/soak_canary_campaign_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/soak_canary_validate.raw"
BAD_DURATION_JSON="$E2E_LOG_DIR/soak_canary_bad_duration.json"
BAD_LOG_JSON="$E2E_LOG_DIR/soak_canary_bad_log_field.json"
BAD_FLAKE_JSON="$E2E_LOG_DIR/soak_canary_bad_flake.json"
BAD_RESOURCE_JSON="$E2E_LOG_DIR/soak_canary_bad_resource.json"
BAD_COMMAND_JSON="$E2E_LOG_DIR/soak_canary_bad_command.json"
BAD_CONSUMER_JSON="$E2E_LOG_DIR/soak_canary_bad_consumer.json"
BAD_RAW="$E2E_LOG_DIR/soak_canary_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/soak_canary_unit_tests.log"

e2e_step "Scenario 1: soak/canary campaign module and CLI are wired"
if grep -q "pub mod soak_canary_campaign" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-soak-canary-campaigns" crates/ffs-harness/src/main.rs; then
    scenario_result "soak_canary_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "soak_canary_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in manifest validates and emits shared QA artifacts"
if cargo run --quiet -p ffs-harness -- validate-soak-canary-campaigns \
    --manifest "$MANIFEST_JSON" \
    --artifact-root "artifacts/soak/dry-run" \
    --out "$REPORT_JSON" \
    --artifact-out "$ARTIFACT_JSON" \
    --summary-out "$SUMMARY_MD" >"$VALIDATE_RAW" 2>&1; then
    scenario_result "soak_canary_manifest_validates" "PASS" "checked-in campaign manifest accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "soak_canary_manifest_validates" "FAIL" "checked-in campaign manifest rejected"
fi

e2e_step "Scenario 3: smoke dry-run covers pass/fail/skip/error/flake and consumers"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["profile_count"] != 4:
    raise SystemExit("expected smoke/nightly/stress/canary profiles")
if report["workload_count"] < 7:
    raise SystemExit("expected representative workload coverage")
if sorted(report["long_profile_ids"]) != ["canary", "nightly", "stress"]:
    raise SystemExit(f"unexpected long profiles: {report['long_profile_ids']}")
for field in ["kernel", "fuse_capability", "toolchain", "git_sha", "resource_usage", "cleanup_status", "reproduction_command"]:
    if field not in report["required_environment_fields"] and field not in report["required_log_fields"]:
        raise SystemExit(f"missing required field {field}")
for consumer in ["operator_proof_bundle", "release_gate_evaluator", "operational_readiness_report"]:
    if consumer not in report["artifact_consumers"]:
        raise SystemExit(f"missing consumer {consumer}")
for outcome in ["pass", "fail", "skip", "error", "flake"]:
    if report["sample_outcome_counts"].get(outcome) != 1:
        raise SystemExit(f"missing sample outcome {outcome}")
commands = [row["command"] for row in report["command_expansions"]]
if not any("--profile smoke" in command or "--campaign-profile smoke" in command for command in commands):
    raise SystemExit("no smoke command expansion")
if not any("FFS_CAMPAIGN_SEED=7001" in command for command in commands):
    raise SystemExit("artifact aggregation seed was not expanded")
if "{seed}" in "\n".join(commands) or "{profile}" in "\n".join(commands):
    raise SystemExit("unexpanded template placeholder")
if artifact["gate_id"] != "soak_canary_campaigns":
    raise SystemExit("wrong artifact gate")
if artifact.get("bead_id") != "bd-rchk0.5.9":
    raise SystemExit("wrong bead id")
metadata = [entry.get("metadata", {}) for entry in artifact["artifacts"]]
if not any(row.get("proof_bundle_lane") == "soak_canary_campaigns" for row in metadata):
    raise SystemExit("missing proof-bundle lane metadata")
if not any(row.get("release_gate_feature") == "operational.soak_canary" for row in metadata):
    raise SystemExit("missing release-gate metadata")
if "HEARTBEAT|" not in summary or "bd-t21em" not in summary:
    raise SystemExit("summary missing heartbeat or follow-up bead")
PY
then
    scenario_result "soak_canary_dry_run_artifacts" "PASS" "dry-run report, artifact, and summary verified"
else
    scenario_result "soak_canary_dry_run_artifacts" "FAIL" "dry-run artifact contract failed"
fi

e2e_step "Scenario 4: invalid campaign variants fail closed"
python3 - "$MANIFEST_JSON" "$BAD_DURATION_JSON" "$BAD_LOG_JSON" "$BAD_FLAKE_JSON" "$BAD_RESOURCE_JSON" "$BAD_COMMAND_JSON" "$BAD_CONSUMER_JSON" <<'PY'
import json
import pathlib
import sys

source, bad_duration, bad_log, bad_flake, bad_resource, bad_command, bad_consumer = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

duration = json.loads(json.dumps(base))
duration["profiles"][0]["duration_seconds"] = 0
bad_duration.write_text(json.dumps(duration, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log = json.loads(json.dumps(base))
log["required_log_fields"] = [field for field in log["required_log_fields"] if field != "reproduction_command"]
bad_log.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")

flake = json.loads(json.dumps(base))
flake["workloads"][0]["failure_threshold"]["max_flakes"] = 1
flake["workloads"][0]["failure_threshold"]["follow_up_bead"] = ""
flake["workloads"][0]["failure_threshold"]["preserve_repro_artifacts"] = False
bad_flake.write_text(json.dumps(flake, indent=2, sort_keys=True) + "\n", encoding="utf-8")

resource = json.loads(json.dumps(base))
resource["profiles"][1]["resource_limits"]["max_wall_seconds"] = 1
bad_resource.write_text(json.dumps(resource, indent=2, sort_keys=True) + "\n", encoding="utf-8")

command = json.loads(json.dumps(base))
command["workloads"][0]["command_template"] = "scripts/e2e/ffs_fuse_production.sh --profile {profile}"
bad_command.write_text(json.dumps(command, indent=2, sort_keys=True) + "\n", encoding="utf-8")

consumer = json.loads(json.dumps(base))
consumer["artifact_consumers"] = ["operator_proof_bundle"]
bad_consumer.write_text(json.dumps(consumer, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_DURATION_JSON" "$BAD_LOG_JSON" "$BAD_FLAKE_JSON" "$BAD_RESOURCE_JSON" "$BAD_COMMAND_JSON" "$BAD_CONSUMER_JSON"; do
    if cargo run --quiet -p ffs-harness -- validate-soak-canary-campaigns \
        --manifest "$bad" \
        --out "$E2E_LOG_DIR/$(basename "$bad" .json).report.json" >"$BAD_RAW" 2>&1; then
        e2e_log "Unexpectedly accepted invalid campaign manifest: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "soak/canary campaign manifest validation failed\\|invalid soak/canary manifest JSON" "$BAD_RAW"; then
        e2e_log "Invalid campaign manifest failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "soak_canary_invalid_variants_rejected" "PASS" "bad duration/log/flake/resource/command/consumer rejected"
else
    scenario_result "soak_canary_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: threshold evaluations preserve failure and flake reproduction data"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
evaluations = report["failure_evaluations"]
outcomes = {row["outcome"] for row in evaluations}
if not {"pass", "fail", "skip", "error", "flake"}.issubset(outcomes):
    raise SystemExit(f"missing outcomes: {outcomes}")
for row in evaluations:
    if row["outcome"] in {"fail", "error", "flake"}:
        if not row["repro_artifacts_required"]:
            raise SystemExit(f"missing repro preservation: {row}")
        if not row["follow_up_bead"]:
            raise SystemExit(f"missing follow-up bead: {row}")
PY
then
    scenario_result "soak_canary_thresholds_preserve_repro" "PASS" "fail/error/flake samples require repro and follow-up"
else
    scenario_result "soak_canary_thresholds_preserve_repro" "FAIL" "threshold classification contract failed"
fi

e2e_step "Scenario 6: soak/canary campaign unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib soak_canary_campaign -- --nocapture >"$UNIT_LOG" 2>&1; then
    cat "$UNIT_LOG"
    scenario_result "soak_canary_unit_tests" "PASS" "soak/canary unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "soak_canary_unit_tests" "FAIL" "soak/canary unit tests failed"
fi

e2e_log "Soak/canary manifest: $MANIFEST_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Soak/canary campaign scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Soak/canary campaign scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
