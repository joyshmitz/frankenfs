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
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_SOAK_CANARY_CAMPAIGN_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_SOAK_CANARY_CAMPAIGN_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_SOAK_CANARY_CAMPAIGN_SKIP_SELF_CHECK:-0}"

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
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

extract_json_object() {
    local input_path="$1"
    local output_path="$2"
    local object_index="${3:-0}"
    python3 - "$input_path" "$output_path" "$object_index" <<'PY'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
target_index = int(sys.argv[3])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
seen = 0
pos = 0
while pos < len(text):
    idx = text.find("{", pos)
    if idx < 0:
        break
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        pos = idx + 1
        continue
    if seen == target_index:
        dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
        raise SystemExit(0)
    seen += 1
    pos = idx + end
raise SystemExit(f"JSON object {target_index} not found in {source}")
PY
}

extract_markdown_report() {
    local input_path="$1"
    local output_path="$2"
    python3 - "$input_path" "$output_path" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Soak/Canary Campaign Report")
if start < 0:
    raise SystemExit(f"soak/canary markdown report not found in {source}")
end_marker = "\nsoak/canary campaign summary written:"
end = text.find(end_marker, start)
if end < 0:
    end = len(text)
dest.write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_soak_canary_campaign"

RCH_OUTPUT_DIR="$REPO_ROOT/artifacts/rch/soak_canary_campaign/$(basename "$E2E_LOG_DIR")"
mkdir -p "$RCH_OUTPUT_DIR"

MANIFEST_JSON="$REPO_ROOT/benchmarks/soak_canary_campaign_manifest.json"
REPORT_JSON="$E2E_LOG_DIR/soak_canary_campaign_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/soak_canary_sample_artifact_manifest.json"
SUMMARY_MD="$E2E_LOG_DIR/soak_canary_campaign_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/soak_canary_validate.raw"
ARTIFACT_RAW="$E2E_LOG_DIR/soak_canary_artifact.raw"
SUMMARY_RAW="$E2E_LOG_DIR/soak_canary_summary.raw"
BAD_DURATION_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_duration.json"
BAD_LOG_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_log_field.json"
BAD_FLAKE_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_flake.json"
BAD_RESOURCE_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_resource.json"
BAD_COMMAND_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_command.json"
BAD_CONSUMER_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_consumer.json"
BAD_POLICY_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_policy.json"
BAD_QUARANTINE_JSON="$RCH_OUTPUT_DIR/soak_canary_bad_quarantine.json"
BAD_RAW="$E2E_LOG_DIR/soak_canary_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/soak_canary_unit_tests.log"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_SOAK_CANARY_CAMPAIGN_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

root_classes = [
    ("product_regression", "bd-t21em", ""),
    ("host_capability_skip", "bd-rchk3", ""),
    ("infrastructure_error", "bd-rchk0.385", ""),
    ("timeout", "bd-timeout-fixture", ""),
    ("resource_exhaustion", "bd-resource-fixture", ""),
    ("known_quarantined_flake", "bd-flake-fixture", "soak_known_fuse_mount_retry_jitter"),
    ("new_recurring_flake", "bd-new-flake-fixture", ""),
    ("inconclusive", "bd-inconclusive-fixture", ""),
]
root_cause_samples = [
    {
        "sample_id": f"root_cause_fixture_{index}",
        "classification": classification,
        "follow_up_bead": bead,
        "quarantine_id": quarantine_id,
        "repro_artifacts": [f"artifacts/soak/dry-run/root-cause-{index}.json"],
    }
    for index, (classification, bead, quarantine_id) in enumerate(root_classes)
]
failure_evaluations = [
    {"outcome": "pass", "repro_artifacts_required": False, "follow_up_bead": ""},
    {"outcome": "fail", "repro_artifacts_required": True, "follow_up_bead": "bd-t21em"},
    {"outcome": "skip", "repro_artifacts_required": False, "follow_up_bead": ""},
    {"outcome": "error", "repro_artifacts_required": True, "follow_up_bead": "bd-rchk0.385"},
    {"outcome": "flake", "repro_artifacts_required": True, "follow_up_bead": "bd-flake-fixture"},
]
report = {
    "valid": True,
    "errors": [],
    "profile_count": 4,
    "workload_count": 7,
    "long_profile_ids": ["canary", "nightly", "stress"],
    "stop_condition_precedence": [
        "resource_budget_exceeded",
        "timeout",
        "infrastructure_error",
        "failure_threshold_exceeded",
        "flake_threshold_exceeded",
        "host_capability_skip",
        "stale_baseline",
        "inconclusive",
        "completed",
    ],
    "root_cause_samples": root_cause_samples,
    "required_environment_fields": [
        "kernel",
        "fuse_capability",
        "toolchain",
        "git_sha",
    ],
    "required_log_fields": [
        "resource_usage",
        "cleanup_status",
        "reproduction_command",
    ],
    "artifact_consumers": [
        "operator_proof_bundle",
        "release_gate_evaluator",
        "operational_readiness_report",
    ],
    "sample_outcome_counts": {
        "pass": 1,
        "fail": 1,
        "skip": 1,
        "error": 1,
        "flake": 1,
    },
    "command_expansions": [
        {
            "profile_id": "smoke",
            "workload_id": "smoke_fixture",
            "command": "FFS_CAMPAIGN_SEED=7001 scripts/e2e/ffs_smoke.sh --campaign-profile smoke --artifact-root artifacts/soak/dry-run",
        },
        {
            "profile_id": "canary",
            "workload_id": "canary_fixture",
            "command": "FFS_CAMPAIGN_SEED=7001 scripts/e2e/ffs_readiness_lab_contracts_e2e.sh --profile canary",
        },
    ],
    "failure_evaluations": failure_evaluations,
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_sample_artifact_manifest() {
    cat <<'JSON'
{
  "schema_version": 1,
  "gate_id": "soak_canary_campaigns",
  "bead_id": "bd-rchk0.5.9",
  "artifacts": [
    {
      "category": "campaign_report",
      "path": "artifacts/soak/dry-run/report.json",
      "metadata": {
        "proof_bundle_lane": "soak_canary_campaigns"
      }
    },
    {
      "category": "release_gate_summary",
      "path": "artifacts/soak/dry-run/release-gate.json",
      "metadata": {
        "release_gate_feature": "operational.soak_canary"
      }
    },
    {
      "category": "root_cause_sample",
      "path": "artifacts/soak/dry-run/root-cause-resource.json",
      "metadata": {
        "classification": "resource_exhaustion"
      }
    }
  ]
}
JSON
}

emit_markdown_summary() {
    cat <<'MD'
# Soak/Canary Campaign Report

HEARTBEAT|profile=smoke|seed=7001|outcome=pass

- follow-up: bd-t21em
- root causes: product_regression, resource_exhaustion, known_quarantined_flake
MD
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown soak/canary fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib soak_canary_campaign"*)
        printf '%s\n' \
            "test soak_canary_campaign::tests::checked_in_manifest_validates ... ok" \
            "test soak_canary_campaign::tests::artifact_manifest_shape ... ok" \
            "test soak_canary_campaign::tests::invalid_campaign_variants_fail_closed ... ok"
        exit 0
        ;;
    *"soak_canary_bad_"*)
        echo "error: soak/canary campaign manifest validation failed: fixture invalid campaign" >&2
        exit 1
        ;;
    *"--artifact-out"*)
        emit_valid_report
        emit_sample_artifact_manifest
        exit 0
        ;;
    *"--summary-out"*)
        emit_markdown_summary
        exit 0
        ;;
    *)
        emit_valid_report
        exit 0
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
    local child_log="$E2E_LOG_DIR/soak_canary_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_SOAK_CANARY_CAMPAIGN_SELF_CHECK=0 \
        FFS_SOAK_CANARY_CAMPAIGN_SKIP_SELF_CHECK=1 \
        FFS_SOAK_CANARY_CAMPAIGN_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_soak_canary_campaign_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic soak/canary wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path artifact_path summary_path unit_log
    stub_path="$E2E_LOG_DIR/rch-soak-canary-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/soak_canary_campaign_report.json"
    artifact_path="$(dirname "$result_path")/soak_canary_sample_artifact_manifest.json"
    summary_path="$(dirname "$result_path")/soak_canary_campaign_summary.md"
    unit_log="$(dirname "$result_path")/soak_canary_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$artifact_path" ]] \
        && [[ -f "$summary_path" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "soak_canary_manifest_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "soak_canary_dry_run_artifacts" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "soak_canary_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "soak_canary_thresholds_preserve_repro" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "soak_canary_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .profile_count == 4
            and .workload_count >= 7
            and ([.root_cause_samples[].classification] | unique | length) >= 8
            and .sample_outcome_counts.pass == 1
            and .sample_outcome_counts.fail == 1
            and .sample_outcome_counts.skip == 1
            and .sample_outcome_counts.error == 1
            and .sample_outcome_counts.flake == 1
            and ([.failure_evaluations[] | select((.outcome == "fail" or .outcome == "error" or .outcome == "flake") and .repro_artifacts_required and (.follow_up_bead | startswith("bd-")))] | length) == 3
        ' "$report_path" >/dev/null \
        && jq -e '
            .gate_id == "soak_canary_campaigns"
            and .bead_id == "bd-rchk0.5.9"
            and ([.artifacts[].metadata.proof_bundle_lane] | index("soak_canary_campaigns") != null)
            and ([.artifacts[].metadata.release_gate_feature] | index("operational.soak_canary") != null)
            and ([.artifacts[].metadata.classification] | index("resource_exhaustion") != null)
        ' "$artifact_path" >/dev/null \
        && grep -q "HEARTBEAT|" "$summary_path" \
        && grep -q "bd-t21em" "$summary_path" \
        && grep -q "soak_canary_campaign::tests::checked_in_manifest_validates" "$unit_log"; then
        scenario_result "soak_canary_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} artifact=${artifact_path}"
    else
        scenario_result "soak_canary_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "soak/canary complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "soak_canary_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "soak_canary_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "soak/canary local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Scenario 1: soak/canary campaign module and CLI are wired"
if grep -q "pub mod soak_canary_campaign" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-soak-canary-campaigns" crates/ffs-harness/src/main.rs; then
    scenario_result "soak_canary_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "soak_canary_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in manifest validates and emits shared QA artifacts"
if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- validate-soak-canary-campaigns \
    --manifest "$MANIFEST_JSON" \
    --artifact-root "artifacts/soak/dry-run" \
    --out /dev/stdout \
    && extract_json_object "$VALIDATE_RAW" "$REPORT_JSON" \
    && run_rch_capture "$ARTIFACT_RAW" cargo run --quiet -p ffs-harness -- validate-soak-canary-campaigns \
        --manifest "$MANIFEST_JSON" \
        --artifact-root "artifacts/soak/dry-run" \
        --artifact-out /dev/stdout \
    && extract_json_object "$ARTIFACT_RAW" "$ARTIFACT_JSON" 1 \
    && run_rch_capture "$SUMMARY_RAW" cargo run --quiet -p ffs-harness -- validate-soak-canary-campaigns \
        --manifest "$MANIFEST_JSON" \
        --artifact-root "artifacts/soak/dry-run" \
        --summary-out /dev/stdout \
    && extract_markdown_report "$SUMMARY_RAW" "$SUMMARY_MD"; then
    scenario_result "soak_canary_manifest_validates" "PASS" "checked-in campaign manifest accepted"
else
    cat "$VALIDATE_RAW"
    [[ -s "$ARTIFACT_RAW" ]] && cat "$ARTIFACT_RAW"
    [[ -s "$SUMMARY_RAW" ]] && cat "$SUMMARY_RAW"
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
required_stop = {
    "resource_budget_exceeded",
    "timeout",
    "infrastructure_error",
    "failure_threshold_exceeded",
    "flake_threshold_exceeded",
    "host_capability_skip",
    "stale_baseline",
    "inconclusive",
    "completed",
}
if set(report["stop_condition_precedence"]) != required_stop:
    raise SystemExit(f"unexpected stop precedence: {report['stop_condition_precedence']}")
required_classes = {
    "product_regression",
    "host_capability_skip",
    "infrastructure_error",
    "timeout",
    "resource_exhaustion",
    "known_quarantined_flake",
    "new_recurring_flake",
    "inconclusive",
}
observed_classes = {row["classification"] for row in report["root_cause_samples"]}
if not required_classes.issubset(observed_classes):
    raise SystemExit(f"missing root-cause classes: {required_classes - observed_classes}")
if not any(row.get("quarantine_id") == "soak_known_fuse_mount_retry_jitter" for row in report["root_cause_samples"]):
    raise SystemExit("known flake quarantine was not surfaced")
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
if not any(row.get("classification") == "resource_exhaustion" for row in metadata):
    raise SystemExit("missing root-cause artifact metadata")
if "HEARTBEAT|" not in summary or "bd-t21em" not in summary:
    raise SystemExit("summary missing heartbeat or follow-up bead")
PY
then
    scenario_result "soak_canary_dry_run_artifacts" "PASS" "dry-run report, artifact, and summary verified"
else
    scenario_result "soak_canary_dry_run_artifacts" "FAIL" "dry-run artifact contract failed"
fi

e2e_step "Scenario 4: invalid campaign variants fail closed"
python3 - "$MANIFEST_JSON" "$BAD_DURATION_JSON" "$BAD_LOG_JSON" "$BAD_FLAKE_JSON" "$BAD_RESOURCE_JSON" "$BAD_COMMAND_JSON" "$BAD_CONSUMER_JSON" "$BAD_POLICY_JSON" "$BAD_QUARANTINE_JSON" <<'PY'
import json
import pathlib
import sys

source, bad_duration, bad_log, bad_flake, bad_resource, bad_command, bad_consumer, bad_policy, bad_quarantine = map(pathlib.Path, sys.argv[1:])
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

policy = json.loads(json.dumps(base))
policy["classification_policy"]["stale_baseline_max_age_hours"] = 0
policy["classification_policy"]["stop_condition_precedence"] = [
    reason for reason in policy["classification_policy"]["stop_condition_precedence"]
    if reason != "timeout"
]
bad_policy.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

quarantine = json.loads(json.dumps(base))
quarantine["classification_policy"]["known_flake_quarantines"][0]["reproduction_pack"] = ""
bad_quarantine.write_text(json.dumps(quarantine, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_DURATION_JSON" "$BAD_LOG_JSON" "$BAD_FLAKE_JSON" "$BAD_RESOURCE_JSON" "$BAD_COMMAND_JSON" "$BAD_CONSUMER_JSON" "$BAD_POLICY_JSON" "$BAD_QUARANTINE_JSON"; do
    if run_rch_capture "$BAD_RAW" cargo run --quiet -p ffs-harness -- validate-soak-canary-campaigns \
        --manifest "$bad" \
        --out "/tmp/$(basename "$bad" .json).report.json"; then
        e2e_log "Unexpectedly accepted invalid campaign manifest: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "soak/canary campaign manifest validation failed\\|invalid soak/canary manifest JSON" "$BAD_RAW"; then
        e2e_log "Invalid campaign manifest failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "soak_canary_invalid_variants_rejected" "PASS" "bad duration/log/flake/resource/command/consumer/policy/quarantine rejected"
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
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib soak_canary_campaign -- --nocapture; then
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
