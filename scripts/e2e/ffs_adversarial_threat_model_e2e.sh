#!/usr/bin/env bash
# ffs_adversarial_threat_model_e2e.sh - dry-run security gate for bd-rchk0.5.11/bd-0qx9b.
#
# Validates the adversarial-image threat model without mounting hostile images
# or running long fuzz campaigns.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_adversarial_threat_model}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_ADVERSARIAL_THREAT_MODEL_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_ADVERSARIAL_THREAT_MODEL_SKIP_SELF_CHECK:-0}"

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

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("${RCH_BIN:-rch}" queue --json 2>/dev/null || true)"
    if [[ -z "$queue_json" ]]; then
        return 0
    fi
    ids="$(jq -r --arg cmd "$command_text" '
        .data.active_builds[]?
        | select(.project_id | startswith("frankenfs-"))
        | select(.command == $cmd)
        | .id
    ' <<<"$queue_json" || true)"
    for id in $ids; do
        if "${RCH_BIN:-rch}" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

run_rch_capture() {
    local log_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    shift
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-600}"
    : >"$log_path"
    set +e
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" "${RCH_BIN:-rch}" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    set -e
    deadline=$((SECONDS + timeout_secs))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                cancel_matching_rch_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${timeout_secs}|log=${log_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done
    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi
    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
            return 99
        fi
        return 0
    fi
    if grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH artifact retrieval failed after worker-side success; accepting remote exit=0 evidence from $log_path"
        return 0
    fi
    return "$status"
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
for idx, ch in enumerate(text):
    if ch != "{":
        continue
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        continue
    if seen == target_index:
        dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
        raise SystemExit(0)
    seen += 1
raise SystemExit(f"JSON object {target_index} not found in {source}")
PY
}

extract_wording_tsv() {
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
lines = [
    line for line in text.splitlines()
    if "\t" in line and "docs alone cannot promote" in line
]
if not lines:
    raise SystemExit(f"no generated wording TSV row found in {source}")
dest.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_adversarial_threat_model"

MODEL_JSON="$REPO_ROOT/security/adversarial_image_threat_model.json"
REPORT_JSON="$E2E_LOG_DIR/adversarial_threat_model_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/adversarial_threat_model_artifact_manifest.json"
WORDING_TSV="$E2E_LOG_DIR/adversarial_threat_model_wording.tsv"
VALIDATE_RAW="$E2E_LOG_DIR/adversarial_threat_model_validate.raw"
ARTIFACT_RAW="$E2E_LOG_DIR/adversarial_threat_model_artifact.raw"
WORDING_RAW="$E2E_LOG_DIR/adversarial_threat_model_wording.raw"
BAD_TRAVERSAL_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_traversal.json"
BAD_REVIEW_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_review.json"
BAD_LOG_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_log.json"
BAD_LIMIT_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_limit.json"
BAD_OPERATOR_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_operator.json"
BAD_CONTROL_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_control.json"
BAD_COUNTER_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_counter.json"
BAD_CLEANUP_JSON="$E2E_LOG_DIR/adversarial_threat_model_bad_cleanup.json"
BAD_RAW="$E2E_LOG_DIR/adversarial_threat_model_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/adversarial_threat_model_unit_tests.log"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_ADVERSARIAL_THREAT_MODEL_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

required_log_fields = [
    "threat_scenario_id",
    "input_hash",
    "parser_capability",
    "mount_capability",
    "repair_capability",
    "resource_controls",
    "expected_safe_behavior",
    "expected_classification",
    "observed_classification",
    "resource_limits",
    "observed_input_bytes",
    "observed_cpu_ms",
    "observed_wall_ms",
    "observed_memory_mib",
    "observed_disk_bytes",
    "enforcement_point",
    "cleanup_status",
    "artifact_paths",
    "remediation_id",
    "reproduction_command",
]
required_scenarios = [
    ("oversized_metadata_seed_capped", "malformed_image", "capped"),
    ("cyclic_metadata_reference_quarantined", "malformed_image", "quarantined"),
    ("deeply_nested_directory_capped", "resource_exhaustion", "capped"),
    ("huge_xattr_payload_capped", "resource_exhaustion", "capped"),
    ("truncated_repair_ledger_quarantined", "repair_ledger_tamper", "quarantined"),
    ("corrupt_repair_ledger_quarantined", "repair_ledger_tamper", "quarantined"),
    ("hostile_proof_bundle_traversal_refused", "hostile_artifact_path", "host_path_refused"),
    ("hostile_proof_bundle_symlink_refused", "hostile_artifact_path", "host_path_refused"),
    ("excessive_log_output_capped", "missing_host_capability", "capped"),
    ("excessive_artifact_count_capped", "missing_host_capability", "capped"),
    ("timeout_capped", "unsupported_mount_option", "unsupported"),
    ("file_descriptor_exhaustion_capped", "unsafe_operator_command", "mutation_refused"),
]

rows = []
for index, (scenario_id, threat_class, classification) in enumerate(required_scenarios):
    rows.append({
        "scenario_id": scenario_id,
        "threat_class": threat_class,
        "observed_classification": classification,
        "resource_controls": [
            {"resource_class": "wall_time", "limit": 1000 + index},
            {"resource_class": "memory", "limit": 64},
        ],
        "artifact_paths": [
            f"artifacts/security/dry-run/{scenario_id}.json",
            f"artifacts/security/dry-run/{scenario_id}.stderr",
        ],
        "observed_resource_counters": {
            "input_bytes": 128 + index,
            "wall_ms": 10 + index,
            "cpu_ms": 5 + index,
            "memory_mib": 8,
            "disk_bytes": 0,
        },
        "primary_enforcement_point": "adversarial_threat_model_fixture",
        "cleanup_status": "clean",
        "remediation_id": "bd-0qx9b",
        "reproduction_command": "cargo run -p ffs-harness -- validate-adversarial-threat-model",
    })

report = {
    "valid": True,
    "required_log_fields": required_log_fields,
    "evaluated_scenarios": rows,
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_sample_artifact_manifest() {
    cat <<'JSON'
{
  "schema_version": 1,
  "gate_id": "adversarial_threat_model",
  "bead_id": "bd-0qx9b",
  "artifacts": [
    {
      "category": "raw_log",
      "path": "artifacts/security/dry-run/raw.log"
    },
    {
      "category": "repro_pack",
      "path": "artifacts/security/dry-run/repro-pack.json"
    },
    {
      "category": "summary_report",
      "path": "artifacts/security/dry-run/threat-model-report.json"
    }
  ]
}
JSON
}

emit_wording_tsv() {
    printf 'security.adversarial_image\tREADME.md\tdocs alone cannot promote hostile-image readiness without artifact-backed security evidence\n'
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown adversarial threat model fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib adversarial_threat_model"*)
        printf '%s\n' \
            "test adversarial_threat_model::tests::checked_in_model_validates ... ok" \
            "test adversarial_threat_model::tests::artifact_manifest_shape ... ok" \
            "test adversarial_threat_model::tests::invalid_model_variants_fail_closed ... ok"
        exit 0
        ;;
    *"--model-json-env ADVERSARIAL_THREAT_MODEL_JSON"*)
        echo "error: adversarial threat model validation failed: fixture invalid model" >&2
        exit 1
        ;;
    *"--artifact-out"*)
        emit_sample_artifact_manifest
        exit 0
        ;;
    *"--wording-out"*)
        emit_wording_tsv
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
    local child_log="$E2E_LOG_DIR/adversarial_threat_model_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_ADVERSARIAL_THREAT_MODEL_SELF_CHECK=0 \
        FFS_ADVERSARIAL_THREAT_MODEL_SKIP_SELF_CHECK=1 \
        FFS_ADVERSARIAL_THREAT_MODEL_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_adversarial_threat_model_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic adversarial threat model wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path artifact_path wording_path unit_log
    stub_path="$E2E_LOG_DIR/rch-adversarial-threat-model-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/adversarial_threat_model_report.json"
    artifact_path="$(dirname "$result_path")/adversarial_threat_model_artifact_manifest.json"
    wording_path="$(dirname "$result_path")/adversarial_threat_model_wording.tsv"
    unit_log="$(dirname "$result_path")/adversarial_threat_model_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$artifact_path" ]] \
        && [[ -f "$wording_path" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "adversarial_threat_model_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adversarial_threat_model_dry_run_expands" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adversarial_threat_model_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "adversarial_threat_model_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and ([.evaluated_scenarios[].threat_class] | unique | length) >= 7
            and ([.evaluated_scenarios[].scenario_id] | length) >= 12
            and ([.required_log_fields[]] | index("input_hash") != null)
            and ([.required_log_fields[]] | index("cleanup_status") != null)
            and ([.evaluated_scenarios[] | select((.resource_controls | length) > 0 and (.artifact_paths | length) > 0)] | length) == 12
            and ([.evaluated_scenarios[] | select(.observed_resource_counters.input_bytes and .observed_resource_counters.wall_ms)] | length) == 12
        ' "$report_path" >/dev/null \
        && jq -e '
            .gate_id == "adversarial_threat_model"
            and .bead_id == "bd-0qx9b"
            and ([.artifacts[].category] | index("raw_log") != null)
            and ([.artifacts[].category] | index("repro_pack") != null)
            and ([.artifacts[].category] | index("summary_report") != null)
        ' "$artifact_path" >/dev/null \
        && grep -q "docs alone cannot promote" "$wording_path" \
        && grep -q "adversarial_threat_model::tests::checked_in_model_validates" "$unit_log"; then
        scenario_result "adversarial_threat_model_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} artifact=${artifact_path}"
    else
        scenario_result "adversarial_threat_model_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "adversarial threat model complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "adversarial_threat_model_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "adversarial_threat_model_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "adversarial threat model local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Scenario 1: adversarial threat model module and CLI are wired"
if grep -q "pub mod adversarial_threat_model" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-adversarial-threat-model" crates/ffs-harness/src/main.rs; then
    scenario_result "adversarial_threat_model_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "adversarial_threat_model_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in threat model validates and emits artifacts"
if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- validate-adversarial-threat-model \
    --model "$MODEL_JSON" \
    --artifact-root "artifacts/security/dry-run" \
    && extract_json_object "$VALIDATE_RAW" "$REPORT_JSON" \
    && run_rch_capture "$ARTIFACT_RAW" cargo run --quiet -p ffs-harness -- validate-adversarial-threat-model \
        --model "$MODEL_JSON" \
        --artifact-root "artifacts/security/dry-run" \
        --out "/tmp/frankenfs_adversarial_threat_model_report.json" \
        --artifact-out /dev/stdout \
    && extract_json_object "$ARTIFACT_RAW" "$ARTIFACT_JSON" \
    && run_rch_capture "$WORDING_RAW" cargo run --quiet -p ffs-harness -- validate-adversarial-threat-model \
        --model "$MODEL_JSON" \
        --artifact-root "artifacts/security/dry-run" \
        --out "/tmp/frankenfs_adversarial_threat_model_report.json" \
        --wording-out /dev/stdout \
    && extract_wording_tsv "$WORDING_RAW" "$WORDING_TSV"; then
    scenario_result "adversarial_threat_model_validates" "PASS" "checked-in threat model accepted"
else
    cat "$VALIDATE_RAW"
    [[ -s "$ARTIFACT_RAW" ]] && cat "$ARTIFACT_RAW"
    [[ -s "$WORDING_RAW" ]] && cat "$WORDING_RAW"
    scenario_result "adversarial_threat_model_validates" "FAIL" "checked-in threat model rejected"
fi

e2e_step "Scenario 3: dry-run coverage, logs, artifact mapping, and wording are present"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" "$WORDING_TSV" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
wording = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit("threat model report invalid")
required = {
    "malformed_image",
    "hostile_artifact_path",
    "missing_host_capability",
    "resource_exhaustion",
    "repair_ledger_tamper",
    "unsupported_mount_option",
    "unsafe_operator_command",
}
covered = {row["threat_class"] for row in report["evaluated_scenarios"]}
missing = required - covered
if missing:
    raise SystemExit(f"missing threat classes: {sorted(missing)}")
log_fields = set(report["required_log_fields"])
for field in [
    "threat_scenario_id",
    "input_hash",
    "parser_capability",
    "mount_capability",
    "repair_capability",
    "resource_controls",
    "expected_safe_behavior",
    "expected_classification",
    "observed_classification",
    "resource_limits",
    "observed_input_bytes",
    "observed_cpu_ms",
    "observed_wall_ms",
    "observed_memory_mib",
    "observed_disk_bytes",
    "enforcement_point",
    "cleanup_status",
    "artifact_paths",
    "remediation_id",
    "reproduction_command",
]:
    if field not in log_fields:
        raise SystemExit(f"missing log field: {field}")
if artifact["gate_id"] != "adversarial_threat_model":
    raise SystemExit("wrong artifact gate_id")
if artifact.get("bead_id") != "bd-0qx9b":
    raise SystemExit("missing bead id")
categories = {entry["category"] for entry in artifact["artifacts"]}
if "raw_log" not in categories or "repro_pack" not in categories or "summary_report" not in categories:
    raise SystemExit(f"missing security artifact categories: {categories}")
if "docs alone cannot promote" not in wording:
    raise SystemExit("wording does not preserve docs-gated security status")
required_scenarios = {
    "oversized_metadata_seed_capped",
    "cyclic_metadata_reference_quarantined",
    "deeply_nested_directory_capped",
    "huge_xattr_payload_capped",
    "truncated_repair_ledger_quarantined",
    "corrupt_repair_ledger_quarantined",
    "hostile_proof_bundle_traversal_refused",
    "hostile_proof_bundle_symlink_refused",
    "excessive_log_output_capped",
    "excessive_artifact_count_capped",
    "timeout_capped",
    "file_descriptor_exhaustion_capped",
}
scenarios = {row["scenario_id"]: row for row in report["evaluated_scenarios"]}
missing_scenarios = required_scenarios - set(scenarios)
if missing_scenarios:
    raise SystemExit(f"missing bounded hostile scenarios: {sorted(missing_scenarios)}")
safe_classifications = {"rejected", "unsupported", "capped", "quarantined", "mutation_refused", "host_path_refused"}
for scenario_id in required_scenarios:
    row = scenarios[scenario_id]
    if row["observed_classification"] not in safe_classifications:
        raise SystemExit(f"unsafe classification for {scenario_id}: {row['observed_classification']}")
    if not row.get("resource_controls"):
        raise SystemExit(f"missing resource controls for {scenario_id}")
    if not row.get("artifact_paths"):
        raise SystemExit(f"missing artifact paths for {scenario_id}")
    counters = row.get("observed_resource_counters") or {}
    for key in ("input_bytes", "wall_ms"):
        if key not in counters:
            raise SystemExit(f"missing observed counter {key} for {scenario_id}")
    if row.get("primary_enforcement_point") in {None, "", "missing"}:
        raise SystemExit(f"missing enforcement point for {scenario_id}")
PY
then
    scenario_result "adversarial_threat_model_dry_run_expands" "PASS" "coverage, logs, artifacts, containment, and wording verified"
else
    scenario_result "adversarial_threat_model_dry_run_expands" "FAIL" "dry-run threat model contract failed"
fi

e2e_step "Scenario 4: malformed threat model variants fail closed"
python3 - "$MODEL_JSON" "$BAD_TRAVERSAL_JSON" "$BAD_REVIEW_JSON" "$BAD_LOG_JSON" "$BAD_LIMIT_JSON" "$BAD_OPERATOR_JSON" "$BAD_CONTROL_JSON" "$BAD_COUNTER_JSON" "$BAD_CLEANUP_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

source, bad_traversal, bad_review, bad_log, bad_limit, bad_operator, bad_control, bad_counter, bad_cleanup = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

traversal = json.loads(json.dumps(base))
traversal["scenarios"][1]["expected_path_decision"] = "accept_confined"
bad_traversal.write_text(json.dumps(traversal, indent=2, sort_keys=True) + "\n", encoding="utf-8")

review = json.loads(json.dumps(base))
review["scenarios"][0]["review_status"] = "unreviewed"
bad_review.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log = json.loads(json.dumps(base))
log["required_log_fields"] = [field for field in log["required_log_fields"] if field != "input_hash"]
bad_log.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")

limit = json.loads(json.dumps(base))
limit["scenarios"][4]["resource_limits"]["max_wall_ms"] = 0
bad_limit.write_text(json.dumps(limit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

operator = json.loads(json.dumps(base))
operator["scenarios"][-1]["release_gate_effect"] = "follow_up_only"
bad_operator.write_text(json.dumps(operator, indent=2, sort_keys=True) + "\n", encoding="utf-8")

control = json.loads(json.dumps(base))
del control["scenarios"][4]["resource_controls"][0]["resource_class"]
bad_control.write_text(json.dumps(control, indent=2, sort_keys=True) + "\n", encoding="utf-8")

counter = json.loads(json.dumps(base))
counter["scenarios"][4]["observed_resource_counters"]["wall_ms"] = counter["scenarios"][4]["resource_limits"]["max_wall_ms"] + 1
bad_counter.write_text(json.dumps(counter, indent=2, sort_keys=True) + "\n", encoding="utf-8")

cleanup = json.loads(json.dumps(base))
cleanup["scenarios"][5]["cleanup_status"] = "failed"
bad_cleanup.write_text(json.dumps(cleanup, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_TRAVERSAL_JSON" "$BAD_REVIEW_JSON" "$BAD_LOG_JSON" "$BAD_LIMIT_JSON" "$BAD_OPERATOR_JSON" "$BAD_CONTROL_JSON" "$BAD_COUNTER_JSON" "$BAD_CLEANUP_JSON"; do
    bad_payload="$(tr -d '\n' <"$bad")"
    if (
        export ADVERSARIAL_THREAT_MODEL_JSON="$bad_payload"
        export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}ADVERSARIAL_THREAT_MODEL_JSON"
        run_rch_capture "$BAD_RAW" cargo run --quiet -p ffs-harness -- validate-adversarial-threat-model \
            --model-json-env ADVERSARIAL_THREAT_MODEL_JSON \
            --out /dev/stdout
    ); then
        e2e_log "Unexpectedly accepted invalid threat model: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "adversarial threat model validation failed\\|invalid adversarial threat model JSON" "$BAD_RAW"; then
        e2e_log "Invalid threat model failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "adversarial_threat_model_invalid_variants_rejected" "PASS" "bad traversal/review/log/limit/operator/control/counter/cleanup variants rejected"
else
    scenario_result "adversarial_threat_model_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: adversarial threat model unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib adversarial_threat_model -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "adversarial_threat_model_unit_tests" "PASS" "adversarial threat model unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "adversarial_threat_model_unit_tests" "FAIL" "adversarial threat model unit tests failed"
fi

e2e_log "Adversarial threat model: $MODEL_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"
e2e_log "Generated wording: $WORDING_TSV"

if ((FAIL_COUNT == 0)); then
    e2e_log "Adversarial threat model scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Adversarial threat model scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
