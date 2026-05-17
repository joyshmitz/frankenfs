#!/usr/bin/env bash
# ffs_metamorphic_workload_seed_catalog_e2e.sh - dry-run metamorphic seed catalog gate for bd-rchk0.78.
#
# Validates seed metadata and proof-consumer coverage without executing
# permissioned or mutating workload reproduction commands.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_metamorphic_workload_seed_catalog}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_CAPTURE_VISIBILITY="${FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-420}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_SKIP_SELF_CHECK:-0}"

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

extract_report_json() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import json
import re
import sys

raw_path, report_path = sys.argv[1:]
text = open(raw_path, encoding="utf-8", errors="replace").read()
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
text = "\n".join(
    line
    for line in text.splitlines()
    if not line.startswith("error: metamorphic workload seed catalog validation failed:")
) + "\n"
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "catalog_id" in obj and "seed_count" in obj:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("metamorphic workload seed catalog report JSON object not found")
PY
}

extract_markdown_report() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# Metamorphic Workload Seed Catalog")
if start < 0:
    raise SystemExit("metamorphic workload seed catalog markdown not found")
end = text.find("\n[RCH]", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
pathlib.Path(report_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

run_rch_capture() {
    local output_path="$1"
    shift
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

run_cargo_capture() {
    local output_path="$1"
    shift
    run_rch_capture "$output_path" cargo "$@"
}

e2e_init "ffs_metamorphic_workload_seed_catalog"

CATALOG_JSON="$REPO_ROOT/tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json"
RCH_INPUT_DIR="${REPO_ROOT}/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/metamorphic_workload_seed_catalog"
mkdir -p "$RCH_INPUT_DIR"
REPORT_JSON="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_report.json"
SUMMARY_MD="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_validate.raw"
SUMMARY_RAW="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_summary.raw"
UNIT_LOG="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_unit_tests.log"
BAD_PERMISSIONED_JSON="$RCH_INPUT_DIR/metamorphic_bad_permissioned_ack.json"
BAD_PERMISSIONED_RAW="$E2E_LOG_DIR/metamorphic_bad_permissioned_ack.raw"
BAD_NON_PERMISSIONED_LEAK_JSON="$RCH_INPUT_DIR/metamorphic_bad_non_permissioned_permission_leak.json"
BAD_NON_PERMISSIONED_LEAK_RAW="$E2E_LOG_DIR/metamorphic_bad_non_permissioned_permission_leak.raw"
BAD_SOURCE_JSON="$RCH_INPUT_DIR/metamorphic_bad_source_artifact.json"
BAD_SOURCE_RAW="$E2E_LOG_DIR/metamorphic_bad_source_artifact.raw"
BAD_NON_JSON_SOURCE="$RCH_INPUT_DIR/metamorphic_bad_source_artifact.txt"
BAD_NON_JSON_JSON="$RCH_INPUT_DIR/metamorphic_bad_non_json_source.json"
BAD_NON_JSON_RAW="$E2E_LOG_DIR/metamorphic_bad_non_json_source.raw"
BAD_POINTER_JSON="$RCH_INPUT_DIR/metamorphic_bad_source_pointer.json"
BAD_POINTER_RAW="$E2E_LOG_DIR/metamorphic_bad_source_pointer.raw"
BAD_VALUE_JSON="$RCH_INPUT_DIR/metamorphic_bad_source_value.json"
BAD_VALUE_RAW="$E2E_LOG_DIR/metamorphic_bad_source_value.raw"
BAD_INVARIANT_JSON="$RCH_INPUT_DIR/metamorphic_bad_invariant.json"
BAD_INVARIANT_RAW="$E2E_LOG_DIR/metamorphic_bad_invariant.raw"
BAD_INVARIANT_REPORT="$E2E_LOG_DIR/metamorphic_bad_invariant_report.json"
BAD_INVARIANT_REPORT_RAW="$E2E_LOG_DIR/metamorphic_bad_invariant_report.raw"
UNIT_TESTS_OK=0

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

relations = [
    "replay_deterministic",
    "repair_monotonic",
    "failure_classification_stable",
    "tail_latency_order_invariant",
]
modes = ["analysis_only", "dry_run", "permissioned"]
consumers = ["proof_bundle", "release_gate", "swarm_workload_harness", "repair_lab"]
matrix = []
for index in range(7):
    mode = modes[index % len(modes)]
    ack = "FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host" if mode == "permissioned" else ""
    command = "cargo run -p ffs-harness -- validate-metamorphic-workload-seeds"
    if ack:
        command = f"{ack} {command}"
    matrix.append({
        "seed_id": f"metamorphic_fixture_seed_{index:02d}",
        "relation": relations[index % len(relations)],
        "execution_mode": mode,
        "ack_requirement": ack,
        "proof_consumers": [consumers[index % len(consumers)]],
        "invariant": "deterministic replay preserves classified outcome",
        "reproduction_command": command,
        "source_value_pointer": f"/seeds/{index}/seed_value",
        "expected_artifact_fields": ["required", "report_json"],
    })

report = {
    "valid": True,
    "catalog_id": "frankenfs_metamorphic_workload_seed_catalog",
    "seed_count": len(matrix),
    "source_kind_count": 5,
    "source_value_verified_count": len(matrix),
    "relation_counts": {relation: 1 for relation in relations},
    "execution_mode_counts": {mode: 1 for mode in modes},
    "by_proof_consumer": {consumer: 1 for consumer in consumers},
    "coverage_matrix": matrix,
    "errors": [],
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_invalid_invariant_report() {
    python3 - <<'PY'
import json

report = {
    "valid": False,
    "catalog_id": "frankenfs_metamorphic_workload_seed_catalog",
    "seed_count": 7,
    "source_value_verified_count": 7,
    "errors": ["seed invariant must not be empty"],
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_markdown_report() {
    cat <<'MD'
# Metamorphic Workload Seed Catalog

- catalog: `frankenfs_metamorphic_workload_seed_catalog`
- relation: `replay_deterministic`
- execution mode: `permissioned`
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
        echo "unknown metamorphic workload seed catalog fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"test -p ffs-harness --lib metamorphic_workload_seed_catalog"*)
        printf '%s\n' \
            "test rejects_duplicate_seed_ids ... ok" \
            "test rejects_missing_source_artifact ... ok" \
            "test rejects_existing_non_json_source_artifact ... ok" \
            "test source_value_coverage_counts_valid_sources_independent_of_row_errors ... ok" \
            "test rejects_missing_source_value_pointer_target ... ok" \
            "test rejects_mismatched_numeric_source_value ... ok" \
            "test accepts_seed_contained_in_source_command_string ... ok" \
            "test rejects_permissioned_seed_without_ack_requirement ... ok" \
            "test rejects_non_permissioned_seed_with_ack_requirement ... ok" \
            "test rejects_non_permissioned_seed_with_permissioned_reproduction_token ... ok" \
            "test rejects_permissioned_seed_with_malformed_ack_requirement ... ok" \
            "test rejects_permissioned_seed_command_missing_declared_ack ... ok" \
            "test rejects_unknown_relation_type ... ok" \
            "test rejects_seed_without_invariant ... ok" \
            "test rejects_seed_without_existing_proof_consumer ... ok" \
            "test rejects_catalog_with_too_few_source_kinds ... ok"
        exit 0
        ;;
    *"metamorphic_bad_invariant.json"*)
        echo "error: metamorphic workload seed catalog validation failed: invariant must not be empty" >&2
        emit_invalid_invariant_report
        exit 1
        ;;
    *"metamorphic_bad_"*)
        echo "error: metamorphic workload seed catalog validation failed: fixture invalid catalog" >&2
        exit 1
        ;;
    *"--format markdown"*)
        emit_markdown_report
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
    local child_log="$E2E_LOG_DIR/metamorphic_seed_catalog_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_SELF_CHECK=0 \
        FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_SKIP_SELF_CHECK=1 \
        FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_metamorphic_workload_seed_catalog_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic metamorphic workload seed catalog wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path summary_path
    stub_path="$E2E_LOG_DIR/rch-metamorphic-seed-catalog-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/metamorphic_workload_seed_catalog_report.json"
    summary_path="$(dirname "$result_path")/metamorphic_workload_seed_catalog_summary.md"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$summary_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "metamorphic_seed_catalog_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "metamorphic_seed_catalog_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "metamorphic_seed_catalog_permissioned_ack" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "metamorphic_seed_catalog_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "metamorphic_seed_catalog_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .seed_count >= 7
            and .source_kind_count >= 5
            and .source_value_verified_count == .seed_count
            and (.coverage_matrix | length) == .seed_count
            and (.execution_mode_counts.permissioned // 0) > 0
        ' "$report_path" >/dev/null \
        && grep -q "# Metamorphic Workload Seed Catalog" "$summary_path" \
        && grep -q "permissioned" "$summary_path"; then
        scenario_result "metamorphic_seed_catalog_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} summary=${summary_path}"
    else
        scenario_result "metamorphic_seed_catalog_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "metamorphic workload seed catalog complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "metamorphic_seed_catalog_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "metamorphic_seed_catalog_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "metamorphic workload seed catalog local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "metamorphic workload seed catalog wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: metamorphic workload seed catalog module and CLI are wired"
if grep -q "pub mod metamorphic_workload_seed_catalog" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-metamorphic-workload-seeds" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_metamorphic_workload_seed_catalog" scripts/e2e/scenario_catalog.json; then
    scenario_result "metamorphic_seed_catalog_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "metamorphic_seed_catalog_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in metamorphic seed catalog validates"
if run_cargo_capture "$VALIDATE_RAW" run --quiet -p ffs-harness -- \
    validate-metamorphic-workload-seeds \
    --catalog "$CATALOG_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON" \
    && run_cargo_capture "$SUMMARY_RAW" run --quiet -p ffs-harness -- \
        validate-metamorphic-workload-seeds \
        --catalog "$CATALOG_JSON" \
        --format markdown \
    && extract_markdown_report "$SUMMARY_RAW" "$SUMMARY_MD"; then
    scenario_result "metamorphic_seed_catalog_validates" "PASS" "checked-in catalog accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "metamorphic_seed_catalog_validates" "FAIL" "checked-in catalog rejected"
fi

e2e_step "Scenario 3: relation and source coverage are durable"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["seed_count"] < 7:
    raise SystemExit("expected at least seven seed rows")
if report["source_kind_count"] < 5:
    raise SystemExit("expected at least five source kinds")
if report.get("source_value_verified_count") != report["seed_count"]:
    raise SystemExit("not every source value was mechanically verified")
for relation in [
    "replay_deterministic",
    "repair_monotonic",
    "failure_classification_stable",
    "tail_latency_order_invariant",
]:
    if report["relation_counts"].get(relation, 0) == 0:
        raise SystemExit(f"missing relation {relation}")
for mode in ["analysis_only", "dry_run", "permissioned"]:
    if report["execution_mode_counts"].get(mode, 0) == 0:
        raise SystemExit(f"missing execution mode {mode}")
for consumer in ["proof_bundle", "release_gate", "swarm_workload_harness", "repair_lab"]:
    if report["by_proof_consumer"].get(consumer, 0) == 0:
        raise SystemExit(f"missing proof consumer {consumer}")
if len(report["coverage_matrix"]) != report["seed_count"]:
    raise SystemExit("coverage matrix row count does not match seed count")
for row in report["coverage_matrix"]:
    if not row["invariant"].strip():
        raise SystemExit(f"missing invariant: {row['seed_id']}")
    if not row["reproduction_command"].strip():
        raise SystemExit(f"missing reproduction command: {row['seed_id']}")
    if not row.get("source_value_pointer", "").startswith("/"):
        raise SystemExit(f"missing source value pointer: {row['seed_id']}")
    if "required" not in row["expected_artifact_fields"]:
        raise SystemExit(f"missing expected artifact fields: {row['seed_id']}")
PY
then
    scenario_result "metamorphic_seed_catalog_coverage" "PASS" "relations, source kinds, execution modes, and consumers verified"
else
    scenario_result "metamorphic_seed_catalog_coverage" "FAIL" "coverage contract failed"
fi

e2e_step "Scenario 4: permissioned rows carry explicit ack metadata"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
permissioned = [row for row in report["coverage_matrix"] if row["execution_mode"] == "permissioned"]
if not permissioned:
    raise SystemExit("expected at least one permissioned row")
for row in permissioned:
    ack = row.get("ack_requirement")
    if not ack or "=" not in ack:
        raise SystemExit(f"permissioned row missing explicit env ack: {row['seed_id']}")
    command = row["reproduction_command"]
    if ack not in command:
        raise SystemExit(f"permissioned command does not mention ack requirement: {row['seed_id']}")
PY
then
    scenario_result "metamorphic_seed_catalog_permissioned_ack" "PASS" "permissioned rows are metadata-only and ack-gated"
else
    scenario_result "metamorphic_seed_catalog_permissioned_ack" "FAIL" "permissioned ack contract failed"
fi

e2e_step "Scenario 5: invalid catalog variants fail closed"
python3 - "$REPO_ROOT" "$CATALOG_JSON" "$BAD_PERMISSIONED_JSON" "$BAD_NON_PERMISSIONED_LEAK_JSON" "$BAD_SOURCE_JSON" "$BAD_NON_JSON_SOURCE" "$BAD_NON_JSON_JSON" "$BAD_POINTER_JSON" "$BAD_VALUE_JSON" "$BAD_INVARIANT_JSON" <<'PY'
import json
import pathlib
import sys

(
    repo_root,
    catalog_path,
    bad_permissioned_path,
    bad_non_permissioned_leak_path,
    bad_source_path,
    bad_non_json_source_path,
    bad_non_json_path,
    bad_pointer_path,
    bad_value_path,
    bad_invariant_path,
) = map(pathlib.Path, sys.argv[1:])
catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

bad_permissioned = json.loads(json.dumps(catalog))
for row in bad_permissioned["seeds"]:
    if row["execution_mode"] == "permissioned":
        row.pop("ack_requirement", None)
        break
bad_permissioned_path.write_text(json.dumps(bad_permissioned, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_non_permissioned_leak = json.loads(json.dumps(catalog))
bad_non_permissioned_leak["seeds"][0]["ack_requirement"] = "FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host"
bad_non_permissioned_leak["seeds"][0]["reproduction_command"] = (
    "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 "
    + bad_non_permissioned_leak["seeds"][0]["reproduction_command"]
)
bad_non_permissioned_leak_path.write_text(json.dumps(bad_non_permissioned_leak, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_source = json.loads(json.dumps(catalog))
bad_source["seeds"][0]["source_artifact"] = "tests/metamorphic-workload-seeds/missing_source_artifact.json"
bad_source_path.write_text(json.dumps(bad_source, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_non_json_source_path.write_text("seed: 64001\n", encoding="utf-8")
bad_non_json = json.loads(json.dumps(catalog))
bad_non_json["seeds"][0]["source_artifact"] = str(bad_non_json_source_path.relative_to(repo_root))
bad_non_json["seeds"][0]["source_value_pointer"] = "/seed"
bad_non_json_path.write_text(json.dumps(bad_non_json, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_pointer = json.loads(json.dumps(catalog))
bad_pointer["seeds"][0]["source_value_pointer"] = "/scenarios/3/missing_seed_field"
bad_pointer_path.write_text(json.dumps(bad_pointer, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_value = json.loads(json.dumps(catalog))
bad_value["seeds"][1]["seed_value"] = 9999999
bad_value_path.write_text(json.dumps(bad_value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_invariant = json.loads(json.dumps(catalog))
bad_invariant["seeds"][0]["invariant"] = ""
bad_invariant_path.write_text(json.dumps(bad_invariant, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for invalid_case in \
    "$BAD_PERMISSIONED_JSON:$BAD_PERMISSIONED_RAW" \
    "$BAD_NON_PERMISSIONED_LEAK_JSON:$BAD_NON_PERMISSIONED_LEAK_RAW" \
    "$BAD_SOURCE_JSON:$BAD_SOURCE_RAW" \
    "$BAD_NON_JSON_JSON:$BAD_NON_JSON_RAW" \
    "$BAD_POINTER_JSON:$BAD_POINTER_RAW" \
    "$BAD_VALUE_JSON:$BAD_VALUE_RAW" \
    "$BAD_INVARIANT_JSON:$BAD_INVARIANT_RAW"; do
    bad_catalog="${invalid_case%%:*}"
    bad_raw="${invalid_case#*:}"
    if run_cargo_capture "$bad_raw" run --quiet -p ffs-harness -- \
        validate-metamorphic-workload-seeds \
        --catalog "$bad_catalog"; then
        cat "$bad_raw"
    else
        invalid_failures=$((invalid_failures + 1))
    fi
done

coverage_preserved=0
if run_cargo_capture "$BAD_INVARIANT_REPORT_RAW" run --quiet -p ffs-harness -- \
    validate-metamorphic-workload-seeds \
    --catalog "$BAD_INVARIANT_JSON"; then
    cat "$BAD_INVARIANT_REPORT_RAW"
else
    if extract_report_json "$BAD_INVARIANT_REPORT_RAW" "$BAD_INVARIANT_REPORT" \
        && python3 - "$BAD_INVARIANT_REPORT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["valid"]:
    raise SystemExit("bad invariant report unexpectedly valid")
if report.get("source_value_verified_count") != report["seed_count"]:
    raise SystemExit("source value coverage was not preserved for unrelated invariant error")
if not any("invariant must not be empty" in error for error in report["errors"]):
    raise SystemExit("bad invariant report did not include invariant error")
PY
    then
        coverage_preserved=1
    fi
fi

if ((invalid_failures == 7 && coverage_preserved == 1)); then
    scenario_result "metamorphic_seed_catalog_invalid_variants_rejected" "PASS" "permissioned ack, non-permissioned permission leak, missing/non-JSON source artifact, source pointer, source value, and invariant variants rejected"
else
    scenario_result "metamorphic_seed_catalog_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures} coverage_preserved=${coverage_preserved}"
fi

e2e_step "Scenario 6: unit coverage rejects malformed catalog rows"
if run_cargo_capture "$UNIT_LOG" test -p ffs-harness --lib metamorphic_workload_seed_catalog -- --nocapture; then
    UNIT_TESTS_OK=1
    cat "$UNIT_LOG"
    for test_name in \
        "rejects_duplicate_seed_ids" \
        "rejects_missing_source_artifact" \
        "rejects_existing_non_json_source_artifact" \
        "source_value_coverage_counts_valid_sources_independent_of_row_errors" \
        "rejects_missing_source_value_pointer_target" \
        "rejects_mismatched_numeric_source_value" \
        "accepts_seed_contained_in_source_command_string" \
        "rejects_permissioned_seed_without_ack_requirement" \
        "rejects_non_permissioned_seed_with_ack_requirement" \
        "rejects_non_permissioned_seed_with_permissioned_reproduction_token" \
        "rejects_permissioned_seed_with_malformed_ack_requirement" \
        "rejects_permissioned_seed_command_missing_declared_ack" \
        "rejects_unknown_relation_type" \
        "rejects_seed_without_invariant" \
        "rejects_seed_without_existing_proof_consumer" \
        "rejects_catalog_with_too_few_source_kinds"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "metamorphic_seed_catalog_unit_tests" "PASS" "metamorphic seed catalog unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "metamorphic_seed_catalog_unit_tests" "FAIL" "unit coverage failed"
fi

e2e_log "Metamorphic seed catalog: $CATALOG_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Metamorphic workload seed catalog scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Metamorphic workload seed catalog scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
