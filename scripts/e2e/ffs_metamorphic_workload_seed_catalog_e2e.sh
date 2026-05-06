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
import sys

raw_path, report_path = sys.argv[1:]
text = open(raw_path, encoding="utf-8", errors="replace").read()
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

run_cargo_cmd() {
    if [[ "${FFS_E2E_LOCAL_CARGO:-0}" == "1" ]]; then
        cargo "$@"
    else
        RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo "$@"
    fi
}

e2e_init "ffs_metamorphic_workload_seed_catalog"

CATALOG_JSON="$REPO_ROOT/tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json"
REPORT_JSON="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_report.json"
SUMMARY_MD="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_validate.raw"
UNIT_LOG="$E2E_LOG_DIR/metamorphic_workload_seed_catalog_unit_tests.log"
BAD_PERMISSIONED_JSON="$E2E_LOG_DIR/metamorphic_bad_permissioned_ack.json"
BAD_SOURCE_JSON="$E2E_LOG_DIR/metamorphic_bad_source_artifact.json"
BAD_POINTER_JSON="$E2E_LOG_DIR/metamorphic_bad_source_pointer.json"
BAD_VALUE_JSON="$E2E_LOG_DIR/metamorphic_bad_source_value.json"
BAD_RAW="$E2E_LOG_DIR/metamorphic_bad.raw"
UNIT_TESTS_OK=0

e2e_step "Scenario 1: metamorphic workload seed catalog module and CLI are wired"
if grep -q "pub mod metamorphic_workload_seed_catalog" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-metamorphic-workload-seeds" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_metamorphic_workload_seed_catalog" scripts/e2e/scenario_catalog.json; then
    scenario_result "metamorphic_seed_catalog_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "metamorphic_seed_catalog_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in metamorphic seed catalog validates"
if run_cargo_cmd run --quiet -p ffs-harness -- \
    validate-metamorphic-workload-seeds \
    --catalog "$CATALOG_JSON" \
    --summary-out "$SUMMARY_MD" >"$VALIDATE_RAW" 2>&1 \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
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
python3 - "$CATALOG_JSON" "$BAD_PERMISSIONED_JSON" "$BAD_SOURCE_JSON" "$BAD_POINTER_JSON" "$BAD_VALUE_JSON" <<'PY'
import json
import pathlib
import sys

(
    catalog_path,
    bad_permissioned_path,
    bad_source_path,
    bad_pointer_path,
    bad_value_path,
) = map(pathlib.Path, sys.argv[1:])
catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

bad_permissioned = json.loads(json.dumps(catalog))
for row in bad_permissioned["seeds"]:
    if row["execution_mode"] == "permissioned":
        row.pop("ack_requirement", None)
        break
bad_permissioned_path.write_text(json.dumps(bad_permissioned, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_source = json.loads(json.dumps(catalog))
bad_source["seeds"][0]["source_artifact"] = "tests/metamorphic-workload-seeds/missing_source_artifact.json"
bad_source_path.write_text(json.dumps(bad_source, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_pointer = json.loads(json.dumps(catalog))
bad_pointer["seeds"][0]["source_value_pointer"] = "/scenarios/3/missing_seed_field"
bad_pointer_path.write_text(json.dumps(bad_pointer, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bad_value = json.loads(json.dumps(catalog))
bad_value["seeds"][1]["seed_value"] = 9999999
bad_value_path.write_text(json.dumps(bad_value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad_catalog in "$BAD_PERMISSIONED_JSON" "$BAD_SOURCE_JSON" "$BAD_POINTER_JSON" "$BAD_VALUE_JSON"; do
    if run_cargo_cmd run --quiet -p ffs-harness -- \
        validate-metamorphic-workload-seeds \
        --catalog "$bad_catalog" >"$BAD_RAW" 2>&1; then
        cat "$BAD_RAW"
    else
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 4)); then
    scenario_result "metamorphic_seed_catalog_invalid_variants_rejected" "PASS" "permissioned ack, source artifact, source pointer, and source value variants rejected"
else
    scenario_result "metamorphic_seed_catalog_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 6: unit coverage rejects malformed catalog rows"
if run_cargo_cmd test -p ffs-harness --lib metamorphic_workload_seed_catalog -- --nocapture >"$UNIT_LOG" 2>&1; then
    UNIT_TESTS_OK=1
    cat "$UNIT_LOG"
    for test_name in \
        "rejects_duplicate_seed_ids" \
        "rejects_missing_source_artifact" \
        "rejects_missing_source_value_pointer_target" \
        "rejects_mismatched_numeric_source_value" \
        "accepts_seed_contained_in_source_command_string" \
        "rejects_permissioned_seed_without_ack_requirement" \
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
