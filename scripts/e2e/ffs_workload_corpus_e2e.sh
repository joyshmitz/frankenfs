#!/usr/bin/env bash
# ffs_workload_corpus_e2e.sh - P1 workload corpus dry-run gate for bd-rchk0.5.7.1.
#
# Validates the shared workload corpus that feeds proof consumers and release
# readiness evidence without running heavyweight mounted or benchmark lanes.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_workload_corpus}"
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
    if isinstance(obj, dict) and "corpus_id" in obj and "scenario_count" in obj:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("workload corpus validation JSON object not found")
PY
}

e2e_init "ffs_workload_corpus"

CORPUS_JSON="$REPO_ROOT/tests/workload-corpus/p1_workload_corpus.json"
REPORT_JSON="$E2E_LOG_DIR/workload_corpus_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/workload_corpus_validate.raw"
UNIT_LOG="$E2E_LOG_DIR/workload_corpus_unit_tests.log"
UNIT_TESTS_OK=0

e2e_step "Scenario 1: workload corpus module and CLI are wired"
if grep -q "pub mod workload_corpus" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-workload-corpus" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_workload_corpus" scripts/e2e/scenario_catalog.json; then
    scenario_result "workload_corpus_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "workload_corpus_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in workload corpus validates"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- \
    validate-workload-corpus \
    --corpus "$CORPUS_JSON" >"$VALIDATE_RAW" 2>&1 \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "workload_corpus_validates" "PASS" "checked-in workload corpus accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "workload_corpus_validates" "FAIL" "checked-in workload corpus rejected"
fi

e2e_step "Scenario 3: proof coverage spans user risks, filesystems, and consumers"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["scenario_count"] < 11:
    raise SystemExit("expected at least 11 representative workload scenarios")
for status in ["positive", "negative", "unsupported", "host_skip"]:
    if report["status_counts"].get(status, 0) == 0:
        raise SystemExit(f"missing status {status}")
for risk in ["data_loss", "tail_latency", "host_capability_ambiguity", "permission_boundary"]:
    if report["by_user_risk"].get(risk, 0) == 0:
        raise SystemExit(f"missing user risk {risk}")
for filesystem in ["ext4", "btrfs", "mixed"]:
    if report["by_filesystem_flavor"].get(filesystem, 0) == 0:
        raise SystemExit(f"missing filesystem {filesystem}")
for consumer in ["invariant_oracle", "mounted_differential_oracle", "proof_bundle", "release_gate"]:
    if report["by_proof_consumer"].get(consumer, 0) == 0:
        raise SystemExit(f"missing proof consumer {consumer}")
if not report["proof_bundle_coverage"]["ready"]:
    raise SystemExit("proof bundle coverage not ready")
if len(report.get("coverage_matrix", [])) != report["scenario_count"]:
    raise SystemExit("coverage matrix row count does not match scenario count")
required_matrix_fields = {
    "claim_id",
    "scenario_id",
    "user_risk",
    "risk_tier",
    "filesystem_scope",
    "operation_class",
    "required_capabilities",
    "proof_consumers",
    "unit_test_obligations",
    "e2e_obligations",
    "expected_log_fields",
    "expected_artifact_fields",
}
for row in report["coverage_matrix"]:
    missing = sorted(required_matrix_fields - set(row))
    if missing:
        raise SystemExit(f"coverage matrix row missing fields: {row.get('scenario_id')} {missing}")
    if row["risk_tier"] in {"p1", "p2"} and not row["e2e_obligations"]:
        raise SystemExit(f"user-visible matrix row has no E2E lane: {row['scenario_id']}")
    if "scenario_id" not in row["expected_log_fields"]:
        raise SystemExit(f"matrix row missing scenario_id log field: {row['scenario_id']}")
    if "required" not in row["expected_artifact_fields"]:
        raise SystemExit(f"matrix row missing required artifact field: {row['scenario_id']}")
if not report["host_skip_scenarios"]:
    raise SystemExit("missing host skip scenario")
if not report["btrfs_default_permissions_scenarios"]:
    raise SystemExit("missing btrfs DefaultPermissions diagnostic")
logs = report["scenario_logs"]
if len(logs) < 3:
    raise SystemExit("expected per-scenario logs")
if not all(row["reproduction_command"] for row in logs[:3]):
    raise SystemExit("missing reproduction command in scenario logs")
if not all("WORKLOAD_CORPUS_SCENARIO" in row["log_line"] for row in logs[:3]):
    raise SystemExit("scenario log lines missing workload marker")
PY
then
    scenario_result "workload_corpus_proof_coverage" "PASS" "proof coverage matrix and scenario logs verified"
else
    scenario_result "workload_corpus_proof_coverage" "FAIL" "proof coverage contract failed"
fi

e2e_step "Scenario 4: invalid corpus variants fail closed in unit coverage"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib workload_corpus -- --nocapture >"$UNIT_LOG" 2>&1; then
    UNIT_TESTS_OK=1
    cat "$UNIT_LOG"
    for test_name in \
        "rejects_duplicate_scenario_ids" \
        "rejects_unknown_capability_tags" \
        "rejects_orphaned_high_risk_categories" \
        "rejects_user_visible_rows_without_e2e_lane" \
        "coverage_matrix_contains_user_risk_and_consumer_axes" \
        "rejects_missing_required_artifact_declarations" \
        "rejects_unsupported_without_classification" \
        "rejects_host_skip_without_host_capability"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "workload_corpus_invalid_variants_rejected" "PASS" "duplicate/capability/artifact/unsupported/host-skip variants rejected"
else
    cat "$UNIT_LOG"
    scenario_result "workload_corpus_invalid_variants_rejected" "FAIL" "invalid variant unit coverage failed"
fi

e2e_step "Scenario 5: docs explain workload corpus extension contract"
if grep -q "Workload Corpus Contract" scripts/e2e/README.md \
    && grep -q "user_risk" scripts/e2e/README.md \
    && grep -q "linked_proof_consumers" scripts/e2e/README.md \
    && grep -q "btrfs DefaultPermissions" scripts/e2e/README.md; then
    scenario_result "workload_corpus_docs_contract" "PASS" "docs cover extension fields and host-skip diagnostic"
else
    scenario_result "workload_corpus_docs_contract" "FAIL" "docs missing workload corpus extension contract"
fi

e2e_step "Scenario 6: workload corpus unit tests pass"
if ((UNIT_TESTS_OK == 1)); then
    scenario_result "workload_corpus_unit_tests" "PASS" "workload corpus unit tests passed"
else
    scenario_result "workload_corpus_unit_tests" "FAIL" "workload corpus unit tests failed"
fi

e2e_log "Workload corpus: $CORPUS_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Workload corpus scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Workload corpus scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
