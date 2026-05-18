#!/usr/bin/env bash
# ffs_workload_corpus_e2e.sh - real-world workload corpus dry-run gate for bd-rchk0.5.7.
#
# Validates the shared workload corpus that feeds proof consumers and release
# readiness evidence without running heavyweight mounted or benchmark lanes.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_workload_corpus}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_WORKLOAD_CORPUS_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_WORKLOAD_CORPUS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_WORKLOAD_CORPUS_SKIP_SELF_CHECK:-0}"

e2e_rch_add_env_allowlist CARGO_TARGET_DIR

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

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

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_WORKLOAD_CORPUS_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

risks = ["data_loss", "tail_latency", "host_capability_ambiguity", "permission_boundary"]
filesystems = ["ext4", "btrfs", "mixed"]
consumers = ["invariant_oracle", "mounted_differential_oracle", "proof_bundle", "release_gate"]
matrix = []
for index in range(11):
    scenario_id = f"workload_fixture_{index:02d}"
    matrix.append({
        "claim_id": f"claim_fixture_{index:02d}",
        "scenario_id": scenario_id,
        "user_risk": risks[index % len(risks)],
        "risk_tier": "p1",
        "filesystem_scope": filesystems[index % len(filesystems)],
        "operation_class": "write_path",
        "required_capabilities": ["rch_remote"],
        "proof_consumers": [consumers[index % len(consumers)]],
        "unit_test_obligations": ["workload_corpus"],
        "e2e_obligations": ["ffs_workload_corpus_e2e"],
        "expected_log_fields": ["scenario_id", "claim_id"],
        "expected_artifact_fields": ["required", "result_json"],
    })

report = {
    "valid": True,
    "corpus_id": "frankenfs_p1_workload_corpus_v1",
    "scenario_count": len(matrix),
    "status_counts": {
        "positive": 5,
        "negative": 2,
        "unsupported": 2,
        "host_skip": 2,
    },
    "by_user_risk": {risk: 1 for risk in risks},
    "by_filesystem_flavor": {filesystem: 1 for filesystem in filesystems},
    "by_proof_consumer": {consumer: 1 for consumer in consumers},
    "proof_bundle_coverage": {"ready": True},
    "coverage_matrix": matrix,
    "host_skip_scenarios": ["workload_fixture_03"],
    "btrfs_default_permissions_scenarios": ["workload_fixture_04"],
    "scenario_logs": [
        {
            "scenario_id": f"workload_fixture_{index:02d}",
            "reproduction_command": "cargo run -p ffs-harness -- validate-workload-corpus",
            "log_line": f"WORKLOAD_CORPUS_SCENARIO|scenario_id=workload_fixture_{index:02d}",
        }
        for index in range(3)
    ],
    "errors": [],
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown workload corpus fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib workload_corpus"*)
        printf '%s\n' \
            "test rejects_duplicate_scenario_ids ... ok" \
            "test rejects_unknown_capability_tags ... ok" \
            "test rejects_orphaned_high_risk_categories ... ok" \
            "test rejects_user_visible_rows_without_e2e_lane ... ok" \
            "test coverage_matrix_contains_user_risk_and_consumer_axes ... ok" \
            "test rejects_missing_required_artifact_declarations ... ok" \
            "test rejects_unsupported_without_classification ... ok" \
            "test rejects_host_skip_without_host_capability ... ok"
        exit 0
        ;;
    *"--select workload_editor_save_atomic_ext4"*)
        echo "selected workload_editor_save_atomic_ext4 accepted"
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
    local child_log="$E2E_LOG_DIR/workload_corpus_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_WORKLOAD_CORPUS_SELF_CHECK=0 \
        FFS_WORKLOAD_CORPUS_SKIP_SELF_CHECK=1 \
        FFS_WORKLOAD_CORPUS_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_workload_corpus_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic workload corpus wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path
    stub_path="$E2E_LOG_DIR/rch-workload-corpus-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/workload_corpus_report.json"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "workload_corpus_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "workload_corpus_selected_scenarios_checked" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "workload_corpus_proof_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "workload_corpus_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "workload_corpus_docs_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "workload_corpus_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .scenario_count >= 11
            and .proof_bundle_coverage.ready == true
            and (.coverage_matrix | length) == .scenario_count
            and (.host_skip_scenarios | length) > 0
            and (.btrfs_default_permissions_scenarios | length) > 0
        ' "$report_path" >/dev/null; then
        scenario_result "workload_corpus_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path}"
    else
        scenario_result "workload_corpus_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "workload corpus complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "workload_corpus_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "workload_corpus_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "workload corpus local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "workload corpus wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: workload corpus module and CLI are wired"
if grep -q "pub mod workload_corpus" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-workload-corpus" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_workload_corpus" scripts/e2e/scenario_catalog.json; then
    scenario_result "workload_corpus_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "workload_corpus_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in workload corpus validates"
if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-workload-corpus \
    --corpus "$CORPUS_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "workload_corpus_validates" "PASS" "checked-in workload corpus accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "workload_corpus_validates" "FAIL" "checked-in workload corpus rejected"
fi

SELECT_RAW="$E2E_LOG_DIR/workload_corpus_select.raw"
e2e_step "Scenario 2b: selected reproduction scenarios are checked"
if run_rch_capture "$SELECT_RAW" cargo run --quiet -p ffs-harness -- \
    validate-workload-corpus \
    --corpus "$CORPUS_JSON" \
    --select workload_editor_save_atomic_ext4; then
    scenario_result "workload_corpus_selected_scenarios_checked" "PASS" "known scenario accepted through the reproduction selector"
else
    cat "$SELECT_RAW"
    scenario_result "workload_corpus_selected_scenarios_checked" "FAIL" "known selected scenario was rejected"
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
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib workload_corpus -- --nocapture; then
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
