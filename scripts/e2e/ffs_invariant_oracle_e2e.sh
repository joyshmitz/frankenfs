#!/usr/bin/env bash
# ffs_invariant_oracle_e2e.sh - smoke gate for bd-rchk0.5.1.
#
# Scenarios:
#   1. Harness module and CLI are wired.
#   2. A create/write/fsync FrankenFS-style operation trace validates offline.
#   3. Report includes deterministic replay and required artifact fields.
#   4. Proof-bundle consumer validation rejects unknown model versions.
#   5. Expected invariant failure emits class, violation, and minimized trace.
#   6. Unexpected invariant failure fails closed.
#   7. Unit tests pass.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_invariant_oracle}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_INVARIANT_ORACLE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_INVARIANT_ORACLE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_INVARIANT_ORACLE_SKIP_SELF_CHECK:-0}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

run_rch_capture() {
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$@"
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

e2e_init "ffs_invariant_oracle"

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_INVARIANT_ORACLE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected invariant-oracle fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown invariant-oracle fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

finish_failure() {
    local status="$1"
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=${status}"
    fi
    exit "$status"
}

emit_valid_report() {
    cat <<'JSON'
{
  "deterministic_replay_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_failure_count": 0,
  "model_version": "ffs-invariant-oracle-model-v1",
  "operation_count": 3,
  "reproduction_command": "ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json --out artifacts/invariant/oracle_report.json",
  "required_artifacts": [
    "logs/op-0.jsonl",
    "logs/op-1.jsonl",
    "logs/op-2.jsonl"
  ],
  "unexpected_failure_count": 0,
  "valid": true
}
JSON
}

emit_expected_failure_report() {
    cat <<'JSON'
{
  "deterministic_replay_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "expected_failure_count": 1,
  "model_version": "ffs-invariant-oracle-model-v1",
  "operation_count": 4,
  "unexpected_failure_count": 0,
  "valid": true,
  "violations": [
    {
      "classification": "production_bug",
      "expected_invariant_result": true,
      "failure_class": "production_bug",
      "minimized_trace": {
        "minimized_trace_len": 4,
        "shrink_steps": [
          "removed no-op probe"
        ]
      },
      "observed_invariant_result": false,
      "operation_index": 3,
      "post_state_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "pre_state_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "violated_invariant": "file_size_matches_model"
    }
  ]
}
JSON
}

emit_unit_test_log() {
    local name
    for name in \
        validates_clean_trace \
        rejects_unknown_model \
        minimizes_expected_failure \
        fails_unexpected_violation \
        preserves_artifact_fields \
        hashes_pre_state \
        hashes_post_state \
        records_reproduction_command \
        counts_operations \
        classifies_failure; do
        printf 'test invariant_oracle::tests::%s ... ok\n' "$name"
    done
    echo "test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
}

report_path_from_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --report)
                printf '%s\n' "${2:-}"
                return 0
                ;;
        esac
        shift
    done
}

if [[ "$command_text" == *"cargo test -p ffs-harness --lib invariant_oracle"* ]]; then
    emit_unit_test_log
    finish_success
fi

if [[ "$command_text" == *"validate-invariant-oracle"* && "$command_text" == *"--report"* ]]; then
    report_path="$(report_path_from_args "$@")"
    if [[ -n "$report_path" ]] && grep -q '"model_version"[[:space:]]*:[[:space:]]*"unknown-model"' "$report_path"; then
        echo "report model_version unknown-model is unsupported"
        finish_failure 1
    fi
    finish_success
fi

case "$command_text" in
    *"unexpected_failure_trace.json"*)
        echo "unexpected invariant violation: file_size_matches_model"
        finish_failure 1
        ;;
    *"expected_failure_trace.json"*)
        emit_expected_failure_report
        finish_success
        ;;
    *"valid_trace.json"*)
        emit_valid_report
        finish_success
        ;;
    *)
        echo "unexpected invariant-oracle fixture command: $command_text" >&2
        exit 64
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
    local child_log="$E2E_LOG_DIR/invariant_oracle_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_INVARIANT_ORACLE_SELF_CHECK=0 \
        FFS_INVARIANT_ORACLE_SKIP_SELF_CHECK=1 \
        FFS_INVARIANT_ORACLE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_invariant_oracle_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic invariant-oracle wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-invariant-oracle-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .invalid_scenario_marker_count == 0
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_real_write_sequence" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_report_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_consumer_rejects_unknown_model" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_expected_failure_minimized" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_unexpected_failure_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "invariant_oracle_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "invariant_oracle_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "invariant_oracle_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "invariant_oracle_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "invariant_oracle_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "invariant_oracle_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "invariant_oracle_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/invariant_oracle"
mkdir -p "$RCH_INPUT_DIR"

VALID_TRACE="${RCH_INPUT_DIR}/valid_trace.json"
EXPECTED_FAILURE_TRACE="${RCH_INPUT_DIR}/expected_failure_trace.json"
UNEXPECTED_FAILURE_TRACE="${RCH_INPUT_DIR}/unexpected_failure_trace.json"
VALID_RAW="${E2E_LOG_DIR}/valid_report.raw"
VALID_REPORT="${E2E_LOG_DIR}/valid_report.json"
VALID_REPORT_RCH="${RCH_INPUT_DIR}/valid_report.json"
VALID_CONSUMER_RAW="${E2E_LOG_DIR}/valid_consumer.raw"
UNKNOWN_MODEL_REPORT="${RCH_INPUT_DIR}/unknown_model_report.json"
UNKNOWN_MODEL_RAW="${E2E_LOG_DIR}/unknown_model.raw"
EXPECTED_RAW="${E2E_LOG_DIR}/expected_failure_report.raw"
EXPECTED_REPORT="${E2E_LOG_DIR}/expected_failure_report.json"
UNEXPECTED_RAW="${E2E_LOG_DIR}/unexpected_failure.raw"
UNIT_LOG="${E2E_LOG_DIR}/invariant_oracle_unit_tests.log"

extract_report_json() {
    local raw_path="$1"
    local report_path="$2"
    local required_key="$3"
    python3 - "$raw_path" "$report_path" "$required_key" <<'PY'
import json
import sys

raw_path, report_path, required_key = sys.argv[1:]
text = open(raw_path, encoding="utf-8", errors="replace").read()
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and required_key in obj:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit(f"report JSON object with {required_key!r} not found")
PY
}

python3 - "$VALID_TRACE" "$EXPECTED_FAILURE_TRACE" "$UNEXPECTED_FAILURE_TRACE" <<'PY'
import hashlib
import json
import sys

valid_path, expected_path, unexpected_path = sys.argv[1:]
empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def hash_part(buf, value):
    encoded = value.encode()
    buf.update(str(len(value)).encode())
    buf.update(b":")
    buf.update(encoded)
    buf.update(b";")


def synthetic_hash(path, size):
    h = hashlib.sha256()
    hash_part(h, path)
    hash_part(h, str(size))
    return h.hexdigest()


def state(files, durable=()):
    rows = []
    for path, size in files:
        rows.append(
            {
                "path": path,
                "size": size,
                "content_hash": empty_hash if size == 0 else synthetic_hash(path, size),
            }
        )
    return {
        "directories": ["/"],
        "files": rows,
        "durable_paths": list(durable),
    }


def op(index, action, path, expected, observed, bytes_written=None):
    row = {
        "operation_id": f"op-{index}",
        "operation_index": index,
        "action": action,
        "path": path,
        "precondition": "request scoped through OpenFs model precondition",
        "expected_model_delta": "path state updated by invariant oracle replay",
        "observed_subsystem_event": f"OpenFs::{action}(path={path})",
        "artifact_refs": [f"logs/op-{index}.jsonl"],
        "expected_state": expected,
        "observed_state": observed,
    }
    if bytes_written is not None:
        row["bytes_written"] = bytes_written
    return row


base_ops = [
    op(0, "create_file", "/alpha", state([("/alpha", 0)]), state([("/alpha", 0)])),
    op(1, "write_file", "/alpha", state([("/alpha", 5)]), state([("/alpha", 5)]), 5),
    op(2, "fsync_file", "/alpha", state([("/alpha", 5)], ["/alpha"]), state([("/alpha", 5)], ["/alpha"])),
]

valid = {
    "schema_version": 1,
    "model_version": "ffs-invariant-oracle-model-v1",
    "trace_id": "e2e-create-write-fsync",
    "seed": 20260503,
    "reproduction_command": "ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json --out artifacts/invariant/oracle_report.json",
    "operations": base_ops,
}

expected = dict(valid)
expected["trace_id"] = "e2e-expected-size-mismatch"
expected["operations"] = list(base_ops)
expected["operations"].append(
    {
        **op(
            3,
            "model_invariant_probe",
            "/alpha",
            state([("/alpha", 5)], ["/alpha"]),
            state([("/alpha", 4)], ["/alpha"]),
        ),
        "expected_violation": "file_size_matches_model",
        "failure_class": "production_bug",
    }
)

unexpected = dict(expected)
unexpected["trace_id"] = "e2e-unexpected-size-mismatch"
unexpected["operations"] = [dict(row) for row in expected["operations"]]
unexpected["operations"][-1].pop("expected_violation")
unexpected["operations"][-1].pop("failure_class")

for path, payload in [
    (valid_path, valid),
    (expected_path, expected),
    (unexpected_path, unexpected),
]:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
PY

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod invariant_oracle" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-invariant-oracle" crates/ffs-harness/src/main.rs; then
    scenario_result "invariant_oracle_wired" "PASS" "module and CLI command exported"
else
    scenario_result "invariant_oracle_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: real write sequence trace validates"
if run_rch_capture "$VALID_RAW" cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
    --trace "$VALID_TRACE"; then
    if extract_report_json "$VALID_RAW" "$VALID_REPORT" "deterministic_replay_id" \
        && python3 - "$VALID_REPORT" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
if not data.get("valid"):
    raise SystemExit("valid trace was rejected")
if data.get("operation_count") != 3:
    raise SystemExit("expected three operations")
if data.get("expected_failure_count") != 0 or data.get("unexpected_failure_count") != 0:
    raise SystemExit("clean trace reported failures")
PY
    then
        scenario_result "invariant_oracle_real_write_sequence" "PASS" "create/write/fsync trace validated"
    else
        scenario_result "invariant_oracle_real_write_sequence" "FAIL" "valid report fields failed"
    fi
else
    scenario_result "invariant_oracle_real_write_sequence" "FAIL" "valid trace CLI failed"
fi

e2e_step "Scenario 3: deterministic replay and artifact fields"
if python3 - "$VALID_REPORT" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
if len(data.get("deterministic_replay_id", "")) != 64:
    raise SystemExit("deterministic replay id missing")
if data.get("model_version") != "ffs-invariant-oracle-model-v1":
    raise SystemExit("model version missing")
if len(data.get("required_artifacts", [])) != 3:
    raise SystemExit("required artifacts not preserved")
if "validate-invariant-oracle" not in data.get("reproduction_command", ""):
    raise SystemExit("reproduction command missing")
PY
then
    scenario_result "invariant_oracle_report_contract" "PASS" "replay id, artifacts, reproduction present"
else
    scenario_result "invariant_oracle_report_contract" "FAIL" "report contract missing fields"
fi

e2e_step "Scenario 4: proof-bundle consumer rejects unknown model versions"
if [[ -f "$VALID_REPORT" ]] && python3 - "$VALID_REPORT" "$VALID_REPORT_RCH" "$UNKNOWN_MODEL_REPORT" <<'PY'
import json
import sys

source, valid_target, unknown_target = sys.argv[1:]
data = json.loads(open(source, encoding="utf-8").read())
with open(valid_target, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
data["model_version"] = "unknown-model"
with open(unknown_target, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
then
    if run_rch_capture "$VALID_CONSUMER_RAW" cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
        --report "$VALID_REPORT_RCH" \
        && ! run_rch_capture "$UNKNOWN_MODEL_RAW" cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
            --report "$UNKNOWN_MODEL_REPORT"; then
        if grep -q "report model_version" "$UNKNOWN_MODEL_RAW"; then
            scenario_result "invariant_oracle_consumer_rejects_unknown_model" "PASS" "consumer rejected unknown model version"
        else
            scenario_result "invariant_oracle_consumer_rejects_unknown_model" "FAIL" "unknown model diagnostic missing"
        fi
    else
        scenario_result "invariant_oracle_consumer_rejects_unknown_model" "FAIL" "consumer validation command contract failed"
    fi
else
    scenario_result "invariant_oracle_consumer_rejects_unknown_model" "FAIL" "valid report fixture unavailable"
fi

e2e_step "Scenario 5: expected failure emits minimized report"
if run_rch_capture "$EXPECTED_RAW" cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
    --trace "$EXPECTED_FAILURE_TRACE"; then
    if extract_report_json "$EXPECTED_RAW" "$EXPECTED_REPORT" "violations" \
        && python3 - "$EXPECTED_REPORT" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
violations = data.get("violations", [])
if not data.get("valid"):
    raise SystemExit("expected failure trace should remain valid")
if data.get("expected_failure_count") != 1:
    raise SystemExit("expected exactly one expected failure")
if not violations:
    raise SystemExit("missing violation row")
row = violations[0]
if row.get("violated_invariant") != "file_size_matches_model":
    raise SystemExit("wrong invariant")
if row.get("failure_class") != "production_bug":
    raise SystemExit("wrong failure class")
if row.get("classification") != "production_bug":
    raise SystemExit("missing classification")
if len(row.get("pre_state_hash", "")) != 64 or len(row.get("post_state_hash", "")) != 64:
    raise SystemExit("state hashes missing")
if row.get("expected_invariant_result") is not True or row.get("observed_invariant_result") is not False:
    raise SystemExit("invariant result evidence missing")
if row.get("minimized_trace", {}).get("minimized_trace_len") != 4:
    raise SystemExit("wrong minimized trace length")
if not row.get("minimized_trace", {}).get("shrink_steps"):
    raise SystemExit("shrink steps missing")
if row.get("operation_index") != 3:
    raise SystemExit("operation index missing")
PY
    then
        scenario_result "invariant_oracle_expected_failure_minimized" "PASS" "expected failure report is structured"
    else
        scenario_result "invariant_oracle_expected_failure_minimized" "FAIL" "expected failure report invalid"
    fi
else
    scenario_result "invariant_oracle_expected_failure_minimized" "FAIL" "expected failure trace CLI failed"
fi

e2e_step "Scenario 6: unexpected failure fails closed"
if run_rch_capture "$UNEXPECTED_RAW" cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
    --trace "$UNEXPECTED_FAILURE_TRACE"; then
    scenario_result "invariant_oracle_unexpected_failure_rejected" "FAIL" "unexpected failure was accepted"
else
    if grep -q "unexpected invariant violation" "$UNEXPECTED_RAW"; then
        scenario_result "invariant_oracle_unexpected_failure_rejected" "PASS" "unexpected failure rejected"
    else
        scenario_result "invariant_oracle_unexpected_failure_rejected" "FAIL" "rejection diagnostic missing"
    fi
fi

e2e_step "Scenario 7: unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib invariant_oracle -- --nocapture; then
    cat "$UNIT_LOG"
    TESTS_RUN=$(grep -c "test invariant_oracle::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "invariant_oracle_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "invariant_oracle_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    cat "$UNIT_LOG"
    scenario_result "invariant_oracle_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_invariant_oracle completed"
else
    e2e_fail "ffs_invariant_oracle failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
