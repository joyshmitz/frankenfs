#!/usr/bin/env bash
# ffs_invariant_oracle_e2e.sh - smoke gate for bd-rchk0.5.1.1.
#
# Scenarios:
#   1. Harness module and CLI are wired.
#   2. A create/write/fsync FrankenFS-style operation trace validates offline.
#   3. Report includes deterministic replay and required artifact fields.
#   4. Expected invariant failure emits class, violation, and minimized trace.
#   5. Unexpected invariant failure fails closed.
#   6. Unit tests pass.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_invariant_oracle}"
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

e2e_init "ffs_invariant_oracle"

VALID_TRACE="${E2E_LOG_DIR}/valid_trace.json"
EXPECTED_FAILURE_TRACE="${E2E_LOG_DIR}/expected_failure_trace.json"
UNEXPECTED_FAILURE_TRACE="${E2E_LOG_DIR}/unexpected_failure_trace.json"
VALID_RAW="${E2E_LOG_DIR}/valid_report.raw"
VALID_REPORT="${E2E_LOG_DIR}/valid_report.json"
EXPECTED_RAW="${E2E_LOG_DIR}/expected_failure_report.raw"
EXPECTED_REPORT="${E2E_LOG_DIR}/expected_failure_report.json"
UNEXPECTED_RAW="${E2E_LOG_DIR}/unexpected_failure.raw"
UNIT_LOG="$(mktemp)"

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
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
    --trace "$VALID_TRACE" >"$VALID_RAW" 2>&1; then
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

e2e_step "Scenario 4: expected failure emits minimized report"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
    --trace "$EXPECTED_FAILURE_TRACE" >"$EXPECTED_RAW" 2>&1; then
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
if row.get("minimized_trace", {}).get("minimized_trace_len") != 4:
    raise SystemExit("wrong minimized trace length")
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

e2e_step "Scenario 5: unexpected failure fails closed"
if RCH_VISIBILITY=none "${RCH_BIN:-rch}" exec -- cargo run --quiet -p ffs-harness -- validate-invariant-oracle \
    --trace "$UNEXPECTED_FAILURE_TRACE" >"$UNEXPECTED_RAW" 2>&1; then
    scenario_result "invariant_oracle_unexpected_failure_rejected" "FAIL" "unexpected failure was accepted"
else
    if grep -q "unexpected invariant violation" "$UNEXPECTED_RAW"; then
        scenario_result "invariant_oracle_unexpected_failure_rejected" "PASS" "unexpected failure rejected"
    else
        scenario_result "invariant_oracle_unexpected_failure_rejected" "FAIL" "rejection diagnostic missing"
    fi
fi

e2e_step "Scenario 6: unit tests pass"
if "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib invariant_oracle -- --nocapture \
    2>"$UNIT_LOG" | tee -a "$UNIT_LOG"; then
    TESTS_RUN=$(grep -c "test invariant_oracle::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 7 ]]; then
        scenario_result "invariant_oracle_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "invariant_oracle_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "invariant_oracle_unit_tests" "FAIL" "unit tests failed"
fi

rm -f "$UNIT_LOG"

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_invariant_oracle completed"
else
    e2e_fail "ffs_invariant_oracle failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
