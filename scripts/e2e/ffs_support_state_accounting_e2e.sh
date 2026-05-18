#!/usr/bin/env bash
# ffs_support_state_accounting_e2e.sh - smoke gate for bd-mpcse.
#
# Validates that implementation-count parity is exported separately from
# tiered support-state readiness, rejects unscoped flat parity wording, and
# keeps the schema/unit tests green.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_support_state_accounting}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_SUPPORT_STATE_ACCOUNTING_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_SUPPORT_STATE_ACCOUNTING_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_SUPPORT_STATE_ACCOUNTING_SKIP_SELF_CHECK:-0}"

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

e2e_init "ffs_support_state_accounting"

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_SUPPORT_STATE_ACCOUNTING_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected support-state fixture rch invocation: $*" >&2
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
        echo "unknown support-state fixture case: $fixture_case" >&2
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

emit_json_report() {
    cat <<'JSON'
{
  "support_state_version": 1,
  "flat_parity_rejected": true,
  "release_gate_contract": "bd-rchk0.5.6.1 fixture",
  "grouped_by_support_state": {
    "validated": [],
    "experimental": [],
    "detection_only": [],
    "dry_run_only": [],
    "parse_only": [],
    "single_device_only": [],
    "basic_coverage": [],
    "disabled": [],
    "opt_in_mutating": [],
    "unsupported": [],
    "deferred": [],
    "host_blocked": []
  },
  "migration_cases": [
    {
      "feature_id": "btrfs_send_receive_streams",
      "classified_support_state": "parse_only"
    },
    {
      "feature_id": "btrfs_multi_device_raid",
      "classified_support_state": "single_device_only"
    },
    {
      "feature_id": "ext4_casefold",
      "classified_support_state": "basic_coverage"
    },
    {
      "feature_id": "mounted_write_paths",
      "classified_support_state": "experimental"
    },
    {
      "feature_id": "background_scrub",
      "classified_support_state": "detection_only"
    },
    {
      "feature_id": "fuse_writeback_cache",
      "classified_support_state": "disabled"
    },
    {
      "feature_id": "rw_background_repair",
      "classified_support_state": "host_blocked"
    },
    {
      "feature_id": "readonly_ext4_btrfs_inspection",
      "classified_support_state": "validated"
    }
  ],
  "evidence_tokens": {
    "feature_id": "fixture",
    "old_count_claim": "fixture",
    "support_state": "fixture",
    "controlling_bead_or_artifact": "fixture",
    "downgrade_or_upgrade_reason": "fixture",
    "docs_target": "fixture",
    "release_gate_effect": "fixture",
    "reproduction_command": "fixture"
  }
}
JSON
}

case "$command_text" in
    *"bad_feature_parity.md"*)
        echo "flat 100 percent parity wording"
        finish_failure 1
        ;;
    *"missing_owner_issues.jsonl"*)
        echo "bd-naww5"
        finish_failure 1
        ;;
    *"cargo test"*support_state_accounting*)
        for i in $(seq 1 7); do
            echo "test support_state_accounting::tests::fixture_case_${i} ... ok"
        done
        echo "test result: ok. fixture passed"
        finish_success
        ;;
    *"--format markdown"*)
        cat <<'MD'
# FrankenFS Support-State Accounting

| Feature | Support State |
|---------|---------------|
| readonly_ext4_btrfs_inspection | validated |
MD
        finish_success
        ;;
    *"validate-support-state-accounting"*)
        emit_json_report
        finish_success
        ;;
    *)
        echo "unexpected support-state fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/support_state_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_SUPPORT_STATE_ACCOUNTING_SELF_CHECK=0 \
        FFS_SUPPORT_STATE_ACCOUNTING_SKIP_SELF_CHECK=1 \
        FFS_SUPPORT_STATE_ACCOUNTING_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_support_state_accounting_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic support-state accounting wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-support-state-accounting-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "support_state_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "support_state_report_writes" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "support_state_grouping" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "support_state_log_tokens" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "support_state_rejects_flat_wording" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "support_state_rejects_missing_owner" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "support_state_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "support_state_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "support_state_fixture_complete_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "support_state_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "support_state_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "support_state_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "support_state_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

REPORT_JSON="${E2E_LOG_DIR}/support_state_accounting.json"
REPORT_MD="${E2E_LOG_DIR}/support_state_accounting.md"
REPORT_RAW="${E2E_LOG_DIR}/support_state_accounting.raw"
REPORT_MD_RAW="${E2E_LOG_DIR}/support_state_accounting_md.raw"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/support_state_accounting"
mkdir -p "$RCH_INPUT_DIR"
ISSUES_JSONL="${RCH_INPUT_DIR}/issues.jsonl"
BAD_FEATURE_PARITY="${RCH_INPUT_DIR}/bad_feature_parity.md"
MISSING_OWNER_JSONL="${RCH_INPUT_DIR}/missing_owner_issues.jsonl"
BAD_WORDING_RAW="${E2E_LOG_DIR}/bad_wording.raw"
MISSING_OWNER_RAW="${E2E_LOG_DIR}/missing_owner.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"
cp .beads/issues.jsonl "$ISSUES_JSONL"

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod support_state_accounting" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-support-state-accounting" crates/ffs-harness/src/main.rs; then
    scenario_result "support_state_wired" "PASS" "module and CLI command exported"
else
    scenario_result "support_state_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: CLI writes JSON and Markdown reports"
if run_rch_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-support-state-accounting \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    && run_rch_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-support-state-accounting \
        --issues "$ISSUES_JSONL" \
        --feature-parity FEATURE_PARITY.md \
        --format markdown; then
    if python3 - "$REPORT_RAW" "$REPORT_JSON" "$REPORT_MD_RAW" "$REPORT_MD" <<'PY'
import json
import sys

json_raw, json_report, md_raw, md_report = sys.argv[1:5]
text = open(json_raw, encoding="utf-8", errors="replace").read()
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "support_state_version" in obj:
        with open(json_report, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("support-state JSON object not found in rch output")

markdown = open(md_raw, encoding="utf-8", errors="replace").read()
marker = "# FrankenFS Support-State Accounting"
index = markdown.find(marker)
if index < 0:
    raise SystemExit("support-state Markdown marker not found")
with open(md_report, "w", encoding="utf-8") as handle:
    handle.write(markdown[index:])
PY
    then
        scenario_result "support_state_report_writes" "PASS" "JSON and Markdown reports captured"
    else
        scenario_result "support_state_report_writes" "FAIL" "missing JSON or Markdown output"
    fi
else
    scenario_result "support_state_report_writes" "FAIL" "CLI command failed"
fi

e2e_step "Scenario 3: report covers required state classes and migration cases"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
required_states = {
    "validated",
    "experimental",
    "detection_only",
    "dry_run_only",
    "parse_only",
    "single_device_only",
    "basic_coverage",
    "disabled",
    "opt_in_mutating",
    "unsupported",
    "deferred",
    "host_blocked",
}
groups = data.get("grouped_by_support_state", {})
missing_states = sorted(required_states.difference(groups))
if missing_states:
    raise SystemExit(f"missing states: {missing_states}")

expected_cases = {
    "btrfs_send_receive_streams": "parse_only",
    "btrfs_multi_device_raid": "single_device_only",
    "ext4_casefold": "basic_coverage",
    "mounted_write_paths": "experimental",
    "background_scrub": "detection_only",
    "fuse_writeback_cache": "disabled",
    "rw_background_repair": "host_blocked",
    "readonly_ext4_btrfs_inspection": "validated",
}
cases = {
    row["feature_id"]: row["classified_support_state"]
    for row in data.get("migration_cases", [])
}
for feature_id, expected in expected_cases.items():
    observed = cases.get(feature_id)
    if observed != expected:
        raise SystemExit(f"{feature_id}: expected {expected}, observed {observed}")
if not data.get("flat_parity_rejected"):
    raise SystemExit("flat_parity_rejected must be true")
if "bd-rchk0.5.6.1" not in data.get("release_gate_contract", ""):
    raise SystemExit("release-gate composition contract missing")
PY
then
    scenario_result "support_state_grouping" "PASS" "required states and migrations represented"
else
    scenario_result "support_state_grouping" "FAIL" "state grouping or migration validation failed"
fi

e2e_step "Scenario 4: structured log fields are present"
TOKENS_FOUND=0
for token in \
    "feature_id" \
    "old_count_claim" \
    "support_state" \
    "controlling_bead_or_artifact" \
    "downgrade_or_upgrade_reason" \
    "docs_target" \
    "release_gate_effect" \
    "reproduction_command"; do
    if grep -q "\"${token}\"" "$REPORT_JSON"; then
        TOKENS_FOUND=$((TOKENS_FOUND + 1))
    fi
done

if [[ $TOKENS_FOUND -eq 8 ]]; then
    scenario_result "support_state_log_tokens" "PASS" "all log tokens present"
else
    scenario_result "support_state_log_tokens" "FAIL" "only ${TOKENS_FOUND}/8 log tokens present"
fi

e2e_step "Scenario 5: unscoped flat parity wording is rejected"
python3 - "$BAD_FEATURE_PARITY" <<'PY'
import sys

path = sys.argv[1]
text = """# FEATURE_PARITY

## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 27 | 27 | 100.0% |

FrankenFS has 100 percent parity.
"""
open(path, "w", encoding="utf-8").write(text)
PY
if run_rch_capture "$BAD_WORDING_RAW" cargo run --quiet -p ffs-harness -- validate-support-state-accounting \
    --issues "$ISSUES_JSONL" \
    --feature-parity "$BAD_FEATURE_PARITY"; then
    scenario_result "support_state_rejects_flat_wording" "FAIL" "bad wording unexpectedly passed"
else
    if grep -q "flat 100 percent parity wording" "$BAD_WORDING_RAW"; then
        scenario_result "support_state_rejects_flat_wording" "PASS" "bad wording failed closed"
    else
        scenario_result "support_state_rejects_flat_wording" "FAIL" "failure did not name flat wording"
    fi
fi

e2e_step "Scenario 6: missing owner beads are rejected"
grep '"id":"bd-mpcse"' "$ISSUES_JSONL" >"$MISSING_OWNER_JSONL"
if run_rch_capture "$MISSING_OWNER_RAW" cargo run --quiet -p ffs-harness -- validate-support-state-accounting \
    --issues "$MISSING_OWNER_JSONL" \
    --feature-parity FEATURE_PARITY.md; then
    scenario_result "support_state_rejects_missing_owner" "FAIL" "missing owner unexpectedly passed"
else
    if grep -q "bd-naww5" "$MISSING_OWNER_RAW"; then
        scenario_result "support_state_rejects_missing_owner" "PASS" "missing owner failed closed"
    else
        scenario_result "support_state_rejects_missing_owner" "FAIL" "failure did not name missing owner"
    fi
fi

e2e_step "Scenario 7: unit/schema tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib -- support_state_accounting; then
    TESTS_RUN=$(grep -c "test support_state_accounting::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 7 ]]; then
        scenario_result "support_state_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "support_state_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "support_state_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_support_state_accounting completed"
else
    e2e_fail "ffs_support_state_accounting failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
