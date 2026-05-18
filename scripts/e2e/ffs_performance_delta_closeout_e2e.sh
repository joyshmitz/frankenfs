#!/usr/bin/env bash
# ffs_performance_delta_closeout_e2e.sh - closeout gate for bd-rchk5.4.
#
# Validates that measured performance artifacts become tracker-backed signal:
# regressions, missing references, and unmeasured claims must all point to
# concrete follow-up beads before the report is accepted.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_performance_delta_closeout}"
case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_PERFORMANCE_DELTA_CLOSEOUT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_PERFORMANCE_DELTA_CLOSEOUT_SKIP_SELF_CHECK:-0}"

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
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" e2e_rch_capture "$log_path" "$@"
}

log_failure_tail() {
    local log_path="$1"
    if [[ -s "$log_path" ]]; then
        e2e_log "Failure tail for ${log_path}:"
        tail -n 80 "$log_path"
    fi
}

run_closeout_report_capture() {
    local log_path="$1"
    shift

    run_rch_capture "$log_path" cargo run --quiet -p ffs-harness -- performance-delta-closeout \
        --config benchmarks/performance_delta_closeout.json \
        --issues "$ISSUES_JSONL" "$@"
}

run_closeout_missing_followup_capture() {
    local log_path="$1"

    run_rch_capture "$log_path" cargo run --quiet -p ffs-harness -- performance-delta-closeout \
        --config benchmarks/performance_delta_closeout.json \
        --issues "$BAD_ISSUES_JSONL"
}

run_closeout_unit_tests_capture() {
    local log_path="$1"

    run_rch_capture "$log_path" cargo test -p ffs-harness performance_delta_closeout -- --nocapture
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_PERFORMANCE_DELTA_CLOSEOUT_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected performance-delta fixture rch invocation: $*" >&2
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
        echo "unknown performance-delta fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

finish_expected_failure() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "[RCH] remote worker=fixture exit=1"
        echo "Remote command finished: exit=1"
    fi
    exit 1
}

emit_report_json() {
    cat <<'JSON'
{
  "schema_version": 1,
  "closeout_id": "fixture-performance-delta-closeout",
  "valid": true,
  "errors": [],
  "row_count": 11,
  "rows_requiring_follow_up": 8,
  "rows": [
    {
      "operation": "mount_cold",
      "classification": "regression",
      "follow_up_bead": "bd-rchk5.5",
      "follow_up_present": true
    },
    {
      "operation": "mount_warm",
      "classification": "regression",
      "follow_up_bead": "bd-rchk5.6",
      "follow_up_present": true
    },
    {
      "operation": "mount_recovery",
      "classification": "regression",
      "follow_up_bead": "bd-rchk5.7",
      "follow_up_present": true
    },
    {
      "operation": "block_cache_sharded_arc_concurrent_hot_read_64threads",
      "classification": "missing_reference",
      "follow_up_bead": "bd-rchk5.8",
      "release_claim_state": "reference_limited_experimental",
      "raw_logs": "artifacts/rch/fixture/arc.log",
      "comparison_target_rationale": "reference artifact absent in fixture",
      "release_wording": "experimental reference-limited claim only",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "operation": "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
      "classification": "missing_reference",
      "follow_up_bead": "bd-rchk5.8",
      "release_claim_state": "reference_limited_experimental",
      "raw_logs": "artifacts/rch/fixture/s3fifo.log",
      "comparison_target_rationale": "reference artifact absent in fixture",
      "release_wording": "experimental reference-limited claim only",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "operation": "cli_metadata_parse_conformance",
      "classification": "missing_reference",
      "follow_up_bead": "bd-rchk5.8",
      "release_claim_state": "reference_limited_experimental",
      "raw_logs": "artifacts/rch/fixture/cli.log",
      "comparison_target_rationale": "reference artifact absent in fixture",
      "release_wording": "experimental reference-limited claim only",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "operation": "repair_symbol_refresh_staleness_latency",
      "classification": "missing_reference",
      "follow_up_bead": "bd-rchk5.8",
      "release_claim_state": "reference_limited_experimental",
      "raw_logs": "artifacts/rch/fixture/repair.log",
      "comparison_target_rationale": "reference artifact absent in fixture",
      "release_wording": "experimental reference-limited claim only",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "operation": "wal_commit_4k_sync",
      "classification": "missing_reference",
      "follow_up_bead": "bd-rchk5.8",
      "release_claim_state": "reference_limited_experimental",
      "raw_logs": "artifacts/rch/fixture/wal.log",
      "comparison_target_rationale": "reference artifact absent in fixture",
      "release_wording": "experimental reference-limited claim only",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "operation": "capability_large_host_swarm",
      "classification": "pending_capability",
      "follow_up_bead": "bd-9vzzk",
      "follow_up_present": true
    },
    {
      "operation": "long_campaign_writeback_cache_smoke",
      "classification": "unmeasured",
      "follow_up_bead": "bd-t21em",
      "follow_up_present": true
    },
    {
      "operation": "extent_lookup_hot_path",
      "classification": "improved",
      "follow_up_present": false
    }
  ],
  "follow_up_payloads": [
    {
      "follow_up_bead": "bd-rchk5.5",
      "classification": "regression",
      "workload_id": "mount_cold",
      "command_template": "cargo bench -p ffs-harness mount_cold",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-baseline-mount-cold",
      "current_artifact_hash": "fixture-current-mount-cold",
      "observed_value": 12.0,
      "threshold_value": 5.0,
      "unit": "p99_delta_percent",
      "suspected_subsystem": "mount",
      "raw_logs": "artifacts/rch/fixture/mount_cold.log",
      "validation_command": "cargo bench -p ffs-harness mount_cold"
    },
    {
      "follow_up_bead": "bd-rchk5.6",
      "classification": "regression",
      "workload_id": "mount_warm",
      "command_template": "cargo bench -p ffs-harness mount_warm",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-baseline-mount-warm",
      "current_artifact_hash": "fixture-current-mount-warm",
      "observed_value": 10.0,
      "threshold_value": 5.0,
      "unit": "p99_delta_percent",
      "suspected_subsystem": "mount",
      "raw_logs": "artifacts/rch/fixture/mount_warm.log",
      "validation_command": "cargo bench -p ffs-harness mount_warm"
    },
    {
      "follow_up_bead": "bd-rchk5.7",
      "classification": "regression",
      "workload_id": "mount_recovery",
      "command_template": "cargo bench -p ffs-harness mount_recovery",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-baseline-mount-recovery",
      "current_artifact_hash": "fixture-current-mount-recovery",
      "observed_value": 9.0,
      "threshold_value": 5.0,
      "unit": "p99_delta_percent",
      "suspected_subsystem": "mount",
      "raw_logs": "artifacts/rch/fixture/mount_recovery.log",
      "validation_command": "cargo bench -p ffs-harness mount_recovery"
    },
    {
      "follow_up_bead": "bd-rchk5.8",
      "classification": "missing_reference",
      "workload_id": "block_cache_sharded_arc_concurrent_hot_read_64threads",
      "command_template": "cargo bench -p ffs-harness block_cache_arc",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-missing-reference-arc",
      "current_artifact_hash": "fixture-current-arc",
      "observed_value": 0.0,
      "threshold_value": 0.0,
      "unit": "reference_required",
      "suspected_subsystem": "block_cache",
      "raw_logs": "artifacts/rch/fixture/arc.log",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "follow_up_bead": "bd-rchk5.8",
      "classification": "missing_reference",
      "workload_id": "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
      "command_template": "cargo bench -p ffs-harness block_cache_s3fifo",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-missing-reference-s3fifo",
      "current_artifact_hash": "fixture-current-s3fifo",
      "observed_value": 0.0,
      "threshold_value": 0.0,
      "unit": "reference_required",
      "suspected_subsystem": "block_cache",
      "raw_logs": "artifacts/rch/fixture/s3fifo.log",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "follow_up_bead": "bd-rchk5.8",
      "classification": "missing_reference",
      "workload_id": "cli_metadata_parse_conformance",
      "command_template": "cargo bench -p ffs-harness cli_metadata",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-missing-reference-cli",
      "current_artifact_hash": "fixture-current-cli",
      "observed_value": 0.0,
      "threshold_value": 0.0,
      "unit": "reference_required",
      "suspected_subsystem": "cli",
      "raw_logs": "artifacts/rch/fixture/cli.log",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "follow_up_bead": "bd-rchk5.8",
      "classification": "missing_reference",
      "workload_id": "repair_symbol_refresh_staleness_latency",
      "command_template": "cargo bench -p ffs-harness repair_symbol_refresh",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-missing-reference-repair",
      "current_artifact_hash": "fixture-current-repair",
      "observed_value": 0.0,
      "threshold_value": 0.0,
      "unit": "reference_required",
      "suspected_subsystem": "repair",
      "raw_logs": "artifacts/rch/fixture/repair.log",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    },
    {
      "follow_up_bead": "bd-rchk5.8",
      "classification": "missing_reference",
      "workload_id": "wal_commit_4k_sync",
      "command_template": "cargo bench -p ffs-harness wal_commit_4k_sync",
      "profile": "release-perf",
      "environment_manifest_id": "fixture-env",
      "baseline_artifact_hash": "fixture-missing-reference-wal",
      "current_artifact_hash": "fixture-current-wal",
      "observed_value": 0.0,
      "threshold_value": 0.0,
      "unit": "reference_required",
      "suspected_subsystem": "wal",
      "raw_logs": "artifacts/rch/fixture/wal.log",
      "validation_command": "cargo run -p ffs-harness -- performance-delta-closeout"
    }
  ]
}
JSON
}

emit_report_markdown() {
    cat <<'MD'
# Performance Delta Closeout

Fixture summary with follow-up beads bd-rchk5.5, bd-rchk5.6, bd-rchk5.7, bd-rchk5.8, bd-9vzzk, and bd-t21em.
MD
}

case "$command_text" in
    *"performance-delta-closeout"*issues_missing_mount_cold_followup*)
        echo "performance delta closeout validation failed: missing follow-up bead"
        finish_expected_failure
        ;;
    *"performance-delta-closeout"*--format*markdown*)
        emit_report_markdown
        finish_success
        ;;
    *"performance-delta-closeout"*)
        emit_report_json
        finish_success
        ;;
    "cargo test -p ffs-harness performance_delta_closeout -- --nocapture")
        echo "test performance_delta_closeout::tests::fixture_contract ... ok"
        echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
        finish_success
        ;;
    *)
        echo "unexpected performance-delta fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/performance_delta_closeout_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_PERFORMANCE_DELTA_CLOSEOUT_SELF_CHECK=0 \
        FFS_PERFORMANCE_DELTA_CLOSEOUT_SKIP_SELF_CHECK=1 \
        FFS_PERFORMANCE_DELTA_CLOSEOUT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_performance_delta_closeout_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic performance-delta closeout wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-performance-delta-closeout-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "performance_delta_closeout_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_delta_closeout_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_delta_closeout_followups" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_delta_closeout_missing_followup_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_delta_closeout_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "performance_delta_closeout_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "performance_delta_closeout_fixture_complete_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "performance_delta_closeout_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "performance_delta_closeout_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "performance_delta_closeout_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "performance_delta_closeout_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_performance_delta_closeout"
e2e_print_env

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

CONFIG_JSON="$REPO_ROOT/benchmarks/performance_delta_closeout.json"
REPORT_JSON="$E2E_LOG_DIR/performance_delta_closeout.json"
SUMMARY_MD="$E2E_LOG_DIR/performance_delta_closeout.md"
VALIDATE_RAW="$E2E_LOG_DIR/performance_delta_closeout.raw"
VALIDATE_MD_RAW="$E2E_LOG_DIR/performance_delta_closeout_md.raw"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/performance_delta_closeout"
mkdir -p "$RCH_INPUT_DIR"
ISSUES_JSONL="$RCH_INPUT_DIR/issues.jsonl"
BAD_ISSUES_JSONL="$RCH_INPUT_DIR/issues_missing_mount_cold_followup.jsonl"
BAD_RAW="$E2E_LOG_DIR/performance_delta_closeout_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/performance_delta_closeout_unit_tests.log"
cat >"$ISSUES_JSONL" <<'JSONL'
{"id":"bd-rchk5.5"}
{"id":"bd-rchk5.6"}
{"id":"bd-rchk5.7"}
{"id":"bd-rchk5.8"}
{"id":"bd-9vzzk"}
{"id":"bd-t21em"}
JSONL
grep -v '"id":"bd-rchk5.5"' "$ISSUES_JSONL" >"$BAD_ISSUES_JSONL"

e2e_step "Scenario 1: performance delta closeout module and CLI are wired"
if grep -q "pub mod performance_delta_closeout" crates/ffs-harness/src/lib.rs \
    && grep -q "performance-delta-closeout" crates/ffs-harness/src/main.rs \
    && [[ -f "$CONFIG_JSON" ]]; then
    scenario_result "performance_delta_closeout_cli_wired" "PASS" "module CLI and config present"
else
    scenario_result "performance_delta_closeout_cli_wired" "FAIL" "missing module CLI or config"
fi

e2e_step "Scenario 2: checked-in closeout config validates artifacts"
if run_closeout_report_capture "$VALIDATE_RAW" \
    && run_closeout_report_capture "$VALIDATE_MD_RAW" --format markdown \
    && python3 - "$VALIDATE_RAW" "$REPORT_JSON" "$VALIDATE_MD_RAW" "$SUMMARY_MD" <<'PY'
from __future__ import annotations

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
    if isinstance(obj, dict) and obj.get("schema_version") == 1 and "closeout_id" in obj:
        with open(json_report, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("performance delta closeout JSON object not found in command output")

markdown = open(md_raw, encoding="utf-8", errors="replace").read()
marker = "# Performance Delta Closeout"
index = markdown.find(marker)
if index < 0:
    raise SystemExit("performance delta closeout Markdown marker not found")
with open(md_report, "w", encoding="utf-8") as handle:
    handle.write(markdown[index:])
PY
then
    scenario_result "performance_delta_closeout_validates" "PASS" "closeout report accepted"
else
    log_failure_tail "$VALIDATE_RAW"
    log_failure_tail "$VALIDATE_MD_RAW"
    scenario_result "performance_delta_closeout_validates" "FAIL" "closeout report rejected"
fi

e2e_step "Scenario 3: closeout report preserves regressions and follow-ups"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(f"report invalid: {report['errors']}")
if report["row_count"] < 10:
    raise SystemExit("expected core, mounted, pending, and deferred rows")

rows = {(row["operation"], row["classification"], row.get("source_artifact", "")): row for row in report["rows"]}

required_regressions = {
    "mount_cold": "bd-rchk5.5",
    "mount_warm": "bd-rchk5.6",
    "mount_recovery": "bd-rchk5.7",
}
for operation, bead in required_regressions.items():
    matches = [
        row for row in report["rows"]
        if row["operation"] == operation
        and row["classification"] == "regression"
        and row.get("follow_up_bead") == bead
    ]
    if not matches:
        raise SystemExit(f"missing regression row for {operation} -> {bead}")
    if not matches[0]["follow_up_present"]:
        raise SystemExit(f"follow-up bead missing for {operation}")

missing_reference_ops = {
    "block_cache_sharded_arc_concurrent_hot_read_64threads",
    "block_cache_sharded_s3fifo_concurrent_hot_read_64threads",
    "cli_metadata_parse_conformance",
    "repair_symbol_refresh_staleness_latency",
    "wal_commit_4k_sync",
}
observed_missing = {
    row["operation"] for row in report["rows"]
    if row["classification"] == "missing_reference"
    and row.get("follow_up_bead") == "bd-rchk5.8"
}
if not missing_reference_ops <= observed_missing:
    raise SystemExit(f"missing reference follow-ups absent: {missing_reference_ops - observed_missing}")

for row in report["rows"]:
    if row["operation"] in missing_reference_ops and row["classification"] == "missing_reference":
        if row["release_claim_state"] != "reference_limited_experimental":
            raise SystemExit(f"missing-reference row lacks explicit no-reference claim state: {row}")
        for field in ("raw_logs", "comparison_target_rationale", "release_wording", "validation_command"):
            if not row.get(field):
                raise SystemExit(f"missing-reference row lacks {field}: {row}")
        wording = row["release_wording"].lower()
        if "regression-free" in wording or "regression free" in wording:
            raise SystemExit(f"missing-reference row overclaims release wording: {row}")

pending = [
    row for row in report["rows"]
    if row["classification"] == "pending_capability"
    and row.get("follow_up_bead") == "bd-9vzzk"
]
if not pending:
    raise SystemExit("missing pending capability row linked to bd-9vzzk")

long_campaign = [
    row for row in report["rows"]
    if row["operation"] == "long_campaign_writeback_cache_smoke"
    and row["classification"] == "unmeasured"
    and row.get("follow_up_bead") == "bd-t21em"
]
if not long_campaign:
    raise SystemExit("missing long-campaign deferred claim row")

if not any(row["classification"] == "improved" for row in report["rows"]):
    raise SystemExit("expected at least one improved core benchmark row")
for bead in ("bd-rchk5.5", "bd-rchk5.6", "bd-rchk5.7", "bd-rchk5.8", "bd-9vzzk", "bd-t21em"):
    if bead not in summary:
        raise SystemExit(f"summary missing {bead}")

payloads = report.get("follow_up_payloads", [])
if len(payloads) != report["rows_requiring_follow_up"]:
    raise SystemExit("expected one deduplicated follow-up payload per required row")
seen_payload_keys = set()
required_payload_fields = {
    "follow_up_bead",
    "classification",
    "workload_id",
    "command_template",
    "profile",
    "environment_manifest_id",
    "baseline_artifact_hash",
    "current_artifact_hash",
    "observed_value",
    "threshold_value",
    "unit",
    "suspected_subsystem",
    "raw_logs",
    "validation_command",
}
for payload in payloads:
    missing = [field for field in required_payload_fields if field not in payload]
    if missing:
        raise SystemExit(f"payload missing fields: {missing}")
    if not payload["raw_logs"]:
        raise SystemExit(f"payload missing raw logs: {payload}")
    key = (payload["follow_up_bead"], payload["classification"], payload["workload_id"])
    if key in seen_payload_keys:
        raise SystemExit(f"duplicate follow-up payload: {key}")
    seen_payload_keys.add(key)

if not any(
    payload["workload_id"] == "mount_cold"
    and payload["follow_up_bead"] == "bd-rchk5.5"
    and payload["unit"] in {"p99_delta_percent", "throughput_delta_percent"}
    for payload in payloads
):
    raise SystemExit("missing bisect-ready mount_cold regression payload")
PY
then
    scenario_result "performance_delta_closeout_followups" "PASS" "regression and missing-reference rows linked"
else
    scenario_result "performance_delta_closeout_followups" "FAIL" "closeout report lost required follow-up signal"
fi

e2e_step "Scenario 4: missing follow-up bead fails closed"
if run_closeout_missing_followup_capture "$BAD_RAW"; then
    scenario_result "performance_delta_closeout_missing_followup_rejected" "FAIL" "missing follow-up bead accepted"
elif grep -q "performance delta closeout validation failed" "$BAD_RAW"; then
    scenario_result "performance_delta_closeout_missing_followup_rejected" "PASS" "missing follow-up bead rejected"
else
    log_failure_tail "$BAD_RAW"
    scenario_result "performance_delta_closeout_missing_followup_rejected" "FAIL" "unexpected failure mode"
fi

e2e_step "Scenario 5: unit tests cover closeout classification and checked-in config"
if run_closeout_unit_tests_capture "$UNIT_LOG"; then
    scenario_result "performance_delta_closeout_unit_tests" "PASS" "unit tests passed"
else
    log_failure_tail "$UNIT_LOG"
    scenario_result "performance_delta_closeout_unit_tests" "FAIL" "unit tests failed"
fi

e2e_log ""
e2e_log "Scenario totals: total=${TOTAL} pass=${PASS_COUNT} fail=${FAIL_COUNT}"

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    exit 1
fi

e2e_pass
