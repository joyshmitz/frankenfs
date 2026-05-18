#!/usr/bin/env bash
# ffs_repair_confidence_lab_e2e.sh - mutation-safety threshold smoke for bd-rchk0.5.3.1.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_confidence_lab}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_REPAIR_CONFIDENCE_LAB_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REPAIR_CONFIDENCE_LAB_SKIP_SELF_CHECK:-0}"

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
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-240}"
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

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REPAIR_CONFIDENCE_LAB_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown repair confidence lab fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab"*"--spec-json-env"*)
        echo "repair confidence lab validation failed: fixture invalid lab rejected"
        exit 1
        ;;
    *"cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab"*"--format markdown"*)
        cat <<'MD'
# Repair Confidence Lab Summary

- mutating_repair_verified
- unsafe_to_repair
- dry_run_success
- detect_only
- failed_verification
- verification_failed_refused
MD
        ;;
    *"cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab"*"--format json"*)
        cat <<'JSON'
{
  "bead_id": "bd-rchk0.5.3.1",
  "by_outcome": {
    "detect_only": 1,
    "dry_run_success": 1,
    "failed_verification": 1,
    "mutating_repair_verified": 1,
    "unsafe_to_repair": 1
  },
  "calibration_case_count": 9,
  "calibration_reports": [
    {
      "corpus_id": "cal_recoverable_single_block",
      "corruption_class": "recoverable_single_block",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_recoverable_single_block ledger_row_ids=1"
    },
    {
      "corpus_id": "cal_recoverable_multi_block",
      "corruption_class": "recoverable_multi_block_within_budget",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_recoverable_multi_block ledger_row_ids=2",
      "observed_outcome": "mutating_repair_verified"
    },
    {
      "corpus_id": "cal_unrecoverable_beyond_budget",
      "corruption_class": "unrecoverable_beyond_budget",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_unrecoverable_beyond_budget ledger_row_ids=3",
      "refusal_reason": "beyond_symbol_budget"
    },
    {
      "corpus_id": "cal_stale_symbols",
      "corruption_class": "stale_symbols",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_stale_symbols ledger_row_ids=4",
      "refusal_reason": "stale_symbols"
    },
    {
      "corpus_id": "cal_insufficient_symbols",
      "corruption_class": "insufficient_symbols",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_insufficient_symbols ledger_row_ids=5",
      "refusal_reason": "insufficient_symbols"
    },
    {
      "corpus_id": "cal_ledger_tamper",
      "corruption_class": "ledger_tamper",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_ledger_tamper ledger_row_ids=6",
      "refusal_reason": "ledger_tamper"
    },
    {
      "corpus_id": "cal_wrong_image_ledger",
      "corruption_class": "wrong_image_ledger",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_wrong_image_ledger ledger_row_ids=7",
      "refusal_reason": "wrong_image_ledger"
    },
    {
      "corpus_id": "cal_hostile_path",
      "corruption_class": "hostile_path",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_hostile_path ledger_row_ids=8",
      "refusal_reason": "hostile_path"
    },
    {
      "corpus_id": "cal_verification_failure",
      "corruption_class": "verification_failure",
      "log_line": "REPAIR_CONFIDENCE_CALIBRATION corpus_id=cal_verification_failure ledger_row_ids=9"
    }
  ],
  "errors": [],
  "mutation_allowed_count": 1,
  "mutation_refused_count": 4,
  "scenario_reports": [
    {
      "log_line": "REPAIR_CONFIDENCE_DECISION scenario_id=repair_mutate_verified_single_block reproduction_command=repair --mutate",
      "mutation_allowed": true,
      "scenario_id": "repair_mutate_verified_single_block",
      "threshold_decision": "mutate_allowed"
    },
    {
      "log_line": "REPAIR_CONFIDENCE_DECISION scenario_id=repair_refuse_low_confidence_multi_block reproduction_command=repair --refuse",
      "mutation_allowed": false,
      "scenario_id": "repair_refuse_low_confidence_multi_block",
      "threshold_decision": "unsafe_refused"
    },
    {
      "log_line": "REPAIR_CONFIDENCE_DECISION scenario_id=repair_failed_verification_hash_mismatch reproduction_command=repair --verify",
      "mutation_allowed": false,
      "scenario_id": "repair_failed_verification_hash_mismatch",
      "threshold_decision": "verification_failed_refused"
    },
    {
      "log_line": "REPAIR_CONFIDENCE_DECISION scenario_id=repair_dry_run_single_block_recoverable reproduction_command=repair --dry-run",
      "mutation_allowed": false,
      "scenario_id": "repair_dry_run_single_block_recoverable",
      "threshold_decision": "dry_run_ready"
    },
    {
      "log_line": "REPAIR_CONFIDENCE_DECISION scenario_id=repair_detect_only_metadata_mismatch reproduction_command=repair --detect-only",
      "mutation_allowed": false,
      "scenario_id": "repair_detect_only_metadata_mismatch",
      "threshold_decision": "detection_only"
    }
  ],
  "valid": true
}
JSON
        ;;
    *"cargo test -p ffs-harness --lib repair_confidence_lab"*)
        printf '%s\n' \
            "running 5 tests" \
            "test repair_confidence_lab::tests::fixture_report_contract ... ok" \
            "test repair_confidence_lab::tests::fixture_refusal_reasons ... ok" \
            "test repair_confidence_lab::tests::fixture_calibration_classes ... ok" \
            "test repair_confidence_lab::tests::fixture_markdown_summary ... ok" \
            "test repair_confidence_lab::tests::fixture_invalid_variants ... ok" \
            "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/repair_confidence_lab_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REPAIR_CONFIDENCE_LAB_SELF_CHECK=0 \
        FFS_REPAIR_CONFIDENCE_LAB_SKIP_SELF_CHECK=1 \
        FFS_REPAIR_CONFIDENCE_LAB_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_repair_confidence_lab_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic repair confidence lab wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-repair-confidence-lab-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "repair_confidence_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_confidence_lab_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_confidence_decision_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_confidence_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_confidence_docs_contract" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_confidence_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "repair_confidence_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_confidence_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "repair_confidence_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_confidence_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "repair_confidence_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_confidence_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

extract_json_report() {
    local input_path="$1"
    local output_path="$2"
    python3 - "$input_path" "$output_path" <<'PY'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for idx, ch in enumerate(text):
    if ch != "{":
        continue
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        continue
    dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
    raise SystemExit(0)
raise SystemExit(f"no JSON report found in {source}")
PY
}

extract_markdown_summary() {
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
start = text.find("# Repair Confidence Lab Summary")
if start < 0:
    raise SystemExit(f"no Markdown summary found in {source}")
summary = text[start:]
cut_points = [
    idx for marker in ("\n  2026-", "\n[RCH] ")
    if (idx := summary.find(marker)) >= 0
]
if cut_points:
    summary = summary[:min(cut_points)]
dest.write_text(summary.rstrip() + "\n", encoding="utf-8")
PY
}

validate_checked_in_lab_remote() {
    local log_path="$1"
    local spec_json="$2"
    local report_json="$3"
    local summary_md="$4"
    local summary_raw="${summary_md%.md}.raw"
    if run_rch_capture "$log_path" cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab \
        --spec "$spec_json" \
        --format json \
        && extract_json_report "$log_path" "$report_json" \
        && run_rch_capture "$summary_raw" cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab \
            --spec "$spec_json" \
            --format markdown \
        && extract_markdown_summary "$summary_raw" "$summary_md"; then
        return 0
    fi
    return 1
}

validate_bad_lab_remote() {
    local log_path="$1"
    local bad_json="$2"
    local bad_payload
    bad_payload="$(tr -d '\n' <"$bad_json")"
    (
        export REPAIR_CONFIDENCE_SPEC_JSON="$bad_payload"
        export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}REPAIR_CONFIDENCE_SPEC_JSON"
        run_rch_capture "$log_path" cargo run --quiet -p ffs-harness -- validate-repair-confidence-lab \
            --spec-json-env REPAIR_CONFIDENCE_SPEC_JSON \
            --format json
    )
}

e2e_init "ffs_repair_confidence_lab"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

SPEC_JSON="$REPO_ROOT/docs/repair-confidence-mutation-safety.json"
REPORT_JSON="$E2E_LOG_DIR/repair_confidence_lab_report.json"
SUMMARY_MD="$E2E_LOG_DIR/repair_confidence_lab_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/repair_confidence_lab_validate.raw"
BAD_MISSING_LOG="$E2E_LOG_DIR/bad_missing_log.json"
BAD_UNSAFE_MUTATION="$E2E_LOG_DIR/bad_unsafe_mutation.json"
BAD_EXPERIMENTAL_NO_FOLLOWUP="$E2E_LOG_DIR/bad_experimental_no_followup.json"
BAD_MISSING_ARTIFACTS="$E2E_LOG_DIR/bad_missing_artifacts.json"
BAD_CALIBRATION_CLASS="$E2E_LOG_DIR/bad_calibration_class.json"
BAD_CALIBRATION_LEDGER="$E2E_LOG_DIR/bad_calibration_ledger.json"
BAD_RAW="$E2E_LOG_DIR/repair_confidence_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/repair_confidence_lab_unit_tests.log"

e2e_step "Scenario 1: repair confidence lab module and CLI are wired"
if grep -q "pub mod repair_confidence_lab" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-repair-confidence-lab" crates/ffs-harness/src/main.rs; then
    scenario_result "repair_confidence_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "repair_confidence_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in repair confidence lab validates"
if validate_checked_in_lab_remote "$VALIDATE_RAW" "$SPEC_JSON" "$REPORT_JSON" "$SUMMARY_MD"; then
    scenario_result "repair_confidence_lab_validates" "PASS" "checked-in lab accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "repair_confidence_lab_validates" "FAIL" "checked-in lab rejected"
fi

e2e_step "Scenario 3: report covers mutation, refusal, dry-run, detect-only, and verification failure"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if not report["valid"]:
    raise SystemExit(report["errors"])
if report["bead_id"] != "bd-rchk0.5.3.1":
    raise SystemExit("wrong bead id")
required = {
    "detect_only",
    "dry_run_success",
    "mutating_repair_verified",
    "unsafe_to_repair",
    "failed_verification",
}
if set(report["by_outcome"]) != required:
    raise SystemExit(f"unexpected outcome coverage: {report['by_outcome']}")
if report["mutation_allowed_count"] != 1:
    raise SystemExit("exactly one scenario should allow mutation")
if report["mutation_refused_count"] < 2:
    raise SystemExit("expected at least two explicit mutation refusals")
if report["calibration_case_count"] != 9:
    raise SystemExit(f"expected 9 calibration cases, got {report['calibration_case_count']}")
required_calibration = {
    "recoverable_single_block",
    "recoverable_multi_block_within_budget",
    "unrecoverable_beyond_budget",
    "stale_symbols",
    "insufficient_symbols",
    "ledger_tamper",
    "wrong_image_ledger",
    "hostile_path",
    "verification_failure",
}
observed_calibration = {row["corruption_class"] for row in report["calibration_reports"]}
if observed_calibration != required_calibration:
    raise SystemExit(f"unexpected calibration classes: {observed_calibration}")
required_refusals = {
    "beyond_symbol_budget",
    "stale_symbols",
    "insufficient_symbols",
    "ledger_tamper",
    "wrong_image_ledger",
    "hostile_path",
}
observed_refusals = {
    row.get("refusal_reason")
    for row in report["calibration_reports"]
    if row.get("refusal_reason")
}
if not required_refusals.issubset(observed_refusals):
    raise SystemExit(f"missing refusal reasons: {required_refusals - observed_refusals}")

decisions = {row["scenario_id"]: row for row in report["scenario_reports"]}
mutating = decisions["repair_mutate_verified_single_block"]
if not mutating["mutation_allowed"] or mutating["threshold_decision"] != "mutate_allowed":
    raise SystemExit("verified mutating scenario was not allowed")
unsafe = decisions["repair_refuse_low_confidence_multi_block"]
if unsafe["mutation_allowed"] or unsafe["threshold_decision"] != "unsafe_refused":
    raise SystemExit("unsafe scenario did not refuse mutation")
failed = decisions["repair_failed_verification_hash_mismatch"]
if failed["mutation_allowed"] or failed["threshold_decision"] != "verification_failed_refused":
    raise SystemExit("failed verification scenario did not refuse mutation")
dry_run = decisions["repair_dry_run_single_block_recoverable"]
if dry_run["mutation_allowed"] or dry_run["threshold_decision"] != "dry_run_ready":
    raise SystemExit("dry-run scenario lost dry-run-only classification")
detect = decisions["repair_detect_only_metadata_mismatch"]
if detect["mutation_allowed"] or detect["threshold_decision"] != "detection_only":
    raise SystemExit("detect-only scenario lost detection-only classification")

for row in decisions.values():
    if "REPAIR_CONFIDENCE_DECISION" not in row["log_line"]:
        raise SystemExit(f"missing structured log marker for {row['scenario_id']}")
    if "reproduction_command=" not in row["log_line"]:
        raise SystemExit(f"missing reproduction command in log for {row['scenario_id']}")
if "verification_failed_refused" not in summary:
    raise SystemExit("summary missing verification refusal")
calibration = {row["corpus_id"]: row for row in report["calibration_reports"]}
if calibration["cal_recoverable_multi_block"]["observed_outcome"] != "mutating_repair_verified":
    raise SystemExit("multi-block calibration did not reach mutating verified outcome")
if calibration["cal_wrong_image_ledger"]["refusal_reason"] != "wrong_image_ledger":
    raise SystemExit("wrong-image ledger refusal not preserved")
for row in calibration.values():
    if "REPAIR_CONFIDENCE_CALIBRATION" not in row["log_line"]:
        raise SystemExit(f"missing calibration log marker for {row['corpus_id']}")
    if "ledger_row_ids=" not in row["log_line"]:
        raise SystemExit(f"missing ledger row ids for {row['corpus_id']}")
PY
then
    scenario_result "repair_confidence_decision_coverage" "PASS" "decision report covers all safety outcomes"
else
    scenario_result "repair_confidence_decision_coverage" "FAIL" "decision report contract failed"
fi

e2e_step "Scenario 4: invalid repair confidence variants fail closed"
python3 - "$SPEC_JSON" "$BAD_MISSING_LOG" "$BAD_UNSAFE_MUTATION" "$BAD_EXPERIMENTAL_NO_FOLLOWUP" "$BAD_MISSING_ARTIFACTS" "$BAD_CALIBRATION_CLASS" "$BAD_CALIBRATION_LEDGER" <<'PY'
import json
import pathlib
import sys

source, missing_log, unsafe_mutation, no_followup, missing_artifacts, bad_calibration_class, bad_calibration_ledger = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

variant = json.loads(json.dumps(base))
variant["required_log_fields"] = [
    field for field in variant["required_log_fields"]
    if field != "verification_verdict"
]
missing_log.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for scenario in variant["scenarios"]:
    if scenario["scenario_id"] == "repair_refuse_low_confidence_multi_block":
        scenario["expected_outcome"] = "mutating_repair_verified"
unsafe_mutation.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for threshold in variant["thresholds"]:
    if threshold["threshold_id"] == "experimental_refusal_calibration_gate":
        threshold.pop("follow_up_bead", None)
no_followup.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
variant["scenarios"][0]["expected_artifacts"] = []
missing_artifacts.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
variant["calibration_corpus"] = [
    row for row in variant["calibration_corpus"]
    if row["corruption_class"] != "wrong_image_ledger"
]
bad_calibration_class.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")

variant = json.loads(json.dumps(base))
for row in variant["calibration_corpus"]:
    if row["corpus_id"] == "cal_wrong_image_ledger":
        row["ledger_expectation"]["require_image_hash_match"] = True
bad_calibration_ledger.write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_MISSING_LOG" "$BAD_UNSAFE_MUTATION" "$BAD_EXPERIMENTAL_NO_FOLLOWUP" "$BAD_MISSING_ARTIFACTS" "$BAD_CALIBRATION_CLASS" "$BAD_CALIBRATION_LEDGER"; do
    if validate_bad_lab_remote "$BAD_RAW" "$bad"; then
        e2e_log "Unexpectedly accepted invalid repair confidence lab: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$BAD_RAW"; then
        e2e_log "Invalid repair confidence lab used local RCH fallback: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "repair confidence lab validation failed\\|invalid repair confidence lab JSON" "$BAD_RAW"; then
        e2e_log "Invalid repair confidence lab failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "repair_confidence_invalid_variants_rejected" "PASS" "bad log/outcome/follow-up/artifact/calibration variants rejected"
else
    scenario_result "repair_confidence_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: docs contract distinguishes mutating repair, detection-only scrub, and unsupported classes"
if grep -q "Repair Confidence Lab Contract" scripts/e2e/README.md \
    && grep -q "automatic mutating repair" scripts/e2e/README.md \
    && grep -q "detection-only scrub" scripts/e2e/README.md \
    && grep -q "unsupported corruption classes" scripts/e2e/README.md; then
    scenario_result "repair_confidence_docs_contract" "PASS" "docs distinguish repair support states"
else
    scenario_result "repair_confidence_docs_contract" "FAIL" "missing repair confidence docs wording"
fi

e2e_step "Scenario 6: repair confidence lab unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib repair_confidence_lab -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "repair_confidence_unit_tests" "PASS" "repair confidence unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "repair_confidence_unit_tests" "FAIL" "repair confidence unit tests failed"
fi

e2e_log "Repair confidence lab spec: $SPEC_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Markdown summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Repair confidence lab scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Repair confidence lab scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
