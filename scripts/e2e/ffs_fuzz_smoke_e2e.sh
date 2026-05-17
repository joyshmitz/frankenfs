#!/usr/bin/env bash
# ffs_fuzz_smoke_e2e.sh - deterministic fixed-seed parser smoke gate for bd-u8hx5.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
}

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fuzz_smoke}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_CAPTURE_VISIBILITY="${FFS_FUZZ_SMOKE_RCH_VISIBILITY:-summary}"
SELF_CHECK="${FFS_FUZZ_SMOKE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_FUZZ_SMOKE_SKIP_SELF_CHECK:-0}"

e2e_init "ffs_fuzz_smoke"

MANIFEST_PATH="${FFS_FUZZ_SMOKE_MANIFEST:-$REPO_ROOT/tests/fuzz-smoke/fuzz_smoke_manifest.json}"
REPORT_JSON="$E2E_LOG_DIR/fuzz_smoke_report.json"
QA_ARTIFACT_JSON="$E2E_LOG_DIR/fuzz_smoke_qa_artifact.json"
STDOUT_PATH="$E2E_LOG_DIR/fuzz_smoke.stdout"
STDERR_PATH="$E2E_LOG_DIR/fuzz_smoke.stderr"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case_name="${FFS_FUZZ_SMOKE_FIXTURE_CASE:-valid}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi

emit_valid_report() {
    cat <<'JSON'
{
  "valid": true,
  "schema_version": 1,
  "corpus_id": "frankenfs_deterministic_fuzz_smoke_v1",
  "bead_id": "bd-u8hx5",
  "corpus_version": "fixture",
  "seed_ids": ["fixture_valid_seed"],
  "corpus_checksum": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "target_summary": {"ext4_superblock": 1},
  "outcome_summary": {"accepted": 1},
  "errors": [],
  "seed_results": [
    {
      "seed_id": "fixture_valid_seed",
      "sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "source": "tests/fuzz_corpus/README.md",
      "provenance": "fixture valid seed",
      "byte_len": 4,
      "duration_ms": 1,
      "resource_budget": {"max_input_bytes": 16, "max_duration_ms": 10, "max_artifact_bytes": 128},
      "minimization_status": "minimized",
      "replay_command": "fixture replay",
      "quarantine_status": "none",
      "class_matched": true,
      "error_detail_matched": true,
      "corpus_checksum_matched": true,
      "timed_out": false,
      "actual_class": "accepted"
    }
  ]
}
JSON
}

emit_unowned_failure_report() {
    cat <<'JSON'
{
  "valid": true,
  "schema_version": 1,
  "corpus_id": "frankenfs_deterministic_fuzz_smoke_v1",
  "bead_id": "bd-u8hx5",
  "corpus_version": "fixture",
  "seed_ids": ["fixture_unowned_failure"],
  "corpus_checksum": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  "target_summary": {"ext4_superblock": 1},
  "outcome_summary": {"panic": 1},
  "errors": [],
  "seed_results": [
    {
      "seed_id": "fixture_unowned_failure",
      "sha256": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
      "source": "tests/fuzz_corpus/README.md",
      "provenance": "fixture unowned failure seed",
      "byte_len": 4,
      "duration_ms": 1,
      "resource_budget": {"max_input_bytes": 16, "max_duration_ms": 10, "max_artifact_bytes": 128},
      "minimization_status": "",
      "replay_command": "",
      "follow_up_bead": null,
      "quarantine_status": "none",
      "quarantine_owning_bead": null,
      "class_matched": false,
      "error_detail_matched": true,
      "corpus_checksum_matched": true,
      "timed_out": false,
      "actual_class": "panic"
    }
  ]
}
JSON
}

case "$case_name" in
    valid)
        echo "[RCH] remote worker=fixture exit=0" >&2
        emit_valid_report
        exit 0
        ;;
    unowned_failure)
        echo "[RCH] remote worker=fixture exit=0" >&2
        emit_unowned_failure_report
        exit 0
        ;;
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        emit_valid_report
        exit 1
        ;;
    *)
        echo "unknown fixture case: $case_name" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_path() {
    local log_path="$1"
    local key="$2"
    sed -n "s/.*${key}=//p" "$log_path" | tail -n 1
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/fuzz_smoke_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_FUZZ_SMOKE_SELF_CHECK=0 \
        FFS_FUZZ_SMOKE_SKIP_SELF_CHECK=1 \
        FFS_FUZZ_SMOKE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/scripts/e2e/ffs_fuzz_smoke_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic fuzz-smoke wrapper self-check"
    local stub_path child_info child_status child_log artifact_path result_path
    stub_path="$E2E_LOG_DIR/rch-fuzz-smoke-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "valid")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    artifact_path="$(extract_child_path "$child_log" "artifact")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$artifact_path" ]] \
        && jq -e '.valid == true and .seed_ids == ["fixture_valid_seed"] and (.errors | length == 0)' "$artifact_path" >/dev/null; then
        scenario_result "fuzz_smoke_fixture_valid_report_self_check" "PASS" "artifact=${artifact_path}"
    else
        scenario_result "fuzz_smoke_fixture_valid_report_self_check" "FAIL" "log=${child_log}"
        e2e_fail "fuzz-smoke valid fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "unowned_failure")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    artifact_path="$(extract_child_path "$child_log" "artifact")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$artifact_path" ]] \
        && jq -e '.valid == false and (.errors[] | contains("unowned fuzz-smoke failures: fixture_unowned_failure"))' "$artifact_path" >/dev/null; then
        scenario_result "fuzz_smoke_fixture_unowned_failure_self_check" "PASS" "artifact=${artifact_path}"
    else
        scenario_result "fuzz_smoke_fixture_unowned_failure_self_check" "FAIL" "log=${child_log}"
        e2e_fail "fuzz-smoke unowned failure fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.rch_local_fallback_rejected_count == 1 and .verdict == "FAIL"' "$result_path" >/dev/null; then
        scenario_result "fuzz_smoke_fixture_local_fallback_marker_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzz_smoke_fixture_local_fallback_marker_self_check" "FAIL" "log=${child_log}"
        e2e_fail "fuzz-smoke local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "fuzz-smoke wrapper self-check"
    exit 0
fi

COMMAND=(
    "${RCH_BIN:-rch}"
    exec
    --
    cargo
    run
    --quiet
    -p
    ffs-harness
    --
    validate-fuzz-smoke
    --manifest
    "$MANIFEST_PATH"
    --workspace-root
    "$REPO_ROOT"
)
printf -v COMMAND_LINE '%q ' "${COMMAND[@]}"
COMMAND_LINE="${COMMAND_LINE% }"

e2e_step "Run deterministic fuzz-smoke manifest"
START_NS="$(date +%s%N)"
if RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" "${COMMAND[@]}" >"$STDOUT_PATH" 2>"$STDERR_PATH"; then
    COMMAND_STATUS="pass"
else
    COMMAND_STATUS="fail"
fi
END_NS="$(date +%s%N)"
DURATION_MS="$(((END_NS - START_NS) / 1000000))"

if grep -Fq "[RCH] local" "$STDOUT_PATH" "$STDERR_PATH" \
    || grep -Fq "exec called with non-compilation command" "$STDOUT_PATH" "$STDERR_PATH"; then
    e2e_log "RCH_LOCAL_FALLBACK_REJECTED|stdout=${STDOUT_PATH}|stderr=${STDERR_PATH}|command=${COMMAND_LINE}"
    printf 'RCH_LOCAL_FALLBACK_REJECTED|stderr=%s\n' "$STDERR_PATH" >>"$STDERR_PATH"
fi

e2e_step "Emit shared QA artifact"
python3 - \
    "$REPORT_JSON" \
    "$QA_ARTIFACT_JSON" \
    "$STDOUT_PATH" \
    "$STDERR_PATH" \
    "$COMMAND_LINE" \
    "$COMMAND_STATUS" \
    "$DURATION_MS" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
from datetime import datetime, timezone

report_path = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
stdout_path = pathlib.Path(sys.argv[3])
stderr_path = pathlib.Path(sys.argv[4])
command_line = sys.argv[5]
command_status = sys.argv[6]
duration_ms = int(sys.argv[7])

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def extract_report_json(text: str) -> dict:
    cleaned = ANSI_ESCAPE.sub("", text)
    decoder = json.JSONDecoder()
    for index, char in enumerate(cleaned):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[index:])
        except json.JSONDecodeError:
            continue
        if (
            isinstance(value, dict)
            and value.get("corpus_id") == "frankenfs_deterministic_fuzz_smoke_v1"
            and "seed_results" in value
        ):
            return value
    raise ValueError("no fuzz-smoke report object found")


if report_path.exists():
    report = json.loads(report_path.read_text(encoding="utf-8"))
else:
    report = None
    decode_errors = []
    for capture_path in (stdout_path, stderr_path):
        try:
            report = extract_report_json(capture_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            decode_errors.append(f"{capture_path}: {exc}")
        else:
            break
    if report is None:
        report = {
            "valid": False,
            "seed_ids": [],
            "corpus_checksum": "",
            "target_summary": {},
            "errors": [
                f"missing report_json: {report_path}",
                "capture streams did not contain report JSON: " + "; ".join(decode_errors),
            ],
        }
    else:
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

seed_results = report.get("seed_results", [])
seed_hashes = {
    row.get("seed_id", ""): row.get("sha256", "")
    for row in seed_results
}
provenance = {
    row.get("seed_id", ""): {
        "source": row.get("source", ""),
        "provenance": row.get("provenance", ""),
    }
    for row in seed_results
}
resource_counters = {
    row.get("seed_id", ""): {
        "byte_len": row.get("byte_len", 0),
        "duration_ms": row.get("duration_ms", 0),
        "budget": row.get("resource_budget", {}),
    }
    for row in seed_results
}
minimization_status = {
    row.get("seed_id", ""): {
        "status": row.get("minimization_status", ""),
        "replay_command": row.get("replay_command", ""),
        "follow_up_bead": row.get("follow_up_bead"),
    }
    for row in seed_results
}
quarantine_status = {
    row.get("seed_id", ""): {
        "status": row.get("quarantine_status", ""),
        "quarantine_id": row.get("quarantine_id"),
        "owner": row.get("quarantine_owner"),
        "expires_at": row.get("quarantine_expires_at"),
        "owning_bead": row.get("quarantine_owning_bead"),
    }
    for row in seed_results
}

unowned_failures = []
for row in seed_results:
    failed = (
        not row.get("class_matched", False)
        or not row.get("error_detail_matched", False)
        or not row.get("corpus_checksum_matched", False)
        or row.get("timed_out", False)
        or row.get("actual_class") in {"panic", "resource_cap"}
    )
    owned = (
        bool(row.get("replay_command"))
        or bool(row.get("follow_up_bead"))
        or bool(row.get("quarantine_owning_bead"))
    )
    if failed and not owned:
        unowned_failures.append(row.get("seed_id", "<unknown>"))

errors = list(report.get("errors", []))
if unowned_failures:
    errors.append("unowned fuzz-smoke failures: " + ", ".join(unowned_failures))

artifact = {
    "schema_version": 1,
    "bead_id": report.get("bead_id", "bd-u8hx5"),
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "command_line": command_line,
    "command_status": command_status,
    "corpus_version": report.get("corpus_version", ""),
    "seed_ids": report.get("seed_ids", []),
    "seed_hashes": seed_hashes,
    "corpus_checksum": report.get("corpus_checksum", ""),
    "duration_ms": duration_ms,
    "provenance": provenance,
    "resource_counters": resource_counters,
    "minimization_status": minimization_status,
    "quarantine_status": quarantine_status,
    "stdout_path": str(stdout_path),
    "stderr_path": str(stderr_path),
    "report_json": str(report_path),
    "coverage_summary": report.get("target_summary", {}),
    "outcome_summary": report.get("outcome_summary", {}),
    "cleanup_status": "registered_with_e2e_cleanup_trap",
    "seed_results": seed_results,
    "valid": command_status == "pass" and bool(report.get("valid")) and not unowned_failures,
    "errors": errors,
}

artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(
    "FUZZ_SMOKE_QA|valid={valid}|seeds={seed_count}|checksum={checksum}|artifact={artifact}".format(
        valid=artifact["valid"],
        seed_count=len(artifact["seed_ids"]),
        checksum=artifact["corpus_checksum"],
        artifact=artifact_path,
    )
)

if not artifact["valid"]:
    raise SystemExit(1)
PY

if [[ "$COMMAND_STATUS" != "pass" ]]; then
    e2e_fail "fuzz-smoke command failed; stdout=$STDOUT_PATH stderr=$STDERR_PATH"
fi

e2e_pass "fuzz-smoke report=$REPORT_JSON qa_artifact=$QA_ARTIFACT_JSON"
