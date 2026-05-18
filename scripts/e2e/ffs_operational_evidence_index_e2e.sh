#!/usr/bin/env bash
# ffs_operational_evidence_index_e2e.sh - latest-truth evidence index gate.
#
# Builds a small artifact tree, runs the operational evidence indexer, and
# proves that the newest authoritative record is selected while older
# conflicting evidence remains visible.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd -P)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_operational_evidence_index}"
RCH_CAPTURE_VISIBILITY="${FFS_OPERATIONAL_EVIDENCE_INDEX_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_OPERATIONAL_EVIDENCE_INDEX_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_OPERATIONAL_EVIDENCE_INDEX_SKIP_SELF_CHECK:-0}"

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

run_indexer() {
    local format="$1"
    local output_path="$2"
    shift 2

    if [[ -n "${FFS_HARNESS_BIN:-}" ]]; then
        "$FFS_HARNESS_BIN" operational-evidence-index --format "$format" "$@" >"$output_path" 2>&1
    else
        RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
            RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
            e2e_rch_capture "$output_path" \
                cargo run -p ffs-harness -- operational-evidence-index --format "$format" "$@"
    fi
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_OPERATIONAL_EVIDENCE_INDEX_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected operational-evidence fixture rch invocation: $*" >&2
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
        echo "unknown operational-evidence fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

emit_index_json() {
    cat <<'JSON'
{
  "conflict_count": 1,
  "index_id": "frankenfs-operational-evidence-index:v1",
  "records": [
    {
      "gate_id": "xfstests",
      "record_id": "run_20260501:mounted_ext4_rw",
      "run_id": "run_20260501",
      "scenario_id": "mounted_ext4_rw",
      "selected": false,
      "outcome": "fail"
    },
    {
      "gate_id": "xfstests",
      "record_id": "run_20260509:mounted_ext4_rw",
      "run_id": "run_20260509",
      "scenario_id": "mounted_ext4_rw",
      "selected": true,
      "outcome": "pass"
    }
  ],
  "selections": [
    {
      "gate_id": "xfstests",
      "scenario_id": "mounted_ext4_rw",
      "selected_outcome": "pass",
      "selected_record_id": "run_20260509:mounted_ext4_rw",
      "selected_run_id": "run_20260509",
      "superseded_record_ids": [
        "run_20260501:mounted_ext4_rw"
      ]
    }
  ],
  "selected_record_count": 1,
  "source_record_count": 2
}
JSON
}

emit_index_markdown() {
    cat <<'MD'
# FrankenFS Operational Evidence Index

## Latest Truth

- `run_20260509` selected for `mounted_ext4_rw`.

## Conflicts

- `run_20260501` superseded by `run_20260509`.
MD
}

case "$command_text" in
    *"operational-evidence-index --format json"*)
        emit_index_json
        finish_success
        ;;
    *"operational-evidence-index --format markdown"*)
        emit_index_markdown
        finish_success
        ;;
    *)
        echo "unexpected operational-evidence fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/operational_evidence_index_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_OPERATIONAL_EVIDENCE_INDEX_SELF_CHECK=0 \
        FFS_OPERATIONAL_EVIDENCE_INDEX_SKIP_SELF_CHECK=1 \
        FFS_OPERATIONAL_EVIDENCE_INDEX_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_operational_evidence_index_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic operational evidence index wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-operational-evidence-index-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "evidence_fixture_conflict_tree" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_index_selects_latest_authoritative" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "evidence_index_markdown_summary" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "evidence_index_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_index_fixture_complete_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "evidence_index_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_index_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "evidence_index_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "evidence_index_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

extract_index_json() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "records" in obj and "selections" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("operational evidence index JSON not found")
PY
}

extract_index_markdown() {
    local raw_path="$1"
    local report_path="$2"

    python3 - "$raw_path" "$report_path" <<'PY'
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# FrankenFS Operational Evidence Index")
if start < 0:
    raise SystemExit("operational evidence index markdown not found")
end = text.find("\noperational evidence index written:", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
pathlib.Path(report_path).write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_operational_evidence_index"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

FIXTURE_DIR="$E2E_LOG_DIR/evidence_fixture"
RAW_JSON="$E2E_LOG_DIR/evidence_index_json_command.log"
RAW_MD="$E2E_LOG_DIR/evidence_index_markdown_command.log"
INDEX_JSON="$E2E_LOG_DIR/evidence_index.json"
INDEX_MD="$E2E_LOG_DIR/evidence_index.md"

e2e_step "Scenario 1: fixture artifact tree contains conflicting evidence"
python3 - "$FIXTURE_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)

def write(path, text):
    path = root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def artifact(path, category="raw_log"):
    return {
        "path": path,
        "category": category,
        "content_type": "text/plain",
        "size_bytes": 4,
        "redacted": False,
        "metadata": {},
    }

def manifest(run_id, scenario_id, result, classification, created_at):
    stdout = f"{run_id}/{scenario_id}/stdout.log"
    stderr = f"{run_id}/{scenario_id}/stderr.log"
    run_stdout = f"{run_id}/run_stdout.log"
    run_stderr = f"{run_id}/run_stderr.log"
    evidence = f"{run_id}/{scenario_id}/evidence.json"
    for rel in [stdout, stderr, run_stdout, run_stderr, evidence]:
        write(rel, f"{rel}\n")
    return {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": created_at,
        "gate_id": "xfstests",
        "bead_id": "bd-4v16z.6",
        "git_context": {"commit": "abc123", "branch": "main", "clean": True},
        "environment": {
            "hostname": "permissioned-host",
            "cpu_model": "cpu",
            "cpu_count": 64,
            "memory_gib": 256,
            "kernel": "Linux 6.17.0",
            "rustc_version": "rustc 1.85.0",
            "cargo_version": "cargo 1.85.0",
        },
        "scenarios": {
            scenario_id: {
                "scenario_id": scenario_id,
                "outcome": result,
                "detail": f"{run_id} fixture",
                "duration_secs": 1.0,
            }
        },
        "operational_context": {
            "command_line": ["scripts/e2e/ffs_operational_evidence_index_e2e.sh"],
            "worker": {"host": "permissioned-host", "worker_id": "worker-a"},
            "fuse_capability": "not_applicable",
            "stdout_path": run_stdout,
            "stderr_path": run_stderr,
        },
        "operational_scenarios": {
            scenario_id: {
                "scenario_id": scenario_id,
                "filesystem": "not_applicable",
                "mount_options": [],
                "expected_outcome": result,
                "actual_outcome": result,
                "classification": classification,
                "exit_status": 0 if classification == "pass" else 1,
                "stdout_path": stdout,
                "stderr_path": stderr,
                "ledger_paths": [],
                "artifact_refs": [evidence],
                "cleanup_status": "clean",
                **({"error_class": "product_failure", "remediation_hint": "fixture failure"} if classification == "fail" else {}),
            }
        },
        "readiness_events": [
            {
                "envelope_version": 1,
                "event_id": f"event_{run_id}_{scenario_id}",
                "report_id": f"report_{run_id}",
                "run_id": run_id,
                "lane_id": "xfstests",
                "scenario_id": scenario_id,
                "artifact_id": evidence,
                "classification": classification,
                "severity": "info" if classification == "pass" else "error",
                "created_at": created_at,
                "git_commit": "abc123",
                "host_fingerprint": "permissioned-host|64cpu|256GiB",
                "capability_fingerprint": "fuse:not_applicable",
                "raw_log_refs": [stdout, stderr],
                "controlling_evidence": [evidence],
                "remediation_id": "bd-4v16z.6:e2e",
                "reproduction_command": "scripts/e2e/ffs_operational_evidence_index_e2e.sh",
            }
        ],
        "artifacts": [
            artifact(stdout),
            artifact(stderr),
            artifact(run_stdout),
            artifact(run_stderr),
            artifact(evidence, "proof_artifact"),
        ],
        "verdict": "PASS" if classification == "pass" else "FAIL",
        "duration_secs": 1.0,
    }

scenario = "mounted_ext4_rw"
(root / "old.json").write_text(
    json.dumps(manifest("run_20260501", scenario, "FAIL", "fail", "2026-05-01T00:00:00Z"), indent=2)
    + "\n",
    encoding="utf-8",
)
(root / "new.json").write_text(
    json.dumps(manifest("run_20260509", scenario, "PASS", "pass", "2026-05-09T00:00:00Z"), indent=2)
    + "\n",
    encoding="utf-8",
)
PY
scenario_result "evidence_fixture_conflict_tree" "PASS" "fixture contains old fail plus newer pass"

e2e_step "Scenario 2: JSON index selects latest authoritative evidence"
if run_indexer json "$RAW_JSON" \
    --artifacts "$FIXTURE_DIR" \
    --current-git-sha abc123 \
    --max-age-days 14 \
    --recency-reference-timestamp 2026-05-09T00:00:00Z; then
    extract_index_json "$RAW_JSON" "$INDEX_JSON"
    python3 - "$INDEX_JSON" <<'PY'
import json
import pathlib
import sys

index = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert index["source_record_count"] == 2, index
assert index["conflict_count"] == 1, index
assert index["selected_record_count"] == 1, index
selection = index["selections"][0]
assert selection["selected_run_id"] == "run_20260509", selection
assert selection["selected_outcome"] == "pass", selection
assert len(selection["superseded_record_ids"]) == 1, selection
assert any(record["run_id"] == "run_20260501" for record in index["records"]), index["records"]
PY
    scenario_result "evidence_index_selects_latest_authoritative" "PASS" "newest pass selected and old fail preserved"
else
    scenario_result "evidence_index_selects_latest_authoritative" "FAIL" "indexer JSON command failed"
fi

e2e_step "Scenario 3: Markdown index is Agent Mail ready"
if run_indexer markdown "$RAW_MD" \
    --artifacts "$FIXTURE_DIR" \
    --current-git-sha abc123 \
    --max-age-days 14 \
    --recency-reference-timestamp 2026-05-09T00:00:00Z; then
    extract_index_markdown "$RAW_MD" "$INDEX_MD"
    if grep -q "## Latest Truth" "$INDEX_MD" \
        && grep -q "## Conflicts" "$INDEX_MD" \
        && grep -q "run_20260509" "$INDEX_MD"; then
        scenario_result "evidence_index_markdown_summary" "PASS" "Markdown preserves latest truth and conflict section"
    else
        scenario_result "evidence_index_markdown_summary" "FAIL" "Markdown missing expected sections"
    fi
else
    scenario_result "evidence_index_markdown_summary" "FAIL" "indexer Markdown command failed"
fi

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_fail "operational evidence index E2E failed: pass=${PASS_COUNT} fail=${FAIL_COUNT} total=${TOTAL}"
fi

e2e_log "SUMMARY|pass=${PASS_COUNT}|fail=${FAIL_COUNT}|total=${TOTAL}|index_json=${INDEX_JSON}|index_md=${INDEX_MD}"
e2e_pass
