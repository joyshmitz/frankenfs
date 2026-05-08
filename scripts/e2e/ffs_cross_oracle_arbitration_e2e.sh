#!/usr/bin/env bash
# ffs_cross_oracle_arbitration_e2e.sh - smoke gate for bd-zj57e.
#
# Builds fixture cross-oracle conflicts, validates arbitration output, and
# proves unresolved high-risk public claims fail closed instead of downgrading.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_cross_oracle}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

case ",${RCH_ENV_ALLOWLIST:-}," in
    *",CARGO_TARGET_DIR,"*) ;;
    *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR" ;;
esac

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("$RCH_BIN" queue --json 2>/dev/null || true)"
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
        if "$RCH_BIN" cancel "$id" >/dev/null 2>&1; then
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

    : >"$log_path"
    set +e
    RCH_VISIBILITY="$RCH_VISIBILITY" "$RCH_BIN" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
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
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|log=${log_path}"
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
        e2e_log "RCH_ARTIFACT_RETRIEVAL_FAILURE_ACCEPTED|log=${log_path}|status=${status}"
        return 0
    fi
    return "$status"
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

e2e_init "ffs_cross_oracle_arbitration"

RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/cross_oracle_arbitration"
mkdir -p "$RCH_INPUT_DIR"

REPORT_JSON="$E2E_LOG_DIR/cross_oracle_report.json"
REPORT_JSON_RCH="$RCH_INPUT_DIR/cross_oracle_report.json"
VALIDATION_JSON="$E2E_LOG_DIR/cross_oracle_validation.json"
VALIDATION_MD="$E2E_LOG_DIR/cross_oracle_validation.md"
VALIDATE_RAW="$E2E_LOG_DIR/cross_oracle_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/cross_oracle_markdown.raw"
BAD_HIGH_RISK_JSON="$RCH_INPUT_DIR/cross_oracle_bad_high_risk.json"
BAD_HIGH_RISK_RAW="$E2E_LOG_DIR/cross_oracle_bad_high_risk.raw"
BAD_STALE_JSON="$RCH_INPUT_DIR/cross_oracle_bad_stale.json"
BAD_STALE_RAW="$E2E_LOG_DIR/cross_oracle_bad_stale.raw"
UNIT_LOG="$E2E_LOG_DIR/cross_oracle_unit_tests.log"

extract_validation_json() {
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
    if isinstance(obj, dict) and "arbitration_count" in obj:
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("cross-oracle validation JSON object not found")
PY
}

e2e_step "Scenario 1: cross-oracle arbitration module and CLI are wired"
if grep -q "pub mod cross_oracle_arbitration" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-cross-oracle-arbitration" crates/ffs-harness/src/main.rs; then
    scenario_result "cross_oracle_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "cross_oracle_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: generate fixture cross-oracle conflicts"
python3 - "$REPORT_JSON_RCH" "$REPORT_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
local_report_path = pathlib.Path(sys.argv[2])
hash_a = "a" * 64
hash_b = "b" * 64
required_log_fields = [
    "arbitration_id",
    "source_oracle_ids",
    "artifact_hashes",
    "normalized_observation_summary",
    "classification",
    "confidence",
    "rationale",
    "release_gate_impact",
    "follow_up_bead_id",
    "output_path",
    "reproduction_command",
]


def source(oracle_id: str, oracle_kind: str, status: str) -> dict[str, str]:
    return {
        "oracle_id": oracle_id,
        "oracle_kind": oracle_kind,
        "status": status,
        "artifact_path": (
            f"missing://{oracle_id}"
            if status == "missing"
            else f"{report_path.parent}/oracles/{oracle_id}.json"
        ),
        "artifact_sha256": "missing" if status == "missing" else (hash_b if oracle_kind == "mounted_differential" else hash_a),
        "observed_at": "2026-05-03T00:00:00Z",
        "summary": f"{oracle_id} reports {status}",
    }


def arbitration(
    arbitration_id: str,
    classification: str,
    status: str,
    sources: list[dict[str, str]],
    blocked_claims: list[str],
    effect: str,
    *,
    non_goal_reason: str | None = None,
) -> dict[str, object]:
    output_path = f"{report_path.parent}/{arbitration_id}/arbitration.json"
    artifact_paths = [output_path] + [
        src["artifact_path"] for src in sources if src["status"] != "missing"
    ]
    return {
        "arbitration_id": arbitration_id,
        "status": status,
        "classification": classification,
        "source_oracles": sources,
        "normalized_observation_summary": f"{arbitration_id} normalized observation summary",
        "confidence": "high" if status != "unresolved" else "medium",
        "confidence_rationale": "fixture sources exercise the arbitration routing contract",
        "release_gate_impact": {
            "effect": effect,
            "gates": [] if effect == "no_impact" else ["mount.rw.ext4", "repair.rw.writeback"],
            "rationale": "user-facing claim remains blocked or downgraded by arbitration result",
        },
        "blocked_public_claims": blocked_claims,
        "owning_bead": "bd-zj57e",
        "remediation_id": "remediate_cross_oracle_conflict",
        "follow_up_bead_id": "bd-zj57e" if status == "unresolved" else None,
        "non_goal_reason": non_goal_reason,
        "output_path": output_path,
        "reproduction_command": (
            "cargo run -p ffs-harness -- validate-cross-oracle-arbitration "
            f"--report {report_path}"
        ),
        "artifact_paths": artifact_paths,
        "log_fields": required_log_fields,
    }


arbitrations = [
    arbitration(
        "cross_oracle_product_bug_fail_closed",
        "frankenfs_product_bug",
        "unresolved",
        [
            source("invariant_trace_product", "invariant_trace", "fail"),
            source("mounted_diff_product", "mounted_differential", "fail"),
            source("release_gate_product", "release_gate_status", "fail"),
        ],
        ["mounted_writes", "data_integrity"],
        "fail_closed",
    ),
    arbitration(
        "cross_oracle_kernel_baseline_issue",
        "kernel_baseline_issue",
        "unresolved",
        [
            source("mounted_diff_kernel_stale", "mounted_differential", "stale"),
            source("crash_replay_kernel_neutral", "crash_replay_survivor", "pass"),
            source("release_gate_kernel", "release_gate_status", "fail"),
        ],
        ["mounted_writes"],
        "fail_closed",
    ),
    arbitration(
        "cross_oracle_repair_oracle_gap",
        "repair_oracle_gap",
        "unresolved",
        [
            source("repair_confidence_missing", "repair_confidence", "missing"),
            source("release_gate_repair", "release_gate_status", "fail"),
        ],
        ["mutating_repair", "background_scrub_mutation"],
        "fail_closed",
    ),
    arbitration(
        "cross_oracle_unsupported_scope_scoped",
        "unsupported_scope",
        "scoped_out",
        [
            source("mounted_diff_unsupported", "mounted_differential", "skip"),
            source("release_gate_unsupported", "release_gate_status", "pass"),
        ],
        ["writeback_cache"],
        "downgrade",
        non_goal_reason="clone-range parity remains outside the current V1 scope",
    ),
    arbitration(
        "cross_oracle_host_capability_gap",
        "host_capability_gap",
        "resolved",
        [
            source("mounted_diff_fuse_skip", "mounted_differential", "skip"),
            source("invariant_host_neutral", "invariant_trace", "pass"),
        ],
        ["mounted_writes"],
        "downgrade",
    ),
]

all_artifacts: list[str] = []
for item in arbitrations:
    all_artifacts.extend(str(path) for path in item["artifact_paths"])

report = {
    "schema_version": 1,
    "bead_id": "bd-zj57e",
    "generated_at": "2026-05-03T00:00:00Z",
    "runner": "scripts/e2e/ffs_cross_oracle_arbitration_e2e.sh",
    "arbitrations": arbitrations,
    "artifact_paths": sorted(set(all_artifacts)),
}
serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
report_path.write_text(serialized, encoding="utf-8")
local_report_path.write_text(serialized, encoding="utf-8")
PY
scenario_result "cross_oracle_fixture_conflicts_generated" "PASS" "fixture conflicts generated"

e2e_step "Scenario 3: validator accepts fixture conflicts"
if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-cross-oracle-arbitration \
    --report "$REPORT_JSON_RCH" \
    && extract_validation_json "$VALIDATE_RAW" "$VALIDATION_JSON" \
    && run_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
        validate-cross-oracle-arbitration \
        --report "$REPORT_JSON_RCH" \
        --format markdown; then
    scenario_result "cross_oracle_fixture_conflicts_classified" "PASS" "validation JSON and markdown generated"
else
    scenario_result "cross_oracle_fixture_conflicts_classified" "FAIL" "validator rejected fixture conflicts"
fi

e2e_step "Scenario 4: validation output preserves blocked claims and control artifacts"
if python3 - "$VALIDATION_JSON" "$MARKDOWN_RAW" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
markdown = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
if not report.get("valid"):
    raise SystemExit("validation report is not valid")
summary = {
    row["arbitration_id"]: row
    for row in report.get("summaries", [])
}
product = summary.get("cross_oracle_product_bug_fail_closed")
if not product:
    raise SystemExit("product conflict summary missing")
if product.get("classification") != "frankenfs_product_bug":
    raise SystemExit("product conflict classification missing")
if "data_integrity" not in product.get("blocked_public_claims", []):
    raise SystemExit("data_integrity blocked claim missing")
if not product.get("controlling_artifacts"):
    raise SystemExit("controlling artifacts missing")
if product.get("remediation_id") != "remediate_cross_oracle_conflict":
    raise SystemExit("remediation id missing")
if "validate-cross-oracle-arbitration" not in product.get("reproduction_command", ""):
    raise SystemExit("reproduction command missing")
if "background_scrub_mutation" not in report.get("blocked_public_claims", []):
    raise SystemExit("background scrub mutation claim not blocked")
if "cross_oracle_product_bug_fail_closed" not in markdown or "data_integrity" not in markdown:
    raise SystemExit("markdown did not render arbitration and blocked claim")
PY
then
    scenario_result "cross_oracle_output_preserves_claims" "PASS" "classification, artifacts, blocked claims, remediation, reproduction preserved"
else
    scenario_result "cross_oracle_output_preserves_claims" "FAIL" "validation output lost required arbitration evidence"
fi

e2e_step "Scenario 5: unresolved high-risk conflict fails closed"
python3 - "$REPORT_JSON_RCH" "$BAD_HIGH_RISK_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["arbitrations"][0]["release_gate_impact"]["effect"] = "downgrade"
target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_HIGH_RISK_RAW" cargo run --quiet -p ffs-harness -- \
    validate-cross-oracle-arbitration \
    --report "$BAD_HIGH_RISK_JSON"; then
    scenario_result "cross_oracle_unresolved_claim_fails_closed" "FAIL" "unsafe downgrade was accepted"
elif grep -q "unresolved high-risk public claim must fail closed" "$BAD_HIGH_RISK_RAW"; then
    scenario_result "cross_oracle_unresolved_claim_fails_closed" "PASS" "unsafe downgrade rejected"
else
    scenario_result "cross_oracle_unresolved_claim_fails_closed" "FAIL" "expected fail-closed diagnostic missing"
fi

e2e_step "Scenario 6: stale or missing oracle evidence requires gap-aware classification"
python3 - "$REPORT_JSON_RCH" "$BAD_STALE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["arbitrations"][2]["classification"] = "frankenfs_product_bug"
target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_STALE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-cross-oracle-arbitration \
    --report "$BAD_STALE_JSON"; then
    scenario_result "cross_oracle_stale_missing_evidence_rejected" "FAIL" "stale/missing evidence was accepted under product-bug classification"
elif grep -q "cannot absorb evidence gaps" "$BAD_STALE_RAW"; then
    scenario_result "cross_oracle_stale_missing_evidence_rejected" "PASS" "stale/missing evidence rejected without gap-aware classification"
else
    scenario_result "cross_oracle_stale_missing_evidence_rejected" "FAIL" "expected stale/missing diagnostic missing"
fi

e2e_step "Scenario 7: cross-oracle arbitration unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib \
    cross_oracle_arbitration -- --nocapture; then
    scenario_result "cross_oracle_unit_tests" "PASS" "unit tests passed"
else
    scenario_result "cross_oracle_unit_tests" "FAIL" "unit tests failed"
fi

if (( FAIL_COUNT == 0 )); then
    e2e_pass "ffs_cross_oracle_arbitration completed"
else
    e2e_fail "ffs_cross_oracle_arbitration failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
