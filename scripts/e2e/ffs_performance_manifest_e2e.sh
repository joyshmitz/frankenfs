#!/usr/bin/env bash
# ffs_performance_manifest_e2e.sh - dry-run gate for bd-rchk5.1.
#
# Validates the performance baseline manifest without running heavyweight
# benchmarks, expands commands, and emits a sample shared QA artifact manifest.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_performance_manifest}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_PERFORMANCE_MANIFEST_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_PERFORMANCE_MANIFEST_SKIP_SELF_CHECK:-0}"

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
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-600}"
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

extract_json_object() {
    local input_path="$1"
    local output_path="$2"
    local object_index="${3:-0}"
    python3 - "$input_path" "$output_path" "$object_index" <<'PY'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
target_index = int(sys.argv[3])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
seen = 0
for idx, ch in enumerate(text):
    if ch != "{":
        continue
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        continue
    if seen == target_index:
        dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
        raise SystemExit(0)
    seen += 1
raise SystemExit(f"no JSON object #{target_index} found in {source}")
PY
}

e2e_init "ffs_performance_manifest"

MANIFEST_JSON="$REPO_ROOT/benchmarks/performance_baseline_manifest.json"
REPORT_JSON="$E2E_LOG_DIR/performance_manifest_report.json"
ARTIFACT_JSON="$E2E_LOG_DIR/performance_sample_artifact_manifest.json"
VALIDATE_RAW="$E2E_LOG_DIR/performance_manifest_validate.raw"
ARTIFACT_RAW="$E2E_LOG_DIR/performance_manifest_artifact.raw"
BAD_CAP_JSON="$E2E_LOG_DIR/performance_manifest_bad_capability.json"
BAD_ENV_JSON="$E2E_LOG_DIR/performance_manifest_bad_environment.json"
BAD_ARTIFACT_JSON="$E2E_LOG_DIR/performance_manifest_bad_artifact.json"
BAD_UNIT_JSON="$E2E_LOG_DIR/performance_manifest_bad_unit.json"
BAD_TARGET_JSON="$E2E_LOG_DIR/performance_manifest_bad_target_dir.json"
BAD_RAW_LOG_JSON="$E2E_LOG_DIR/performance_manifest_bad_raw_log.json"
BAD_FIXTURE_JSON="$E2E_LOG_DIR/performance_manifest_bad_fixture.json"
BAD_CLAIM_JSON="$E2E_LOG_DIR/performance_manifest_bad_claim_policy.json"
BAD_STATS_JSON="$E2E_LOG_DIR/performance_manifest_bad_statistical_summary.json"
BAD_AUTHORITATIVE_JSON="$E2E_LOG_DIR/performance_manifest_bad_authoritative_claim.json"
BAD_RAW="$E2E_LOG_DIR/performance_manifest_bad.raw"
UNIT_LOG="$E2E_LOG_DIR/performance_manifest_unit_tests.log"
MOUNT_PROBE_JSON="$E2E_LOG_DIR/mount_benchmark_probe_input_error.json"
MOUNT_PROBE_RAW="$E2E_LOG_DIR/mount_benchmark_probe_input_error.raw"
MOUNT_PROBE_POLICY_JSON="$E2E_LOG_DIR/mount_benchmark_probe_scrub_policy.json"
MOUNT_PROBE_POLICY_RAW="$E2E_LOG_DIR/mount_benchmark_probe_scrub_policy.raw"
MOUNT_PROBE_ARGS_LOG="$E2E_LOG_DIR/mount_benchmark_probe_ffs_args.log"
MOUNT_PENDING_BASELINE_JSON="$REPO_ROOT/benchmarks/baselines/history/20260503-bd-rchk5-3-mount-warm-pending.json"
MOUNT_PENDING_PROBE_JSON="$REPO_ROOT/baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-pending/ffs_cli_mount_cold_probe_report.json"
MOUNT_MEASURED_BASELINE_JSON="$REPO_ROOT/benchmarks/baselines/history/20260503-bd-rchk5-3-mount-warm-sudo-measured.json"
MOUNT_MEASURED_HYPERFINE_JSON="$REPO_ROOT/baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/ffs_cli_mount_warm_probe.json"
MOUNT_MEASURED_PROBE_JSON="$REPO_ROOT/baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/ffs_cli_mount_warm_probe_report.json"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_PERFORMANCE_MANIFEST_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

classes = [
    "pass",
    "warn",
    "fail",
    "noisy",
    "stale",
    "missing",
    "missing_baseline",
    "environment_mismatch",
    "budget_exceeded",
    "instrumentation_overhead_exceeded",
    "degraded_but_accepted",
    "blocked",
]

def row(index, verdict, claim_tier, authority, public_state, fixture_id=None):
    return {
        "fixture_id": fixture_id or f"fixture_{verdict}_{index}",
        "workload_id": f"fixture_workload_{index}",
        "claim_tier_before": "experimental",
        "claim_tier_after": claim_tier,
        "evidence_authority": authority,
        "baseline_id": f"baseline-{index}",
        "baseline_artifact_hash": "sha256:" + f"{index:064d}"[-64:],
        "current_artifact_id": f"artifact-{index}",
        "current_artifact_hash": "sha256:" + f"{index + 1:064d}"[-64:],
        "environment_fingerprint": f"fixture-host-{index}",
        "environment_matches_claim_lane": authority == "authoritative",
        "metric_unit": "micros",
        "observed_value": float(index + 1),
        "threshold": float(index + 10),
        "freshness_window_days": 30,
        "overhead_budget": 0.05,
        "runtime_seconds": 0.1,
        "memory_mib": 8,
        "instrumentation_overhead_percent": 0.01,
        "statistical_summary": {"sample_count": 10, "p50": float(index + 1), "p99": float(index + 2)},
        "noise_decision": "stable",
        "stale_decision": "fresh",
        "budget_decision": "budget_within_limit",
        "overhead_decision": "instrumentation_overhead_within_limit",
        "comparison_verdict": verdict,
        "public_claim_state": public_state,
        "release_claim_effect": "no_public_promotion" if public_state != "validated" else "release_claim_allowed",
        "docs_wording_id": f"performance.fixture.{index}",
        "output_path": f"artifacts/performance/fixture-{index}.json",
        "raw_stdout_path": f"artifacts/performance/fixture-{index}.stdout",
        "raw_stderr_path": f"artifacts/performance/fixture-{index}.stderr",
        "reproduction_command": "cargo run -p ffs-harness -- validate-performance-baseline-manifest",
        "follow_up_bead": f"bd-fixture-{index}",
    }

reports = [
    row(0, "pass", "regression_free", "authoritative", "validated", "fixture_pass_core"),
    row(1, "warn", "experimental", "local", "experimental"),
    row(2, "fail", "blocked", "local", "unknown"),
    row(3, "noisy", "experimental", "local", "experimental"),
    row(4, "stale", "experimental", "local", "unknown"),
    row(5, "missing", "blocked", "local", "unknown"),
    row(6, "missing_baseline", "experimental", "local", "unknown"),
    row(7, "environment_mismatch", "experimental", "local", "experimental"),
    row(8, "budget_exceeded", "experimental", "local", "unknown"),
    row(9, "instrumentation_overhead_exceeded", "experimental", "local", "experimental"),
    row(10, "degraded_but_accepted", "degraded_but_accepted", "authoritative", "validated"),
    row(11, "blocked", "blocked", "local", "unknown"),
]

report = {
    "valid": True,
    "workload_count": 8,
    "missing_required_workload_kinds": [],
    "fixture_classification_counts": {name: 1 for name in classes},
    "command_expansions": [
        {
            "workload_id": "btree_insert_bench",
            "command": "cargo bench -p ffs-harness btree_insert -- --profile release-perf",
            "target_dir": "/data/tmp/rch_target_frankenfs_performance_manifest",
            "workload_kind": "micro_benchmark",
            "skip_semantics": "runs_on_rch",
        },
        {
            "workload_id": "fuse_mount_warm",
            "command": "sudo -n scripts/mount_benchmark_probe.sh --mode warm --out-json artifacts/performance/mount.json",
            "target_dir": "/data/tmp/rch_target_frankenfs_performance_manifest",
            "workload_kind": "mounted_probe",
            "skip_semantics": "permissioned_required",
        },
        {
            "workload_id": "swarm_tail_latency_campaign",
            "command": "scripts/e2e/ffs_swarm_tail_latency_e2e.sh",
            "target_dir": "/data/tmp/rch_target_frankenfs_performance_manifest",
            "workload_kind": "long_campaign_observation",
            "skip_semantics": "long_campaign_deferred",
        },
    ],
    "fixture_evidence_reports": reports,
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_sample_artifact_manifest() {
    cat <<'JSON'
{
  "schema_version": 1,
  "gate_id": "performance_baseline_manifest",
  "bead_id": "bd-rchk5.1",
  "artifacts": [
    {
      "category": "benchmark_baseline",
      "path": "artifacts/performance/dry-run/baseline.json"
    },
    {
      "category": "benchmark_report",
      "path": "artifacts/performance/dry-run/report.json"
    }
  ]
}
JSON
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown performance manifest fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib performance_baseline_manifest"*)
        printf '%s\n' \
            "test performance_baseline_manifest::tests::checked_in_manifest_validates ... ok" \
            "test performance_baseline_manifest::tests::artifact_manifest_shape ... ok" \
            "test performance_baseline_manifest::tests::invalid_manifest_variants_fail_closed ... ok"
        exit 0
        ;;
    *"--manifest-json-env PERFORMANCE_BASELINE_MANIFEST_JSON"*)
        echo "error: performance baseline manifest validation failed: fixture invalid manifest" >&2
        exit 1
        ;;
    *"--artifact-out"*)
        emit_sample_artifact_manifest
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
    local child_log="$E2E_LOG_DIR/performance_manifest_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_PERFORMANCE_MANIFEST_SELF_CHECK=0 \
        FFS_PERFORMANCE_MANIFEST_SKIP_SELF_CHECK=1 \
        FFS_PERFORMANCE_MANIFEST_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_performance_manifest_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic performance manifest wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path artifact_path unit_log
    stub_path="$E2E_LOG_DIR/rch-performance-manifest-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/performance_manifest_report.json"
    artifact_path="$(dirname "$result_path")/performance_sample_artifact_manifest.json"
    unit_log="$(dirname "$result_path")/performance_manifest_unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$artifact_path" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "performance_manifest_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_manifest_dry_run_expands" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_manifest_invalid_variants_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_manifest_unit_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_mount_probe_structured_failure" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "performance_mount_probe_disables_background_scrub" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .valid == true
            and .workload_count >= 8
            and (.missing_required_workload_kinds | length) == 0
            and (.fixture_classification_counts.pass == 1)
            and (.fixture_classification_counts.blocked == 1)
            and ([.command_expansions[] | select(.command | contains("cargo bench"))] | length) >= 1
            and ([.command_expansions[] | select(.command | contains("mount_benchmark_probe.sh"))] | length) >= 1
            and ([.command_expansions[] | select(.workload_kind == "long_campaign_observation" and .skip_semantics == "long_campaign_deferred")] | length) >= 1
            and ([.fixture_evidence_reports[] | select(.fixture_id == "fixture_pass_core" and .claim_tier_after == "regression_free")] | length) == 1
            and ([.fixture_evidence_reports[] | select(.comparison_verdict == "degraded_but_accepted" and .claim_tier_after == "degraded_but_accepted")] | length) == 1
            and ([.fixture_evidence_reports[] | select(.comparison_verdict == "blocked" and .claim_tier_after == "blocked")] | length) == 1
        ' "$report_path" >/dev/null \
        && jq -e '
            .gate_id == "performance_baseline_manifest"
            and .bead_id == "bd-rchk5.1"
            and ([.artifacts[].category] | index("benchmark_baseline") != null)
            and ([.artifacts[].category] | index("benchmark_report") != null)
        ' "$artifact_path" >/dev/null \
        && grep -q "performance_baseline_manifest::tests::checked_in_manifest_validates" "$unit_log"; then
        scenario_result "performance_manifest_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} artifact=${artifact_path}"
    else
        scenario_result "performance_manifest_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "performance manifest complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "performance_manifest_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "performance_manifest_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "performance manifest local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Scenario 1: performance manifest module and CLI are wired"
if grep -q "pub mod performance_baseline_manifest" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-performance-baseline-manifest" crates/ffs-harness/src/main.rs; then
    scenario_result "performance_manifest_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "performance_manifest_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: checked-in manifest validates and emits shared QA artifact"
if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- validate-performance-baseline-manifest \
    --manifest "$MANIFEST_JSON" \
    --artifact-root "artifacts/performance/dry-run" \
    && extract_json_object "$VALIDATE_RAW" "$REPORT_JSON" \
    && run_rch_capture "$ARTIFACT_RAW" cargo run --quiet -p ffs-harness -- validate-performance-baseline-manifest \
        --manifest "$MANIFEST_JSON" \
        --artifact-root "artifacts/performance/dry-run" \
        --out "/tmp/frankenfs_performance_manifest_report.json" \
        --artifact-out /dev/stdout \
    && extract_json_object "$ARTIFACT_RAW" "$ARTIFACT_JSON"; then
    scenario_result "performance_manifest_validates" "PASS" "checked-in performance manifest accepted"
else
    [[ -s "$VALIDATE_RAW" ]] && cat "$VALIDATE_RAW"
    [[ -s "$ARTIFACT_RAW" ]] && cat "$ARTIFACT_RAW"
    scenario_result "performance_manifest_validates" "FAIL" "checked-in performance manifest rejected"
fi

e2e_step "Scenario 3: command expansion and artifact mapping are dry-run only"
if python3 - "$REPORT_JSON" "$ARTIFACT_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifact = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))

if not report["valid"]:
    raise SystemExit("manifest report invalid")
if report["workload_count"] < 8:
    raise SystemExit("expected representative workload coverage")
if report["missing_required_workload_kinds"]:
    raise SystemExit(f"missing workload kinds: {report['missing_required_workload_kinds']}")
required_classes = {
    "pass",
    "warn",
    "fail",
    "noisy",
    "stale",
    "missing",
    "missing_baseline",
    "environment_mismatch",
    "budget_exceeded",
    "instrumentation_overhead_exceeded",
    "degraded_but_accepted",
    "blocked",
}
classes = set(report["fixture_classification_counts"])
if not required_classes <= classes:
    raise SystemExit(f"missing fixture classifications: {required_classes - classes}")
commands = {row["workload_id"]: row["command"] for row in report["command_expansions"]}
if "{profile}" in "\n".join(commands.values()):
    raise SystemExit("unexpanded profile placeholder")
if not all(row["target_dir"] for row in report["command_expansions"]):
    raise SystemExit("missing target_dir expansion")
if not any("cargo bench" in command for command in commands.values()):
    raise SystemExit("no cargo bench command expansion")
if not any("mount_benchmark_probe.sh" in command for command in commands.values()):
    raise SystemExit("no mounted FUSE dry-run command expansion")
if not any(
    row["workload_kind"] == "long_campaign_observation"
    and row["skip_semantics"] == "long_campaign_deferred"
    for row in report["command_expansions"]
):
    raise SystemExit("no long-campaign observation workload with deferred skip semantics")
for row in report["fixture_evidence_reports"]:
    for field in (
        "workload_id",
        "claim_tier_before",
        "claim_tier_after",
        "evidence_authority",
        "baseline_id",
        "baseline_artifact_hash",
        "current_artifact_id",
        "current_artifact_hash",
        "environment_fingerprint",
        "environment_matches_claim_lane",
        "metric_unit",
        "observed_value",
        "threshold",
        "freshness_window_days",
        "overhead_budget",
        "runtime_seconds",
        "memory_mib",
        "instrumentation_overhead_percent",
        "statistical_summary",
        "noise_decision",
        "stale_decision",
        "budget_decision",
        "overhead_decision",
        "comparison_verdict",
        "public_claim_state",
        "release_claim_effect",
        "docs_wording_id",
        "output_path",
        "raw_stdout_path",
        "raw_stderr_path",
        "reproduction_command",
    ):
        if field not in row:
            raise SystemExit(f"fixture evidence row missing {field}")
    if row["comparison_verdict"] in {"fail", "noisy", "stale", "missing"}:
        if row["public_claim_state"] not in {"unknown", "experimental"}:
            raise SystemExit(f"quarantined row overclaims public state: {row}")
        if not row["follow_up_bead"].startswith("bd-"):
            raise SystemExit(f"quarantined row missing follow-up bead: {row}")
    if row["comparison_verdict"] in {
        "missing_baseline",
        "environment_mismatch",
        "budget_exceeded",
        "instrumentation_overhead_exceeded",
    } and row["public_claim_state"] not in {"unknown", "experimental"}:
        raise SystemExit(f"budget/evidence failure overclaims public state: {row}")
    if row["claim_tier_after"] in {"measured_authoritative", "regression_free"}:
        if row["evidence_authority"] != "authoritative":
            raise SystemExit(f"authoritative claim lacks authoritative evidence: {row}")
        if row["stale_decision"] != "fresh":
            raise SystemExit(f"authoritative claim is stale: {row}")
        if row["budget_decision"] != "budget_within_limit":
            raise SystemExit(f"authoritative claim exceeded runtime/memory budget: {row}")
        if row["overhead_decision"] != "instrumentation_overhead_within_limit":
            raise SystemExit(f"authoritative claim exceeded instrumentation budget: {row}")
if not any(
    row["fixture_id"] == "fixture_pass_core"
    and row["claim_tier_after"] == "regression_free"
    for row in report["fixture_evidence_reports"]
):
    raise SystemExit("missing regression-free claim mapping")
if not any(
    row["comparison_verdict"] == "degraded_but_accepted"
    and row["claim_tier_after"] == "degraded_but_accepted"
    for row in report["fixture_evidence_reports"]
):
    raise SystemExit("missing degraded-but-accepted claim mapping")
if not any(
    row["comparison_verdict"] == "blocked"
    and row["claim_tier_after"] == "blocked"
    for row in report["fixture_evidence_reports"]
):
    raise SystemExit("missing blocked claim mapping")
if artifact["gate_id"] != "performance_baseline_manifest":
    raise SystemExit("wrong artifact gate_id")
if artifact.get("bead_id") != "bd-rchk5.1":
    raise SystemExit("missing bead id")
categories = {entry["category"] for entry in artifact["artifacts"]}
if "benchmark_baseline" not in categories or "benchmark_report" not in categories:
    raise SystemExit(f"missing benchmark artifact categories: {categories}")
PY
then
    scenario_result "performance_manifest_dry_run_expands" "PASS" "commands and shared QA artifact verified"
else
    scenario_result "performance_manifest_dry_run_expands" "FAIL" "dry-run expansion contract failed"
fi

e2e_step "Scenario 3b: mounted benchmark probe emits structured failure artifacts"
set +e
scripts/mount_benchmark_probe.sh \
    --bin "$E2E_TEMP_DIR/missing-ffs-cli" \
    --image "$E2E_TEMP_DIR/missing.ext4" \
    --mount-root "$E2E_TEMP_DIR/mount-benchmark" \
    --mode warm \
    --out-json "$MOUNT_PROBE_JSON" >"$MOUNT_PROBE_RAW" 2>&1
MOUNT_PROBE_RC=$?
set -e

if python3 - "$MOUNT_PROBE_JSON" "$MOUNT_PROBE_RC" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
rc = int(sys.argv[2])

if rc != 2:
    raise SystemExit(f"expected input-error exit 2, got {rc}")
if report["schema_version"] != 1:
    raise SystemExit("wrong schema_version")
if report["probe_id"] != "mount_benchmark_probe":
    raise SystemExit("wrong probe_id")
if report["outcome"] != "error" or report["classification"] != "input_error":
    raise SystemExit(f"wrong outcome/classification: {report}")
if report["mode"] != "warm":
    raise SystemExit("mode was not preserved")
if report["kernel_fuse_mode"] != "permissioned_required":
    raise SystemExit("missing FUSE lane classification")
if "fuse" not in report["required_capabilities"]:
    raise SystemExit("missing FUSE required capability")
if report["mount_options"]["writeback_cache"] != "disabled":
    raise SystemExit("writeback-cache policy missing")
if report["mount_options"]["background_scrub"] != "disabled_by_probe":
    raise SystemExit("background scrub policy missing")
poll = report["readiness_poll"]
if poll["interval_secs"] != 0.005 or poll["max_wait_secs"] != 10.0:
    raise SystemExit(f"unexpected readiness poll policy: {poll}")
if report["attempts"]:
    raise SystemExit("input validation error should not create mount attempts")
if "ffs-cli binary is not executable" not in report["reason"]:
    raise SystemExit("input-error reason was not preserved")
PY
then
    scenario_result "performance_mount_probe_structured_failure" "PASS" "mount benchmark probe writes structured input-error artifact"
else
    cat "$MOUNT_PROBE_RAW"
    scenario_result "performance_mount_probe_structured_failure" "FAIL" "mount benchmark probe structured failure contract failed"
fi

e2e_step "Scenario 3bb: mounted benchmark probe disables background scrub for mount latency runs"
FAKE_FFS_CLI="$E2E_TEMP_DIR/fake-ffs-cli"
FAKE_PROBE_IMAGE="$E2E_TEMP_DIR/fake-probe.ext4"
: >"$FAKE_PROBE_IMAGE"
cat >"$FAKE_FFS_CLI" <<SH
#!/usr/bin/env bash
printf '%s\n' "\$*" > "$MOUNT_PROBE_ARGS_LOG"
printf 'fake mount rejected after argument capture\n' >&2
exit 43
SH
chmod +x "$FAKE_FFS_CLI"

set +e
scripts/mount_benchmark_probe.sh \
    --bin "$FAKE_FFS_CLI" \
    --image "$FAKE_PROBE_IMAGE" \
    --mount-root "$E2E_TEMP_DIR/mount-benchmark-policy" \
    --mode cold \
    --out-json "$MOUNT_PROBE_POLICY_JSON" >"$MOUNT_PROBE_POLICY_RAW" 2>&1
MOUNT_PROBE_POLICY_RC=$?
set -e

if python3 - "$MOUNT_PROBE_POLICY_JSON" "$MOUNT_PROBE_ARGS_LOG" "$MOUNT_PROBE_POLICY_RC" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
args = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
rc = int(sys.argv[3])

if rc != 1:
    raise SystemExit(f"expected mount failure exit 1, got {rc}")
if "mount --no-background-scrub " not in args:
    raise SystemExit(f"probe did not disable background scrub: {args}")
if report["mount_options"]["background_scrub"] != "disabled_by_probe":
    raise SystemExit(f"probe report lost scrub policy: {report['mount_options']}")
if report["readiness_poll"]["interval_secs"] != 0.005:
    raise SystemExit(f"probe report lost fast polling policy: {report['readiness_poll']}")
if report["classification"] != "mount_failed":
    raise SystemExit(f"fake binary failure should classify as mount_failed: {report['classification']}")
if len(report["attempts"]) != 1 or report["attempts"][0]["cleanup_status"] != "unmounted":
    raise SystemExit(f"probe cleanup evidence missing: {report['attempts']}")
PY
then
    scenario_result "performance_mount_probe_disables_background_scrub" "PASS" "mount probe passes --no-background-scrub and records the policy"
else
    cat "$MOUNT_PROBE_POLICY_RAW"
    scenario_result "performance_mount_probe_disables_background_scrub" "FAIL" "mount benchmark probe did not preserve scrub-disabled latency policy"
fi

e2e_step "Scenario 3c: mounted benchmark pending artifact preserves probe evidence"
if python3 - "$MOUNT_PENDING_BASELINE_JSON" "$MOUNT_PENDING_PROBE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

baseline_path = pathlib.Path(sys.argv[1])
probe_path = pathlib.Path(sys.argv[2])
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
probe = json.loads(probe_path.read_text(encoding="utf-8"))

coverage = baseline["measurement_coverage"]
if coverage["measured_count"] != 0 or coverage["pending_count"] != 1:
    raise SystemExit(f"unexpected coverage: {coverage}")
measurements = baseline["measurements"]
if len(measurements) != 1:
    raise SystemExit(f"expected one targeted pending row, got {len(measurements)}")
row = measurements[0]
if row["operation"] != "mount_warm" or row["status"] != "pending":
    raise SystemExit(f"wrong pending row: {row}")
expected_probe = "baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-pending/ffs_cli_mount_cold_probe_report.json"
if row["source_json"] != expected_probe or row["probe_report_json"] != expected_probe:
    raise SystemExit(f"pending row lost probe path: {row}")
if "Permission denied" not in row["reason"]:
    raise SystemExit("pending reason did not preserve FUSE denial")
if probe["classification"] != "host_capability_skip":
    raise SystemExit(f"wrong probe classification: {probe['classification']}")
if probe["outcome"] != "fail":
    raise SystemExit(f"wrong probe outcome: {probe['outcome']}")
if probe["kernel_fuse_mode"] != "permissioned_required":
    raise SystemExit("missing permissioned FUSE lane")
attempts = probe["attempts"]
if len(attempts) != 1 or attempts[0]["cleanup_status"] != "unmounted":
    raise SystemExit(f"probe did not preserve cleanup evidence: {attempts}")
PY
then
    scenario_result "performance_mount_pending_artifact_preserves_probe" "PASS" "targeted mount_warm pending row points at structured FUSE denial report"
else
    scenario_result "performance_mount_pending_artifact_preserves_probe" "FAIL" "checked-in mount pending artifact lost probe evidence"
fi

e2e_step "Scenario 3d: mounted benchmark measured artifact preserves sudo FUSE evidence"
if python3 - "$MOUNT_MEASURED_BASELINE_JSON" "$MOUNT_MEASURED_HYPERFINE_JSON" "$MOUNT_MEASURED_PROBE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

baseline_path = pathlib.Path(sys.argv[1])
hyperfine_path = pathlib.Path(sys.argv[2])
probe_path = pathlib.Path(sys.argv[3])
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
hyperfine = json.loads(hyperfine_path.read_text(encoding="utf-8"))
probe = json.loads(probe_path.read_text(encoding="utf-8"))

coverage = baseline["measurement_coverage"]
if coverage["measured_count"] != 1 or coverage["pending_count"] != 0:
    raise SystemExit(f"unexpected coverage: {coverage}")
measurements = baseline["measurements"]
if len(measurements) != 1:
    raise SystemExit(f"expected one targeted measured row, got {len(measurements)}")
row = measurements[0]
if row["operation"] != "mount_warm" or row["status"] != "measured":
    raise SystemExit(f"wrong measured row: {row}")
if row["benchmark_mode"] != "hyperfine":
    raise SystemExit(f"wrong benchmark mode: {row}")
expected_hyperfine = "baselines/hyperfine/20260503-bd-rchk5-3-mount-warm-sudo-measured/ffs_cli_mount_warm_probe.json"
if row["source_json"] != expected_hyperfine:
    raise SystemExit(f"measured row lost hyperfine source path: {row}")
if "sudo -n scripts/mount_benchmark_probe.sh" not in row["command"]:
    raise SystemExit("measured command did not preserve sudo FUSE lane")
if not (row["p50_us"] > 0 and row["p99_us"] >= row["p50_us"]):
    raise SystemExit(f"invalid measured latency summary: {row}")
times = hyperfine["results"][0]["times"]
if len(times) != 10 or min(times) <= 0:
    raise SystemExit(f"hyperfine run count/values invalid: {times}")
if probe["classification"] != "measured" or probe["outcome"] != "pass":
    raise SystemExit(f"wrong probe result: {probe}")
labels = [attempt["label"] for attempt in probe["attempts"]]
if labels != ["warm_prepare", "warm_measure"]:
    raise SystemExit(f"warm probe attempts not preserved: {labels}")
if any(not attempt["ready"] or attempt["cleanup_status"] != "unmounted" for attempt in probe["attempts"]):
    raise SystemExit(f"warm probe cleanup failed: {probe['attempts']}")
PY
then
    scenario_result "performance_mount_measured_artifact_preserves_probe" "PASS" "targeted mount_warm measured row points at sudo FUSE hyperfine and probe reports"
else
    scenario_result "performance_mount_measured_artifact_preserves_probe" "FAIL" "checked-in mount measured artifact lost sudo FUSE evidence"
fi

e2e_step "Scenario 4: invalid manifest variants fail closed"
python3 - "$MANIFEST_JSON" "$BAD_CAP_JSON" "$BAD_ENV_JSON" "$BAD_ARTIFACT_JSON" "$BAD_UNIT_JSON" "$BAD_TARGET_JSON" "$BAD_RAW_LOG_JSON" "$BAD_FIXTURE_JSON" "$BAD_CLAIM_JSON" "$BAD_STATS_JSON" "$BAD_AUTHORITATIVE_JSON" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

(
    source,
    bad_cap,
    bad_env,
    bad_artifact,
    bad_unit,
    bad_target,
    bad_raw_log,
    bad_fixture,
    bad_claim,
    bad_stats,
    bad_authoritative,
) = map(pathlib.Path, sys.argv[1:])
base = json.loads(source.read_text(encoding="utf-8"))

cap = json.loads(json.dumps(base))
cap["workloads"][0]["required_capabilities"].append("unknown_accelerator")
bad_cap.write_text(json.dumps(cap, indent=2, sort_keys=True) + "\n", encoding="utf-8")

env = json.loads(json.dumps(base))
env["required_environment_fields"] = [f for f in env["required_environment_fields"] if f != "git_sha"]
bad_env.write_text(json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8")

artifact = json.loads(json.dumps(base))
artifact["workloads"][0]["output_artifact"]["aggregate_key"] = "median_ns"
artifact["workloads"][0]["output_artifact"]["path_template"] = "results/static.json"
bad_artifact.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")

unit = json.loads(json.dumps(base))
unit["workloads"][0]["metric_unit"] = "invalid_unit"
bad_unit.write_text(json.dumps(unit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

target = json.loads(json.dumps(base))
target["workloads"][0]["target_dir_template"] = "static-target"
bad_target.write_text(json.dumps(target, indent=2, sort_keys=True) + "\n", encoding="utf-8")

raw_log = json.loads(json.dumps(base))
raw_log["workloads"][0]["required_raw_logs"] = ["stdout"]
bad_raw_log.write_text(json.dumps(raw_log, indent=2, sort_keys=True) + "\n", encoding="utf-8")

fixture = json.loads(json.dumps(base))
for workload in fixture["workloads"]:
    if workload["workload_id"] == "mvcc_conflict_detection_rate":
        workload["quarantine_policy"]["follow_up_bead"] = ""
bad_fixture.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")

claim = json.loads(json.dumps(base))
claim["workloads"][0]["claim_policy"]["clean_claim_tier"] = "measured_authoritative"
claim["workloads"][0]["claim_policy"]["release_claim_effect"] = "local_claim"
bad_claim.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n", encoding="utf-8")

stats = json.loads(json.dumps(base))
del stats["fixture_evidence"][0]["statistical_summary"]
bad_stats.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")

authoritative = json.loads(json.dumps(base))
authoritative["fixture_evidence"][0]["evidence_authority"] = "local"
bad_authoritative.write_text(json.dumps(authoritative, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

invalid_failures=0
for bad in "$BAD_CAP_JSON" "$BAD_ENV_JSON" "$BAD_ARTIFACT_JSON" "$BAD_UNIT_JSON" "$BAD_TARGET_JSON" "$BAD_RAW_LOG_JSON" "$BAD_FIXTURE_JSON" "$BAD_CLAIM_JSON" "$BAD_STATS_JSON" "$BAD_AUTHORITATIVE_JSON"; do
    bad_payload="$(tr -d '\n' <"$bad")"
    if (
        export PERFORMANCE_BASELINE_MANIFEST_JSON="$bad_payload"
        export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}PERFORMANCE_BASELINE_MANIFEST_JSON"
        run_rch_capture "$BAD_RAW" cargo run --quiet -p ffs-harness -- validate-performance-baseline-manifest \
            --manifest-json-env PERFORMANCE_BASELINE_MANIFEST_JSON \
            --out /dev/stdout
    ); then
        e2e_log "Unexpectedly accepted invalid manifest: $bad"
        invalid_failures=$((invalid_failures + 1))
    elif ! grep -q "performance baseline manifest validation failed\\|invalid performance manifest JSON" "$BAD_RAW"; then
        e2e_log "Invalid manifest failed without expected diagnostic: $bad"
        invalid_failures=$((invalid_failures + 1))
    fi
done

if ((invalid_failures == 0)); then
    scenario_result "performance_manifest_invalid_variants_rejected" "PASS" "bad capability/env/artifact/unit/claim/budget variants rejected"
else
    scenario_result "performance_manifest_invalid_variants_rejected" "FAIL" "invalid_failures=${invalid_failures}"
fi

e2e_step "Scenario 5: performance manifest unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib performance_baseline_manifest -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "performance_manifest_unit_tests" "PASS" "performance manifest unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "performance_manifest_unit_tests" "FAIL" "performance manifest unit tests failed"
fi

e2e_log "Performance manifest: $MANIFEST_JSON"
e2e_log "Validation report: $REPORT_JSON"
e2e_log "Sample artifact manifest: $ARTIFACT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Performance manifest scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Performance manifest scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
