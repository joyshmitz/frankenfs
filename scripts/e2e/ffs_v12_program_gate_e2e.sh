#!/usr/bin/env bash
# ffs_v12_program_gate_e2e.sh - V1.2 program acceptance rollup (bd-ckivp).
#
# Writes structured per-scenario JSONL plus a program gate manifest under
# artifacts/release_gate/v12/. Cargo-bearing checks are always routed through
# rch; this script never invokes cargo directly.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/.cargo-target-frankenfs-v12-program-gate}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR,RUST_LOG,RUST_BACKTRACE"

ARTIFACT_DIR="${FFS_V12_PROGRAM_GATE_ARTIFACT_DIR:-$REPO_ROOT/artifacts/release_gate/v12}"
SCENARIO_DIR="$ARTIFACT_DIR/scenarios"
MANIFEST_JSON="$ARTIFACT_DIR/program_gate_manifest.json"
COMMAND_LOG="$ARTIFACT_DIR/command_transcript.tsv"
DEFAULT_BUDGET_SECS="${FFS_V12_PROGRAM_GATE_SCENARIO_TIMEOUT_SECS:-300}"
SMOKE_MODE="${FFS_V12_PROGRAM_GATE_SMOKE:-0}"

PASS_COUNT=0
FAIL_COUNT=0
TIMEOUT_COUNT=0
SKIP_COUNT=0
TOTAL=0
SCENARIO_RECORDS=()

mkdir -p "$SCENARIO_DIR"
printf 'started_at\tscenario\tname\texit_code\tcommand\tstdout\tstderr\n' >"$COMMAND_LOG"

json_quote() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

iso_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

tail_text() {
    local path="$1"
    if [[ -f "$path" ]]; then
        tail -c 200 "$path" | tr '\n' ' '
    fi
}

write_scenario_record() {
    local number="$1"
    local name="$2"
    local status="$3"
    local started_at="$4"
    local finished_at="$5"
    local duration_ms="$6"
    local budget_ms="$7"
    local child_gate_bead="$8"
    local exit_code="$9"
    local stdout_path="${10}"
    local stderr_path="${11}"
    local evidence_paths="${12}"
    local stderr_tail
    stderr_tail="$(tail_text "$stderr_path")"

    local scenario_file="$SCENARIO_DIR/scenario_${number}.jsonl"
    local record_file="$E2E_LOG_DIR/scenario_${number}.json"
    python3 - "$record_file" "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$budget_ms" "$child_gate_bead" "$exit_code" "$stderr_tail" \
        "$stdout_path" "$stderr_path" "$evidence_paths" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

(
    record_file,
    number,
    name,
    status,
    started_at,
    finished_at,
    duration_ms,
    budget_ms,
    child_gate_bead,
    exit_code,
    stderr_tail,
    stdout_path,
    stderr_path,
    evidence_paths,
) = sys.argv[1:]

record = {
    "scenario": int(number),
    "name": name,
    "status": status,
    "duration_ms": int(duration_ms),
    "budget_ms": int(budget_ms),
    "started_at": started_at,
    "finished_at": finished_at,
    "evidence_paths": [item for item in evidence_paths.split(";") if item],
    "child_gate_bead": child_gate_bead,
    "exit_code": int(exit_code),
    "stdout_path": stdout_path,
    "stderr_path": stderr_path,
    "stderr_tail": stderr_tail,
}
pathlib.Path(record_file).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
PY
    cat "$record_file" >>"$scenario_file"
    cat "$record_file"
    SCENARIO_RECORDS+=("$record_file")

    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        TIMEOUT) TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
        *) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    esac
    TOTAL=$((TOTAL + 1))
    e2e_log "SCENARIO_RESULT|scenario_id=v12_program_gate_${number}|outcome=${status}|detail=${name}"
}

run_scenario_command() {
    local number="$1"
    local name="$2"
    local child_gate_bead="$3"
    local budget_secs="${4:-$DEFAULT_BUDGET_SECS}"
    shift 4

    local stdout_path="$ARTIFACT_DIR/scenario_${number}.stdout"
    local stderr_path="$ARTIFACT_DIR/scenario_${number}.stderr"
    local started_at finished_at started_s finished_s duration_ms budget_ms status exit_code
    local command_text
    started_at="$(iso_now)"
    started_s="$(date +%s)"
    command_text="$*"
    e2e_step "Scenario ${number}: ${name}"

    set +e
    timeout "${budget_secs}s" "$@" >"$stdout_path" 2>"$stderr_path"
    exit_code=$?
    set -e

    finished_at="$(iso_now)"
    finished_s="$(date +%s)"
    duration_ms=$(((finished_s - started_s) * 1000))
    budget_ms=$((budget_secs * 1000))
    if [[ "$exit_code" -eq 0 ]]; then
        status="PASS"
    elif [[ "$exit_code" -eq 124 ]]; then
        status="TIMEOUT"
    else
        status="FAIL"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_at" "$number" "$name" "$exit_code" "$command_text" "$stdout_path" "$stderr_path" >>"$COMMAND_LOG"
    write_scenario_record "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$budget_ms" "$child_gate_bead" "$exit_code" "$stdout_path" "$stderr_path" \
        "$stdout_path;$stderr_path"
}

run_scenario_check() {
    local number="$1"
    local name="$2"
    local child_gate_bead="$3"
    local expression="$4"
    local started_at finished_at started_s finished_s duration_ms
    local stdout_path="$ARTIFACT_DIR/scenario_${number}.stdout"
    local stderr_path="$ARTIFACT_DIR/scenario_${number}.stderr"
    started_at="$(iso_now)"
    started_s="$(date +%s)"
    e2e_step "Scenario ${number}: ${name}"
    set +e
    bash -c "$expression" >"$stdout_path" 2>"$stderr_path"
    local exit_code=$?
    set -e
    finished_at="$(iso_now)"
    finished_s="$(date +%s)"
    duration_ms=$(((finished_s - started_s) * 1000))
    local status="FAIL"
    [[ "$exit_code" -eq 0 ]] && status="PASS"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_at" "$number" "$name" "$exit_code" "$expression" "$stdout_path" "$stderr_path" >>"$COMMAND_LOG"
    write_scenario_record "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$((DEFAULT_BUDGET_SECS * 1000))" "$child_gate_bead" "$exit_code" \
        "$stdout_path" "$stderr_path" "$stdout_path;$stderr_path"
}

run_smoke_mode() {
    run_scenario_check 1 "synthetic PASS fixture" "bd-ckivp" "printf 'synthetic pass\n'"
    if [[ "${FFS_V12_PROGRAM_GATE_SMOKE_EXPECT_FAIL:-0}" == "1" ]]; then
        run_scenario_check 2 "synthetic FAIL fixture" "bd-ckivp" "printf 'synthetic fail\n' >&2; exit 42"
    else
        run_scenario_check 2 "synthetic second PASS fixture" "bd-ckivp" "printf 'synthetic pass 2\n'"
    fi
}

run_full_mode() {
    run_scenario_command 1 "bd-m5wf.1.7 performance optimization gate" "bd-m5wf.1.7" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo test -p ffs-harness --lib perf_comparison -- --nocapture
    run_scenario_command 2 "bd-m5wf.2.5 writeback-cache gate" "bd-m5wf.2.5" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo test -p ffs-core writeback -- --nocapture
    run_scenario_command 3 "bd-m5wf.3.5 safe-merge high-contention gate" "bd-m5wf.3.5" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo test -p ffs-mvcc --test mvcc_stress_suite verification_gate_safe_merge_correctness_under_high_contention -- --nocapture
    run_scenario_command 4 "bd-m5wf.4.5 adaptive refresh gate" "bd-m5wf.4.5" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo test -p ffs-repair verification_gate_hybrid -- --nocapture
    run_scenario_command 5 "bd-m5wf.5.5 multi-host repair gate" "bd-m5wf.5.5" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_repair_recovery_smoke.sh
    run_scenario_command 6 "bd-m5wf.6.5 btrfs multi-device and subvolume gate" "bd-m5wf.6.5" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo test -p ffs-core btrfs_subvolume -- --nocapture
    run_scenario_command 7 "bd-m5wf.7.5 xfstests conformance regression gate" "bd-m5wf.7.5" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_xfstests_regression_gate.sh
    run_scenario_command 8 "bd-m5wf.8.7 observability metrics and dashboard gate" "bd-m5wf.8.7" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_operator_tooling_gate_e2e.sh
    run_scenario_command 9 "bd-m5wf.9.5 coverage hardening gate" "bd-m5wf.9.5" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_verification_gate_e2e.sh
    run_scenario_command 10 "workspace format gate" "bd-ckivp" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo fmt --check
    run_scenario_command 11 "workspace clippy gate" "bd-ckivp" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo clippy --workspace --all-targets -- -D warnings
    run_scenario_command 12 "workspace tests no-fail-fast gate" "bd-ckivp" "$DEFAULT_BUDGET_SECS" \
        "${RCH_BIN:-rch}" exec -- cargo test --workspace --no-fail-fast
    run_scenario_check 13 "CLI ergonomics evidence" "bd-ckivp" \
        "grep -q '\"mount\"' crates/ffs-cli/src/main.rs && grep -q '\"repair\"' crates/ffs-cli/src/main.rs && grep -q '\"evidence\"' crates/ffs-cli/src/main.rs && grep -q '\"mkfs\"' crates/ffs-cli/src/main.rs"
    run_scenario_check 14 "structured logging traceability evidence" "bd-ckivp" \
        "grep -q 'degradation_transition' crates/ffs-core/src/degradation.rs && grep -q 'wal_replay_start' crates/ffs-mvcc/src/wal_replay.rs && grep -q 'repair_complete' crates/ffs-cli/src/cmd_repair.rs && grep -q 'evidence_preset' crates/ffs-cli/src/cmd_evidence.rs"
}

write_manifest() {
    local recommendation="PROCEED"
    local reason="all scenarios passed"
    if [[ "$FAIL_COUNT" -gt 0 || "$TIMEOUT_COUNT" -gt 0 ]]; then
        recommendation="NO-PROCEED"
        reason="${FAIL_COUNT} failed, ${TIMEOUT_COUNT} timed out"
    elif [[ -s "$REPO_ROOT/docs/release/V1.2_test_waivers.md" ]]; then
        recommendation="PASS-WITH-WAIVERS"
        reason="all scenarios passed with documented waivers"
    fi

    local records_json="$E2E_LOG_DIR/scenario_records.json"
    python3 - "$records_json" "${SCENARIO_RECORDS[@]}" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

records = []
for item in sys.argv[2:]:
    records.append(json.loads(pathlib.Path(item).read_text(encoding="utf-8")))
pathlib.Path(sys.argv[1]).write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
PY

    local git_head kernel rustc cargo_version package_version waiver_path
    git_head="$(git rev-parse HEAD)"
    kernel="$(uname -srmo 2>/dev/null || uname -a)"
    rustc="$("${RUSTC_BIN:-rustc}" --version 2>/dev/null || printf 'rustc unavailable')"
    cargo_version="$("${CARGO_BIN:-cargo}" --version 2>/dev/null || printf 'cargo unavailable')"
    package_version="$(sed -n 's/^version = \"\\(.*\\)\"/\\1/p' crates/ffs-harness/Cargo.toml | head -1)"
    waiver_path="docs/release/V1.2_test_waivers.md"

    python3 - "$MANIFEST_JSON" "$records_json" "$recommendation" "$reason" "$git_head" \
        "$kernel" "$rustc" "$cargo_version" "$package_version" "$COMMAND_LOG" "$waiver_path" \
        "$PASS_COUNT" "$FAIL_COUNT" "$TIMEOUT_COUNT" "$SKIP_COUNT" "$TOTAL" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone

(
    out_path,
    records_path,
    recommendation,
    reason,
    git_head,
    kernel,
    rustc,
    cargo_version,
    package_version,
    command_log,
    waiver_path,
    pass_count,
    fail_count,
    timeout_count,
    skip_count,
    total,
) = sys.argv[1:]

records = json.loads(pathlib.Path(records_path).read_text(encoding="utf-8"))
payload = {
    "schema_version": 1,
    "gate_id": "bd-ckivp-v12-program-gate",
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "git_head": git_head,
    "environment": {
        "kernel": kernel,
        "rustc": rustc,
        "cargo": cargo_version,
        "ffs_harness_version": package_version,
    },
    "scenario_count": int(total),
    "pass_count": int(pass_count),
    "fail_count": int(fail_count),
    "timeout_count": int(timeout_count),
    "skip_count": int(skip_count),
    "scenarios": records,
    "release_recommendation": recommendation,
    "release_recommendation_reason": reason,
    "command_transcript": command_log,
    "waiver_document": waiver_path,
}
pathlib.Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    e2e_log "V1.2 program gate manifest: $MANIFEST_JSON"
    e2e_log "RELEASE RECOMMENDATION: $recommendation"
    e2e_log "Reason: $reason"
}

e2e_init "ffs_v12_program_gate"
e2e_print_env

if [[ "$SMOKE_MODE" == "1" ]]; then
    run_smoke_mode
else
    run_full_mode
fi

write_manifest

if [[ "$FAIL_COUNT" -gt 0 || "$TIMEOUT_COUNT" -gt 0 ]]; then
    e2e_fail "ffs_v12_program_gate NO-PROCEED: ${FAIL_COUNT} failed, ${TIMEOUT_COUNT} timed out"
else
    e2e_pass "ffs_v12_program_gate completed"
fi
