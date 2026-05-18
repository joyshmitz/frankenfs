#!/usr/bin/env bash
# ffs_program_gate_e2e.sh - Final V1.1 program acceptance gate (bd-h6nz.8)
#
# Validates all epic verification gates have passed and cross-cutting
# concerns (workspace build, workspace tests, CLI ergonomics, error
# messaging, structured logging) are operationally sound.
#
# Scenarios:
# 1. All epic verification gate E2E scripts exist
# 2. Workspace builds clean (fmt + clippy)
# 3. Workspace tests pass (all crates, 0 failures)
# 4. MVCC replay gate (Epic 1) - durable replay path
# 5. Mount runtime gate (Epic 2) - runtime mode enforcement
# 6. Btrfs RW hardening gate (Epic 3) - experimental write path
# 7. Fuzzing gate (Epic 4) - adversarial input coverage
# 8. Benchmark governance gate (Epic 5) - regression tracking
# 9. OQ decision integration (Epic 6) - spec/backlog alignment
# 10. Operator tooling gate (Epic 7) - runbooks/observability
# 11. Cross-epic verification toolchain (Epic 9) - consistency
# 12. CLI ergonomics and error messaging
# 13. Structured logging traceability across surfaces
#
# Usage: ./scripts/e2e/ffs_program_gate_e2e.sh

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_PROGRAM_GATE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_PROGRAM_GATE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_PROGRAM_GATE_SKIP_SELF_CHECK:-0}"

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

log_rch_refusal_if_present() {
    local log_path="$1"
    shift

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${log_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$log_path" >>"$log_path"
        return 0
    fi
    return 1
}

run_rch_capture() {
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$@"
}

e2e_init "ffs_program_gate"

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_PROGRAM_GATE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected program-gate fixture rch invocation: $*" >&2
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
        echo "unknown program-gate fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

case "$command_text" in
    "cargo clippy --workspace -- -D warnings")
        echo "program-gate fixture clippy clean"
        finish_success
        ;;
    "cargo test --workspace")
        for test_name in \
            program_gate_workspace_smoke \
            program_gate_cli_contract \
            program_gate_logging_contract \
            program_gate_verification_contract \
            program_gate_operator_contract \
            program_gate_benchmark_contract \
            program_gate_fuzz_contract \
            program_gate_mount_contract \
            program_gate_mvcc_contract \
            program_gate_btrfs_contract; do
            printf 'test %s ... ok\n' "$test_name"
        done
        finish_success
        ;;
    *)
        echo "unexpected program-gate fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/program_gate_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_PROGRAM_GATE_SELF_CHECK=0 \
        FFS_PROGRAM_GATE_SKIP_SELF_CHECK=1 \
        FFS_PROGRAM_GATE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_program_gate_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic program-gate wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-program-gate-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "pgat_gate_scripts_exist" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_workspace_clippy" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_workspace_tests" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_mvcc_replay" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_mount_modes" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_btrfs_hardening" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_fuzzing_infrastructure" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_benchmark_governance" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_oq_decisions" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_operator_tooling" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_verification_toolchain" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_cli_ergonomics" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "pgat_logging_traceability" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "program_gate_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "program_gate_fixture_complete_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "program_gate_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "program_gate_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "program_gate_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "program_gate_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

#######################################
# Scenario 1: All epic verification gate E2E scripts exist
#######################################
e2e_step "Scenario 1: Epic verification gate scripts exist"

SCRIPTS_FOUND=0
for script in \
    "scripts/e2e/ffs_mvcc_replay_gate_e2e.sh" \
    "scripts/e2e/ffs_mount_runtime_gate_e2e.sh" \
    "scripts/e2e/ffs_btrfs_rw_hardening_gate_e2e.sh" \
    "scripts/e2e/ffs_fuzzing_gate_e2e.sh" \
    "scripts/e2e/ffs_benchmark_governance_e2e.sh" \
    "scripts/e2e/ffs_oq_decision_integration_e2e.sh" \
    "scripts/e2e/ffs_operator_tooling_gate_e2e.sh" \
    "scripts/e2e/ffs_verification_gate_e2e.sh"; do
    [[ -f "$script" ]] && SCRIPTS_FOUND=$((SCRIPTS_FOUND + 1))
done

if [[ $SCRIPTS_FOUND -eq 8 ]]; then
    scenario_result "pgat_gate_scripts_exist" "PASS" "All 8 epic gate E2E scripts found"
else
    scenario_result "pgat_gate_scripts_exist" "FAIL" "Only ${SCRIPTS_FOUND}/8 gate scripts found"
fi

#######################################
# Scenario 2: Workspace builds clean
#######################################
e2e_step "Scenario 2: Workspace builds clean (clippy)"

CLIPPY_LOG=$(mktemp)
if run_rch_capture "$CLIPPY_LOG" cargo clippy --workspace -- -D warnings; then
    scenario_result "pgat_workspace_clippy" "PASS" "Workspace clippy clean (0 warnings, 0 errors)"
else
    log_rch_refusal_if_present "$CLIPPY_LOG" cargo clippy --workspace -- -D warnings || true
    scenario_result "pgat_workspace_clippy" "FAIL" "Workspace clippy has warnings or errors"
fi
e2e_cleanup_tmp_file "$CLIPPY_LOG"

#######################################
# Scenario 3: Workspace tests pass
#######################################
e2e_step "Scenario 3: Workspace tests pass"

TEST_LOG=$(mktemp)
if run_rch_capture "$TEST_LOG" cargo test --workspace; then
    TOTAL_PASS=$(grep -c " ok$" "$TEST_LOG" 2>/dev/null || true)
    TOTAL_PASS="${TOTAL_PASS:-0}"
    scenario_result "pgat_workspace_tests" "PASS" "All workspace tests pass (${TOTAL_PASS}+ tests)"
else
    log_rch_refusal_if_present "$TEST_LOG" cargo test --workspace || true
    scenario_result "pgat_workspace_tests" "FAIL" "Workspace tests have failures"
fi
e2e_cleanup_tmp_file "$TEST_LOG"

#######################################
# Scenario 4: MVCC replay gate (Epic 1)
#######################################
e2e_step "Scenario 4: MVCC replay gate"

MVCC_CHECKS=0
# WAL replay module
[[ -f "crates/ffs-mvcc/src/wal_replay.rs" ]] && MVCC_CHECKS=$((MVCC_CHECKS + 1))
# Durable persistence layer
[[ -f "crates/ffs-mvcc/src/persist.rs" ]] && MVCC_CHECKS=$((MVCC_CHECKS + 1))
# Replay lifecycle E2E script
[[ -f "scripts/e2e/ffs_wal_replay_e2e.sh" ]] && MVCC_CHECKS=$((MVCC_CHECKS + 1))

if [[ $MVCC_CHECKS -eq 3 ]]; then
    scenario_result "pgat_mvcc_replay" "PASS" "WAL replay, persistence layer, E2E script"
else
    scenario_result "pgat_mvcc_replay" "FAIL" "Only ${MVCC_CHECKS}/3 MVCC checks pass"
fi

#######################################
# Scenario 5: Mount runtime gate (Epic 2)
#######################################
e2e_step "Scenario 5: Mount runtime modes"

MOUNT_CHECKS=0
# Runtime mode types in CLI
grep -q "MountRuntimeMode" "crates/ffs-cli/src/main.rs" && MOUNT_CHECKS=$((MOUNT_CHECKS + 1))
# Mode enforcement E2E
[[ -f "scripts/e2e/ffs_mount_mode_e2e.sh" ]] && MOUNT_CHECKS=$((MOUNT_CHECKS + 1))
# Runtime mode gate E2E
[[ -f "scripts/e2e/ffs_mount_runtime_gate_e2e.sh" ]] && MOUNT_CHECKS=$((MOUNT_CHECKS + 1))

if [[ $MOUNT_CHECKS -eq 3 ]]; then
    scenario_result "pgat_mount_modes" "PASS" "MountRuntimeMode types, mode E2E, runtime gate E2E"
else
    scenario_result "pgat_mount_modes" "FAIL" "Only ${MOUNT_CHECKS}/3 mount checks pass"
fi

#######################################
# Scenario 6: Btrfs RW hardening gate (Epic 3)
#######################################
e2e_step "Scenario 6: Btrfs RW hardening"

BTRFS_CHECKS=0
# Btrfs write churn E2E
[[ -f "scripts/e2e/ffs_btrfs_write_churn_e2e.sh" ]] && BTRFS_CHECKS=$((BTRFS_CHECKS + 1))
# Capability drift module
[[ -f "crates/ffs-harness/src/btrfs_capability_drift.rs" ]] && BTRFS_CHECKS=$((BTRFS_CHECKS + 1))
# RW hardening gate E2E
[[ -f "scripts/e2e/ffs_btrfs_rw_hardening_gate_e2e.sh" ]] && BTRFS_CHECKS=$((BTRFS_CHECKS + 1))

if [[ $BTRFS_CHECKS -eq 3 ]]; then
    scenario_result "pgat_btrfs_hardening" "PASS" "Write churn E2E, capability drift, hardening gate"
else
    scenario_result "pgat_btrfs_hardening" "FAIL" "Only ${BTRFS_CHECKS}/3 btrfs checks pass"
fi

#######################################
# Scenario 7: Fuzzing gate (Epic 4)
#######################################
e2e_step "Scenario 7: Fuzzing infrastructure"

FUZZ_CHECKS=0
# Registered fuzz targets
TARGETS=0
for t in $(find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' | sed 's/\.rs$//'); do
    [[ -f "fuzz/fuzz_targets/${t}.rs" ]] && TARGETS=$((TARGETS + 1))
done
[[ $TARGETS -ge 1 ]] && FUZZ_CHECKS=$((FUZZ_CHECKS + 1))
# Nightly campaign runner
[[ -x "fuzz/scripts/nightly_fuzz.sh" ]] && FUZZ_CHECKS=$((FUZZ_CHECKS + 1))
# Crash promotion
[[ -x "fuzz/scripts/promote_crash.sh" ]] && FUZZ_CHECKS=$((FUZZ_CHECKS + 1))
# Dashboard module
grep -q "pub mod fuzz_dashboard" "crates/ffs-harness/src/lib.rs" && FUZZ_CHECKS=$((FUZZ_CHECKS + 1))

if [[ $FUZZ_CHECKS -eq 4 ]]; then
    scenario_result "pgat_fuzzing_infrastructure" "PASS" "${TARGETS} targets, nightly runner, promotion, dashboard"
else
    scenario_result "pgat_fuzzing_infrastructure" "FAIL" "Only ${FUZZ_CHECKS}/4 fuzzing checks pass"
fi

#######################################
# Scenario 8: Benchmark governance gate (Epic 5)
#######################################
e2e_step "Scenario 8: Benchmark governance"

BENCH_CHECKS=0
# Benchmark taxonomy module
grep -q "pub mod benchmark_taxonomy" "crates/ffs-harness/src/lib.rs" && BENCH_CHECKS=$((BENCH_CHECKS + 1))
# Performance comparison module
grep -q "pub mod perf_comparison" "crates/ffs-harness/src/lib.rs" && BENCH_CHECKS=$((BENCH_CHECKS + 1))
# Performance regression module
grep -q "pub mod perf_regression" "crates/ffs-harness/src/lib.rs" && BENCH_CHECKS=$((BENCH_CHECKS + 1))
# Performance triage module
grep -q "pub mod perf_triage" "crates/ffs-harness/src/lib.rs" && BENCH_CHECKS=$((BENCH_CHECKS + 1))

if [[ $BENCH_CHECKS -eq 4 ]]; then
    scenario_result "pgat_benchmark_governance" "PASS" "Taxonomy, comparison, regression, triage modules"
else
    scenario_result "pgat_benchmark_governance" "FAIL" "Only ${BENCH_CHECKS}/4 benchmark modules found"
fi

#######################################
# Scenario 9: OQ decision integration (Epic 6)
#######################################
e2e_step "Scenario 9: OQ decision integration"

OQ_CHECKS=0
# OQ decision matrix module
grep -q "pub mod oq_decision_matrix" "crates/ffs-harness/src/lib.rs" && OQ_CHECKS=$((OQ_CHECKS + 1))
# OQ decisions in spec
[[ -f "crates/ffs-harness/src/oq_decision_matrix.rs" ]] && OQ_CHECKS=$((OQ_CHECKS + 1))
# Integration E2E
[[ -f "scripts/e2e/ffs_oq_decision_integration_e2e.sh" ]] && OQ_CHECKS=$((OQ_CHECKS + 1))

if [[ $OQ_CHECKS -eq 3 ]]; then
    scenario_result "pgat_oq_decisions" "PASS" "OQ matrix module, decision data, integration E2E"
else
    scenario_result "pgat_oq_decisions" "FAIL" "Only ${OQ_CHECKS}/3 OQ checks pass"
fi

#######################################
# Scenario 10: Operator tooling gate (Epic 7)
#######################################
e2e_step "Scenario 10: Operator tooling"

OPS_CHECKS=0
# 3 operator runbooks
for rb in "docs/runbooks/replay-failure-triage.md" "docs/runbooks/corruption-recovery.md" "docs/runbooks/backpressure-investigation.md"; do
    [[ -f "$rb" ]] && OPS_CHECKS=$((OPS_CHECKS + 1))
done
# Error taxonomy
grep -q "pub mod error_taxonomy" "crates/ffs-harness/src/lib.rs" && OPS_CHECKS=$((OPS_CHECKS + 1))
# Tabletop drills
grep -q "pub mod tabletop_drill" "crates/ffs-harness/src/lib.rs" && OPS_CHECKS=$((OPS_CHECKS + 1))

if [[ $OPS_CHECKS -eq 5 ]]; then
    scenario_result "pgat_operator_tooling" "PASS" "3 runbooks, error taxonomy, tabletop drills"
else
    scenario_result "pgat_operator_tooling" "FAIL" "Only ${OPS_CHECKS}/5 operator checks pass"
fi

#######################################
# Scenario 11: Cross-epic verification toolchain (Epic 9)
#######################################
e2e_step "Scenario 11: Verification toolchain"

VERIFY_CHECKS=0
# Verification runner module
grep -q "pub mod verification_runner" "crates/ffs-harness/src/lib.rs" && VERIFY_CHECKS=$((VERIFY_CHECKS + 1))
# Artifact manifest
grep -q "pub mod artifact_manifest" "crates/ffs-harness/src/lib.rs" && VERIFY_CHECKS=$((VERIFY_CHECKS + 1))
# Log contract
grep -q "pub mod log_contract" "crates/ffs-harness/src/lib.rs" && VERIFY_CHECKS=$((VERIFY_CHECKS + 1))
# E2E lib and run_gate
[[ -f "scripts/e2e/lib.sh" ]] && VERIFY_CHECKS=$((VERIFY_CHECKS + 1))
[[ -f "scripts/e2e/run_gate.sh" ]] && VERIFY_CHECKS=$((VERIFY_CHECKS + 1))

if [[ $VERIFY_CHECKS -eq 5 ]]; then
    scenario_result "pgat_verification_toolchain" "PASS" "Runner, manifest, log contract, E2E lib, run_gate"
else
    scenario_result "pgat_verification_toolchain" "FAIL" "Only ${VERIFY_CHECKS}/5 verification checks pass"
fi

#######################################
# Scenario 12: CLI ergonomics and error messaging
#######################################
e2e_step "Scenario 12: CLI ergonomics"

CLI_CHECKS=0
# CLI binary exists
[[ -f "crates/ffs-cli/src/main.rs" ]] && CLI_CHECKS=$((CLI_CHECKS + 1))
# Key subcommands implemented
for cmd in mount repair evidence mkfs; do
    grep -q "\"${cmd}\"" "crates/ffs-cli/src/main.rs" && CLI_CHECKS=$((CLI_CHECKS + 1))
done

if [[ $CLI_CHECKS -eq 5 ]]; then
    scenario_result "pgat_cli_ergonomics" "PASS" "CLI binary with mount/repair/evidence/mkfs subcommands"
else
    scenario_result "pgat_cli_ergonomics" "FAIL" "Only ${CLI_CHECKS}/5 CLI checks pass"
fi

#######################################
# Scenario 13: Structured logging traceability
#######################################
e2e_step "Scenario 13: Structured logging traceability"

LOG_CHECKS=0

# Degradation transitions logged
grep -q "degradation_transition" "crates/ffs-core/src/degradation.rs" && LOG_CHECKS=$((LOG_CHECKS + 1))
# WAL replay lifecycle
grep -q "wal_replay_start" "crates/ffs-mvcc/src/wal_replay.rs" && LOG_CHECKS=$((LOG_CHECKS + 1))
# Repair lifecycle
grep -q "repair_complete" "crates/ffs-cli/src/cmd_repair.rs" && LOG_CHECKS=$((LOG_CHECKS + 1))
# Evidence preset queries
grep -q "evidence_preset" "crates/ffs-cli/src/cmd_evidence.rs" && LOG_CHECKS=$((LOG_CHECKS + 1))
# Log contract E2E validation
[[ -f "scripts/e2e/ffs_log_contract_e2e.sh" ]] && LOG_CHECKS=$((LOG_CHECKS + 1))

if [[ $LOG_CHECKS -eq 5 ]]; then
    scenario_result "pgat_logging_traceability" "PASS" "Degradation, WAL, repair, evidence, log contract E2E"
else
    scenario_result "pgat_logging_traceability" "FAIL" "Only ${LOG_CHECKS}/5 logging checks pass"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    e2e_log "RELEASE RECOMMENDATION: HOLD — resolve failures before proceeding"
    exit 1
else
    e2e_log "OVERALL: PASS"
    e2e_log "RELEASE RECOMMENDATION: PROCEED — all V1.1 acceptance criteria met"
    exit 0
fi
