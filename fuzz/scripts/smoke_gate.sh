#!/usr/bin/env bash
# smoke_gate.sh — deterministic fuzz smoke gate for high-risk parsers.
#
# Address bd-rchk7.4: routine pre-merge / pre-release sanity gate that runs
# the parser/metadata surfaces most likely to regress, with a small
# deterministic budget. Distinct from nightly_fuzz.sh (which runs every
# target for minutes); this gate stays under ~2 minutes wall-time for
# routine use while preserving each target's full corpus for deeper
# campaigns.
#
# Behaviour:
#   * For each high-risk target, replay the full corpus (-runs=0) to detect
#     any regression that the existing seeds would catch instantly.
#   * Then run a tiny mutation budget (-runs=2000) with a fixed PRNG seed
#     so the gate is deterministic across runs (same input sequence).
#   * Exit non-zero on the first failure; print a summary line per target.
#
# Usage:
#   ./fuzz/scripts/smoke_gate.sh                 # default budget
#   ./fuzz/scripts/smoke_gate.sh --runs 500     # smaller budget
#   ./fuzz/scripts/smoke_gate.sh --seed 42      # different fuzzer seed
#   ./fuzz/scripts/smoke_gate.sh --json out.json # write summary as JSON

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"
cd "$REPO_ROOT"

# High-risk parser surfaces from bd-rchk7.4:
#   * ext4 superblock / group desc / inode / extent parsing
#   * btrfs superblock / chunk array / tree walking
#   * sparse fixture / image reader paths
#   * repair metadata decode (codec, ledger, symbols, LRC, PoR)
HIGH_RISK_TARGETS=(
    fuzz_ext4_metadata
    fuzz_ext4_image_reader
    fuzz_ext4_dir_extent
    fuzz_ext4_htree_mmp
    fuzz_ext4_checksums
    fuzz_inode_roundtrip
    fuzz_extent_tree
    fuzz_btrfs_metadata
    fuzz_btrfs_chunk_mapping
    fuzz_btrfs_tree_items
    fuzz_btrfs_devitem
    fuzz_btrfs_send_stream
    fuzz_repair_codec_roundtrip
    fuzz_repair_evidence_ledger
    fuzz_lrc_repair
    fuzz_por_authenticator
    fuzz_native_cow_recovery
    fuzz_jbd2_replay
    fuzz_verify_ext4_integrity
)

if [[ -n "${FFS_FUZZ_SMOKE_TARGETS:-}" ]]; then
    # shellcheck disable=SC2206
    HIGH_RISK_TARGETS=(${FFS_FUZZ_SMOKE_TARGETS})
fi

RUNS=2000
SEED=1
JSON_OUT=""
FUZZ_CORPUS_ROOT="${FFS_FUZZ_CORPUS_ROOT:-$FUZZ_DIR/corpus}"
SMOKE_LOG_DIR="${FFS_FUZZ_SMOKE_LOG_DIR:-$FUZZ_DIR/campaigns/smoke_gate_$(date +%Y%m%d_%H%M%S)}"

usage() {
    cat <<'EOF'
Usage: smoke_gate.sh [--runs <N>] [--seed <N>] [--json <path>]

Deterministic fuzz smoke gate over high-risk parser targets.
Exits non-zero on the first failure.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="${2:?--runs requires a value}"; shift 2 ;;
        --seed) SEED="${2:?--seed requires a value}"; shift 2 ;;
        --json) JSON_OUT="${2:?--json requires a path}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fuzz_smoke_gate}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
mkdir -p "$SMOKE_LOG_DIR"

run_remote_cargo_capture() {
    local output_path="$1"
    local status=0
    shift

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${FFS_FUZZ_RCH_LOG_LEVEL:-error}" \
        RCH_VISIBILITY="${FFS_FUZZ_RCH_VISIBILITY:-summary}" \
        "${RCH_BIN:-rch}" exec -- cargo "$@" >"$output_path" 2>&1
    status=$?

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s|command=cargo %s\n' "$output_path" "$*" | tee -a "$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s|command=cargo %s\n' "$output_path" "$*" | tee -a "$output_path"
        return 99
    fi

    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi

case "${FFS_FUZZ_RCH_FIXTURE_CASE:-remote_success}" in
    remote_success)
        echo "[RCH] remote worker=fixture"
        echo "Remote command finished: exit=0"
        exit 0
        ;;
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 0
        ;;
    missing_remote_evidence)
        echo "fixture completed without remote marker"
        exit 0
        ;;
    target_failure)
        echo "[RCH] remote worker=fixture"
        echo "Remote command finished: exit=1"
        exit 1
        ;;
    *)
        echo "unknown fixture case: ${FFS_FUZZ_RCH_FIXTURE_CASE:-}" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

run_fixture_case() {
    local stub_path="$1"
    local work_dir="$2"
    local fixture_case="$3"
    local expected_status="$4"
    local required_marker="$5"
    local child_log="$work_dir/${fixture_case}.child.log"
    local log_dir="$work_dir/${fixture_case}_logs"
    local corpus_root="$work_dir/corpus"
    local child_status

    mkdir -p "$corpus_root/fuzz_fixture" "$log_dir"
    printf 'seed\n' >"$corpus_root/fuzz_fixture/seed_fixture"

    set +e
    FFS_FUZZ_RCH_SELF_TEST=0 \
        FFS_FUZZ_RCH_FIXTURE_CASE="$fixture_case" \
        FFS_FUZZ_SMOKE_TARGETS="fuzz_fixture" \
        FFS_FUZZ_CORPUS_ROOT="$corpus_root" \
        FFS_FUZZ_SMOKE_LOG_DIR="$log_dir" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/fuzz/scripts/smoke_gate.sh" --runs 1 >"$child_log" 2>&1
    child_status=$?
    set -e

    if [[ "$child_status" != "$expected_status" ]]; then
        echo "FUZZ_RCH_SELF_TEST_FAIL|script=smoke_gate|case=${fixture_case}|expected=${expected_status}|actual=${child_status}|log=${child_log}"
        return 1
    fi
    if [[ -n "$required_marker" ]] && ! grep -R -Fq "$required_marker" "$child_log" "$log_dir"; then
        echo "FUZZ_RCH_SELF_TEST_FAIL|script=smoke_gate|case=${fixture_case}|missing_marker=${required_marker}|log=${child_log}|log_dir=${log_dir}"
        return 1
    fi

    echo "FUZZ_RCH_SELF_TEST_PASS|script=smoke_gate|case=${fixture_case}|status=${child_status}|log=${child_log}|log_dir=${log_dir}"
}

run_self_test() {
    local work_dir stub_path
    work_dir="$(mktemp -d -t ffs_fuzz_smoke_gate_self_test_XXXXXX)"
    stub_path="$work_dir/rch-fixture"
    write_fixture_rch_stub "$stub_path"

    run_fixture_case "$stub_path" "$work_dir" remote_success 0 "[RCH] remote"
    run_fixture_case "$stub_path" "$work_dir" local_fallback 1 "RCH_LOCAL_FALLBACK_REJECTED"
    run_fixture_case "$stub_path" "$work_dir" missing_remote_evidence 1 "RCH_REMOTE_EVIDENCE_MISSING"
    run_fixture_case "$stub_path" "$work_dir" target_failure 1 "Remote command finished: exit=1"
    echo "FUZZ_RCH_SELF_TEST_DONE|script=smoke_gate|work_dir=${work_dir}"
}

if [[ "${FFS_FUZZ_RCH_SELF_TEST:-0}" == "1" ]]; then
    run_self_test
    exit 0
fi

echo "=== fuzz smoke gate ==="
echo "  targets:    ${#HIGH_RISK_TARGETS[@]}"
echo "  per-target: -runs=$RUNS -seed=$SEED"
echo "  target_dir: $CARGO_TARGET_DIR"
echo "  logs:       $SMOKE_LOG_DIR"
echo ""

results=()
failures=0
total_start=$(date +%s)

for target in "${HIGH_RISK_TARGETS[@]}"; do
    corpus="$FUZZ_CORPUS_ROOT/$target"
    if [[ ! -d "$corpus" ]]; then
        echo "SKIP   $target: corpus dir missing"
        results+=("{\"target\":\"$target\",\"status\":\"skip\",\"reason\":\"no_corpus\"}")
        continue
    fi

    target_start=$(date +%s)
    replay_log="$SMOKE_LOG_DIR/${target}_replay.log"
    mutate_log="$SMOKE_LOG_DIR/${target}_mutate.log"

    # Phase 1: corpus replay (instant; catches regressions on existing seeds).
    replay_status=0
    set +e
    run_remote_cargo_capture "$replay_log" run --manifest-path fuzz/Cargo.toml --bin "$target" -- "$corpus" -runs=0
    replay_status=$?
    set -e
    if [[ $replay_status -ne 0 ]]; then
        echo "FAIL   $target: corpus replay regressed (status=$replay_status, log=$replay_log)"
        results+=("{\"target\":\"$target\",\"status\":\"fail\",\"phase\":\"replay\",\"exit_code\":$replay_status,\"log\":\"$replay_log\"}")
        failures=$((failures + 1))
        continue
    fi

    # Phase 2: small deterministic mutation budget.
    mutate_status=0
    set +e
    run_remote_cargo_capture "$mutate_log" run --manifest-path fuzz/Cargo.toml --bin "$target" -- \
        "$corpus" -runs="$RUNS" -seed="$SEED" -timeout=10
    mutate_status=$?
    set -e
    if [[ $mutate_status -ne 0 ]]; then
        echo "FAIL   $target: mutation found new crash (status=$mutate_status, log=$mutate_log)"
        results+=("{\"target\":\"$target\",\"status\":\"fail\",\"phase\":\"mutate\",\"exit_code\":$mutate_status,\"log\":\"$mutate_log\"}")
        failures=$((failures + 1))
        continue
    fi

    target_elapsed=$(( $(date +%s) - target_start ))
    echo "PASS   $target  (${target_elapsed}s, replay_log=$replay_log, mutate_log=$mutate_log)"
    results+=("{\"target\":\"$target\",\"status\":\"pass\",\"elapsed_s\":$target_elapsed,\"replay_log\":\"$replay_log\",\"mutate_log\":\"$mutate_log\"}")
done

total_elapsed=$(( $(date +%s) - total_start ))
echo ""
echo "=== smoke gate summary ==="
echo "  passed:  $(( ${#HIGH_RISK_TARGETS[@]} - failures ))"
echo "  failed:  $failures"
echo "  total:   ${total_elapsed}s"

if [[ -n "$JSON_OUT" ]]; then
    {
        echo '{'
        echo "  \"runs\": $RUNS,"
        echo "  \"seed\": $SEED,"
        echo "  \"total_elapsed_s\": $total_elapsed,"
        echo "  \"failures\": $failures,"
        echo '  "results": ['
        for i in "${!results[@]}"; do
            sep=","
            [[ $i -eq $(( ${#results[@]} - 1 )) ]] && sep=""
            echo "    ${results[$i]}$sep"
        done
        echo '  ]'
        echo '}'
    } > "$JSON_OUT"
    echo "  json:    $JSON_OUT"
fi

if [[ $failures -gt 0 ]]; then
    exit 1
fi
