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

RUNS=2000
SEED=1
JSON_OUT=""

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

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target-fuzz-smoke}"
export CARGO_TARGET_DIR

echo "=== fuzz smoke gate ==="
echo "  targets:    ${#HIGH_RISK_TARGETS[@]}"
echo "  per-target: -runs=$RUNS -seed=$SEED"
echo "  target_dir: $CARGO_TARGET_DIR"
echo ""

results=()
failures=0
total_start=$(date +%s)

for target in "${HIGH_RISK_TARGETS[@]}"; do
    corpus="fuzz/corpus/$target"
    if [[ ! -d "$corpus" ]]; then
        echo "SKIP   $target: corpus dir missing"
        results+=("{\"target\":\"$target\",\"status\":\"skip\",\"reason\":\"no_corpus\"}")
        continue
    fi

    target_start=$(date +%s)

    # Phase 1: corpus replay (instant; catches regressions on existing seeds).
    if ! cargo fuzz run "$target" "$corpus" -- -runs=0 >/dev/null 2>&1; then
        echo "FAIL   $target: corpus replay regressed"
        results+=("{\"target\":\"$target\",\"status\":\"fail\",\"phase\":\"replay\"}")
        failures=$((failures + 1))
        continue
    fi

    # Phase 2: small deterministic mutation budget.
    if ! cargo fuzz run "$target" "$corpus" -- \
            -runs="$RUNS" -seed="$SEED" -timeout=10 >/dev/null 2>&1; then
        echo "FAIL   $target: mutation found new crash"
        results+=("{\"target\":\"$target\",\"status\":\"fail\",\"phase\":\"mutate\"}")
        failures=$((failures + 1))
        continue
    fi

    target_elapsed=$(( $(date +%s) - target_start ))
    echo "PASS   $target  (${target_elapsed}s)"
    results+=("{\"target\":\"$target\",\"status\":\"pass\",\"elapsed_s\":$target_elapsed}")
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
