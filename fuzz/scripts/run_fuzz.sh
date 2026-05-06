#!/usr/bin/env bash
# run_fuzz.sh - Run a single fuzz target for a specified duration.
#
# Usage: ./fuzz/scripts/run_fuzz.sh <target> [duration_secs]
#
# Examples:
#   ./fuzz/scripts/run_fuzz.sh fuzz_ext4_metadata 60
#   ./fuzz/scripts/run_fuzz.sh fuzz_wal_replay 300

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"

TARGET="${1:?Usage: run_fuzz.sh <target> [duration_secs]}"
DURATION="${2:-60}"

cd "$REPO_ROOT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_run_fuzz}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

run_remote_cargo() {
    RCH_LOG_LEVEL="${FFS_FUZZ_RCH_LOG_LEVEL:-error}" \
        RCH_VISIBILITY="${FFS_FUZZ_RCH_VISIBILITY:-none}" \
        "${RCH_BIN:-rch}" exec -- cargo "$@"
}

echo "=== Fuzz target: $TARGET ==="
echo "Duration: ${DURATION}s"
echo "Corpus: fuzz/corpus/$TARGET"
echo "Target dir: $CARGO_TARGET_DIR"
echo ""

DICT_ARGS=()
if [[ "$TARGET" == *ext4* ]]; then
    DICT_ARGS=(-dict=fuzz/dictionaries/ext4.dict)
elif [[ "$TARGET" == *btrfs* ]]; then
    DICT_ARGS=(-dict=fuzz/dictionaries/btrfs.dict)
fi

run_remote_cargo run --manifest-path fuzz/Cargo.toml --bin "$TARGET" \
    -- \
    -max_total_time="$DURATION" \
    -max_len=65536 \
    "${DICT_ARGS[@]}" \
    2>&1 | tee "fuzz/${TARGET}_$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "=== Fuzz run complete ==="
