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

echo "=== Fuzz target: $TARGET ==="
echo "Duration: ${DURATION}s"
echo "Corpus: fuzz/corpus/$TARGET"
echo ""

DICT_FLAG=""
if [[ "$TARGET" == *ext4* ]]; then
    DICT_FLAG="-dict=fuzz/dictionaries/ext4.dict"
elif [[ "$TARGET" == *btrfs* ]]; then
    DICT_FLAG="-dict=fuzz/dictionaries/btrfs.dict"
fi

cargo fuzz run "$TARGET" \
    -- \
    -max_total_time="$DURATION" \
    -max_len=65536 \
    $DICT_FLAG \
    2>&1 | tee "fuzz/${TARGET}_$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "=== Fuzz run complete ==="
